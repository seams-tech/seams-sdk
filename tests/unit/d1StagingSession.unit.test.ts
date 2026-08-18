import { expect, test } from '@playwright/test';
import { createInMemoryConsoleOrganizationAccessService } from '../../packages/console-server-ts/src/teamRbac/service';
import {
  createConsoleSessionAuthAdapter,
  createEd25519SessionAdapter,
  createHmacSessionAdapter,
  type Ed25519SessionAdapterOptions,
} from '../../packages/wallet-console-server-ts/src/router/cloudflare/d1StagingSession';
import { decodeJwtPayloadRecord } from '../../packages/shared-ts/src/utils/sessionTokens';

const SESSION_SECRET = '0123456789abcdef0123456789abcdef';

function bearerHeaders(token: string): Record<string, string> {
  return {
    authorization: `Bearer ${token}`,
  };
}

async function signConsoleSession(input: {
  readonly userId: string;
  readonly orgId: string;
  readonly roles?: readonly string[];
}): Promise<string> {
  const session = createHmacSessionAdapter({
    secret: SESSION_SECRET,
    issuer: 'seams-console-staging',
    audience: 'seams-console-dashboard',
  });
  return await session.signJwt(input.userId, {
    kind: 'console_session_v1',
    orgId: input.orgId,
    email: `${input.userId}@example.test`,
    ...(input.roles ? { roles: [...input.roles] } : {}),
  });
}

async function hmacSessionRoundTrip(): Promise<void> {
  const session = createHmacSessionAdapter({
    secret: SESSION_SECRET,
    issuer: 'seams-gateway-staging',
    audience: 'seams-wallet-session',
  });
  const jwt = await session.signJwt('wallet-user', {
    kind: 'app_session_v1',
    appSessionVersion: 'session-v1',
  });
  const parsed = await session.parse(bearerHeaders(jwt));
  expect(parsed.ok).toBe(true);
  if (!parsed.ok) throw new Error('expected signed HMAC session to parse');
  expect(parsed.claims.sub).toBe('wallet-user');
  expect(parsed.claims.kind).toBe('app_session_v1');
  expect(parsed.claims.appSessionVersion).toBe('session-v1');
}

async function hmacSessionRejectsWrongAudience(): Promise<void> {
  const signer = createHmacSessionAdapter({
    secret: SESSION_SECRET,
    issuer: 'seams-gateway-staging',
    audience: 'seams-wallet-session',
  });
  const verifier = createHmacSessionAdapter({
    secret: SESSION_SECRET,
    issuer: 'seams-gateway-staging',
    audience: 'other-audience',
  });
  const jwt = await signer.signJwt('wallet-user', { kind: 'app_session_v1' });
  await expect(verifier.parse(bearerHeaders(jwt))).resolves.toEqual({
    ok: false,
    reason: 'signature_invalid',
  });
}

async function linkedWalletSessionClaimsSurviveProductionSigning(): Promise<void> {
  const session = createEd25519SessionAdapter({
    privateJwk: await generateEd25519PrivateJwk(),
    keyId: 'linked-session-test-key',
    issuer: 'seams-router-test',
    audience: 'seams-linked-wallet-session',
    ttlSeconds: 3_600,
  });
  const nowSeconds = Math.floor(Date.now() / 1_000);
  const iat = nowSeconds - 5;
  const exp = nowSeconds + 300;
  const jwt = await session.signJwt('linked-device:device-r103', {
    kind: 'router_ab_ed25519_wallet_session_v1',
    authorizationKind: 'linked_device_wallet_session',
    tenantId: 'tenant-r103',
    iat,
    exp,
  });
  const payload = decodeJwtPayloadRecord(jwt);

  expect(payload).toMatchObject({
    sub: 'linked-device:device-r103',
    kind: 'router_ab_ed25519_wallet_session_v1',
    authorizationKind: 'linked_device_wallet_session',
    tenantId: 'tenant-r103',
    iat,
    exp,
    iss: 'seams-router-test',
    aud: 'seams-linked-wallet-session',
  });
  expect(payload).not.toHaveProperty('org_id');
  expect(payload).not.toHaveProperty('project_id');
  expect(payload).not.toHaveProperty('environment');
}

async function generateEd25519PrivateJwk(): Promise<Ed25519SessionAdapterOptions['privateJwk']> {
  const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.x || !jwk.d) {
    throw new Error('generated Ed25519 JWK is incomplete');
  }
  return {
    ...jwk,
    kty: 'OKP',
    crv: 'Ed25519',
    x: jwk.x,
    d: jwk.d,
  };
}

function hmacSessionUsesCrossSiteCookiePolicy(): void {
  const session = createHmacSessionAdapter({
    secret: SESSION_SECRET,
    cookieName: 'dashboard-session',
    ttlSeconds: 3600,
  });

  expect(session.buildSetCookie('session-token')).toMatch(
    /^dashboard-session=session-token; Path=\/; HttpOnly; Secure; SameSite=None; Max-Age=3600; Expires=/,
  );
  expect(session.buildClearCookie()).toBe(
    'dashboard-session=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
  );
}

async function consoleAuthUsesCurrentOrganizationAuthorization(): Promise<void> {
  const organizationAccess = createInMemoryConsoleOrganizationAccessService();
  await organizationAccess.bootstrapInitialOwner({
    orgId: 'org_staging',
    userId: 'console-user',
    email: 'console-user@example.test',
    displayName: 'Console User',
  });
  const token = await signConsoleSession({
    userId: 'console-user',
    orgId: 'org_staging',
  });
  const auth = createConsoleSessionAuthAdapter({
    session: createHmacSessionAdapter({
      secret: SESSION_SECRET,
      issuer: 'seams-console-staging',
      audience: 'seams-console-dashboard',
    }),
    organizationAccess,
  });
  const result = await auth.authenticate(bearerHeaders(token));
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error('expected console auth to pass');
  expect(result.claims).toMatchObject({
    role: 'OWNER',
    projectAccess: { kind: 'all' },
    platformSupport: false,
  });
  expect('roles' in result.claims).toBe(false);
}

async function consoleAuthIgnoresTokenRoleEscalation(): Promise<void> {
  const token = await signConsoleSession({
    userId: 'console-user',
    orgId: 'org_staging',
    roles: ['owner', 'platform_admin'],
  });
  const auth = createConsoleSessionAuthAdapter({
    session: createHmacSessionAdapter({
      secret: SESSION_SECRET,
      issuer: 'seams-console-staging',
      audience: 'seams-console-dashboard',
    }),
    organizationAccess: createInMemoryConsoleOrganizationAccessService(),
  });
  const result = await auth.authenticate(bearerHeaders(token));
  expect(result).toMatchObject({
    ok: false,
    code: 'forbidden',
    status: 403,
  });
}

test('HMAC staging session signs and verifies JWT claims', hmacSessionRoundTrip);
test('HMAC staging session rejects wrong audience', hmacSessionRejectsWrongAudience);
test(
  'production Ed25519 session signing preserves linked authorization lifetime and scope',
  linkedWalletSessionClaimsSurviveProductionSigning,
);
test(
  'HMAC staging session cookies support cross-site credentialed requests',
  hmacSessionUsesCrossSiteCookiePolicy,
);
test(
  'console staging auth resolves current organization authorization',
  consoleAuthUsesCurrentOrganizationAuthorization,
);
test('console staging auth rejects token role escalation', consoleAuthIgnoresTokenRoleEscalation);
