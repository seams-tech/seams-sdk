import { expect, test } from '@playwright/test';
import { createInMemoryConsoleOrganizationAccessService } from '../../packages/console-server-ts/src/teamRbac/service';
import {
  createCloudflareSecretsStoreKekProviderFromEnv,
  createConsoleSessionAuthAdapter,
  createHmacSessionAdapter,
  secretBindingNameForKekId,
} from '../../packages/console-server-ts/src/router/cloudflare/d1StagingSession';

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

async function secretsStoreKekProviderUsesExpectedBindingName(): Promise<void> {
  const secretBinding = {
    get: readSecretValue,
  };
  const provider = createCloudflareSecretsStoreKekProviderFromEnv({
    SIGNING_ROOT_KEK_PROVIDER: 'cloudflare_secrets_store',
    SIGNING_ROOT_KEK_ENCODING: 'base64url',
    SIGNING_ROOT_KEK_IDS: 'signing-root-kek-staging-r1',
    SIGNING_ROOT_KEK_STAGING_R1: secretBinding,
  });
  expect(secretBindingNameForKekId('signing-root-kek-staging-r1')).toBe(
    'SIGNING_ROOT_KEK_STAGING_R1',
  );
  expect(provider.kind).toBe('cloudflare_secrets_store');
  if (provider.kind !== 'cloudflare_secrets_store') {
    throw new Error('expected Cloudflare Secrets Store provider');
  }
  await expect(provider.secretsByKekId['signing-root-kek-staging-r1']?.get()).resolves.toBe(
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  );
}

async function secretsStoreKekProviderRejectsMissingBinding(): Promise<void> {
  expect(() =>
    createCloudflareSecretsStoreKekProviderFromEnv({
      SIGNING_ROOT_KEK_PROVIDER: 'cloudflare_secrets_store',
      SIGNING_ROOT_KEK_ENCODING: 'base64url',
      SIGNING_ROOT_KEK_IDS: 'signing-root-kek-staging-r1',
    }),
  ).toThrow('Cloudflare Secrets Store binding SIGNING_ROOT_KEK_STAGING_R1 is required');
}

async function readSecretValue(): Promise<string> {
  return 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
}

test('HMAC staging session signs and verifies JWT claims', hmacSessionRoundTrip);
test('HMAC staging session rejects wrong audience', hmacSessionRejectsWrongAudience);
test(
  'HMAC staging session cookies support cross-site credentialed requests',
  hmacSessionUsesCrossSiteCookiePolicy,
);
test(
  'console staging auth resolves current organization authorization',
  consoleAuthUsesCurrentOrganizationAuthorization,
);
test('console staging auth rejects token role escalation', consoleAuthIgnoresTokenRoleEscalation);
test('Secrets Store KEK provider resolves upper-snake bindings', secretsStoreKekProviderUsesExpectedBindingName);
test('Secrets Store KEK provider rejects missing bindings', secretsStoreKekProviderRejectsMissingBinding);
