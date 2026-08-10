import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '../../packages/shared-ts/src/utils/sessionTokens';
import { handleLinkedDeviceEd25519NormalSigning } from '../../packages/sdk-server-ts/src/router/transport/fetch/routes/linkedDeviceNormalSigning';
import type { FetchRouterApiContext } from '../../packages/sdk-server-ts/src/router/transport/fetch/fetchRouter.types';
import type { SessionAdapter } from '../../packages/sdk-server-ts/src/router/framework/routerApi';

function digest(fill: number): string {
  return base64UrlEncode(new Uint8Array(32).fill(fill));
}

function linkedClaims(expiresAtMs: number): Record<string, unknown> {
  return {
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    authorizationKind: 'linked_device_wallet_session',
    sub: 'linked-device:device:2',
    walletId: 'wallet:1',
    tenantId: 'tenant:1',
    deviceId: 'device:2',
    enrollmentId: 'enrollment:2',
    walletKeyId: 'wallet-key:1',
    keyManifestDigestB64u: digest(1),
    revocationEpoch: 0,
    permission: {
      kind: 'owner_equivalent_signing',
      administrationScope: 'signing_only',
      localUserPresence: 'required',
    },
    issuedAtMs: 100,
    expiresAtMs,
    authorizationId: 'linked-device-wallet-session-authorization:1',
    walletSessionId: 'wallet-session:linked',
    quotaId: 'wallet-quota:linked',
    iat: 0,
    exp: Math.floor(expiresAtMs / 1000),
  };
}

function sessionWithClaims(claims: Record<string, unknown>): SessionAdapter {
  return {
    signJwt: async () => 'unused',
    verifyJwt: async () => ({ valid: false as const }),
    parse: async () => ({ ok: true as const, claims }),
    buildSetCookie: (token) => `session=${token}`,
    buildClearCookie: () => 'session=',
    refresh: async () => ({ ok: false }),
  };
}

function context(session: SessionAdapter): FetchRouterApiContext {
  const request = new Request('https://example.test/router-ab/ed25519/signing/prepare', {
    method: 'POST',
    headers: { authorization: 'Bearer linked-session' },
  });
  return {
    request,
    url: new URL(request.url),
    pathname: '/router-ab/ed25519/signing/prepare',
    method: 'POST',
    runtime: { kind: 'inline' },
    service: {},
    opts: { session },
    logger: {},
    mePath: '/me',
    routeDefinitions: [],
  } as unknown as FetchRouterApiContext;
}

test('routes a linked session into the linked admission branch', async () => {
  const result = await handleLinkedDeviceEd25519NormalSigning({
    ctx: context(sessionWithClaims(linkedClaims(Date.now() + 60_000))),
    body: {},
    phase: 'prepare',
  });
  expect(result?.status).toBe(501);
  expect(await result?.json()).toMatchObject({
    ok: false,
    code: 'not_configured',
  });
});

test('does not treat an expired linked session as an owner signing request', async () => {
  const result = await handleLinkedDeviceEd25519NormalSigning({
    ctx: context(sessionWithClaims(linkedClaims(Date.now() - 1))),
    body: {},
    phase: 'prepare',
  });
  expect(result).toBeNull();
});
