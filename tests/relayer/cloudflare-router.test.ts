import { test, expect } from '@playwright/test';
import {
  createCloudflareRouter,
  createInMemoryConsoleWebhookService,
} from '@server/router/cloudflare-adaptor';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '@server/core/ThresholdService/schemes/schemeIds';
import { callCf, getPath, makeCfCtx, makeFakeAuthService, makeSessionAdapter } from './helpers';

function validLoginOptionsBody(overrides?: Partial<any>): any {
  return {
    user_id: 'bob.testnet',
    rp_id: 'example.localhost',
    ...overrides,
  };
}

function validLoginVerifyBody(overrides?: Partial<any>): any {
  return {
    sessionKind: 'jwt',
    challengeId: 'challenge-123',
    webauthn_authentication: { ok: true, ...(overrides?.webauthn_authentication || {}) },
    ...overrides,
  };
}

function validSmartAccountDeployBody(overrides?: Partial<any>): any {
  return {
    nearAccountId: 'bob.testnet',
    chain: 'tempo',
    chainId: 'tempo:42431',
    accountAddress: '0xabc123',
    accountModel: 'tempo-native',
    counterfactualAddress: '0xabc123',
    ...overrides,
  };
}

function makeUnsignedJwtWithExp(expSeconds: number): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' }), 'utf8').toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({ sub: 'session-exchange-test', exp: expSeconds }),
    'utf8',
  ).toString('base64url');
  return `${header}.${payload}.signature`;
}

function makeEd25519ThresholdAdapter(input: {
  authorize: (args: {
    claims: Record<string, unknown>;
    request: Record<string, unknown>;
  }) => Promise<Record<string, unknown>>;
}): {
  getSchemeModule: (schemeId: string) => Record<string, unknown> | null;
} {
  return {
    getSchemeModule: (schemeId: string) => {
      if (schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) return null;
      return {
        schemeId: THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
        healthz: async () => ({ ok: true }),
        keygen: async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' }),
        session: async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' }),
        authorize: async (args: { claims: Record<string, unknown>; request: Record<string, unknown> }) =>
          await input.authorize(args),
        protocol: {
          signInit: async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' }),
          signFinalize: async () => ({
            ok: false,
            code: 'not_implemented',
            message: 'not implemented',
          }),
        },
      };
    },
  };
}

test.describe('relayer router (cloudflare) – P0', () => {
  test('CORS preflight: default HTTPS port in allowlist still matches origin without explicit port', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://wallet.example.localhost:443'],
    });

    const res = await callCf(handler, {
      method: 'OPTIONS',
      path: '/sync-account/verify',
      origin: 'https://wallet.example.localhost',
    });

    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe('https://wallet.example.localhost');
    expect(res.headers.get('access-control-allow-credentials')).toBe('true');
  });

  test('CORS preflight: allowlist echoes Origin + allows credentials', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'OPTIONS',
      path: '/auth/passkey/verify',
      origin: 'https://example.localhost',
    });

    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe('https://example.localhost');
    expect(res.headers.get('access-control-allow-credentials')).toBe('true');
    expect(res.headers.get('access-control-allow-methods')).toContain('OPTIONS');
    expect(res.headers.get('access-control-allow-headers')).toContain('Authorization');
    expect(res.headers.get('vary')).toContain('Origin');
  });

  test('CORS preflight: "*" allows origin but not credentials', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { corsOrigins: [] });

    const res = await callCf(handler, {
      method: 'OPTIONS',
      path: '/auth/passkey/verify',
      origin: 'https://example.localhost',
    });

    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    expect(res.headers.get('access-control-allow-credentials')).toBe(null);
  });

  test('POST /auth/passkey/options: invalid body', async () => {
    const service = makeFakeAuthService({
      createWebAuthnLoginOptions: async () => ({
        ok: false,
        code: 'invalid_body',
        message: 'Missing user_id',
      }),
    });
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/auth/passkey/options',
      origin: 'https://example.localhost',
      body: {},
    });

    expect(res.status).toBe(400);
    expect(res.json?.code).toBe('invalid_body');
  });

  test('POST /auth/passkey/options: ok returns challengeId', async () => {
    const service = makeFakeAuthService({
      createWebAuthnLoginOptions: async () => ({
        ok: true,
        challengeId: 'cid-123',
        challengeB64u: 'challenge-b64u',
        expiresAtMs: 123,
      }),
    });
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/auth/passkey/options',
      origin: 'https://example.localhost',
      body: validLoginOptionsBody(),
    });

    expect(res.status).toBe(200);
    expect(res.json?.challengeId).toBe('cid-123');
  });

  test('POST /sync-account/options: forwards account_id and returns credentialIds', async () => {
    let receivedBody: Record<string, unknown> | null = null;
    const service = makeFakeAuthService({
      createWebAuthnSyncAccountOptions: async (body) => {
        receivedBody = (body || {}) as Record<string, unknown>;
        return {
          ok: true,
          challengeId: 'sync-cid-123',
          challengeB64u: 'sync-challenge-b64u',
          credentialIds: ['cred-a', 'cred-b'],
          expiresAtMs: 123,
        };
      },
    });
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/sync-account/options',
      origin: 'https://example.localhost',
      body: { rp_id: 'example.localhost', account_id: 'bob.testnet' },
    });

    expect(res.status).toBe(200);
    expect(res.json?.challengeId).toBe('sync-cid-123');
    expect(res.json?.credentialIds).toEqual(['cred-a', 'cred-b']);
    expect((receivedBody as Record<string, unknown> | null)?.['rp_id']).toBe(
      'example.localhost',
    );
    expect((receivedBody as Record<string, unknown> | null)?.['account_id']).toBe('bob.testnet');
  });

  test('POST /auth/passkey/verify: invalid body', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/auth/passkey/verify',
      origin: 'https://example.localhost',
      body: {},
    });

    expect(res.status).toBe(400);
    expect(res.json?.code).toBe('invalid_body');
  });

  test('POST /auth/passkey/verify: not verified maps to 400', async () => {
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async () => ({
        ok: false,
        verified: false,
        code: 'not_verified',
        message: 'nope',
      }),
    });
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/auth/passkey/verify',
      origin: 'https://example.localhost',
      body: validLoginVerifyBody(),
    });

    expect(res.status).toBe(400);
    expect(res.json?.code).toBe('not_verified');
  });

  test('POST /auth/passkey/verify: verified does not mint app-session jwt', async () => {
    const session = makeSessionAdapter({ signJwt: async () => 'jwt-123' });
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async () => ({
        ok: true,
        verified: true,
        userId: 'bob.testnet',
        rpId: 'example.localhost',
      }),
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/auth/passkey/verify',
      origin: 'https://example.localhost',
      body: validLoginVerifyBody({ sessionKind: 'jwt' }),
    });

    expect(res.status).toBe(200);
    expect(res.json?.verified).toBe(true);
    expect(res.json?.jwt).toBeUndefined();
  });

  test('POST /auth/passkey/verify: verified does not set app-session cookie', async () => {
    const session = makeSessionAdapter({
      signJwt: async () => 'cookie-456',
      buildSetCookie: (t) => `tatchi-jwt=${t}; Path=/; HttpOnly`,
    });
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async () => ({
        ok: true,
        verified: true,
        userId: 'bob.testnet',
        rpId: 'example.localhost',
      }),
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/auth/passkey/verify',
      origin: 'https://example.localhost',
      body: validLoginVerifyBody({ sessionKind: 'cookie' }),
    });

    expect(res.status).toBe(200);
    expect(res.headers.get('set-cookie')).toBeNull();
    expect(res.json?.verified).toBe(true);
    expect(res.json?.jwt).toBeUndefined();
  });

  test('POST /auth/passkey/verify: ignores session adapter failures', async () => {
    const session = makeSessionAdapter({
      signJwt: async () => {
        throw new Error('boom');
      },
    });
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async () => ({
        ok: true,
        verified: true,
        userId: 'bob.testnet',
        rpId: 'example.localhost',
      }),
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/auth/passkey/verify',
      origin: 'https://example.localhost',
      body: validLoginVerifyBody({ sessionKind: 'jwt' }),
    });

    expect(res.status).toBe(200);
    expect(res.json?.verified).toBe(true);
    expect(res.json?.jwt).toBeUndefined();
  });

  test('POST /auth/google/verify: verified does not mint app-session jwt/cookie', async () => {
    const session = makeSessionAdapter({
      signJwt: async () => 'google-jwt-should-not-be-returned',
      buildSetCookie: (t) => `tatchi-jwt=${t}; Path=/; HttpOnly`,
    });
    const service = makeFakeAuthService({
      verifyGoogleLogin: async () => ({
        ok: true,
        verified: true,
        userId: 'bob.testnet',
        sub: 'google-sub-1',
        email: 'bob@example.com',
        emailVerified: true,
      }),
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/auth/google/verify',
      origin: 'https://example.localhost',
      body: {
        sessionKind: 'cookie',
        idToken: 'header.payload.signature',
      },
    });

    expect(res.status).toBe(200);
    expect(res.json?.verified).toBe(true);
    expect(res.json?.email).toBe('bob@example.com');
    expect(res.json?.jwt).toBeUndefined();
    expect(res.headers.get('set-cookie')).toBeNull();
  });

  test('GET /auth/identities: stale bearer parse failure emits session.warm.expired webhook', async () => {
    const dispatched: Array<{ eventType: string; payload: Record<string, unknown> }> = [];
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async (input) => {
          const body = JSON.parse(input.body) as Record<string, unknown>;
          dispatched.push({
            eventType: String(body.type || ''),
            payload:
              body.data && typeof body.data === 'object' && !Array.isArray(body.data)
                ? (body.data as Record<string, unknown>)
                : {},
          });
          return { ok: true, statusCode: 200, responseBody: 'ok' };
        },
      },
    });
    await webhooks.createEndpoint(
      { orgId: 'org-relay-cf-auth-identities-parse-fail', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session'],
      },
    );

    const session = makeSessionAdapter({ parse: async () => ({ ok: false }) });
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-cf-auth-identities-parse-fail',
      },
    });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/auth/identities',
      origin: 'https://example.localhost',
      headers: { Authorization: 'Bearer stale-token' },
    });
    expect(res.status).toBe(401);
    expect(res.json?.code).toBe('unauthorized');
    expect(dispatched.length).toBe(1);
    expect(dispatched[0]?.eventType).toBe('session.warm.expired');
    expect(dispatched[0]?.payload?.source).toBe('auth.identities');
    expect(dispatched[0]?.payload?.code).toBe('unauthorized');
    expect(dispatched[0]?.payload?.orgId).toBe('org-relay-cf-auth-identities-parse-fail');
  });

  test('POST /smart-account/deploy: default route returns assumed_deployed', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/smart-account/deploy',
      origin: 'https://example.localhost',
      body: validSmartAccountDeployBody(),
    });

    expect(res.status).toBe(200);
    expect(res.json?.ok).toBe(true);
    expect(res.json?.code).toBe('assumed_deployed');
  });

  test('POST /smart-account/deploy: custom hook response is returned', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      smartAccountDeploy: async (req) => {
        expect(req.nearAccountId).toBe('bob.testnet');
        expect(req.chain).toBe('tempo');
        return { ok: true, deploymentTxHash: '0xdeploytx' };
      },
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/smart-account/deploy',
      origin: 'https://example.localhost',
      body: validSmartAccountDeployBody(),
    });

    expect(res.status).toBe(200);
    expect(res.json?.ok).toBe(true);
    expect(res.json?.deploymentTxHash).toBe('0xdeploytx');
  });

  test('POST /smart-account/deploy: invalid body maps to 400', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/smart-account/deploy',
      origin: 'https://example.localhost',
      body: { nearAccountId: 'bob.testnet' },
    });

    expect(res.status).toBe(400);
    expect(res.json?.ok).toBe(false);
    expect(res.json?.code).toBe('invalid_body');
  });

  test('POST /threshold-ecdsa/keygen and /threshold-ecdsa/session: removed (404)', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const keygen = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ecdsa/keygen',
      origin: 'https://example.localhost',
      body: {},
    });
    expect(keygen.status).toBe(404);

    const session = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ecdsa/session',
      origin: 'https://example.localhost',
      body: {},
    });
    expect(session.status).toBe(404);
  });

  test('GET /session/state: sessions disabled -> 501', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/session/state',
      origin: 'https://example.localhost',
    });

    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('sessions_disabled');
    expect(res.json?.authenticated).toBe(false);
  });

  test('GET /session/state: invalid session -> 401', async () => {
    const session = makeSessionAdapter({ parse: async () => ({ ok: false }) });
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/session/state',
      origin: 'https://example.localhost',
    });

    expect(res.status).toBe(401);
    expect(res.json?.authenticated).toBe(false);
  });

  test('GET /session/state: returns authenticated app session claims', async () => {
    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: { sub: 'bob.testnet', kind: 'app_session_v1', appSessionVersion: 'v1' },
      }),
    });
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/session/state',
      origin: 'https://example.localhost',
    });

    expect(res.status).toBe(200);
    expect(res.json?.authenticated).toBe(true);
    expect(getPath(res.json, 'claims', 'sub')).toBe('bob.testnet');
  });

  test('GET /session/state: stale bearer parse failure emits session.warm.expired webhook', async () => {
    const dispatched: Array<{ eventType: string; payload: Record<string, unknown> }> = [];
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async (input) => {
          const body = JSON.parse(input.body) as Record<string, unknown>;
          dispatched.push({
            eventType: String(body.type || ''),
            payload:
              body.data && typeof body.data === 'object' && !Array.isArray(body.data)
                ? (body.data as Record<string, unknown>)
                : {},
          });
          return { ok: true, statusCode: 200, responseBody: 'ok' };
        },
      },
    });
    await webhooks.createEndpoint(
      { orgId: 'org-relay-cf-parse-fail', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session'],
      },
    );
    const session = makeSessionAdapter({ parse: async () => ({ ok: false }) });
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-cf-parse-fail',
      },
    });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/session/state',
      origin: 'https://example.localhost',
      headers: { Authorization: 'Bearer stale-token' },
    });
    expect(res.status).toBe(401);
    expect(res.json?.authenticated).toBe(false);
    expect(dispatched.length).toBe(1);
    expect(dispatched[0]?.eventType).toBe('session.warm.expired');
    expect(dispatched[0]?.payload?.source).toBe('session.state');
    expect(dispatched[0]?.payload?.code).toBe('unauthorized');
    expect(dispatched[0]?.payload?.orgId).toBe('org-relay-cf-parse-fail');
  });

  test('GET /session/state: stale cookie parse failure emits session.warm.expired webhook', async () => {
    const dispatched: Array<{ eventType: string; payload: Record<string, unknown> }> = [];
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async (input) => {
          const body = JSON.parse(input.body) as Record<string, unknown>;
          dispatched.push({
            eventType: String(body.type || ''),
            payload:
              body.data && typeof body.data === 'object' && !Array.isArray(body.data)
                ? (body.data as Record<string, unknown>)
                : {},
          });
          return { ok: true, statusCode: 200, responseBody: 'ok' };
        },
      },
    });
    await webhooks.createEndpoint(
      { orgId: 'org-relay-cf-cookie-parse-fail', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session'],
      },
    );
    const session = makeSessionAdapter({ parse: async () => ({ ok: false }) });
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-cf-cookie-parse-fail',
      },
    });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/session/state',
      origin: 'https://example.localhost',
      headers: { Cookie: 'tatchi-jwt=stale-cookie-token' },
    });
    expect(res.status).toBe(401);
    expect(res.json?.authenticated).toBe(false);
    expect(dispatched.length).toBe(1);
    expect(dispatched[0]?.eventType).toBe('session.warm.expired');
    expect(dispatched[0]?.payload?.source).toBe('session.state');
    expect(dispatched[0]?.payload?.code).toBe('unauthorized');
    expect(dispatched[0]?.payload?.orgId).toBe('org-relay-cf-cookie-parse-fail');
  });

  test('GET /session/state: non-matching cookie name does not emit session.warm.expired webhook', async () => {
    const dispatched: Array<{ eventType: string; payload: Record<string, unknown> }> = [];
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async (input) => {
          const body = JSON.parse(input.body) as Record<string, unknown>;
          dispatched.push({
            eventType: String(body.type || ''),
            payload:
              body.data && typeof body.data === 'object' && !Array.isArray(body.data)
                ? (body.data as Record<string, unknown>)
                : {},
          });
          return { ok: true, statusCode: 200, responseBody: 'ok' };
        },
      },
    });
    await webhooks.createEndpoint(
      { orgId: 'org-relay-cf-cookie-nonmatch', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session'],
      },
    );
    const session = makeSessionAdapter({ parse: async () => ({ ok: false }) });
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-cf-cookie-nonmatch',
      },
    });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/session/state',
      origin: 'https://example.localhost',
      headers: { Cookie: 'other-cookie=stale-cookie-token' },
    });
    expect(res.status).toBe(401);
    expect(res.json?.authenticated).toBe(false);
    expect(dispatched.length).toBe(0);
  });

  test('POST /session/exchange: oidc_jwt -> app session jwt', async () => {
    const expSeconds = 1_893_456_000; // 2030-01-01T00:00:00.000Z
    const session = makeSessionAdapter({ signJwt: async () => makeUnsignedJwtWithExp(expSeconds) });
    const service = makeFakeAuthService({
      verifyOidcJwtExchange: async () => ({
        ok: true,
        verified: true,
        userId: 'user-oidc-cf-1',
        providerSubject: 'oidc:https://issuer.example.com:user-123',
        iss: 'https://issuer.example.com',
        aud: ['wallet-app'],
        sub: 'user-123',
      }),
      getOrCreateAppSessionVersion: async () => ({ ok: true, appSessionVersion: 'app-v1' }),
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/session/exchange',
      origin: 'https://example.localhost',
      body: {
        sessionKind: 'jwt',
        exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
      },
    });

    expect(res.status).toBe(200);
    expect(res.json?.ok).toBe(true);
    expect(getPath(res.json, 'session', 'kind')).toBe('app_session_v1');
    expect(getPath(res.json, 'session', 'userId')).toBe('user-oidc-cf-1');
    expect(getPath(res.json, 'session', 'expiresAt')).toBe('2030-01-01T00:00:00.000Z');
    expect(typeof res.json?.jwt).toBe('string');
  });

  test('POST /session/exchange: oidc_jwt + sessionKind=cookie sets cookie and omits jwt', async () => {
    const session = makeSessionAdapter({
      signJwt: async () => 'app-jwt-cf-cookie-123',
      buildSetCookie: (t) => `tatchi-jwt=${t}; Path=/; HttpOnly`,
    });
    const service = makeFakeAuthService({
      verifyOidcJwtExchange: async () => ({
        ok: true,
        verified: true,
        userId: 'user-oidc-cf-cookie-1',
        providerSubject: 'oidc:https://issuer.example.com:user-cookie-1',
      }),
      getOrCreateAppSessionVersion: async () => ({ ok: true, appSessionVersion: 'app-v1' }),
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/session/exchange',
      origin: 'https://example.localhost',
      body: {
        sessionKind: 'cookie',
        exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
      },
    });

    expect(res.status).toBe(200);
    expect(res.json?.ok).toBe(true);
    expect(getPath(res.json, 'session', 'kind')).toBe('app_session_v1');
    expect(getPath(res.json, 'session', 'userId')).toBe('user-oidc-cf-cookie-1');
    expect(getPath(res.json, 'session', 'expiresAt')).toBeUndefined();
    expect(res.json?.jwt).toBeUndefined();
    expect(res.headers.get('set-cookie')).toContain('tatchi-jwt=app-jwt-cf-cookie-123');
  });

  test('POST /session/exchange: passkey_assertion mints app session and emits unlock webhook', async () => {
    const dispatched: Array<{ eventType: string; payload: Record<string, unknown> }> = [];
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async (input) => {
          const body = JSON.parse(input.body) as Record<string, unknown>;
          dispatched.push({
            eventType: String(body.type || ''),
            payload:
              body.data && typeof body.data === 'object' && !Array.isArray(body.data)
                ? (body.data as Record<string, unknown>)
                : {},
          });
          return { ok: true, statusCode: 200, responseBody: 'ok' };
        },
      },
    });
    await webhooks.createEndpoint(
      {
        orgId: 'org-relay-cf-passkey-exchange',
        actorUserId: 'test-admin',
        roles: ['admin'],
      },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session', 'wallet'],
      },
    );

    let verifyArgs: Record<string, unknown> | null = null;
    const session = makeSessionAdapter({ signJwt: async () => 'app-jwt-cf-passkey-1' });
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async (args: any) => {
        verifyArgs = args as Record<string, unknown>;
        return {
          ok: true,
          verified: true,
          userId: 'user-passkey-cf-1',
          rpId: 'example.localhost',
        };
      },
      getOrCreateAppSessionVersion: async () => ({ ok: true, appSessionVersion: 'app-v1' }),
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-cf-passkey-exchange',
      },
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/session/exchange',
      origin: 'https://wallet.example.localhost',
      body: {
        sessionKind: 'jwt',
        exchange: {
          type: 'passkey_assertion',
          challengeId: 'challenge-passkey-cf-1',
          webauthn_authentication: {
            id: 'cred-1',
            rawId: 'cred-1',
            type: 'public-key',
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: null,
            },
            clientExtensionResults: null,
          },
        },
      },
    });

    expect(res.status).toBe(200);
    expect(res.json?.ok).toBe(true);
    expect(getPath(res.json, 'session', 'kind')).toBe('app_session_v1');
    expect(getPath(res.json, 'session', 'userId')).toBe('user-passkey-cf-1');
    expect(res.json?.jwt).toBe('app-jwt-cf-passkey-1');
    expect(String((verifyArgs as Record<string, unknown> | null)?.['challengeId'] || '')).toBe(
      'challenge-passkey-cf-1',
    );
    expect(
      String((verifyArgs as Record<string, unknown> | null)?.['expected_origin'] || ''),
    ).toBe('https://wallet.example.localhost');
    expect(dispatched.map((item) => item.eventType)).toEqual([
      'session.warm.created',
      'wallet.unlocked',
    ]);
    expect(dispatched[0]?.payload?.provider).toBe('passkey');
    expect(dispatched[1]?.payload?.challengeId).toBe('challenge-passkey-cf-1');
  });

  test('POST /session/exchange: passkey_assertion + sessionKind=cookie sets cookie and omits jwt', async () => {
    const session = makeSessionAdapter({
      signJwt: async () => 'app-jwt-cf-passkey-cookie-1',
      buildSetCookie: (t) => `tatchi-jwt=${t}; Path=/; HttpOnly`,
    });
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async () => ({
        ok: true,
        verified: true,
        userId: 'user-passkey-cf-cookie-1',
        rpId: 'example.localhost',
      }),
      getOrCreateAppSessionVersion: async () => ({ ok: true, appSessionVersion: 'app-v1' }),
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/session/exchange',
      origin: 'https://example.localhost',
      body: {
        sessionKind: 'cookie',
        exchange: {
          type: 'passkey_assertion',
          challengeId: 'challenge-passkey-cf-cookie-1',
          webauthn_authentication: {
            id: 'cred-1',
            rawId: 'cred-1',
            type: 'public-key',
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: null,
            },
            clientExtensionResults: null,
          },
        },
      },
    });

    expect(res.status).toBe(200);
    expect(res.json?.ok).toBe(true);
    expect(getPath(res.json, 'session', 'kind')).toBe('app_session_v1');
    expect(getPath(res.json, 'session', 'userId')).toBe('user-passkey-cf-cookie-1');
    expect(res.json?.jwt).toBeUndefined();
    expect(res.headers.get('set-cookie')).toContain('tatchi-jwt=app-jwt-cf-passkey-cookie-1');
  });

  test('POST /session/exchange: passkey_assertion requires challengeId', async () => {
    const session = makeSessionAdapter();
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/session/exchange',
      origin: 'https://example.localhost',
      body: {
        sessionKind: 'jwt',
        exchange: {
          type: 'passkey_assertion',
          webauthn_authentication: { id: 'cred-1' },
        },
      },
    });
    expect(res.status).toBe(400);
    expect(res.json?.ok).toBe(false);
    expect(res.json?.code).toBe('invalid_body');
    expect(String(res.json?.message || '')).toContain('challengeId');
  });

  test('POST /session/exchange: passkey_assertion requires webauthn_authentication', async () => {
    const session = makeSessionAdapter();
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/session/exchange',
      origin: 'https://example.localhost',
      body: {
        sessionKind: 'jwt',
        exchange: {
          type: 'passkey_assertion',
          challengeId: 'challenge-passkey-missing-auth-cf',
        },
      },
    });
    expect(res.status).toBe(400);
    expect(res.json?.ok).toBe(false);
    expect(res.json?.code).toBe('invalid_body');
    expect(String(res.json?.message || '')).toContain('webauthn_authentication');
  });

  test('session exchange + refresh emits warm session lifecycle webhooks', async () => {
    const dispatched: Array<{ eventType: string; payload: Record<string, unknown> }> = [];
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async (input) => {
          const body = JSON.parse(input.body) as Record<string, unknown>;
          dispatched.push({
            eventType: String(body.type || ''),
            payload:
              body.data && typeof body.data === 'object' && !Array.isArray(body.data)
                ? (body.data as Record<string, unknown>)
                : {},
          });
          return { ok: true, statusCode: 200, responseBody: 'ok' };
        },
      },
    });
    await webhooks.createEndpoint(
      { orgId: 'org-relay-cf-warm', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session'],
      },
    );

    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: { sub: 'user-oidc-cf-warm-1', kind: 'app_session_v1', appSessionVersion: 'app-v1' },
      }),
      refresh: async () => ({ ok: true, jwt: 'refreshed-cf-warm-1' }),
    });
    const service = makeFakeAuthService({
      verifyOidcJwtExchange: async () => ({
        ok: true,
        verified: true,
        userId: 'user-oidc-cf-warm-1',
        providerSubject: 'oidc:https://issuer.example.com:user-cf-warm-1',
      }),
      getOrCreateAppSessionVersion: async () => ({ ok: true, appSessionVersion: 'app-v1' }),
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-cf-warm',
      },
    });

    const exchange = await callCf(handler, {
      method: 'POST',
      path: '/session/exchange',
      origin: 'https://example.localhost',
      body: {
        sessionKind: 'jwt',
        exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
      },
    });
    expect(exchange.status).toBe(200);

    const refresh = await callCf(handler, {
      method: 'POST',
      path: '/session/refresh',
      origin: 'https://example.localhost',
      body: { sessionKind: 'jwt' },
    });
    expect(refresh.status).toBe(200);

    expect(dispatched.map((item) => item.eventType)).toEqual([
      'session.warm.created',
      'session.warm.refreshed',
    ]);
    expect(dispatched[0]?.payload?.sessionKind).toBe('jwt');
    expect(dispatched[1]?.payload?.refreshed).toBe(true);
  });

  test('POST /session/exchange: failure emits session.exchange.failed webhook', async () => {
    const dispatched: Array<{ eventType: string; payload: Record<string, unknown> }> = [];
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async (input) => {
          const body = JSON.parse(input.body) as Record<string, unknown>;
          dispatched.push({
            eventType: String(body.type || ''),
            payload:
              body.data && typeof body.data === 'object' && !Array.isArray(body.data)
                ? (body.data as Record<string, unknown>)
                : {},
          });
          return { ok: true, statusCode: 200, responseBody: 'ok' };
        },
      },
    });
    await webhooks.createEndpoint(
      { orgId: 'org-relay-cf-1', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session'],
      },
    );

    const session = makeSessionAdapter();
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-cf-1',
      },
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/session/exchange',
      origin: 'https://example.localhost',
      body: {
        sessionKind: 'cookie',
        exchange: { type: 'not_oidc', token: 'header.payload.signature' },
      },
    });
    expect(res.status).toBe(400);
    expect(res.json?.code).toBe('invalid_body');
    expect(dispatched.length).toBe(1);
    expect(dispatched[0]?.eventType).toBe('session.exchange.failed');
    expect(dispatched[0]?.payload?.code).toBe('invalid_body');
    expect(dispatched[0]?.payload?.sessionKind).toBe('cookie');
    expect(dispatched[0]?.payload?.orgId).toBe('org-relay-cf-1');
  });

  test('POST /session/exchange: unsupported verifier capability maps to 501', async () => {
    const session = makeSessionAdapter();
    const service = makeFakeAuthService({
      verifyOidcJwtExchange: async () => ({
        ok: false,
        verified: false,
        code: 'unsupported',
        message: 'WebCrypto unavailable',
      }),
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/session/exchange',
      origin: 'https://example.localhost',
      body: {
        sessionKind: 'jwt',
        exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
      },
    });
    expect(res.status).toBe(501);
    expect(res.json?.ok).toBe(false);
    expect(res.json?.code).toBe('unsupported');
  });

  test('POST /session/refresh: unauthorized maps to 401', async () => {
    const session = makeSessionAdapter({
      refresh: async () => ({ ok: false, code: 'unauthorized', message: 'no token' }),
    });
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/session/refresh',
      origin: 'https://example.localhost',
      body: { sessionKind: 'jwt' },
    });

    expect(res.status).toBe(401);
    expect(res.json?.code).toBe('unauthorized');
  });

  test('POST /session/refresh: unauthorized emits session.warm.expired webhook', async () => {
    const dispatched: Array<{ eventType: string; payload: Record<string, unknown> }> = [];
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async (input) => {
          const body = JSON.parse(input.body) as Record<string, unknown>;
          dispatched.push({
            eventType: String(body.type || ''),
            payload:
              body.data && typeof body.data === 'object' && !Array.isArray(body.data)
                ? (body.data as Record<string, unknown>)
                : {},
          });
          return { ok: true, statusCode: 200, responseBody: 'ok' };
        },
      },
    });
    await webhooks.createEndpoint(
      { orgId: 'org-relay-cf-expired', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session'],
      },
    );

    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: { sub: 'user-expired-cf-1', kind: 'app_session_v1', appSessionVersion: 'app-v1' },
      }),
      refresh: async () => ({ ok: false, code: 'unauthorized', message: 'session expired' }),
    });
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-cf-expired',
      },
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/session/refresh',
      origin: 'https://example.localhost',
      body: { sessionKind: 'jwt' },
    });
    expect(res.status).toBe(401);
    expect(res.json?.code).toBe('unauthorized');
    expect(dispatched.length).toBe(1);
    expect(dispatched[0]?.eventType).toBe('session.warm.expired');
    expect(dispatched[0]?.payload?.expired).toBe(true);
    expect(dispatched[0]?.payload?.source).toBe('session.refresh');
    expect(dispatched[0]?.payload?.userId).toBe('user-expired-cf-1');
  });

  test('POST /session/revoke: rotates app-session-version and clears cookie', async () => {
    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: { sub: 'bob.testnet', kind: 'app_session_v1', appSessionVersion: 'v1' },
      }),
      buildClearCookie: () => 'tatchi-jwt=; Path=/; Max-Age=0',
    });
    const service = makeFakeAuthService({
      rotateAppSessionVersion: async () => ({ ok: true, appSessionVersion: 'v2' }),
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/session/revoke',
      origin: 'https://example.localhost',
      headers: { Authorization: 'Bearer token' },
    });

    expect(res.status).toBe(200);
    expect(res.json?.ok).toBe(true);
    expect(res.json?.revoked).toBe(true);
    expect(res.headers.get('set-cookie')).toContain('Max-Age=0');
  });

  test('POST /session/revoke: stale app session is rejected on subsequent protected call', async () => {
    let currentAppSessionVersion = 'v1';
    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: {
          sub: 'bob.testnet',
          kind: 'app_session_v1',
          // Simulate a previously-issued token that keeps presenting v1.
          appSessionVersion: 'v1',
        },
      }),
      buildClearCookie: () => 'tatchi-jwt=; Path=/; Max-Age=0',
    });
    const service = makeFakeAuthService({
      validateAppSessionVersion: async (args: any) => ({
        ok: String(args?.appSessionVersion || '').trim() === currentAppSessionVersion,
        code: 'invalid_session_version',
        message: 'Session revoked',
      }),
      rotateAppSessionVersion: async () => {
        currentAppSessionVersion = 'v2';
        return { ok: true, appSessionVersion: currentAppSessionVersion };
      },
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const revoke = await callCf(handler, {
      method: 'POST',
      path: '/session/revoke',
      origin: 'https://example.localhost',
      headers: { Authorization: 'Bearer stale-token' },
    });
    expect(revoke.status).toBe(200);
    expect(revoke.json?.ok).toBe(true);

    const state = await callCf(handler, {
      method: 'GET',
      path: '/session/state',
      origin: 'https://example.localhost',
      headers: { Authorization: 'Bearer stale-token' },
    });
    expect(state.status).toBe(401);
    expect(state.json?.authenticated).toBe(false);
    expect(state.json?.code).toBe('invalid_session_version');
  });

  test('GET /session/state: invalid_session_version emits session.warm.expired webhook', async () => {
    const dispatched: Array<{ eventType: string; payload: Record<string, unknown> }> = [];
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async (input) => {
          const body = JSON.parse(input.body) as Record<string, unknown>;
          dispatched.push({
            eventType: String(body.type || ''),
            payload:
              body.data && typeof body.data === 'object' && !Array.isArray(body.data)
                ? (body.data as Record<string, unknown>)
                : {},
          });
          return { ok: true, statusCode: 200, responseBody: 'ok' };
        },
      },
    });
    await webhooks.createEndpoint(
      { orgId: 'org-relay-cf-invalid-version', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session'],
      },
    );

    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: {
          sub: 'bob.testnet',
          kind: 'app_session_v1',
          appSessionVersion: 'v1',
        },
      }),
    });
    const service = makeFakeAuthService({
      validateAppSessionVersion: async () => ({
        ok: false,
        code: 'invalid_session_version',
        message: 'Session revoked',
      }),
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-cf-invalid-version',
      },
    });

    const state = await callCf(handler, {
      method: 'GET',
      path: '/session/state',
      origin: 'https://example.localhost',
      headers: { Authorization: 'Bearer stale-token' },
    });
    expect(state.status).toBe(401);
    expect(state.json?.code).toBe('invalid_session_version');
    expect(dispatched.length).toBe(1);
    expect(dispatched[0]?.eventType).toBe('session.warm.expired');
    expect(dispatched[0]?.payload?.source).toBe('session.state');
    expect(dispatched[0]?.payload?.userId).toBe('bob.testnet');
    expect(dispatched[0]?.payload?.code).toBe('invalid_session_version');
  });

  test('POST /wallet/unlock/options: returns passkey challenge options', async () => {
    const service = makeFakeAuthService({
      createWebAuthnLoginOptions: async () => ({
        ok: true,
        challengeId: 'wallet-unlock-cid-cf-1',
        challengeB64u: 'wallet-unlock-challenge-cf',
        expiresAtMs: 123,
      }),
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/wallet/unlock/options',
      origin: 'https://example.localhost',
      body: validLoginOptionsBody(),
    });

    expect(res.status).toBe(200);
    expect(res.json?.ok).toBe(true);
    expect(res.json?.challengeId).toBe('wallet-unlock-cid-cf-1');
  });

  test('POST /wallet/unlock/verify: verified passkey assertion returns unlocked', async () => {
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async () => ({
        ok: true,
        verified: true,
        userId: 'bob.testnet',
        rpId: 'example.localhost',
      }),
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/wallet/unlock/verify',
      origin: 'https://example.localhost',
      body: validLoginVerifyBody({ sessionKind: undefined }),
    });

    expect(res.status).toBe(200);
    expect(res.json?.ok).toBe(true);
    expect(res.json?.unlocked).toBe(true);
    expect(res.json?.userId).toBe('bob.testnet');
    expect(res.json?.jwt).toBeUndefined();
  });

  test('GET /wallet/state: valid app session reports unlocked state', async () => {
    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: { sub: 'bob.testnet', kind: 'app_session_v1', appSessionVersion: 'v1' },
      }),
    });
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/wallet/state',
      origin: 'https://example.localhost',
    });
    expect(res.status).toBe(200);
    expect(res.json?.ok).toBe(true);
    expect(res.json?.locked).toBe(false);
    expect(res.json?.userId).toBe('bob.testnet');
  });

  test('POST /wallet/lock: rotates app-session-version and clears cookie', async () => {
    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: { sub: 'bob.testnet', kind: 'app_session_v1', appSessionVersion: 'v1' },
      }),
      buildClearCookie: () => 'tatchi-jwt=; Path=/; Max-Age=0',
    });
    const service = makeFakeAuthService({
      rotateAppSessionVersion: async () => ({ ok: true, appSessionVersion: 'v2' }),
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/wallet/lock',
      origin: 'https://example.localhost',
      headers: { Authorization: 'Bearer token' },
    });
    expect(res.status).toBe(200);
    expect(res.json?.ok).toBe(true);
    expect(res.json?.locked).toBe(true);
    expect(res.json?.userId).toBe('bob.testnet');
    expect(res.headers.get('set-cookie')).toContain('Max-Age=0');
  });

  test('POST /wallet/lock: stale app session is rejected on subsequent protected call', async () => {
    let currentAppSessionVersion = 'v1';
    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: {
          sub: 'bob.testnet',
          kind: 'app_session_v1',
          // Simulate a previously-issued token that keeps presenting v1.
          appSessionVersion: 'v1',
        },
      }),
      buildClearCookie: () => 'tatchi-jwt=; Path=/; Max-Age=0',
    });
    const service = makeFakeAuthService({
      validateAppSessionVersion: async (args: any) => ({
        ok: String(args?.appSessionVersion || '').trim() === currentAppSessionVersion,
        code: 'invalid_session_version',
        message: 'Session locked',
      }),
      rotateAppSessionVersion: async () => {
        currentAppSessionVersion = 'v2';
        return { ok: true, appSessionVersion: currentAppSessionVersion };
      },
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
    });

    const lock = await callCf(handler, {
      method: 'POST',
      path: '/wallet/lock',
      origin: 'https://example.localhost',
      headers: { Authorization: 'Bearer stale-token' },
    });
    expect(lock.status).toBe(200);
    expect(lock.json?.ok).toBe(true);

    const state = await callCf(handler, {
      method: 'GET',
      path: '/wallet/state',
      origin: 'https://example.localhost',
      headers: { Authorization: 'Bearer stale-token' },
    });
    expect(state.status).toBe(401);
    expect(state.json?.ok).toBe(false);
    expect(state.json?.locked).toBe(true);
    expect(state.json?.code).toBe('invalid_session_version');
  });

  test('wallet/session lifecycle routes emit wallet/session webhook events', async () => {
    const dispatched: Array<{ eventType: string; payload: Record<string, unknown> }> = [];
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async (input) => {
          const body = JSON.parse(input.body) as Record<string, unknown>;
          dispatched.push({
            eventType: String(body.type || ''),
            payload:
              body.data && typeof body.data === 'object' && !Array.isArray(body.data)
                ? (body.data as Record<string, unknown>)
                : {},
          });
          return { ok: true, statusCode: 200, responseBody: 'ok' };
        },
      },
    });
    await webhooks.createEndpoint(
      { orgId: 'org-relay-cf-2', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session', 'wallet'],
      },
    );

    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: { sub: 'bob.testnet', kind: 'app_session_v1', appSessionVersion: 'v1' },
      }),
      buildClearCookie: () => 'tatchi-jwt=; Path=/; Max-Age=0',
    });
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async () => ({
        ok: true,
        verified: true,
        userId: 'bob.testnet',
        rpId: 'example.localhost',
      }),
      rotateAppSessionVersion: async () => ({ ok: true, appSessionVersion: 'v2' }),
    });
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-cf-2',
      },
    });

    const unlock = await callCf(handler, {
      method: 'POST',
      path: '/wallet/unlock/verify',
      origin: 'https://example.localhost',
      body: validLoginVerifyBody({ sessionKind: undefined }),
    });
    expect(unlock.status).toBe(200);

    const revoke = await callCf(handler, {
      method: 'POST',
      path: '/session/revoke',
      origin: 'https://example.localhost',
      headers: { Authorization: 'Bearer app-session' },
    });
    expect(revoke.status).toBe(200);

    const lock = await callCf(handler, {
      method: 'POST',
      path: '/wallet/lock',
      origin: 'https://example.localhost',
      headers: { Authorization: 'Bearer app-session' },
    });
    expect(lock.status).toBe(200);

    expect(dispatched.map((item) => item.eventType)).toEqual([
      'wallet.unlocked',
      'session.revoked',
      'wallet.locked',
    ]);
    expect(dispatched[0]?.payload?.userId).toBe('bob.testnet');
    expect(dispatched[1]?.payload?.userId).toBe('bob.testnet');
    expect(dispatched[2]?.payload?.userId).toBe('bob.testnet');
    expect(dispatched[2]?.payload?.orgId).toBe('org-relay-cf-2');
  });

  test('POST /threshold-ed25519/authorize validates runtime snapshot checksum against latest scoped snapshot', async () => {
    let authorizeCalls = 0;
    const service = makeFakeAuthService();
    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: {
          sub: 'bob.testnet',
          kind: 'threshold_ed25519_session_v1',
          sessionId: 'session-ed25519-runtime-cf',
          relayerKeyId: 'relayer-key-cf-1',
          rpId: 'example.localhost',
          thresholdExpiresAtMs: Date.now() + 60_000,
          participantIds: [1, 2],
          runtimeSnapshotScope: {
            orgId: 'org-runtime-cf-1',
            projectId: 'project-runtime-cf-1',
            environmentId: 'env-runtime-cf-1',
          },
        },
      }),
    });
    const threshold = makeEd25519ThresholdAdapter({
      authorize: async () => {
        authorizeCalls += 1;
        return { ok: true, mpcSessionId: 'mpc-runtime-cf-1' };
      },
    });
    const handler = createCloudflareRouter(service, {
      session,
      threshold: threshold as any,
      runtimeSnapshots: {
        getLatestSnapshot: async () => ({
          snapshotId: 'snapshot-runtime-cf-latest',
          version: 5,
          checksum: 'fnv1a32:runtime-cf-checksum',
          effectiveAt: '2026-03-01T00:00:00.000Z',
        }),
      },
    });

    const okRes = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/authorize',
      headers: { Authorization: 'Bearer token' },
      body: {
        relayerKeyId: 'relayer-key-cf-1',
        clientVerifyingShareB64u: 'client-share',
        purpose: 'near_tx',
        signing_digest_32: new Array(32).fill(1),
        runtimeSnapshot: {
          checksum: 'fnv1a32:runtime-cf-checksum',
          version: 5,
        },
      },
    });
    expect(okRes.status).toBe(200);
    expect(okRes.json?.ok).toBe(true);
    expect(authorizeCalls).toBe(1);

    const mismatchRes = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/authorize',
      headers: { Authorization: 'Bearer token' },
      body: {
        relayerKeyId: 'relayer-key-cf-1',
        clientVerifyingShareB64u: 'client-share',
        purpose: 'near_tx',
        signing_digest_32: new Array(32).fill(1),
        runtimeSnapshot: {
          checksum: 'fnv1a32:runtime-cf-checksum-stale',
          version: 5,
        },
      },
    });
    expect(mismatchRes.status).toBe(409);
    expect(mismatchRes.json?.code).toBe('runtime_snapshot_checksum_mismatch');
    expect(authorizeCalls).toBe(1);
  });

  test('POST /session/logout: removed (404)', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/session/logout',
      origin: 'https://example.localhost',
    });

    expect(res.status).toBe(404);
  });

  test('GET /session/auth: removed (404)', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
    });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/session/auth',
      origin: 'https://example.localhost',
    });

    expect(res.status).toBe(404);
  });

  test('POST /recover-email: async mode uses ctx.waitUntil and returns 202 queued', async () => {
    const { ctx, waited } = makeCfCtx();
    const emailRecovery = {
      requestEmailRecovery: async () => ({ success: true, transactionHash: 'tx' }),
    };
    const service = makeFakeAuthService({ emailRecovery });
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/recover-email?async=1',
      origin: 'https://example.localhost',
      body: {
        from: 'sender@example.com',
        to: 'recover@web3authn.org',
        headers: { Subject: 'recover-ABC123 bob.testnet ed25519:pk' },
        raw: 'Subject: recover-ABC123 bob.testnet ed25519:pk\r\n\r\ntee-encrypted',
        rawSize: 1,
      },
      ctx,
    });

    expect(res.status).toBe(202);
    expect(res.json?.queued).toBe(true);
    expect(waited.length).toBe(1);
  });
});
