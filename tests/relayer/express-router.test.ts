import { test, expect } from '@playwright/test';
import {
  createAppSessionConsoleAuthAdapter,
  createConsoleRouter,
  createInMemoryConsoleAuditService,
  createInMemoryConsoleOrgProjectEnvService,
  createInMemoryConsoleTeamRbacService,
  createInMemoryConsoleWebhookService,
  createRelayRouter,
} from '@server/router/express-adaptor';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '@server/core/ThresholdService/schemes/schemeIds';
import {
  fetchJson,
  getPath,
  makeFakeAuthService,
  makeSessionAdapter,
  startExpressRouter,
} from './helpers';

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

test.describe('relayer router (express) – P0', () => {
  test('CORS preflight: default HTTPS port in allowlist still matches origin without explicit port', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      corsOrigins: ['https://wallet.example.localhost:443'],
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetch(`${srv.baseUrl}/sync-account/verify`, {
        method: 'OPTIONS',
        headers: {
          Origin: 'https://wallet.example.localhost',
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'content-type',
        },
      });
      expect(res.status).toBe(204);
      expect(res.headers.get('access-control-allow-origin')).toBe(
        'https://wallet.example.localhost',
      );
      expect(res.headers.get('access-control-allow-credentials')).toBe('true');
    } finally {
      await srv.close();
    }
  });

  test('POST /auth/passkey/options: invalid body', async () => {
    const service = makeFakeAuthService({
      createWebAuthnLoginOptions: async () => ({
        ok: false,
        code: 'invalid_body',
        message: 'Missing user_id',
      }),
    });
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/auth/passkey/options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
      expect(res.json?.code).toBe('invalid_body');
    } finally {
      await srv.close();
    }
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
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/auth/passkey/options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validLoginOptionsBody()),
      });
      expect(res.status).toBe(200);
      expect(res.json?.challengeId).toBe('cid-123');
    } finally {
      await srv.close();
    }
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
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/sync-account/options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rp_id: 'example.localhost', account_id: 'bob.testnet' }),
      });
      expect(res.status).toBe(200);
      expect(res.json?.challengeId).toBe('sync-cid-123');
      expect(res.json?.credentialIds).toEqual(['cred-a', 'cred-b']);
      expect((receivedBody as Record<string, unknown> | null)?.['rp_id']).toBe(
        'example.localhost',
      );
      expect((receivedBody as Record<string, unknown> | null)?.['account_id']).toBe('bob.testnet');
    } finally {
      await srv.close();
    }
  });

  test('POST /auth/passkey/verify: invalid body', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/auth/passkey/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
      expect(res.json?.code).toBe('invalid_body');
    } finally {
      await srv.close();
    }
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
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/auth/passkey/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validLoginVerifyBody()),
      });
      expect(res.status).toBe(400);
      expect(res.json?.code).toBe('not_verified');
    } finally {
      await srv.close();
    }
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
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/auth/passkey/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validLoginVerifyBody({ sessionKind: 'jwt' })),
      });
      expect(res.status).toBe(200);
      expect(res.json?.verified).toBe(true);
      expect(res.json?.jwt).toBeUndefined();
    } finally {
      await srv.close();
    }
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
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/auth/passkey/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validLoginVerifyBody({ sessionKind: 'cookie' })),
      });
      expect(res.status).toBe(200);
      expect(res.headers.get('set-cookie')).toBeNull();
      expect(res.json?.verified).toBe(true);
      expect(res.json?.jwt).toBeUndefined();
    } finally {
      await srv.close();
    }
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
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/auth/passkey/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validLoginVerifyBody({ sessionKind: 'jwt' })),
      });
      expect(res.status).toBe(200);
      expect(res.json?.verified).toBe(true);
      expect(res.json?.jwt).toBeUndefined();
    } finally {
      await srv.close();
    }
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
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/auth/google/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'cookie',
          idToken: 'header.payload.signature',
        }),
      });
      expect(res.status).toBe(200);
      expect(res.json?.verified).toBe(true);
      expect(res.json?.email).toBe('bob@example.com');
      expect(res.json?.jwt).toBeUndefined();
      expect(res.headers.get('set-cookie')).toBeNull();
    } finally {
      await srv.close();
    }
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
      { orgId: 'org-relay-express-auth-identities-parse-fail', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session'],
      },
    );

    const session = makeSessionAdapter({ parse: async () => ({ ok: false }) });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-express-auth-identities-parse-fail',
      },
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/auth/identities`, {
        method: 'GET',
        headers: { Authorization: 'Bearer stale-token' },
      });
      expect(res.status).toBe(401);
      expect(res.json?.code).toBe('unauthorized');
      expect(dispatched.length).toBe(1);
      expect(dispatched[0]?.eventType).toBe('session.warm.expired');
      expect(dispatched[0]?.payload?.source).toBe('auth.identities');
      expect(dispatched[0]?.payload?.code).toBe('unauthorized');
      expect(dispatched[0]?.payload?.orgId).toBe('org-relay-express-auth-identities-parse-fail');
    } finally {
      await srv.close();
    }
  });

  test('POST /smart-account/deploy: default route returns assumed_deployed', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/smart-account/deploy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validSmartAccountDeployBody()),
      });
      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);
      expect(res.json?.code).toBe('assumed_deployed');
    } finally {
      await srv.close();
    }
  });

  test('POST /smart-account/deploy: custom hook response is returned', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      smartAccountDeploy: async (req) => {
        expect(req.nearAccountId).toBe('bob.testnet');
        expect(req.chain).toBe('tempo');
        return { ok: true, deploymentTxHash: '0xdeploytx' };
      },
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/smart-account/deploy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validSmartAccountDeployBody()),
      });
      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);
      expect(res.json?.deploymentTxHash).toBe('0xdeploytx');
    } finally {
      await srv.close();
    }
  });

  test('POST /threshold-ecdsa/keygen and /threshold-ecdsa/session: removed (404)', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const keygen = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/keygen`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(keygen.status).toBe(404);

      const session = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(session.status).toBe(404);
    } finally {
      await srv.close();
    }
  });

  test('GET /session/state: sessions disabled -> 501', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/state`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('sessions_disabled');
      expect(res.json?.authenticated).toBe(false);
    } finally {
      await srv.close();
    }
  });

  test('GET /session/state: valid session -> 200 with claims', async () => {
    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: { sub: 'bob.testnet', kind: 'app_session_v1', appSessionVersion: 'v1' },
      }),
    });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/state`, { method: 'GET' });
      expect(res.status).toBe(200);
      expect(res.json?.authenticated).toBe(true);
      expect(getPath(res.json, 'claims', 'sub')).toBe('bob.testnet');
    } finally {
      await srv.close();
    }
  });

  test('GET /session/state: returns authenticated app session claims', async () => {
    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: { sub: 'bob.testnet', kind: 'app_session_v1', appSessionVersion: 'v1' },
      }),
    });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/state`, { method: 'GET' });
      expect(res.status).toBe(200);
      expect(res.json?.authenticated).toBe(true);
      expect(getPath(res.json, 'claims', 'sub')).toBe('bob.testnet');
    } finally {
      await srv.close();
    }
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
      { orgId: 'org-relay-express-parse-fail', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session'],
      },
    );
    const session = makeSessionAdapter({ parse: async () => ({ ok: false }) });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-express-parse-fail',
      },
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/state`, {
        method: 'GET',
        headers: { Authorization: 'Bearer stale-token' },
      });
      expect(res.status).toBe(401);
      expect(res.json?.authenticated).toBe(false);
      expect(dispatched.length).toBe(1);
      expect(dispatched[0]?.eventType).toBe('session.warm.expired');
      expect(dispatched[0]?.payload?.source).toBe('session.state');
      expect(dispatched[0]?.payload?.code).toBe('unauthorized');
      expect(dispatched[0]?.payload?.orgId).toBe('org-relay-express-parse-fail');
    } finally {
      await srv.close();
    }
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
      { orgId: 'org-relay-express-cookie-parse-fail', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session'],
      },
    );
    const session = makeSessionAdapter({ parse: async () => ({ ok: false }) });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-express-cookie-parse-fail',
      },
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/state`, {
        method: 'GET',
        headers: { Cookie: 'tatchi-jwt=stale-cookie-token' },
      });
      expect(res.status).toBe(401);
      expect(res.json?.authenticated).toBe(false);
      expect(dispatched.length).toBe(1);
      expect(dispatched[0]?.eventType).toBe('session.warm.expired');
      expect(dispatched[0]?.payload?.source).toBe('session.state');
      expect(dispatched[0]?.payload?.code).toBe('unauthorized');
      expect(dispatched[0]?.payload?.orgId).toBe('org-relay-express-cookie-parse-fail');
    } finally {
      await srv.close();
    }
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
      {
        orgId: 'org-relay-express-cookie-nonmatch',
        actorUserId: 'test-admin',
        roles: ['admin'],
      },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session'],
      },
    );
    const session = makeSessionAdapter({ parse: async () => ({ ok: false }) });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-express-cookie-nonmatch',
      },
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/state`, {
        method: 'GET',
        headers: { Cookie: 'other-cookie=stale-cookie-token' },
      });
      expect(res.status).toBe(401);
      expect(res.json?.authenticated).toBe(false);
      expect(dispatched.length).toBe(0);
    } finally {
      await srv.close();
    }
  });

  test('POST /session/exchange: oidc_jwt -> app session jwt', async () => {
    const expSeconds = 1_893_456_000; // 2030-01-01T00:00:00.000Z
    const session = makeSessionAdapter({ signJwt: async () => makeUnsignedJwtWithExp(expSeconds) });
    const service = makeFakeAuthService({
      verifyOidcJwtExchange: async () => ({
        ok: true,
        verified: true,
        userId: 'user-oidc-1',
        providerSubject: 'oidc:https://issuer.example.com:user-123',
        iss: 'https://issuer.example.com',
        aud: ['wallet-app'],
        sub: 'user-123',
      }),
      getOrCreateAppSessionVersion: async () => ({ ok: true, appSessionVersion: 'app-v1' }),
    });
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'jwt',
          exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
        }),
      });
      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);
      expect(getPath(res.json, 'session', 'kind')).toBe('app_session_v1');
      expect(getPath(res.json, 'session', 'userId')).toBe('user-oidc-1');
      expect(getPath(res.json, 'session', 'expiresAt')).toBe('2030-01-01T00:00:00.000Z');
      expect(typeof res.json?.jwt).toBe('string');
    } finally {
      await srv.close();
    }
  });

  test('POST /session/exchange: oidc_jwt + sessionKind=cookie sets cookie and omits jwt', async () => {
    const session = makeSessionAdapter({
      signJwt: async () => 'app-jwt-cookie-123',
      buildSetCookie: (t) => `tatchi-jwt=${t}; Path=/; HttpOnly`,
    });
    const service = makeFakeAuthService({
      verifyOidcJwtExchange: async () => ({
        ok: true,
        verified: true,
        userId: 'user-oidc-cookie-1',
        providerSubject: 'oidc:https://issuer.example.com:user-cookie-1',
      }),
      getOrCreateAppSessionVersion: async () => ({ ok: true, appSessionVersion: 'app-v1' }),
    });
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'cookie',
          exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
        }),
      });
      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);
      expect(getPath(res.json, 'session', 'kind')).toBe('app_session_v1');
      expect(getPath(res.json, 'session', 'userId')).toBe('user-oidc-cookie-1');
      expect(getPath(res.json, 'session', 'expiresAt')).toBeUndefined();
      expect(res.json?.jwt).toBeUndefined();
      expect(res.headers.get('set-cookie')).toContain('tatchi-jwt=app-jwt-cookie-123');
    } finally {
      await srv.close();
    }
  });

  test('POST /session/exchange + /session/revoke: oidc_jwt cookie session is invalidated after revoke', async () => {
    const issuedClaimsByToken = new Map<string, { sub: string; appSessionVersion: string }>();
    let currentAppSessionVersion = 'v1';

    const parseCookieToken = (cookieHeader: string): string | null => {
      for (const part of cookieHeader.split(';')) {
        const chunk = String(part || '').trim();
        if (!chunk) continue;
        const equalsIndex = chunk.indexOf('=');
        const name = (equalsIndex >= 0 ? chunk.slice(0, equalsIndex) : chunk).trim();
        if (name !== 'tatchi-jwt') continue;
        const value = (equalsIndex >= 0 ? chunk.slice(equalsIndex + 1) : '').trim();
        return value || null;
      }
      return null;
    };

    const session = makeSessionAdapter({
      signJwt: async (sub, extra) => {
        const appSessionVersion =
          typeof extra?.appSessionVersion === 'string'
            ? String(extra.appSessionVersion).trim()
            : '';
        const token = `app-session:${sub}:${appSessionVersion}:${issuedClaimsByToken.size + 1}`;
        issuedClaimsByToken.set(token, { sub, appSessionVersion });
        return token;
      },
      parse: async (headers) => {
        const cookieHeaderValue = headers.cookie ?? headers.Cookie;
        const cookieHeader =
          typeof cookieHeaderValue === 'string'
            ? cookieHeaderValue
            : Array.isArray(cookieHeaderValue)
              ? String(cookieHeaderValue[0] || '')
              : '';
        const token = parseCookieToken(cookieHeader);
        if (!token) return { ok: false } as const;
        const claims = issuedClaimsByToken.get(token);
        if (!claims) return { ok: false } as const;
        return {
          ok: true as const,
          claims: {
            sub: claims.sub,
            kind: 'app_session_v1',
            appSessionVersion: claims.appSessionVersion,
          },
        };
      },
      buildSetCookie: (token) => `tatchi-jwt=${token}; Path=/; HttpOnly`,
      buildClearCookie: () => 'tatchi-jwt=; Path=/; Max-Age=0',
    });
    const service = makeFakeAuthService({
      verifyOidcJwtExchange: async () => ({
        ok: true,
        verified: true,
        userId: 'user-oidc-cookie-revoke-1',
        providerSubject: 'oidc:https://issuer.example.com:user-oidc-cookie-revoke-1',
      }),
      getOrCreateAppSessionVersion: async () => ({
        ok: true,
        appSessionVersion: currentAppSessionVersion,
      }),
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
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const exchange = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'cookie',
          exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
        }),
      });
      expect(exchange.status).toBe(200);
      expect(exchange.json?.ok).toBe(true);
      const issuedCookieHeader = String(exchange.headers.get('set-cookie') || '');
      expect(issuedCookieHeader).toContain('tatchi-jwt=');
      const cookieHeader = String(issuedCookieHeader.split(';')[0] || '').trim();
      expect(cookieHeader).toMatch(/^tatchi-jwt=/);

      const stateBefore = await fetchJson(`${srv.baseUrl}/session/state`, {
        method: 'GET',
        headers: { Cookie: cookieHeader },
      });
      expect(stateBefore.status).toBe(200);
      expect(stateBefore.json?.authenticated).toBe(true);

      const revoke = await fetchJson(`${srv.baseUrl}/session/revoke`, {
        method: 'POST',
        headers: { Cookie: cookieHeader },
      });
      expect(revoke.status).toBe(200);
      expect(revoke.json?.ok).toBe(true);
      expect(revoke.json?.revoked).toBe(true);
      expect(revoke.headers.get('set-cookie')).toContain('Max-Age=0');

      const stateAfter = await fetchJson(`${srv.baseUrl}/session/state`, {
        method: 'GET',
        headers: { Cookie: cookieHeader },
      });
      expect(stateAfter.status).toBe(401);
      expect(stateAfter.json?.authenticated).toBe(false);
      expect(stateAfter.json?.code).toBe('invalid_session_version');
    } finally {
      await srv.close();
    }
  });

  test('POST /session/exchange -> GET /console/session -> POST /session/revoke invalidates console session', async () => {
    const issuedClaimsByToken = new Map<string, { sub: string; appSessionVersion: string }>();
    let currentAppSessionVersion = 'v1';

    const parseCookieToken = (cookieHeader: string): string | null => {
      for (const part of cookieHeader.split(';')) {
        const chunk = String(part || '').trim();
        if (!chunk) continue;
        const equalsIndex = chunk.indexOf('=');
        const name = (equalsIndex >= 0 ? chunk.slice(0, equalsIndex) : chunk).trim();
        if (name !== 'tatchi-jwt') continue;
        const value = (equalsIndex >= 0 ? chunk.slice(equalsIndex + 1) : '').trim();
        return value || null;
      }
      return null;
    };

    const session = makeSessionAdapter({
      signJwt: async (sub, extra) => {
        const appSessionVersion =
          typeof extra?.appSessionVersion === 'string'
            ? String(extra.appSessionVersion).trim()
            : '';
        const token = `app-session:${sub}:${appSessionVersion}:${issuedClaimsByToken.size + 1}`;
        issuedClaimsByToken.set(token, { sub, appSessionVersion });
        return token;
      },
      parse: async (headers) => {
        const cookieHeaderValue = headers.cookie ?? headers.Cookie;
        const cookieHeader =
          typeof cookieHeaderValue === 'string'
            ? cookieHeaderValue
            : Array.isArray(cookieHeaderValue)
              ? String(cookieHeaderValue[0] || '')
              : '';
        const token = parseCookieToken(cookieHeader);
        if (!token) return { ok: false } as const;
        const claims = issuedClaimsByToken.get(token);
        if (!claims) return { ok: false } as const;
        return {
          ok: true as const,
          claims: {
            sub: claims.sub,
            kind: 'app_session_v1',
            appSessionVersion: claims.appSessionVersion,
          },
        };
      },
      buildSetCookie: (token) => `tatchi-jwt=${token}; Path=/; HttpOnly`,
      buildClearCookie: () => 'tatchi-jwt=; Path=/; Max-Age=0',
    });
    const service = makeFakeAuthService({
      verifyOidcJwtExchange: async () => ({
        ok: true,
        verified: true,
        userId: 'user-oidc-console-express-1',
        providerSubject: 'oidc:https://issuer.example.com:user-oidc-console-express-1',
      }),
      getOrCreateAppSessionVersion: async () => ({
        ok: true,
        appSessionVersion: currentAppSessionVersion,
      }),
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

    const consoleAuth = createAppSessionConsoleAuthAdapter({
      session,
      authService: service,
      defaultOrgId: 'org-oidc-console-express-1',
      fallbackRoles: ['admin'],
    });

    const relayRouter = createRelayRouter(service, { session }) as any;
    relayRouter.use(createConsoleRouter({ auth: consoleAuth }));
    const srv = await startExpressRouter(relayRouter);
    try {
      const exchange = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'cookie',
          exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
        }),
      });
      expect(exchange.status).toBe(200);
      const issuedCookieHeader = String(exchange.headers.get('set-cookie') || '');
      const cookieHeader = String(issuedCookieHeader.split(';')[0] || '').trim();
      expect(cookieHeader).toMatch(/^tatchi-jwt=/);

      const consoleSessionBefore = await fetchJson(`${srv.baseUrl}/console/session`, {
        method: 'GET',
        headers: { Cookie: cookieHeader },
      });
      expect(consoleSessionBefore.status).toBe(200);
      expect(consoleSessionBefore.json?.ok).toBe(true);
      expect(getPath(consoleSessionBefore.json, 'claims', 'userId')).toBe(
        'user-oidc-console-express-1',
      );
      expect(getPath(consoleSessionBefore.json, 'claims', 'orgId')).toBe('org-oidc-console-express-1');

      const revoke = await fetchJson(`${srv.baseUrl}/session/revoke`, {
        method: 'POST',
        headers: { Cookie: cookieHeader },
      });
      expect(revoke.status).toBe(200);
      expect(revoke.json?.ok).toBe(true);
      expect(revoke.json?.revoked).toBe(true);

      const consoleSessionAfter = await fetchJson(`${srv.baseUrl}/console/session`, {
        method: 'GET',
        headers: { Cookie: cookieHeader },
      });
      expect(consoleSessionAfter.status).toBe(401);
      expect(consoleSessionAfter.json?.ok).toBe(false);
      expect(consoleSessionAfter.json?.code).toBe('unauthorized');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/session: authenticated user without membership is forbidden', async () => {
    const issuedClaimsByToken = new Map<string, { sub: string; appSessionVersion: string }>();
    const parseCookieToken = (cookieHeader: string): string | null => {
      for (const part of cookieHeader.split(';')) {
        const chunk = String(part || '').trim();
        if (!chunk) continue;
        const equalsIndex = chunk.indexOf('=');
        const name = (equalsIndex >= 0 ? chunk.slice(0, equalsIndex) : chunk).trim();
        if (name !== 'tatchi-jwt') continue;
        const value = (equalsIndex >= 0 ? chunk.slice(equalsIndex + 1) : '').trim();
        return value || null;
      }
      return null;
    };

    const session = makeSessionAdapter({
      signJwt: async (sub, extra) => {
        const appSessionVersion = String(extra?.appSessionVersion || '').trim() || 'app-v1';
        const token = `app-session:${sub}:${appSessionVersion}:${issuedClaimsByToken.size + 1}`;
        issuedClaimsByToken.set(token, { sub, appSessionVersion });
        return token;
      },
      parse: async (headers) => {
        const cookieHeader = String(headers.cookie ?? headers.Cookie ?? '').trim();
        const token = parseCookieToken(cookieHeader);
        if (!token) return { ok: false } as const;
        const claims = issuedClaimsByToken.get(token);
        if (!claims) return { ok: false } as const;
        return {
          ok: true as const,
          claims: {
            sub: claims.sub,
            kind: 'app_session_v1',
            appSessionVersion: claims.appSessionVersion,
          },
        };
      },
      buildSetCookie: (token) => `tatchi-jwt=${token}; Path=/; HttpOnly`,
      buildClearCookie: () => 'tatchi-jwt=; Path=/; Max-Age=0',
    });

    const service = makeFakeAuthService({
      verifyOidcJwtExchange: async () => ({
        ok: true,
        verified: true,
        userId: 'user-no-membership-express-1',
        providerSubject: 'oidc:https://issuer.example.com:user-no-membership-express-1',
      }),
      getOrCreateAppSessionVersion: async () => ({ ok: true, appSessionVersion: 'app-v1' }),
      validateAppSessionVersion: async () => ({ ok: true }),
    });
    const teamRbac = createInMemoryConsoleTeamRbacService();
    const consoleAuth = createAppSessionConsoleAuthAdapter({
      session,
      authService: service,
      defaultOrgId: 'org-no-membership-express-1',
      fallbackRoles: [],
      provisioning: {
        teamRbac,
        bootstrapRoles: [],
      },
    });
    const relayRouter = createRelayRouter(service, { session }) as any;
    relayRouter.use(
      createConsoleRouter({
        auth: consoleAuth,
        teamRbac,
      }),
    );
    const srv = await startExpressRouter(relayRouter);
    try {
      const exchange = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'cookie',
          exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
        }),
      });
      expect(exchange.status).toBe(200);
      const issuedClaims = Array.from(issuedClaimsByToken.values());
      expect(String(issuedClaims[0]?.email || '')).toBe('alice@example.com');
      expect(String(issuedClaims[0]?.name || '')).toBe('Alice Example');
      const cookieHeader = String(exchange.headers.get('set-cookie') || '').split(';')[0] || '';

      const consoleSession = await fetchJson(`${srv.baseUrl}/console/session`, {
        method: 'GET',
        headers: { Cookie: cookieHeader },
      });
      expect(consoleSession.status).toBe(403);
      expect(consoleSession.json?.ok).toBe(false);
      expect(consoleSession.json?.code).toBe('forbidden');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/session: first login provisions membership and audit event', async () => {
    const issuedClaimsByToken = new Map<string, { sub: string; appSessionVersion: string }>();
    const parseCookieToken = (cookieHeader: string): string | null => {
      for (const part of cookieHeader.split(';')) {
        const chunk = String(part || '').trim();
        if (!chunk) continue;
        const equalsIndex = chunk.indexOf('=');
        const name = (equalsIndex >= 0 ? chunk.slice(0, equalsIndex) : chunk).trim();
        if (name !== 'tatchi-jwt') continue;
        const value = (equalsIndex >= 0 ? chunk.slice(equalsIndex + 1) : '').trim();
        return value || null;
      }
      return null;
    };

    const session = makeSessionAdapter({
      signJwt: async (sub, extra) => {
        const appSessionVersion = String(extra?.appSessionVersion || '').trim() || 'app-v1';
        const token = `app-session:${sub}:${appSessionVersion}:${issuedClaimsByToken.size + 1}`;
        issuedClaimsByToken.set(token, { sub, appSessionVersion, ...(extra || {}) });
        return token;
      },
      parse: async (headers) => {
        const cookieHeader = String(headers.cookie ?? headers.Cookie ?? '').trim();
        const token = parseCookieToken(cookieHeader);
        if (!token) return { ok: false } as const;
        const claims = issuedClaimsByToken.get(token);
        if (!claims) return { ok: false } as const;
        return {
          ok: true as const,
          claims: {
            ...claims,
          },
        };
      },
      buildSetCookie: (token) => `tatchi-jwt=${token}; Path=/; HttpOnly`,
      buildClearCookie: () => 'tatchi-jwt=; Path=/; Max-Age=0',
    });

    const service = makeFakeAuthService({
      verifyOidcJwtExchange: async () => ({
        ok: true,
        verified: true,
        userId: 'user-provisioning-express-1',
        providerSubject: 'oidc:https://issuer.example.com:user-provisioning-express-1',
      }),
      getOrCreateAppSessionVersion: async () => ({ ok: true, appSessionVersion: 'app-v1' }),
      validateAppSessionVersion: async () => ({ ok: true }),
    });
    const teamRbac = createInMemoryConsoleTeamRbacService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const audit = createInMemoryConsoleAuditService({ seedDemoData: false });
    const consoleAuth = createAppSessionConsoleAuthAdapter({
      session,
      authService: service,
      defaultOrgId: 'org-provisioning-express-1',
      fallbackRoles: [],
      provisioning: {
        teamRbac,
        orgProjectEnv,
        audit,
        bootstrapRoles: ['owner', 'admin'],
      },
    });
    const relayRouter = createRelayRouter(service, { session }) as any;
    relayRouter.use(
      createConsoleRouter({
        auth: consoleAuth,
        teamRbac,
        orgProjectEnv,
        audit,
      }),
    );
    const srv = await startExpressRouter(relayRouter);
    try {
      const exchange = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'cookie',
          exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
        }),
      });
      expect(exchange.status).toBe(200);
      const cookieHeader = String(exchange.headers.get('set-cookie') || '').split(';')[0] || '';

      const consoleSession = await fetchJson(`${srv.baseUrl}/console/session`, {
        method: 'GET',
        headers: { Cookie: cookieHeader },
      });
      expect(consoleSession.status).toBe(200);
      expect(consoleSession.json?.ok).toBe(true);
      const roles = getPath(consoleSession.json, 'claims', 'roles');
      expect(Array.isArray(roles)).toBe(true);
      expect((roles as string[]).includes('owner')).toBe(true);
      expect((roles as string[]).includes('admin')).toBe(true);
      expect(getPath(consoleSession.json, 'claims', 'projectId')).toBeUndefined();
      expect(getPath(consoleSession.json, 'claims', 'environmentId')).toBeUndefined();

      const members = await fetchJson(`${srv.baseUrl}/console/members?status=ACTIVE`, {
        method: 'GET',
        headers: { Cookie: cookieHeader },
      });
      expect(members.status).toBe(200);
      const memberRows = Array.isArray(members.json?.members) ? members.json?.members : [];
      const actor = memberRows.find(
        (entry: any) => String(entry?.userId || '') === 'user-provisioning-express-1',
      );
      expect(actor).toBeTruthy();

      const auditEvents = await fetchJson(`${srv.baseUrl}/console/audit/events?limit=20`, {
        method: 'GET',
        headers: { Cookie: cookieHeader },
      });
      expect(auditEvents.status).toBe(200);
      const rows = Array.isArray(auditEvents.json?.events) ? auditEvents.json?.events : [];
      const actions = rows.map((row: any) => String(row?.action || ''));
      expect(actions).toContain('member.owner.bootstrap');
    } finally {
      await srv.close();
    }
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
        orgId: 'org-relay-express-passkey-exchange',
        actorUserId: 'test-admin',
        roles: ['admin'],
      },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session', 'wallet'],
      },
    );

    let verifyArgs: Record<string, unknown> | null = null;
    const session = makeSessionAdapter({ signJwt: async () => 'app-jwt-passkey-1' });
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async (args: any) => {
        verifyArgs = args as Record<string, unknown>;
        return {
          ok: true,
          verified: true,
          userId: 'user-passkey-1',
          rpId: 'example.localhost',
        };
      },
      getOrCreateAppSessionVersion: async () => ({ ok: true, appSessionVersion: 'app-v1' }),
    });
    const router = createRelayRouter(service, {
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-express-passkey-exchange',
      },
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://wallet.example.localhost',
        },
        body: JSON.stringify({
          sessionKind: 'jwt',
          exchange: {
            type: 'passkey_assertion',
            challengeId: 'challenge-passkey-1',
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
        }),
      });

      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);
      expect(getPath(res.json, 'session', 'kind')).toBe('app_session_v1');
      expect(getPath(res.json, 'session', 'userId')).toBe('user-passkey-1');
      expect(res.json?.jwt).toBe('app-jwt-passkey-1');
      expect(String((verifyArgs as Record<string, unknown> | null)?.['challengeId'] || '')).toBe(
        'challenge-passkey-1',
      );
      expect(
        String((verifyArgs as Record<string, unknown> | null)?.['expected_origin'] || ''),
      ).toBe('https://wallet.example.localhost');
      expect(dispatched.map((item) => item.eventType)).toEqual([
        'session.warm.created',
        'wallet.unlocked',
      ]);
      expect(dispatched[0]?.payload?.provider).toBe('passkey');
      expect(dispatched[1]?.payload?.challengeId).toBe('challenge-passkey-1');
    } finally {
      await srv.close();
    }
  });

  test('POST /session/exchange: passkey_assertion + sessionKind=cookie sets cookie and omits jwt', async () => {
    const session = makeSessionAdapter({
      signJwt: async () => 'app-jwt-passkey-cookie-1',
      buildSetCookie: (t) => `tatchi-jwt=${t}; Path=/; HttpOnly`,
    });
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async () => ({
        ok: true,
        verified: true,
        userId: 'user-passkey-cookie-1',
        rpId: 'example.localhost',
      }),
      getOrCreateAppSessionVersion: async () => ({ ok: true, appSessionVersion: 'app-v1' }),
    });
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'cookie',
          exchange: {
            type: 'passkey_assertion',
            challengeId: 'challenge-passkey-cookie-1',
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
        }),
      });
      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);
      expect(getPath(res.json, 'session', 'kind')).toBe('app_session_v1');
      expect(getPath(res.json, 'session', 'userId')).toBe('user-passkey-cookie-1');
      expect(res.json?.jwt).toBeUndefined();
      expect(res.headers.get('set-cookie')).toContain('tatchi-jwt=app-jwt-passkey-cookie-1');
    } finally {
      await srv.close();
    }
  });

  test('POST /session/exchange: passkey_assertion requires challengeId', async () => {
    const session = makeSessionAdapter();
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'jwt',
          exchange: {
            type: 'passkey_assertion',
            webauthn_authentication: { id: 'cred-1' },
          },
        }),
      });
      expect(res.status).toBe(400);
      expect(res.json?.ok).toBe(false);
      expect(res.json?.code).toBe('invalid_body');
      expect(String(res.json?.message || '')).toContain('challengeId');
    } finally {
      await srv.close();
    }
  });

  test('POST /session/exchange: passkey_assertion requires webauthn_authentication', async () => {
    const session = makeSessionAdapter();
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'jwt',
          exchange: {
            type: 'passkey_assertion',
            challengeId: 'challenge-passkey-missing-auth',
          },
        }),
      });
      expect(res.status).toBe(400);
      expect(res.json?.ok).toBe(false);
      expect(res.json?.code).toBe('invalid_body');
      expect(String(res.json?.message || '')).toContain('webauthn_authentication');
    } finally {
      await srv.close();
    }
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
      { orgId: 'org-relay-express-warm', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session'],
      },
    );

    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: { sub: 'user-oidc-warm-1', kind: 'app_session_v1', appSessionVersion: 'app-v1' },
      }),
      refresh: async () => ({ ok: true, jwt: 'refreshed-warm-1' }),
    });
    const service = makeFakeAuthService({
      verifyOidcJwtExchange: async () => ({
        ok: true,
        verified: true,
        userId: 'user-oidc-warm-1',
        providerSubject: 'oidc:https://issuer.example.com:user-warm-1',
      }),
      getOrCreateAppSessionVersion: async () => ({ ok: true, appSessionVersion: 'app-v1' }),
    });
    const router = createRelayRouter(service, {
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-express-warm',
      },
    });
    const srv = await startExpressRouter(router);
    try {
      const exchange = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'jwt',
          exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
        }),
      });
      expect(exchange.status).toBe(200);

      const refresh = await fetchJson(`${srv.baseUrl}/session/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionKind: 'jwt' }),
      });
      expect(refresh.status).toBe(200);

      expect(dispatched.map((item) => item.eventType)).toEqual([
        'session.warm.created',
        'session.warm.refreshed',
      ]);
      expect(dispatched[0]?.payload?.sessionKind).toBe('jwt');
      expect(dispatched[1]?.payload?.refreshed).toBe(true);
    } finally {
      await srv.close();
    }
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
      { orgId: 'org-relay-express-1', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session'],
      },
    );

    const session = makeSessionAdapter();
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-express-1',
      },
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'cookie',
          exchange: { type: 'not_oidc', token: 'header.payload.signature' },
        }),
      });
      expect(res.status).toBe(400);
      expect(res.json?.code).toBe('invalid_body');
      expect(dispatched.length).toBe(1);
      expect(dispatched[0]?.eventType).toBe('session.exchange.failed');
      expect(dispatched[0]?.payload?.code).toBe('invalid_body');
      expect(dispatched[0]?.payload?.sessionKind).toBe('cookie');
      expect(dispatched[0]?.payload?.orgId).toBe('org-relay-express-1');
    } finally {
      await srv.close();
    }
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
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'jwt',
          exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
        }),
      });
      expect(res.status).toBe(501);
      expect(res.json?.ok).toBe(false);
      expect(res.json?.code).toBe('unsupported');
    } finally {
      await srv.close();
    }
  });

  test('POST /session/exchange: invalid_issuer maps to 401', async () => {
    const session = makeSessionAdapter();
    const service = makeFakeAuthService({
      verifyOidcJwtExchange: async () => ({
        ok: false,
        verified: false,
        code: 'invalid_issuer',
        message: 'exchange.token issuer is not allowed',
      }),
    });
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'jwt',
          exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
        }),
      });
      expect(res.status).toBe(401);
      expect(res.json?.ok).toBe(false);
      expect(res.json?.code).toBe('invalid_issuer');
    } finally {
      await srv.close();
    }
  });

  test('POST /session/exchange: invalid_audience maps to 401', async () => {
    const session = makeSessionAdapter();
    const service = makeFakeAuthService({
      verifyOidcJwtExchange: async () => ({
        ok: false,
        verified: false,
        code: 'invalid_audience',
        message: 'exchange.token audience mismatch',
      }),
    });
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'jwt',
          exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
        }),
      });
      expect(res.status).toBe(401);
      expect(res.json?.ok).toBe(false);
      expect(res.json?.code).toBe('invalid_audience');
    } finally {
      await srv.close();
    }
  });

  test('POST /session/exchange: expired maps to 401', async () => {
    const session = makeSessionAdapter();
    const service = makeFakeAuthService({
      verifyOidcJwtExchange: async () => ({
        ok: false,
        verified: false,
        code: 'expired',
        message: 'exchange.token is expired',
      }),
    });
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'jwt',
          exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
        }),
      });
      expect(res.status).toBe(401);
      expect(res.json?.ok).toBe(false);
      expect(res.json?.code).toBe('expired');
    } finally {
      await srv.close();
    }
  });

  test('webhook signatures use HMAC v1 format (no fallback variants)', async () => {
    const signatures: string[] = [];
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async (input) => {
          signatures.push(String(input.headers['X-Console-Webhook-Signature'] || ''));
          return { ok: true, statusCode: 200, responseBody: 'ok' };
        },
      },
    });
    await webhooks.createEndpoint(
      { orgId: 'org-relay-express-signature-format', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session'],
      },
    );

    const session = makeSessionAdapter();
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-express-signature-format',
      },
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'cookie',
          exchange: { type: 'not_oidc', token: 'header.payload.signature' },
        }),
      });
      expect(res.status).toBe(400);
      expect(signatures.length).toBe(1);
      expect(signatures[0]).toMatch(/^v1=[0-9a-f]+$/);
      expect(signatures[0]).not.toContain('fallback');
    } finally {
      await srv.close();
    }
  });

  test('POST /session/refresh: cookie session sets Set-Cookie and returns { ok: true }', async () => {
    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: { sub: 'bob.testnet', kind: 'app_session_v1', appSessionVersion: 'v1' },
      }),
      refresh: async () => ({ ok: true, jwt: 'refreshed-999' }),
      buildSetCookie: (t) => `tatchi-jwt=${t}; Path=/; HttpOnly`,
    });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionKind: 'cookie' }),
      });
      expect(res.status).toBe(200);
      expect(res.headers.get('set-cookie')).toContain('tatchi-jwt=refreshed-999');
      expect(res.json?.ok).toBe(true);
      expect(res.json?.jwt).toBeUndefined();
    } finally {
      await srv.close();
    }
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
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/revoke`, {
        method: 'POST',
        headers: { Authorization: 'Bearer token' },
      });
      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);
      expect(res.json?.revoked).toBe(true);
      expect(res.headers.get('set-cookie')).toContain('Max-Age=0');
    } finally {
      await srv.close();
    }
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
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const revoke = await fetchJson(`${srv.baseUrl}/session/revoke`, {
        method: 'POST',
        headers: { Authorization: 'Bearer stale-token' },
      });
      expect(revoke.status).toBe(200);
      expect(revoke.json?.ok).toBe(true);

      const state = await fetchJson(`${srv.baseUrl}/session/state`, {
        method: 'GET',
        headers: { Authorization: 'Bearer stale-token' },
      });
      expect(state.status).toBe(401);
      expect(state.json?.authenticated).toBe(false);
      expect(state.json?.code).toBe('invalid_session_version');
    } finally {
      await srv.close();
    }
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
      { orgId: 'org-relay-express-invalid-version', actorUserId: 'test-admin', roles: ['admin'] },
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
    const router = createRelayRouter(service, {
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-express-invalid-version',
      },
    });
    const srv = await startExpressRouter(router);
    try {
      const state = await fetchJson(`${srv.baseUrl}/session/state`, {
        method: 'GET',
        headers: { Authorization: 'Bearer stale-token' },
      });
      expect(state.status).toBe(401);
      expect(state.json?.code).toBe('invalid_session_version');
      expect(dispatched.length).toBe(1);
      expect(dispatched[0]?.eventType).toBe('session.warm.expired');
      expect(dispatched[0]?.payload?.source).toBe('session.state');
      expect(dispatched[0]?.payload?.userId).toBe('bob.testnet');
      expect(dispatched[0]?.payload?.code).toBe('invalid_session_version');
    } finally {
      await srv.close();
    }
  });

  test('POST /wallet/unlock/challenge: returns passkey challenge options', async () => {
    const service = makeFakeAuthService({
      createWebAuthnLoginOptions: async () => ({
        ok: true,
        challengeId: 'wallet-unlock-cid-1',
        challengeB64u: 'wallet-unlock-challenge',
        expiresAtMs: 123,
      }),
    });
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/wallet/unlock/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validLoginOptionsBody()),
      });
      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);
      expect(res.json?.challengeId).toBe('wallet-unlock-cid-1');
    } finally {
      await srv.close();
    }
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
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/wallet/unlock/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validLoginVerifyBody({ sessionKind: undefined })),
      });
      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);
      expect(res.json?.unlocked).toBe(true);
      expect(res.json?.userId).toBe('bob.testnet');
      expect(res.json?.jwt).toBeUndefined();
    } finally {
      await srv.close();
    }
  });

  test('GET /wallet/state: valid app session reports unlocked state', async () => {
    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: { sub: 'bob.testnet', kind: 'app_session_v1', appSessionVersion: 'v1' },
      }),
    });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/wallet/state`, { method: 'GET' });
      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);
      expect(res.json?.locked).toBe(false);
      expect(res.json?.userId).toBe('bob.testnet');
    } finally {
      await srv.close();
    }
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
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/wallet/lock`, {
        method: 'POST',
        headers: { Authorization: 'Bearer token' },
      });
      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);
      expect(res.json?.locked).toBe(true);
      expect(res.json?.userId).toBe('bob.testnet');
      expect(res.headers.get('set-cookie')).toContain('Max-Age=0');
    } finally {
      await srv.close();
    }
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
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const lock = await fetchJson(`${srv.baseUrl}/wallet/lock`, {
        method: 'POST',
        headers: { Authorization: 'Bearer stale-token' },
      });
      expect(lock.status).toBe(200);
      expect(lock.json?.ok).toBe(true);

      const state = await fetchJson(`${srv.baseUrl}/wallet/state`, {
        method: 'GET',
        headers: { Authorization: 'Bearer stale-token' },
      });
      expect(state.status).toBe(401);
      expect(state.json?.ok).toBe(false);
      expect(state.json?.locked).toBe(true);
      expect(state.json?.code).toBe('invalid_session_version');
    } finally {
      await srv.close();
    }
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
      { orgId: 'org-relay-express-2', actorUserId: 'test-admin', roles: ['admin'] },
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
    const router = createRelayRouter(service, {
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-express-2',
      },
    });
    const srv = await startExpressRouter(router);
    try {
      const unlock = await fetchJson(`${srv.baseUrl}/wallet/unlock/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validLoginVerifyBody({ sessionKind: undefined })),
      });
      expect(unlock.status).toBe(200);

      const revoke = await fetchJson(`${srv.baseUrl}/session/revoke`, {
        method: 'POST',
        headers: { Authorization: 'Bearer app-session' },
      });
      expect(revoke.status).toBe(200);

      const lock = await fetchJson(`${srv.baseUrl}/wallet/lock`, {
        method: 'POST',
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
      expect(dispatched[2]?.payload?.orgId).toBe('org-relay-express-2');
    } finally {
      await srv.close();
    }
  });

  test('POST /session/refresh: unauthorized maps to 401', async () => {
    const session = makeSessionAdapter({
      refresh: async () => ({ ok: false, code: 'unauthorized', message: 'no token' }),
    });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionKind: 'jwt' }),
      });
      expect(res.status).toBe(401);
      expect(res.json?.code).toBe('unauthorized');
    } finally {
      await srv.close();
    }
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
      { orgId: 'org-relay-express-expired', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        subscriptions: ['session'],
      },
    );

    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: { sub: 'user-expired-1', kind: 'app_session_v1', appSessionVersion: 'app-v1' },
      }),
      refresh: async () => ({ ok: false, code: 'unauthorized', message: 'session expired' }),
    });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      session,
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-relay-express-expired',
      },
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionKind: 'jwt' }),
      });
      expect(res.status).toBe(401);
      expect(res.json?.code).toBe('unauthorized');
      expect(dispatched.length).toBe(1);
      expect(dispatched[0]?.eventType).toBe('session.warm.expired');
      expect(dispatched[0]?.payload?.expired).toBe(true);
      expect(dispatched[0]?.payload?.source).toBe('session.refresh');
      expect(dispatched[0]?.payload?.userId).toBe('user-expired-1');
    } finally {
      await srv.close();
    }
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
          sessionId: 'session-ed25519-runtime',
          relayerKeyId: 'relayer-key-1',
          rpId: 'example.localhost',
          thresholdExpiresAtMs: Date.now() + 60_000,
          participantIds: [1, 2],
          runtimeSnapshotScope: {
            orgId: 'org-runtime-express-1',
            projectId: 'project-runtime-express-1',
            environmentId: 'env-runtime-express-1',
          },
        },
      }),
    });
    const threshold = makeEd25519ThresholdAdapter({
      authorize: async () => {
        authorizeCalls += 1;
        return { ok: true, mpcSessionId: 'mpc-runtime-express-1' };
      },
    });
    const router = createRelayRouter(service, {
      session,
      threshold: threshold as any,
      runtimeSnapshots: {
        getLatestSnapshot: async () => ({
          snapshotId: 'snapshot-runtime-express-latest',
          version: 7,
          checksum: 'fnv1a32:runtime-express-checksum',
          effectiveAt: '2026-03-01T00:00:00.000Z',
        }),
      },
    });
    const srv = await startExpressRouter(router);
    try {
      const okRes = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer token' },
        body: JSON.stringify({
          relayerKeyId: 'relayer-key-1',
          clientVerifyingShareB64u: 'client-share',
          purpose: 'near_tx',
          signing_digest_32: new Array(32).fill(1),
          runtimeSnapshot: {
            checksum: 'fnv1a32:runtime-express-checksum',
            version: 7,
          },
        }),
      });
      expect(okRes.status).toBe(200);
      expect(okRes.json?.ok).toBe(true);
      expect(authorizeCalls).toBe(1);

      const mismatchRes = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer token' },
        body: JSON.stringify({
          relayerKeyId: 'relayer-key-1',
          clientVerifyingShareB64u: 'client-share',
          purpose: 'near_tx',
          signing_digest_32: new Array(32).fill(1),
          runtimeSnapshot: {
            checksum: 'fnv1a32:runtime-express-checksum-stale',
            version: 7,
          },
        }),
      });
      expect(mismatchRes.status).toBe(409);
      expect(mismatchRes.json?.code).toBe('runtime_snapshot_checksum_mismatch');
      expect(authorizeCalls).toBe(1);
    } finally {
      await srv.close();
    }
  });

  test('POST /session/logout: removed (404)', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/logout`, { method: 'POST' });
      expect(res.status).toBe(404);
    } finally {
      await srv.close();
    }
  });

  test('GET /session/auth: removed (404)', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/auth`, { method: 'GET' });
      expect(res.status).toBe(404);
    } finally {
      await srv.close();
    }
  });

  test('custom sessionRoutes: state path is honored', async () => {
    const session = makeSessionAdapter({
      parse: async () => ({
        ok: true,
        claims: { sub: 'bob.testnet', kind: 'app_session_v1', appSessionVersion: 'v1' },
      }),
    });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      session,
      sessionRoutes: { state: '/me' },
    });
    const srv = await startExpressRouter(router);
    try {
      const me = await fetchJson(`${srv.baseUrl}/me`, { method: 'GET' });
      expect(me.status).toBe(200);
      expect(me.json?.authenticated).toBe(true);
    } finally {
      await srv.close();
    }
  });
});
