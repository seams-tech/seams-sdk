import { test, expect } from '@playwright/test';
import { createRelayRouter } from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import {
  THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
  THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
} from '@server/core/ThresholdService/schemes/schemeIds';
import {
  ROUTER_AB_ED25519_HEALTH_PATH_V2,
  ROUTER_AB_ED25519_HSS_PREPARE_PATH_V2,
  ROUTER_AB_ED25519_WALLET_SESSION_PATH_V2,
} from '@shared/utils/signingSessionSeal';
import { ROUTER_AB_ECDSA_HSS_KEY_IDENTITIES_PATH_V1 } from '@shared/utils/routerAbEcdsaHss';
import {
  callCf,
  fetchJson,
  makeFakeAuthService,
  makeSessionAdapter,
  startExpressRouter,
} from './helpers';

function makeThresholdAdapter(module: unknown) {
  const requestedSchemeIds: string[] = [];
  return {
    requestedSchemeIds,
    threshold: {
      getSchemeModule(schemeId: string) {
        requestedSchemeIds.push(schemeId);
        return module as any;
      },
    },
  };
}

function makeEd25519SessionModule(calls: unknown[]) {
  return {
    schemeId: THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
    session: async (request: unknown) => {
      calls.push(request);
      return { ok: true, sessionId: 'unexpected-session' };
    },
  };
}

function routerAbEd25519WalletSessionCookieBody() {
  return {
    sessionKind: 'cookie',
    relayerKeyId: 'ed25519:relayer-key',
    sessionPolicy: {
      version: 'threshold_session_v1',
      nearAccountId: 'alice.testnet',
      rpId: 'wallet.example.test',
      participantIds: [1, 2],
    },
  };
}

function legacyEd25519SessionClaims() {
  return {
    kind: 'threshold_ed25519_session_v1',
    sub: 'alice.testnet',
    walletId: 'alice.testnet',
    sessionId: 'legacy-threshold-session',
    signingGrantId: 'wallet-session-1',
    relayerKeyId: 'ed25519:relayer-key',
    rpId: 'wallet.example.test',
    thresholdExpiresAtMs: Date.now() + 60_000,
    participantIds: [1, 2],
  };
}

test.describe('threshold-ed25519 scheme registry + dispatch coverage', () => {
  test('express: old public threshold lifecycle route names are not registered', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const oldRoutes = [
        { method: 'GET', path: '/threshold-ed25519/healthz' },
        { method: 'POST', path: '/threshold-ed25519/session' },
        { method: 'POST', path: '/threshold-ed25519/hss/prepare' },
        { method: 'POST', path: '/threshold-ed25519/hss/respond' },
        { method: 'POST', path: '/threshold-ed25519/hss/finalize' },
        { method: 'POST', path: '/threshold-ed25519/internal/cosign/init' },
        { method: 'POST', path: '/threshold-ed25519/internal/cosign/finalize' },
        { method: 'GET', path: '/threshold-ecdsa/healthz' },
        { method: 'POST', path: '/threshold-ecdsa/key-identities' },
        { method: 'POST', path: '/threshold-ecdsa/hss/bootstrap' },
        { method: 'POST', path: '/threshold-ecdsa/hss/export/share' },
        { method: 'POST', path: '/threshold-ecdsa/internal/cosign/init' },
        { method: 'POST', path: '/threshold-ecdsa/internal/cosign/finalize' },
        { method: 'POST', path: '/threshold/signing-session-seal/apply-server-seal' },
        { method: 'POST', path: '/threshold/signing-session-seal/remove-server-seal' },
      ] as const;
      for (const route of oldRoutes) {
        const res = await fetchJson(`${srv.baseUrl}${route.path}`, {
          method: route.method,
          headers: { 'Content-Type': 'application/json' },
          body: route.method === 'POST' ? '{}' : undefined,
        });
        expect(res.status, `${route.method} ${route.path}`).toBe(404);
      }
    } finally {
      await srv.close();
    }
  });

  test('express: Router A/B Ed25519 Wallet Session issuance rejects cookie mode', async () => {
    const sessionCalls: unknown[] = [];
    const { threshold } = makeThresholdAdapter(makeEd25519SessionModule(sessionCalls));
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      threshold: threshold as any,
      session: makeSessionAdapter({
        signJwt: async () => {
          throw new Error('cookie-mode Router A/B issuance must not sign a JWT');
        },
        parse: async () => {
          throw new Error('cookie-mode Router A/B issuance must not parse route auth');
        },
      }),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}${ROUTER_AB_ED25519_WALLET_SESSION_PATH_V2}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(routerAbEd25519WalletSessionCookieBody()),
      });

      expect(res.status).toBe(400);
      expect(res.headers.get('set-cookie')).toBeNull();
      expect(res.json).toMatchObject({
        ok: false,
        code: 'invalid_body',
        message: 'Router A/B Ed25519 Wallet Session issuance requires sessionKind=jwt',
      });
      expect(sessionCalls).toHaveLength(0);
    } finally {
      await srv.close();
    }
  });

  test('cloudflare: Router A/B Ed25519 Wallet Session issuance rejects cookie mode', async () => {
    const sessionCalls: unknown[] = [];
    const { threshold } = makeThresholdAdapter(makeEd25519SessionModule(sessionCalls));
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      threshold: threshold as any,
      session: makeSessionAdapter({
        signJwt: async () => {
          throw new Error('cookie-mode Router A/B issuance must not sign a JWT');
        },
        parse: async () => {
          throw new Error('cookie-mode Router A/B issuance must not parse route auth');
        },
      }),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: ROUTER_AB_ED25519_WALLET_SESSION_PATH_V2,
      body: routerAbEd25519WalletSessionCookieBody(),
    });

    expect(res.status).toBe(400);
    expect(res.headers.get('set-cookie')).toBeNull();
    expect(res.json).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'Router A/B Ed25519 Wallet Session issuance requires sessionKind=jwt',
    });
    expect(sessionCalls).toHaveLength(0);
  });

  test('express: Router A/B Ed25519 HSS rejects cookie mode before session parsing', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      threshold: {
        ed25519Hss: {
          prepareWithSession: async () => {
            throw new Error('cookie-mode HSS must not reach Ed25519 HSS prepare');
          },
        },
      } as any,
      session: makeSessionAdapter({
        parse: async () => {
          throw new Error('cookie-mode HSS must not parse route auth');
        },
      }),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}${ROUTER_AB_ED25519_HSS_PREPARE_PATH_V2}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer router-ab-wallet-session',
        },
        body: JSON.stringify({ sessionKind: 'cookie' }),
      });

      expect(res.status).toBe(400);
      expect(res.json).toMatchObject({
        ok: false,
        code: 'invalid_body',
        message: 'Router A/B Ed25519 HSS requires sessionKind=jwt',
      });
    } finally {
      await srv.close();
    }
  });

  test('cloudflare: Router A/B Ed25519 HSS rejects cookie mode before session parsing', async () => {
    const service = makeFakeAuthService();
    const { threshold } = makeThresholdAdapter({
      schemeId: THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
    });
    const handler = createCloudflareRouter(service, {
      threshold: {
        ...threshold,
        ed25519Hss: {
          prepareWithSession: async () => {
            throw new Error('cookie-mode HSS must not reach Ed25519 HSS prepare');
          },
        },
      } as any,
      session: makeSessionAdapter({
        parse: async () => {
          throw new Error('cookie-mode HSS must not parse route auth');
        },
      }),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: ROUTER_AB_ED25519_HSS_PREPARE_PATH_V2,
      headers: { Authorization: 'Bearer router-ab-wallet-session' },
      body: { sessionKind: 'cookie' },
    });

    expect(res.status).toBe(400);
    expect(res.json).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'Router A/B Ed25519 HSS requires sessionKind=jwt',
    });
  });

  test('express: Router A/B ECDSA key identities rejects cookie mode before session parsing', async () => {
    const service = makeFakeAuthService({
      listThresholdEcdsaKeyIdentityTargetsForUser: async () => {
        throw new Error('cookie-mode ECDSA key identities must not reach lookup');
      },
    } as any);
    const router = createRelayRouter(service, {
      session: makeSessionAdapter({
        parse: async () => {
          throw new Error('cookie-mode ECDSA key identities must not parse route auth');
        },
      }),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}${ROUTER_AB_ECDSA_HSS_KEY_IDENTITIES_PATH_V1}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer router-ab-wallet-session',
        },
        body: JSON.stringify({ sessionKind: 'cookie', keyTargets: [] }),
      });

      expect(res.status).toBe(400);
      expect(res.json).toMatchObject({
        ok: false,
        code: 'invalid_body',
        message: 'Router A/B ECDSA-HSS key identities requires sessionKind=jwt',
      });
    } finally {
      await srv.close();
    }
  });

  test('cloudflare: Router A/B ECDSA key identities rejects cookie mode before session parsing', async () => {
    const service = makeFakeAuthService({
      listThresholdEcdsaKeyIdentityTargetsForUser: async () => {
        throw new Error('cookie-mode ECDSA key identities must not reach lookup');
      },
    } as any);
    const { threshold } = makeThresholdAdapter({
      schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
    });
    const handler = createCloudflareRouter(service, {
      threshold: threshold as any,
      session: makeSessionAdapter({
        parse: async () => {
          throw new Error('cookie-mode ECDSA key identities must not parse route auth');
        },
      }),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: ROUTER_AB_ECDSA_HSS_KEY_IDENTITIES_PATH_V1,
      headers: { Authorization: 'Bearer router-ab-wallet-session' },
      body: { sessionKind: 'cookie', keyTargets: [] },
    });

    expect(res.status).toBe(400);
    expect(res.json).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'Router A/B ECDSA-HSS key identities requires sessionKind=jwt',
    });
  });

  test('express: Router A/B Ed25519 HSS rejects legacy threshold-session JWT claims', async () => {
    const hssCalls: unknown[] = [];
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      threshold: {
        ed25519Hss: {
          prepareWithSession: async (request: unknown) => {
            hssCalls.push(request);
            return { ok: true };
          },
        },
      } as any,
      session: makeSessionAdapter({
        parse: async () => ({ ok: true, claims: legacyEd25519SessionClaims() }),
      }),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}${ROUTER_AB_ED25519_HSS_PREPARE_PATH_V2}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer legacy-threshold-session',
        },
        body: JSON.stringify({ relayerKeyId: 'ed25519:relayer-key' }),
      });

      expect(res.status).toBe(401);
      expect(res.json).toMatchObject({
        ok: false,
        code: 'unauthorized',
        message: 'Invalid Router A/B Wallet Session claims',
      });
      expect(hssCalls).toHaveLength(0);
    } finally {
      await srv.close();
    }
  });

  test('express: Router A/B ECDSA key identities rejects legacy threshold-session JWT claims', async () => {
    const service = makeFakeAuthService({
      listThresholdEcdsaKeyIdentityTargetsForUser: async () => {
        throw new Error('legacy threshold-session JWT must not reach ECDSA identity lookup');
      },
    } as any);
    const router = createRelayRouter(service, {
      session: makeSessionAdapter({
        parse: async () => ({ ok: true, claims: legacyEd25519SessionClaims() }),
      }),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}${ROUTER_AB_ECDSA_HSS_KEY_IDENTITIES_PATH_V1}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer legacy-threshold-session',
        },
        body: JSON.stringify({ keyTargets: [] }),
      });

      expect(res.status).toBe(401);
      expect(res.json).toMatchObject({
        ok: false,
        code: 'unauthorized',
        message: 'Invalid Router A/B Wallet Session claims',
      });
    } finally {
      await srv.close();
    }
  });

  test('express: healthz returns not_found when ed25519 scheme module is not registered', async () => {
    const { requestedSchemeIds, threshold } = makeThresholdAdapter({
      schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
    });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { threshold: threshold as any });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}${ROUTER_AB_ED25519_HEALTH_PATH_V2}`, {
        method: 'GET',
      });
      expect(res.status).toBe(404);
      expect(res.json?.ok).toBe(false);
      expect(res.json?.code).toBe('not_found');
      expect(res.json?.message).toBe('threshold-ed25519 scheme is not enabled on this server');
      expect(requestedSchemeIds).toEqual([THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID]);
    } finally {
      await srv.close();
    }
  });

  test('cloudflare: healthz returns not_found when ed25519 scheme module is not registered', async () => {
    const { requestedSchemeIds, threshold } = makeThresholdAdapter({
      schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
    });
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { threshold: threshold as any });
    const res = await callCf(handler, { method: 'GET', path: ROUTER_AB_ED25519_HEALTH_PATH_V2 });
    expect(res.status).toBe(404);
    expect(res.json?.ok).toBe(false);
    expect(res.json?.code).toBe('not_found');
    expect(res.json?.message).toBe('threshold-ed25519 scheme is not enabled on this server');
    expect(requestedSchemeIds).toEqual([THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID]);
  });

});
