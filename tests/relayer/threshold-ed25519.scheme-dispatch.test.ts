import { test, expect } from '@playwright/test';
import { createRelayRouter } from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import {
  THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
  THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
} from '@server/core/ThresholdService/schemes/schemeIds';
import { ROUTER_AB_ED25519_HEALTH_PATH_V2 } from '@shared/utils/signingSessionSeal';
import { callCf, fetchJson, makeFakeAuthService, startExpressRouter } from './helpers';

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
