/**
 * Threshold Ed25519 (2-party) — authorization digest binding (negative tests).
 *
 * Validates that `/threshold-ed25519/authorize` recomputes and validates the signing digest from
 * `signingPayload`, rejecting any mismatch between `signingPayload` and `signing_digest_32`.
 */

import { test, expect } from '@playwright/test';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import { createRelayRouter } from '@server/router/express-adaptor';
import { startExpressRouter } from '../relayer/helpers';
import {
  createInMemoryJwtSessionAdapter,
  installFastNearRpcMock,
  installThresholdEd25519RegistrationMocks,
  makeAuthServiceForThreshold,
  persistThresholdEd25519RegistrationMaterial,
  setupThresholdE2ePage,
} from './thresholdEd25519.testUtils';

test.describe('threshold-ed25519 digest binding', () => {
  test.setTimeout(180_000);

  test.beforeEach(async ({ page }) => {
    await setupThresholdE2ePage(page);
  });

  test('rejects tampered signingPayload (signing_digest mismatch)', async ({ page }) => {
    const keysOnChain = new Set<string>();
    const nonceByPublicKey = new Map<string, number>();

    const { service, threshold } = makeAuthServiceForThreshold(keysOnChain);
    await service.getRelayerAccount();

    const frontendOrigin = new URL(DEFAULT_TEST_CONFIG.frontendUrl).origin;
    const session = createInMemoryJwtSessionAdapter();
    const router = createRelayRouter(service, {
      corsOrigins: [frontendOrigin],
      threshold,
      session,
    });
    const srv = await startExpressRouter(router);

    const relayerCounts = { authorize: 0, init: 0, finalize: 0, keygen: 0 };

    try {
      // Tamper the authorize body by mutating the signingPayload after it was intent-bound.
      await page.route(`${srv.baseUrl}/threshold-ed25519/authorize`, async (route) => {
        const req = route.request();
        const method = req.method().toUpperCase();
        if (method !== 'POST') return route.fallback();
        relayerCounts.authorize += 1;

        const original = JSON.parse(req.postData() || '{}');
        const mutated = { ...original };
        try {
          const txs = mutated?.signingPayload?.txSigningRequests;
          if (Array.isArray(txs) && txs[0] && typeof txs[0] === 'object') {
            // Change receiverId so the recomputed intent digest differs from the originally-authorized intent digest.
            (txs[0] as any).receiverId = 'evil.w3a-v1.testnet';
          }
        } catch {}

        await route.continue({ postData: JSON.stringify(mutated) });
      });

      // These should NOT be reached if /authorize fails.
      await page.route(`${srv.baseUrl}/threshold-ed25519/sign/init`, async (route) => {
        const req = route.request();
        if (req.method().toUpperCase() === 'POST') relayerCounts.init += 1;
        await route.fallback();
      });
      await page.route(`${srv.baseUrl}/threshold-ed25519/sign/finalize`, async (route) => {
        const req = route.request();
        if (req.method().toUpperCase() === 'POST') relayerCounts.finalize += 1;
        await route.fallback();
      });

      await installThresholdEd25519RegistrationMocks(page, {
        relayerBaseUrl: srv.baseUrl,
        keysOnChain,
        nonceByPublicKey,
        onBootstrap: async (bootstrap) => {
          await persistThresholdEd25519RegistrationMaterial({ threshold, ...bootstrap });
        },
      });

      await installFastNearRpcMock(page, {
        keysOnChain,
        nonceByPublicKey,
        strictAccessKeyLookup: true,
      });

      const result = await page.evaluate(
        async ({ relayerUrl }) => {
          try {
            const { SeamsWeb } = await import('/sdk/esm/SeamsWeb/index.js');
            const { ActionType } = await import('/sdk/esm/core/types/actions.js');
            const suffix =
              typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
                ? crypto.randomUUID()
                : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
            const accountId = `e2edigest${suffix}.w3a-v1.testnet`;

            const pm = new SeamsWeb({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayer: { url: relayerUrl },
              iframeWallet: { walletOrigin: '' },
            });

            const confirmConfig = { uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 };

            const reg = await pm.registration.registerPasskey(accountId, {
              signerOptions: {
                tempo: {
                  enabled: false,
                  participantIds: [1, 2],
                  signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                },
                evm: {
                  enabled: false,
                  participantIds: [1, 2],
                  signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                },
              },
              confirmationConfig: confirmConfig as any,
            });
            if (!reg?.success) return { ok: false, error: reg?.error || 'registration failed' };
            const login = await pm.auth.unlock(accountId);
            if (!login?.success) return { ok: false, error: login?.error || 'login failed' };

            // Attempt a threshold sign. The test tampered /authorize, so this must fail.
            await pm.near.signTransactionsWithActions({
              nearAccount: { accountId },
              transactions: [
                {
                  receiverId: 'w3a-v1.testnet',
                  actions: [{ type: ActionType.Transfer, amount: '1' }],
                },
              ],
              options: {
                confirmationConfig: confirmConfig as any,
              },
            });

            return { ok: false, error: 'expected signing to fail but it succeeded' };
          } catch (e: any) {
            return { ok: true, error: e?.message || String(e) };
          }
        },
        { relayerUrl: srv.baseUrl },
      );

      expect(result.ok).toBe(true);
      expect(String(result.error)).toContain('signing_digest_mismatch');
      expect(relayerCounts.keygen).toBe(0);
      expect(relayerCounts.authorize).toBeGreaterThanOrEqual(1);
      expect(relayerCounts.init).toBe(0);
      expect(relayerCounts.finalize).toBe(0);
    } finally {
      await srv.close().catch(() => undefined);
    }
  });

  test('rejects tampered signing_digest_32 (signing_digest mismatch)', async ({ page }) => {
    const keysOnChain = new Set<string>();
    const nonceByPublicKey = new Map<string, number>();

    const { service, threshold } = makeAuthServiceForThreshold(keysOnChain);
    await service.getRelayerAccount();

    const frontendOrigin = new URL(DEFAULT_TEST_CONFIG.frontendUrl).origin;
    const session = createInMemoryJwtSessionAdapter();
    const router = createRelayRouter(service, {
      corsOrigins: [frontendOrigin],
      threshold,
      session,
    });
    const srv = await startExpressRouter(router);

    const relayerCounts = { authorize: 0, init: 0, finalize: 0, keygen: 0 };

    try {
      // Tamper signing_digest_32 bytes while keeping signingPayload intact.
      await page.route(`${srv.baseUrl}/threshold-ed25519/authorize`, async (route) => {
        const req = route.request();
        const method = req.method().toUpperCase();
        if (method !== 'POST') return route.fallback();
        relayerCounts.authorize += 1;

        const original = JSON.parse(req.postData() || '{}');
        const mutated = { ...original };
        try {
          const bytes = mutated?.signing_digest_32;
          if (Array.isArray(bytes) && bytes.length === 32 && Number.isFinite(Number(bytes[0]))) {
            bytes[0] = (Number(bytes[0]) ^ 0xff) & 0xff;
          }
        } catch {}

        await route.continue({ postData: JSON.stringify(mutated) });
      });

      await page.route(`${srv.baseUrl}/threshold-ed25519/sign/init`, async (route) => {
        const req = route.request();
        if (req.method().toUpperCase() === 'POST') relayerCounts.init += 1;
        await route.fallback();
      });
      await page.route(`${srv.baseUrl}/threshold-ed25519/sign/finalize`, async (route) => {
        const req = route.request();
        if (req.method().toUpperCase() === 'POST') relayerCounts.finalize += 1;
        await route.fallback();
      });

      await installThresholdEd25519RegistrationMocks(page, {
        relayerBaseUrl: srv.baseUrl,
        keysOnChain,
        nonceByPublicKey,
        onBootstrap: async (bootstrap) => {
          await persistThresholdEd25519RegistrationMaterial({ threshold, ...bootstrap });
        },
      });

      await installFastNearRpcMock(page, {
        keysOnChain,
        nonceByPublicKey,
        strictAccessKeyLookup: true,
      });

      const result = await page.evaluate(
        async ({ relayerUrl }) => {
          try {
            const { SeamsWeb } = await import('/sdk/esm/SeamsWeb/index.js');
            const { ActionType } = await import('/sdk/esm/core/types/actions.js');
            const suffix =
              typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
                ? crypto.randomUUID()
                : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
            const accountId = `e2edigest${suffix}.w3a-v1.testnet`;

            const pm = new SeamsWeb({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayer: { url: relayerUrl },
              iframeWallet: { walletOrigin: '' },
            });

            const confirmConfig = { uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 };

            const reg = await pm.registration.registerPasskey(accountId, {
              signerOptions: {
                tempo: {
                  enabled: false,
                  participantIds: [1, 2],
                  signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                },
                evm: {
                  enabled: false,
                  participantIds: [1, 2],
                  signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                },
              },
              confirmationConfig: confirmConfig as any,
            });
            if (!reg?.success) return { ok: false, error: reg?.error || 'registration failed' };
            const login = await pm.auth.unlock(accountId);
            if (!login?.success) return { ok: false, error: login?.error || 'login failed' };

            await pm.near.signTransactionsWithActions({
              nearAccount: { accountId },
              transactions: [
                {
                  receiverId: 'w3a-v1.testnet',
                  actions: [{ type: ActionType.Transfer, amount: '1' }],
                },
              ],
              options: {
                confirmationConfig: confirmConfig as any,
              },
            });

            return { ok: false, error: 'expected signing to fail but it succeeded' };
          } catch (e: any) {
            return { ok: true, error: e?.message || String(e) };
          }
        },
        { relayerUrl: srv.baseUrl },
      );

      expect(result.ok).toBe(true);
      expect(String(result.error)).toContain('signing_digest_mismatch');
      expect(relayerCounts.keygen).toBe(0);
      expect(relayerCounts.authorize).toBeGreaterThanOrEqual(1);
      expect(relayerCounts.init).toBe(0);
      expect(relayerCounts.finalize).toBe(0);
    } finally {
      await srv.close().catch(() => undefined);
    }
  });
});
