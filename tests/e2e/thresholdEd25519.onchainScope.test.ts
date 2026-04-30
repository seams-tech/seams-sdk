/**
 * Threshold Ed25519 (2-party) — on-chain access key scope.
 *
 * Validates that threshold signing is rejected when the threshold key is not an active on-chain
 * access key for the account (relayer refuses to authorize).
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

test.describe('threshold-ed25519 on-chain scope', () => {
  test.setTimeout(180_000);

  test.beforeEach(async ({ page }) => {
    await setupThresholdE2ePage(page);
  });

  test('rejects threshold signing when relayerKeyId is not an active access key', async ({
    page,
  }) => {
    const keysOnChainClient = new Set<string>();
    const keysOnChainServer = new Set<string>();
    const nonceByPublicKey = new Map<string, number>();

    const { service, threshold } = makeAuthServiceForThreshold(keysOnChainServer);
    await service.getRelayerAccount();

    const frontendOrigin = new URL(DEFAULT_TEST_CONFIG.frontendUrl).origin;
    const session = createInMemoryJwtSessionAdapter();
    const router = createRelayRouter(service, {
      corsOrigins: [frontendOrigin],
      threshold,
      session,
    });
    const srv = await startExpressRouter(router);

    const relayerCounts = { keygen: 0, session: 0, authorize: 0, init: 0, finalize: 0 };

    try {
      await page.route(`${srv.baseUrl}/threshold-ed25519/session`, async (route) => {
        const req = route.request();
        if (req.method().toUpperCase() === 'POST') relayerCounts.session += 1;
        await route.fallback();
      });

      await page.route(`${srv.baseUrl}/threshold-ed25519/authorize`, async (route) => {
        const req = route.request();
        if (req.method().toUpperCase() === 'POST') relayerCounts.authorize += 1;
        await route.fallback();
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
        keysOnChain: keysOnChainClient,
        nonceByPublicKey,
        onBootstrap: async (bootstrap) => {
          await persistThresholdEd25519RegistrationMaterial({ threshold, ...bootstrap });
        },
      });

      await installFastNearRpcMock(page, {
        keysOnChain: keysOnChainClient,
        nonceByPublicKey,
        strictAccessKeyLookup: true,
      });

      const result = await page.evaluate(
        async ({ relayerUrl }) => {
          try {
            const { SeamsPasskey } = await import('/sdk/esm/core/SeamsPasskey/index.js');
            const { ActionType } = await import('/sdk/esm/core/types/actions.js');
            const suffix =
              typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
                ? crypto.randomUUID()
                : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
            const accountId = `e2escope${suffix}.w3a-v1.testnet`;

            const pm = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayer: { url: relayerUrl },
              iframeWallet: { walletOrigin: '' },
            });

            const confirmConfig = { uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 };

            const reg = await pm.registration.registerPasskeyInternal(
              accountId,
              {
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
              },
              confirmConfig as any,
            );
            if (!reg?.success) throw new Error(reg?.error || 'registration failed');
            const login = await pm.auth.unlock(accountId);
            if (!login?.success) throw new Error(login?.error || 'login failed');

            await pm.near.signTransactionsWithActions({
              nearAccountId: accountId,
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
      expect(String(result.error)).toContain('not an active access key');
      expect(relayerCounts.keygen).toBe(0);
      expect(relayerCounts.session).toBeGreaterThanOrEqual(1);
      expect(relayerCounts.authorize).toBe(0);
      expect(relayerCounts.init).toBe(0);
      expect(relayerCounts.finalize).toBe(0);
    } finally {
      await srv.close().catch(() => undefined);
    }
  });
});
