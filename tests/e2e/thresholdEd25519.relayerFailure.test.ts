/**
 * Threshold Ed25519 (2-party) — relayer failure behavior.
 *
 * Validates "no silent downgrade": when relayer endpoints fail (5xx), threshold signing returns a
 * hard error in strict mode instead of falling back to local signing.
 */

import { test, expect } from '@playwright/test';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import { createRelayRouter } from '@server/router/express-adaptor';
import { startExpressRouter } from '../relayer/helpers';
import {
  corsHeadersForRoute,
  createInMemoryJwtSessionAdapter,
  installFastNearRpcMock,
  installThresholdEd25519RegistrationMocks,
  makeAuthServiceForThreshold,
  persistThresholdEd25519RegistrationMaterial,
  setupThresholdE2ePage,
} from './thresholdEd25519.testUtils';

test.describe('threshold-ed25519 relayer failure behavior', () => {
  test.setTimeout(180_000);

  test.beforeEach(async ({ page }) => {
    await setupThresholdE2ePage(page);
  });

  test('no silent downgrade: /authorize 5xx causes threshold signing to error', async ({
    page,
  }) => {
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

    try {
      await page.route(`${srv.baseUrl}/threshold-ed25519/authorize`, async (route) => {
        const req = route.request();
        const method = req.method().toUpperCase();
        if (method === 'OPTIONS') {
          await route.fallback();
          return;
        }
        if (method !== 'POST') {
          await route.fallback();
          return;
        }
        const corsHeaders = corsHeadersForRoute(route);
        await route.fulfill({
          status: 500,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            ok: false,
            code: 'internal',
            message: 'forced 5xx for /authorize',
          }),
        });
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
            const accountId = `e2erelayfail${suffix}.w3a-v1.testnet`;

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
            if (!reg?.success) throw new Error(reg?.error || 'registration failed');
            const login = await pm.auth.unlock(accountId);
            if (!login?.success) throw new Error(login?.error || 'login failed');

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

            return { ok: false, error: 'expected threshold signing to fail but it succeeded' };
          } catch (e: any) {
            return { ok: true, error: e?.message || String(e) };
          }
        },
        { relayerUrl: srv.baseUrl },
      );

      expect(result.ok).toBe(true);
      expect(String(result.error)).toContain('forced 5xx for /authorize');
    } finally {
      await srv.close().catch(() => undefined);
    }
  });

  test('no silent downgrade: /sign/finalize 5xx causes threshold signing to error', async ({
    page,
  }) => {
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

    try {
      await page.route(`${srv.baseUrl}/threshold-ed25519/sign/finalize`, async (route) => {
        const req = route.request();
        const method = req.method().toUpperCase();
        if (method === 'OPTIONS') {
          await route.fallback();
          return;
        }
        if (method !== 'POST') {
          await route.fallback();
          return;
        }
        const corsHeaders = corsHeadersForRoute(route);
        await route.fulfill({
          status: 500,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            ok: false,
            code: 'internal',
            message: 'forced 5xx for /sign/finalize',
          }),
        });
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
            const accountId = `e2erelayfail${suffix}.w3a-v1.testnet`;

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
            if (!reg?.success) throw new Error(reg?.error || 'registration failed');
            const login = await pm.auth.unlock(accountId);
            if (!login?.success) throw new Error(login?.error || 'login failed');

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

            return { ok: false, error: 'expected threshold signing to fail but it succeeded' };
          } catch (e: any) {
            return { ok: true, error: e?.message || String(e) };
          }
        },
        { relayerUrl: srv.baseUrl },
      );

      expect(result.ok).toBe(true);
      expect(String(result.error)).toContain('forced 5xx for /sign/finalize');
    } finally {
      await srv.close().catch(() => undefined);
    }
  });
});
