/**
 * Threshold Ed25519 (2-party) — authorize unauthorized should not broadcast.
 *
 * Regression for "signed successfully but never dispatches":
 * when `/threshold-ed25519/authorize` returns 401, the client must surface an error
 * and must not call NEAR RPC `send_tx`.
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

test.describe('threshold-ed25519 authorize unauthorized', () => {
  test.setTimeout(180_000);

  test.beforeEach(async ({ page }) => {
    await setupThresholdE2ePage(page);
  });

  test('401 from /authorize surfaces error and does not broadcast', async ({ page }) => {
    const keysOnChain = new Set<string>();
    const nonceByPublicKey = new Map<string, number>();
    let sendTxCount = 0;
    let forceAuthorizeUnauthorized = false;
    let authorizePostCount = 0;

    const { service, threshold } = makeAuthServiceForThreshold(keysOnChain);
    await service.getRelayerAccount();

    const session = createInMemoryJwtSessionAdapter();
    const frontendOrigin = new URL(DEFAULT_TEST_CONFIG.frontendUrl).origin;
    const router = createRelayRouter(service, {
      corsOrigins: [frontendOrigin],
      threshold,
      session,
    });
    const srv = await startExpressRouter(router);

    try {
      await page.route('**/threshold-ed25519/authorize', async (route) => {
        const req = route.request();
        const method = req.method().toUpperCase();
        if (method === 'OPTIONS') {
          await route.fallback();
          return;
        }
        if (method === 'POST') authorizePostCount += 1;
        if (method !== 'POST' || !forceAuthorizeUnauthorized) {
          await route.fallback();
          return;
        }
        const corsHeaders = corsHeadersForRoute(route);
        await route.fulfill({
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            ok: false,
            code: 'unauthorized',
            message: 'threshold session expired or invalid',
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
        onSendTx: () => {
          sendTxCount += 1;
        },
        strictAccessKeyLookup: true,
      });

      const setup = await page.evaluate(
        async ({ relayerUrl }) => {
          try {
            const { SeamsWeb } = await import('/sdk/esm/SeamsWeb/index.js');
            const suffix =
              typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
                ? crypto.randomUUID()
                : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
            const accountId = `e2eunauth${suffix}.w3a-v1.testnet`;

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

            (window as any).__thresholdUnauthorizedPm = pm;
            (window as any).__thresholdUnauthorizedAccountId = accountId;
            (window as any).__thresholdUnauthorizedConfirmConfig = confirmConfig;

            return { ok: true };
          } catch (e: any) {
            return { ok: false, error: e?.message || String(e) };
          }
        },
        { relayerUrl: srv.baseUrl },
      );

      expect(setup.ok, setup.ok ? '' : setup.error).toBe(true);

      const baselineSendTxCount = sendTxCount;
      forceAuthorizeUnauthorized = true;

      const result = await page.evaluate(async () => {
        try {
          const pm = (window as any).__thresholdUnauthorizedPm;
          const accountId = String((window as any).__thresholdUnauthorizedAccountId || '');
          const confirmConfig = (window as any).__thresholdUnauthorizedConfirmConfig;
          if (!pm || !accountId) throw new Error('missing test state');

          const { ActionType } = await import('/sdk/esm/core/types/actions.js');

          const out = await pm.near.executeAction({
            nearAccount: { accountId },
            receiverId: 'w3a-v1.testnet',
            actionArgs: { type: ActionType.Transfer, amount: '1' },
            options: {
              confirmationConfig: confirmConfig,
            },
          });

          const ok =
            out && typeof out === 'object' && 'success' in out && (out as any).success === false;
          return { ok, error: String((out as any)?.error || '') };
        } catch (e: any) {
          return { ok: true, error: e?.message || String(e) };
        }
      });

      expect(
        result.ok,
        `executeAction unexpectedly succeeded (authorizePostCount=${authorizePostCount}, sendTxCount=${sendTxCount}, baselineSendTxCount=${baselineSendTxCount})`,
      ).toBe(true);
      expect(String(result.error)).toContain('threshold signingSession auth is unavailable');
      expect(authorizePostCount).toBeGreaterThan(0);
      expect(sendTxCount).toBe(baselineSendTxCount);
    } finally {
      await srv.close().catch(() => undefined);
    }
  });
});
