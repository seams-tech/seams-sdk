import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, handleInfrastructureErrors, SDK_ESM_PATHS } from '../setup';
import {
  buildWalletServiceHtml,
  registerWalletServiceRoute,
  waitFor,
  captureOverlay,
} from './harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';
const WAIT_FOR_SOURCE = `(${waitFor.toString()})`;
const CAPTURE_OVERLAY_SOURCE = `(${captureOverlay.toString()})`;
const SIGN_TEMPO_SESSION_LOSS_SCRIPT = String.raw`
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;
        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object') return;
          if (data.type !== 'PM_SIGN_TEMPO' || typeof data.requestId !== 'string') return;
          const requestId = data.requestId;
          setTimeout(() => {
            pendingRequests.delete(requestId);
            try {
              adoptedPort.postMessage({
                type: 'ERROR',
                requestId,
                payload: {
                  code: 'session_not_ready',
                  message:
                    '[SigningEngine] missing canonical threshold ECDSA session for alice.testnet; reconnect threshold session via bootstrapEcdsaSession',
                },
              });
            } catch (err) {
              console.error('Failed to post ERROR for PM_SIGN_TEMPO session loss test', err);
            }
          }, 20);
        };
      };
`;
const FAILED_UNLOCK_WITH_ACTIVE_EMAIL_OTP_SESSION_SCRIPT = String.raw`
      const accountId = 'crisp-plain-29ph888gzw.w3a-relayer.testnet';
      const postResult = (requestId, result) => {
        pendingRequests.delete(requestId);
        adoptedPort.postMessage({
          type: 'PM_RESULT',
          requestId,
          payload: { ok: true, result },
        });
      };
      const activeEmailOtpSession = {
        login: {
          isLoggedIn: true,
          nearAccountId: accountId,
          publicKey: null,
          userData: null,
          authMethod: 'email_otp',
        },
        signingSession: {
          status: 'active',
          sessionId: 'email-otp-session-1',
          authMethod: 'email_otp',
          retention: 'session',
        },
        authMethod: 'email_otp',
        retention: 'session',
      };
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;
        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object' || typeof data.requestId !== 'string') return;
          const requestId = data.requestId;
          if (data.type === 'PM_GET_WALLET_SESSION') {
            postResult(requestId, activeEmailOtpSession);
            return;
          }
          if (data.type === 'PM_UNLOCK') {
            adoptedPort.postMessage({
              type: 'PROGRESS',
              requestId,
              payload: {
                version: 2,
                flow: 'unlock',
                step: 99,
                phase: 'unlock.failed',
                status: 'failed',
                message: 'No authenticators found for account ' + accountId + '. Please register an account.',
                flowId: 'unlock:test:' + requestId,
                requestId,
                accountId,
                authMethod: 'passkey',
                error: {
                  message: 'No authenticators found for account ' + accountId + '. Please register an account.',
                },
              },
            });
            postResult(requestId, {
              success: false,
              error: 'No authenticators found for account ' + accountId + '. Please register an account.',
            });
          }
        };
      };
`;
const CAPTURE_UNLOCK_PAYLOAD_SCRIPT = String.raw`
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;
        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object' || data.type !== 'PM_UNLOCK') return;
          const requestId = data.requestId;
          if (typeof requestId !== 'string') return;
          pendingRequests.delete(requestId);
          window.parent?.postMessage(
            {
              type: 'CAPTURED_PM_UNLOCK_PAYLOAD',
              payload: data.payload,
            },
            '*',
          );
          adoptedPort.postMessage({
            type: 'PM_RESULT',
            requestId,
            payload: {
              ok: true,
              result: { success: false, error: 'captured unlock payload' },
            },
          });
        };
      };
`;

test.describe('WalletIframeRouter – overlay + timeout behavior', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await page.waitForTimeout(200);
    // Register wallet service route with default stub which sends READY and PROGRESS but no PM_RESULT
    await registerWalletServiceRoute(page, buildWalletServiceHtml(), WALLET_SERVICE_ROUTE);
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  test('executeAction shows overlay then hides it after request timeout', async ({ page }) => {
    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, waitForSource, captureOverlaySource, routerPath }) => {
        const waitFor = eval(waitForSource) as typeof import('./harness').waitFor;
        const capture = eval(captureOverlaySource) as typeof import('./harness').captureOverlay;
        try {
          // Dynamically import the router from built ESM
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');

          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 200, // short timeout to exercise cleanup
            debug: true,
            sdkBasePath: '/sdk',
          });
          await router.init();

          // Fire-and-forget request that will time out since the stub never replies with PM_RESULT
          const p = router
            .executeAction({
              nearAccountId: 'e2e_router_timeout.testnet',
              receiverId: 'w3a-v1.testnet',
              actionArgs: { type: 'Transfer', amount: '1' } as any,
              options: {},
            })
            .catch((e) => ({ ok: false, error: String(e?.message || e) }));

          // Expect overlay to become visible soon after posting
          const shown = await waitFor(() => {
            const s = capture();
            return s.exists && s.visible;
          }, 3000);

          // Wait for timeout path and cleanup
          await p;
          // Wait for overlay to contract (hide) after timeout cleanup
          const hidden = await waitFor(() => {
            const s = capture();
            if (!s.exists) return true; // entirely removed counts as hidden
            return !s.visible;
          }, 3000);
          const after = capture();

          return { success: true, shown, hidden, after };
        } catch (error: any) {
          return { success: false, error: error?.message || String(error) };
        }
      },
      {
        walletOrigin: WALLET_ORIGIN,
        waitForSource: WAIT_FOR_SOURCE,
        captureOverlaySource: CAPTURE_OVERLAY_SOURCE,
        routerPath,
      },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.shown).toBe(true);
    // After timeout, overlay should contract and become inert
    if (!result.hidden) {
      console.log('[router.behavior] overlay state after timeout', result.after);
    }
    expect(result.hidden).toBe(true);
  });

  test('executeAction still times out when host keeps sending PROGRESS frames', async ({
    page,
  }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    const spamProgressHtml = buildWalletServiceHtml({
      extraScript: `
        setInterval(() => {
          if (!adoptedPort) return;
          for (const requestId of pendingRequests.keys()) {
            try {
              adoptedPort.postMessage({
                type: 'PROGRESS',
                requestId,
                payload: {
                  version: 2,
                  flow: 'signing',
                  step: 10,
                  phase: 'signing.commit.started',
                  status: 'running',
                  message: 'Creating threshold signature',
                  flowId: 'signing:test:' + requestId,
                  requestId,
                  interaction: { kind: 'none', overlay: 'none' }
                }
              });
            } catch (err) {
              console.error('Failed to spam PROGRESS frame', err);
            }
          }
        }, 40);
      `,
    });
    await registerWalletServiceRoute(page, spamProgressHtml, WALLET_SERVICE_ROUTE);

    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, routerPath }) => {
        try {
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');

          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 200,
            debug: true,
            sdkBasePath: '/sdk',
          });
          await router.init();

          const start = Date.now();
          const outcome = await router
            .executeAction({
              nearAccountId: 'e2e_router_progress_timeout.testnet',
              receiverId: 'w3a-v1.testnet',
              actionArgs: { type: 'Transfer', amount: '1' } as any,
              options: {},
            })
            .then(
              () => ({ ok: true as const }),
              (error: unknown) => ({
                ok: false as const,
                error: String((error as { message?: unknown })?.message || error || ''),
                elapsedMs: Date.now() - start,
              }),
            );

          return { success: true as const, outcome };
        } catch (error: unknown) {
          return {
            success: false as const,
            error: String((error as { message?: unknown })?.message || error || ''),
          };
        }
      },
      { walletOrigin: WALLET_ORIGIN, routerPath },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.outcome.ok).toBe(false);
    if (result.outcome.ok) return;
    expect(result.outcome.error).toContain('Wallet request timeout for PM_EXECUTE_ACTION');
    expect(result.outcome.elapsedMs).toBeGreaterThanOrEqual(500);
    expect(result.outcome.elapsedMs).toBeLessThan(2500);
  });

  test('signTempo session-loss error is surfaced as session_not_ready with canonical guidance', async ({
    page,
  }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: SIGN_TEMPO_SESSION_LOSS_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );

    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, routerPath }) => {
        try {
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');

          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 800,
            debug: true,
            sdkBasePath: '/sdk',
          });
          await router.init();

          const outcome = await (router as any)
            .signTempo({
              nearAccountId: 'alice.testnet',
              request: {
                chain: 'evm',
                kind: 'eip1559',
                senderSignatureAlgorithm: 'secp256k1',
                tx: {},
              },
            })
            .then(
              () => ({ ok: true as const }),
              (error: any) => ({
                ok: false as const,
                code: String(error?.code || ''),
                message: String(error?.message || ''),
              }),
            );

          return { success: true as const, outcome };
        } catch (error: any) {
          return { success: false as const, error: error?.message || String(error) };
        }
      },
      { walletOrigin: WALLET_ORIGIN, routerPath },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.outcome.ok).toBe(false);
    if (result.outcome.ok) return;
    expect(result.outcome.code).toBe('session_not_ready');
    expect(result.outcome.message).toContain('Threshold signing session is not ready');
    expect(result.outcome.message).toContain('Refresh the signing session');
    expect(result.outcome.message).not.toContain('missing canonical threshold ECDSA session');
  });

  test('failed passkey unlock does not publish stale Email OTP login status', async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({
        extraScript: FAILED_UNLOCK_WITH_ACTIVE_EMAIL_OTP_SESSION_SCRIPT,
      }),
      WALLET_SERVICE_ROUTE,
    );

    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, routerPath }) => {
        try {
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');

          const accountId = 'crisp-plain-29ph888gzw.w3a-relayer.testnet';
          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 1000,
            debug: true,
            sdkBasePath: '/sdk',
          });
          await router.init();

          const statuses: Array<{ isLoggedIn: boolean; walletId: string | null }> = [];
          router.onLoginStatusChanged((status) => statuses.push(status));

          const unlockResult = await router.unlock({
            kind: 'default_options',
            nearAccountId: accountId,
          });

          return {
            success: true as const,
            unlockResult,
            statuses,
          };
        } catch (error: unknown) {
          return {
            success: false as const,
            error: String((error as { message?: unknown })?.message || error || ''),
          };
        }
      },
      { walletOrigin: WALLET_ORIGIN, routerPath },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.unlockResult.success).toBe(false);
    expect(result.unlockResult.error).toContain('No authenticators found');
    expect(result.statuses).toEqual([]);
  });

  test('unlock posts strict protocol options for selection and ECDSA inventory', async ({
    page,
  }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({
        extraScript: CAPTURE_UNLOCK_PAYLOAD_SCRIPT,
      }),
      WALLET_SERVICE_ROUTE,
    );

    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, routerPath }) => {
        const capturedPayload = new Promise((resolve) => {
          const onMessage = (event: MessageEvent) => {
            const data = event.data || {};
            if (!data || typeof data !== 'object') return;
            if ((data as { type?: unknown }).type !== 'CAPTURED_PM_UNLOCK_PAYLOAD') return;
            window.removeEventListener('message', onMessage);
            resolve((data as { payload: unknown }).payload);
          };
          window.addEventListener('message', onMessage);
        });

        try {
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');
          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 1000,
            debug: true,
            sdkBasePath: '/sdk',
          });
          await router.init();

          const unlockResult = await router.unlock({
            kind: 'custom_options',
            nearAccountId: 'alice.testnet',
            options: {
              signerSlot: 2,
              session: {
                kind: 'jwt',
                relayUrl: 'https://relay.example.localhost',
                route: '/session/exchange',
              },
              signingSession: {
                ttlMs: 60_000,
                remainingUses: 2,
              },
              unlockSelection: {
                mode: 'ecdsa_only',
                ecdsa: true,
              },
              ecdsaKeyFactsInventory: {
                mode: 'app_session',
                appSessionJwt: 'app-session-jwt',
                policyTtlMs: 30_000,
              },
            },
          });

          return {
            success: true as const,
            unlockResult,
            capturedPayload: await capturedPayload,
          };
        } catch (error: unknown) {
          return {
            success: false as const,
            error: String((error as { message?: unknown })?.message || error || ''),
          };
        }
      },
      { walletOrigin: WALLET_ORIGIN, routerPath },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.unlockResult).toEqual({
      success: false,
      error: 'captured unlock payload',
    });
    expect(result.capturedPayload).toEqual({
      kind: 'custom_options',
      nearAccountId: 'alice.testnet',
      options: {
        kind: 'pm_unlock_options_v1',
        signerSlot: { kind: 'value', value: 2 },
        session: {
          kind: 'value',
          value: {
            kind: 'jwt',
            relayUrl: 'https://relay.example.localhost',
            route: '/session/exchange',
          },
        },
        signingSession: {
          kind: 'value',
          value: {
            ttlMs: 60_000,
            remainingUses: 2,
          },
        },
        unlockSelection: {
          kind: 'value',
          value: {
            mode: 'ecdsa_only',
            ecdsa: true,
          },
        },
        ecdsaKeyFactsInventory: {
          kind: 'value',
          value: {
            mode: 'app_session',
            appSessionJwt: 'app-session-jwt',
            policyTtlMs: 30_000,
          },
        },
      },
    });
  });
});
