import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, handleInfrastructureErrors, SDK_ESM_PATHS } from '../setup';
import { buildWalletServiceHtml, registerWalletServiceRoute, waitFor, captureOverlay } from './harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';
const WAIT_FOR_SOURCE = `(${waitFor.toString()})`;
const CAPTURE_OVERLAY_SOURCE = `(${captureOverlay.toString()})`;

const stickyResponseScript = String.raw`
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;

        const respondSticky = (requestId) => {
          setTimeout(() => {
            try {
              adoptedPort.postMessage({
                type: 'PROGRESS',
                requestId,
                payload: {
                  step: 3,
                  phase: 'user-confirmation',
                  status: 'progress',
                  message: 'Awaiting authorization (sticky test)'
                }
              });
            } catch (err) {
              console.error('Failed to post PROGRESS for sticky test', err);
            }
          }, 20);

          setTimeout(() => {
            pendingRequests.delete(requestId);
            try {
              adoptedPort.postMessage({
                type: 'PM_RESULT',
                requestId,
                payload: {
                  ok: true,
                  result: null
                }
              });
            } catch (err) {
              console.error('Failed to post PM_RESULT for sticky test', err);
            }
          }, 60);
        };

        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object') return;
          if ((data.type === 'PM_EXPORT_NEAR_KEYPAIR_UI' || data.type === 'PM_EXPORT_KEYS_UI') && typeof data.requestId === 'string') {
            respondSticky(data.requestId);
            return;
          }
          if (data.type === 'PM_SIGN_TEMPO' && typeof data.requestId === 'string') {
            const requestId = data.requestId;
            setTimeout(() => {
              try {
                adoptedPort.postMessage({
                  type: 'PROGRESS',
                  requestId,
                  payload: {
                    step: 3,
                    phase: 'webauthn-authentication',
                    status: 'progress',
                    message: 'Authenticating with passkey (tempo sticky regression)'
                  }
                });
              } catch (err) {
                console.error('Failed to post PROGRESS(show) for PM_SIGN_TEMPO', err);
              }
            }, 20);
            setTimeout(() => {
              try {
                adoptedPort.postMessage({
                  type: 'PROGRESS',
                  requestId,
                  payload: {
                    step: 4,
                    phase: 'authentication-complete',
                    status: 'success',
                    message: 'Authentication complete'
                  }
                });
              } catch (err) {
                console.error('Failed to post PROGRESS(hide) for PM_SIGN_TEMPO', err);
              }
            }, 45);
            setTimeout(() => {
              pendingRequests.delete(requestId);
              try {
                adoptedPort.postMessage({
                  type: 'PM_RESULT',
                  requestId,
                  payload: {
                    ok: true,
                    result: { chain: 'evm', txHashHex: '0xabc', rawTxHex: '0xdef' }
                  }
                });
              } catch (err) {
                console.error('Failed to post PM_RESULT for PM_SIGN_TEMPO', err);
              }
            }, 70);
          }
        };
      };
`;

test.describe('WalletIframeRouter – sticky overlay lifecycle', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await page.waitForTimeout(200);
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: stickyResponseScript }),
      WALLET_SERVICE_ROUTE
    );
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  test('sticky requests keep overlay visible until explicit cancel', async ({ page }) => {
    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(async ({ walletOrigin, waitForSource, captureOverlaySource, routerPath }) => {
      const waitFor = eval(waitForSource) as typeof import('./harness').waitFor;
      const capture = eval(captureOverlaySource) as typeof import('./harness').captureOverlay;
      try {
        const mod = await import(routerPath);
        const { WalletIframeRouter } = mod as typeof import('@/core/WalletIframe/client/router');

        const router = new WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          connectTimeoutMs: 3000,
          requestTimeoutMs: 1200,
          debug: true,
          sdkBasePath: '/sdk',
        });
        await router.init();


        const stickyPromise = router.exportPrivateKeysWithUI('sticky.testnet', {
          schemes: ['ed25519', 'secp256k1'],
        });

        const shown = await waitFor(() => {
          const state = capture();
          return state.exists && state.visible;
        }, 3000);

        await stickyPromise;
        const afterResult = capture();
        const stillVisible = afterResult.exists && afterResult.visible;

        await router.cancelAll();
        const hidden = await waitFor(() => {
          const state = capture();
          if (!state.exists) return true;
          return !state.visible;
        }, 3000);

        return {
          success: true,
          shown,
          stillVisible,
          hidden,
          afterResult,
        } as const;
      } catch (error: any) {
        return { success: false, error: error?.message || String(error) } as const;
      }
    }, { walletOrigin: WALLET_ORIGIN, waitForSource: WAIT_FOR_SOURCE, captureOverlaySource: CAPTURE_OVERLAY_SOURCE, routerPath });

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.shown).toBe(true);
    expect(result.stillVisible).toBe(true);
    expect(result.hidden).toBe(true);
  });

  test('sticky demand does not pin later PM_SIGN_TEMPO overlay visibility', async ({ page }) => {
    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(async ({ walletOrigin, waitForSource, captureOverlaySource, routerPath }) => {
      const waitFor = eval(waitForSource) as typeof import('./harness').waitFor;
      const capture = eval(captureOverlaySource) as typeof import('./harness').captureOverlay;
      try {
        const mod = await import(routerPath);
        const { WalletIframeRouter } = mod as typeof import('@/core/WalletIframe/client/router');

        const router = new WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          connectTimeoutMs: 3000,
          requestTimeoutMs: 1200,
          debug: true,
          sdkBasePath: '/sdk',
        });
        await router.init();

        await router.exportPrivateKeysWithUI('sticky.testnet', {
          schemes: ['ed25519', 'secp256k1'],
        });

        // Simulate wallet-host export UI close cleanup (release sticky + hide),
        // while intentionally leaving the sticky subscription entry alive.
        (router as any).overlayState.controller.setSticky(false);
        (router as any).hideFrameForActivation();

        const hiddenAfterExportClose = await waitFor(() => {
          const state = capture();
          if (!state.exists) return true;
          return !state.visible;
        }, 3000);

        const signPromise = (router as any).signTempo({
          nearAccountId: 'sticky.testnet',
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {},
          },
        });

        const shownForTempo = await waitFor(() => {
          const state = capture();
          return state.exists && state.visible;
        }, 3000);

        await signPromise;
        const hiddenAfterTempoResult = await waitFor(() => {
          const state = capture();
          if (!state.exists) return true;
          return !state.visible;
        }, 3000);

        return {
          success: true,
          hiddenAfterExportClose,
          shownForTempo,
          hiddenAfterTempoResult,
        } as const;
      } catch (error: any) {
        return { success: false, error: error?.message || String(error) } as const;
      }
    }, { walletOrigin: WALLET_ORIGIN, waitForSource: WAIT_FOR_SOURCE, captureOverlaySource: CAPTURE_OVERLAY_SOURCE, routerPath });

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.hiddenAfterExportClose).toBe(true);
    expect(result.shownForTempo).toBe(true);
    expect(result.hiddenAfterTempoResult).toBe(true);
  });
});
