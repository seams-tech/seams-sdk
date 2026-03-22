import { expect, test } from '@playwright/test';
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

const exportFlowScript = String.raw`
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;
        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object') return;
          if (data.type !== 'PM_EXPORT_KEYPAIR_UI' || typeof data.requestId !== 'string') return;

          try {
            window.parent?.postMessage({
              type: 'TEST_MARKER',
              marker: 'EXPORT_REQUEST_CAPTURED',
              payload: data.payload || {},
              requestId: data.requestId,
            }, '*');
          } catch {}

          setTimeout(() => {
            try {
              adoptedPort.postMessage({
                type: 'PROGRESS',
                requestId: data.requestId,
                payload: {
                  step: 2,
                  phase: 'user-confirmation',
                  status: 'progress',
                  message: 'Export confirmation pending',
                },
              });
            } catch (err) {
              console.error('Failed to post export PROGRESS', err);
            }
          }, 20);

          setTimeout(() => {
            pendingRequests.delete(data.requestId);
            try {
              adoptedPort.postMessage({
                type: 'PM_RESULT',
                requestId: data.requestId,
                payload: { ok: true, result: null },
              });
            } catch (err) {
              console.error('Failed to post export PM_RESULT', err);
            }
          }, 80);

          setTimeout(() => {
            try {
              window.parent?.postMessage({ type: 'WALLET_UI_CLOSED' }, '*');
              window.parent?.postMessage({ type: 'TEST_MARKER', marker: 'EXPORT_UI_CLOSED' }, '*');
            } catch (err) {
              console.error('Failed to post WALLET_UI_CLOSED', err);
            }
          }, 260);
        };
      };
`;

const exportSigningIsolationScript = String.raw`
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;
        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object' || typeof data.requestId !== 'string') return;

          if (data.type === 'PM_EXPORT_KEYPAIR_UI') {
            try {
              window.parent?.postMessage({
                type: 'TEST_MARKER',
                marker: 'EXPORT_REQUEST_CAPTURED',
                requestId: data.requestId,
              }, '*');
            } catch {}

            setTimeout(() => {
              try {
                adoptedPort.postMessage({
                  type: 'PROGRESS',
                  requestId: data.requestId,
                  payload: {
                    step: 2,
                    phase: 'user-confirmation',
                    status: 'progress',
                    message: 'Export confirmation pending',
                  },
                });
              } catch (err) {
                console.error('Failed to post export PROGRESS', err);
              }
            }, 20);

            setTimeout(() => {
              pendingRequests.delete(data.requestId);
              try {
                adoptedPort.postMessage({
                  type: 'PM_RESULT',
                  requestId: data.requestId,
                  payload: { ok: true, result: null },
                });
              } catch (err) {
                console.error('Failed to post export PM_RESULT', err);
              }
            }, 100);

            setTimeout(() => {
              try {
                window.parent?.postMessage({ type: 'WALLET_UI_CLOSED' }, '*');
                window.parent?.postMessage({ type: 'TEST_MARKER', marker: 'EXPORT_UI_CLOSED' }, '*');
              } catch (err) {
                console.error('Failed to post export close marker', err);
              }
            }, 900);
            return;
          }

          if (data.type === 'PM_EXECUTE_ACTION') {
            try {
              window.parent?.postMessage({
                type: 'TEST_MARKER',
                marker: 'SIGNING_REQUEST_CAPTURED',
                requestId: data.requestId,
              }, '*');
            } catch {}

            setTimeout(() => {
              try {
                adoptedPort.postMessage({
                  type: 'PROGRESS',
                  requestId: data.requestId,
                  payload: {
                    step: 2,
                    phase: 'user-confirmation',
                    status: 'progress',
                    message: 'Signing confirmation pending',
                  },
                });
              } catch (err) {
                console.error('Failed to post signing PROGRESS', err);
              }
            }, 40);

            setTimeout(() => {
              pendingRequests.delete(data.requestId);
              try {
                adoptedPort.postMessage({
                  type: 'PM_RESULT',
                  requestId: data.requestId,
                  payload: { ok: true, result: { ok: true, source: 'signing' } },
                });
                window.parent?.postMessage({
                  type: 'TEST_MARKER',
                  marker: 'SIGNING_RESULT',
                  requestId: data.requestId,
                }, '*');
              } catch (err) {
                console.error('Failed to post signing PM_RESULT', err);
              }
            }, 180);
          }
        };
      };
`;

test.describe('wallet-origin export flow integration', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await page.waitForTimeout(200);
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  test('export flow completes and overlay closes on wallet-origin WALLET_UI_CLOSED', async ({
    page,
  }) => {
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: exportFlowScript }),
      WALLET_SERVICE_ROUTE,
    );

    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, waitForSource, captureOverlaySource, routerPath }) => {
        const waitFor = eval(waitForSource) as typeof import('./harness').waitFor;
        const capture = eval(captureOverlaySource) as typeof import('./harness').captureOverlay;
        try {
          const mod = await import(routerPath);
          const { WalletIframeRouter } = mod as typeof import('@/core/WalletIframe/client/router');

          const marks: Record<string, boolean> = {};
          let capturedPayload: Record<string, unknown> | null = null;
          window.addEventListener('message', (ev) => {
            const data = ev.data || {};
            if (!data || typeof data !== 'object') return;
            if ((data as any).type !== 'TEST_MARKER') return;
            const marker = String((data as any).marker || '');
            if (marker) marks[marker] = true;
            if (marker === 'EXPORT_REQUEST_CAPTURED') {
              capturedPayload = ((data as any).payload || null) as Record<string, unknown> | null;
            }
          });

          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 1800,
            debug: true,
            sdkBasePath: '/sdk',
          });
          await router.init();

          const exportPromise = router.exportKeypairWithUI('export-flow.testnet', {
            chain: 'near',
            variant: 'drawer',
            theme: 'light',
          });

          const shown = await waitFor(() => {
            const state = capture();
            return state.exists && state.visible;
          }, 3000);

          await exportPromise;
          const visibleAfterExportPromise = (() => {
            const state = capture();
            return state.exists && state.visible;
          })();

          const closeMarker = await waitFor(() => !!marks.EXPORT_UI_CLOSED, 3000);
          const hiddenAfterClose = await waitFor(() => {
            const state = capture();
            if (!state.exists) return true;
            return !state.visible;
          }, 3000);

          return {
            success: true,
            shown,
            visibleAfterExportPromise,
            closeMarker,
            hiddenAfterClose,
            exportPayload: capturedPayload,
          } as const;
        } catch (error: any) {
          return { success: false, error: error?.message || String(error) } as const;
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
    expect(result.visibleAfterExportPromise).toBe(true);
    expect(result.closeMarker).toBe(true);
    expect(result.hiddenAfterClose).toBe(true);
    expect(result.exportPayload).toMatchObject({
      nearAccountId: 'export-flow.testnet',
      chain: 'near',
      variant: 'drawer',
      theme: 'light',
    });
  });

  test('concurrent export and signing remain isolated and do not cross-talk', async ({ page }) => {
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: exportSigningIsolationScript }),
      WALLET_SERVICE_ROUTE,
    );

    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, waitForSource, captureOverlaySource, routerPath }) => {
        const waitFor = eval(waitForSource) as typeof import('./harness').waitFor;
        const capture = eval(captureOverlaySource) as typeof import('./harness').captureOverlay;
        try {
          const mod = await import(routerPath);
          const { WalletIframeRouter } = mod as typeof import('@/core/WalletIframe/client/router');

          const marks: Record<string, boolean> = {};
          let exportRequestId = '';
          let signingRequestId = '';
          window.addEventListener('message', (ev) => {
            const data = ev.data || {};
            if (!data || typeof data !== 'object') return;
            if ((data as any).type !== 'TEST_MARKER') return;
            const marker = String((data as any).marker || '');
            if (marker) marks[marker] = true;
            if (marker === 'EXPORT_REQUEST_CAPTURED') {
              exportRequestId = String((data as any).requestId || '').trim();
            }
            if (marker === 'SIGNING_REQUEST_CAPTURED') {
              signingRequestId = String((data as any).requestId || '').trim();
            }
          });

          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 2200,
            debug: true,
            sdkBasePath: '/sdk',
          });
          await router.init();

          const exportPromise = router.exportKeypairWithUI('isolation.testnet', {
            chain: 'near',
            variant: 'drawer',
            theme: 'dark',
          });
          const shown = await waitFor(() => {
            const state = capture();
            return state.exists && state.visible;
          }, 3000);

          const signPromise = router.executeAction({
            nearAccountId: 'isolation.testnet',
            receiverId: 'w3a-v1.testnet',
            actionArgs: { type: 'Transfer', amount: '1' } as any,
            options: {},
          });

          const visibleDuringSigning = await waitFor(() => {
            if (!marks.SIGNING_REQUEST_CAPTURED) return false;
            const state = capture();
            return state.exists && state.visible;
          }, 3000);
          const signingResultMarker = await waitFor(() => !!marks.SIGNING_RESULT, 3000);
          const [exportResult, signingResult] = await Promise.all([
            exportPromise.then(() => ({ ok: true })),
            signPromise,
          ]);

          const closeMarker = await waitFor(() => !!marks.EXPORT_UI_CLOSED, 3000);
          const hiddenAfterClose = await waitFor(() => {
            const state = capture();
            if (!state.exists) return true;
            return !state.visible;
          }, 3000);

          return {
            success: true,
            shown,
            visibleDuringSigning,
            signingResultMarker,
            exportResult,
            signingResult,
            closeMarker,
            hiddenAfterClose,
            exportRequestId,
            signingRequestId,
          } as const;
        } catch (error: any) {
          return { success: false, error: error?.message || String(error) } as const;
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
    expect(result.visibleDuringSigning).toBe(true);
    expect(result.signingResultMarker).toBe(true);
    expect(result.exportResult).toEqual({ ok: true });
    expect(result.signingResult).toMatchObject({ ok: true, source: 'signing' });
    expect(result.closeMarker).toBe(true);
    expect(result.hiddenAfterClose).toBe(true);
    expect(result.exportRequestId).toBeTruthy();
    expect(result.signingRequestId).toBeTruthy();
    expect(result.exportRequestId).not.toBe(result.signingRequestId);
  });
});
