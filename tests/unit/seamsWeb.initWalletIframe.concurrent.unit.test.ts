import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { buildWalletServiceHtml, registerWalletServiceRoute } from '../wallet-iframe/harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';

// Extend the default wallet-service stub so initWalletIframe() can complete.
// initWalletIframe() triggers router.init() + getWalletSession() paths that await
// responses for PM_SET_CONFIG, PM_GET_WALLET_SESSION, and PM_PREFETCH_BLOCKHEIGHT.
// The base stub logs these but doesn't reply, so we patch in canned responses.
const WALLET_STUB_RESPONSE_SCRIPT = String.raw`
  const originalAdoptPort = adoptPort;
  adoptPort = function patchedAdoptPort(port) {
    originalAdoptPort(port);
    if (!adoptedPort) return;

    const originalHandler = adoptedPort.onmessage;
    adoptedPort.onmessage = (event) => {
      originalHandler?.(event);
      const data = event.data || {};
      if (!data || typeof data !== 'object') return;
      const requestId = data.requestId;
      if (typeof requestId !== 'string') return;

      const respond = (result) => {
        try {
          pendingRequests.delete(requestId);
          adoptedPort.postMessage({ type: 'PM_RESULT', requestId, payload: { ok: true, result } });
        } catch (err) {
          console.error('post PM_RESULT failed', err);
        }
      };

      // Router init posts PM_SET_CONFIG and expects a response.
      if (data.type === 'PM_SET_CONFIG') {
        respond(null);
      }

      if (data.type === 'PM_PREFETCH_BLOCKHEIGHT') {
        respond(null);
      }

      if (data.type === 'PM_GET_WALLET_SESSION') {
        respond({
          login: {
            isLoggedIn: false,
            nearAccountId: null,
            publicKey: null,
            userData: null,
          },
          signingSession: null,
        });
      }

      if (data.type === 'PM_GET_CONFIRMATION_CONFIG') {
        respond({ behavior: 'requireClick', uiMode: 'modal' });
      }
    };
  };
`;

const WALLET_STUB_EARLY_PREFERENCES_SCRIPT = String.raw`
  const originalAdoptPort = adoptPort;
  adoptPort = function patchedAdoptPort(port) {
    originalAdoptPort(port);
    if (!adoptedPort) return;

    const originalHandler = adoptedPort.onmessage;
    adoptedPort.onmessage = (event) => {
      const data = event.data || {};
      if (data && data.type === 'PM_SET_CONFIG') {
        adoptedPort.postMessage({
          type: 'PREFERENCES_CHANGED',
          payload: {
            walletId: 'restored-session-wallet',
            confirmationConfig: { behavior: 'requireClick', uiMode: 'modal' },
            updatedAt: Date.now(),
          },
        });
      }
      originalHandler?.(event);
      if (!data || typeof data !== 'object') return;
      const requestId = data.requestId;
      if (typeof requestId !== 'string') return;

      const respond = (result) => {
        try {
          pendingRequests.delete(requestId);
          adoptedPort.postMessage({ type: 'PM_RESULT', requestId, payload: { ok: true, result } });
        } catch (err) {
          console.error('post PM_RESULT failed', err);
        }
      };

      if (data.type === 'PM_PREFETCH_BLOCKHEIGHT') {
        respond(null);
      }
      if (data.type === 'PM_GET_WALLET_SESSION') {
        respond({
          login: {
            isLoggedIn: false,
            nearAccountId: null,
            publicKey: null,
            userData: null,
          },
          signingSession: null,
        });
      }
      if (data.type === 'PM_GET_CONFIRMATION_CONFIG') {
        respond({ behavior: 'requireClick', uiMode: 'modal' });
      }
    };
  };
`;

test.describe('SeamsWeb.initWalletIframe', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: WALLET_STUB_RESPONSE_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await page.unroute(WALLET_SERVICE_ROUTE.replace('wallet-service', 'service')).catch(() => {});
  });

  test('does not mount multiple wallet iframes on concurrent init', async ({ page }) => {
    const result = await page.evaluate(
      async ({ walletOrigin }) => {
        const mod = await import('/sdk/esm/SeamsWeb/index.js');
        const { SeamsWeb } = mod as any;

        // Defensive: ensure a clean slate.
        for (const el of Array.from(document.querySelectorAll('iframe.w3a-wallet-overlay'))) {
          try {
            el.remove();
          } catch {}
        }

        const pm = new SeamsWeb({
          relayer: { url: 'http://localhost:3000' },
          iframeWallet: {
            walletOrigin,
            walletServicePath: '/wallet-service',
            sdkBasePath: '/sdk',
          },
        });

        const timeoutMs = 12_000;
        const start = Date.now();
        const init = Promise.all([
          pm.initWalletIframe(),
          pm.initWalletIframe(),
          pm.initWalletIframe(),
          pm.initWalletIframe(),
        ])
          .then(() => ({ ok: true as const }))
          .catch((err) => ({ ok: false as const, error: String(err?.message || err) }));

        const out = await Promise.race([
          init,
          new Promise<{ ok: false; error: string }>((resolve) =>
            setTimeout(
              () =>
                resolve({
                  ok: false,
                  error: `timeout after ${timeoutMs}ms (elapsed ${Date.now() - start}ms)`,
                }),
              timeoutMs,
            ),
          ),
        ]);

        const waitUntilReady = async (pmInst: any, waitMs = 1000): Promise<boolean> => {
          const started = Date.now();
          while (Date.now() - started < waitMs) {
            try {
              if (pmInst.isWalletIframeReady?.()) return true;
            } catch {}
            await new Promise((resolve) => setTimeout(resolve, 25));
          }
          try {
            return !!pmInst.isWalletIframeReady?.();
          } catch {
            return false;
          }
        };

        return {
          ok: out.ok,
          error: (out as any).error,
          iframeCount: document.querySelectorAll('iframe.w3a-wallet-overlay').length,
          routerReady: await waitUntilReady(pm),
        };
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    expect(result.ok, JSON.stringify(result)).toBe(true);
    expect(result.iframeCount).toBe(1);
  });

  test('adopts wallet-host current wallet from early preferences event', async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await page.unroute(WALLET_SERVICE_ROUTE.replace('wallet-service', 'service')).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: WALLET_STUB_EARLY_PREFERENCES_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );

    const result = await page.evaluate(
      async ({ walletOrigin }) => {
        const mod = await import('/sdk/esm/SeamsWeb/index.js');
        const { SeamsWeb } = mod as any;
        const observedWalletIds: string[] = [];

        const pm = new SeamsWeb({
          relayer: { url: 'http://localhost:3000' },
          iframeWallet: {
            walletOrigin,
            walletServicePath: '/wallet-service',
            sdkBasePath: '/sdk',
          },
        });
        pm.preferences.onCurrentWalletChange((walletId: string | null) => {
          observedWalletIds.push(String(walletId || ''));
        });

        await pm.initWalletIframe();

        const latePreferencesPayloads: string[] = [];
        pm.onWalletIframePreferencesChanged((payload: { walletId: string | null }) => {
          latePreferencesPayloads.push(String(payload.walletId || ''));
        });

        return {
          currentWalletId: String(pm.preferences.getCurrentWalletId() || ''),
          observedWalletIds,
          latePreferencesPayloads,
        };
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    expect(result).toEqual({
      currentWalletId: 'restored-session-wallet',
      observedWalletIds: ['restored-session-wallet'],
      latePreferencesPayloads: ['restored-session-wallet'],
    });
  });
});
