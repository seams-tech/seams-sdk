import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { buildWalletServiceHtml, registerWalletServiceRoute, captureOverlay } from './harness';

const IMPORT_PATHS = {
  provider: '/sdk/esm/react/context/SeamsWebProvider.js',
  passkeyAuthMenu: '/sdk/esm/react/components/PasskeyAuthMenu/public.js',
} as const;

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';
const CAPTURE_OVERLAY_SOURCE = `(${captureOverlay.toString()})`;

const qrFlowResponseScript = String.raw`
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;

        const respondOk = (requestId, result) => {
          pendingRequests.delete(requestId);
          try {
            adoptedPort.postMessage({
              type: 'PM_RESULT',
              requestId,
              payload: { ok: true, result }
            });
          } catch (err) {
            console.error('Failed to post PM_RESULT in QR regression harness', err);
          }
        };

        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object') return;
          const requestId = typeof data.requestId === 'string' ? data.requestId : '';
          if (!requestId) return;

          if (data.type === 'PM_SET_CONFIG') return;

          if (data.type === 'PM_GET_WALLET_SESSION') {
            respondOk(requestId, {
              login: {
                isLoggedIn: false,
                nearAccountId: null,
                publicKey: null,
                userData: null
              },
              signingSession: null
            });
            return;
          }

          if (data.type === 'PM_GET_RECENT_UNLOCKS') {
            respondOk(requestId, {
              accountIds: [],
              lastUsedAccount: null
            });
            return;
          }

          if (data.type === 'PM_START_DEVICE2_LINKING_FLOW') {
            try {
              window.parent?.postMessage({ type: 'W3A_TEST_PM_START_LINKING_SEEN' }, '*');
            } catch {}
            setTimeout(() => {
              if (!pendingRequests.has(requestId)) return;
              respondOk(requestId, {
                qrData: {
                  sessionId: 'session-qr-regression',
                  timestamp: Date.now(),
                  version: '1'
                },
                qrCodeDataURL: 'data:image/svg+xml;base64,PHN2Zz48L3N2Zz4='
              });
            }, 300);
            return;
          }

          if (data.type === 'PM_STOP_DEVICE2_LINKING_FLOW') {
            respondOk(requestId, undefined);
            return;
          }

          if (data.type === 'PM_SET_THEME' || data.type === 'PM_PREFETCH_BLOCKHEIGHT') {
            respondOk(requestId, undefined);
            return;
          }
        };
      };
`;

test.describe('PasskeyAuthMenu QR button overlay regression', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: qrFlowResponseScript }),
      WALLET_SERVICE_ROUTE,
    );
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  test('clicking Scan and Link Device keeps wallet iframe overlay hidden', async ({ page }) => {
    await page.evaluate(
      async ({ paths, walletOrigin }) => {
        const prevRoot = (window as any).__w3aQrRegressionRoot;
        if (prevRoot?.unmount) prevRoot.unmount();

        let mount = document.getElementById('w3a-qr-regression-mount');
        if (!mount) {
          mount = document.createElement('div');
          mount.id = 'w3a-qr-regression-mount';
          document.body.appendChild(mount);
        }

        const React = await import('react');
        const ReactRuntime = (React as any).default || React;
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOMClientRuntime = (ReactDOMClient as any).default || ReactDOMClient;
        const ReactDOM = await import('react-dom');
        const ReactDOMRuntime = (ReactDOM as any).default || ReactDOM;

        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.passkeyAuthMenu);
        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const PasskeyAuthMenu = menuMod.PasskeyAuthMenu || menuMod.default;
        const AuthMenuMode = menuMod.AuthMenuMode;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: {
            walletOrigin,
            walletServicePath: '/wallet-service',
            sdkBasePath: '/sdk',
            rpIdOverride: 'example.localhost',
          },
        };

        const root = ReactDOMClientRuntime.createRoot(mount);
        ReactDOMRuntime.flushSync(() => {
          root.render(
            ReactRuntime.createElement(
              Provider,
              { config },
              ReactRuntime.createElement(PasskeyAuthMenu, { defaultMode: AuthMenuMode.Login }),
            ),
          );
        });
        (window as any).__w3aQrRegressionRoot = root;
      },
      { paths: IMPORT_PATHS, walletOrigin: WALLET_ORIGIN },
    );

    const capture = async () =>
      page.evaluate(
        ({ captureOverlaySource }) => {
          const fn = eval(captureOverlaySource) as () => {
            exists: boolean;
            visible: boolean;
          };
          return fn();
        },
        { captureOverlaySource: CAPTURE_OVERLAY_SOURCE },
      );

    const mount = page.locator('#w3a-qr-regression-mount');
    const qrButton = mount.getByRole('button', { name: 'Scan and Link Device' }).first();
    await expect(qrButton).toBeVisible();
    await expect(qrButton).toBeEnabled();

    const beforeClick = await capture();
    if (beforeClick.exists) expect(beforeClick.visible).toBe(false);

    await qrButton.click();
    await expect(mount.locator('.w3a-signup-menu-root[data-scan-device="true"]')).toBeVisible();
    await page.waitForTimeout(120);

    const duringLoading = await capture();
    expect(duringLoading.visible).toBe(false);

    await expect(mount.locator('img[alt="Device Linking QR Code"]')).toBeVisible();

    const afterQrReady = await capture();
    expect(afterQrReady.visible).toBe(false);

    const backButton = mount.getByRole('button', { name: 'Back' }).first();
    await expect(backButton).toBeVisible();
    await backButton.click();
    await expect(mount.locator('.w3a-signup-menu-root[data-scan-device="false"]')).toBeVisible();
    await expect(qrButton).toBeVisible();
  });
});
