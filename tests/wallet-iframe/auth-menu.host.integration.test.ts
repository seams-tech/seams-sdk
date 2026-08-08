import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { injectImportMap } from '../setup/bootstrap';
import { registerWalletServiceRoute } from './harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';

const HOST_HTML = String.raw`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Wallet auth-menu host</title>
  </head>
  <body>
    <script type="module" src="/_test-sdk/esm/sdk/wallet-iframe-host-runtime.js"></script>
  </body>
</html>`;

test.describe('wallet-host auth-menu integration', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, {
      skipSeamsWebInit: true,
      injectWalletServiceImportMap: true,
    });
    await page.goto('about:blank');
    await injectImportMap(page);
    await registerWalletServiceRoute(page, HOST_HTML, WALLET_SERVICE_ROUTE);
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  test('mounts one compact wallet-origin surface', async ({ page }) => {
    await page.evaluate(
      async ({ walletOrigin }) => {
        const routerModule = await import('/_test-sdk/esm/SeamsWeb/walletIframe/client/router.js');
        const messages = await import('/_test-sdk/esm/SeamsWeb/walletIframe/shared/messages.js');
        const router = new routerModule.WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          sdkBasePath: '/sdk',
          relayer: { url: window.location.origin },
          registration: {
            projectEnvironmentId: 'proj_local:test',
            publishableKey: 'pk_local',
          },
          testOptions: { ownerTag: 'auth-menu-host-test' },
        });
        await router.init();
        const request = messages.buildHostedAuthMenuOpenRequest({
          authMenuSessionId: 'auth-menu-host-test-session',
          initialMode: 'login',
          registrationAccountInput: 'implicit_wallet',
          showRegistrationInput: false,
          showProgress: true,
          enabledExternalProviders: [],
        });
        (window as typeof window & { __authMenuHostTestRouter?: typeof router })
          .__authMenuHostTestRouter = router;
        void router.openHostedAuthMenu(request).catch(() => undefined);
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    const surface = page
      .frameLocator('iframe[data-w3a-owner="auth-menu-host-test"]')
      .locator('seams-auth-menu-surface');
    await expect(surface).toHaveCount(1);
    await expect(page.locator('seams-auth-menu-surface')).toHaveCount(0);
    const dialog = page.locator('dialog.w3a-wallet-overlay-dialog');
    await expect(dialog).not.toHaveClass(/is-viewport-fallback/);
    const dialogBox = await dialog.boundingBox();
    const viewport = page.viewportSize();
    expect(dialogBox).not.toBeNull();
    expect(viewport).not.toBeNull();
    expect(dialogBox!.width).toBeLessThan(viewport!.width);
    expect(dialogBox!.height).toBeLessThan(viewport!.height);

    await page.evaluate(() => {
      const testWindow = window as typeof window & {
        __authMenuHostTestRouter?: { dispose: () => void };
      };
      testWindow.__authMenuHostTestRouter?.dispose();
      delete testWindow.__authMenuHostTestRouter;
    });
  });
});
