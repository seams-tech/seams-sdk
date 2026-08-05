import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest, SDK_ESM_PATHS } from '../setup';
import { buildWalletServiceHtml, registerWalletServiceRoute } from './harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';

test.describe('WalletIframeRouter connection teardown', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    await registerWalletServiceRoute(page, buildWalletServiceHtml(), WALLET_SERVICE_ROUTE);
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  test('settles only the hosted auth-menu request on explicit router disposal', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ routerPath, walletOrigin }) => {
        const routerModule = await import(routerPath);
        const messages = await import('/_test-sdk/esm/SeamsWeb/walletIframe/shared/messages.js');
        const router = new routerModule.WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          sdkBasePath: '/sdk',
          testOptions: { ownerTag: 'connection-closed-test' },
        });
        await router.init();

        const request = messages.buildHostedAuthMenuOpenRequest({
          authMenuSessionId: 'connection-closed-test-session',
          initialMode: 'login',
          registrationAccountInput: 'implicit_wallet',
          showRegistrationInput: false,
          showProgress: true,
          enabledExternalProviders: [],
        });
        const outcomePromise = router.openHostedAuthMenu(request);
        const startedAt = Date.now();
        while (!router.getOverlayState().visible && Date.now() - startedAt < 3000) {
          await new Promise((resolve) => setTimeout(resolve, 20));
        }
        const shown = router.getOverlayState().visible;

        router.dispose();
        const outcome = await outcomePromise;
        const hidden = !router.getOverlayState().visible;

        return { shown, hidden, outcome };
      },
      { routerPath: SDK_ESM_PATHS.walletIframeRouter, walletOrigin: WALLET_ORIGIN },
    );

    expect(result.shown).toBe(true);
    expect(result.hidden).toBe(true);
    expect(result.outcome).toMatchObject({
      kind: 'cancelled',
      reason: 'connection_closed',
    });
  });
});
