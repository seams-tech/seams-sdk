import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { buildWalletServiceHtml, initRouter, registerWalletServiceRoute } from './harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';

const HOST_BOOT_SCRIPT = String.raw`
      import('/_test-sdk/esm/sdk/wallet-iframe-host-runtime.js').catch((error) => {
        console.error('[auth-menu-host-test] host boot failed', error);
      });
`;

test.describe('wallet-host auth-menu integration', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: HOST_BOOT_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  test('mounts one wallet-origin surface and exact cancellation removes it', async ({ page }) => {
    const result = await page.evaluate(
      async ({ walletOrigin }) => {
        const routerModule = await import('/_test-sdk/esm/SeamsWeb/walletIframe/client/router.js');
        const messages = await import('/_test-sdk/esm/SeamsWeb/walletIframe/shared/messages.js');
        const router = new routerModule.WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          sdkBasePath: '/sdk',
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
        const outcomePromise = router.openHostedAuthMenu(request);
        await new Promise((resolve) => setTimeout(resolve, 300));
        const iframe = document.querySelector(
          'iframe[data-w3a-owner="auth-menu-host-test"]',
        ) as HTMLIFrameElement | null;
        const beforeCancel = iframe?.contentDocument
          ? {
              count: iframe.contentDocument.querySelectorAll('seams-auth-menu-surface').length,
              appCount: document.querySelectorAll('seams-auth-menu-surface').length,
            }
          : null;
        await router.cancelHostedAuthMenu({ authMenuSessionId: request.authMenuSessionId });
        const outcome = await outcomePromise;
        const afterCancel = iframe?.contentDocument
          ? iframe.contentDocument.querySelectorAll('seams-auth-menu-surface').length
          : -1;
        return { beforeCancel, afterCancel, outcome };
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    expect(result.beforeCancel?.count).toBe(1);
    expect(result.beforeCancel?.appCount).toBe(0);
    expect(result.afterCancel).toBe(0);
    expect(result.outcome).toMatchObject({
      kind: 'cancelled',
      reason: 'component_unmounted',
    });
  });
});
