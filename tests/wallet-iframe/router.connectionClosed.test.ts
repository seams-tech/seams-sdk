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

  test('hides and removes an ordinary request surface on router disposal', async ({ page }) => {
    const result = await page.evaluate(
      async ({ routerPath, walletOrigin }) => {
        const routerModule = await import(routerPath);
        const router = new routerModule.WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          sdkBasePath: '/sdk',
          requestTimeoutMs: 10_000,
          testOptions: { ownerTag: 'connection-closed-request-test' },
        });
        await router.init();
        const request = router
          .executeAction({
            walletId: 'connection-closed-request.testnet',
            nearAccountId: 'connection-closed-request.testnet',
            receiverId: 'seams-v1.testnet',
            actionArgs: { type: 'Transfer', amount: '1' } as any,
            options: {},
          })
          .then(
            () => ({ kind: 'resolved' as const }),
            (error: unknown) => ({
              kind: 'rejected' as const,
              code: error && typeof error === 'object' && 'code' in error
                ? String((error as { code?: unknown }).code)
                : undefined,
              requestId:
                error && typeof error === 'object' && 'requestId' in error
                  ? (error as { requestId?: unknown }).requestId
                  : undefined,
            }),
          );
        const startedAt = Date.now();
        while (!router.getOverlayState().visible && Date.now() - startedAt < 3000) {
          await new Promise((resolve) => setTimeout(resolve, 20));
        }
        const shown = router.getOverlayState().visible;
        const ownedDialog = document
          .querySelector('iframe[data-w3a-owner="connection-closed-request-test"]')
          ?.closest('dialog.w3a-wallet-overlay-dialog');
        const disposedAt = Date.now();
        router.dispose();
        const outcome = await Promise.race([
          request,
          new Promise<{ kind: 'timed_out' }>((resolve) =>
            setTimeout(() => resolve({ kind: 'timed_out' }), 500),
          ),
        ]);
        return {
          shown,
          settlementMs: Date.now() - disposedAt,
          outcome,
          hidden: !router.getOverlayState().visible,
          iframeRemoved: router.getIframeEl() === null,
          ownedDialogRemoved: ownedDialog ? !ownedDialog.isConnected : false,
        };
      },
      { routerPath: SDK_ESM_PATHS.walletIframeRouter, walletOrigin: WALLET_ORIGIN },
    );

    expect(result.shown).toBe(true);
    expect(result.settlementMs).toBeLessThan(500);
    expect(result.outcome).toMatchObject({
      kind: 'rejected',
      code: 'connection_closed',
    });
    expect(result.outcome.requestId).toEqual(expect.any(String));
    expect(result.hidden).toBe(true);
    expect(result.iframeRemoved).toBe(true);
    expect(result.ownedDialogRemoved).toBe(true);
  });
});
