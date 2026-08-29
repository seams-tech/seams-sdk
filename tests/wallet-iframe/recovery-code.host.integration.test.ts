import { expect, test } from '@playwright/test';
import { buildWalletServiceHtml } from '@/plugins/plugin-utils';
import { setupBasicPasskeyTest } from '../setup';
import { injectImportMap } from '../setup/bootstrap';
import { registerWalletServiceRoute } from './harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';

const HOST_HTML = buildWalletServiceHtml('/_test-sdk/esm/sdk');

test('reveals the recovery summary while the full wallet runtime is still loading', async ({
  page,
}) => {
  let fullWalletRuntimeRequested = false;
  await page.route('**/_test-sdk/esm/sdk/runtimeContext-*.js', async (route) => {
    fullWalletRuntimeRequested = true;
    await new Promise<void>((resolve) => setTimeout(resolve, 5_000));
    await route.fallback();
  });
  await setupBasicPasskeyTest(page, {
    skipSeamsWebInit: true,
    injectWalletServiceImportMap: true,
  });
  await page.goto('about:blank');
  await injectImportMap(page);
  await registerWalletServiceRoute(page, HOST_HTML, WALLET_SERVICE_ROUTE);

  await page.evaluate(
    async ({ walletOrigin }) => {
      const routerModule = await import('/_test-sdk/esm/SeamsWeb/walletIframe/client/router.js');
      const router = new routerModule.WalletIframeRouter({
        walletOrigin,
        servicePath: '/wallet-service',
        sdkBasePath: '/_test-sdk/esm/sdk',
        relayer: { url: window.location.origin },
        registration: {
          projectEnvironmentId: 'proj_local:test',
          publishableKey: 'pk_local',
        },
        testOptions: { ownerTag: 'recovery-code-host-test' },
      });
      const initialization = router.init();
      const testWindow = window as typeof window & {
        __recoveryCodeHostTest?: {
          readonly startedAt: number;
          readonly router: typeof router;
        };
      };
      testWindow.__recoveryCodeHostTest = { startedAt: performance.now(), router };
      void router
        .acknowledgeWalletRecoveryCodeBackup({ walletId: 'recovery-delay-test-wallet' })
        .catch(() => undefined);
      void initialization.catch(() => undefined);
    },
    { walletOrigin: WALLET_ORIGIN },
  );

  const parentDialog = page.locator('dialog.w3a-wallet-overlay-dialog');
  await expect(parentDialog).toBeVisible({ timeout: 2_000 });
  await expect(parentDialog).not.toHaveClass(/is-provisional/);
  await expect(parentDialog).not.toHaveClass(/is-viewport-fallback/);
  await expect(parentDialog).toHaveCSS('opacity', '1');
  const elapsedMs = await page.evaluate(() => {
    const testWindow = window as typeof window & {
      __recoveryCodeHostTest?: { readonly startedAt: number };
    };
    return performance.now() - (testWindow.__recoveryCodeHostTest?.startedAt ?? 0);
  });
  expect(elapsedMs).toBeLessThan(2_000);
  expect(fullWalletRuntimeRequested).toBe(true);

  const childDialog = page
    .frameLocator('iframe[data-w3a-owner="recovery-code-host-test"]')
    .locator('[data-w3a-wallet-recovery-backup-dialog]');
  await expect(childDialog).toBeVisible();

  await page.evaluate(() => {
    const testWindow = window as typeof window & {
      __recoveryCodeHostTest?: { readonly router: { dispose: () => void } };
    };
    testWindow.__recoveryCodeHostTest?.router.dispose();
    delete testWindow.__recoveryCodeHostTest;
  });
  await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
});
