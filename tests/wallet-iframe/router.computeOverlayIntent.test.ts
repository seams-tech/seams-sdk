import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, SDK_ESM_PATHS } from '../setup';

const WALLET_ORIGIN = 'https://wallet.example.localhost';

test.describe('WalletIframeRouter.computeOverlayIntent', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('preflight fullscreen intent for activation-required requests', async ({ page }) => {
    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, routerPath }) => {
        const mod = await import(routerPath);
        const { WalletIframeRouter } = mod as typeof import('@/SeamsWeb/walletIframe/client/router');
        const router = new WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          connectTimeoutMs: 1000,
          requestTimeoutMs: 1000,
          sdkBasePath: '/sdk',
        });
        const calls: Array<{ type: string; mode: string }> = [];
        const fullscreenTypes = [
          'PM_EXPORT_KEYPAIR_UI',
          'PM_REGISTER',
          'PM_UNLOCK',
          'PM_SIGN_AND_SEND_TXS',
          'PM_EXECUTE_ACTION',
          'PM_SEND_TRANSACTION',
          'PM_SIGN_TXS_WITH_ACTIONS',
          'PM_SIGN_DELEGATE_ACTION',
          'PM_SIGN_NEP413',
          'PM_SIGN_TEMPO',
        ];
        const hiddenTypes = [
          'PM_GET_WALLET_SESSION',
          'PM_SET_THEME',
          'PM_GET_CONFIRMATION_CONFIG',
          'PM_SET_CONFIRM_BEHAVIOR',
          'PM_SET_CONFIRMATION_CONFIG',
          'PM_PREFETCH_BLOCKHEIGHT',
          'PM_START_DEVICE2_LINKING_FLOW',
          'PM_LOCK',
        ];

        const compute = (router as any).computeOverlayIntent.bind(router) as (t: string) => {
          mode: 'hidden' | 'fullscreen';
        };
        for (const t of fullscreenTypes) calls.push({ type: t, mode: compute(t).mode });
        for (const t of hiddenTypes) calls.push({ type: t, mode: compute(t).mode });
        return { calls };
      },
      { walletOrigin: WALLET_ORIGIN, routerPath },
    );

    const byType = Object.fromEntries(result.calls.map((c) => [c.type, c.mode]));
    // Fullscreen intents
    expect(byType['PM_EXPORT_KEYPAIR_UI']).toBe('fullscreen');
    expect(byType['PM_REGISTER']).toBe('fullscreen');
    expect(byType['PM_UNLOCK']).toBe('fullscreen');
    expect(byType['PM_SIGN_AND_SEND_TXS']).toBe('fullscreen');
    expect(byType['PM_EXECUTE_ACTION']).toBe('fullscreen');
    expect(byType['PM_SEND_TRANSACTION']).toBe('fullscreen');
    expect(byType['PM_SIGN_TXS_WITH_ACTIONS']).toBe('fullscreen');
    expect(byType['PM_SIGN_DELEGATE_ACTION']).toBe('fullscreen');
    expect(byType['PM_SIGN_NEP413']).toBe('fullscreen');
    expect(byType['PM_SIGN_TEMPO']).toBe('fullscreen');
    // Hidden intents
    expect(byType['PM_GET_WALLET_SESSION']).toBe('hidden');
    expect(byType['PM_SET_THEME']).toBe('hidden');
    expect(byType['PM_GET_CONFIRMATION_CONFIG']).toBe('hidden');
    expect(byType['PM_SET_CONFIRM_BEHAVIOR']).toBe('hidden');
    expect(byType['PM_SET_CONFIRMATION_CONFIG']).toBe('hidden');
    expect(byType['PM_PREFETCH_BLOCKHEIGHT']).toBe('hidden');
    expect(byType['PM_START_DEVICE2_LINKING_FLOW']).toBe('hidden');
    expect(byType['PM_LOCK']).toBe('hidden');
  });
});
