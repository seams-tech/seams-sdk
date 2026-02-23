import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

test.describe('TatchiPasskey.setTheme', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('updates theme synchronously', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import('/sdk/esm/core/TatchiPasskey/index.js');
      const { TatchiPasskey } = mod as any;

      const tatchi = new TatchiPasskey({
        nearNetwork: 'testnet',
        nearRpcUrl: 'https://test.rpc.fastnear.com',
        relayer: { url: 'https://relay-server.localhost' },
        iframeWallet: { walletOrigin: '' },
      });

      const before = tatchi.theme;
      tatchi.setTheme('light');

      return { before, after: tatchi.theme };
    });

    expect(result).toEqual({ before: 'dark', after: 'light' });
  });

  test('initializes theme from config appearance.theme', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import('/sdk/esm/core/TatchiPasskey/index.js');
      const { TatchiPasskey } = mod as any;

      const tatchi = new TatchiPasskey({
        appearance: { theme: 'light' },
        nearNetwork: 'testnet',
        nearRpcUrl: 'https://test.rpc.fastnear.com',
        relayer: { url: 'https://relay-server.localhost' },
        iframeWallet: { walletOrigin: '' },
      });

      return { theme: tatchi.theme };
    });

    expect(result).toEqual({ theme: 'light' });
  });
});
