import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

test.describe('SeamsWeb.setTheme', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('updates theme synchronously', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import('/sdk/esm/SeamsWeb/index.js');
      const { SeamsWeb } = mod as any;

      const seams = new SeamsWeb({
        nearNetwork: 'testnet',
        nearRpcUrl: 'https://test.rpc.fastnear.com',
        relayer: { url: 'https://router-api.localhost' },
        iframeWallet: { walletOrigin: '' },
      });

      const before = seams.theme;
      seams.setTheme('light');

      return { before, after: seams.theme };
    });

    expect(result).toEqual({ before: 'dark', after: 'light' });
  });

  test('initializes theme from config appearance.theme', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import('/sdk/esm/SeamsWeb/index.js');
      const { SeamsWeb } = mod as any;

      const seams = new SeamsWeb({
        appearance: { theme: 'light' },
        nearNetwork: 'testnet',
        nearRpcUrl: 'https://test.rpc.fastnear.com',
        relayer: { url: 'https://router-api.localhost' },
        iframeWallet: { walletOrigin: '' },
      });

      return { theme: seams.theme };
    });

    expect(result).toEqual({ theme: 'light' });
  });
});
