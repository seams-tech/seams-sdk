import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

test.describe('SeamsPasskey.setTheme', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('updates theme synchronously', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import('/sdk/esm/core/SeamsPasskey/index.js');
      const { SeamsPasskey } = mod as any;

      const seams = new SeamsPasskey({
        nearNetwork: 'testnet',
        nearRpcUrl: 'https://test.rpc.fastnear.com',
        relayer: { url: 'https://relay-server.localhost' },
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
      const mod = await import('/sdk/esm/core/SeamsPasskey/index.js');
      const { SeamsPasskey } = mod as any;

      const seams = new SeamsPasskey({
        appearance: { theme: 'light' },
        nearNetwork: 'testnet',
        nearRpcUrl: 'https://test.rpc.fastnear.com',
        relayer: { url: 'https://relay-server.localhost' },
        iframeWallet: { walletOrigin: '' },
      });

      return { theme: seams.theme };
    });

    expect(result).toEqual({ theme: 'light' });
  });
});
