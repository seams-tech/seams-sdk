import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

test.describe('SeamsWeb.setTheme', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('updates theme synchronously', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import('/_test-sdk/esm/SeamsWeb/index.js');
      const { SeamsWeb } = mod as any;

      const seams = new SeamsWeb({
        nearNetwork: 'testnet',
        nearRpcUrl: 'https://test.rpc.fastnear.com',
        relayer: { url: 'https://router-api.localhost' },
        iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
      });

      const before = seams.theme;
      seams.setTheme('light');

      return {
        before,
        after: seams.theme,
        signingSurfaceTheme: (seams as any).signingEngine.theme,
      };
    });

    expect(result).toEqual({ before: 'dark', after: 'light', signingSurfaceTheme: 'light' });
  });

  test('initializes theme from config appearance.theme', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import('/_test-sdk/esm/SeamsWeb/index.js');
      const { SeamsWeb } = mod as any;

      const seams = new SeamsWeb({
        appearance: { theme: 'light' },
        nearNetwork: 'testnet',
        nearRpcUrl: 'https://test.rpc.fastnear.com',
        relayer: { url: 'https://router-api.localhost' },
        iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
      });

      return { theme: seams.theme };
    });

    expect(result).toEqual({ theme: 'light' });
  });

  test('setAppearance updates local signing-surface tokens for key export UI', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import('/_test-sdk/esm/SeamsWeb/index.js');
      const { SeamsWeb } = mod as any;

      const seams = new SeamsWeb({
        nearNetwork: 'testnet',
        nearRpcUrl: 'https://test.rpc.fastnear.com',
        relayer: { url: 'https://router-api.localhost' },
        iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
      });

      seams.setAppearance({
        theme: 'light',
        tokens: {
          light: {
            colors: {
              primary: '#123abc',
              surface: '#f8f4ec',
            },
          },
        },
      });

      return {
        theme: seams.theme,
        signingSurfaceTheme: (seams as any).signingEngine.theme,
        lightPrimary: (seams as any).signingEngine.appearanceTokens.light.colors.primary,
        lightSurface: (seams as any).signingEngine.appearanceTokens.light.colors.surface,
      };
    });

    expect(result).toEqual({
      theme: 'light',
      signingSurfaceTheme: 'light',
      lightPrimary: '#123abc',
      lightSurface: '#f8f4ec',
    });
  });

  test('setAppearance token-only updates preserve current theme', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import('/_test-sdk/esm/SeamsWeb/index.js');
      const { SeamsWeb } = mod as any;

      const seams = new SeamsWeb({
        appearance: { theme: 'light' },
        nearNetwork: 'testnet',
        nearRpcUrl: 'https://test.rpc.fastnear.com',
        relayer: { url: 'https://router-api.localhost' },
        iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
      });

      seams.setAppearance({
        tokens: {
          dark: {
            colors: {
              surface: '#101010',
            },
          },
        },
      });

      return {
        theme: seams.theme,
        signingSurfaceTheme: (seams as any).signingEngine.theme,
        darkSurface: (seams as any).signingEngine.appearanceTokens.dark.colors.surface,
      };
    });

    expect(result).toEqual({
      theme: 'light',
      signingSurfaceTheme: 'light',
      darkSurface: '#101010',
    });
  });
});
