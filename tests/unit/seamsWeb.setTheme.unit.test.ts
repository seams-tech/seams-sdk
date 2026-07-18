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
        signingSurfaceMode: (seams as any).signingEngine.appearance.theme.mode,
      };
    });

    expect(result).toEqual({ before: 'dark', after: 'light', signingSurfaceMode: 'light' });
  });

  test('initializes theme from config appearance.theme', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import('/_test-sdk/esm/SeamsWeb/index.js');
      const { SeamsWeb } = mod as any;

      const seams = new SeamsWeb({
        appearance: { theme: { id: 'app-theme', mode: 'light' } },
        nearNetwork: 'testnet',
        nearRpcUrl: 'https://test.rpc.fastnear.com',
        relayer: { url: 'https://router-api.localhost' },
        iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
      });

      return { theme: seams.theme };
    });

    expect(result).toEqual({ theme: 'light' });
  });

  test('setAppearance updates local signing-surface appearance for key export UI', async ({ page }) => {
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
        theme: {
          id: 'customer-defined-theme',
          mode: 'light',
          colors: {
            primary: '#123abc',
            surface: '#f8f4ec',
          },
        },
      });

      return {
        theme: seams.theme,
        signingSurfaceAppearance: (seams as any).signingEngine.appearance,
      };
    });

    expect(result).toEqual({
      theme: 'light',
      signingSurfaceAppearance: {
        theme: {
          id: 'customer-defined-theme',
          mode: 'light',
          colors: {
            primary: '#123abc',
            surface: '#f8f4ec',
          },
        },
        palette: 'default',
      },
    });
  });

  test('setAppearance with a new theme id replaces colors instead of merging', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import('/_test-sdk/esm/SeamsWeb/index.js');
      const { SeamsWeb } = mod as any;

      const seams = new SeamsWeb({
        nearNetwork: 'testnet',
        nearRpcUrl: 'https://test.rpc.fastnear.com',
        relayer: { url: 'https://router-api.localhost' },
        iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
      });

      // A light theme that pins the passkey halo chip color.
      seams.setAppearance({
        theme: {
          id: 'paper',
          mode: 'light',
          colors: {
            surface: '#ffffff',
            passkeyHaloBackground: '#f8f8f7',
          },
        },
      });

      // Switching to a theme that does not define passkeyHaloBackground must
      // not inherit it from the previous theme.
      seams.setAppearance({
        theme: {
          id: 'midnight',
          mode: 'dark',
          colors: {
            surface: '#181e28',
          },
        },
      });

      return (seams as any).signingEngine.appearance;
    });

    expect(result).toEqual({
      theme: {
        id: 'midnight',
        mode: 'dark',
        colors: {
          surface: '#181e28',
        },
      },
      palette: 'default',
    });
  });

  test('setTheme preserves the current theme id and color tokens', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import('/_test-sdk/esm/SeamsWeb/index.js');
      const { SeamsWeb } = mod as any;

      const seams = new SeamsWeb({
        appearance: {
          theme: {
            id: 'customer-defined-theme',
            mode: 'light',
            colors: {
              surface: '#f8f4ec',
            },
          },
        },
        nearNetwork: 'testnet',
        nearRpcUrl: 'https://test.rpc.fastnear.com',
        relayer: { url: 'https://router-api.localhost' },
        iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
      });

      seams.setTheme('dark');

      return {
        theme: seams.theme,
        signingSurfaceAppearance: (seams as any).signingEngine.appearance,
      };
    });

    expect(result).toEqual({
      theme: 'dark',
      signingSurfaceAppearance: {
        theme: {
          id: 'customer-defined-theme',
          mode: 'dark',
          colors: {
            surface: '#f8f4ec',
          },
        },
        palette: 'default',
      },
    });
  });
});
