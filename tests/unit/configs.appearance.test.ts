import { test, expect } from '@playwright/test';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';

const iframeWallet = { walletOrigin: 'https://wallet.example.test' } as const;

test.describe('buildConfigsFromEnv appearance defaults and overrides', () => {
  test('applies default appearance when overrides are omitted', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      iframeWallet,
    });

    expect(cfg.ui.appearance).toEqual({
      theme: 'dark',
      palette: 'default',
      tokens: {
        light: { colors: {} },
        dark: { colors: {} },
      },
    });
  });

  test('merges explicit appearance overrides', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      iframeWallet,
      appearance: {
        theme: 'light',
        palette: 'default',
        tokens: {
          light: {
            colors: {
              primary: '#123456',
            },
          },
          dark: {
            colors: {
              borderPrimary: '#556677',
            },
          },
        },
      },
    });

    expect(cfg.ui.appearance.theme).toBe('light');
    expect(cfg.ui.appearance.palette).toBe('default');
    expect(cfg.ui.appearance.tokens.light.colors.primary).toBe('#123456');
    expect(cfg.ui.appearance.tokens.dark.colors.borderPrimary).toBe('#556677');
  });

  test('throws for invalid appearance enum values', async () => {
    expect(() =>
      buildConfigsFromEnv({
        relayer: { url: 'https://relay.example' },
        iframeWallet,
        appearance: {
          theme: 'sepia' as any,
          palette: 'midnight' as any,
        } as any,
      }),
    ).toThrow("[configPresets] Invalid config: appearance.theme must be 'light' or 'dark'");
  });
});
