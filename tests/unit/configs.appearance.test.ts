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
      theme: {
        id: 'default',
        mode: 'dark',
        colors: {},
      },
      palette: 'default',
    });
  });

  test('merges explicit appearance overrides', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      iframeWallet,
      appearance: {
        theme: {
          id: 'customer-defined-theme',
          mode: 'light',
          colors: {
            primary: '#123456',
            borderPrimary: '#556677',
          },
        },
        palette: 'default',
      },
    });

    expect(cfg.ui.appearance.theme.id).toBe('customer-defined-theme');
    expect(cfg.ui.appearance.theme.mode).toBe('light');
    expect(cfg.ui.appearance.palette).toBe('default');
    expect(cfg.ui.appearance.theme.colors.primary).toBe('#123456');
    expect(cfg.ui.appearance.theme.colors.borderPrimary).toBe('#556677');
  });

  test('throws for invalid appearance enum values', async () => {
    expect(() =>
      buildConfigsFromEnv({
        relayer: { url: 'https://relay.example' },
        iframeWallet,
        appearance: {
          theme: { id: 'sepia', mode: 'sepia' as any },
          palette: 'midnight' as any,
        } as any,
      }),
    ).toThrow("[configPresets] Invalid config: appearance.theme.mode must be 'light' or 'dark'");
  });
});
