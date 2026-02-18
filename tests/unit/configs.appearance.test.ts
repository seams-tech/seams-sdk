import { test, expect } from '@playwright/test';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';

test.describe('buildConfigsFromEnv appearance defaults and overrides', () => {
  test('applies default appearance when overrides are omitted', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
    });

    expect(cfg.appearance).toEqual({
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

    expect(cfg.appearance.theme).toBe('light');
    expect(cfg.appearance.palette).toBe('default');
    expect(cfg.appearance.tokens.light.colors.primary).toBe('#123456');
    expect(cfg.appearance.tokens.dark.colors.borderPrimary).toBe('#556677');
  });

  test('falls back to default palette for removed legacy cream palette', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      appearance: {
        theme: 'light',
        palette: 'cream' as any,
      } as any,
    });

    expect(cfg.appearance.theme).toBe('light');
    expect(cfg.appearance.palette).toBe('default');
  });

  test('falls back to defaults for invalid appearance enum values', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      appearance: {
        theme: 'sepia' as any,
        palette: 'midnight' as any,
      } as any,
    });

    expect(cfg.appearance.theme).toBe('dark');
    expect(cfg.appearance.palette).toBe('default');
  });
});
