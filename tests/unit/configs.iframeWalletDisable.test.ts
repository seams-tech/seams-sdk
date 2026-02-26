import { test, expect } from '@playwright/test';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';

test.describe('buildConfigsFromEnv iframeWallet override semantics', () => {
  test('preserves explicit walletOrigin "" by forcing direct wallet mode', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      iframeWallet: { walletOrigin: '' },
    });
    expect(cfg.wallet.mode).toBe('direct');
    expect('origin' in cfg.wallet.iframe).toBe(false);
  });

  test('treats walletOrigin undefined as absent and keeps iframe defaults', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      iframeWallet: { walletOrigin: undefined },
    });
    expect(cfg.wallet.mode).toBe('iframe');
    expect(cfg.wallet.iframe.origin).toBeTruthy();
  });

  test('keeps direct wallet mode by default when iframe override is omitted', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
    });
    expect(cfg.wallet.mode).toBe('direct');
    expect(cfg.wallet.iframe.origin).toBeTruthy();
  });
});
