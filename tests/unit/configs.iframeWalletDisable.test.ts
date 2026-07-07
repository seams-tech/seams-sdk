import { test, expect } from '@playwright/test';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';

test.describe('buildConfigsFromEnv hosted wallet origin semantics', () => {
  test('rejects explicit empty walletOrigin instead of selecting direct browser mode', async () => {
    expect(() =>
      buildConfigsFromEnv({
        relayer: { url: 'https://relay.example' },
        iframeWallet: { walletOrigin: '' },
      }),
    ).toThrow(/SEAMS_HOSTED_WALLET_ORIGIN_REQUIRED/);
  });

  test('rejects undefined walletOrigin when iframeWallet is configured', async () => {
    expect(() =>
      buildConfigsFromEnv({
        relayer: { url: 'https://relay.example' },
        iframeWallet: { walletOrigin: undefined },
      }),
    ).toThrow(/SEAMS_HOSTED_WALLET_ORIGIN_REQUIRED/);
  });

  test('allows direct wallet mode only through the wallet-host internal boundary', async () => {
    const cfg = buildConfigsFromEnv(
      {
        relayer: { url: 'https://relay.example' },
        iframeWallet: { walletOrigin: '' },
      },
      { allowDirectWalletMode: 'wallet_host' },
    );
    expect(cfg.wallet.mode).toBe('direct');
    expect('origin' in cfg.wallet.iframe).toBe(false);
  });

  test('rejects omitted iframeWallet instead of selecting direct browser mode', async () => {
    expect(() =>
      buildConfigsFromEnv({
        relayer: { url: 'https://relay.example' },
      }),
    ).toThrow(/SEAMS_HOSTED_WALLET_ORIGIN_REQUIRED/);
  });
});
