import { test, expect } from '@playwright/test';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';

const iframeWallet = { walletOrigin: 'https://wallet.example.test' } as const;

test.describe('buildConfigsFromEnv registration transport defaults', () => {
  test('omitting registration config builds, leaving credentials empty', async () => {
    /* The backend-proxied mode is gone, so managed is the only shape. But an
       app that only signs for an already-registered wallet never registers,
       and registration credentials are not a precondition for the rest of the
       SDK — so omitting them builds, and registration fails at the call. */
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      iframeWallet,
    });
    expect(cfg.registration.mode).toBe('managed');
    expect(cfg.registration.projectEnvironmentId).toBe('');
    expect(cfg.registration.publishableKey).toBe('');
  });

  test('declaring registration config and leaving it incomplete throws', async () => {
    expect(() =>
      buildConfigsFromEnv({
        relayer: { url: 'https://relay.example' },
        iframeWallet,
        // @ts-expect-error managed registration requires publishableKey.
        registration: { mode: 'managed', projectEnvironmentId: 'env_prod' },
      }),
    ).toThrow(/registration\.publishableKey/i);
  });

  test('requires projectEnvironmentId for managed registration config', async () => {
    expect(() =>
      buildConfigsFromEnv({
        relayer: { url: 'https://relay.example' },
        iframeWallet,
        // @ts-expect-error managed registration requires projectEnvironmentId.
        registration: {
          mode: 'managed',
          publishableKey: 'pk_publishable',
        },
      }),
    ).toThrow(/registration\.projectEnvironmentId/i);
  });

  test('resolves managed registration config fields', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      iframeWallet,
      registration: {
        mode: 'managed',
        projectEnvironmentId: 'env_prod',
        publishableKey: 'pk_publishable',
      },
    });

    expect(cfg.registration.mode).toBe('managed');
    if (cfg.registration.mode !== 'managed') {
      throw new Error('Expected managed registration mode');
    }
    expect(cfg.registration.projectEnvironmentId).toBe('env_prod');
    expect(cfg.registration.publishableKey).toBe('pk_publishable');
    expect(cfg.registration.paymentMode).toBe('disabled');
  });
});
