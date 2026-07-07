import { test, expect } from '@playwright/test';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';

const iframeWallet = { walletOrigin: 'https://wallet.example.test' } as const;

test.describe('buildConfigsFromEnv registration transport defaults', () => {
  test('defaults registration bootstrap URL from relayer.url', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      iframeWallet,
    });

    expect(cfg.registration.mode).toBe('backend_proxy');
    if (cfg.registration.mode !== 'backend_proxy') {
      throw new Error('Expected backend_proxy registration mode');
    }
    expect(cfg.registration.bootstrapUrl).toBe('https://relay.example/wallets/register/intent');
  });

  test('uses explicit backend proxy registration bootstrap URL', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      iframeWallet,
      registration: {
        mode: 'backend_proxy',
        registrationBootstrapUrl: 'https://app.example/api/registration/bootstrap',
      },
    });

    expect(cfg.registration.mode).toBe('backend_proxy');
    if (cfg.registration.mode !== 'backend_proxy') {
      throw new Error('Expected backend_proxy registration mode');
    }
    expect(cfg.registration.bootstrapUrl).toBe('https://app.example/api/registration/bootstrap');
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
