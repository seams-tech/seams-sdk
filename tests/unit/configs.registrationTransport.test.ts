import { test, expect } from '@playwright/test';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';

test.describe('buildConfigsFromEnv registration transport defaults', () => {
  test('defaults registration bootstrap URL from relayer.url', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
    });

    expect(cfg.registration.mode).toBe('backend_proxy');
    if (cfg.registration.mode !== 'backend_proxy') {
      throw new Error('Expected backend_proxy registration mode');
    }
    expect(cfg.registration.bootstrapUrl).toBe('https://relay.example/registration/bootstrap');
  });

  test('uses explicit backend proxy registration bootstrap URL', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
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

  test('rejects removed browser-side relayer.apiKey config', async () => {
    expect(() =>
      buildConfigsFromEnv({
        relayer: {
          url: 'https://relay.example',
          apiKey: 'tsk_v1_secret',
        } as any,
      }),
    ).toThrow(/relayer\.apiKey has been removed/i);
  });

  test('requires environmentId for managed registration config', async () => {
    expect(() =>
      buildConfigsFromEnv({
        relayer: { url: 'https://relay.example' },
        registration: {
          mode: 'managed',
          publishableKey: 'tpk_v1_publishable',
        } as any,
      }),
    ).toThrow(/registration\.environmentId/i);
  });

  test('resolves managed registration config fields', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      registration: {
        mode: 'managed',
        environmentId: 'env_prod',
        publishableKey: 'tpk_v1_publishable',
        brokerUrl: 'https://broker.example/v1/registration/bootstrap-grants',
      },
    });

    expect(cfg.registration.mode).toBe('managed');
    if (cfg.registration.mode !== 'managed') {
      throw new Error('Expected managed registration mode');
    }
    expect(cfg.registration.environmentId).toBe('env_prod');
    expect(cfg.registration.publishableKey).toBe('tpk_v1_publishable');
    expect(cfg.registration.brokerUrl).toBe('https://broker.example/v1/registration/bootstrap-grants');
  });
});
