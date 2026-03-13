import { test, expect } from '@playwright/test';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';

test.describe('buildConfigsFromEnv smart-account deployment mode defaults', () => {
  test('defaults to observe when relayer mode override is omitted', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
    });
    expect(cfg.network.relayer.smartAccountDeployment.mode).toBe('observe');
  });

  test('respects explicit observe override', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: {
        url: 'https://relay.example',
        smartAccountDeploymentMode: 'observe',
      },
    });
    expect(cfg.network.relayer.smartAccountDeployment.mode).toBe('observe');
  });

  test('keeps explicit enforce override', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: {
        url: 'https://relay.example',
        smartAccountDeploymentMode: 'enforce',
      },
    });
    expect(cfg.network.relayer.smartAccountDeployment.mode).toBe('enforce');
  });
});
