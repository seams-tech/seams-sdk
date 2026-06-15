import { test, expect } from '@playwright/test';
import { resolveWorkerCronFeatureFlags } from '../../examples/relay-cloudflare-worker/src/cronFlags';

test.describe('relay cloudflare worker cron flags', () => {
  test('enables cron when a job flag is enabled', async () => {
    const flags = resolveWorkerCronFeatureFlags({
      BILLING_FINALIZATION_ENABLED: '1',
      RUNTIME_SNAPSHOT_OUTBOX_ENABLED: '0',
      WEBHOOK_RETRY_ENABLED: '0',
    });
    expect(flags.billingFinalizationEnabled).toBe(true);
    expect(flags.cronEnabled).toBe(true);
  });

  test('enables cron when webhook retry is enabled', async () => {
    const flags = resolveWorkerCronFeatureFlags({
      BILLING_FINALIZATION_ENABLED: '0',
      RUNTIME_SNAPSHOT_OUTBOX_ENABLED: '0',
      WEBHOOK_RETRY_ENABLED: '1',
    });
    expect(flags.webhookRetryEnabled).toBe(true);
    expect(flags.cronEnabled).toBe(true);
  });

  test('disables cron when no feature flags are enabled', async () => {
    const flags = resolveWorkerCronFeatureFlags({
      BILLING_FINALIZATION_ENABLED: '0',
      RUNTIME_SNAPSHOT_OUTBOX_ENABLED: '0',
      WEBHOOK_RETRY_ENABLED: '0',
    });
    expect(flags.billingFinalizationEnabled).toBe(false);
    expect(flags.runtimeSnapshotOutboxEnabled).toBe(false);
    expect(flags.webhookRetryEnabled).toBe(false);
    expect(flags.cronEnabled).toBe(false);
  });
});
