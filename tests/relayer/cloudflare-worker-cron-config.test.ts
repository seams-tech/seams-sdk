import { test, expect } from '@playwright/test';
import { createWorkerCronOptions } from '../../examples/relay-cloudflare-worker/src/cronConfig';
import { resolveWorkerCronFeatureFlags } from '../../examples/relay-cloudflare-worker/src/cronFlags';

test.describe('relay cloudflare worker cron config', () => {
  test('maps enabled env flags into cron job options', async () => {
    const flags = resolveWorkerCronFeatureFlags({
      ENABLE_ROTATION: '0',
      BILLING_FINALIZATION_ENABLED: '1',
      RUNTIME_SNAPSHOT_OUTBOX_ENABLED: '1',
      WEBHOOK_RETRY_ENABLED: '1',
    });

    const seenOutboxEvents: unknown[] = [];
    const options = createWorkerCronOptions(
      {
        BILLING_POSTGRES_URL: 'postgres://billing/db',
        BILLING_NAMESPACE: 'billing-ns',
        BILLING_FINALIZATION_PERIOD_MONTH_UTC: '2026-02',
        BILLING_FINALIZATION_ORG_IDS: 'org-a, org-b',
        BILLING_FINALIZATION_CRONS: '0 2 1 * *, 0 3 1 * *',
        RUNTIME_SNAPSHOT_OUTBOX_ORG_IDS: 'org-a',
        RUNTIME_SNAPSHOT_OUTBOX_CRONS: '*/5 * * * *',
        RUNTIME_SNAPSHOT_OUTBOX_LIMIT: '50',
        WEBHOOK_RETRY_ORG_IDS: 'org-a,org-c',
        WEBHOOK_RETRY_CRONS: '*/10 * * * *',
        WEBHOOK_RETRY_LIMIT: '25',
        WEBHOOK_RETRY_MAX_ATTEMPTS: '7',
        WEBHOOK_RETRY_INITIAL_BACKOFF_MS: '1000',
        WEBHOOK_RETRY_MAX_BACKOFF_MS: '60000',
      },
      flags,
      {
        applyOutboxEvent(event) {
          seenOutboxEvents.push(event);
        },
      },
      null,
    );

    expect(options.enabled).toBe(true);
    expect(options.rotate).toBe(false);
    expect(options.billingMonthlyFinalization?.orgIds).toEqual(['org-a', 'org-b']);
    expect(options.billingMonthlyFinalization?.cronExpressions).toEqual([
      '0 2 1 * *',
      '0 3 1 * *',
    ]);
    expect(options.runtimeSnapshotOutbox?.postgresUrl).toBe('postgres://billing/db');
    expect(options.runtimeSnapshotOutbox?.namespace).toBe('billing-ns');
    expect(options.runtimeSnapshotOutbox?.orgIds).toEqual(['org-a']);
    expect(options.runtimeSnapshotOutbox?.cronExpressions).toEqual(['*/5 * * * *']);
    expect(options.runtimeSnapshotOutbox?.limit).toBe(50);
    expect(options.webhookRetryDispatch?.orgIds).toEqual(['org-a', 'org-c']);
    expect(options.webhookRetryDispatch?.cronExpressions).toEqual(['*/10 * * * *']);
    expect(options.webhookRetryDispatch?.limit).toBe(25);
    expect(options.webhookRetryDispatch?.maxAttempts).toBe(7);
    expect(options.webhookRetryDispatch?.initialBackoffMs).toBe(1000);
    expect(options.webhookRetryDispatch?.maxBackoffMs).toBe(60000);

    await options.runtimeSnapshotOutbox?.dispatch?.({
      payload: { snapshotId: 'snap_1' },
    } as any);
    expect(seenOutboxEvents).toEqual([{ payload: { snapshotId: 'snap_1' } }]);
  });

  test('uses per-job url/namespace overrides when provided', async () => {
    const flags = resolveWorkerCronFeatureFlags({
      ENABLE_ROTATION: '0',
      BILLING_FINALIZATION_ENABLED: '0',
      RUNTIME_SNAPSHOT_OUTBOX_ENABLED: '1',
      WEBHOOK_RETRY_ENABLED: '1',
    });
    const options = createWorkerCronOptions(
      {
        BILLING_POSTGRES_URL: 'postgres://billing/db',
        BILLING_NAMESPACE: 'billing-ns',
        RUNTIME_SNAPSHOT_OUTBOX_POSTGRES_URL: 'postgres://outbox/db',
        RUNTIME_SNAPSHOT_OUTBOX_NAMESPACE: 'outbox-ns',
        RUNTIME_SNAPSHOT_OUTBOX_ORG_IDS: 'org-a',
        WEBHOOK_RETRY_POSTGRES_URL: 'postgres://webhooks/db',
        WEBHOOK_RETRY_NAMESPACE: 'webhooks-ns',
        WEBHOOK_RETRY_ORG_IDS: 'org-a',
      },
      flags,
      {
        applyOutboxEvent() {},
      },
      null,
    );

    expect(options.billingMonthlyFinalization).toBeUndefined();
    expect(options.runtimeSnapshotOutbox?.postgresUrl).toBe('postgres://outbox/db');
    expect(options.runtimeSnapshotOutbox?.namespace).toBe('outbox-ns');
    expect(options.webhookRetryDispatch?.postgresUrl).toBe('postgres://webhooks/db');
    expect(options.webhookRetryDispatch?.namespace).toBe('webhooks-ns');
  });

  test('disables cron when no feature flags are enabled', async () => {
    const flags = resolveWorkerCronFeatureFlags({
      ENABLE_ROTATION: '0',
      BILLING_FINALIZATION_ENABLED: '0',
      RUNTIME_SNAPSHOT_OUTBOX_ENABLED: '0',
      WEBHOOK_RETRY_ENABLED: '0',
    });
    const options = createWorkerCronOptions(
      {
        BILLING_POSTGRES_URL: 'postgres://billing/db',
      },
      flags,
      {
        applyOutboxEvent() {},
      },
      null,
    );

    expect(options.enabled).toBe(false);
    expect(options.rotate).toBe(false);
    expect(options.billingMonthlyFinalization).toBeUndefined();
    expect(options.runtimeSnapshotOutbox).toBeUndefined();
    expect(options.webhookRetryDispatch).toBeUndefined();
  });

  test('forwards webhook retry observability ingestion when provided', async () => {
    const flags = resolveWorkerCronFeatureFlags({
      ENABLE_ROTATION: '0',
      BILLING_FINALIZATION_ENABLED: '0',
      RUNTIME_SNAPSHOT_OUTBOX_ENABLED: '0',
      WEBHOOK_RETRY_ENABLED: '1',
    });
    const observabilityIngestion = {
      appendEvent: async () => ({ accepted: 1, deduplicated: 0 }),
      appendEvents: async (_ctx: unknown, events: unknown[]) => ({
        accepted: events.length,
        deduplicated: 0,
      }),
    };
    const options = createWorkerCronOptions(
      {
        BILLING_POSTGRES_URL: 'postgres://billing/db',
        WEBHOOK_RETRY_ORG_IDS: 'org-a',
      },
      flags,
      {
        applyOutboxEvent() {},
      },
      observabilityIngestion as any,
    );

    expect(options.webhookRetryDispatch?.observabilityIngestion).toBe(observabilityIngestion);
  });
});
