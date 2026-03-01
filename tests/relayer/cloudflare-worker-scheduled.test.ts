import { test, expect } from '@playwright/test';
import { createWorkerScheduledHandler } from '../../examples/relay-cloudflare-worker/src/scheduledHandler';

test.describe('relay cloudflare worker scheduled handler', () => {
  test('builds cron options from env and forwards scheduled invocation', async () => {
    const seen = {
      authServiceEnv: undefined as any,
      cronOptions: undefined as any,
      event: undefined as any,
      env: undefined as any,
      ctx: undefined as any,
      outboxEvents: [] as unknown[],
    };

    const scheduled = createWorkerScheduledHandler({
      createAuthService: (env) => {
        seen.authServiceEnv = env;
        return {} as any;
      },
      outboxSink: {
        applyOutboxEvent(event) {
          seen.outboxEvents.push(event);
        },
      },
      createCron: (_service, options) => {
        seen.cronOptions = options;
        return async (event, env, ctx) => {
          seen.event = event;
          seen.env = env;
          seen.ctx = ctx;
        };
      },
    });

    const event = { scheduledTime: Date.now(), cron: '*/5 * * * *' } as any;
    const env = {
      ENABLE_ROTATION: '0',
      BILLING_FINALIZATION_ENABLED: '1',
      BILLING_POSTGRES_URL: 'postgres://billing/db',
      BILLING_NAMESPACE: 'billing-ns',
      BILLING_FINALIZATION_ORG_IDS: 'org-a, org-b',
      BILLING_FINALIZATION_CRONS: '0 2 1 * *',
      RUNTIME_SNAPSHOT_OUTBOX_ENABLED: '1',
      RUNTIME_SNAPSHOT_OUTBOX_ORG_IDS: 'org-a',
      RUNTIME_SNAPSHOT_OUTBOX_CRONS: '*/5 * * * *',
      WEBHOOK_RETRY_ENABLED: '1',
      WEBHOOK_RETRY_ORG_IDS: 'org-c',
      WEBHOOK_RETRY_CRONS: '*/10 * * * *',
    } as any;
    const ctx = {} as any;

    await scheduled(event, env, ctx);

    expect(seen.authServiceEnv).toBe(env);
    expect(seen.event).toBe(event);
    expect(seen.env).toBe(env);
    expect(seen.ctx).toBe(ctx);
    expect(seen.cronOptions?.enabled).toBe(true);
    expect(seen.cronOptions?.rotate).toBe(false);
    expect(seen.cronOptions?.billingMonthlyFinalization?.orgIds).toEqual(['org-a', 'org-b']);
    expect(seen.cronOptions?.billingMonthlyFinalization?.cronExpressions).toEqual(['0 2 1 * *']);
    expect(seen.cronOptions?.runtimeSnapshotOutbox?.orgIds).toEqual(['org-a']);
    expect(seen.cronOptions?.runtimeSnapshotOutbox?.cronExpressions).toEqual(['*/5 * * * *']);
    expect(seen.cronOptions?.webhookRetryDispatch?.orgIds).toEqual(['org-c']);
    expect(seen.cronOptions?.webhookRetryDispatch?.cronExpressions).toEqual(['*/10 * * * *']);

    await seen.cronOptions?.runtimeSnapshotOutbox?.dispatch?.({
      payload: { snapshotId: 'snap_scheduled' },
    });
    expect(seen.outboxEvents).toEqual([{ payload: { snapshotId: 'snap_scheduled' } }]);
  });

  test('disables cron and all jobs when flags are off', async () => {
    let cronOptions: any = null;
    const scheduled = createWorkerScheduledHandler({
      createAuthService: () => ({} as any),
      outboxSink: {
        applyOutboxEvent() {},
      },
      createCron: (_service, options) => {
        cronOptions = options;
        return async () => {};
      },
    });

    await scheduled(
      { scheduledTime: Date.now(), cron: '*/5 * * * *' } as any,
      {
        ENABLE_ROTATION: '0',
        BILLING_FINALIZATION_ENABLED: '0',
        RUNTIME_SNAPSHOT_OUTBOX_ENABLED: '0',
        WEBHOOK_RETRY_ENABLED: '0',
      } as any,
      {} as any,
    );

    expect(cronOptions).toBeTruthy();
    expect(cronOptions.enabled).toBe(false);
    expect(cronOptions.rotate).toBe(false);
    expect(cronOptions.billingMonthlyFinalization).toBeUndefined();
    expect(cronOptions.runtimeSnapshotOutbox).toBeUndefined();
    expect(cronOptions.webhookRetryDispatch).toBeUndefined();
  });

  test('emits config warnings when enabled jobs are missing required env values', async () => {
    const warnings: Array<{ message: string; meta: any }> = [];
    const scheduled = createWorkerScheduledHandler({
      createAuthService: () => ({} as any),
      outboxSink: {
        applyOutboxEvent() {},
      },
      logger: {
        warn(message, meta) {
          warnings.push({ message, meta });
        },
      },
      createCron: () => async () => {},
    });

    await scheduled(
      { scheduledTime: Date.now(), cron: '*/5 * * * *' } as any,
      {
        ENABLE_ROTATION: '0',
        BILLING_FINALIZATION_ENABLED: '1',
        RUNTIME_SNAPSHOT_OUTBOX_ENABLED: '1',
        WEBHOOK_RETRY_ENABLED: '1',
        BILLING_POSTGRES_URL: '',
        BILLING_FINALIZATION_ORG_IDS: '',
        RUNTIME_SNAPSHOT_OUTBOX_ORG_IDS: '',
        WEBHOOK_RETRY_ORG_IDS: '',
      } as any,
      {} as any,
    );

    const codes = warnings.map((warning) => warning.meta?.code).sort();
    expect(codes).toEqual([
      'missing_org_ids',
      'missing_org_ids',
      'missing_org_ids',
      'missing_postgres_url',
      'missing_postgres_url',
      'missing_postgres_url',
    ]);
    expect(warnings.every((warning) => warning.message.includes('[cron][worker-config]'))).toBe(
      true,
    );
  });
});
