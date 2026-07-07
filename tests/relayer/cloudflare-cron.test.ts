import { test, expect } from '@playwright/test';
import { createCloudflareCron } from '@seams-internal/console-server/router/cloudflare-adaptor';

const fakeD1Database = {} as any;
const fakeWebhookSecretCipher = {} as any;

test.describe('cloudflare cron billing finalization', () => {
  test('skips billing finalization when D1 database is missing', async () => {
    let runnerCalled = false;
    const cron = createCloudflareCron({
      billingMonthlyFinalization: {
        orgIds: ['org-a'],
        runner: async () => {
          runnerCalled = true;
          return {
            namespace: 'ns',
            periodMonthUtc: '2026-01',
            orgCount: 1,
            generatedCount: 0,
            skippedCount: 0,
            failures: [],
          };
        },
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '0 2 * * *' }, undefined, undefined);
    expect(runnerCalled).toBe(false);
  });

  test('runs billing finalization with D1 runner input', async () => {
    let runnerInput: any = null;
    const now = () => new Date('2026-02-03T04:05:06.000Z');
    const cron = createCloudflareCron({
      billingMonthlyFinalization: {
        database: fakeD1Database,
        namespace: 'billing-ns',
        periodMonthUtc: '2026-01',
        orgIds: ['org-a', 'org-b'],
        now,
        runner: async (input) => {
          runnerInput = input;
          return {
            namespace: 'billing-ns',
            periodMonthUtc: '2026-01',
            orgCount: 2,
            generatedCount: 2,
            skippedCount: 0,
            failures: [],
          };
        },
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '0 2 * * *' }, undefined, undefined);

    expect(runnerInput?.database).toBe(fakeD1Database);
    expect(runnerInput?.namespace).toBe('billing-ns');
    expect(runnerInput?.orgIds).toEqual(['org-a', 'org-b']);
    expect(runnerInput?.periodMonthUtc).toBe('2026-01');
    expect(runnerInput?.now).toBe(now);
  });
});

test.describe('cloudflare cron runtime snapshot outbox', () => {
  test('skips runtime snapshot outbox when D1 database is missing', async () => {
    let runnerCalled = false;
    const cron = createCloudflareCron({
      runtimeSnapshotOutbox: {
        orgIds: ['org-a'],
        dispatch: async () => {},
        runner: async () => {
          runnerCalled = true;
          return {
            namespace: 'ns',
            orgCount: 1,
            dispatchedCount: 0,
            failureCount: 0,
            failures: [],
          };
        },
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '*/5 * * * *' }, undefined, undefined);
    expect(runnerCalled).toBe(false);
  });

  test('runs runtime snapshot outbox when a runner override omits dispatch callback', async () => {
    let runnerCalled = false;
    const cron = createCloudflareCron({
      runtimeSnapshotOutbox: {
        database: fakeD1Database,
        namespace: 'runtime-ns',
        orgIds: ['org-a'],
        runner: async () => {
          runnerCalled = true;
          return {
            namespace: 'runtime-ns',
            orgCount: 1,
            dispatchedCount: 0,
            failureCount: 0,
            failures: [],
          };
        },
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '*/5 * * * *' }, undefined, undefined);
    expect(runnerCalled).toBe(true);
  });

  test('runs runtime snapshot outbox with D1 runner input', async () => {
    let runnerInput: any = null;
    const now = () => new Date('2026-02-03T04:05:06.000Z');
    const dispatch = async () => {};
    const cron = createCloudflareCron({
      runtimeSnapshotOutbox: {
        database: fakeD1Database,
        namespace: 'runtime-ns',
        orgIds: ['org-a', 'org-b'],
        limit: 50,
        ensureSchema: false,
        workerId: 'worker-1',
        claimTtlMs: 1234,
        retryBackoffMs: 5678,
        maxAttempts: 9,
        now,
        dispatch,
        runner: async (input) => {
          runnerInput = input;
          return {
            namespace: 'runtime-ns',
            orgCount: 2,
            dispatchedCount: 5,
            failureCount: 0,
            failures: [],
          };
        },
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '*/5 * * * *' }, undefined, undefined);

    expect(runnerInput?.database).toBe(fakeD1Database);
    expect(runnerInput?.namespace).toBe('runtime-ns');
    expect(runnerInput?.orgIds).toEqual(['org-a', 'org-b']);
    expect(runnerInput?.limit).toBe(50);
    expect(runnerInput?.ensureSchema).toBe(false);
    expect(runnerInput?.workerId).toBe('worker-1');
    expect(runnerInput?.claimTtlMs).toBe(1234);
    expect(runnerInput?.retryBackoffMs).toBe(5678);
    expect(runnerInput?.maxAttempts).toBe(9);
    expect(runnerInput?.now).toBe(now);
    expect(runnerInput?.dispatch).toBe(dispatch);
  });
});

test.describe('cloudflare cron webhook retry dispatch', () => {
  test('skips webhook retry dispatch when D1 database or cipher is missing', async () => {
    let runnerCalled = false;
    const cron = createCloudflareCron({
      webhookRetryDispatch: {
        orgIds: ['org-a'],
        runner: async () => {
          runnerCalled = true;
          return {
            namespace: 'ns',
            orgCount: 1,
            attemptedCount: 0,
            deliveredCount: 0,
            failedCount: 0,
            skippedCount: 0,
            failures: [],
          };
        },
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '*/5 * * * *' }, undefined, undefined);
    expect(runnerCalled).toBe(false);
  });

  test('runs webhook retry dispatch with D1 runner input', async () => {
    let runnerInput: any = null;
    const now = () => new Date('2026-02-03T04:05:06.000Z');
    const observabilityIngestion = {
      appendEvent: async () => ({ accepted: 1, deduplicated: 0 }),
      appendEvents: async (_ctx: unknown, events: unknown[]) => ({
        accepted: events.length,
        deduplicated: 0,
      }),
    };
    const cron = createCloudflareCron({
      webhookRetryDispatch: {
        database: fakeD1Database,
        secretCipher: fakeWebhookSecretCipher,
        namespace: 'webhook-ns',
        orgIds: ['org-a', 'org-b'],
        limit: 25,
        maxAttempts: 7,
        initialBackoffMs: 1000,
        maxBackoffMs: 60000,
        ensureSchema: false,
        workerId: 'webhook-worker-1',
        claimTtlMs: 4321,
        observabilityIngestion: observabilityIngestion as any,
        now,
        runner: async (input) => {
          runnerInput = input;
          return {
            namespace: 'webhook-ns',
            orgCount: 2,
            attemptedCount: 5,
            deliveredCount: 4,
            failedCount: 1,
            skippedCount: 0,
            failures: [],
          };
        },
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '*/5 * * * *' }, undefined, undefined);

    expect(runnerInput?.database).toBe(fakeD1Database);
    expect(runnerInput?.secretCipher).toBe(fakeWebhookSecretCipher);
    expect(runnerInput?.namespace).toBe('webhook-ns');
    expect(runnerInput?.orgIds).toEqual(['org-a', 'org-b']);
    expect(runnerInput?.limit).toBe(25);
    expect(runnerInput?.maxAttempts).toBe(7);
    expect(runnerInput?.initialBackoffMs).toBe(1000);
    expect(runnerInput?.maxBackoffMs).toBe(60000);
    expect(runnerInput?.ensureSchema).toBe(false);
    expect(runnerInput?.workerId).toBe('webhook-worker-1');
    expect(runnerInput?.claimTtlMs).toBe(4321);
    expect(runnerInput?.observabilityIngestion).toBe(observabilityIngestion);
    expect(runnerInput?.now).toBe(now);
  });
});

test.describe('cloudflare cron per-job expression filters', () => {
  test('runs only jobs whose cron allowlist matches the current tick', async () => {
    let billingCalled = false;
    let runtimeCalled = false;
    let webhookCalled = false;
    const cron = createCloudflareCron({
      billingMonthlyFinalization: {
        database: fakeD1Database,
        namespace: 'billing-ns',
        orgIds: ['org-a'],
        cronExpressions: ['0 2 1 * *'],
        runner: async () => {
          billingCalled = true;
          return {
            namespace: 'billing-ns',
            periodMonthUtc: '2026-01',
            orgCount: 1,
            generatedCount: 1,
            skippedCount: 0,
            failures: [],
          };
        },
      },
      runtimeSnapshotOutbox: {
        database: fakeD1Database,
        namespace: 'runtime-ns',
        orgIds: ['org-a'],
        cronExpressions: ['*/5 * * * *'],
        dispatch: async () => {},
        runner: async () => {
          runtimeCalled = true;
          return {
            namespace: 'runtime-ns',
            orgCount: 1,
            dispatchedCount: 1,
            failureCount: 0,
            failures: [],
          };
        },
      },
      webhookRetryDispatch: {
        database: fakeD1Database,
        secretCipher: fakeWebhookSecretCipher,
        namespace: 'webhook-ns',
        orgIds: ['org-a'],
        cronExpressions: ['*/5 * * * *'],
        runner: async () => {
          webhookCalled = true;
          return {
            namespace: 'webhook-ns',
            orgCount: 1,
            attemptedCount: 1,
            deliveredCount: 1,
            failedCount: 0,
            skippedCount: 0,
            failures: [],
          };
        },
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '*/5 * * * *' }, undefined, undefined);

    expect(billingCalled).toBe(false);
    expect(runtimeCalled).toBe(true);
    expect(webhookCalled).toBe(true);
  });

  test('skips cron-allowlisted jobs when event cron is absent', async () => {
    let runnerCalled = false;
    const cron = createCloudflareCron({
      billingMonthlyFinalization: {
        database: fakeD1Database,
        namespace: 'billing-ns',
        orgIds: ['org-a'],
        cronExpressions: ['0 2 1 * *'],
        runner: async () => {
          runnerCalled = true;
          return {
            namespace: 'billing-ns',
            periodMonthUtc: '2026-01',
            orgCount: 1,
            generatedCount: 1,
            skippedCount: 0,
            failures: [],
          };
        },
      },
    });

    await cron({ scheduledTime: Date.now() } as any, undefined, undefined);
    expect(runnerCalled).toBe(false);
  });
});
