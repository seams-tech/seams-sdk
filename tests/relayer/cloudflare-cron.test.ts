import { test, expect } from '@playwright/test';
import { createCloudflareCron } from '@server/router/cloudflare-adaptor';

test.describe('cloudflare cron billing finalization', () => {
  test('skips billing finalization when postgres url is missing', async () => {
    let runnerCalled = false;
    let lockProviderCalled = false;
    const cron = createCloudflareCron({} as any, {
      enabled: true,
      billingMonthlyFinalization: {
        enabled: true,
        runner: async () => {
          runnerCalled = true;
          return {
            namespace: 'ns',
            periodMonthUtc: '2026-01',
            orgCount: 0,
            generatedCount: 0,
            skippedCount: 0,
            failures: [],
          };
        },
        lockProvider: async () => {
          lockProviderCalled = true;
          return {
            acquired: true,
            release: async () => {},
          };
        },
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '0 2 * * *' }, undefined, undefined);
    expect(runnerCalled).toBe(false);
    expect(lockProviderCalled).toBe(false);
  });

  test('skips billing finalization when advisory lock is not acquired', async () => {
    let runnerCalled = false;
    let releaseCalled = false;
    const cron = createCloudflareCron({} as any, {
      enabled: true,
      billingMonthlyFinalization: {
        enabled: true,
        postgresUrl: 'postgres://example.invalid/db',
        namespace: 'test-ns',
        periodMonthUtc: '2026-01',
        orgIds: ['org-a'],
        runner: async () => {
          runnerCalled = true;
          return {
            namespace: 'test-ns',
            periodMonthUtc: '2026-01',
            orgCount: 0,
            generatedCount: 0,
            skippedCount: 0,
            failures: [],
          };
        },
        lockProvider: async () => ({
          acquired: false,
          release: async () => {
            releaseCalled = true;
          },
        }),
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '0 2 * * *' }, undefined, undefined);
    expect(runnerCalled).toBe(false);
    expect(releaseCalled).toBe(false);
  });

  test('runs billing finalization when lock is acquired and releases lock', async () => {
    let releaseCalled = false;
    let runnerInput: any = null;
    const cron = createCloudflareCron({} as any, {
      enabled: true,
      billingMonthlyFinalization: {
        enabled: true,
        postgresUrl: 'postgres://example.invalid/db',
        namespace: 'billing-ns',
        periodMonthUtc: '2026-01',
        orgIds: ['org-a', 'org-b'],
        ensureSchema: false,
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
        lockProvider: async () => ({
          acquired: true,
          release: async () => {
            releaseCalled = true;
          },
        }),
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '0 2 * * *' }, undefined, undefined);

    expect(runnerInput).toBeTruthy();
    expect(String(runnerInput?.postgresUrl || '')).toContain('postgres://example.invalid/db');
    expect(runnerInput?.namespace).toBe('billing-ns');
    expect(Array.isArray(runnerInput?.orgIds)).toBe(true);
    expect(runnerInput?.orgIds).toEqual(['org-a', 'org-b']);
    expect(runnerInput?.periodMonthUtc).toBe('2026-01');
    expect(runnerInput?.ensureSchema).toBe(false);
    expect(releaseCalled).toBe(true);
  });
});

test.describe('cloudflare cron runtime snapshot outbox', () => {
  test('skips runtime snapshot outbox when postgres url is missing', async () => {
    let runnerCalled = false;
    let lockProviderCalled = false;
    const cron = createCloudflareCron({} as any, {
      enabled: true,
      runtimeSnapshotOutbox: {
        enabled: true,
        orgIds: ['org-a'],
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
        lockProvider: async () => {
          lockProviderCalled = true;
          return {
            acquired: true,
            release: async () => {},
          };
        },
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '*/5 * * * *' }, undefined, undefined);
    expect(runnerCalled).toBe(false);
    expect(lockProviderCalled).toBe(false);
  });

  test('skips runtime snapshot outbox when advisory lock is not acquired', async () => {
    let runnerCalled = false;
    let releaseCalled = false;
    const cron = createCloudflareCron({} as any, {
      enabled: true,
      runtimeSnapshotOutbox: {
        enabled: true,
        postgresUrl: 'postgres://example.invalid/db',
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
        lockProvider: async () => ({
          acquired: false,
          release: async () => {
            releaseCalled = true;
          },
        }),
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '*/5 * * * *' }, undefined, undefined);
    expect(runnerCalled).toBe(false);
    expect(releaseCalled).toBe(false);
  });

  test('skips runtime snapshot outbox when default runner has no dispatch callback', async () => {
    let lockProviderCalled = false;
    const cron = createCloudflareCron({} as any, {
      enabled: true,
      runtimeSnapshotOutbox: {
        enabled: true,
        postgresUrl: 'postgres://example.invalid/db',
        namespace: 'runtime-ns',
        orgIds: ['org-a'],
        lockProvider: async () => {
          lockProviderCalled = true;
          return {
            acquired: true,
            release: async () => {},
          };
        },
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '*/5 * * * *' }, undefined, undefined);
    expect(lockProviderCalled).toBe(false);
  });

  test('runs runtime snapshot outbox when lock is acquired and releases lock', async () => {
    let releaseCalled = false;
    let runnerInput: any = null;
    const cron = createCloudflareCron({} as any, {
      enabled: true,
      runtimeSnapshotOutbox: {
        enabled: true,
        postgresUrl: 'postgres://example.invalid/db',
        namespace: 'runtime-ns',
        orgIds: ['org-a', 'org-b'],
        limit: 50,
        ensureSchema: false,
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
        lockProvider: async () => ({
          acquired: true,
          release: async () => {
            releaseCalled = true;
          },
        }),
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '*/5 * * * *' }, undefined, undefined);

    expect(runnerInput).toBeTruthy();
    expect(String(runnerInput?.postgresUrl || '')).toContain('postgres://example.invalid/db');
    expect(runnerInput?.namespace).toBe('runtime-ns');
    expect(runnerInput?.orgIds).toEqual(['org-a', 'org-b']);
    expect(runnerInput?.limit).toBe(50);
    expect(runnerInput?.ensureSchema).toBe(false);
    expect(releaseCalled).toBe(true);
  });
});

test.describe('cloudflare cron webhook retry dispatch', () => {
  test('skips webhook retry dispatch when postgres url is missing', async () => {
    let runnerCalled = false;
    let lockProviderCalled = false;
    const cron = createCloudflareCron({} as any, {
      enabled: true,
      webhookRetryDispatch: {
        enabled: true,
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
        lockProvider: async () => {
          lockProviderCalled = true;
          return {
            acquired: true,
            release: async () => {},
          };
        },
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '*/5 * * * *' }, undefined, undefined);
    expect(runnerCalled).toBe(false);
    expect(lockProviderCalled).toBe(false);
  });

  test('skips webhook retry dispatch when advisory lock is not acquired', async () => {
    let runnerCalled = false;
    let releaseCalled = false;
    const cron = createCloudflareCron({} as any, {
      enabled: true,
      webhookRetryDispatch: {
        enabled: true,
        postgresUrl: 'postgres://example.invalid/db',
        namespace: 'webhook-ns',
        orgIds: ['org-a'],
        runner: async () => {
          runnerCalled = true;
          return {
            namespace: 'webhook-ns',
            orgCount: 1,
            attemptedCount: 0,
            deliveredCount: 0,
            failedCount: 0,
            skippedCount: 0,
            failures: [],
          };
        },
        lockProvider: async () => ({
          acquired: false,
          release: async () => {
            releaseCalled = true;
          },
        }),
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '*/5 * * * *' }, undefined, undefined);
    expect(runnerCalled).toBe(false);
    expect(releaseCalled).toBe(false);
  });

  test('runs webhook retry dispatch when lock is acquired and releases lock', async () => {
    let releaseCalled = false;
    let runnerInput: any = null;
    const observabilityIngestion = {
      appendEvent: async () => ({ accepted: 1, deduplicated: 0 }),
      appendEvents: async (_ctx: unknown, events: unknown[]) => ({
        accepted: events.length,
        deduplicated: 0,
      }),
    };
    const cron = createCloudflareCron({} as any, {
      enabled: true,
      webhookRetryDispatch: {
        enabled: true,
        postgresUrl: 'postgres://example.invalid/db',
        namespace: 'webhook-ns',
        orgIds: ['org-a', 'org-b'],
        limit: 25,
        maxAttempts: 7,
        initialBackoffMs: 1000,
        maxBackoffMs: 60000,
        ensureSchema: false,
        observabilityIngestion: observabilityIngestion as any,
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
        lockProvider: async () => ({
          acquired: true,
          release: async () => {
            releaseCalled = true;
          },
        }),
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '*/5 * * * *' }, undefined, undefined);

    expect(runnerInput).toBeTruthy();
    expect(String(runnerInput?.postgresUrl || '')).toContain('postgres://example.invalid/db');
    expect(runnerInput?.namespace).toBe('webhook-ns');
    expect(runnerInput?.orgIds).toEqual(['org-a', 'org-b']);
    expect(runnerInput?.limit).toBe(25);
    expect(runnerInput?.maxAttempts).toBe(7);
    expect(runnerInput?.initialBackoffMs).toBe(1000);
    expect(runnerInput?.maxBackoffMs).toBe(60000);
    expect(runnerInput?.ensureSchema).toBe(false);
    expect(runnerInput?.observabilityIngestion).toBe(observabilityIngestion);
    expect(releaseCalled).toBe(true);
  });
});

test.describe('cloudflare cron per-job expression filters', () => {
  test('runs only jobs whose cron allowlist matches the current tick', async () => {
    let billingCalled = false;
    let runtimeCalled = false;
    let webhookCalled = false;
    const lockProvider = async () => ({
      acquired: true,
      release: async () => {},
    });
    const cron = createCloudflareCron({} as any, {
      enabled: true,
      billingMonthlyFinalization: {
        enabled: true,
        postgresUrl: 'postgres://example.invalid/db',
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
        lockProvider,
      },
      runtimeSnapshotOutbox: {
        enabled: true,
        postgresUrl: 'postgres://example.invalid/db',
        namespace: 'runtime-ns',
        orgIds: ['org-a'],
        cronExpressions: ['*/5 * * * *'],
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
        lockProvider,
      },
      webhookRetryDispatch: {
        enabled: true,
        postgresUrl: 'postgres://example.invalid/db',
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
        lockProvider,
      },
    });

    await cron({ scheduledTime: Date.now(), cron: '*/5 * * * *' }, undefined, undefined);

    expect(billingCalled).toBe(false);
    expect(runtimeCalled).toBe(true);
    expect(webhookCalled).toBe(true);
  });

  test('skips cron-allowlisted jobs when event cron is absent', async () => {
    let runnerCalled = false;
    const cron = createCloudflareCron({} as any, {
      enabled: true,
      billingMonthlyFinalization: {
        enabled: true,
        postgresUrl: 'postgres://example.invalid/db',
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
        lockProvider: async () => ({
          acquired: true,
          release: async () => {},
        }),
      },
    });

    await cron({ scheduledTime: Date.now() } as any, undefined, undefined);
    expect(runnerCalled).toBe(false);
  });
});
