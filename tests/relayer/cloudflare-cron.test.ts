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
    expect(runnerInput?.periodMonthUtc).toBe('2026-01');
    expect(runnerInput?.ensureSchema).toBe(false);
    expect(releaseCalled).toBe(true);
  });
});
