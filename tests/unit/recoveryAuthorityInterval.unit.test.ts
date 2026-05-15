import { expect, test } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';

const IMPORT_PATHS = {
  server: '/sdk/esm/server/router/recoveryAuthorityInterval.js',
} as const;

test.describe('recovery authority interval runner', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await injectImportMap(page);
  });

  test('starts, unreferences, and stops the scheduled interval', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { createRecoveryAuthorityIntervalRunner } = await import(paths.server);
      const loggerEvents: Array<{ level: string; message: string }> = [];
      let scheduledDelayMs = 0;
      let unrefCalled = false;
      let cleared = 0;

      const runner = createRecoveryAuthorityIntervalRunner(
        {
          listRecoveryExecutionsByStatus: async () => ({ ok: true as const, records: [] }),
          listAccountSignersByAccount: async () => ({ ok: true as const, records: [] }),
          putAccountSigner: async (record: Record<string, unknown>) => ({ ok: true as const, record }),
          recordRecoveryExecution: async (record: Record<string, unknown>) => ({
            ok: true as const,
            record,
          }),
          getRecoverySession: async () => ({ ok: true as const, record: null }),
          listRecoveryExecutions: async () => ({ ok: true as const, records: [] }),
          updateRecoverySessionStatus: async (record: Record<string, unknown>) => ({
            ok: true as const,
            record,
          }),
        } as any,
        {
          logger: {
            info(message: string) {
              loggerEvents.push({ level: 'info', message });
            },
            warn(message: string) {
              loggerEvents.push({ level: 'warn', message });
            },
            error(message: string) {
              loggerEvents.push({ level: 'error', message });
            },
          } as any,
          intervalMs: 1234,
          runImmediately: false,
          setIntervalImpl: (callback: () => void, delayMs: number) => {
            scheduledDelayMs = delayMs;
            return {
              callback,
              unref() {
                unrefCalled = true;
              },
            };
          },
          clearIntervalImpl: (handle: { callback: () => void } | null) => {
            if (!handle) return;
            cleared += 1;
          },
        },
      );

      const runningBeforeStart = runner.isRunning();
      runner.start();
      const runningAfterStart = runner.isRunning();
      runner.stop();
      const runningAfterStop = runner.isRunning();

      return {
        runningBeforeStart,
        runningAfterStart,
        runningAfterStop,
        scheduledDelayMs,
        unrefCalled,
        cleared,
        loggerEvents,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.runningBeforeStart).toBe(false);
    expect(result.runningAfterStart).toBe(true);
    expect(result.runningAfterStop).toBe(false);
    expect(result.scheduledDelayMs).toBe(1234);
    expect(result.unrefCalled).toBe(true);
    expect(result.cleared).toBe(1);
    expect(result.loggerEvents).toEqual([]);
  });

  test('triggerNow executes a recovery tick against canonical queues', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { createRecoveryAuthorityIntervalRunner } = await import(paths.server);
      let statusReads = 0;
      const runner = createRecoveryAuthorityIntervalRunner(
        {
          listRecoveryExecutionsByStatus: async () => {
            statusReads += 1;
            return { ok: true as const, records: [] };
          },
          listAccountSignersByAccount: async () => ({ ok: true as const, records: [] }),
          putAccountSigner: async (record: Record<string, unknown>) => ({ ok: true as const, record }),
          recordRecoveryExecution: async (record: Record<string, unknown>) => ({
            ok: true as const,
            record,
          }),
          getRecoverySession: async () => ({ ok: true as const, record: null }),
          listRecoveryExecutions: async () => ({ ok: true as const, records: [] }),
          updateRecoverySessionStatus: async (record: Record<string, unknown>) => ({
            ok: true as const,
            record,
          }),
        } as any,
        {
          logger: console as any,
          intervalMs: 1000,
          runImmediately: false,
        },
      );

      await runner.triggerNow();

      return {
        statusReads,
        running: runner.isRunning(),
      };
    }, { paths: IMPORT_PATHS });

    expect(result.statusReads).toBe(6);
    expect(result.running).toBe(false);
  });
});
