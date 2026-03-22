import { expect, test } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';

const IMPORT_PATHS = {
  server: '/sdk/esm/server/index.js',
} as const;

test.describe('recovery authority monitoring', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await injectImportMap(page);
  });

  test('warns on failed and stale recovery executions', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { monitorRecoveryAuthorityExecutions } = await import(paths.server);
      const warnings: Array<{ message: string; meta?: Record<string, unknown> }> = [];
      const nowMs = 500_000;
      const recordsByStatus = {
        failed: [
          {
            sessionId: 'session-failed',
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'11'.repeat(20)}`,
            status: 'failed',
          },
        ],
        pending: [
          {
            sessionId: 'session-pending',
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'22'.repeat(20)}`,
            status: 'pending',
          },
        ],
        submitted: [
          {
            sessionId: 'session-submitted',
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'33'.repeat(20)}`,
            status: 'submitted',
          },
        ],
      } as const;

      const monitored = await monitorRecoveryAuthorityExecutions(
        {
          listRecoveryExecutionsByStatus: async ({ status }: { status: keyof typeof recordsByStatus }) =>
            ({
              ok: true as const,
              records: [...recordsByStatus[status]],
            }) as const,
        } as any,
        {
          logger: {
            info() {},
            error() {},
            warn(message: string, meta?: Record<string, unknown>) {
              warnings.push({ message, meta });
            },
          } as any,
          config: {
            enabled: true,
            nowMs,
            stalePendingAfterMs: 10_000,
            staleSubmittedAfterMs: 20_000,
          },
        },
      );

      return {
        monitored,
        warnings,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.monitored.ok).toBe(true);
    expect((result.monitored as any).summary).toEqual({
      failed: 1,
      stalePending: 1,
      staleSubmitted: 1,
    });
    expect(result.warnings).toHaveLength(3);
    expect(result.warnings[0]?.message).toContain('failed recovery executions detected');
    expect(result.warnings[1]?.message).toContain('stale pending recovery executions detected');
    expect(result.warnings[2]?.message).toContain('stale submitted recovery executions detected');
  });

  test('emits grouped observability events when sponsorship scope metadata is present', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { monitorRecoveryAuthorityExecutions } = await import(paths.server);
      const appended: Array<{
        orgId: string;
        actorUserId: string;
        roles: string[];
        eventId: string;
        eventType: string;
      }> = [];

      const recordsByStatus = {
        failed: [
          {
            sessionId: 'session-failed',
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'11'.repeat(20)}`,
            status: 'failed',
            errorCode: 'tx_reverted',
            metadata: {
              sponsorshipScope: {
                orgId: 'org_recovery',
                environmentId: 'env_recovery',
                projectId: 'proj_recovery',
              },
            },
          },
        ],
        pending: [
          {
            sessionId: 'session-pending',
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'22'.repeat(20)}`,
            status: 'pending',
            metadata: {
              sponsorshipScope: {
                orgId: 'org_recovery',
                environmentId: 'env_recovery',
                projectId: 'proj_recovery',
              },
            },
          },
        ],
        submitted: [
          {
            sessionId: 'session-submitted',
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'33'.repeat(20)}`,
            status: 'submitted',
            metadata: {
              sponsorshipScope: {
                orgId: 'org_recovery',
                environmentId: 'env_recovery',
                projectId: 'proj_recovery',
              },
            },
          },
        ],
      } as const;

      const monitoringInput = {
        logger: console as any,
        observabilityIngestion: {
          appendEvent: async (
            ingestCtx: { orgId: string; actorUserId: string; roles: string[] },
            event: { eventId: string; eventType: string },
          ) => {
            appended.push({
              orgId: ingestCtx.orgId,
              actorUserId: ingestCtx.actorUserId,
              roles: ingestCtx.roles,
              eventId: event.eventId,
              eventType: event.eventType,
            });
            return { accepted: 1, deduplicated: 0 };
          },
        } as any,
        actorUserId: 'system-monitor',
        actorRoles: ['ops', 'support'],
        config: {
          enabled: true,
          nowMs: 500_000,
          stalePendingAfterMs: 10_000,
          staleSubmittedAfterMs: 20_000,
        },
      } as const;

      const monitored = await monitorRecoveryAuthorityExecutions(
        {
          listRecoveryExecutionsByStatus: async ({ status }: { status: keyof typeof recordsByStatus }) =>
            ({
              ok: true as const,
              records: [...recordsByStatus[status]],
            }) as const,
        } as any,
        monitoringInput,
      );
      const monitoredSecond = await monitorRecoveryAuthorityExecutions(
        {
          listRecoveryExecutionsByStatus: async ({ status }: { status: keyof typeof recordsByStatus }) =>
            ({
              ok: true as const,
              records: [...recordsByStatus[status]],
            }) as const,
        } as any,
        monitoringInput,
      );

      return {
        monitored,
        monitoredSecond,
        appended,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.monitored.ok).toBe(true);
    expect(result.monitoredSecond.ok).toBe(true);
    const firstRun = result.appended.slice(0, 3);
    const secondRun = result.appended.slice(3);
    expect(firstRun.map((entry: any) => ({
      orgId: entry.orgId,
      actorUserId: entry.actorUserId,
      roles: entry.roles,
      eventType: entry.eventType,
    }))).toEqual([
      {
        orgId: 'org_recovery',
        actorUserId: 'system-monitor',
        roles: ['ops', 'support'],
        eventType: 'system.recovery_execution.failed',
      },
      {
        orgId: 'org_recovery',
        actorUserId: 'system-monitor',
        roles: ['ops', 'support'],
        eventType: 'system.recovery_execution.stuck',
      },
      {
        orgId: 'org_recovery',
        actorUserId: 'system-monitor',
        roles: ['ops', 'support'],
        eventType: 'system.recovery_execution.stuck',
      },
    ]);
    expect(firstRun.map((entry: any) => entry.eventId)).toEqual(secondRun.map((entry: any) => entry.eventId));
    expect(firstRun[0]?.eventId).toMatch(/^obs_recovery_execution_failed_[0-9a-f]{16}$/);
    expect(firstRun[1]?.eventId).toMatch(/^obs_recovery_execution_stuck_[0-9a-f]{16}$/);
    expect(firstRun[2]?.eventId).toMatch(/^obs_recovery_execution_stuck_[0-9a-f]{16}$/);
    expect(new Set(firstRun.map((entry: any) => entry.eventId)).size).toBe(3);
  });
});
