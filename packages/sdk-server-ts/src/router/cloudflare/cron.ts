import type { AuthService } from '../../core/AuthService';
import { getPostgresPool } from '../../storage/postgres';
import {
  runPostgresConsoleBillingMonthlyFinalization,
  type PostgresConsoleBillingMonthlyFinalizationOptions,
  type PostgresConsoleBillingMonthlyFinalizationResult,
} from '../../console/billing';
import {
  runPostgresConsoleRuntimeSnapshotOutboxDispatch,
  type ConsoleRuntimeSnapshotOutboxEvent,
  type PostgresConsoleRuntimeSnapshotOutboxDispatchOptions,
  type PostgresConsoleRuntimeSnapshotOutboxDispatchResult,
} from '../../console/runtimeSnapshots';
import {
  runPostgresConsoleWebhookRetryDispatch,
  type PostgresConsoleWebhookRetryDispatchOptions,
  type PostgresConsoleWebhookRetryDispatchResult,
} from '../../console/webhooks';
import type { ConsoleObservabilityIngestionService } from '../../console/observability';
import type { ScheduledHandler } from './types';
import type { RouterLogger } from '../logger';
import { coerceRouterLogger } from '../logger';

const DEFAULT_BILLING_MONTHLY_FINALIZATION_LOCK_ID = 9452360123591;
const DEFAULT_RUNTIME_SNAPSHOT_OUTBOX_LOCK_ID = 9452360123592;
const DEFAULT_WEBHOOK_RETRY_DISPATCH_LOCK_ID = 9452360123593;

type BillingMonthlyFinalizationRunner = (
  options: PostgresConsoleBillingMonthlyFinalizationOptions,
) => Promise<PostgresConsoleBillingMonthlyFinalizationResult>;

type RuntimeSnapshotOutboxRunner = (
  options: PostgresConsoleRuntimeSnapshotOutboxDispatchOptions,
) => Promise<PostgresConsoleRuntimeSnapshotOutboxDispatchResult>;

type WebhookRetryDispatchRunner = (
  options: PostgresConsoleWebhookRetryDispatchOptions,
) => Promise<PostgresConsoleWebhookRetryDispatchResult>;

type BillingMonthlyFinalizationLockProvider = (input: {
  postgresUrl: string;
  lockId: number;
}) => Promise<{ acquired: boolean; release: () => Promise<void> }>;

type RuntimeSnapshotOutboxLockProvider = (input: {
  postgresUrl: string;
  lockId: number;
}) => Promise<{ acquired: boolean; release: () => Promise<void> }>;

type WebhookRetryDispatchLockProvider = (input: {
  postgresUrl: string;
  lockId: number;
}) => Promise<{ acquired: boolean; release: () => Promise<void> }>;

export interface CloudflareBillingMonthlyFinalizationCronOptions {
  /**
   * Enable monthly billing finalization.
   * Defaults to false.
   */
  enabled?: boolean;
  /**
   * Postgres URL for console billing schema.
   */
  postgresUrl?: string;
  /**
   * Optional billing namespace; defaults to `console-default`.
   */
  namespace?: string;
  /**
   * Optional target month (`YYYY-MM`). Defaults to previous UTC month.
   */
  periodMonthUtc?: string;
  /**
   * Org ids to finalize for this run.
   */
  orgIds?: string[];
  /**
   * Optional cron-expression allowlist for this job.
   * When provided, the job runs only for matching `event.cron` ticks.
   */
  cronExpressions?: string[];
  /**
   * Ensure schema before running finalization.
   * Defaults to true.
   */
  ensureSchema?: boolean;
  /**
   * Advisory lock id to prevent concurrent finalization runners.
   * Defaults to an internal constant.
   */
  advisoryLockId?: number;
  /**
   * Optional runner override for tests.
   */
  runner?: BillingMonthlyFinalizationRunner;
  /**
   * Optional lock provider override for tests.
   */
  lockProvider?: BillingMonthlyFinalizationLockProvider;
}

export interface CloudflareRuntimeSnapshotOutboxCronOptions {
  /**
   * Enable runtime snapshot outbox dispatch.
   * Defaults to false.
   */
  enabled?: boolean;
  /**
   * Postgres URL for runtime snapshot schema.
   */
  postgresUrl?: string;
  /**
   * Optional runtime snapshot namespace; defaults to `console-default`.
   */
  namespace?: string;
  /**
   * Org ids to dispatch for this run.
   */
  orgIds?: string[];
  /**
   * Optional cron-expression allowlist for this job.
   * When provided, the job runs only for matching `event.cron` ticks.
   */
  cronExpressions?: string[];
  /**
   * Max events to dispatch this run.
   * Defaults to 100.
   */
  limit?: number;
  /**
   * Ensure schema before dispatch.
   * Defaults to true.
   */
  ensureSchema?: boolean;
  /**
   * Advisory lock id to prevent concurrent dispatch runners.
   * Defaults to an internal constant.
   */
  advisoryLockId?: number;
  /**
   * Optional runner override for tests.
   */
  runner?: RuntimeSnapshotOutboxRunner;
  /**
   * Dispatch callback used by the default Postgres outbox runner.
   */
  dispatch?: (event: ConsoleRuntimeSnapshotOutboxEvent) => Promise<void> | void;
  /**
   * Optional lock provider override for tests.
   */
  lockProvider?: RuntimeSnapshotOutboxLockProvider;
}

export interface CloudflareWebhookRetryDispatchCronOptions {
  /**
   * Enable webhook retry dispatch.
   * Defaults to false.
   */
  enabled?: boolean;
  /**
   * Postgres URL for webhook schema.
   */
  postgresUrl?: string;
  /**
   * Optional webhook namespace; defaults to `console-default`.
   */
  namespace?: string;
  /**
   * Org ids to dispatch retries for this run.
   */
  orgIds?: string[];
  /**
   * Optional cron-expression allowlist for this job.
   * When provided, the job runs only for matching `event.cron` ticks.
   */
  cronExpressions?: string[];
  /**
   * Max failed deliveries to retry per org in this run.
   * Defaults to 100.
   */
  limit?: number;
  /**
   * Retry ceiling for total attempts per delivery.
   * Defaults to 5.
   */
  maxAttempts?: number;
  /**
   * Initial retry backoff in milliseconds.
   * Defaults to 60000.
   */
  initialBackoffMs?: number;
  /**
   * Max retry backoff in milliseconds.
   * Defaults to 3600000.
   */
  maxBackoffMs?: number;
  /**
   * Ensure schema before dispatch.
   * Defaults to true.
   */
  ensureSchema?: boolean;
  /**
   * Advisory lock id to prevent concurrent dispatch runners.
   * Defaults to an internal constant.
   */
  advisoryLockId?: number;
  /**
   * Optional runner override for tests.
   */
  runner?: WebhookRetryDispatchRunner;
  /**
   * Optional observability ingestion service forwarded to the retry runner.
   */
  observabilityIngestion?: ConsoleObservabilityIngestionService | null;
  /**
   * Optional lock provider override for tests.
   */
  lockProvider?: WebhookRetryDispatchLockProvider;
}

export interface CloudflareCronOptions {
  /**
   * When false, the handler is a no-op.
   * Defaults to true.
   */
  enabled?: boolean;
  /**
   * Legacy rotation flag used by older relay deployments.
   * Rotation logic is intentionally a no-op in the threshold-only stack.
   */
  rotate?: boolean;
  /**
   * Optional logger; defaults to silent.
   */
  logger?: RouterLogger | null;
  /**
   * When true, logs cron metadata for each tick.
   */
  verbose?: boolean;
  /**
   * Optional billing monthly-finalization job.
   */
  billingMonthlyFinalization?: CloudflareBillingMonthlyFinalizationCronOptions;
  /**
   * Optional runtime snapshot outbox dispatch job.
   */
  runtimeSnapshotOutbox?: CloudflareRuntimeSnapshotOutboxCronOptions;
  /**
   * Optional webhook retry dispatch job.
   */
  webhookRetryDispatch?: CloudflareWebhookRetryDispatchCronOptions;
}

function toValidLockId(input: unknown, fallback: number): number {
  const n = typeof input === 'number' ? input : Number(input);
  if (!Number.isInteger(n)) return fallback;
  return n;
}

function normalizeCronExpressions(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  return Array.from(
    new Set(
      input
        .map((value) => String(value || '').trim())
        .filter(Boolean),
    ),
  );
}

function shouldRunForCronTick(
  cronExpressions: string[],
  eventCron: string | undefined,
): boolean {
  if (cronExpressions.length === 0) return true;
  const tick = String(eventCron || '').trim();
  if (!tick) return false;
  return cronExpressions.includes(tick);
}

async function defaultBillingLockProvider(input: {
  postgresUrl: string;
  lockId: number;
}): Promise<{ acquired: boolean; release: () => Promise<void> }> {
  const pool = await getPostgresPool(input.postgresUrl);
  const lockRow = await pool.query('SELECT pg_try_advisory_lock($1) AS locked', [input.lockId]);
  const acquired = Boolean((lockRow.rows?.[0] as any)?.locked);
  let released = false;
  return {
    acquired,
    release: async () => {
      if (!acquired || released) return;
      released = true;
      await pool.query('SELECT pg_advisory_unlock($1)', [input.lockId]);
    },
  };
}

export function createCloudflareCron(
  _service: AuthService,
  opts: CloudflareCronOptions = {},
): ScheduledHandler {
  const enabled = opts.enabled !== false;
  const rotate = Boolean(opts.rotate);
  const verbose = Boolean(opts.verbose);
  const logger = coerceRouterLogger(opts.logger);
  const billingFinalization = opts.billingMonthlyFinalization;
  const billingFinalizationEnabled = Boolean(billingFinalization?.enabled);
  const billingFinalizationOrgIds = Array.from(
    new Set(
      (Array.isArray(billingFinalization?.orgIds) ? billingFinalization?.orgIds : [])
        .map((orgId) => String(orgId || '').trim())
        .filter(Boolean),
    ),
  );
  const billingFinalizationCronExpressions = normalizeCronExpressions(
    billingFinalization?.cronExpressions,
  );
  const runtimeSnapshotOutbox = opts.runtimeSnapshotOutbox;
  const runtimeSnapshotOutboxEnabled = Boolean(runtimeSnapshotOutbox?.enabled);
  const runtimeSnapshotOutboxOrgIds = Array.from(
    new Set(
      (Array.isArray(runtimeSnapshotOutbox?.orgIds) ? runtimeSnapshotOutbox?.orgIds : [])
        .map((orgId) => String(orgId || '').trim())
        .filter(Boolean),
    ),
  );
  const runtimeSnapshotOutboxCronExpressions = normalizeCronExpressions(
    runtimeSnapshotOutbox?.cronExpressions,
  );
  const webhookRetryDispatch = opts.webhookRetryDispatch;
  const webhookRetryDispatchEnabled = Boolean(webhookRetryDispatch?.enabled);
  const webhookRetryDispatchOrgIds = Array.from(
    new Set(
      (Array.isArray(webhookRetryDispatch?.orgIds) ? webhookRetryDispatch?.orgIds : [])
        .map((orgId) => String(orgId || '').trim())
        .filter(Boolean),
    ),
  );
  const webhookRetryDispatchCronExpressions = normalizeCronExpressions(
    webhookRetryDispatch?.cronExpressions,
  );
  return async (event) => {
    if (!enabled) return;

    if (verbose) {
      logger.info('[cron] tick', {
        scheduledTime: typeof event?.scheduledTime === 'number' ? event.scheduledTime : undefined,
        cron: typeof event?.cron === 'string' ? event.cron : undefined,
        rotate,
        billingMonthlyFinalization: billingFinalizationEnabled,
        runtimeSnapshotOutbox: runtimeSnapshotOutboxEnabled,
        webhookRetryDispatch: webhookRetryDispatchEnabled,
      });
    }

    if (billingFinalizationEnabled) {
      const eventCron = typeof event?.cron === 'string' ? event.cron : undefined;
      const billingCronMatches = shouldRunForCronTick(
        billingFinalizationCronExpressions,
        eventCron,
      );
      const postgresUrl = String(billingFinalization?.postgresUrl || '').trim();
      if (!billingCronMatches) {
        if (verbose) {
          logger.info('[cron][billing-finalization] skipped: cron expression mismatch', {
            eventCron,
            cronExpressions: billingFinalizationCronExpressions,
          });
        }
      } else if (!postgresUrl) {
        logger.warn('[cron][billing-finalization] skipped: missing postgresUrl');
      } else if (billingFinalizationOrgIds.length === 0) {
        logger.warn('[cron][billing-finalization] skipped: missing orgIds');
      } else {
        const lockId = toValidLockId(
          billingFinalization?.advisoryLockId,
          DEFAULT_BILLING_MONTHLY_FINALIZATION_LOCK_ID,
        );
        const lockProvider = billingFinalization?.lockProvider || defaultBillingLockProvider;
        const runner = billingFinalization?.runner || runPostgresConsoleBillingMonthlyFinalization;
        const lock = await lockProvider({ postgresUrl, lockId });
        if (!lock.acquired) {
          logger.info('[cron][billing-finalization] skipped: advisory lock not acquired', {
            lockId,
          });
        } else {
          try {
            const result = await runner({
              postgresUrl,
              namespace: billingFinalization?.namespace,
              orgIds: billingFinalizationOrgIds,
              periodMonthUtc: billingFinalization?.periodMonthUtc,
              ensureSchema: billingFinalization?.ensureSchema,
              logger: logger as any,
            });
            logger.info('[cron][billing-finalization] completed', {
              namespace: result.namespace,
              periodMonthUtc: result.periodMonthUtc,
              orgCount: result.orgCount,
              generatedCount: result.generatedCount,
              skippedCount: result.skippedCount,
              failureCount: result.failures.length,
            });
            if (result.failures.length > 0) {
              logger.warn('[cron][billing-finalization] failures', {
                namespace: result.namespace,
                periodMonthUtc: result.periodMonthUtc,
                failures: result.failures,
              });
            }
          } finally {
            try {
              await lock.release();
            } catch (error: unknown) {
              logger.error('[cron][billing-finalization] failed to release advisory lock', {
                lockId,
                message: error instanceof Error ? error.message : String(error),
              });
            }
          }
        }
      }
    }

    if (runtimeSnapshotOutboxEnabled) {
      const eventCron = typeof event?.cron === 'string' ? event.cron : undefined;
      const runtimeSnapshotOutboxCronMatches = shouldRunForCronTick(
        runtimeSnapshotOutboxCronExpressions,
        eventCron,
      );
      const postgresUrl = String(runtimeSnapshotOutbox?.postgresUrl || '').trim();
      if (!runtimeSnapshotOutboxCronMatches) {
        if (verbose) {
          logger.info('[cron][runtime-snapshot-outbox] skipped: cron expression mismatch', {
            eventCron,
            cronExpressions: runtimeSnapshotOutboxCronExpressions,
          });
        }
      } else if (!postgresUrl) {
        logger.warn('[cron][runtime-snapshot-outbox] skipped: missing postgresUrl');
      } else if (runtimeSnapshotOutboxOrgIds.length === 0) {
        logger.warn('[cron][runtime-snapshot-outbox] skipped: missing orgIds');
      } else if (!runtimeSnapshotOutbox?.runner && typeof runtimeSnapshotOutbox?.dispatch !== 'function') {
        logger.warn(
          '[cron][runtime-snapshot-outbox] skipped: missing dispatch callback for default runner',
        );
      } else {
        const lockId = toValidLockId(
          runtimeSnapshotOutbox?.advisoryLockId,
          DEFAULT_RUNTIME_SNAPSHOT_OUTBOX_LOCK_ID,
        );
        const lockProvider = runtimeSnapshotOutbox?.lockProvider || defaultBillingLockProvider;
        const runner =
          runtimeSnapshotOutbox?.runner || runPostgresConsoleRuntimeSnapshotOutboxDispatch;
        const lock = await lockProvider({ postgresUrl, lockId });
        if (!lock.acquired) {
          logger.info('[cron][runtime-snapshot-outbox] skipped: advisory lock not acquired', {
            lockId,
          });
        } else {
          try {
            const result = await runner({
              postgresUrl,
              namespace: runtimeSnapshotOutbox?.namespace,
              orgIds: runtimeSnapshotOutboxOrgIds,
              limit: runtimeSnapshotOutbox?.limit,
              ensureSchema: runtimeSnapshotOutbox?.ensureSchema,
              dispatch: runtimeSnapshotOutbox?.dispatch,
              logger: logger as any,
            });
            logger.info('[cron][runtime-snapshot-outbox] completed', {
              namespace: result.namespace,
              orgCount: result.orgCount,
              dispatchedCount: result.dispatchedCount,
              failureCount: result.failureCount,
            });
            if (result.failures.length > 0) {
              logger.warn('[cron][runtime-snapshot-outbox] failures', {
                namespace: result.namespace,
                failures: result.failures,
              });
            }
          } finally {
            try {
              await lock.release();
            } catch (error: unknown) {
              logger.error('[cron][runtime-snapshot-outbox] failed to release advisory lock', {
                lockId,
                message: error instanceof Error ? error.message : String(error),
              });
            }
          }
        }
      }
    }

    if (webhookRetryDispatchEnabled) {
      const eventCron = typeof event?.cron === 'string' ? event.cron : undefined;
      const webhookRetryDispatchCronMatches = shouldRunForCronTick(
        webhookRetryDispatchCronExpressions,
        eventCron,
      );
      const postgresUrl = String(webhookRetryDispatch?.postgresUrl || '').trim();
      if (!webhookRetryDispatchCronMatches) {
        if (verbose) {
          logger.info('[cron][webhook-retry-dispatch] skipped: cron expression mismatch', {
            eventCron,
            cronExpressions: webhookRetryDispatchCronExpressions,
          });
        }
      } else if (!postgresUrl) {
        logger.warn('[cron][webhook-retry-dispatch] skipped: missing postgresUrl');
      } else if (webhookRetryDispatchOrgIds.length === 0) {
        logger.warn('[cron][webhook-retry-dispatch] skipped: missing orgIds');
      } else {
        const lockId = toValidLockId(
          webhookRetryDispatch?.advisoryLockId,
          DEFAULT_WEBHOOK_RETRY_DISPATCH_LOCK_ID,
        );
        const lockProvider = webhookRetryDispatch?.lockProvider || defaultBillingLockProvider;
        const runner = webhookRetryDispatch?.runner || runPostgresConsoleWebhookRetryDispatch;
        const lock = await lockProvider({ postgresUrl, lockId });
        if (!lock.acquired) {
          logger.info('[cron][webhook-retry-dispatch] skipped: advisory lock not acquired', {
            lockId,
          });
        } else {
          try {
            const result = await runner({
              postgresUrl,
              namespace: webhookRetryDispatch?.namespace,
              orgIds: webhookRetryDispatchOrgIds,
              limit: webhookRetryDispatch?.limit,
              maxAttempts: webhookRetryDispatch?.maxAttempts,
              initialBackoffMs: webhookRetryDispatch?.initialBackoffMs,
              maxBackoffMs: webhookRetryDispatch?.maxBackoffMs,
              ensureSchema: webhookRetryDispatch?.ensureSchema,
              observabilityIngestion: webhookRetryDispatch?.observabilityIngestion,
              logger: logger as any,
            });
            logger.info('[cron][webhook-retry-dispatch] completed', {
              namespace: result.namespace,
              orgCount: result.orgCount,
              attemptedCount: result.attemptedCount,
              deliveredCount: result.deliveredCount,
              failedCount: result.failedCount,
              skippedCount: result.skippedCount,
              failureCount: result.failures.length,
            });
            if (result.failures.length > 0) {
              logger.warn('[cron][webhook-retry-dispatch] failures', {
                namespace: result.namespace,
                failures: result.failures,
              });
            }
          } finally {
            try {
              await lock.release();
            } catch (error: unknown) {
              logger.error('[cron][webhook-retry-dispatch] failed to release advisory lock', {
                lockId,
                message: error instanceof Error ? error.message : String(error),
              });
            }
          }
        }
      }
    }

    // NOTE: The legacy key-rotation cron is intentionally not implemented here.
    // The lite/threshold-only refactor removes legacy unlock/rotation flows; keep this as a no-op
    // to preserve the Cloudflare router surface during the transition.
  };
}
