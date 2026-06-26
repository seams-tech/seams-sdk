import type { AuthService } from '../../core/AuthService';
import {
  runD1ConsoleBillingMonthlyFinalization,
  type D1ConsoleBillingMonthlyFinalizationOptions,
  type D1ConsoleBillingMonthlyFinalizationResult,
} from '../../console/billing';
import {
  runD1ConsoleRuntimeSnapshotOutboxDispatch,
  type ConsoleRuntimeSnapshotOutboxEvent,
  type D1ConsoleRuntimeSnapshotOutboxDispatchOptions,
  type D1ConsoleRuntimeSnapshotOutboxDispatchResult,
} from '../../console/runtimeSnapshots';
import {
  runD1ConsoleWebhookRetryDispatch,
  type ConsoleWebhookSecretCipher,
  type D1ConsoleWebhookRetryDispatchOptions,
  type D1ConsoleWebhookRetryDispatchResult,
} from '../../console/webhooks';
import type { ConsoleObservabilityIngestionService } from '../../console/observability';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
import type { ScheduledHandler } from './cloudflare.types';
import type { RouterLogger } from '../logger';
import { coerceRouterLogger } from '../logger';

type BillingMonthlyFinalizationRunner = (
  options: D1ConsoleBillingMonthlyFinalizationOptions,
) => Promise<D1ConsoleBillingMonthlyFinalizationResult>;

type RuntimeSnapshotOutboxRunner = (
  options: D1ConsoleRuntimeSnapshotOutboxDispatchOptions,
) => Promise<D1ConsoleRuntimeSnapshotOutboxDispatchResult>;

type WebhookRetryDispatchRunner = (
  options: D1ConsoleWebhookRetryDispatchOptions,
) => Promise<D1ConsoleWebhookRetryDispatchResult>;

export interface CloudflareBillingMonthlyFinalizationCronOptions {
  /**
   * Enable monthly billing finalization.
   * Defaults to false.
   */
  enabled?: boolean;
  /**
   * D1 database for console billing finalization.
   */
  database?: D1DatabaseLike;
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
   * Optional runner override for tests.
   */
  runner?: BillingMonthlyFinalizationRunner;
  /**
   * Clock used by the D1 billing finalization runner.
   */
  now?: () => Date;
}

export interface CloudflareRuntimeSnapshotOutboxCronOptions {
  /**
   * Enable runtime snapshot outbox dispatch.
   * Defaults to false.
   */
  enabled?: boolean;
  /**
   * D1 database for runtime snapshot outbox dispatch.
   */
  database?: D1DatabaseLike;
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
   * Optional runner override for tests.
   */
  runner?: RuntimeSnapshotOutboxRunner;
  /**
   * Dispatch callback used by the default D1 outbox runner.
   */
  dispatch?: (event: ConsoleRuntimeSnapshotOutboxEvent) => Promise<void> | void;
  /**
   * D1 dispatch worker id used in claim leases.
   */
  workerId?: string;
  /**
   * D1 claim lease duration in milliseconds.
   */
  claimTtlMs?: number;
  /**
   * Retry backoff in milliseconds.
   */
  retryBackoffMs?: number;
  /**
   * Retry ceiling for total attempts per event.
   */
  maxAttempts?: number;
  /**
   * Clock used by the D1 runtime snapshot outbox runner.
   */
  now?: () => Date;
}

export interface CloudflareWebhookRetryDispatchCronOptions {
  /**
   * Enable webhook retry dispatch.
   * Defaults to false.
   */
  enabled?: boolean;
  /**
   * D1 database for Cloudflare webhook retry dispatch.
   */
  database?: D1DatabaseLike;
  /**
   * Webhook secret cipher required by D1 retry dispatch.
   */
  secretCipher?: ConsoleWebhookSecretCipher;
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
   * Optional runner override for tests.
   */
  runner?: WebhookRetryDispatchRunner;
  /**
   * D1 retry worker id used in claim leases.
   */
  workerId?: string;
  /**
   * D1 retry claim lease duration in milliseconds.
   */
  claimTtlMs?: number;
  /**
   * Optional observability ingestion service forwarded to the retry runner.
   */
  observabilityIngestion?: ConsoleObservabilityIngestionService | null;
  /**
   * Clock used by the D1 webhook retry runner.
   */
  now?: () => Date;
}

export interface CloudflareCronOptions {
  /**
   * When false, the handler is a no-op.
   * Defaults to true.
   */
  enabled?: boolean;
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

export function createCloudflareCron(
  _service: AuthService,
  opts: CloudflareCronOptions = {},
): ScheduledHandler {
  const enabled = opts.enabled !== false;
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
      const database = billingFinalization?.database || null;
      if (!billingCronMatches) {
        if (verbose) {
          logger.info('[cron][billing-finalization] skipped: cron expression mismatch', {
            eventCron,
            cronExpressions: billingFinalizationCronExpressions,
          });
        }
      } else if (!database) {
        logger.warn('[cron][billing-finalization] skipped: missing D1 database');
      } else if (billingFinalizationOrgIds.length === 0) {
        logger.warn('[cron][billing-finalization] skipped: missing orgIds');
      } else {
        const runner = billingFinalization?.runner || runD1ConsoleBillingMonthlyFinalization;
        const result = await runner({
          database,
          namespace: billingFinalization?.namespace,
          orgIds: billingFinalizationOrgIds,
          periodMonthUtc: billingFinalization?.periodMonthUtc,
          ensureSchema: billingFinalization?.ensureSchema,
          now: billingFinalization?.now,
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
      }
    }

    if (runtimeSnapshotOutboxEnabled) {
      const eventCron = typeof event?.cron === 'string' ? event.cron : undefined;
      const runtimeSnapshotOutboxCronMatches = shouldRunForCronTick(
        runtimeSnapshotOutboxCronExpressions,
        eventCron,
      );
      const database = runtimeSnapshotOutbox?.database || null;
      if (!runtimeSnapshotOutboxCronMatches) {
        if (verbose) {
          logger.info('[cron][runtime-snapshot-outbox] skipped: cron expression mismatch', {
            eventCron,
            cronExpressions: runtimeSnapshotOutboxCronExpressions,
          });
        }
      } else if (!database) {
        logger.warn('[cron][runtime-snapshot-outbox] skipped: missing D1 database');
      } else if (runtimeSnapshotOutboxOrgIds.length === 0) {
        logger.warn('[cron][runtime-snapshot-outbox] skipped: missing orgIds');
      } else if (!runtimeSnapshotOutbox?.runner && typeof runtimeSnapshotOutbox?.dispatch !== 'function') {
        logger.warn(
          '[cron][runtime-snapshot-outbox] skipped: missing dispatch callback for default D1 runner',
        );
      } else {
        const runner = runtimeSnapshotOutbox?.runner || runD1ConsoleRuntimeSnapshotOutboxDispatch;
        const result = await runner({
          database,
          namespace: runtimeSnapshotOutbox?.namespace,
          orgIds: runtimeSnapshotOutboxOrgIds,
          limit: runtimeSnapshotOutbox?.limit,
          ensureSchema: runtimeSnapshotOutbox?.ensureSchema,
          dispatch: runtimeSnapshotOutbox?.dispatch,
          logger: logger as any,
          workerId: runtimeSnapshotOutbox?.workerId,
          claimTtlMs: runtimeSnapshotOutbox?.claimTtlMs,
          retryBackoffMs: runtimeSnapshotOutbox?.retryBackoffMs,
          maxAttempts: runtimeSnapshotOutbox?.maxAttempts,
          now: runtimeSnapshotOutbox?.now,
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
      }
    }

    if (webhookRetryDispatchEnabled) {
      const eventCron = typeof event?.cron === 'string' ? event.cron : undefined;
      const webhookRetryDispatchCronMatches = shouldRunForCronTick(
        webhookRetryDispatchCronExpressions,
        eventCron,
      );
      const d1Database = webhookRetryDispatch?.database || null;
      const d1SecretCipher = webhookRetryDispatch?.secretCipher || null;
      if (!webhookRetryDispatchCronMatches) {
        if (verbose) {
          logger.info('[cron][webhook-retry-dispatch] skipped: cron expression mismatch', {
            eventCron,
            cronExpressions: webhookRetryDispatchCronExpressions,
          });
        }
      } else if (webhookRetryDispatchOrgIds.length === 0) {
        logger.warn('[cron][webhook-retry-dispatch] skipped: missing orgIds');
      } else if (!d1Database || !d1SecretCipher) {
        logger.warn(
          '[cron][webhook-retry-dispatch] skipped: missing D1 database or secret cipher',
        );
      } else {
        const runner = webhookRetryDispatch?.runner || runD1ConsoleWebhookRetryDispatch;
        const result = await runner({
          database: d1Database,
          secretCipher: d1SecretCipher,
          namespace: webhookRetryDispatch?.namespace,
          orgIds: webhookRetryDispatchOrgIds,
          limit: webhookRetryDispatch?.limit,
          maxAttempts: webhookRetryDispatch?.maxAttempts,
          initialBackoffMs: webhookRetryDispatch?.initialBackoffMs,
          maxBackoffMs: webhookRetryDispatch?.maxBackoffMs,
          ensureSchema: webhookRetryDispatch?.ensureSchema,
          observabilityIngestion: webhookRetryDispatch?.observabilityIngestion,
          logger: logger as any,
          workerId: webhookRetryDispatch?.workerId,
          claimTtlMs: webhookRetryDispatch?.claimTtlMs,
          now: webhookRetryDispatch?.now,
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
      }
    }
  };
}
