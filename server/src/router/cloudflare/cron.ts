import type { AuthService } from '../../core/AuthService';
import { getPostgresPool } from '../../storage/postgres';
import {
  runPostgresConsoleBillingMonthlyFinalization,
  type PostgresConsoleBillingMonthlyFinalizationOptions,
  type PostgresConsoleBillingMonthlyFinalizationResult,
} from '../../console/billing';
import type { ScheduledHandler } from './types';
import type { RouterLogger } from '../logger';
import { coerceRouterLogger } from '../logger';

const DEFAULT_BILLING_MONTHLY_FINALIZATION_LOCK_ID = 9452360123591;

type BillingMonthlyFinalizationRunner = (
  options: PostgresConsoleBillingMonthlyFinalizationOptions,
) => Promise<PostgresConsoleBillingMonthlyFinalizationResult>;

type BillingMonthlyFinalizationLockProvider = (input: {
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
}

function toValidLockId(input: unknown, fallback: number): number {
  const n = typeof input === 'number' ? input : Number(input);
  if (!Number.isInteger(n)) return fallback;
  return n;
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

  return async (event) => {
    if (!enabled) return;

    if (verbose) {
      logger.info('[cron] tick', {
        scheduledTime: typeof event?.scheduledTime === 'number' ? event.scheduledTime : undefined,
        cron: typeof event?.cron === 'string' ? event.cron : undefined,
        rotate,
        billingMonthlyFinalization: billingFinalizationEnabled,
      });
    }

    if (billingFinalizationEnabled) {
      const postgresUrl = String(billingFinalization?.postgresUrl || '').trim();
      if (!postgresUrl) {
        logger.warn('[cron][billing-finalization] skipped: missing postgresUrl');
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

    // NOTE: The legacy key-rotation cron is intentionally not implemented here.
    // The lite/threshold-only refactor removes legacy unlock/rotation flows; keep this as a no-op
    // to preserve the Cloudflare router surface during the transition.
  };
}
