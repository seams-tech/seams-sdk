import { WALLET_CONSOLE_WEBHOOK_EVENT_CATEGORY_VALIDATION } from '@seams-internal/wallet-console-shared/webhookEventCategories';
import {
  runD1ConsoleBillingMonthlyFinalization,
  type D1ConsoleBillingMonthlyFinalizationOptions,
  type D1ConsoleBillingMonthlyFinalizationResult,
} from '@seams-internal/console-server/billing/d1';
import {
  runD1ConsoleRuntimeSnapshotOutboxDispatch,
  type D1ConsoleRuntimeSnapshotOutboxDispatchOptions,
  type D1ConsoleRuntimeSnapshotOutboxDispatchResult,
} from '@seams-internal/wallet-console-server/runtimeSnapshots/d1';
import type { ConsoleRuntimeSnapshotOutboxEvent } from '@seams-internal/wallet-console-server/runtimeSnapshots/types';
import {
  runD1ConsoleWebhookRetryDispatch,
  type ConsoleWebhookSecretCipher,
  type D1ConsoleWebhookRetryDispatchOptions,
  type D1ConsoleWebhookRetryDispatchResult,
} from '@seams-internal/console-server/webhooks/d1';
import type { ConsoleObservabilityIngestionService } from '@seams-internal/console-server/observability/ingestionService';
import {
  runD1ConsoleEmailDispatcher,
  type D1ConsoleEmailDispatcherOptions,
} from '@seams-internal/console-server/email/d1';
import {
  createCaptureConsoleEmailProvider,
  createResendConsoleEmailProvider,
} from '@seams-internal/console-server/email/providers';
import {
  createAesGcmConsoleInvitationSecretCipher,
  type ConsoleInvitationSecretCipher,
} from '@seams-internal/console-server/email/secrets';
import type {
  ConsoleEmailDispatchResult,
  ConsoleEmailProvider,
} from '@seams-internal/console-server/email/types';
import type { D1DatabaseLike } from '@seams/wallet-server/cloud-host';
import type { ScheduledHandler } from '@seams/wallet-server/cloud-host';
import type { RouterLogger } from '@seams/wallet-server/cloud-host';
import { base64UrlDecode, coerceRouterLogger } from '@seams/wallet-server/cloud-host';
import type { RouterApiCloudflareConsoleWorkerEnv } from './cloudflareConsole.types';

type BillingMonthlyFinalizationRunner = (
  options: D1ConsoleBillingMonthlyFinalizationOptions,
) => Promise<D1ConsoleBillingMonthlyFinalizationResult>;

type RuntimeSnapshotOutboxRunner = (
  options: D1ConsoleRuntimeSnapshotOutboxDispatchOptions,
) => Promise<D1ConsoleRuntimeSnapshotOutboxDispatchResult>;

type WebhookRetryDispatchRunner = (
  options: D1ConsoleWebhookRetryDispatchOptions,
) => Promise<D1ConsoleWebhookRetryDispatchResult>;

type ConsoleEmailDispatchRunner = (
  options: D1ConsoleEmailDispatcherOptions,
) => Promise<ConsoleEmailDispatchResult>;

export type CloudflareConsoleEmailRuntimeProfile = 'DEVELOPMENT' | 'PRODUCTION';

export interface CloudflareConsoleEmailDispatchCronOptions {
  readonly runtimeProfile: CloudflareConsoleEmailRuntimeProfile;
  readonly database: D1DatabaseLike;
  readonly provider: ConsoleEmailProvider;
  readonly invitationSecretCipher?: ConsoleInvitationSecretCipher;
  readonly namespace: string;
  readonly cronExpressions?: string[];
  readonly ensureSchema?: boolean;
  readonly runner?: ConsoleEmailDispatchRunner;
  readonly now?: () => Date;
}

export interface ResolveCloudflareConsoleEmailDispatchCronOptionsInput {
  readonly env: RouterApiCloudflareConsoleWorkerEnv;
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
  readonly invitationDelivery: { readonly kind: 'ENABLED' } | { readonly kind: 'DISABLED' };
}

export interface CloudflareBillingMonthlyFinalizationCronOptions {
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
  /**
   * Optional console transactional-email dispatch job.
   */
  consoleEmailDispatch?: CloudflareConsoleEmailDispatchCronOptions;
}

export function resolveCloudflareConsoleEmailDispatchCronOptions(
  input: ResolveCloudflareConsoleEmailDispatchCronOptionsInput,
): CloudflareConsoleEmailDispatchCronOptions {
  const runtimeProfile = parseConsoleEmailRuntimeProfile(
    requireConsoleEmailEnv(
      input.env.CONSOLE_EMAIL_RUNTIME_PROFILE,
      'CONSOLE_EMAIL_RUNTIME_PROFILE',
    ),
  );
  const provider = resolveConsoleEmailProvider(input.env, runtimeProfile);
  const invitationSecretCipher = resolveOptionalConsoleEmailInvitationSecretCipher(input);
  return {
    runtimeProfile,
    database: input.database,
    provider,
    ...(invitationSecretCipher ? { invitationSecretCipher } : {}),
    namespace: requireConsoleEmailEnv(input.namespace, 'console email namespace'),
    cronExpressions: parseConsoleEmailCommaList(input.env.CONSOLE_EMAIL_CRON_EXPRESSIONS),
    ensureSchema: input.ensureSchema,
    now: input.now,
  };
}

function resolveOptionalConsoleEmailInvitationSecretCipher(
  input: ResolveCloudflareConsoleEmailDispatchCronOptionsInput,
): ConsoleInvitationSecretCipher | null {
  switch (input.invitationDelivery.kind) {
    case 'ENABLED':
      return resolveConsoleEmailInvitationSecretCipher(input.env);
    case 'DISABLED':
      return null;
    default:
      return assertNeverConsoleInvitationDelivery(input.invitationDelivery);
  }
}

function resolveConsoleEmailInvitationSecretCipher(
  env: RouterApiCloudflareConsoleWorkerEnv,
): ConsoleInvitationSecretCipher {
  const keyId = requireConsoleEmailEnv(
    env.CONSOLE_EMAIL_INVITATION_SECRET_KEY_ID,
    'CONSOLE_EMAIL_INVITATION_SECRET_KEY_ID',
  );
  const keyBytes = decodeConsoleEmailInvitationSecretKey(
    requireConsoleEmailEnv(
      env.CONSOLE_EMAIL_INVITATION_SECRET_KEY_B64U,
      'CONSOLE_EMAIL_INVITATION_SECRET_KEY_B64U',
    ),
  );
  try {
    return createAesGcmConsoleInvitationSecretCipher({ keyId, keyBytes });
  } finally {
    keyBytes.fill(0);
  }
}

function resolveConsoleEmailProvider(
  env: RouterApiCloudflareConsoleWorkerEnv,
  runtimeProfile: CloudflareConsoleEmailRuntimeProfile,
): ConsoleEmailProvider {
  const providerKind = requireConsoleEmailEnv(
    env.CONSOLE_EMAIL_PROVIDER,
    'CONSOLE_EMAIL_PROVIDER',
  ).toUpperCase();
  switch (runtimeProfile) {
    case 'DEVELOPMENT':
      if (providerKind !== 'CAPTURE') {
        throw new Error('Development console email requires CONSOLE_EMAIL_PROVIDER=CAPTURE');
      }
      return createCaptureConsoleEmailProvider();
    case 'PRODUCTION':
      if (providerKind !== 'RESEND') {
        throw new Error('Production console email requires CONSOLE_EMAIL_PROVIDER=RESEND');
      }
      return createResendConsoleEmailProvider({
        apiKey: requireConsoleEmailEnv(env.RESEND_API_KEY, 'RESEND_API_KEY'),
        from: requireConsoleEmailEnv(env.CONSOLE_EMAIL_FROM, 'CONSOLE_EMAIL_FROM'),
        replyTo: optionalConsoleEmailEnv(env.CONSOLE_EMAIL_REPLY_TO) || undefined,
      });
    default:
      return assertNeverConsoleEmailRuntimeProfile(runtimeProfile);
  }
}

function parseConsoleEmailRuntimeProfile(value: string): CloudflareConsoleEmailRuntimeProfile {
  switch (value.trim().toUpperCase()) {
    case 'DEVELOPMENT':
      return 'DEVELOPMENT';
    case 'PRODUCTION':
      return 'PRODUCTION';
    default:
      throw new Error('CONSOLE_EMAIL_RUNTIME_PROFILE must be DEVELOPMENT or PRODUCTION');
  }
}

function decodeConsoleEmailInvitationSecretKey(value: string): Uint8Array {
  let decoded: Uint8Array;
  try {
    decoded = base64UrlDecode(value);
  } catch {
    throw new Error('CONSOLE_EMAIL_INVITATION_SECRET_KEY_B64U must be valid base64url');
  }
  if (decoded.byteLength !== 32) {
    decoded.fill(0);
    throw new Error('CONSOLE_EMAIL_INVITATION_SECRET_KEY_B64U must decode to 32 bytes');
  }
  return decoded;
}

function parseConsoleEmailCommaList(value: string | undefined): string[] {
  const normalized = optionalConsoleEmailEnv(value);
  if (!normalized) return [];
  const items: string[] = [];
  const seen = new Set<string>();
  for (const item of normalized.split(',')) {
    const entry = item.trim();
    if (!entry || seen.has(entry)) continue;
    seen.add(entry);
    items.push(entry);
  }
  return items;
}

function requireConsoleEmailEnv(value: string | undefined, field: string): string {
  const normalized = optionalConsoleEmailEnv(value);
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
}

function optionalConsoleEmailEnv(value: string | undefined): string {
  return typeof value === 'string' ? value.trim() : '';
}

function assertNeverConsoleEmailRuntimeProfile(value: never): never {
  throw new Error(`Unhandled console email runtime profile: ${String(value)}`);
}

function assertNeverConsoleInvitationDelivery(value: never): never {
  throw new Error(`Unhandled console invitation delivery state: ${String(value)}`);
}

function normalizeCronExpressions(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  return Array.from(new Set(input.map((value) => String(value || '').trim()).filter(Boolean)));
}

function shouldRunForCronTick(cronExpressions: string[], eventCron: string | undefined): boolean {
  if (cronExpressions.length === 0) return true;
  const tick = String(eventCron || '').trim();
  if (!tick) return false;
  return cronExpressions.includes(tick);
}

function validateConsoleEmailDispatchCronOptions(
  options: CloudflareConsoleEmailDispatchCronOptions,
): void {
  if (options.runtimeProfile === 'DEVELOPMENT' && options.provider.provider !== 'capture') {
    throw new Error('Development console email cron requires the capture provider');
  }
  if (options.runtimeProfile === 'PRODUCTION' && options.provider.provider !== 'resend') {
    throw new Error('Production console email cron requires the Resend provider');
  }
}

export function createCloudflareCron(opts: CloudflareCronOptions = {}): ScheduledHandler {
  const verbose = Boolean(opts.verbose);
  const logger = coerceRouterLogger(opts.logger);
  const billingFinalization = opts.billingMonthlyFinalization;
  const billingFinalizationEnabled = Boolean(billingFinalization);
  const billingFinalizationOrgIds = Array.from(
    new Set(
      (billingFinalization && Array.isArray(billingFinalization.orgIds)
        ? billingFinalization.orgIds
        : []
      )
        .map((orgId) => String(orgId || '').trim())
        .filter(Boolean),
    ),
  );
  const billingFinalizationCronExpressions = normalizeCronExpressions(
    billingFinalization?.cronExpressions,
  );
  const runtimeSnapshotOutbox = opts.runtimeSnapshotOutbox;
  const runtimeSnapshotOutboxEnabled = Boolean(runtimeSnapshotOutbox);
  const runtimeSnapshotOutboxOrgIds = Array.from(
    new Set(
      (runtimeSnapshotOutbox && Array.isArray(runtimeSnapshotOutbox.orgIds)
        ? runtimeSnapshotOutbox.orgIds
        : []
      )
        .map((orgId) => String(orgId || '').trim())
        .filter(Boolean),
    ),
  );
  const runtimeSnapshotOutboxCronExpressions = normalizeCronExpressions(
    runtimeSnapshotOutbox?.cronExpressions,
  );
  const webhookRetryDispatch = opts.webhookRetryDispatch;
  const webhookRetryDispatchEnabled = Boolean(webhookRetryDispatch);
  const webhookRetryDispatchOrgIds = Array.from(
    new Set(
      (webhookRetryDispatch && Array.isArray(webhookRetryDispatch.orgIds)
        ? webhookRetryDispatch.orgIds
        : []
      )
        .map((orgId) => String(orgId || '').trim())
        .filter(Boolean),
    ),
  );
  const webhookRetryDispatchCronExpressions = normalizeCronExpressions(
    webhookRetryDispatch?.cronExpressions,
  );
  const consoleEmailDispatch = opts.consoleEmailDispatch;
  const consoleEmailDispatchEnabled = Boolean(consoleEmailDispatch);
  if (consoleEmailDispatch) {
    validateConsoleEmailDispatchCronOptions(consoleEmailDispatch);
  }
  const consoleEmailDispatchCronExpressions = normalizeCronExpressions(
    consoleEmailDispatch?.cronExpressions,
  );
  return async (event) => {
    if (verbose) {
      logger.info('[cron] tick', {
        scheduledTime: typeof event?.scheduledTime === 'number' ? event.scheduledTime : undefined,
        cron: typeof event?.cron === 'string' ? event.cron : undefined,
        billingMonthlyFinalization: billingFinalizationEnabled,
        runtimeSnapshotOutbox: runtimeSnapshotOutboxEnabled,
        webhookRetryDispatch: webhookRetryDispatchEnabled,
        consoleEmailDispatch: consoleEmailDispatchEnabled,
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
      } else if (
        !runtimeSnapshotOutbox?.runner &&
        typeof runtimeSnapshotOutbox?.dispatch !== 'function'
      ) {
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
        logger.warn('[cron][webhook-retry-dispatch] skipped: missing D1 database or secret cipher');
      } else {
        const runner = webhookRetryDispatch?.runner || runD1ConsoleWebhookRetryDispatch;
        const result = await runner({
          categoryValidation: WALLET_CONSOLE_WEBHOOK_EVENT_CATEGORY_VALIDATION,
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

    if (consoleEmailDispatchEnabled && consoleEmailDispatch) {
      const eventCron = typeof event?.cron === 'string' ? event.cron : undefined;
      const consoleEmailCronMatches = shouldRunForCronTick(
        consoleEmailDispatchCronExpressions,
        eventCron,
      );
      if (!consoleEmailCronMatches) {
        if (verbose) {
          logger.info('[cron][console-email] skipped: cron expression mismatch', {
            eventCron,
            cronExpressions: consoleEmailDispatchCronExpressions,
          });
        }
      } else {
        const runner = consoleEmailDispatch.runner || runD1ConsoleEmailDispatcher;
        const result = await runner({
          database: consoleEmailDispatch.database,
          provider: consoleEmailDispatch.provider,
          invitationSecretCipher: consoleEmailDispatch.invitationSecretCipher,
          namespace: consoleEmailDispatch.namespace,
          ensureSchema: consoleEmailDispatch.ensureSchema,
          now: consoleEmailDispatch.now,
        });
        logger.info('[cron][console-email] completed', {
          claimedCount: result.claimedCount,
          sentCount: result.sentCount,
          retryScheduledCount: result.retryScheduledCount,
          finalFailureCount: result.finalFailureCount,
          canceledCount: result.canceledCount,
          failureCount: result.failures.length,
        });
        if (result.failures.length > 0) {
          logger.warn('[cron][console-email] failures', {
            failures: result.failures,
          });
        }
      }
    }
  };
}
