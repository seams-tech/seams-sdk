export type ConsoleBackendKind = 'postgres' | 'memory';

const DEFAULT_OBSERVABILITY_QUERY_MAX_WINDOW_MS = 1000 * 60 * 60 * 24 * 7;
const DEFAULT_OBSERVABILITY_INGEST_MAX_BATCH_SIZE = 200;
const DEFAULT_OBSERVABILITY_INGEST_MAX_EVENTS_PER_MINUTE = 10_000;
const DEFAULT_OBSERVABILITY_RETENTION_TTL_MS = 1000 * 60 * 60 * 24 * 30;
const DEFAULT_OBSERVABILITY_RETENTION_PRUNE_INTERVAL_MS = 1000 * 60 * 5;
const DEFAULT_OBSERVABILITY_RETENTION_BATCH_SIZE = 1_000;
const DEFAULT_RUNTIME_SNAPSHOT_RETENTION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const DEFAULT_RUNTIME_SNAPSHOT_RETENTION_PRUNE_INTERVAL_MS = 1000 * 60 * 5;
const DEFAULT_RUNTIME_SNAPSHOT_RETENTION_BATCH_SIZE = 1_000;

export interface RelayServerConsoleConfig {
  thresholdPostgresUrl: string;
  signerMigrationPostgresUrl: string;
  consolePostgresUrl: string;
  consoleMigrationPostgresUrl: string;
  consoleBillingBackend: ConsoleBackendKind;
  consoleBillingEnsureSchema: boolean;
  consoleBillingNamespace: string;
  consoleWebhooksBackend: ConsoleBackendKind;
  consoleWebhooksEnsureSchema: boolean;
  consoleWebhooksNamespace: string;
  consoleObservabilityBackend: ConsoleBackendKind;
  consoleObservabilityEnsureSchema: boolean;
  consoleObservabilityNamespace: string;
  consoleObservabilityQueryMaxWindowMs: number;
  consoleObservabilityIngestMaxBatchSize: number;
  consoleObservabilityIngestMaxEventsPerMinute: number;
  consoleObservabilityRetentionTtlMs: number;
  consoleObservabilityRetentionPruneIntervalMs: number;
  consoleObservabilityRetentionBatchSize: number;
  consoleRuntimeSnapshotRetentionTtlMs: number;
  consoleRuntimeSnapshotRetentionPruneIntervalMs: number;
  consoleRuntimeSnapshotRetentionBatchSize: number;
  consoleBillingStripeWebhookSecret: string;
}

function normalizeString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function parseConsoleBackendKind(
  value: unknown,
  fallback: ConsoleBackendKind,
  envKey: string,
): ConsoleBackendKind {
  const raw = normalizeString(value).toLowerCase() || fallback;
  if (raw !== 'postgres' && raw !== 'memory') {
    throw new Error(`Invalid ${envKey}="${raw}". Expected "postgres" or "memory".`);
  }
  return raw;
}

function parseBooleanEnv(value: unknown, fallback: boolean, envKey: string): boolean {
  const raw = normalizeString(value).toLowerCase();
  if (!raw) return fallback;
  if (raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on') return true;
  if (raw === '0' || raw === 'false' || raw === 'no' || raw === 'off') return false;
  throw new Error(
    `Invalid ${envKey}="${raw}". Expected one of: 1,true,yes,on,0,false,no,off.`,
  );
}

function parsePositiveIntegerEnv(value: unknown, fallback: number, envKey: string): number {
  const raw = normalizeString(value);
  if (!raw) return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`Invalid ${envKey}="${raw}". Expected a positive integer.`);
  }
  return Math.floor(parsed);
}

export function resolveRelayServerConsoleConfig(env: Record<string, unknown>): RelayServerConsoleConfig {
  const thresholdPostgresUrl = normalizeString(env.POSTGRES_URL);
  const signerMigrationPostgresUrl =
    normalizeString(env.POSTGRES_MIGRATION_URL) || thresholdPostgresUrl;
  const consolePostgresUrl = normalizeString(env.CONSOLE_POSTGRES_URL);
  const consoleMigrationPostgresUrl =
    normalizeString(env.CONSOLE_POSTGRES_MIGRATION_URL) || consolePostgresUrl;
  const consoleDefaultBackend: ConsoleBackendKind = consolePostgresUrl ? 'postgres' : 'memory';

  return {
    thresholdPostgresUrl,
    signerMigrationPostgresUrl,
    consolePostgresUrl,
    consoleMigrationPostgresUrl,
    consoleBillingBackend: parseConsoleBackendKind(
      env.CONSOLE_BILLING_BACKEND,
      consoleDefaultBackend,
      'CONSOLE_BILLING_BACKEND',
    ),
    consoleBillingEnsureSchema: parseBooleanEnv(
      env.CONSOLE_BILLING_ENSURE_SCHEMA,
      true,
      'CONSOLE_BILLING_ENSURE_SCHEMA',
    ),
    consoleBillingNamespace: normalizeString(env.CONSOLE_BILLING_NAMESPACE) || 'relay-console',
    consoleWebhooksBackend: parseConsoleBackendKind(
      env.CONSOLE_WEBHOOKS_BACKEND,
      consoleDefaultBackend,
      'CONSOLE_WEBHOOKS_BACKEND',
    ),
    consoleWebhooksEnsureSchema: parseBooleanEnv(
      env.CONSOLE_WEBHOOKS_ENSURE_SCHEMA,
      true,
      'CONSOLE_WEBHOOKS_ENSURE_SCHEMA',
    ),
    consoleWebhooksNamespace: normalizeString(env.CONSOLE_WEBHOOKS_NAMESPACE) || 'relay-console',
    consoleObservabilityBackend: parseConsoleBackendKind(
      env.CONSOLE_OBSERVABILITY_BACKEND,
      consoleDefaultBackend,
      'CONSOLE_OBSERVABILITY_BACKEND',
    ),
    consoleObservabilityEnsureSchema: parseBooleanEnv(
      env.CONSOLE_OBSERVABILITY_ENSURE_SCHEMA,
      true,
      'CONSOLE_OBSERVABILITY_ENSURE_SCHEMA',
    ),
    consoleObservabilityNamespace:
      normalizeString(env.CONSOLE_OBSERVABILITY_NAMESPACE) || 'relay-console',
    consoleObservabilityQueryMaxWindowMs: parsePositiveIntegerEnv(
      env.CONSOLE_OBSERVABILITY_QUERY_MAX_WINDOW_MS,
      DEFAULT_OBSERVABILITY_QUERY_MAX_WINDOW_MS,
      'CONSOLE_OBSERVABILITY_QUERY_MAX_WINDOW_MS',
    ),
    consoleObservabilityIngestMaxBatchSize: parsePositiveIntegerEnv(
      env.CONSOLE_OBSERVABILITY_INGEST_MAX_BATCH_SIZE,
      DEFAULT_OBSERVABILITY_INGEST_MAX_BATCH_SIZE,
      'CONSOLE_OBSERVABILITY_INGEST_MAX_BATCH_SIZE',
    ),
    consoleObservabilityIngestMaxEventsPerMinute: parsePositiveIntegerEnv(
      env.CONSOLE_OBSERVABILITY_INGEST_MAX_EVENTS_PER_MINUTE,
      DEFAULT_OBSERVABILITY_INGEST_MAX_EVENTS_PER_MINUTE,
      'CONSOLE_OBSERVABILITY_INGEST_MAX_EVENTS_PER_MINUTE',
    ),
    consoleObservabilityRetentionTtlMs: parsePositiveIntegerEnv(
      env.CONSOLE_OBSERVABILITY_RETENTION_TTL_MS,
      DEFAULT_OBSERVABILITY_RETENTION_TTL_MS,
      'CONSOLE_OBSERVABILITY_RETENTION_TTL_MS',
    ),
    consoleObservabilityRetentionPruneIntervalMs: parsePositiveIntegerEnv(
      env.CONSOLE_OBSERVABILITY_RETENTION_PRUNE_INTERVAL_MS,
      DEFAULT_OBSERVABILITY_RETENTION_PRUNE_INTERVAL_MS,
      'CONSOLE_OBSERVABILITY_RETENTION_PRUNE_INTERVAL_MS',
    ),
    consoleObservabilityRetentionBatchSize: parsePositiveIntegerEnv(
      env.CONSOLE_OBSERVABILITY_RETENTION_BATCH_SIZE,
      DEFAULT_OBSERVABILITY_RETENTION_BATCH_SIZE,
      'CONSOLE_OBSERVABILITY_RETENTION_BATCH_SIZE',
    ),
    consoleRuntimeSnapshotRetentionTtlMs: parsePositiveIntegerEnv(
      env.CONSOLE_RUNTIME_SNAPSHOT_RETENTION_TTL_MS,
      DEFAULT_RUNTIME_SNAPSHOT_RETENTION_TTL_MS,
      'CONSOLE_RUNTIME_SNAPSHOT_RETENTION_TTL_MS',
    ),
    consoleRuntimeSnapshotRetentionPruneIntervalMs: parsePositiveIntegerEnv(
      env.CONSOLE_RUNTIME_SNAPSHOT_RETENTION_PRUNE_INTERVAL_MS,
      DEFAULT_RUNTIME_SNAPSHOT_RETENTION_PRUNE_INTERVAL_MS,
      'CONSOLE_RUNTIME_SNAPSHOT_RETENTION_PRUNE_INTERVAL_MS',
    ),
    consoleRuntimeSnapshotRetentionBatchSize: parsePositiveIntegerEnv(
      env.CONSOLE_RUNTIME_SNAPSHOT_RETENTION_BATCH_SIZE,
      DEFAULT_RUNTIME_SNAPSHOT_RETENTION_BATCH_SIZE,
      'CONSOLE_RUNTIME_SNAPSHOT_RETENTION_BATCH_SIZE',
    ),
    consoleBillingStripeWebhookSecret: normalizeString(env.CONSOLE_BILLING_STRIPE_WEBHOOK_SECRET),
  };
}

export function toOptionalSecret(secret: string): string | undefined {
  return normalizeString(secret) || undefined;
}
