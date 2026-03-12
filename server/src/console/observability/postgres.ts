import { getPostgresPool } from '../../storage/postgres';
import { ensureConsoleNamespace as ensureNamespace } from '../shared/postgresNormalize';
import { withConsoleTenantContextTx } from '../shared/postgresTenantContext';
import { ConsoleObservabilityError } from './errors';
import {
  pruneConsoleObservabilityRetentionForTenant,
  type PostgresConsoleObservabilityRetentionCleanupResult,
} from './retention';
import {
  ensureConsoleObservabilityPostgresSchema,
  type PostgresConsoleObservabilitySchemaOptions,
} from './schema';
import type { InMemoryConsoleObservabilityServiceOptions } from './service';

const DEFAULT_RETENTION_TTL_MS = 1000 * 60 * 60 * 24 * 30;
const DEFAULT_RETENTION_BATCH_SIZE = 1_000;

export interface PostgresConsoleObservabilityRetentionCleanupOptions
  extends PostgresConsoleObservabilitySchemaOptions,
    Pick<InMemoryConsoleObservabilityServiceOptions, 'now'> {
  namespace?: string;
  orgId: string;
  ensureSchema?: boolean;
  ttlMs?: number;
  batchSize?: number;
}

function normalizeString(raw: unknown): string {
  return String(raw || '').trim();
}

function nowMs(now: Date): number {
  return now.getTime();
}

function ensureRequiredString(field: string, raw: unknown): string {
  const value = normalizeString(raw);
  if (!value) {
    throw new ConsoleObservabilityError('invalid_body', 400, `Field ${field} is required`);
  }
  return value;
}

function normalizePositiveInteger(raw: unknown, fallback: number): number {
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) return fallback;
  return Math.floor(value);
}

export async function runPostgresConsoleObservabilityRetentionCleanup(
  options: PostgresConsoleObservabilityRetentionCleanupOptions,
): Promise<PostgresConsoleObservabilityRetentionCleanupResult> {
  const postgresUrl = normalizeString(options.postgresUrl);
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres console observability retention cleanup');
  }
  const namespace = ensureNamespace(options.namespace);
  const orgId = ensureRequiredString('orgId', options.orgId);
  const now = options.now || (() => new Date());
  const ttlMs = normalizePositiveInteger(options.ttlMs, DEFAULT_RETENTION_TTL_MS);
  const batchSize = normalizePositiveInteger(options.batchSize, DEFAULT_RETENTION_BATCH_SIZE);

  if (options.ensureSchema !== false) {
    await ensureConsoleObservabilityPostgresSchema({
      postgresUrl,
      logger: options.logger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);
  return withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) => {
    const cutoffMs = Math.max(0, nowMs(now()) - ttlMs);
    return pruneConsoleObservabilityRetentionForTenant(q, {
      namespace,
      orgId,
      cutoffMs,
      batchSize,
    });
  });
}
