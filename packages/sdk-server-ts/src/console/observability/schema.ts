import type { NormalizedLogger } from '../../core/logger';
import { getPostgresPool } from '../../storage/postgres';
import { ensureConsoleTenantRlsPolicies } from '../shared/postgresTenantContext';
import { CONSOLE_OBSERVABILITY_SOURCES_SQL } from './policy';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;

interface Queryable {
  query: (text: string, values?: unknown[]) => Promise<{ rows: Record<string, unknown>[]; rowCount?: number }>;
}

const CONSOLE_OBSERVABILITY_MIGRATION_LOCK_ID = 9452360124981;
const PRECREATE_PARTITION_MONTHS_BEHIND = 1;
const PRECREATE_PARTITION_MONTHS_AHEAD = 2;
const LEGACY_ROUTER_REQUEST_COMPLETED_EVENT_TYPE = 'router.request.completed';
const LEGACY_ROUTER_SOURCE = 'ROUTER';

export interface PostgresConsoleObservabilitySchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export function monthStartUtcMs(inputMs: number): number {
  const d = new Date(inputMs);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1, 0, 0, 0, 0);
}

function addUtcMonths(monthStartMs: number, deltaMonths: number): number {
  const d = new Date(monthStartMs);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + deltaMonths, 1, 0, 0, 0, 0);
}

function buildEventsPartitionTableName(monthStartMsValue: number): string {
  const d = new Date(monthStartMsValue);
  const year = d.getUTCFullYear();
  const month = String(d.getUTCMonth() + 1).padStart(2, '0');
  return `console_observability_events_p_${year}${month}`;
}

export async function ensureConsoleObservabilityEventsPartition(
  q: Queryable,
  monthStartMsValue: number,
): Promise<void> {
  const rangeStartMs = monthStartUtcMs(monthStartMsValue);
  const rangeEndMs = addUtcMonths(rangeStartMs, 1);
  const tableName = buildEventsPartitionTableName(rangeStartMs);
  await q.query(`
    CREATE TABLE IF NOT EXISTS ${tableName}
    PARTITION OF console_observability_events
    FOR VALUES FROM (${rangeStartMs}) TO (${rangeEndMs})
  `);
}

async function ensureConsoleObservabilityEventsPartitionsForRange(
  q: Queryable,
  rangeStartMs: number,
  rangeEndMs: number,
): Promise<void> {
  let monthStartMsValue = monthStartUtcMs(rangeStartMs);
  const endMonthStartMsValue = monthStartUtcMs(rangeEndMs);
  while (monthStartMsValue <= endMonthStartMsValue) {
    await ensureConsoleObservabilityEventsPartition(q, monthStartMsValue);
    monthStartMsValue = addUtcMonths(monthStartMsValue, 1);
  }
}

async function prepareLegacyEventsTableForMigration(q: Queryable): Promise<void> {
  await q.query(`
    DO $$
    BEGIN
      IF to_regclass('console_observability_events') IS NULL THEN
        RETURN;
      END IF;

      IF EXISTS (
        SELECT 1
          FROM pg_class
         WHERE oid = to_regclass('console_observability_events')
           AND relkind = 'r'
      ) THEN
        IF to_regclass('console_observability_events_legacy') IS NULL THEN
          ALTER TABLE console_observability_events RENAME TO console_observability_events_legacy;
        ELSE
          INSERT INTO console_observability_events_legacy
          SELECT *
            FROM console_observability_events
          ON CONFLICT (namespace, org_id, event_id) DO NOTHING;
          DROP TABLE console_observability_events;
        END IF;
      END IF;
    END $$;
  `);
}

async function migrateLegacyRowsIntoPartitionedEvents(
  q: Queryable,
  logger: NormalizedLogger,
): Promise<void> {
  const legacyExistsResult = await q.query(
    `SELECT to_regclass('console_observability_events_legacy') IS NOT NULL AS exists`,
  );
  const legacyExists = Boolean(legacyExistsResult.rows?.[0]?.exists);
  if (!legacyExists) return;

  const minMax = await q.query(`
    SELECT MIN(created_at_ms) AS min_created_at_ms, MAX(created_at_ms) AS max_created_at_ms
      FROM console_observability_events_legacy
  `);
  const minCreatedAtMs = Number(minMax.rows?.[0]?.min_created_at_ms || 0);
  const maxCreatedAtMs = Number(minMax.rows?.[0]?.max_created_at_ms || 0);
  if (Number.isFinite(minCreatedAtMs) && Number.isFinite(maxCreatedAtMs) && maxCreatedAtMs > 0) {
    await ensureConsoleObservabilityEventsPartitionsForRange(q, minCreatedAtMs, maxCreatedAtMs);
  }

  const dedupeCopy = await q.query(
    `INSERT INTO console_observability_event_dedup (namespace, org_id, event_id, created_at_ms)
     SELECT namespace, org_id, event_id, created_at_ms
       FROM console_observability_events_legacy
      WHERE COALESCE(event_type, '') <> $1
        AND COALESCE(source, '') <> $2
     ON CONFLICT (namespace, org_id, event_id) DO NOTHING`,
    [LEGACY_ROUTER_REQUEST_COMPLETED_EVENT_TYPE, LEGACY_ROUTER_SOURCE],
  );
  const eventsCopy = await q.query(
    `INSERT INTO console_observability_events
      (namespace, org_id, event_id, schema_version, source, ingested_at_ms, timestamp_ms,
       project_id, environment_id, service, component, level, event_type, message,
       request_id, trace_id, metadata, redaction_version, redaction_applied, created_at_ms)
     SELECT namespace, org_id, event_id, schema_version, source, ingested_at_ms, timestamp_ms,
            project_id, environment_id, service, component, level, event_type, message,
            request_id, trace_id, metadata, redaction_version, redaction_applied, created_at_ms
       FROM console_observability_events_legacy
      WHERE COALESCE(event_type, '') <> $1
        AND COALESCE(source, '') <> $2
     ON CONFLICT (namespace, org_id, created_at_ms, event_id) DO NOTHING`,
    [LEGACY_ROUTER_REQUEST_COMPLETED_EVENT_TYPE, LEGACY_ROUTER_SOURCE],
  );

  await q.query('DROP TABLE IF EXISTS console_observability_events_legacy');
  logger.info(
    `[console-observability][postgres] migrated legacy events table rows: dedupe=${Number(
      dedupeCopy.rowCount || 0,
    )} events=${Number(eventsCopy.rowCount || 0)}`,
  );
}

async function deleteLegacyRouterObservabilityEvents(q: Queryable): Promise<number> {
  const out = await q.query(
    `DELETE FROM console_observability_events
      WHERE event_type = $1
         OR source = $2`,
    [LEGACY_ROUTER_REQUEST_COMPLETED_EVENT_TYPE, LEGACY_ROUTER_SOURCE],
  );
  return Number(out.rowCount || 0);
}

async function ensureObservabilityEventsSourceConstraint(q: Queryable): Promise<void> {
  await q.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'console_observability_events'::regclass
           AND conname = 'console_observability_events_source_check'
      ) THEN
        ALTER TABLE console_observability_events
          DROP CONSTRAINT console_observability_events_source_check;
      END IF;
      ALTER TABLE console_observability_events
        ADD CONSTRAINT console_observability_events_source_check
        CHECK (source IN (${CONSOLE_OBSERVABILITY_SOURCES_SQL}));
    END $$;
  `);
}

export async function ensureConsoleObservabilityPostgresSchema(
  options: PostgresConsoleObservabilitySchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_OBSERVABILITY_MIGRATION_LOCK_ID]);
  try {
    await prepareLegacyEventsTableForMigration(pool);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_observability_events (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        schema_version INTEGER NOT NULL,
        source TEXT NOT NULL,
        ingested_at_ms BIGINT NOT NULL,
        timestamp_ms BIGINT NOT NULL,
        project_id TEXT,
        environment_id TEXT,
        service TEXT NOT NULL,
        component TEXT NOT NULL,
        level TEXT NOT NULL,
        event_type TEXT NOT NULL,
        message TEXT NOT NULL,
        request_id TEXT,
        trace_id TEXT,
        metadata JSONB NOT NULL,
        redaction_version INTEGER NOT NULL,
        redaction_applied BOOLEAN NOT NULL,
        created_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id, created_at_ms, event_id),
        CHECK (schema_version >= 1),
        CHECK (source IN (${CONSOLE_OBSERVABILITY_SOURCES_SQL})),
        CHECK (level IN ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')),
        CHECK (jsonb_typeof(metadata) = 'object'),
        CHECK (redaction_version >= 1)
      )
      PARTITION BY RANGE (created_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_observability_event_dedup (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id, event_id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_observability_ingest_windows (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        window_start_ms BIGINT NOT NULL,
        accepted_count INTEGER NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id, window_start_ms),
        CHECK (accepted_count >= 0)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_observability_request_rollups_minute (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        window_start_ms BIGINT NOT NULL,
        project_id TEXT NOT NULL DEFAULT '',
        environment_id TEXT NOT NULL DEFAULT '',
        service TEXT NOT NULL,
        route_family TEXT NOT NULL,
        method TEXT NOT NULL,
        status_class TEXT NOT NULL,
        request_count INTEGER NOT NULL,
        error_count INTEGER NOT NULL,
        latency_sum_ms DOUBLE PRECISION NOT NULL,
        latency_max_ms DOUBLE PRECISION NOT NULL,
        latency_bucket_le_50 INTEGER NOT NULL,
        latency_bucket_le_100 INTEGER NOT NULL,
        latency_bucket_le_250 INTEGER NOT NULL,
        latency_bucket_le_500 INTEGER NOT NULL,
        latency_bucket_le_1000 INTEGER NOT NULL,
        latency_bucket_le_2000 INTEGER NOT NULL,
        latency_bucket_le_5000 INTEGER NOT NULL,
        PRIMARY KEY (
          namespace,
          org_id,
          window_start_ms,
          project_id,
          environment_id,
          service,
          route_family,
          method,
          status_class
        ),
        CHECK (request_count >= 0),
        CHECK (error_count >= 0),
        CHECK (latency_sum_ms >= 0),
        CHECK (latency_max_ms >= 0),
        CHECK (error_count <= request_count)
      )
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_observability_events_org_created_idx_v2
      ON console_observability_events (namespace, org_id, created_at_ms DESC, event_id DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_observability_events_org_service_created_idx_v2
      ON console_observability_events (namespace, org_id, service, created_at_ms DESC, event_id DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_observability_events_org_level_created_idx_v2
      ON console_observability_events (namespace, org_id, level, created_at_ms DESC, event_id DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_observability_events_org_timestamp_idx_v2
      ON console_observability_events (namespace, org_id, timestamp_ms DESC, event_id DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_observability_event_dedup_created_idx_v2
      ON console_observability_event_dedup (namespace, org_id, created_at_ms)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_observability_ingest_windows_window_idx_v2
      ON console_observability_ingest_windows (namespace, org_id, window_start_ms)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_observability_request_rollups_org_window_idx_v1
      ON console_observability_request_rollups_minute (namespace, org_id, window_start_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_observability_request_rollups_org_service_window_idx_v1
      ON console_observability_request_rollups_minute (namespace, org_id, service, window_start_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_observability_request_rollups_org_route_window_idx_v1
      ON console_observability_request_rollups_minute (namespace, org_id, route_family, window_start_ms DESC)
    `);

    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_observability_events',
      policyName: 'console_observability_events_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_observability_event_dedup',
      policyName: 'console_observability_event_dedup_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_observability_ingest_windows',
      policyName: 'console_observability_ingest_windows_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_observability_request_rollups_minute',
      policyName: 'console_observability_request_rollups_minute_tenant_rls',
    });

    const nowValue = Date.now();
    await ensureConsoleObservabilityEventsPartitionsForRange(
      pool,
      addUtcMonths(monthStartUtcMs(nowValue), -PRECREATE_PARTITION_MONTHS_BEHIND),
      addUtcMonths(monthStartUtcMs(nowValue), PRECREATE_PARTITION_MONTHS_AHEAD),
    );
    await migrateLegacyRowsIntoPartitionedEvents(pool, options.logger);
    const deletedLegacyRouterRows = await deleteLegacyRouterObservabilityEvents(pool);
    await ensureObservabilityEventsSourceConstraint(pool);
    if (deletedLegacyRouterRows > 0) {
      options.logger.info(
        `[console-observability][postgres] removed ${deletedLegacyRouterRows} legacy router.request.completed rows`,
      );
    }
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_OBSERVABILITY_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }

  options.logger.info('[console-observability][postgres] Schema ready');
}
