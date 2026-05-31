import { secureRandomBase36 } from '@shared/utils/secureRandomId';
import type { NormalizedLogger } from '../../core/logger';
import { getPostgresPool } from '../../storage/postgres';
import {
  ensureConsoleNamespace as ensureNamespace,
  toConsoleIso as toIso,
  toConsoleNumber as toNumber,
} from '../shared/postgresNormalize';
import {
  ensureConsoleTenantRlsPolicies,
  withConsoleTenantContextTx,
} from '../shared/postgresTenantContext';
import type {
  ConsoleRuntimeSnapshot,
  ConsoleRuntimeSnapshotPayload,
  GetLatestConsoleRuntimeSnapshotRequest,
  ListConsoleRuntimeSnapshotsRequest,
  PublishConsoleRuntimeSnapshotRequest,
} from './types';
import {
  computeConsoleRuntimeSnapshotChecksum,
  type ConsoleRuntimeSnapshotContext,
  type ConsoleRuntimeSnapshotService,
} from './service';
import {
  maybeRunConsoleRuntimeSnapshotRetentionForTenant,
  pruneConsoleRuntimeSnapshotRetentionForTenant,
  type PostgresConsoleRuntimeSnapshotRetentionCleanupResult,
} from './retention';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_RUNTIME_SNAPSHOTS_MIGRATION_LOCK_ID = 9452360123599;
const DEFAULT_RETENTION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const DEFAULT_RETENTION_PRUNE_INTERVAL_MS = 1000 * 60 * 5;
const DEFAULT_RETENTION_BATCH_SIZE = 1_000;

function nowMs(now: Date): number {
  return now.getTime();
}

function normalizeProjectId(projectId: string | undefined | null): string {
  const value = String(projectId || '').trim();
  return value;
}

function toNullableProjectId(projectId: string): string | null {
  const value = String(projectId || '').trim();
  return value || null;
}

function parseJsonObject(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return raw as Record<string, unknown>;
  }
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      return {};
    }
  }
  return {};
}

function cloneObject(input: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(input || {})) as Record<string, unknown>;
}

function clonePayload(input: ConsoleRuntimeSnapshotPayload): ConsoleRuntimeSnapshotPayload {
  return {
    policy: cloneObject(input.policy),
    gasSponsorship: cloneObject(input.gasSponsorship),
    ...(input.metadata ? { metadata: cloneObject(input.metadata) } : {}),
  };
}

function parsePayload(raw: unknown): ConsoleRuntimeSnapshotPayload {
  const row = parseJsonObject(raw);
  const metadataRaw = row.metadata;
  return {
    policy: parseJsonObject(row.policy),
    gasSponsorship: parseJsonObject(row.gasSponsorship),
    ...(metadataRaw && typeof metadataRaw === 'object' && !Array.isArray(metadataRaw)
      ? { metadata: parseJsonObject(metadataRaw) }
      : {}),
  };
}

function parseSnapshotRow(row: PgRow): ConsoleRuntimeSnapshot {
  const payload = parsePayload(row.payload);
  return {
    orgId: String(row.org_id || ''),
    projectId: toNullableProjectId(String(row.project_id || '')),
    environmentId: String(row.environment_id || ''),
    snapshotId: String(row.snapshot_id || ''),
    version: Math.max(1, Math.floor(toNumber(row.version, 1))),
    effectiveAt: toIso(toNumber(row.effective_at_ms, Date.now())) || new Date().toISOString(),
    checksum: String(row.checksum || ''),
    payload: clonePayload(payload),
    createdAt: toIso(toNumber(row.created_at_ms, Date.now())) || new Date().toISOString(),
    createdBy: String(row.created_by || ''),
  };
}

export interface ConsoleRuntimeSnapshotOutboxEvent {
  namespace: string;
  orgId: string;
  projectId: string | null;
  environmentId: string;
  eventId: string;
  eventType: 'RUNTIME_SNAPSHOT_PUBLISHED_V1';
  snapshotId: string;
  snapshotVersion: number;
  payload: Record<string, unknown>;
  createdAt: string;
  dispatchedAt: string | null;
}

function parseOutboxEventRow(row: PgRow): ConsoleRuntimeSnapshotOutboxEvent {
  const createdAtMs = toNumber(row.created_at_ms, Date.now());
  const dispatchedAtMs = row.dispatched_at_ms === null ? null : toNumber(row.dispatched_at_ms, 0);
  return {
    namespace: String(row.namespace || ''),
    orgId: String(row.org_id || ''),
    projectId: toNullableProjectId(String(row.project_id || '')),
    environmentId: String(row.environment_id || ''),
    eventId: String(row.event_id || ''),
    eventType: 'RUNTIME_SNAPSHOT_PUBLISHED_V1',
    snapshotId: String(row.snapshot_id || ''),
    snapshotVersion: Math.max(1, Math.floor(toNumber(row.snapshot_version, 1))),
    payload: parseJsonObject(row.payload),
    createdAt: toIso(createdAtMs) || new Date(createdAtMs).toISOString(),
    dispatchedAt:
      dispatchedAtMs && dispatchedAtMs > 0
        ? toIso(dispatchedAtMs) || new Date(dispatchedAtMs).toISOString()
        : null,
  };
}

function makeSnapshotId(now: Date): string {
  return `runtime_snapshot_${now.getTime().toString(36)}_${secureRandomBase36(8, 'console IDs')}`;
}

function makeOutboxEventId(now: Date): string {
  return `runtime_snapshot_event_${now.getTime().toString(36)}_${secureRandomBase36(8, 'console IDs')}`;
}

function readEffectiveAtMs(input: string | undefined, fallback: Date): number {
  if (!input) return nowMs(fallback);
  const asDate = new Date(input);
  if (!Number.isFinite(asDate.getTime())) return nowMs(fallback);
  return asDate.getTime();
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

function normalizePositiveInteger(raw: unknown, fallback: number): number {
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) return fallback;
  return Math.floor(value);
}

function normalizeRequiredString(field: string, raw: unknown): string {
  const value = String(raw || '').trim();
  if (!value) {
    throw new Error(`Missing ${field} for Postgres console runtime snapshot retention cleanup`);
  }
  return value;
}

export interface PostgresConsoleRuntimeSnapshotSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleRuntimeSnapshotsPostgresSchema(
  options: PostgresConsoleRuntimeSnapshotSchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_RUNTIME_SNAPSHOTS_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_runtime_snapshots (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        project_id TEXT NOT NULL DEFAULT '',
        environment_id TEXT NOT NULL,
        snapshot_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        effective_at_ms BIGINT NOT NULL,
        checksum TEXT NOT NULL,
        payload JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        created_by TEXT NOT NULL,
        PRIMARY KEY (namespace, org_id, snapshot_id),
        UNIQUE (namespace, org_id, project_id, environment_id, version),
        CHECK (jsonb_typeof(payload) = 'object')
      )
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_runtime_snapshots_scope_version_idx
      ON console_runtime_snapshots (
        namespace,
        org_id,
        project_id,
        environment_id,
        version DESC,
        created_at_ms DESC
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_runtime_snapshot_outbox (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        project_id TEXT NOT NULL DEFAULT '',
        environment_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        snapshot_id TEXT NOT NULL,
        snapshot_version INTEGER NOT NULL,
        payload JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        dispatched_at_ms BIGINT,
        PRIMARY KEY (namespace, org_id, event_id),
        UNIQUE (namespace, org_id, snapshot_id, snapshot_version, event_type),
        CHECK (event_type IN ('RUNTIME_SNAPSHOT_PUBLISHED_V1')),
        CHECK (jsonb_typeof(payload) = 'object')
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_runtime_snapshot_outbox_scope_created_idx
      ON console_runtime_snapshot_outbox (namespace, org_id, created_at_ms ASC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_runtime_snapshot_outbox_pending_idx
      ON console_runtime_snapshot_outbox (namespace, created_at_ms ASC)
      WHERE dispatched_at_ms IS NULL
    `);

    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_runtime_snapshots',
      policyName: 'console_runtime_snapshots_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_runtime_snapshot_outbox',
      policyName: 'console_runtime_snapshot_outbox_tenant_rls',
    });
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [
        CONSOLE_RUNTIME_SNAPSHOTS_MIGRATION_LOCK_ID,
      ]);
    } catch {
      // no-op
    }
  }

  options.logger.info('[console-runtime-snapshots][postgres] Schema ready');
}

export interface PostgresConsoleRuntimeSnapshotServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
  retentionTtlMs?: number;
  retentionPruneIntervalMs?: number;
  retentionBatchSize?: number;
}

export interface PostgresConsoleRuntimeSnapshotOutboxDispatchOptions {
  postgresUrl: string;
  namespace?: string;
  orgIds: string[];
  limit?: number;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
  dispatch?: (event: ConsoleRuntimeSnapshotOutboxEvent) => Promise<void> | void;
}

export interface PostgresConsoleRuntimeSnapshotOutboxDispatchResult {
  namespace: string;
  orgCount: number;
  dispatchedCount: number;
  failureCount: number;
  failures: Array<{
    orgId: string;
    eventId: string;
    code: string;
    message: string;
  }>;
}

export interface PostgresConsoleRuntimeSnapshotRetentionCleanupOptions extends PostgresConsoleRuntimeSnapshotSchemaOptions {
  namespace?: string;
  orgId: string;
  ensureSchema?: boolean;
  now?: () => Date;
  ttlMs?: number;
  batchSize?: number;
}

export async function createPostgresConsoleRuntimeSnapshotService(
  options: PostgresConsoleRuntimeSnapshotServiceOptions,
): Promise<ConsoleRuntimeSnapshotService> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres console runtime snapshot service');
  }

  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const nowFn = options.now || (() => new Date());
  const retentionTtlMs = normalizePositiveInteger(options.retentionTtlMs, DEFAULT_RETENTION_TTL_MS);
  const retentionPruneIntervalMs = normalizePositiveInteger(
    options.retentionPruneIntervalMs,
    DEFAULT_RETENTION_PRUNE_INTERVAL_MS,
  );
  const retentionBatchSize = normalizePositiveInteger(
    options.retentionBatchSize,
    DEFAULT_RETENTION_BATCH_SIZE,
  );
  const nextRetentionRunAtByOrg = new Map<string, number>();

  if (options.ensureSchema !== false) {
    await ensureConsoleRuntimeSnapshotsPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);

  async function listRows(
    q: Queryable,
    input: { orgId: string; projectId?: string | null; environmentId: string; limit: number },
  ): Promise<ConsoleRuntimeSnapshot[]> {
    const values: unknown[] = [namespace, input.orgId, input.environmentId];
    let sql = `SELECT *
         FROM console_runtime_snapshots
        WHERE namespace = $1
          AND org_id = $2
          AND environment_id = $3`;
    if (input.projectId) {
      values.push(input.projectId);
      sql += `
          AND project_id = $4
        ORDER BY version DESC, created_at_ms DESC
        LIMIT $5`;
      values.push(input.limit);
    } else {
      sql += `
        ORDER BY version DESC, created_at_ms DESC
        LIMIT $4`;
      values.push(input.limit);
    }
    const result = await q.query(sql, values);
    return result.rows.map((row) => parseSnapshotRow(row as PgRow));
  }

  return {
    async listSnapshots(
      ctx: ConsoleRuntimeSnapshotContext,
      request: ListConsoleRuntimeSnapshotsRequest,
    ): Promise<ConsoleRuntimeSnapshot[]> {
      const rows = await withConsoleTenantContextTx(
        pool,
        { namespace, orgId: ctx.orgId },
        async (q) =>
          listRows(q, {
            orgId: ctx.orgId,
            projectId: normalizeProjectId(request.projectId) || null,
            environmentId: request.environmentId,
            limit: request.limit || 20,
          }),
      );
      return rows.map((row) => ({
        ...row,
        payload: clonePayload(row.payload),
      }));
    },

    async getLatestSnapshot(
      ctx: ConsoleRuntimeSnapshotContext,
      request: GetLatestConsoleRuntimeSnapshotRequest,
    ): Promise<ConsoleRuntimeSnapshot | null> {
      const projectId = normalizeProjectId(request.projectId) || null;
      const row = await withConsoleTenantContextTx(
        pool,
        { namespace, orgId: ctx.orgId },
        async (q) => {
          const values: unknown[] = [namespace, ctx.orgId, request.environmentId];
          let sql = `SELECT *
               FROM console_runtime_snapshots
              WHERE namespace = $1
                AND org_id = $2
                AND environment_id = $3`;
          if (projectId) {
            values.push(projectId);
            sql += `
                AND project_id = $4
              ORDER BY version DESC, created_at_ms DESC
              LIMIT 1`;
          } else {
            sql += `
              ORDER BY version DESC, created_at_ms DESC
              LIMIT 1`;
          }
          return await queryOne(q, sql, values);
        },
      );
      if (!row) return null;
      const snapshot = parseSnapshotRow(row);
      return {
        ...snapshot,
        payload: clonePayload(snapshot.payload),
      };
    },

    async publishSnapshot(
      ctx: ConsoleRuntimeSnapshotContext,
      request: PublishConsoleRuntimeSnapshotRequest,
    ): Promise<ConsoleRuntimeSnapshot> {
      const now = nowFn();
      const projectId = normalizeProjectId(request.projectId);
      const snapshotId = String(request.snapshotId || makeSnapshotId(now)).trim();
      const payload = clonePayload(request.payload);
      const effectiveAtMs = readEffectiveAtMs(request.effectiveAt, now);
      const effectiveAt = toIso(effectiveAtMs) || now.toISOString();
      const createdAtMs = nowMs(now);

      const inserted = await withConsoleTenantContextTx(
        pool,
        { namespace, orgId: ctx.orgId },
        async (q) => {
          const nextVersionRow = await queryOne(
            q,
            `SELECT COALESCE(MAX(version), 0) + 1 AS next_version
             FROM console_runtime_snapshots
            WHERE namespace = $1
              AND org_id = $2
              AND project_id = $3
              AND environment_id = $4`,
            [namespace, ctx.orgId, projectId, request.environmentId],
          );
          const version = Math.max(1, Math.floor(toNumber(nextVersionRow?.next_version, 1)));
          const checksum = computeConsoleRuntimeSnapshotChecksum({
            orgId: ctx.orgId,
            projectId: toNullableProjectId(projectId),
            environmentId: request.environmentId,
            snapshotId,
            version,
            effectiveAt,
            payload,
          });
          const insertedRow = await queryOne(
            q,
            `INSERT INTO console_runtime_snapshots
            (
              namespace,
              org_id,
              project_id,
              environment_id,
              snapshot_id,
              version,
              effective_at_ms,
              checksum,
              payload,
              created_at_ms,
              created_by
            )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)
           RETURNING *`,
            [
              namespace,
              ctx.orgId,
              projectId,
              request.environmentId,
              snapshotId,
              version,
              effectiveAtMs,
              checksum,
              JSON.stringify(payload),
              createdAtMs,
              ctx.actorUserId,
            ],
          );
          if (!insertedRow) {
            throw new Error('Failed to insert runtime snapshot');
          }
          const snapshot = parseSnapshotRow(insertedRow);
          const outboxEventId = makeOutboxEventId(now);
          const outboxPayload = {
            eventType: 'runtime_snapshot.published.v1',
            snapshot: {
              orgId: snapshot.orgId,
              projectId: snapshot.projectId,
              environmentId: snapshot.environmentId,
              snapshotId: snapshot.snapshotId,
              version: snapshot.version,
              effectiveAt: snapshot.effectiveAt,
              checksum: snapshot.checksum,
              createdAt: snapshot.createdAt,
              createdBy: snapshot.createdBy,
            },
          };
          await q.query(
            `INSERT INTO console_runtime_snapshot_outbox
            (
              namespace,
              org_id,
              project_id,
              environment_id,
              event_id,
              event_type,
              snapshot_id,
              snapshot_version,
              payload,
              created_at_ms,
              dispatched_at_ms
            )
           VALUES ($1, $2, $3, $4, $5, 'RUNTIME_SNAPSHOT_PUBLISHED_V1', $6, $7, $8::jsonb, $9, NULL)`,
            [
              namespace,
              ctx.orgId,
              projectId,
              request.environmentId,
              outboxEventId,
              snapshot.snapshotId,
              snapshot.version,
              JSON.stringify(outboxPayload),
              createdAtMs,
            ],
          );
          return snapshot;
        },
      );

      try {
        await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (q) => {
          await maybeRunConsoleRuntimeSnapshotRetentionForTenant(q, {
            namespace,
            orgId: ctx.orgId,
            nowValueMs: createdAtMs,
            ttlMs: retentionTtlMs,
            pruneIntervalMs: retentionPruneIntervalMs,
            batchSize: retentionBatchSize,
            nextRunAtByOrg: nextRetentionRunAtByOrg,
          });
        });
      } catch (error: unknown) {
        logger.warn('[console-runtime-snapshots][postgres] retention cleanup failed', {
          namespace,
          orgId: ctx.orgId,
          message: error instanceof Error ? error.message : String(error),
        });
      }

      return {
        ...inserted,
        payload: clonePayload(inserted.payload),
      };
    },
  };
}

export async function runPostgresConsoleRuntimeSnapshotRetentionCleanup(
  options: PostgresConsoleRuntimeSnapshotRetentionCleanupOptions,
): Promise<PostgresConsoleRuntimeSnapshotRetentionCleanupResult> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres console runtime snapshot retention cleanup');
  }
  const namespace = ensureNamespace(options.namespace);
  const orgId = normalizeRequiredString('orgId', options.orgId);
  const now = options.now || (() => new Date());
  const ttlMs = normalizePositiveInteger(options.ttlMs, DEFAULT_RETENTION_TTL_MS);
  const batchSize = normalizePositiveInteger(options.batchSize, DEFAULT_RETENTION_BATCH_SIZE);

  if (options.ensureSchema !== false) {
    await ensureConsoleRuntimeSnapshotsPostgresSchema({
      postgresUrl,
      logger: options.logger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);
  return withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) => {
    const cutoffMs = Math.max(0, nowMs(now()) - ttlMs);
    return pruneConsoleRuntimeSnapshotRetentionForTenant(q, {
      namespace,
      orgId,
      cutoffMs,
      batchSize,
    });
  });
}

export async function runPostgresConsoleRuntimeSnapshotOutboxDispatch(
  options: PostgresConsoleRuntimeSnapshotOutboxDispatchOptions,
): Promise<PostgresConsoleRuntimeSnapshotOutboxDispatchResult> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres runtime snapshot outbox dispatch');
  }
  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const nowFn = options.now || (() => new Date());
  const orgIds = Array.from(
    new Set(
      (Array.isArray(options.orgIds) ? options.orgIds : [])
        .map((orgId) => String(orgId || '').trim())
        .filter(Boolean),
    ),
  );
  if (orgIds.length === 0) {
    throw new Error('Runtime snapshot outbox dispatch requires at least one orgId');
  }
  if (typeof options.dispatch !== 'function') {
    throw new Error(
      'Runtime snapshot outbox dispatch requires a dispatch callback to avoid dropping events',
    );
  }
  const limit = Math.max(1, Math.min(500, Math.floor(Number(options.limit || 100))));
  const dispatch = options.dispatch;

  if (options.ensureSchema !== false) {
    await ensureConsoleRuntimeSnapshotsPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);
  const failures: PostgresConsoleRuntimeSnapshotOutboxDispatchResult['failures'] = [];
  let dispatchedCount = 0;

  for (const orgId of orgIds) {
    if (dispatchedCount >= limit) break;
    const remaining = limit - dispatchedCount;
    const perOrgDispatched = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId },
      async (q) => {
        const rows = await q.query(
          `SELECT *
             FROM console_runtime_snapshot_outbox
            WHERE namespace = $1
              AND org_id = $2
              AND dispatched_at_ms IS NULL
            ORDER BY created_at_ms ASC, event_id ASC
            LIMIT $3
            FOR UPDATE SKIP LOCKED`,
          [namespace, orgId, remaining],
        );
        let dispatched = 0;
        for (const row of rows.rows) {
          const event = parseOutboxEventRow(row as PgRow);
          try {
            await dispatch(event);
            await q.query(
              `UPDATE console_runtime_snapshot_outbox
                  SET dispatched_at_ms = $4
                WHERE namespace = $1
                  AND org_id = $2
                  AND event_id = $3
                  AND dispatched_at_ms IS NULL`,
              [namespace, orgId, event.eventId, nowMs(nowFn())],
            );
            dispatched += 1;
          } catch (error: unknown) {
            const code = 'dispatch_failed';
            const message = error instanceof Error ? error.message : String(error);
            failures.push({
              orgId,
              eventId: event.eventId,
              code,
              message,
            });
            logger.error('[console-runtime-snapshots][outbox] dispatch failed', {
              namespace,
              orgId,
              eventId: event.eventId,
              code,
              message,
            });
          }
        }
        return dispatched;
      },
    );
    dispatchedCount += perOrgDispatched;
  }

  return {
    namespace,
    orgCount: orgIds.length,
    dispatchedCount,
    failureCount: failures.length,
    failures,
  };
}
