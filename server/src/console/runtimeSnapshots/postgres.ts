import type { NormalizedLogger } from '../../core/logger';
import { getPostgresPool } from '../../storage/postgres';
import {
  ensureConsoleNamespace as ensureNamespace,
  toConsoleIso as toIso,
  toConsoleNumber as toNumber,
} from '../shared/postgresNormalize';
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

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_RUNTIME_SNAPSHOTS_MIGRATION_LOCK_ID = 9452360123599;

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
    settings: cloneObject(input.settings),
    gasSponsorship: cloneObject(input.gasSponsorship),
    smartWallets: cloneObject(input.smartWallets),
    ...(input.metadata ? { metadata: cloneObject(input.metadata) } : {}),
  };
}

function parsePayload(raw: unknown): ConsoleRuntimeSnapshotPayload {
  const row = parseJsonObject(raw);
  const metadataRaw = row.metadata;
  return {
    policy: parseJsonObject(row.policy),
    settings: parseJsonObject(row.settings),
    gasSponsorship: parseJsonObject(row.gasSponsorship),
    smartWallets: parseJsonObject(row.smartWallets),
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

function makeSnapshotId(now: Date): string {
  return `runtime_snapshot_${now.getTime().toString(36)}_${Math.random().toString(16).slice(2, 10)}`;
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

async function withTx<T>(pool: PgPool, fn: (q: Queryable) => Promise<T>): Promise<T> {
  await pool.query('BEGIN');
  try {
    const result = await fn(pool);
    await pool.query('COMMIT');
    return result;
  } catch (error: unknown) {
    try {
      await pool.query('ROLLBACK');
    } catch {
      // no-op
    }
    throw error;
  }
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
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_RUNTIME_SNAPSHOTS_MIGRATION_LOCK_ID]);
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

  if (options.ensureSchema !== false) {
    await ensureConsoleRuntimeSnapshotsPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);

  async function listRows(
    q: Queryable,
    input: { orgId: string; projectId: string; environmentId: string; limit: number },
  ): Promise<ConsoleRuntimeSnapshot[]> {
    const result = await q.query(
      `SELECT *
         FROM console_runtime_snapshots
        WHERE namespace = $1
          AND org_id = $2
          AND project_id = $3
          AND environment_id = $4
        ORDER BY version DESC, created_at_ms DESC
        LIMIT $5`,
      [namespace, input.orgId, input.projectId, input.environmentId, input.limit],
    );
    return result.rows.map((row) => parseSnapshotRow(row as PgRow));
  }

  return {
    async listSnapshots(
      ctx: ConsoleRuntimeSnapshotContext,
      request: ListConsoleRuntimeSnapshotsRequest,
    ): Promise<ConsoleRuntimeSnapshot[]> {
      const rows = await listRows(pool, {
        orgId: ctx.orgId,
        projectId: normalizeProjectId(request.projectId),
        environmentId: request.environmentId,
        limit: request.limit || 20,
      });
      return rows.map((row) => ({
        ...row,
        payload: clonePayload(row.payload),
      }));
    },

    async getLatestSnapshot(
      ctx: ConsoleRuntimeSnapshotContext,
      request: GetLatestConsoleRuntimeSnapshotRequest,
    ): Promise<ConsoleRuntimeSnapshot | null> {
      const row = await queryOne(
        pool,
        `SELECT *
           FROM console_runtime_snapshots
          WHERE namespace = $1
            AND org_id = $2
            AND project_id = $3
            AND environment_id = $4
          ORDER BY version DESC, created_at_ms DESC
          LIMIT 1`,
        [namespace, ctx.orgId, normalizeProjectId(request.projectId), request.environmentId],
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

      const inserted = await withTx(pool, async (q) => {
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
        return parseSnapshotRow(insertedRow);
      });

      return {
        ...inserted,
        payload: clonePayload(inserted.payload),
      };
    },
  };
}
