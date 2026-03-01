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
import { ConsoleKeyExportError } from './errors';
import type {
  ApproveConsoleKeyExportRequest,
  ConsoleKeyExportApproval,
  ConsoleKeyExportConstraints,
  ConsoleKeyExportRequestRecord,
  CreateConsoleKeyExportRequest,
} from './types';
import type { ConsoleKeyExportService, ConsoleKeyExportsContext } from './service';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_KEY_EXPORTS_MIGRATION_LOCK_ID = 9452360123594;

function nowMs(now: Date): number {
  return now.getTime();
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function parseJsonArray(raw: unknown): unknown[] {
  if (Array.isArray(raw)) return raw;
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
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

function parseStringArray(raw: unknown): string[] {
  const source = parseJsonArray(raw);
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of source) {
    const value = String(entry || '').trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

function toNullableString(raw: unknown): string | null {
  const value = String(raw || '').trim();
  return value || null;
}

function normalizeConstraints(
  input: Partial<ConsoleKeyExportConstraints> | undefined,
): ConsoleKeyExportConstraints {
  return {
    roles: parseStringArray(input?.roles),
    chains: parseStringArray(input?.chains),
    walletTypes: parseStringArray(input?.walletTypes),
    environmentIds: parseStringArray(input?.environmentIds),
  };
}

function parseApprovals(raw: unknown): ConsoleKeyExportApproval[] {
  const out: ConsoleKeyExportApproval[] = [];
  for (const entry of parseJsonArray(raw)) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const row = entry as Record<string, unknown>;
    const approverUserId = String(row.approverUserId || '').trim();
    const approvedAt = String(row.approvedAt || '').trim();
    if (!approverUserId || !approvedAt) continue;
    out.push({
      approverUserId,
      approvedAt,
      reason: String(row.reason || '').trim(),
      mfaVerified: row.mfaVerified === true,
    });
  }
  return out;
}

function parseConstraints(raw: unknown): ConsoleKeyExportConstraints {
  const row = parseJsonObject(raw);
  return {
    roles: parseStringArray(row.roles),
    chains: parseStringArray(row.chains),
    walletTypes: parseStringArray(row.walletTypes),
    environmentIds: parseStringArray(row.environmentIds),
  };
}

function parseRecordRow(row: PgRow): ConsoleKeyExportRequestRecord {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    environmentId: String(row.environment_id || ''),
    walletId: toNullableString(row.wallet_id),
    mode: String(row.mode || 'APPROVAL_REQUIRED') as ConsoleKeyExportRequestRecord['mode'],
    status: String(row.status || 'PENDING_APPROVAL') as ConsoleKeyExportRequestRecord['status'],
    reason: String(row.reason || ''),
    requestedByUserId: String(row.requested_by_user_id || ''),
    requiredApprovals: Math.max(1, Math.floor(toNumber(row.required_approvals, 1))),
    approvals: parseApprovals(row.approvals),
    constraints: parseConstraints(row.constraints),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
  };
}

function isUniqueViolation(error: unknown): boolean {
  return !!error && typeof error === 'object' && (error as any).code === '23505';
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

export interface PostgresConsoleKeyExportSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleKeyExportsPostgresSchema(
  options: PostgresConsoleKeyExportSchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_KEY_EXPORTS_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_key_exports (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        id TEXT NOT NULL,
        environment_id TEXT NOT NULL,
        wallet_id TEXT,
        mode TEXT NOT NULL,
        status TEXT NOT NULL,
        reason TEXT NOT NULL,
        requested_by_user_id TEXT NOT NULL,
        required_approvals INTEGER NOT NULL,
        approvals JSONB NOT NULL,
        constraints JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id, id),
        CHECK (mode IN ('DISABLED', 'APPROVAL_REQUIRED', 'ALLOWED_WITH_CONSTRAINTS')),
        CHECK (status IN ('PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'EXECUTED', 'CANCELED')),
        CHECK (required_approvals > 0),
        CHECK (jsonb_typeof(approvals) = 'array'),
        CHECK (jsonb_typeof(constraints) = 'object')
      )
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_key_exports_org_updated_idx
      ON console_key_exports (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_key_exports_org_status_idx
      ON console_key_exports (namespace, org_id, status, updated_at_ms DESC)
    `);

    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_key_exports',
      policyName: 'console_key_exports_tenant_rls',
    });
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_KEY_EXPORTS_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }

  options.logger.info('[console-key-exports][postgres] Schema ready');
}

export interface PostgresConsoleKeyExportServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
}

export async function createPostgresConsoleKeyExportService(
  options: PostgresConsoleKeyExportServiceOptions,
): Promise<ConsoleKeyExportService> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres console key export service');
  }

  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const nowFn = options.now || (() => new Date());

  if (options.ensureSchema !== false) {
    await ensureConsoleKeyExportsPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);
  const withTenantTx = <T>(
    ctx: ConsoleKeyExportsContext,
    fn: (q: Queryable) => Promise<T>,
  ): Promise<T> => withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, fn);

  return {
    async listKeyExports(ctx, request = {}) {
      return withTenantTx(ctx, async (q) => {
        const out = await q.query(
          `SELECT *
             FROM console_key_exports
            WHERE namespace = $1
              AND org_id = $2
              AND ($3::text IS NULL OR environment_id = $3::text)
              AND ($4::text IS NULL OR status = $4::text)
            ORDER BY updated_at_ms DESC, created_at_ms DESC`,
          [namespace, ctx.orgId, request.environmentId || null, request.status || null],
        );
        return out.rows.map((row) => parseRecordRow(row as PgRow));
      });
    },

    async createKeyExport(ctx, request: CreateConsoleKeyExportRequest) {
      return withTenantTx(ctx, async (q) => {
        const now = nowFn();
        const createdAtMs = nowMs(now);
        const record: ConsoleKeyExportRequestRecord = {
          id: toNullableString(request.id) || makeId('ke', now),
          orgId: ctx.orgId,
          environmentId: request.environmentId,
          walletId: toNullableString(request.walletId),
          mode: request.mode || 'APPROVAL_REQUIRED',
          status: 'PENDING_APPROVAL',
          reason: request.reason,
          requestedByUserId: ctx.actorUserId,
          requiredApprovals: Math.max(1, request.requiredApprovals || 2),
          approvals: [],
          constraints: normalizeConstraints(request.constraints),
          createdAt: now.toISOString(),
          updatedAt: now.toISOString(),
        };

        try {
          const row = await queryOne(
            q,
            `INSERT INTO console_key_exports
              (namespace, org_id, id, environment_id, wallet_id, mode, status, reason, requested_by_user_id, required_approvals, approvals, constraints, created_at_ms, updated_at_ms)
             VALUES
              ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12::jsonb, $13, $13)
             RETURNING *`,
            [
              namespace,
              ctx.orgId,
              record.id,
              record.environmentId,
              record.walletId,
              record.mode,
              record.status,
              record.reason,
              record.requestedByUserId,
              record.requiredApprovals,
              JSON.stringify(record.approvals),
              JSON.stringify(record.constraints),
              createdAtMs,
            ],
          );
          if (!row) {
            throw new ConsoleKeyExportError('internal', 500, 'Failed to create key export request');
          }
          return parseRecordRow(row);
        } catch (error: unknown) {
          if (isUniqueViolation(error)) {
            throw new ConsoleKeyExportError(
              'key_export_exists',
              409,
              `Key export request ${record.id} already exists`,
            );
          }
          throw error;
        }
      });
    },

    async approveKeyExport(
      ctx: ConsoleKeyExportsContext,
      exportId: string,
      request: ApproveConsoleKeyExportRequest,
    ) {
      return withTenantTx(ctx, async (tx) => {
        const row = await queryOne(
          tx,
          `SELECT *
             FROM console_key_exports
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            FOR UPDATE`,
          [namespace, ctx.orgId, exportId],
        );
        if (!row) return null;
        const current = parseRecordRow(row);
        if (current.status !== 'PENDING_APPROVAL') {
          throw new ConsoleKeyExportError(
            'invalid_state',
            409,
            `Key export request ${exportId} is not pending approval`,
          );
        }
        if (!request.mfaVerified) {
          throw new ConsoleKeyExportError(
            'mfa_required',
            400,
            'MFA is required to approve key export requests',
          );
        }
        if (current.approvals.some((entry) => entry.approverUserId === ctx.actorUserId)) {
          throw new ConsoleKeyExportError(
            'already_approved',
            409,
            `User ${ctx.actorUserId} already approved key export request ${exportId}`,
          );
        }

        const approval: ConsoleKeyExportApproval = {
          approverUserId: ctx.actorUserId,
          approvedAt: nowFn().toISOString(),
          reason: request.reason,
          mfaVerified: true,
        };
        const nextApprovals = [...current.approvals, approval];
        const nextStatus =
          nextApprovals.length >= current.requiredApprovals ? 'APPROVED' : 'PENDING_APPROVAL';
        const updatedAtMs = nowMs(new Date(approval.approvedAt));

        const updated = await queryOne(
          tx,
          `UPDATE console_key_exports
              SET approvals = $4::jsonb,
                  status = $5,
                  updated_at_ms = $6
            WHERE namespace = $1
              AND org_id = $2
              AND id = $3
            RETURNING *`,
          [
            namespace,
            ctx.orgId,
            exportId,
            JSON.stringify(nextApprovals),
            nextStatus,
            updatedAtMs,
          ],
        );
        return updated ? parseRecordRow(updated) : null;
      });
    },
  };
}
