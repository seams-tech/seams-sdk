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
import { ConsoleApprovalsError } from './errors';
import type { ConsoleApprovalService, ConsoleApprovalsContext } from './service';
import type {
  ApproveConsoleApprovalRequest,
  ConsoleApprovalDecision,
  ConsoleApprovalDecisionRecord,
  ConsoleApprovalOperationType,
  ConsoleApprovalRequestRecord,
  ConsoleApprovalStatus,
  CreateConsoleApprovalRequest,
  ListConsoleApprovalsRequest,
  RejectConsoleApprovalRequest,
} from './types';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_APPROVALS_MIGRATION_LOCK_ID = 9452360123603;

const OPERATION_DEFAULTS: Record<
  ConsoleApprovalOperationType,
  {
    requiredApprovals: number;
    requireMfa: boolean;
  }
> = {
  POLICY_PUBLISH: { requiredApprovals: 1, requireMfa: false },
  KEY_EXPORT: { requiredApprovals: 2, requireMfa: true },
  SECURITY_SETTINGS_CHANGE: { requiredApprovals: 1, requireMfa: true },
};

function nowMs(now: Date): number {
  return now.getTime();
}

function makeId(prefix: string, now: Date): string {
  return `${prefix}_${now.getTime().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

function normalizeString(raw: unknown): string {
  return String(raw || '').trim();
}

function toNullableString(raw: unknown): string | null {
  const value = normalizeString(raw);
  return value || null;
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

function parseDecision(raw: unknown): ConsoleApprovalDecisionRecord | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const decisionRaw = normalizeString(row.decision).toUpperCase();
  const decision: ConsoleApprovalDecision = decisionRaw === 'REJECT' ? 'REJECT' : 'APPROVE';
  const actorUserId = normalizeString(row.actorUserId);
  const reason = normalizeString(row.reason);
  const decidedAt = normalizeString(row.decidedAt);
  if (!actorUserId || !reason || !decidedAt) return null;
  return {
    decision,
    actorUserId,
    reason,
    mfaVerified: row.mfaVerified === true,
    decidedAt,
  };
}

function parseDecisions(raw: unknown): ConsoleApprovalDecisionRecord[] {
  return parseJsonArray(raw)
    .map((entry) => parseDecision(entry))
    .filter((entry): entry is ConsoleApprovalDecisionRecord => entry !== null);
}

function parseOperationType(raw: unknown): ConsoleApprovalOperationType {
  const value = normalizeString(raw).toUpperCase() as ConsoleApprovalOperationType;
  if (value === 'KEY_EXPORT' || value === 'SECURITY_SETTINGS_CHANGE') return value;
  return 'POLICY_PUBLISH';
}

function parseStatus(raw: unknown): ConsoleApprovalStatus {
  const value = normalizeString(raw).toUpperCase() as ConsoleApprovalStatus;
  if (value === 'APPROVED' || value === 'REJECTED' || value === 'CANCELED') return value;
  return 'PENDING';
}

function parseRecordRow(row: PgRow): ConsoleApprovalRequestRecord {
  return {
    id: normalizeString(row.id),
    orgId: normalizeString(row.org_id),
    operationType: parseOperationType(row.operation_type),
    status: parseStatus(row.status),
    reason: normalizeString(row.reason),
    requestedByUserId: normalizeString(row.requested_by_user_id),
    requiredApprovals: Math.max(1, Math.floor(toNumber(row.required_approvals, 1))),
    requireMfa: row.require_mfa === true,
    projectId: toNullableString(row.project_id),
    environmentId: toNullableString(row.environment_id),
    resourceType: toNullableString(row.resource_type),
    resourceId: toNullableString(row.resource_id),
    metadata: parseJsonObject(row.metadata),
    decisions: parseDecisions(row.decisions),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
    resolvedAt: toIso(toNumber(row.resolved_at_ms, NaN)),
  };
}

function isUniqueViolation(error: unknown): boolean {
  return !!error && typeof error === 'object' && (error as any).code === '23505';
}

function countApprovals(decisions: ConsoleApprovalDecisionRecord[]): number {
  return decisions.filter((entry) => entry.decision === 'APPROVE').length;
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

export interface PostgresConsoleApprovalSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleApprovalsPostgresSchema(
  options: PostgresConsoleApprovalSchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_APPROVALS_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_approvals (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        id TEXT NOT NULL,
        operation_type TEXT NOT NULL,
        status TEXT NOT NULL,
        reason TEXT NOT NULL,
        requested_by_user_id TEXT NOT NULL,
        required_approvals INTEGER NOT NULL,
        require_mfa BOOLEAN NOT NULL,
        project_id TEXT,
        environment_id TEXT,
        resource_type TEXT,
        resource_id TEXT,
        metadata JSONB NOT NULL,
        decisions JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        resolved_at_ms BIGINT,
        PRIMARY KEY (namespace, org_id, id),
        CHECK (operation_type IN ('POLICY_PUBLISH', 'KEY_EXPORT', 'SECURITY_SETTINGS_CHANGE')),
        CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'CANCELED')),
        CHECK (required_approvals > 0),
        CHECK (jsonb_typeof(metadata) = 'object'),
        CHECK (jsonb_typeof(decisions) = 'array')
      )
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_approvals_org_updated_idx
      ON console_approvals (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_approvals_org_status_idx
      ON console_approvals (namespace, org_id, status, updated_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_approvals_org_operation_idx
      ON console_approvals (namespace, org_id, operation_type, updated_at_ms DESC)
    `);

    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_approvals',
      policyName: 'console_approvals_tenant_rls',
    });
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_APPROVALS_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }

  options.logger.info('[console-approvals][postgres] Schema ready');
}

export interface PostgresConsoleApprovalServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
}

export async function createPostgresConsoleApprovalService(
  options: PostgresConsoleApprovalServiceOptions,
): Promise<ConsoleApprovalService> {
  const postgresUrl = normalizeString(options.postgresUrl);
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres console approvals service');
  }

  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const nowFn = options.now || (() => new Date());

  if (options.ensureSchema !== false) {
    await ensureConsoleApprovalsPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);
  const withTenantTx = <T>(
    ctx: ConsoleApprovalsContext,
    fn: (q: Queryable) => Promise<T>,
  ): Promise<T> => withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, fn);

  return {
    async listApprovalRequests(
      ctx: ConsoleApprovalsContext,
      request: ListConsoleApprovalsRequest = {},
    ): Promise<ConsoleApprovalRequestRecord[]> {
      return withTenantTx(ctx, async (q) => {
        const out = await q.query(
          `SELECT *
             FROM console_approvals
            WHERE namespace = $1
              AND org_id = $2
              AND ($3::text IS NULL OR status = $3::text)
              AND ($4::text IS NULL OR operation_type = $4::text)
              AND ($5::text IS NULL OR project_id = $5::text)
              AND ($6::text IS NULL OR environment_id = $6::text)
            ORDER BY updated_at_ms DESC, created_at_ms DESC`,
          [
            namespace,
            ctx.orgId,
            request.status || null,
            request.operationType || null,
            request.projectId || null,
            request.environmentId || null,
          ],
        );
        return out.rows.map((row) => parseRecordRow(row as PgRow));
      });
    },

    async getApprovalRequest(
      ctx: ConsoleApprovalsContext,
      approvalId: string,
    ): Promise<ConsoleApprovalRequestRecord | null> {
      return withTenantTx(ctx, async (q) => {
        const row = await queryOne(
          q,
          `SELECT *
             FROM console_approvals
            WHERE namespace = $1
              AND org_id = $2
              AND id = $3`,
          [namespace, ctx.orgId, approvalId],
        );
        return row ? parseRecordRow(row) : null;
      });
    },

    async createApprovalRequest(
      ctx: ConsoleApprovalsContext,
      request: CreateConsoleApprovalRequest,
    ): Promise<ConsoleApprovalRequestRecord> {
      return withTenantTx(ctx, async (q) => {
        const now = nowFn();
        const nowTs = nowMs(now);
        const defaults = OPERATION_DEFAULTS[request.operationType];
        const id = toNullableString(request.id) || makeId('apr', now);
        const requiredApprovals = Math.max(
          1,
          Math.floor(toNumber(request.requiredApprovals, defaults.requiredApprovals)),
        );
        const requireMfa =
          request.requireMfa === undefined ? defaults.requireMfa : request.requireMfa === true;
        const metadata =
          request.metadata && typeof request.metadata === 'object' && !Array.isArray(request.metadata)
            ? request.metadata
            : {};
        try {
          const row = await queryOne(
            q,
            `INSERT INTO console_approvals
              (namespace, org_id, id, operation_type, status, reason, requested_by_user_id, required_approvals, require_mfa, project_id, environment_id, resource_type, resource_id, metadata, decisions, created_at_ms, updated_at_ms, resolved_at_ms)
             VALUES
              ($1, $2, $3, $4, 'PENDING', $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, '[]'::jsonb, $14, $14, NULL)
             RETURNING *`,
            [
              namespace,
              ctx.orgId,
              id,
              request.operationType,
              request.reason,
              ctx.actorUserId,
              requiredApprovals,
              requireMfa,
              toNullableString(request.projectId),
              toNullableString(request.environmentId),
              toNullableString(request.resourceType),
              toNullableString(request.resourceId),
              JSON.stringify(metadata),
              nowTs,
            ],
          );
          if (!row) {
            throw new ConsoleApprovalsError('internal', 500, 'Failed to create approval request');
          }
          return parseRecordRow(row);
        } catch (error: unknown) {
          if (isUniqueViolation(error)) {
            throw new ConsoleApprovalsError(
              'approval_request_exists',
              409,
              `Approval request ${id} already exists`,
            );
          }
          throw error;
        }
      });
    },

    async approveApprovalRequest(
      ctx: ConsoleApprovalsContext,
      approvalId: string,
      request: ApproveConsoleApprovalRequest,
    ): Promise<ConsoleApprovalRequestRecord | null> {
      return withTenantTx(ctx, async (q) => {
        const row = await queryOne(
          q,
          `SELECT *
             FROM console_approvals
            WHERE namespace = $1
              AND org_id = $2
              AND id = $3
            FOR UPDATE`,
          [namespace, ctx.orgId, approvalId],
        );
        if (!row) return null;
        const current = parseRecordRow(row);
        if (current.status !== 'PENDING') {
          throw new ConsoleApprovalsError(
            'invalid_state',
            409,
            `Approval request ${approvalId} is not pending`,
          );
        }
        if (current.requireMfa && !request.mfaVerified) {
          throw new ConsoleApprovalsError(
            'mfa_required',
            400,
            'MFA is required to approve this request',
          );
        }
        if (current.decisions.some((entry) => entry.actorUserId === ctx.actorUserId)) {
          throw new ConsoleApprovalsError(
            'already_decided',
            409,
            `User ${ctx.actorUserId} has already decided request ${approvalId}`,
          );
        }

        const decision: ConsoleApprovalDecisionRecord = {
          decision: 'APPROVE',
          actorUserId: ctx.actorUserId,
          reason: request.reason,
          mfaVerified: request.mfaVerified,
          decidedAt: nowFn().toISOString(),
        };
        const nextDecisions = [...current.decisions, decision];
        const nextStatus: ConsoleApprovalStatus =
          countApprovals(nextDecisions) >= current.requiredApprovals ? 'APPROVED' : 'PENDING';
        const updatedAtMs = nowMs(new Date(decision.decidedAt));
        const resolvedAtMs = nextStatus === 'APPROVED' ? updatedAtMs : null;
        const updated = await queryOne(
          q,
          `UPDATE console_approvals
              SET decisions = $4::jsonb,
                  status = $5,
                  updated_at_ms = $6,
                  resolved_at_ms = $7
            WHERE namespace = $1
              AND org_id = $2
              AND id = $3
            RETURNING *`,
          [
            namespace,
            ctx.orgId,
            approvalId,
            JSON.stringify(nextDecisions),
            nextStatus,
            updatedAtMs,
            resolvedAtMs,
          ],
        );
        return updated ? parseRecordRow(updated) : null;
      });
    },

    async rejectApprovalRequest(
      ctx: ConsoleApprovalsContext,
      approvalId: string,
      request: RejectConsoleApprovalRequest,
    ): Promise<ConsoleApprovalRequestRecord | null> {
      return withTenantTx(ctx, async (q) => {
        const row = await queryOne(
          q,
          `SELECT *
             FROM console_approvals
            WHERE namespace = $1
              AND org_id = $2
              AND id = $3
            FOR UPDATE`,
          [namespace, ctx.orgId, approvalId],
        );
        if (!row) return null;
        const current = parseRecordRow(row);
        if (current.status !== 'PENDING') {
          throw new ConsoleApprovalsError(
            'invalid_state',
            409,
            `Approval request ${approvalId} is not pending`,
          );
        }
        if (current.decisions.some((entry) => entry.actorUserId === ctx.actorUserId)) {
          throw new ConsoleApprovalsError(
            'already_decided',
            409,
            `User ${ctx.actorUserId} has already decided request ${approvalId}`,
          );
        }

        const decision: ConsoleApprovalDecisionRecord = {
          decision: 'REJECT',
          actorUserId: ctx.actorUserId,
          reason: request.reason,
          mfaVerified: false,
          decidedAt: nowFn().toISOString(),
        };
        const nextDecisions = [...current.decisions, decision];
        const updatedAtMs = nowMs(new Date(decision.decidedAt));
        const updated = await queryOne(
          q,
          `UPDATE console_approvals
              SET decisions = $4::jsonb,
                  status = 'REJECTED',
                  updated_at_ms = $5,
                  resolved_at_ms = $5
            WHERE namespace = $1
              AND org_id = $2
              AND id = $3
            RETURNING *`,
          [namespace, ctx.orgId, approvalId, JSON.stringify(nextDecisions), updatedAtMs],
        );
        return updated ? parseRecordRow(updated) : null;
      });
    },
  };
}
