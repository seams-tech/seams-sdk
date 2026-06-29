import { secureRandomBase36 } from '@shared/utils/secureRandomId';
import {
  d1Integer as toNumber,
  d1ChangedRows,
  formatD1ExecStatement,
  parseD1JsonArrayColumn as parseJsonArray,
  parseD1JsonObjectColumn as parseJsonObject,
  type D1Row,
} from '../../storage/d1Sql';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
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


const OPERATION_DEFAULTS: Record<
  ConsoleApprovalOperationType,
  {
    readonly requiredApprovals: number;
    readonly requireMfa: boolean;
  }
> = {
  POLICY_PUBLISH: { requiredApprovals: 1, requireMfa: false },
  KEY_EXPORT: { requiredApprovals: 2, requireMfa: true },
};

const MAX_CONDITIONAL_RETRIES = 3;

interface D1ConsoleApprovalState {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

type ApprovalTransition =
  | {
      readonly kind: 'approve';
      readonly decision: ConsoleApprovalDecisionRecord;
      readonly nextStatus: ConsoleApprovalStatus;
      readonly resolvedAtMs: number | null;
    }
  | {
      readonly kind: 'reject';
      readonly decision: ConsoleApprovalDecisionRecord;
      readonly nextStatus: 'REJECTED';
      readonly resolvedAtMs: number;
    };

type ApprovalQueryParts = {
  readonly whereSql: string;
  readonly values: readonly unknown[];
};

export const CONSOLE_APPROVALS_D1_RUNTIME = Symbol('consoleApprovalsD1Runtime');

export interface ConsoleApprovalsD1Runtime {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

export type ConsoleApprovalsD1Service = ConsoleApprovalService & {
  readonly [CONSOLE_APPROVALS_D1_RUNTIME]: ConsoleApprovalsD1Runtime;
};

export interface D1ConsoleApprovalSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1ConsoleApprovalServiceOptions {
  readonly database: D1DatabaseLike;
  readonly namespace?: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
}

export const CONSOLE_APPROVALS_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS approvals (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      operation_type TEXT NOT NULL,
      status TEXT NOT NULL,
      reason TEXT NOT NULL,
      requested_by_user_id TEXT NOT NULL,
      required_approvals INTEGER NOT NULL,
      require_mfa INTEGER NOT NULL,
      project_id TEXT,
      environment_id TEXT,
      resource_type TEXT,
      resource_id TEXT,
      metadata_json TEXT NOT NULL,
      decisions_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      resolved_at_ms INTEGER,
      PRIMARY KEY (namespace, org_id, id),
      CHECK (operation_type IN ('POLICY_PUBLISH', 'KEY_EXPORT')),
      CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'CANCELED')),
      CHECK (required_approvals > 0),
      CHECK (require_mfa IN (0, 1)),
      CHECK (json_valid(metadata_json)),
      CHECK (json_valid(decisions_json))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS approvals_org_updated_idx
      ON approvals (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS approvals_org_status_idx
      ON approvals (namespace, org_id, status, updated_at_ms DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS approvals_org_operation_idx
      ON approvals (namespace, org_id, operation_type, updated_at_ms DESC)
  `,
] as const);

export async function ensureConsoleApprovalsD1Schema(
  options: D1ConsoleApprovalSchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_APPROVALS_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export function getConsoleApprovalsD1Runtime(
  service: ConsoleApprovalService | null | undefined,
): ConsoleApprovalsD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (service as Partial<ConsoleApprovalsD1Service>)[CONSOLE_APPROVALS_D1_RUNTIME] || null;
}

export async function createD1ConsoleApprovalService(
  options: D1ConsoleApprovalServiceOptions,
): Promise<ConsoleApprovalsD1Service> {
  const state: D1ConsoleApprovalState = {
    database: options.database,
    namespace: ensureNamespace(options.namespace),
    now: options.now || defaultNow,
  };
  if (options.ensureSchema !== false) {
    await ensureConsoleApprovalsD1Schema({ database: state.database });
  }
  return new D1ConsoleApprovalServiceImpl(state) as ConsoleApprovalsD1Service;
}

function defaultNow(): Date {
  return new Date();
}

function ensureNamespace(namespace: string | undefined): string {
  const normalized = String(namespace || 'default').trim();
  return normalized || 'default';
}

function nowMs(now: Date): number {
  return now.getTime();
}

function toIso(ms: number): string {
  return new Date(ms).toISOString();
}

function toNullableIso(value: unknown): string | null {
  if (value === null || value === undefined || value === '') return null;
  const parsed = toNumber(value, NaN);
  return Number.isFinite(parsed) ? toIso(parsed) : null;
}


function normalizeString(raw: unknown): string {
  return String(raw || '').trim();
}

function toNullableString(raw: unknown): string | null {
  const value = normalizeString(raw);
  return value || null;
}

function makeId(prefix: string, now: Date): string {
  return `${prefix}_${now.getTime().toString(36)}_${secureRandomBase36(8, 'console IDs')}`;
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
    mfaVerified: row.mfaVerified === true || row.mfaVerified === 1,
    decidedAt,
  };
}

function parseDecisions(raw: unknown): ConsoleApprovalDecisionRecord[] {
  const out: ConsoleApprovalDecisionRecord[] = [];
  for (const entry of parseJsonArray(raw)) {
    const parsed = parseDecision(entry);
    if (parsed) out.push(parsed);
  }
  return out;
}

function parseOperationType(raw: unknown): ConsoleApprovalOperationType {
  const value = normalizeString(raw).toUpperCase();
  return value === 'KEY_EXPORT' ? 'KEY_EXPORT' : 'POLICY_PUBLISH';
}

function parseStatus(raw: unknown): ConsoleApprovalStatus {
  const value = normalizeString(raw).toUpperCase();
  switch (value) {
    case 'APPROVED':
    case 'REJECTED':
    case 'CANCELED':
    case 'PENDING':
      return value;
    default:
      return 'PENDING';
  }
}

function parseBooleanFlag(raw: unknown): boolean {
  if (typeof raw === 'boolean') return raw;
  if (typeof raw === 'number') return raw === 1;
  const normalized = normalizeString(raw).toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 't';
}

function parseRecordRow(row: D1Row): ConsoleApprovalRequestRecord {
  return {
    id: normalizeString(row.id),
    orgId: normalizeString(row.org_id),
    operationType: parseOperationType(row.operation_type),
    status: parseStatus(row.status),
    reason: normalizeString(row.reason),
    requestedByUserId: normalizeString(row.requested_by_user_id),
    requiredApprovals: Math.max(1, toNumber(row.required_approvals, 1)),
    requireMfa: parseBooleanFlag(row.require_mfa),
    projectId: toNullableString(row.project_id),
    environmentId: toNullableString(row.environment_id),
    resourceType: toNullableString(row.resource_type),
    resourceId: toNullableString(row.resource_id),
    metadata: parseJsonObject(row.metadata_json),
    decisions: parseDecisions(row.decisions_json),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
    resolvedAt: toNullableIso(row.resolved_at_ms),
  };
}

function countApprovals(decisions: readonly ConsoleApprovalDecisionRecord[]): number {
  return decisions.filter((entry) => entry.decision === 'APPROVE').length;
}

function ensureMetadataObject(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  return { ...(raw as Record<string, unknown>) };
}


function isD1ConstraintError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes('UNIQUE constraint failed') || message.includes('constraint failed');
}

function appendEqualsFilter(
  input: {
    readonly clauses: string[];
    readonly values: unknown[];
  },
  column: string,
  raw: unknown,
): void {
  const value = normalizeString(raw);
  if (!value) return;
  input.clauses.push(`${column} = ?`);
  input.values.push(value);
}

function buildApprovalListQuery(
  namespace: string,
  orgId: string,
  request: ListConsoleApprovalsRequest,
): ApprovalQueryParts {
  const clauses = ['namespace = ?', 'org_id = ?'];
  const values: unknown[] = [namespace, orgId];
  appendEqualsFilter({ clauses, values }, 'status', request.status);
  appendEqualsFilter({ clauses, values }, 'operation_type', request.operationType);
  appendEqualsFilter({ clauses, values }, 'project_id', request.projectId);
  appendEqualsFilter({ clauses, values }, 'environment_id', request.environmentId);
  return {
    whereSql: clauses.join(' AND '),
    values,
  };
}

function actorAlreadyDecided(
  record: ConsoleApprovalRequestRecord,
  actorUserId: string,
): boolean {
  return record.decisions.some((entry) => entry.actorUserId === actorUserId);
}

function ensurePendingDecisionAllowed(input: {
  readonly record: ConsoleApprovalRequestRecord;
  readonly approvalId: string;
  readonly actorUserId: string;
}): void {
  if (input.record.status !== 'PENDING') {
    throw new ConsoleApprovalsError(
      'invalid_state',
      409,
      `Approval request ${input.approvalId} is not pending`,
    );
  }
  if (actorAlreadyDecided(input.record, input.actorUserId)) {
    throw new ConsoleApprovalsError(
      'already_decided',
      409,
      `User ${input.actorUserId} has already decided request ${input.approvalId}`,
    );
  }
}

function buildApproveTransition(input: {
  readonly record: ConsoleApprovalRequestRecord;
  readonly actorUserId: string;
  readonly request: ApproveConsoleApprovalRequest;
  readonly decidedAtMs: number;
}): ApprovalTransition {
  if (input.record.requireMfa && !input.request.mfaVerified) {
    throw new ConsoleApprovalsError(
      'mfa_required',
      400,
      'MFA is required to approve this request',
    );
  }
  const decision: ConsoleApprovalDecisionRecord = {
    decision: 'APPROVE',
    actorUserId: input.actorUserId,
    reason: input.request.reason,
    mfaVerified: input.request.mfaVerified,
    decidedAt: toIso(input.decidedAtMs),
  };
  const nextDecisions = [...input.record.decisions, decision];
  const nextStatus: ConsoleApprovalStatus =
    countApprovals(nextDecisions) >= input.record.requiredApprovals ? 'APPROVED' : 'PENDING';
  return {
    kind: 'approve',
    decision,
    nextStatus,
    resolvedAtMs: nextStatus === 'APPROVED' ? input.decidedAtMs : null,
  };
}

function buildRejectTransition(input: {
  readonly actorUserId: string;
  readonly request: RejectConsoleApprovalRequest;
  readonly decidedAtMs: number;
}): ApprovalTransition {
  return {
    kind: 'reject',
    decision: {
      decision: 'REJECT',
      actorUserId: input.actorUserId,
      reason: input.request.reason,
      mfaVerified: false,
      decidedAt: toIso(input.decidedAtMs),
    },
    nextStatus: 'REJECTED',
    resolvedAtMs: input.decidedAtMs,
  };
}

class D1ConsoleApprovalServiceImpl implements ConsoleApprovalService {
  readonly [CONSOLE_APPROVALS_D1_RUNTIME]: ConsoleApprovalsD1Runtime;

  private readonly state: D1ConsoleApprovalState;

  constructor(state: D1ConsoleApprovalState) {
    this.state = state;
    this[CONSOLE_APPROVALS_D1_RUNTIME] = {
      database: state.database,
      namespace: state.namespace,
      now: state.now,
    };
    this.listApprovalRequests = this.listApprovalRequests.bind(this);
    this.getApprovalRequest = this.getApprovalRequest.bind(this);
    this.createApprovalRequest = this.createApprovalRequest.bind(this);
    this.approveApprovalRequest = this.approveApprovalRequest.bind(this);
    this.rejectApprovalRequest = this.rejectApprovalRequest.bind(this);
  }

  async listApprovalRequests(
    ctx: ConsoleApprovalsContext,
    request: ListConsoleApprovalsRequest = {},
  ): Promise<ConsoleApprovalRequestRecord[]> {
    const query = buildApprovalListQuery(this.state.namespace, ctx.orgId, request);
    const out = await this.state.database
      .prepare(
        `SELECT *
           FROM approvals
          WHERE ${query.whereSql}
          ORDER BY updated_at_ms DESC, created_at_ms DESC`,
      )
      .bind(...query.values)
      .all<D1Row>();
    return (out.results || []).map((row) => parseRecordRow(row));
  }

  async getApprovalRequest(
    ctx: ConsoleApprovalsContext,
    approvalId: string,
  ): Promise<ConsoleApprovalRequestRecord | null> {
    return await this.findApproval(ctx.orgId, approvalId);
  }

  async createApprovalRequest(
    ctx: ConsoleApprovalsContext,
    request: CreateConsoleApprovalRequest,
  ): Promise<ConsoleApprovalRequestRecord> {
    const now = this.state.now();
    const createdAtMs = nowMs(now);
    const defaults = OPERATION_DEFAULTS[request.operationType];
    const id = toNullableString(request.id) || makeId('apr', now);
    const requiredApprovals = Math.max(
      1,
      Math.floor(toNumber(request.requiredApprovals, defaults.requiredApprovals)),
    );
    const requireMfa =
      request.requireMfa === undefined ? defaults.requireMfa : request.requireMfa === true;
    try {
      await this.state.database
        .prepare(
          `INSERT INTO approvals
            (namespace, org_id, id, operation_type, status, reason, requested_by_user_id, required_approvals, require_mfa, project_id, environment_id, resource_type, resource_id, metadata_json, decisions_json, created_at_ms, updated_at_ms, resolved_at_ms)
           VALUES
            (?, ?, ?, ?, 'PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?, NULL)`,
        )
        .bind(
          this.state.namespace,
          ctx.orgId,
          id,
          request.operationType,
          request.reason,
          ctx.actorUserId,
          requiredApprovals,
          requireMfa ? 1 : 0,
          toNullableString(request.projectId),
          toNullableString(request.environmentId),
          toNullableString(request.resourceType),
          toNullableString(request.resourceId),
          JSON.stringify(ensureMetadataObject(request.metadata)),
          createdAtMs,
          createdAtMs,
        )
        .run();
    } catch (error: unknown) {
      if (isD1ConstraintError(error)) {
        throw new ConsoleApprovalsError(
          'approval_request_exists',
          409,
          `Approval request ${id} already exists`,
        );
      }
      throw error;
    }
    const created = await this.findApproval(ctx.orgId, id);
    if (!created) {
      throw new ConsoleApprovalsError('internal', 500, 'Failed to create approval request');
    }
    return created;
  }

  async approveApprovalRequest(
    ctx: ConsoleApprovalsContext,
    approvalId: string,
    request: ApproveConsoleApprovalRequest,
  ): Promise<ConsoleApprovalRequestRecord | null> {
    for (let attempt = 0; attempt < MAX_CONDITIONAL_RETRIES; attempt += 1) {
      const current = await this.findApproval(ctx.orgId, approvalId);
      if (!current) return null;
      ensurePendingDecisionAllowed({
        record: current,
        approvalId,
        actorUserId: ctx.actorUserId,
      });
      const decidedAtMs = nowMs(this.state.now());
      const transition = buildApproveTransition({
        record: current,
        actorUserId: ctx.actorUserId,
        request,
        decidedAtMs,
      });
      const updated = await this.applyTransition({
        current,
        transition,
        updatedAtMs: decidedAtMs,
      });
      if (updated) return updated;
    }
    return await this.resolveStaleTransition(ctx, approvalId);
  }

  async rejectApprovalRequest(
    ctx: ConsoleApprovalsContext,
    approvalId: string,
    request: RejectConsoleApprovalRequest,
  ): Promise<ConsoleApprovalRequestRecord | null> {
    for (let attempt = 0; attempt < MAX_CONDITIONAL_RETRIES; attempt += 1) {
      const current = await this.findApproval(ctx.orgId, approvalId);
      if (!current) return null;
      ensurePendingDecisionAllowed({
        record: current,
        approvalId,
        actorUserId: ctx.actorUserId,
      });
      const decidedAtMs = nowMs(this.state.now());
      const transition = buildRejectTransition({
        actorUserId: ctx.actorUserId,
        request,
        decidedAtMs,
      });
      const updated = await this.applyTransition({
        current,
        transition,
        updatedAtMs: decidedAtMs,
      });
      if (updated) return updated;
    }
    return await this.resolveStaleTransition(ctx, approvalId);
  }

  private async findApproval(
    orgId: string,
    approvalId: string,
  ): Promise<ConsoleApprovalRequestRecord | null> {
    const row = await this.state.database
      .prepare(
        `SELECT *
           FROM approvals
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?`,
      )
      .bind(this.state.namespace, orgId, approvalId)
      .first<D1Row>();
    return row ? parseRecordRow(row) : null;
  }

  private async applyTransition(input: {
    readonly current: ConsoleApprovalRequestRecord;
    readonly transition: ApprovalTransition;
    readonly updatedAtMs: number;
  }): Promise<ConsoleApprovalRequestRecord | null> {
    const currentDecisionsJson = JSON.stringify(input.current.decisions);
    const nextDecisions = [...input.current.decisions, input.transition.decision];
    const result = await this.state.database
      .prepare(
        `UPDATE approvals
            SET decisions_json = ?,
                status = ?,
                updated_at_ms = ?,
                resolved_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?
            AND status = 'PENDING'
            AND decisions_json = ?`,
      )
      .bind(
        JSON.stringify(nextDecisions),
        input.transition.nextStatus,
        input.updatedAtMs,
        input.transition.resolvedAtMs,
        this.state.namespace,
        input.current.orgId,
        input.current.id,
        currentDecisionsJson,
      )
      .run();
    if (d1ChangedRows(result) < 1) return null;
    return await this.findApproval(input.current.orgId, input.current.id);
  }

  private async resolveStaleTransition(
    ctx: ConsoleApprovalsContext,
    approvalId: string,
  ): Promise<ConsoleApprovalRequestRecord | null> {
    const current = await this.findApproval(ctx.orgId, approvalId);
    if (!current) return null;
    ensurePendingDecisionAllowed({
      record: current,
      approvalId,
      actorUserId: ctx.actorUserId,
    });
    throw new ConsoleApprovalsError(
      'conflict',
      409,
      `Approval request ${approvalId} changed while recording the decision`,
    );
  }
}
