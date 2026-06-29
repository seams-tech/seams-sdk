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
import { ConsoleKeyExportError } from './errors';
import type { ConsoleKeyExportService, ConsoleKeyExportsContext } from './service';
import type {
  ApproveConsoleKeyExportRequest,
  ConsoleKeyExportApproval,
  ConsoleKeyExportConstraints,
  ConsoleKeyExportMode,
  ConsoleKeyExportRequestRecord,
  ConsoleKeyExportStatus,
  CreateConsoleKeyExportRequest,
  ListConsoleKeyExportsRequest,
} from './types';


const MAX_CONDITIONAL_RETRIES = 3;

interface D1ConsoleKeyExportState {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

interface KeyExportListQuery {
  readonly whereSql: string;
  readonly values: readonly unknown[];
}

export const CONSOLE_KEY_EXPORTS_D1_RUNTIME = Symbol('consoleKeyExportsD1Runtime');

export interface ConsoleKeyExportsD1Runtime {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

export type ConsoleKeyExportD1Service = ConsoleKeyExportService & {
  readonly [CONSOLE_KEY_EXPORTS_D1_RUNTIME]: ConsoleKeyExportsD1Runtime;
};

export interface D1ConsoleKeyExportSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1ConsoleKeyExportServiceOptions {
  readonly database: D1DatabaseLike;
  readonly namespace?: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
}

export const CONSOLE_KEY_EXPORTS_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS key_exports (
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
      approvals_json TEXT NOT NULL,
      constraints_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, id),
      CHECK (mode IN ('DISABLED', 'APPROVAL_REQUIRED', 'ALLOWED_WITH_CONSTRAINTS')),
      CHECK (status IN ('PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'EXECUTED', 'CANCELED')),
      CHECK (required_approvals > 0),
      CHECK (json_valid(approvals_json)),
      CHECK (json_valid(constraints_json))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS key_exports_org_updated_idx
      ON key_exports (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS key_exports_org_status_idx
      ON key_exports (namespace, org_id, status, updated_at_ms DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS key_exports_org_environment_idx
      ON key_exports (namespace, org_id, environment_id, updated_at_ms DESC)
  `,
] as const);

export async function ensureConsoleKeyExportsD1Schema(
  options: D1ConsoleKeyExportSchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_KEY_EXPORTS_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export function getConsoleKeyExportsD1Runtime(
  service: ConsoleKeyExportService | null | undefined,
): ConsoleKeyExportsD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (service as Partial<ConsoleKeyExportD1Service>)[CONSOLE_KEY_EXPORTS_D1_RUNTIME] || null;
}

export async function createD1ConsoleKeyExportService(
  options: D1ConsoleKeyExportServiceOptions,
): Promise<ConsoleKeyExportD1Service> {
  const state: D1ConsoleKeyExportState = {
    database: options.database,
    namespace: ensureNamespace(options.namespace),
    now: options.now || defaultNow,
  };
  if (options.ensureSchema !== false) {
    await ensureConsoleKeyExportsD1Schema({ database: state.database });
  }
  return new D1ConsoleKeyExportServiceImpl(state);
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


function normalizeString(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return normalized || null;
}

function normalizeRequiredString(value: unknown, field: string): string {
  const normalized = normalizeString(value);
  if (!normalized) {
    throw new ConsoleKeyExportError('invalid_body', 400, `${field} is required`);
  }
  return normalized;
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = secureRandomBase36(8, 'console IDs');
  return `${prefix}_${ts}_${rand}`;
}

function parseStringArray(raw: unknown): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of parseJsonArray(raw)) {
    const value = String(entry || '').trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

function normalizeStringArray(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return parseStringArray(raw);
}

function normalizeConstraints(
  input: Partial<ConsoleKeyExportConstraints> | undefined,
): ConsoleKeyExportConstraints {
  return {
    roles: normalizeStringArray(input?.roles),
    chains: normalizeStringArray(input?.chains),
    walletTypes: normalizeStringArray(input?.walletTypes),
    environmentIds: normalizeStringArray(input?.environmentIds),
  };
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

function parseMode(raw: unknown): ConsoleKeyExportMode {
  const value = String(raw || '').trim();
  switch (value) {
    case 'DISABLED':
    case 'ALLOWED_WITH_CONSTRAINTS':
    case 'APPROVAL_REQUIRED':
      return value;
    default:
      return 'APPROVAL_REQUIRED';
  }
}

function parseStatus(raw: unknown): ConsoleKeyExportStatus {
  const value = String(raw || '').trim();
  switch (value) {
    case 'APPROVED':
    case 'REJECTED':
    case 'EXECUTED':
    case 'CANCELED':
    case 'PENDING_APPROVAL':
      return value;
    default:
      return 'PENDING_APPROVAL';
  }
}

function parseApproval(raw: unknown): ConsoleKeyExportApproval | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const approverUserId = String(row.approverUserId || '').trim();
  const approvedAt = String(row.approvedAt || '').trim();
  if (!approverUserId || !approvedAt) return null;
  return {
    approverUserId,
    approvedAt,
    reason: String(row.reason || '').trim(),
    mfaVerified: row.mfaVerified === true || row.mfaVerified === 1,
  };
}

function parseApprovals(raw: unknown): ConsoleKeyExportApproval[] {
  const out: ConsoleKeyExportApproval[] = [];
  for (const entry of parseJsonArray(raw)) {
    const approval = parseApproval(entry);
    if (approval) out.push(approval);
  }
  return out;
}

function parseRecordRow(row: D1Row): ConsoleKeyExportRequestRecord {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    environmentId: String(row.environment_id || ''),
    walletId: normalizeString(row.wallet_id),
    mode: parseMode(row.mode),
    status: parseStatus(row.status),
    reason: String(row.reason || ''),
    requestedByUserId: String(row.requested_by_user_id || ''),
    requiredApprovals: Math.max(1, toNumber(row.required_approvals, 1)),
    approvals: parseApprovals(row.approvals_json),
    constraints: parseConstraints(row.constraints_json),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
  };
}


function isD1ConstraintError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes('UNIQUE constraint failed') || message.includes('constraint failed');
}

function buildListQuery(input: {
  readonly namespace: string;
  readonly orgId: string;
  readonly request: ListConsoleKeyExportsRequest;
}): KeyExportListQuery {
  const clauses = ['namespace = ?', 'org_id = ?'];
  const values: unknown[] = [input.namespace, input.orgId];
  const environmentId = normalizeString(input.request.environmentId);
  if (environmentId) {
    clauses.push('environment_id = ?');
    values.push(environmentId);
  }
  const status = normalizeString(input.request.status);
  if (status) {
    clauses.push('status = ?');
    values.push(status);
  }
  return {
    whereSql: clauses.join(' AND '),
    values,
  };
}

function ensureApprovalAllowed(input: {
  readonly record: ConsoleKeyExportRequestRecord;
  readonly exportId: string;
  readonly actorUserId: string;
  readonly request: ApproveConsoleKeyExportRequest;
}): void {
  if (input.record.status !== 'PENDING_APPROVAL') {
    throw new ConsoleKeyExportError(
      'invalid_state',
      409,
      `Key export request ${input.exportId} is not pending approval`,
    );
  }
  if (!input.request.mfaVerified) {
    throw new ConsoleKeyExportError(
      'mfa_required',
      400,
      'MFA is required to approve key export requests',
    );
  }
  if (input.record.approvals.some((entry) => entry.approverUserId === input.actorUserId)) {
    throw new ConsoleKeyExportError(
      'already_approved',
      409,
      `User ${input.actorUserId} already approved key export request ${input.exportId}`,
    );
  }
}

class D1ConsoleKeyExportServiceImpl implements ConsoleKeyExportD1Service {
  readonly [CONSOLE_KEY_EXPORTS_D1_RUNTIME]: ConsoleKeyExportsD1Runtime;

  private readonly state: D1ConsoleKeyExportState;

  constructor(state: D1ConsoleKeyExportState) {
    this.state = state;
    this[CONSOLE_KEY_EXPORTS_D1_RUNTIME] = {
      database: state.database,
      namespace: state.namespace,
      now: state.now,
    };
    this.listKeyExports = this.listKeyExports.bind(this);
    this.createKeyExport = this.createKeyExport.bind(this);
    this.approveKeyExport = this.approveKeyExport.bind(this);
  }

  async listKeyExports(
    ctx: ConsoleKeyExportsContext,
    request: ListConsoleKeyExportsRequest = {},
  ): Promise<ConsoleKeyExportRequestRecord[]> {
    const query = buildListQuery({
      namespace: this.state.namespace,
      orgId: ctx.orgId,
      request,
    });
    const out = await this.state.database
      .prepare(
        `SELECT *
           FROM key_exports
          WHERE ${query.whereSql}
          ORDER BY updated_at_ms DESC, created_at_ms DESC`,
      )
      .bind(...query.values)
      .all<D1Row>();
    return (out.results || []).map((row) => parseRecordRow(row));
  }

  async createKeyExport(
    ctx: ConsoleKeyExportsContext,
    request: CreateConsoleKeyExportRequest,
  ): Promise<ConsoleKeyExportRequestRecord> {
    const now = this.state.now();
    const createdAtMs = nowMs(now);
    const id = normalizeString(request.id) || makeId('ke', now);
    const record = {
      id,
      environmentId: normalizeRequiredString(request.environmentId, 'environmentId'),
      walletId: normalizeString(request.walletId),
      mode: request.mode || 'APPROVAL_REQUIRED',
      reason: normalizeRequiredString(request.reason, 'reason'),
      requiredApprovals: Math.max(1, Math.floor(toNumber(request.requiredApprovals, 2))),
      constraints: normalizeConstraints(request.constraints),
    };
    try {
      await this.state.database
        .prepare(
          `INSERT INTO key_exports
            (namespace, org_id, id, environment_id, wallet_id, mode, status, reason, requested_by_user_id, required_approvals, approvals_json, constraints_json, created_at_ms, updated_at_ms)
           VALUES
            (?, ?, ?, ?, ?, ?, 'PENDING_APPROVAL', ?, ?, ?, '[]', ?, ?, ?)`,
        )
        .bind(
          this.state.namespace,
          ctx.orgId,
          record.id,
          record.environmentId,
          record.walletId,
          record.mode,
          record.reason,
          ctx.actorUserId,
          record.requiredApprovals,
          JSON.stringify(record.constraints),
          createdAtMs,
          createdAtMs,
        )
        .run();
    } catch (error: unknown) {
      if (isD1ConstraintError(error)) {
        throw new ConsoleKeyExportError(
          'key_export_exists',
          409,
          `Key export request ${record.id} already exists`,
        );
      }
      throw error;
    }
    const created = await this.findKeyExport(ctx.orgId, record.id);
    if (!created) {
      throw new ConsoleKeyExportError('internal', 500, 'Failed to create key export request');
    }
    return created;
  }

  async approveKeyExport(
    ctx: ConsoleKeyExportsContext,
    exportId: string,
    request: ApproveConsoleKeyExportRequest,
  ): Promise<ConsoleKeyExportRequestRecord | null> {
    for (let attempt = 0; attempt < MAX_CONDITIONAL_RETRIES; attempt += 1) {
      const current = await this.findKeyExport(ctx.orgId, exportId);
      if (!current) return null;
      ensureApprovalAllowed({
        record: current,
        exportId,
        actorUserId: ctx.actorUserId,
        request,
      });
      const approvedAtMs = nowMs(this.state.now());
      const approval: ConsoleKeyExportApproval = {
        approverUserId: ctx.actorUserId,
        approvedAt: toIso(approvedAtMs),
        reason: request.reason,
        mfaVerified: true,
      };
      const nextApprovals = [...current.approvals, approval];
      const nextStatus: ConsoleKeyExportStatus =
        nextApprovals.length >= current.requiredApprovals ? 'APPROVED' : 'PENDING_APPROVAL';
      const updated = await this.applyApproval({
        current,
        nextApprovals,
        nextStatus,
        updatedAtMs: approvedAtMs,
      });
      if (updated) return updated;
    }
    return await this.resolveStaleApproval(ctx, exportId, request);
  }

  private async findKeyExport(
    orgId: string,
    exportId: string,
  ): Promise<ConsoleKeyExportRequestRecord | null> {
    const row = await this.state.database
      .prepare(
        `SELECT *
           FROM key_exports
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?`,
      )
      .bind(this.state.namespace, orgId, exportId)
      .first<D1Row>();
    return row ? parseRecordRow(row) : null;
  }

  private async applyApproval(input: {
    readonly current: ConsoleKeyExportRequestRecord;
    readonly nextApprovals: readonly ConsoleKeyExportApproval[];
    readonly nextStatus: ConsoleKeyExportStatus;
    readonly updatedAtMs: number;
  }): Promise<ConsoleKeyExportRequestRecord | null> {
    const currentApprovalsJson = JSON.stringify(input.current.approvals);
    const result = await this.state.database
      .prepare(
        `UPDATE key_exports
            SET approvals_json = ?,
                status = ?,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?
            AND status = 'PENDING_APPROVAL'
            AND approvals_json = ?`,
      )
      .bind(
        JSON.stringify(input.nextApprovals),
        input.nextStatus,
        input.updatedAtMs,
        this.state.namespace,
        input.current.orgId,
        input.current.id,
        currentApprovalsJson,
      )
      .run();
    if (d1ChangedRows(result) !== 1) return null;
    return await this.findKeyExport(input.current.orgId, input.current.id);
  }

  private async resolveStaleApproval(
    ctx: ConsoleKeyExportsContext,
    exportId: string,
    request: ApproveConsoleKeyExportRequest,
  ): Promise<ConsoleKeyExportRequestRecord | null> {
    const current = await this.findKeyExport(ctx.orgId, exportId);
    if (!current) return null;
    ensureApprovalAllowed({
      record: current,
      exportId,
      actorUserId: ctx.actorUserId,
      request,
    });
    throw new ConsoleKeyExportError(
      'conflict',
      409,
      `Key export request ${exportId} changed while recording the approval`,
    );
  }
}
