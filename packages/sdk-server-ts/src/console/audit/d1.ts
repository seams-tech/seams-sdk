import { secureRandomBase36 } from '@shared/utils/secureRandomId';
import {
  d1Integer as toNumber,
  formatD1ExecStatement,
  parseD1JsonArrayColumn as parseJsonArray,
  parseD1JsonObjectColumn as parseJsonObject,
  type D1Row,
} from '../../storage/d1Sql';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
import { ConsoleAuditError } from './errors';
import type { ConsoleAuditContext, ConsoleAuditService } from './service';
import type {
  AppendConsoleAuditEvidenceRequest,
  AppendConsoleAuditEventRequest,
  ConsoleAuditActorType,
  ConsoleAuditCategory,
  ConsoleAuditEvidenceDomain,
  ConsoleAuditEvidenceRecord,
  ConsoleAuditEvidenceReference,
  ConsoleAuditEvidenceReferenceKind,
  ConsoleAuditEvent,
  ConsoleAuditOutcome,
  ListConsoleAuditEventsRequest,
  ListConsoleAuditEvidenceRequest,
} from './types';


const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

const AUDIT_ACTOR_TYPES = new Set<ConsoleAuditActorType>(['USER', 'SYSTEM']);
const AUDIT_CATEGORIES = new Set<ConsoleAuditCategory>([
  'POLICY',
  'SETTINGS',
  'KEY_EXPORT',
  'BILLING',
  'WEBHOOK',
  'API_KEY',
  'TEAM',
  'APPROVAL',
  'ORG_PROJECT_ENV',
  'RUNTIME_SNAPSHOT',
  'SYSTEM',
]);
const AUDIT_OUTCOMES = new Set<ConsoleAuditOutcome>(['SUCCESS', 'FAILURE', 'PENDING']);
const AUDIT_EVIDENCE_DOMAINS = new Set<ConsoleAuditEvidenceDomain>([
  'POLICY',
  'BILLING',
  'KEY_EXPORT',
  'SECURITY',
]);
const AUDIT_EVIDENCE_REFERENCE_KINDS = new Set<ConsoleAuditEvidenceReferenceKind>([
  'LOG',
  'EXPORT',
  'PAYMENT',
  'APPROVAL',
]);

interface D1ConsoleAuditState {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

type AuditQueryParts = {
  readonly whereSql: string;
  readonly values: readonly unknown[];
  readonly limit: number;
};

export const CONSOLE_AUDIT_D1_RUNTIME = Symbol('consoleAuditD1Runtime');

export interface ConsoleAuditD1Runtime {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

export type ConsoleAuditD1Service = ConsoleAuditService & {
  readonly [CONSOLE_AUDIT_D1_RUNTIME]: ConsoleAuditD1Runtime;
};

export interface D1ConsoleAuditSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1ConsoleAuditServiceOptions {
  readonly database: D1DatabaseLike;
  readonly namespace?: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
}

export const CONSOLE_AUDIT_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS audit_events (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      project_id TEXT,
      environment_id TEXT,
      actor_user_id TEXT NOT NULL,
      actor_type TEXT NOT NULL,
      category TEXT NOT NULL,
      action TEXT NOT NULL,
      outcome TEXT NOT NULL,
      summary TEXT NOT NULL,
      metadata_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, id),
      CHECK (actor_type IN ('USER', 'SYSTEM')),
      CHECK (category IN ('POLICY', 'SETTINGS', 'KEY_EXPORT', 'BILLING', 'WEBHOOK', 'API_KEY', 'TEAM', 'APPROVAL', 'ORG_PROJECT_ENV', 'RUNTIME_SNAPSHOT', 'SYSTEM')),
      CHECK (outcome IN ('SUCCESS', 'FAILURE', 'PENDING')),
      CHECK (json_valid(metadata_json))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS audit_events_org_created_idx
      ON audit_events (namespace, org_id, created_at_ms DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS audit_events_org_category_idx
      ON audit_events (namespace, org_id, category, created_at_ms DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS audit_events_org_outcome_idx
      ON audit_events (namespace, org_id, outcome, created_at_ms DESC)
  `,
  `
    CREATE TABLE IF NOT EXISTS audit_evidence (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      project_id TEXT,
      environment_id TEXT,
      domain TEXT NOT NULL,
      title TEXT NOT NULL,
      summary TEXT NOT NULL,
      event_ids_json TEXT NOT NULL,
      references_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, id),
      CHECK (domain IN ('POLICY', 'BILLING', 'KEY_EXPORT', 'SECURITY')),
      CHECK (json_valid(event_ids_json)),
      CHECK (json_valid(references_json))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS audit_evidence_org_created_idx
      ON audit_evidence (namespace, org_id, created_at_ms DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS audit_evidence_org_domain_idx
      ON audit_evidence (namespace, org_id, domain, created_at_ms DESC)
  `,
] as const);

export async function ensureConsoleAuditD1Schema(
  options: D1ConsoleAuditSchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_AUDIT_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export function getConsoleAuditD1Runtime(
  service: ConsoleAuditService | null | undefined,
): ConsoleAuditD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (service as Partial<ConsoleAuditD1Service>)[CONSOLE_AUDIT_D1_RUNTIME] || null;
}

export async function createD1ConsoleAuditService(
  options: D1ConsoleAuditServiceOptions,
): Promise<ConsoleAuditD1Service> {
  const state: D1ConsoleAuditState = {
    database: options.database,
    namespace: ensureNamespace(options.namespace),
    now: options.now || defaultNow,
  };
  if (options.ensureSchema !== false) {
    await ensureConsoleAuditD1Schema({ database: state.database });
  }
  return new D1ConsoleAuditServiceImpl(state) as ConsoleAuditD1Service;
}

function defaultNow(): Date {
  return new Date();
}

function ensureNamespace(namespace: string | undefined): string {
  const normalized = String(namespace || 'default').trim();
  return normalized || 'default';
}

function makeId(prefix: string, now: Date): string {
  return `${prefix}_${now.getTime().toString(36)}_${secureRandomBase36(8, 'console IDs')}`;
}

function nowMs(now: Date): number {
  return now.getTime();
}

function toIso(ms: number): string {
  return new Date(ms).toISOString();
}


function normalizeString(raw: unknown): string {
  return String(raw || '').trim();
}

function toNullableString(raw: unknown): string | null {
  const value = normalizeString(raw);
  return value || null;
}

function parseActorType(raw: unknown): ConsoleAuditActorType {
  const value = normalizeString(raw).toUpperCase() as ConsoleAuditActorType;
  return AUDIT_ACTOR_TYPES.has(value) ? value : 'USER';
}

function parseCategory(raw: unknown): ConsoleAuditCategory {
  const value = normalizeString(raw).toUpperCase() as ConsoleAuditCategory;
  return AUDIT_CATEGORIES.has(value) ? value : 'SYSTEM';
}

function parseOutcome(raw: unknown): ConsoleAuditOutcome {
  const value = normalizeString(raw).toUpperCase() as ConsoleAuditOutcome;
  return AUDIT_OUTCOMES.has(value) ? value : 'SUCCESS';
}

function parseDomain(raw: unknown): ConsoleAuditEvidenceDomain {
  const value = normalizeString(raw).toUpperCase() as ConsoleAuditEvidenceDomain;
  return AUDIT_EVIDENCE_DOMAINS.has(value) ? value : 'SECURITY';
}

function parseReference(raw: unknown): ConsoleAuditEvidenceReference | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const kind = normalizeString(row.kind).toUpperCase() as ConsoleAuditEvidenceReferenceKind;
  if (!AUDIT_EVIDENCE_REFERENCE_KINDS.has(kind)) return null;
  const referenceId = normalizeString(row.referenceId);
  const label = normalizeString(row.label);
  if (!referenceId || !label) return null;
  return { kind, referenceId, label };
}

function parseReferences(raw: unknown): ConsoleAuditEvidenceReference[] {
  const out: ConsoleAuditEvidenceReference[] = [];
  for (const entry of parseJsonArray(raw)) {
    const parsed = parseReference(entry);
    if (parsed) out.push(parsed);
  }
  return out;
}

function parseEventIds(raw: unknown): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of parseJsonArray(raw)) {
    const value = normalizeString(entry);
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

function parseEventRow(row: D1Row): ConsoleAuditEvent {
  return {
    id: normalizeString(row.id),
    orgId: normalizeString(row.org_id),
    ...(toNullableString(row.project_id) ? { projectId: toNullableString(row.project_id)! } : {}),
    ...(toNullableString(row.environment_id)
      ? { environmentId: toNullableString(row.environment_id)! }
      : {}),
    actorUserId: normalizeString(row.actor_user_id),
    actorType: parseActorType(row.actor_type),
    category: parseCategory(row.category),
    action: normalizeString(row.action),
    outcome: parseOutcome(row.outcome),
    summary: normalizeString(row.summary),
    metadata: parseJsonObject(row.metadata_json),
    createdAt: toIso(toNumber(row.created_at_ms)),
  };
}

function parseEvidenceRow(row: D1Row): ConsoleAuditEvidenceRecord {
  return {
    id: normalizeString(row.id),
    orgId: normalizeString(row.org_id),
    ...(toNullableString(row.project_id) ? { projectId: toNullableString(row.project_id)! } : {}),
    ...(toNullableString(row.environment_id)
      ? { environmentId: toNullableString(row.environment_id)! }
      : {}),
    domain: parseDomain(row.domain),
    title: normalizeString(row.title),
    summary: normalizeString(row.summary),
    eventIds: parseEventIds(row.event_ids_json),
    references: parseReferences(row.references_json),
    createdAt: toIso(toNumber(row.created_at_ms)),
  };
}

function normalizeLimit(raw: unknown): number {
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) return DEFAULT_LIMIT;
  return Math.min(Math.floor(value), MAX_LIMIT);
}

function toTimestampMs(raw: unknown): number | null {
  const value = normalizeString(raw);
  if (!value) return null;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? Math.floor(timestamp) : null;
}

function toEscapedLikePattern(raw: unknown): string | null {
  const value = normalizeString(raw).toLowerCase();
  if (!value) return null;
  return `%${value.replace(/[\\%_]/g, '\\$&')}%`;
}

function ensureCategory(raw: unknown): ConsoleAuditCategory {
  const value = normalizeString(raw).toUpperCase() as ConsoleAuditCategory;
  if (!AUDIT_CATEGORIES.has(value)) {
    throw new ConsoleAuditError('invalid_body', 400, 'Field category is invalid');
  }
  return value;
}

function ensureOutcome(raw: unknown): ConsoleAuditOutcome {
  const value = normalizeString(raw).toUpperCase() as ConsoleAuditOutcome;
  if (!AUDIT_OUTCOMES.has(value)) {
    throw new ConsoleAuditError('invalid_body', 400, 'Field outcome is invalid');
  }
  return value;
}

function ensureDomain(raw: unknown): ConsoleAuditEvidenceDomain {
  const value = normalizeString(raw).toUpperCase() as ConsoleAuditEvidenceDomain;
  if (!AUDIT_EVIDENCE_DOMAINS.has(value)) {
    throw new ConsoleAuditError('invalid_body', 400, 'Field domain is invalid');
  }
  return value;
}

function ensureActorType(raw: unknown): ConsoleAuditActorType {
  const value = normalizeString(raw).toUpperCase() as ConsoleAuditActorType;
  if (!AUDIT_ACTOR_TYPES.has(value)) {
    throw new ConsoleAuditError('invalid_body', 400, 'Field actorType is invalid');
  }
  return value;
}

function ensureSummary(field: string, raw: unknown): string {
  const value = normalizeString(raw);
  if (!value) {
    throw new ConsoleAuditError('invalid_body', 400, `Field ${field} is required`);
  }
  if (value.length > 1024) {
    throw new ConsoleAuditError(
      'invalid_body',
      400,
      `Field ${field} must be 1024 characters or less`,
    );
  }
  return value;
}

function ensureMetadataObject(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  return { ...(raw as Record<string, unknown>) };
}

function ensureReferences(raw: unknown): ConsoleAuditEvidenceReference[] {
  if (!Array.isArray(raw)) return [];
  const out: ConsoleAuditEvidenceReference[] = [];
  const seen = new Set<string>();
  for (const entryRaw of raw) {
    const entry = parseReference(entryRaw);
    if (!entry) continue;
    const key = `${entry.kind}:${entry.referenceId}:${entry.label}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(entry);
  }
  return out;
}

function ensureEventIds(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entryRaw of raw) {
    const value = normalizeString(entryRaw);
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
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

function appendTimestampRangeFilter(
  input: {
    readonly clauses: string[];
    readonly values: unknown[];
  },
  column: string,
  from: unknown,
  to: unknown,
): void {
  const fromTs = toTimestampMs(from);
  if (fromTs !== null) {
    input.clauses.push(`${column} >= ?`);
    input.values.push(fromTs);
  }
  const toTs = toTimestampMs(to);
  if (toTs !== null) {
    input.clauses.push(`${column} <= ?`);
    input.values.push(toTs);
  }
}

function buildEventQueryParts(
  namespace: string,
  orgId: string,
  request: ListConsoleAuditEventsRequest,
): AuditQueryParts {
  const clauses = ['namespace = ?', 'org_id = ?'];
  const values: unknown[] = [namespace, orgId];
  appendEqualsFilter({ clauses, values }, 'project_id', request.projectId);
  appendEqualsFilter({ clauses, values }, 'environment_id', request.environmentId);
  appendEqualsFilter({ clauses, values }, 'category', request.category);
  appendEqualsFilter({ clauses, values }, 'actor_user_id', request.actorUserId);
  appendEqualsFilter({ clauses, values }, 'outcome', request.outcome);
  appendEventSearchFilter({ clauses, values }, request.q);
  appendTimestampRangeFilter({ clauses, values }, 'created_at_ms', request.from, request.to);
  return {
    whereSql: clauses.join(' AND '),
    values,
    limit: normalizeLimit(request.limit),
  };
}

function buildEvidenceQueryParts(
  namespace: string,
  orgId: string,
  request: ListConsoleAuditEvidenceRequest,
): AuditQueryParts {
  const clauses = ['namespace = ?', 'org_id = ?'];
  const values: unknown[] = [namespace, orgId];
  appendEqualsFilter({ clauses, values }, 'project_id', request.projectId);
  appendEqualsFilter({ clauses, values }, 'environment_id', request.environmentId);
  appendEqualsFilter({ clauses, values }, 'domain', request.domain);
  appendTimestampRangeFilter({ clauses, values }, 'created_at_ms', request.from, request.to);
  return {
    whereSql: clauses.join(' AND '),
    values,
    limit: normalizeLimit(request.limit),
  };
}

function appendEventSearchFilter(
  input: {
    readonly clauses: string[];
    readonly values: unknown[];
  },
  rawQuery: unknown,
): void {
  const searchPattern = toEscapedLikePattern(rawQuery);
  if (!searchPattern) return;
  input.clauses.push(
    `(LOWER(id) LIKE ? ESCAPE '\\' OR LOWER(COALESCE(project_id, '')) LIKE ? ESCAPE '\\' OR LOWER(COALESCE(environment_id, '')) LIKE ? ESCAPE '\\' OR LOWER(actor_user_id) LIKE ? ESCAPE '\\' OR LOWER(action) LIKE ? ESCAPE '\\' OR LOWER(summary) LIKE ? ESCAPE '\\' OR LOWER(category) LIKE ? ESCAPE '\\' OR LOWER(outcome) LIKE ? ESCAPE '\\' OR LOWER(metadata_json) LIKE ? ESCAPE '\\')`,
  );
  for (let index = 0; index < 9; index += 1) {
    input.values.push(searchPattern);
  }
}

class D1ConsoleAuditServiceImpl implements ConsoleAuditService {
  readonly [CONSOLE_AUDIT_D1_RUNTIME]: ConsoleAuditD1Runtime;

  private readonly state: D1ConsoleAuditState;

  constructor(state: D1ConsoleAuditState) {
    this.state = state;
    this[CONSOLE_AUDIT_D1_RUNTIME] = {
      database: state.database,
      namespace: state.namespace,
      now: state.now,
    };
    this.listEvents = this.listEvents.bind(this);
    this.listEvidence = this.listEvidence.bind(this);
    this.appendEvent = this.appendEvent.bind(this);
    this.appendEvidence = this.appendEvidence.bind(this);
  }

  async listEvents(
    ctx: ConsoleAuditContext,
    request: ListConsoleAuditEventsRequest = {},
  ): Promise<ConsoleAuditEvent[]> {
    const query = buildEventQueryParts(this.state.namespace, ctx.orgId, request);
    const out = await this.state.database
      .prepare(
        `SELECT *
           FROM audit_events
          WHERE ${query.whereSql}
          ORDER BY created_at_ms DESC, id DESC
          LIMIT ?`,
      )
      .bind(...query.values, query.limit)
      .all<D1Row>();
    return (out.results || []).map((row) => parseEventRow(row));
  }

  async listEvidence(
    ctx: ConsoleAuditContext,
    request: ListConsoleAuditEvidenceRequest = {},
  ): Promise<ConsoleAuditEvidenceRecord[]> {
    const query = buildEvidenceQueryParts(this.state.namespace, ctx.orgId, request);
    const out = await this.state.database
      .prepare(
        `SELECT *
           FROM audit_evidence
          WHERE ${query.whereSql}
          ORDER BY created_at_ms DESC, id DESC
          LIMIT ?`,
      )
      .bind(...query.values, query.limit)
      .all<D1Row>();
    return (out.results || []).map((row) => parseEvidenceRow(row));
  }

  async appendEvent(
    ctx: ConsoleAuditContext,
    request: AppendConsoleAuditEventRequest,
  ): Promise<ConsoleAuditEvent> {
    const now = this.state.now();
    const id = normalizeString(request.id) || makeId('aud', now);
    const createdAtMs = nowMs(now);
    const event = this.buildEvent({ ctx, request, id, createdAtMs });
    try {
      await this.state.database
        .prepare(
          `INSERT INTO audit_events
            (namespace, org_id, id, project_id, environment_id, actor_user_id, actor_type, category, action, outcome, summary, metadata_json, created_at_ms)
           VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          this.state.namespace,
          event.orgId,
          event.id,
          event.projectId || null,
          event.environmentId || null,
          event.actorUserId,
          event.actorType,
          event.category,
          event.action,
          event.outcome,
          event.summary,
          JSON.stringify(event.metadata),
          createdAtMs,
        )
        .run();
    } catch (error: unknown) {
      if (isD1ConstraintError(error)) {
        throw new ConsoleAuditError(
          'event_already_exists',
          409,
          `Audit event ${id} already exists`,
        );
      }
      throw error;
    }
    return event;
  }

  async appendEvidence(
    ctx: ConsoleAuditContext,
    request: AppendConsoleAuditEvidenceRequest,
  ): Promise<ConsoleAuditEvidenceRecord> {
    const now = this.state.now();
    const id = normalizeString(request.id) || makeId('evd', now);
    const createdAtMs = nowMs(now);
    const evidence = this.buildEvidence({ ctx, request, id, createdAtMs });
    try {
      await this.state.database
        .prepare(
          `INSERT INTO audit_evidence
            (namespace, org_id, id, project_id, environment_id, domain, title, summary, event_ids_json, references_json, created_at_ms)
           VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          this.state.namespace,
          evidence.orgId,
          evidence.id,
          evidence.projectId || null,
          evidence.environmentId || null,
          evidence.domain,
          evidence.title,
          evidence.summary,
          JSON.stringify(evidence.eventIds),
          JSON.stringify(evidence.references),
          createdAtMs,
        )
        .run();
    } catch (error: unknown) {
      if (isD1ConstraintError(error)) {
        throw new ConsoleAuditError(
          'evidence_already_exists',
          409,
          `Audit evidence ${id} already exists`,
        );
      }
      throw error;
    }
    return evidence;
  }

  private buildEvent(input: {
    readonly ctx: ConsoleAuditContext;
    readonly request: AppendConsoleAuditEventRequest;
    readonly id: string;
    readonly createdAtMs: number;
  }): ConsoleAuditEvent {
    const actorUserId =
      normalizeString(input.request.actorUserId) || normalizeString(input.ctx.actorUserId);
    if (!actorUserId) {
      throw new ConsoleAuditError('invalid_body', 400, 'Field actorUserId is required');
    }
    const projectId = toNullableString(input.request.projectId);
    const environmentId = toNullableString(input.request.environmentId);
    return {
      id: input.id,
      orgId: input.ctx.orgId,
      ...(projectId ? { projectId } : {}),
      ...(environmentId ? { environmentId } : {}),
      actorUserId,
      actorType: input.request.actorType ? ensureActorType(input.request.actorType) : 'USER',
      category: ensureCategory(input.request.category),
      action: ensureSummary('action', input.request.action),
      outcome: ensureOutcome(input.request.outcome),
      summary: ensureSummary('summary', input.request.summary),
      metadata: ensureMetadataObject(input.request.metadata),
      createdAt: toIso(input.createdAtMs),
    };
  }

  private buildEvidence(input: {
    readonly ctx: ConsoleAuditContext;
    readonly request: AppendConsoleAuditEvidenceRequest;
    readonly id: string;
    readonly createdAtMs: number;
  }): ConsoleAuditEvidenceRecord {
    const projectId = toNullableString(input.request.projectId);
    const environmentId = toNullableString(input.request.environmentId);
    return {
      id: input.id,
      orgId: input.ctx.orgId,
      ...(projectId ? { projectId } : {}),
      ...(environmentId ? { environmentId } : {}),
      domain: ensureDomain(input.request.domain),
      title: ensureSummary('title', input.request.title),
      summary: ensureSummary('summary', input.request.summary),
      eventIds: ensureEventIds(input.request.eventIds),
      references: ensureReferences(input.request.references),
      createdAt: toIso(input.createdAtMs),
    };
  }
}
