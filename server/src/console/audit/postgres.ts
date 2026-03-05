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

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_AUDIT_MIGRATION_LOCK_ID = 9452360123621;
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
  return parseJsonArray(raw)
    .map((entry) => parseReference(entry))
    .filter((entry): entry is ConsoleAuditEvidenceReference => entry !== null);
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

function parseEventRow(row: PgRow): ConsoleAuditEvent {
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
    metadata: parseJsonObject(row.metadata),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
  };
}

function parseEvidenceRow(row: PgRow): ConsoleAuditEvidenceRecord {
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
    eventIds: parseEventIds(row.event_ids),
    references: parseReferences(row.references),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
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
  if (!Number.isFinite(timestamp)) return null;
  return timestamp;
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
    throw new ConsoleAuditError('invalid_body', 400, `Field ${field} must be 1024 characters or less`);
  }
  return value;
}

function ensureMetadataObject(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  return { ...(raw as Record<string, unknown>) };
}

function ensureReferences(
  raw: unknown,
): ConsoleAuditEvidenceReference[] {
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

function isUniqueViolation(error: unknown): boolean {
  return !!error && typeof error === 'object' && (error as any).code === '23505';
}

export interface PostgresConsoleAuditSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleAuditPostgresSchema(
  options: PostgresConsoleAuditSchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_AUDIT_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_audit_events (
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
        metadata JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id, id),
        CHECK (actor_type IN ('USER', 'SYSTEM')),
        CHECK (category IN ('POLICY', 'SETTINGS', 'KEY_EXPORT', 'BILLING', 'WEBHOOK', 'API_KEY', 'TEAM', 'APPROVAL', 'ORG_PROJECT_ENV', 'RUNTIME_SNAPSHOT', 'SYSTEM')),
        CHECK (outcome IN ('SUCCESS', 'FAILURE', 'PENDING')),
        CHECK (jsonb_typeof(metadata) = 'object')
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_audit_evidence (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        id TEXT NOT NULL,
        project_id TEXT,
        environment_id TEXT,
        domain TEXT NOT NULL,
        title TEXT NOT NULL,
        summary TEXT NOT NULL,
        event_ids JSONB NOT NULL,
        "references" JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id, id),
        CHECK (domain IN ('POLICY', 'BILLING', 'KEY_EXPORT', 'SECURITY')),
        CHECK (jsonb_typeof(event_ids) = 'array'),
        CHECK (jsonb_typeof("references") = 'array')
      )
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_audit_events_org_created_idx
      ON console_audit_events (namespace, org_id, created_at_ms DESC, id DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_audit_events_org_category_idx
      ON console_audit_events (namespace, org_id, category, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_audit_events_org_outcome_idx
      ON console_audit_events (namespace, org_id, outcome, created_at_ms DESC)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_audit_evidence_org_created_idx
      ON console_audit_evidence (namespace, org_id, created_at_ms DESC, id DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_audit_evidence_org_domain_idx
      ON console_audit_evidence (namespace, org_id, domain, created_at_ms DESC)
    `);

    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_audit_events',
      policyName: 'console_audit_events_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_audit_evidence',
      policyName: 'console_audit_evidence_tenant_rls',
    });
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_AUDIT_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }

  options.logger.info('[console-audit][postgres] Schema ready');
}

export interface PostgresConsoleAuditServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
}

export async function createPostgresConsoleAuditService(
  options: PostgresConsoleAuditServiceOptions,
): Promise<ConsoleAuditService> {
  const postgresUrl = normalizeString(options.postgresUrl);
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres console audit service');
  }

  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const nowFn = options.now || (() => new Date());

  if (options.ensureSchema !== false) {
    await ensureConsoleAuditPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);

  const withTenantTx = <T>(
    ctx: ConsoleAuditContext,
    fn: (q: Queryable) => Promise<T>,
  ): Promise<T> =>
    withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, fn);

  async function listEvents(
    ctx: ConsoleAuditContext,
    request: ListConsoleAuditEventsRequest = {},
  ): Promise<ConsoleAuditEvent[]> {
    const where: string[] = ['namespace = $1', 'org_id = $2'];
    const values: unknown[] = [namespace, ctx.orgId];
    let valueIndex = values.length;

    const pushEq = (column: string, raw: unknown): void => {
      const value = normalizeString(raw);
      if (!value) return;
      valueIndex += 1;
      values.push(value);
      where.push(`${column} = $${valueIndex}`);
    };

    pushEq('project_id', request.projectId);
    pushEq('environment_id', request.environmentId);
    pushEq('category', request.category);
    pushEq('actor_user_id', request.actorUserId);
    pushEq('outcome', request.outcome);

    const fromTs = toTimestampMs(request.from);
    if (fromTs !== null) {
      valueIndex += 1;
      values.push(fromTs);
      where.push(`created_at_ms >= $${valueIndex}`);
    }
    const toTs = toTimestampMs(request.to);
    if (toTs !== null) {
      valueIndex += 1;
      values.push(toTs);
      where.push(`created_at_ms <= $${valueIndex}`);
    }

    valueIndex += 1;
    values.push(normalizeLimit(request.limit));

    return withTenantTx(ctx, async (q) => {
      const out = await q.query(
        `SELECT *
           FROM console_audit_events
          WHERE ${where.join(' AND ')}
          ORDER BY created_at_ms DESC, id DESC
          LIMIT $${valueIndex}`,
        values,
      );
      return out.rows.map((row) => parseEventRow(row as PgRow));
    });
  }

  async function listEvidence(
    ctx: ConsoleAuditContext,
    request: ListConsoleAuditEvidenceRequest = {},
  ): Promise<ConsoleAuditEvidenceRecord[]> {
    const where: string[] = ['namespace = $1', 'org_id = $2'];
    const values: unknown[] = [namespace, ctx.orgId];
    let valueIndex = values.length;

    const pushEq = (column: string, raw: unknown): void => {
      const value = normalizeString(raw);
      if (!value) return;
      valueIndex += 1;
      values.push(value);
      where.push(`${column} = $${valueIndex}`);
    };

    pushEq('project_id', request.projectId);
    pushEq('environment_id', request.environmentId);
    pushEq('domain', request.domain);

    const fromTs = toTimestampMs(request.from);
    if (fromTs !== null) {
      valueIndex += 1;
      values.push(fromTs);
      where.push(`created_at_ms >= $${valueIndex}`);
    }
    const toTs = toTimestampMs(request.to);
    if (toTs !== null) {
      valueIndex += 1;
      values.push(toTs);
      where.push(`created_at_ms <= $${valueIndex}`);
    }

    valueIndex += 1;
    values.push(normalizeLimit(request.limit));

    return withTenantTx(ctx, async (q) => {
      const out = await q.query(
        `SELECT *
           FROM console_audit_evidence
          WHERE ${where.join(' AND ')}
          ORDER BY created_at_ms DESC, id DESC
          LIMIT $${valueIndex}`,
        values,
      );
      return out.rows.map((row) => parseEvidenceRow(row as PgRow));
    });
  }

  async function appendEvent(
    ctx: ConsoleAuditContext,
    request: AppendConsoleAuditEventRequest,
  ): Promise<ConsoleAuditEvent> {
    const now = nowFn();
    const id = normalizeString(request.id) || makeId('aud', now);
    const category = ensureCategory(request.category);
    const outcome = ensureOutcome(request.outcome);
    const action = ensureSummary('action', request.action);
    const summary = ensureSummary('summary', request.summary);
    const actorUserId = normalizeString(request.actorUserId) || normalizeString(ctx.actorUserId);
    if (!actorUserId) {
      throw new ConsoleAuditError('invalid_body', 400, 'Field actorUserId is required');
    }
    const actorType = request.actorType ? ensureActorType(request.actorType) : 'USER';
    const createdAtMs = nowMs(now);
    const metadata = ensureMetadataObject(request.metadata);

    return withTenantTx(ctx, async (q) => {
      try {
        const out = await q.query(
          `INSERT INTO console_audit_events
            (namespace, org_id, id, project_id, environment_id, actor_user_id, actor_type, category, action, outcome, summary, metadata, created_at_ms)
           VALUES
            ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13)
           RETURNING *`,
          [
            namespace,
            ctx.orgId,
            id,
            toNullableString(request.projectId),
            toNullableString(request.environmentId),
            actorUserId,
            actorType,
            category,
            action,
            outcome,
            summary,
            JSON.stringify(metadata),
            createdAtMs,
          ],
        );
        return parseEventRow((out.rows[0] as PgRow) || {});
      } catch (error: unknown) {
        if (isUniqueViolation(error)) {
          throw new ConsoleAuditError('event_already_exists', 409, `Audit event ${id} already exists`);
        }
        throw error;
      }
    });
  }

  async function appendEvidence(
    ctx: ConsoleAuditContext,
    request: AppendConsoleAuditEvidenceRequest,
  ): Promise<ConsoleAuditEvidenceRecord> {
    const now = nowFn();
    const id = normalizeString(request.id) || makeId('evd', now);
    const domain = ensureDomain(request.domain);
    const title = ensureSummary('title', request.title);
    const summary = ensureSummary('summary', request.summary);
    const eventIds = ensureEventIds(request.eventIds);
    const references = ensureReferences(request.references);
    const createdAtMs = nowMs(now);

    return withTenantTx(ctx, async (q) => {
      try {
        const out = await q.query(
          `INSERT INTO console_audit_evidence
            (namespace, org_id, id, project_id, environment_id, domain, title, summary, event_ids, "references", created_at_ms)
           VALUES
            ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb, $11)
           RETURNING *`,
          [
            namespace,
            ctx.orgId,
            id,
            toNullableString(request.projectId),
            toNullableString(request.environmentId),
            domain,
            title,
            summary,
            JSON.stringify(eventIds),
            JSON.stringify(references),
            createdAtMs,
          ],
        );
        return parseEvidenceRow((out.rows[0] as PgRow) || {});
      } catch (error: unknown) {
        if (isUniqueViolation(error)) {
          throw new ConsoleAuditError(
            'evidence_already_exists',
            409,
            `Audit evidence ${id} already exists`,
          );
        }
        throw error;
      }
    });
  }

  return {
    listEvents,
    listEvidence,
    appendEvent,
    appendEvidence,
  };
}
