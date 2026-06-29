import {
  d1Number as toNumber,
  d1ChangedRows,
  formatD1ExecStatement,
  parseD1JsonObjectColumn as parseJsonObject,
  queryD1All as queryRows,
  queryD1One as queryFirstRow,
  type D1Row,
} from '../../storage/d1Sql';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
import { ConsoleObservabilityError } from './errors';
import { CONSOLE_OBSERVABILITY_SOURCE_SET, CONSOLE_OBSERVABILITY_SOURCES_SQL } from './policy';
import { redactConsoleObservabilityMetadata } from './redaction';
import {
  REQUEST_ROLLUP_BUCKET_COLUMN_NAMES,
  REQUEST_ROLLUP_WINDOW_MS,
  normalizeConsoleObservabilityRequestMetricForInsert,
  percentileFromConsoleObservabilityHistogram,
} from './requestRollups';
import type {
  ConsoleObservabilityContext,
  ConsoleObservabilityService,
  InMemoryConsoleObservabilityServiceOptions,
} from './service';
import type { ConsoleObservabilityIngestionService } from './ingestionService';
import type {
  ConsoleObservabilityEvent,
  ConsoleObservabilityEventEnvelope,
  ConsoleObservabilityEventIngestResult,
  ConsoleObservabilityEventsPage,
  ConsoleObservabilityIngestionContext,
  ConsoleObservabilityLevel,
  ConsoleObservabilityMetadataRedactionPolicy,
  ConsoleObservabilityRequestMetricInput,
  ConsoleObservabilityServiceHealth,
  ConsoleObservabilityServicesView,
  ConsoleObservabilitySource,
  ConsoleObservabilitySummary,
  ConsoleObservabilityTimeseries,
  ConsoleObservabilityTimeseriesBucket,
  GetConsoleObservabilitySummaryRequest,
  GetConsoleObservabilityTimeseriesRequest,
  ListConsoleObservabilityEventsRequest,
  ListConsoleObservabilityServicesRequest,
} from './types';

const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 200;
const DEFAULT_BUCKET_MINUTES = 5;
const MAX_BUCKET_MINUTES = 60;
const DEFAULT_QUERY_MAX_WINDOW_MS = 1000 * 60 * 60 * 24 * 7;
const DEFAULT_INGEST_MAX_BATCH_SIZE = 200;
const DEFAULT_INGEST_MAX_EVENTS_PER_MINUTE = 10_000;
const INGEST_WINDOW_MS = 60_000;
const RETIRED_ROUTER_REQUEST_COMPLETED_EVENT_TYPE = 'router.request.completed';

const OBSERVABILITY_LEVELS = new Set<ConsoleObservabilityLevel>([
  'DEBUG',
  'INFO',
  'WARN',
  'ERROR',
  'FATAL',
]);

interface EventsCursor {
  readonly sortMs: number;
  readonly eventId: string;
}

interface NormalizedInsertEvent {
  readonly eventId: string;
  readonly schemaVersion: number;
  readonly source: ConsoleObservabilitySource;
  readonly ingestedAtMs: number;
  readonly timestampMs: number;
  readonly projectId: string;
  readonly environmentId: string;
  readonly service: string;
  readonly component: string;
  readonly level: ConsoleObservabilityLevel;
  readonly eventType: string;
  readonly message: string;
  readonly requestId: string;
  readonly traceId: string;
  readonly metadata: Record<string, unknown>;
  readonly redactionVersion: number;
  readonly redactionApplied: boolean;
}

interface D1ConsoleObservabilityState {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
  readonly queryMaxWindowMs: number;
}

interface D1ConsoleObservabilityIngestionState {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
  readonly redactionPolicy?: ConsoleObservabilityMetadataRedactionPolicy;
  readonly maxBatchSize: number;
  readonly maxEventsPerMinute: number;
}

interface D1WhereParts {
  readonly whereSql: string;
  readonly values: readonly unknown[];
}

export const CONSOLE_OBSERVABILITY_D1_RUNTIME = Symbol('consoleObservabilityD1Runtime');
export const CONSOLE_OBSERVABILITY_INGESTION_D1_RUNTIME = Symbol(
  'consoleObservabilityIngestionD1Runtime',
);

export interface ConsoleObservabilityD1Runtime {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

export type ConsoleObservabilityD1Service = ConsoleObservabilityService & {
  readonly [CONSOLE_OBSERVABILITY_D1_RUNTIME]: ConsoleObservabilityD1Runtime;
};

export type ConsoleObservabilityIngestionD1Service = ConsoleObservabilityIngestionService & {
  readonly [CONSOLE_OBSERVABILITY_INGESTION_D1_RUNTIME]: ConsoleObservabilityD1Runtime;
  observeRequestMetric(
    ctx: ConsoleObservabilityIngestionContext,
    metric: ConsoleObservabilityRequestMetricInput,
  ): Promise<void>;
};

export interface D1ConsoleObservabilitySchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1ConsoleObservabilityServiceOptions
  extends Pick<InMemoryConsoleObservabilityServiceOptions, 'now'> {
  readonly database: D1DatabaseLike;
  readonly namespace?: string;
  readonly ensureSchema?: boolean;
  readonly queryMaxWindowMs?: number;
}

export interface D1ConsoleObservabilityIngestionServiceOptions
  extends Pick<InMemoryConsoleObservabilityServiceOptions, 'now'> {
  readonly database: D1DatabaseLike;
  readonly namespace?: string;
  readonly ensureSchema?: boolean;
  readonly redactionPolicy?: ConsoleObservabilityMetadataRedactionPolicy;
  readonly maxBatchSize?: number;
  readonly maxEventsPerMinute?: number;
}

export const CONSOLE_OBSERVABILITY_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS observability_events (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      event_id TEXT NOT NULL,
      schema_version INTEGER NOT NULL,
      source TEXT NOT NULL,
      ingested_at_ms INTEGER NOT NULL,
      timestamp_ms INTEGER NOT NULL,
      project_id TEXT NOT NULL DEFAULT '',
      environment_id TEXT NOT NULL DEFAULT '',
      service TEXT NOT NULL,
      component TEXT NOT NULL,
      level TEXT NOT NULL,
      event_type TEXT NOT NULL,
      message TEXT NOT NULL,
      request_id TEXT NOT NULL DEFAULT '',
      trace_id TEXT NOT NULL DEFAULT '',
      metadata_json TEXT NOT NULL,
      redaction_version INTEGER NOT NULL,
      redaction_applied INTEGER NOT NULL,
      created_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, created_at_ms, event_id),
      CHECK (schema_version >= 1),
      CHECK (source IN (${CONSOLE_OBSERVABILITY_SOURCES_SQL})),
      CHECK (level IN ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')),
      CHECK (json_valid(metadata_json)),
      CHECK (redaction_version >= 1),
      CHECK (redaction_applied IN (0, 1))
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS observability_event_dedup (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      event_id TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, event_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS observability_ingest_windows (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      window_start_ms INTEGER NOT NULL,
      accepted_count INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, window_start_ms),
      CHECK (accepted_count >= 0)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS observability_request_rollups_minute (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      window_start_ms INTEGER NOT NULL,
      project_id TEXT NOT NULL DEFAULT '',
      environment_id TEXT NOT NULL DEFAULT '',
      service TEXT NOT NULL,
      route_family TEXT NOT NULL,
      method TEXT NOT NULL,
      status_class TEXT NOT NULL,
      request_count INTEGER NOT NULL,
      error_count INTEGER NOT NULL,
      latency_sum_ms REAL NOT NULL,
      latency_max_ms REAL NOT NULL,
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
  `,
  `
    CREATE INDEX IF NOT EXISTS observability_events_org_created_idx
      ON observability_events (namespace, org_id, created_at_ms DESC, event_id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS observability_events_org_service_created_idx
      ON observability_events (namespace, org_id, service, created_at_ms DESC, event_id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS observability_events_org_level_created_idx
      ON observability_events (namespace, org_id, level, created_at_ms DESC, event_id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS observability_events_org_timestamp_idx
      ON observability_events (namespace, org_id, timestamp_ms DESC, event_id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS observability_event_dedup_created_idx
      ON observability_event_dedup (namespace, org_id, created_at_ms)
  `,
  `
    CREATE INDEX IF NOT EXISTS observability_ingest_windows_window_idx
      ON observability_ingest_windows (namespace, org_id, window_start_ms)
  `,
  `
    CREATE INDEX IF NOT EXISTS observability_request_rollups_org_window_idx
      ON observability_request_rollups_minute (namespace, org_id, window_start_ms DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS observability_request_rollups_org_service_window_idx
      ON observability_request_rollups_minute (namespace, org_id, service, window_start_ms DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS observability_request_rollups_org_route_window_idx
      ON observability_request_rollups_minute (namespace, org_id, route_family, window_start_ms DESC)
  `,
] as const);

export async function ensureConsoleObservabilityD1Schema(
  options: D1ConsoleObservabilitySchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_OBSERVABILITY_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export function getConsoleObservabilityD1Runtime(
  service: ConsoleObservabilityService | null | undefined,
): ConsoleObservabilityD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (
    (service as Partial<ConsoleObservabilityD1Service>)[CONSOLE_OBSERVABILITY_D1_RUNTIME] || null
  );
}

export function getConsoleObservabilityIngestionD1Runtime(
  service: ConsoleObservabilityIngestionService | null | undefined,
): ConsoleObservabilityD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (
    (service as Partial<ConsoleObservabilityIngestionD1Service>)[
      CONSOLE_OBSERVABILITY_INGESTION_D1_RUNTIME
    ] || null
  );
}

export async function createD1ConsoleObservabilityService(
  options: D1ConsoleObservabilityServiceOptions,
): Promise<ConsoleObservabilityD1Service> {
  const state: D1ConsoleObservabilityState = {
    database: options.database,
    namespace: ensureNamespace(options.namespace),
    now: options.now || defaultNow,
    queryMaxWindowMs: normalizePositiveInteger(
      options.queryMaxWindowMs,
      DEFAULT_QUERY_MAX_WINDOW_MS,
    ),
  };
  if (options.ensureSchema !== false) {
    await ensureConsoleObservabilityD1Schema({ database: state.database });
  }
  return new D1ConsoleObservabilityServiceImpl(state);
}

export async function createD1ConsoleObservabilityIngestionService(
  options: D1ConsoleObservabilityIngestionServiceOptions,
): Promise<ConsoleObservabilityIngestionD1Service> {
  const state: D1ConsoleObservabilityIngestionState = {
    database: options.database,
    namespace: ensureNamespace(options.namespace),
    now: options.now || defaultNow,
    redactionPolicy: options.redactionPolicy,
    maxBatchSize: normalizePositiveInteger(options.maxBatchSize, DEFAULT_INGEST_MAX_BATCH_SIZE),
    maxEventsPerMinute: normalizePositiveInteger(
      options.maxEventsPerMinute,
      DEFAULT_INGEST_MAX_EVENTS_PER_MINUTE,
    ),
  };
  if (options.ensureSchema !== false) {
    await ensureConsoleObservabilityD1Schema({ database: state.database });
  }
  return new D1ConsoleObservabilityIngestionServiceImpl(state);
}

function defaultNow(): Date {
  return new Date();
}

function ensureNamespace(namespace: string | undefined): string {
  const normalized = String(namespace || 'default').trim();
  return normalized || 'default';
}

function normalizeString(raw: unknown): string {
  return String(raw || '').trim();
}

function nowMs(now: Date): number {
  return now.getTime();
}

function parseIsoToMs(raw: unknown): number | null {
  const value = normalizeString(raw);
  if (!value) return null;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return null;
  return Math.floor(parsed);
}

function parseIsoToMsStrict(raw: unknown, fieldName: string): number | null {
  const value = normalizeString(raw);
  if (!value) return null;
  const parsed = parseIsoToMs(value);
  if (parsed === null) {
    throw new ConsoleObservabilityError(
      'invalid_query',
      400,
      `Query parameter ${fieldName} must be a valid ISO timestamp`,
    );
  }
  return parsed;
}

function ensureRequiredString(field: string, raw: unknown): string {
  const value = normalizeString(raw);
  if (!value) {
    throw new ConsoleObservabilityError('invalid_body', 400, `Field ${field} is required`);
  }
  return value;
}

function ensureSchemaVersion(raw: unknown): number {
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) return 1;
  return Math.floor(value);
}

function ensureSource(raw: unknown): ConsoleObservabilitySource {
  const value = normalizeString(raw).toUpperCase() as ConsoleObservabilitySource;
  if (!CONSOLE_OBSERVABILITY_SOURCE_SET.has(value)) {
    throw new ConsoleObservabilityError('invalid_body', 400, 'Field source is invalid');
  }
  return value;
}

function ensureLevel(raw: unknown): ConsoleObservabilityLevel {
  const value = normalizeString(raw).toUpperCase() as ConsoleObservabilityLevel;
  if (!OBSERVABILITY_LEVELS.has(value)) {
    throw new ConsoleObservabilityError('invalid_body', 400, 'Field level is invalid');
  }
  return value;
}

function ensureMetadataObject(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  return { ...(raw as Record<string, unknown>) };
}

function normalizePositiveInteger(raw: unknown, fallback: number): number {
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) return fallback;
  return Math.floor(value);
}

function normalizeLimit(raw: unknown): number {
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) return DEFAULT_LIST_LIMIT;
  return Math.min(Math.floor(value), MAX_LIST_LIMIT);
}

function normalizeBucketMinutes(raw: unknown): number {
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) return DEFAULT_BUCKET_MINUTES;
  return Math.min(Math.floor(value), MAX_BUCKET_MINUTES);
}

function toIso(rawMs: unknown): string {
  const value = Number(rawMs);
  if (!Number.isFinite(value) || value < 0) return new Date(0).toISOString();
  return new Date(value).toISOString();
}



function encodeEventsCursor(sortMs: number, eventId: string): string {
  if (!Number.isFinite(sortMs) || !Number.isSafeInteger(Math.floor(sortMs)) || sortMs < 0) {
    throw new ConsoleObservabilityError('invalid_query', 400, 'Invalid cursor sort key');
  }
  const normalizedEventId = normalizeString(eventId);
  if (!normalizedEventId) {
    throw new ConsoleObservabilityError('invalid_query', 400, 'Invalid cursor value');
  }
  return `${Math.floor(sortMs)}:${encodeURIComponent(normalizedEventId)}`;
}

function parseEventsCursor(raw: unknown): EventsCursor | null {
  const value = normalizeString(raw);
  if (!value) return null;
  const separator = value.indexOf(':');
  if (separator <= 0 || separator === value.length - 1) {
    throw new ConsoleObservabilityError('invalid_query', 400, 'Invalid cursor format');
  }
  const sortMsRaw = value.slice(0, separator);
  const encodedEventId = value.slice(separator + 1);
  if (!/^\d+$/.test(sortMsRaw)) {
    throw new ConsoleObservabilityError('invalid_query', 400, 'Invalid cursor sort key');
  }
  const sortMs = Number.parseInt(sortMsRaw, 10);
  if (!Number.isSafeInteger(sortMs)) {
    throw new ConsoleObservabilityError('invalid_query', 400, 'Invalid cursor sort key');
  }
  let eventId = '';
  try {
    eventId = decodeURIComponent(encodedEventId);
  } catch {
    throw new ConsoleObservabilityError('invalid_query', 400, 'Invalid cursor value');
  }
  if (!eventId) {
    throw new ConsoleObservabilityError('invalid_query', 400, 'Invalid cursor value');
  }
  return { sortMs, eventId };
}

function escapedLikePattern(raw: unknown): string | null {
  const value = normalizeString(raw);
  if (!value) return null;
  return `%${value.replace(/[\\%_]/g, '\\$&').toLowerCase()}%`;
}

function resolveBoundedQueryWindow(
  request: { readonly from?: unknown; readonly to?: unknown },
  now: Date,
  queryMaxWindowMs: number,
): { readonly fromMs: number; readonly toMs: number } {
  const explicitFromMs = parseIsoToMsStrict(request.from, 'from');
  const explicitToMs = parseIsoToMsStrict(request.to, 'to');
  const nowValue = nowMs(now);
  let fromMs = explicitFromMs;
  let toMs = explicitToMs;
  if (fromMs === null && toMs === null) {
    toMs = nowValue;
    fromMs = toMs - queryMaxWindowMs;
  } else if (fromMs === null && toMs !== null) {
    fromMs = toMs - queryMaxWindowMs;
  } else if (fromMs !== null && toMs === null) {
    toMs = Math.min(nowValue, fromMs + queryMaxWindowMs);
  }
  const boundedFromMs = Math.max(0, Math.floor(fromMs || 0));
  const boundedToMs = Math.max(0, Math.floor(toMs || 0));
  if (boundedFromMs > boundedToMs) {
    throw new ConsoleObservabilityError(
      'invalid_query',
      400,
      'Query parameter from must be earlier than or equal to to',
    );
  }
  if (boundedToMs - boundedFromMs > queryMaxWindowMs) {
    throw new ConsoleObservabilityError('invalid_query', 400, 'Query window must be 7 days or less');
  }
  return {
    fromMs: boundedFromMs,
    toMs: boundedToMs,
  };
}

function parseEventRow(row: D1Row): ConsoleObservabilityEvent {
  const levelRaw = normalizeString(row.level).toUpperCase() as ConsoleObservabilityLevel;
  const projectId = normalizeString(row.project_id);
  const environmentId = normalizeString(row.environment_id);
  const requestId = normalizeString(row.request_id);
  const traceId = normalizeString(row.trace_id);
  return {
    id: normalizeString(row.event_id),
    orgId: normalizeString(row.org_id),
    ...(projectId ? { projectId } : {}),
    ...(environmentId ? { environmentId } : {}),
    timestamp: toIso(row.timestamp_ms),
    service: normalizeString(row.service),
    component: normalizeString(row.component),
    level: OBSERVABILITY_LEVELS.has(levelRaw) ? levelRaw : 'INFO',
    eventType: normalizeString(row.event_type),
    message: normalizeString(row.message),
    ...(requestId ? { requestId } : {}),
    ...(traceId ? { traceId } : {}),
    metadata: parseJsonObject(row.metadata_json),
  };
}

function normalizeEnvelopeForInsert(
  input: ConsoleObservabilityEventEnvelope,
  redactionPolicy: ConsoleObservabilityMetadataRedactionPolicy | undefined,
): NormalizedInsertEvent {
  const eventId = ensureRequiredString('eventId', input.eventId);
  const schemaVersion = ensureSchemaVersion(input.schemaVersion);
  const source = ensureSource(input.source);
  const ingestedAtMs = Number.isFinite(Number(input.ingestedAtMs))
    ? Math.max(0, Math.floor(Number(input.ingestedAtMs)))
    : nowMs(new Date());
  const timestampMs = parseIsoToMs(input.timestamp) ?? ingestedAtMs;
  const redacted = redactConsoleObservabilityMetadata(
    ensureMetadataObject(input.metadata),
    redactionPolicy,
  );
  return {
    eventId,
    schemaVersion,
    source,
    ingestedAtMs,
    timestampMs,
    projectId: normalizeString(input.projectId),
    environmentId: normalizeString(input.environmentId),
    service: ensureRequiredString('service', input.service),
    component: ensureRequiredString('component', input.component),
    level: ensureLevel(input.level),
    eventType: ensureRequiredString('eventType', input.eventType),
    message: ensureRequiredString('message', input.message),
    requestId: normalizeString(input.requestId),
    traceId: normalizeString(input.traceId),
    metadata: redacted.metadata,
    redactionVersion: Math.max(
      1,
      Math.floor(
        Number(input.redactionVersion || 0) > 0
          ? Number(input.redactionVersion || 0)
          : redacted.redactionVersion,
      ),
    ),
    redactionApplied: Boolean(input.redactionApplied) || redacted.redactionApplied,
  };
}

function ensureNotRetiredRouterTimingEvent(event: ConsoleObservabilityEventEnvelope): void {
  if (normalizeString(event.eventType) !== RETIRED_ROUTER_REQUEST_COMPLETED_EVENT_TYPE) return;
  throw new ConsoleObservabilityError(
    'invalid_body',
    400,
    `Event type ${RETIRED_ROUTER_REQUEST_COMPLETED_EVENT_TYPE} is no longer accepted`,
  );
}

function toServiceHealthStatus(
  recentFailureCount: number,
): ConsoleObservabilityServiceHealth['status'] {
  if (recentFailureCount >= 5) return 'FAILING';
  if (recentFailureCount > 0) return 'DEGRADED';
  return 'HEALTHY';
}

function buildProjectEnvironmentWhere(input: {
  readonly initialClauses: readonly string[];
  readonly initialValues: readonly unknown[];
  readonly projectId?: unknown;
  readonly environmentId?: unknown;
}): D1WhereParts {
  const clauses = [...input.initialClauses];
  const values = [...input.initialValues];
  const projectId = normalizeString(input.projectId);
  if (projectId) {
    clauses.push('project_id = ?');
    values.push(projectId);
  }
  const environmentId = normalizeString(input.environmentId);
  if (environmentId) {
    clauses.push('environment_id = ?');
    values.push(environmentId);
  }
  return {
    whereSql: clauses.join(' AND '),
    values,
  };
}

function eventWindowWhere(input: {
  readonly namespace: string;
  readonly orgId: string;
  readonly window: { readonly fromMs: number; readonly toMs: number };
  readonly request: { readonly projectId?: unknown; readonly environmentId?: unknown };
}): D1WhereParts {
  return buildProjectEnvironmentWhere({
    initialClauses: [
      'namespace = ?',
      'org_id = ?',
      'created_at_ms >= ?',
      'created_at_ms <= ?',
    ],
    initialValues: [input.namespace, input.orgId, input.window.fromMs, input.window.toMs],
    projectId: input.request.projectId,
    environmentId: input.request.environmentId,
  });
}

function rollupWindowWhere(input: {
  readonly namespace: string;
  readonly orgId: string;
  readonly window: { readonly fromMs: number; readonly toMs: number };
  readonly request: { readonly projectId?: unknown; readonly environmentId?: unknown };
}): D1WhereParts {
  return buildProjectEnvironmentWhere({
    initialClauses: [
      'namespace = ?',
      'org_id = ?',
      'window_start_ms >= ?',
      'window_start_ms <= ?',
    ],
    initialValues: [input.namespace, input.orgId, input.window.fromMs, input.window.toMs],
    projectId: input.request.projectId,
    environmentId: input.request.environmentId,
  });
}

async function reserveIngestBudget(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly requestedCount: number;
  readonly nowValueMs: number;
  readonly maxEventsPerMinute: number;
}): Promise<void> {
  if (input.maxEventsPerMinute <= 0 || input.requestedCount <= 0) return;
  if (input.requestedCount > input.maxEventsPerMinute) {
    throw new ConsoleObservabilityError(
      'rate_limited',
      429,
      `Observability ingest rate exceeded for org ${input.orgId}`,
    );
  }
  const windowStartMs = input.nowValueMs - (input.nowValueMs % INGEST_WINDOW_MS);
  const result = await input.database
    .prepare(
      `INSERT INTO observability_ingest_windows
        (namespace, org_id, window_start_ms, accepted_count, updated_at_ms)
       VALUES
        (?, ?, ?, ?, ?)
       ON CONFLICT (namespace, org_id, window_start_ms)
       DO UPDATE SET
        accepted_count = observability_ingest_windows.accepted_count + excluded.accepted_count,
        updated_at_ms = excluded.updated_at_ms
       WHERE
        observability_ingest_windows.accepted_count + excluded.accepted_count <= ?`,
    )
    .bind(
      input.namespace,
      input.orgId,
      windowStartMs,
      input.requestedCount,
      input.nowValueMs,
      input.maxEventsPerMinute,
    )
    .run();
  if (d1ChangedRows(result) <= 0) {
    throw new ConsoleObservabilityError(
      'rate_limited',
      429,
      `Observability ingest rate exceeded for org ${input.orgId}`,
    );
  }
  await input.database
    .prepare(
      `DELETE FROM observability_ingest_windows
        WHERE namespace = ?
          AND org_id = ?
          AND window_start_ms < ?`,
    )
    .bind(input.namespace, input.orgId, windowStartMs - INGEST_WINDOW_MS * 10)
    .run();
}

async function observeRequestMetric(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly metric: ConsoleObservabilityRequestMetricInput;
}): Promise<void> {
  const normalized = normalizeConsoleObservabilityRequestMetricForInsert(input.metric);
  if (!normalized) return;
  const windowStartMs = normalized.timestampMs - (normalized.timestampMs % REQUEST_ROLLUP_WINDOW_MS);
  const [b50, b100, b250, b500, b1000, b2000, b5000] = normalized.histogramCounts;
  await input.database
    .prepare(
      `INSERT INTO observability_request_rollups_minute
        (namespace, org_id, window_start_ms, project_id, environment_id, service, route_family, method, status_class,
         request_count, error_count, latency_sum_ms, latency_max_ms,
         latency_bucket_le_50, latency_bucket_le_100, latency_bucket_le_250, latency_bucket_le_500,
         latency_bucket_le_1000, latency_bucket_le_2000, latency_bucket_le_5000)
       VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (
         namespace, org_id, window_start_ms, project_id, environment_id, service, route_family, method, status_class
       )
       DO UPDATE SET
         request_count = observability_request_rollups_minute.request_count + excluded.request_count,
         error_count = observability_request_rollups_minute.error_count + excluded.error_count,
         latency_sum_ms = observability_request_rollups_minute.latency_sum_ms + excluded.latency_sum_ms,
         latency_max_ms = MAX(observability_request_rollups_minute.latency_max_ms, excluded.latency_max_ms),
         latency_bucket_le_50 =
           observability_request_rollups_minute.latency_bucket_le_50
           + excluded.latency_bucket_le_50,
         latency_bucket_le_100 =
           observability_request_rollups_minute.latency_bucket_le_100
           + excluded.latency_bucket_le_100,
         latency_bucket_le_250 =
           observability_request_rollups_minute.latency_bucket_le_250
           + excluded.latency_bucket_le_250,
         latency_bucket_le_500 =
           observability_request_rollups_minute.latency_bucket_le_500
           + excluded.latency_bucket_le_500,
         latency_bucket_le_1000 =
           observability_request_rollups_minute.latency_bucket_le_1000
           + excluded.latency_bucket_le_1000,
         latency_bucket_le_2000 =
           observability_request_rollups_minute.latency_bucket_le_2000
           + excluded.latency_bucket_le_2000,
         latency_bucket_le_5000 =
           observability_request_rollups_minute.latency_bucket_le_5000
           + excluded.latency_bucket_le_5000`,
    )
    .bind(
      input.namespace,
      input.orgId,
      windowStartMs,
      normalized.projectId,
      normalized.environmentId,
      normalized.service,
      normalized.routeFamily,
      normalized.method,
      normalized.statusClass,
      1,
      normalized.errorCount,
      normalized.latencyMs,
      normalized.latencyMs,
      b50,
      b100,
      b250,
      b500,
      b1000,
      b2000,
      b5000,
    )
    .run();
}

class D1ConsoleObservabilityIngestionServiceImpl
  implements ConsoleObservabilityIngestionD1Service
{
  readonly [CONSOLE_OBSERVABILITY_INGESTION_D1_RUNTIME]: ConsoleObservabilityD1Runtime;

  private readonly state: D1ConsoleObservabilityIngestionState;

  constructor(state: D1ConsoleObservabilityIngestionState) {
    this.state = state;
    this[CONSOLE_OBSERVABILITY_INGESTION_D1_RUNTIME] = {
      database: state.database,
      namespace: state.namespace,
      now: state.now,
    };
    this.appendEvent = this.appendEvent.bind(this);
    this.appendEvents = this.appendEvents.bind(this);
    this.observeRequestMetric = this.observeRequestMetric.bind(this);
  }

  async appendEvent(
    ctx: ConsoleObservabilityIngestionContext,
    event: ConsoleObservabilityEventEnvelope,
  ): Promise<ConsoleObservabilityEventIngestResult> {
    return await this.appendEvents(ctx, [event]);
  }

  async appendEvents(
    ctx: ConsoleObservabilityIngestionContext,
    events: ConsoleObservabilityEventEnvelope[],
  ): Promise<ConsoleObservabilityEventIngestResult> {
    const orgId = ensureRequiredString('ctx.orgId', ctx.orgId);
    if (!Array.isArray(events) || events.length === 0) {
      return { accepted: 0, deduplicated: 0 };
    }
    if (events.length > this.state.maxBatchSize) {
      throw new ConsoleObservabilityError(
        'rate_limited',
        429,
        `Observability ingest batch exceeds max batch size (${this.state.maxBatchSize})`,
      );
    }

    const normalizedEvents: NormalizedInsertEvent[] = [];
    for (const event of events) {
      const eventOrgId = ensureRequiredString('event.orgId', event.orgId);
      if (eventOrgId !== orgId) {
        throw new ConsoleObservabilityError(
          'invalid_body',
          400,
          'Event orgId must match ingestion context orgId',
        );
      }
      ensureNotRetiredRouterTimingEvent(event);
      normalizedEvents.push(normalizeEnvelopeForInsert(event, this.state.redactionPolicy));
    }

    const nowValueMs = nowMs(this.state.now());
    await reserveIngestBudget({
      database: this.state.database,
      namespace: this.state.namespace,
      orgId,
      requestedCount: normalizedEvents.length,
      nowValueMs,
      maxEventsPerMinute: this.state.maxEventsPerMinute,
    });

    let accepted = 0;
    let deduplicated = 0;
    for (const normalized of normalizedEvents) {
      const dedupe = await this.state.database
        .prepare(
          `INSERT OR IGNORE INTO observability_event_dedup
            (namespace, org_id, event_id, created_at_ms)
           VALUES
            (?, ?, ?, ?)`,
        )
        .bind(this.state.namespace, orgId, normalized.eventId, normalized.ingestedAtMs)
        .run();
      if (d1ChangedRows(dedupe) <= 0) {
        deduplicated += 1;
        continue;
      }
      const out = await this.state.database
        .prepare(
          `INSERT OR IGNORE INTO observability_events
            (namespace, org_id, event_id, schema_version, source, ingested_at_ms, timestamp_ms,
             project_id, environment_id, service, component, level, event_type, message,
             request_id, trace_id, metadata_json, redaction_version, redaction_applied, created_at_ms)
           VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          this.state.namespace,
          orgId,
          normalized.eventId,
          normalized.schemaVersion,
          normalized.source,
          normalized.ingestedAtMs,
          normalized.timestampMs,
          normalized.projectId,
          normalized.environmentId,
          normalized.service,
          normalized.component,
          normalized.level,
          normalized.eventType,
          normalized.message,
          normalized.requestId,
          normalized.traceId,
          JSON.stringify(normalized.metadata),
          normalized.redactionVersion,
          normalized.redactionApplied ? 1 : 0,
          normalized.ingestedAtMs,
        )
        .run();
      if (d1ChangedRows(out) > 0) accepted += 1;
      else deduplicated += 1;
    }
    return { accepted, deduplicated };
  }

  async observeRequestMetric(
    ctx: ConsoleObservabilityIngestionContext,
    metric: ConsoleObservabilityRequestMetricInput,
  ): Promise<void> {
    const orgId = ensureRequiredString('ctx.orgId', ctx.orgId);
    const metricOrgId = ensureRequiredString('metric.orgId', metric.orgId);
    if (orgId !== metricOrgId) {
      throw new ConsoleObservabilityError(
        'invalid_body',
        400,
        'Request metric orgId must match ingestion context orgId',
      );
    }
    await observeRequestMetric({
      database: this.state.database,
      namespace: this.state.namespace,
      orgId,
      metric,
    });
  }
}

class D1ConsoleObservabilityServiceImpl implements ConsoleObservabilityD1Service {
  readonly [CONSOLE_OBSERVABILITY_D1_RUNTIME]: ConsoleObservabilityD1Runtime;

  private readonly state: D1ConsoleObservabilityState;

  constructor(state: D1ConsoleObservabilityState) {
    this.state = state;
    this[CONSOLE_OBSERVABILITY_D1_RUNTIME] = {
      database: state.database,
      namespace: state.namespace,
      now: state.now,
    };
    this.getSummary = this.getSummary.bind(this);
    this.listEvents = this.listEvents.bind(this);
    this.getTimeseries = this.getTimeseries.bind(this);
    this.listServices = this.listServices.bind(this);
  }

  async getSummary(
    ctx: ConsoleObservabilityContext,
    request: GetConsoleObservabilitySummaryRequest = {},
  ): Promise<ConsoleObservabilitySummary> {
    const orgId = ensureRequiredString('ctx.orgId', ctx.orgId);
    const window = resolveBoundedQueryWindow(request, this.state.now(), this.state.queryMaxWindowMs);
    const eventWhere = eventWindowWhere({
      namespace: this.state.namespace,
      orgId,
      window,
      request,
    });
    const rollupWhere = rollupWindowWhere({
      namespace: this.state.namespace,
      orgId,
      window,
      request,
    });
    const requestRow = await queryFirstRow(
      this.state.database,
      `SELECT
         COALESCE(SUM(request_count), 0) AS request_count,
         COALESCE(SUM(error_count), 0) AS request_error_count,
         COALESCE(SUM(latency_bucket_le_50), 0) AS latency_bucket_le_50,
         COALESCE(SUM(latency_bucket_le_100), 0) AS latency_bucket_le_100,
         COALESCE(SUM(latency_bucket_le_250), 0) AS latency_bucket_le_250,
         COALESCE(SUM(latency_bucket_le_500), 0) AS latency_bucket_le_500,
         COALESCE(SUM(latency_bucket_le_1000), 0) AS latency_bucket_le_1000,
         COALESCE(SUM(latency_bucket_le_2000), 0) AS latency_bucket_le_2000,
         COALESCE(SUM(latency_bucket_le_5000), 0) AS latency_bucket_le_5000
         FROM observability_request_rollups_minute
        WHERE ${rollupWhere.whereSql}`,
      rollupWhere.values,
    );
    const requestCount = Math.max(0, toNumber(requestRow?.request_count, 0));
    const requestErrorCount = Math.max(0, toNumber(requestRow?.request_error_count, 0));
    const histogramCounts = REQUEST_ROLLUP_BUCKET_COLUMN_NAMES.map((column) =>
      Math.max(0, Math.floor(toNumber(requestRow?.[column], 0))),
    );

    const deadLetterRow = await queryFirstRow(
      this.state.database,
      `SELECT COUNT(*) AS dead_letter_count
         FROM observability_events
        WHERE ${eventWhere.whereSql}
          AND event_type = 'webhook.delivery.dead_letter'`,
      eventWhere.values,
    );
    const requestFailureRows = await queryRows(
      this.state.database,
      `SELECT DISTINCT service
         FROM observability_request_rollups_minute
        WHERE ${rollupWhere.whereSql}
          AND error_count > 0`,
      rollupWhere.values,
    );
    const incidentFailureRows = await queryRows(
      this.state.database,
      `SELECT DISTINCT service
         FROM observability_events
        WHERE ${eventWhere.whereSql}
          AND level IN ('ERROR', 'FATAL')`,
      eventWhere.values,
    );
    const failingServiceSet = new Set<string>();
    for (const row of requestFailureRows) {
      const service = normalizeString(row.service);
      if (service) failingServiceSet.add(service);
    }
    for (const row of incidentFailureRows) {
      const service = normalizeString(row.service);
      if (service) failingServiceSet.add(service);
    }
    return {
      generatedAt: this.state.now().toISOString(),
      status: { state: 'ok' },
      errorRate: requestCount > 0 ? requestErrorCount / requestCount : 0,
      p95LatencyMs: percentileFromConsoleObservabilityHistogram(histogramCounts, 0.95),
      failingServices: failingServiceSet.size,
      deadLetterCount: Math.max(0, Math.floor(toNumber(deadLetterRow?.dead_letter_count, 0))),
    };
  }

  async listEvents(
    ctx: ConsoleObservabilityContext,
    request: ListConsoleObservabilityEventsRequest = {},
  ): Promise<ConsoleObservabilityEventsPage> {
    const orgId = ensureRequiredString('ctx.orgId', ctx.orgId);
    const window = resolveBoundedQueryWindow(request, this.state.now(), this.state.queryMaxWindowMs);
    const clauses = [
      'namespace = ?',
      'org_id = ?',
      'created_at_ms >= ?',
      'created_at_ms <= ?',
    ];
    const values: unknown[] = [this.state.namespace, orgId, window.fromMs, window.toMs];
    const pushEq = (column: string, raw: unknown): void => {
      const value = normalizeString(raw);
      if (!value) return;
      clauses.push(`${column} = ?`);
      values.push(value);
    };
    pushEq('level', request.level);
    pushEq('service', request.service);
    pushEq('component', request.component);
    pushEq('event_type', request.eventType);
    pushEq('project_id', request.projectId);
    pushEq('environment_id', request.environmentId);
    const searchPattern = escapedLikePattern(request.query);
    if (searchPattern) {
      clauses.push(
        `(LOWER(event_id) LIKE ? ESCAPE '\\' OR LOWER(service) LIKE ? ESCAPE '\\' OR LOWER(component) LIKE ? ESCAPE '\\' OR LOWER(event_type) LIKE ? ESCAPE '\\' OR LOWER(message) LIKE ? ESCAPE '\\' OR LOWER(request_id) LIKE ? ESCAPE '\\' OR LOWER(trace_id) LIKE ? ESCAPE '\\' OR LOWER(metadata_json) LIKE ? ESCAPE '\\')`,
      );
      values.push(
        searchPattern,
        searchPattern,
        searchPattern,
        searchPattern,
        searchPattern,
        searchPattern,
        searchPattern,
        searchPattern,
      );
    }
    const whereSql = clauses.join(' AND ');
    const countValues = [...values];
    const cursor = parseEventsCursor(request.cursor);
    let cursorClause = '';
    if (cursor) {
      values.push(cursor.sortMs, cursor.sortMs, cursor.eventId);
      cursorClause = ' AND (created_at_ms < ? OR (created_at_ms = ? AND event_id < ?))';
    }
    const limit = normalizeLimit(request.limit);
    values.push(limit + 1);
    const countRow = await queryFirstRow(
      this.state.database,
      `SELECT COUNT(*) AS total_count
         FROM observability_events
        WHERE ${whereSql}`,
      countValues,
    );
    const totalCount = Math.max(0, Math.floor(toNumber(countRow?.total_count, 0)));
    const totalPages = Math.max(1, Math.ceil(totalCount / limit));
    const rows = await queryRows(
      this.state.database,
      `SELECT *
         FROM observability_events
        WHERE ${whereSql}${cursorClause}
        ORDER BY created_at_ms DESC, event_id DESC
        LIMIT ?`,
      values,
    );
    const hasMore = rows.length > limit;
    const pageRows = hasMore ? rows.slice(0, limit) : rows;
    const last = pageRows[pageRows.length - 1];
    const nextCursor =
      hasMore && last
        ? encodeEventsCursor(toNumber(last.created_at_ms), normalizeString(last.event_id))
        : undefined;
    return {
      status: { state: 'ok' },
      events: pageRows.map(parseEventRow),
      totalPages,
      ...(nextCursor ? { nextCursor } : {}),
    };
  }

  async getTimeseries(
    ctx: ConsoleObservabilityContext,
    request: GetConsoleObservabilityTimeseriesRequest = {},
  ): Promise<ConsoleObservabilityTimeseries> {
    const orgId = ensureRequiredString('ctx.orgId', ctx.orgId);
    const window = resolveBoundedQueryWindow(request, this.state.now(), this.state.queryMaxWindowMs);
    const baseWhere = rollupWindowWhere({
      namespace: this.state.namespace,
      orgId,
      window,
      request,
    });
    const clauses = [baseWhere.whereSql];
    const values = [...baseWhere.values];
    const service = normalizeString(request.service);
    if (service) {
      clauses.push('service = ?');
      values.push(service);
    }
    const bucketMinutes = normalizeBucketMinutes(request.bucketMinutes);
    const bucketMs = bucketMinutes * 60 * 1000;
    const rows = await queryRows(
      this.state.database,
      `SELECT *
         FROM observability_request_rollups_minute
        WHERE ${clauses.join(' AND ')}
        ORDER BY window_start_ms ASC`,
      values,
    );
    const countsByStart = new Map<
      string,
      { errorCount: number; requestCount: number; histogramCounts: number[] }
    >();
    for (const row of rows) {
      const windowStartMs = Math.floor(toNumber(row.window_start_ms));
      const bucketStartMs =
        window.fromMs + Math.floor((windowStartMs - window.fromMs) / bucketMs) * bucketMs;
      const key = String(bucketStartMs);
      const current =
        countsByStart.get(key) || {
          errorCount: 0,
          requestCount: 0,
          histogramCounts: REQUEST_ROLLUP_BUCKET_COLUMN_NAMES.map(() => 0),
        };
      current.errorCount += Math.max(0, Math.floor(toNumber(row.error_count, 0)));
      current.requestCount += Math.max(0, Math.floor(toNumber(row.request_count, 0)));
      REQUEST_ROLLUP_BUCKET_COLUMN_NAMES.forEach((column, index) => {
        current.histogramCounts[index] += Math.max(0, Math.floor(toNumber(row[column], 0)));
      });
      countsByStart.set(key, current);
    }

    const buckets: ConsoleObservabilityTimeseriesBucket[] = [];
    for (let bucketStartMs = window.fromMs; bucketStartMs <= window.toMs; bucketStartMs += bucketMs) {
      const key = String(bucketStartMs);
      const row = countsByStart.get(key) || {
        errorCount: 0,
        requestCount: 0,
        histogramCounts: REQUEST_ROLLUP_BUCKET_COLUMN_NAMES.map(() => 0),
      };
      const bucketEndMs = Math.min(window.toMs, bucketStartMs + bucketMs - 1);
      buckets.push({
        start: toIso(bucketStartMs),
        end: toIso(Math.max(bucketStartMs, bucketEndMs)),
        errorCount: row.errorCount,
        requestCount: row.requestCount,
        p50LatencyMs: percentileFromConsoleObservabilityHistogram(row.histogramCounts, 0.5),
        p95LatencyMs: percentileFromConsoleObservabilityHistogram(row.histogramCounts, 0.95),
      });
    }
    return {
      status: { state: 'ok' },
      buckets,
    };
  }

  async listServices(
    ctx: ConsoleObservabilityContext,
    request: ListConsoleObservabilityServicesRequest = {},
  ): Promise<ConsoleObservabilityServicesView> {
    const orgId = ensureRequiredString('ctx.orgId', ctx.orgId);
    const window = resolveBoundedQueryWindow(request, this.state.now(), this.state.queryMaxWindowMs);
    const eventWhere = eventWindowWhere({
      namespace: this.state.namespace,
      orgId,
      window,
      request,
    });
    const rollupWhere = rollupWindowWhere({
      namespace: this.state.namespace,
      orgId,
      window,
      request,
    });
    const limit = normalizeLimit(request.limit);
    const requestFailureRows = await queryRows(
      this.state.database,
      `SELECT
         service,
         COALESCE(SUM(error_count), 0) AS recent_failure_count,
         MAX(CASE WHEN error_count > 0 THEN window_start_ms ELSE NULL END) AS latest_incident_ms
         FROM observability_request_rollups_minute
        WHERE ${rollupWhere.whereSql}
        GROUP BY service
        ORDER BY recent_failure_count DESC, latest_incident_ms DESC, service ASC
        LIMIT ?`,
      [...rollupWhere.values, limit * 2],
    );
    const eventFailureRows = await queryRows(
      this.state.database,
      `SELECT
         service,
         COUNT(CASE WHEN level IN ('ERROR', 'FATAL') THEN 1 ELSE NULL END) AS recent_failure_count,
         MAX(CASE WHEN level IN ('ERROR', 'FATAL') THEN created_at_ms ELSE NULL END) AS latest_incident_ms
         FROM observability_events
        WHERE ${eventWhere.whereSql}
        GROUP BY service
        ORDER BY recent_failure_count DESC, latest_incident_ms DESC, service ASC
        LIMIT ?`,
      [...eventWhere.values, limit * 2],
    );
    const merged = new Map<string, { recentFailureCount: number; latestIncidentMs: number }>();
    for (const row of requestFailureRows) {
      const service = normalizeString(row.service);
      if (!service) continue;
      merged.set(service, {
        recentFailureCount: Math.max(0, Math.floor(toNumber(row.recent_failure_count, 0))),
        latestIncidentMs: Math.max(0, Math.floor(toNumber(row.latest_incident_ms, 0))),
      });
    }
    for (const row of eventFailureRows) {
      const service = normalizeString(row.service);
      if (!service) continue;
      const entry = merged.get(service) || { recentFailureCount: 0, latestIncidentMs: 0 };
      entry.recentFailureCount += Math.max(0, Math.floor(toNumber(row.recent_failure_count, 0)));
      entry.latestIncidentMs = Math.max(
        entry.latestIncidentMs,
        Math.max(0, Math.floor(toNumber(row.latest_incident_ms, 0))),
      );
      merged.set(service, entry);
    }
    const services = [...merged.entries()]
      .sort((a, b) => {
        const failureDelta = b[1].recentFailureCount - a[1].recentFailureCount;
        if (failureDelta !== 0) return failureDelta;
        const incidentDelta = b[1].latestIncidentMs - a[1].latestIncidentMs;
        if (incidentDelta !== 0) return incidentDelta;
        return a[0].localeCompare(b[0]);
      })
      .slice(0, limit)
      .map(([service, row]) => ({
        service,
        status: toServiceHealthStatus(row.recentFailureCount),
        recentFailureCount: row.recentFailureCount,
        ...(row.latestIncidentMs > 0 ? { latestIncidentAt: toIso(row.latestIncidentMs) } : {}),
      }));
    return {
      status: { state: 'ok' },
      services,
    };
  }
}
