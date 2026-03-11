import type { NormalizedLogger } from '../../core/logger';
import { getPostgresPool } from '../../storage/postgres';
import { ensureConsoleNamespace as ensureNamespace } from '../shared/postgresNormalize';
import {
  ensureConsoleTenantRlsPolicies,
  withConsoleTenantContextTx,
} from '../shared/postgresTenantContext';
import { ConsoleObservabilityError } from './errors';
import { redactConsoleObservabilityMetadata } from './redaction';
import type {
  ConsoleObservabilityContext,
  ConsoleObservabilityService,
  InMemoryConsoleObservabilityServiceOptions,
} from './service';
import type {
  ConsoleObservabilityServiceHealth,
  ConsoleObservabilityServicesView,
  ConsoleObservabilitySummary,
  ConsoleObservabilityEvent,
  ConsoleObservabilityEventEnvelope,
  ConsoleObservabilityEventIngestResult,
  ConsoleObservabilityEventsPage,
  ConsoleObservabilityIngestionContext,
  ConsoleObservabilityLevel,
  ConsoleObservabilityMetadataRedactionPolicy,
  ConsoleObservabilityRequestMetricInput,
  ConsoleObservabilitySource,
  ConsoleObservabilityTimeseries,
  ConsoleObservabilityTimeseriesBucket,
  GetConsoleObservabilitySummaryRequest,
  GetConsoleObservabilityTimeseriesRequest,
  ListConsoleObservabilityEventsRequest,
  ListConsoleObservabilityServicesRequest,
} from './types';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_OBSERVABILITY_MIGRATION_LOCK_ID = 9452360124981;
const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 200;
const DEFAULT_BUCKET_MINUTES = 5;
const MAX_BUCKET_MINUTES = 60;
const DEFAULT_QUERY_MAX_WINDOW_MS = 1000 * 60 * 60 * 24 * 7;
const DEFAULT_INGEST_MAX_BATCH_SIZE = 200;
const DEFAULT_INGEST_MAX_EVENTS_PER_MINUTE = 10_000;
const INGEST_WINDOW_MS = 60_000;
const DEFAULT_RETENTION_TTL_MS = 1000 * 60 * 60 * 24 * 30;
const DEFAULT_RETENTION_PRUNE_INTERVAL_MS = 1000 * 60 * 5;
const DEFAULT_RETENTION_BATCH_SIZE = 1_000;
const PRECREATE_PARTITION_MONTHS_BEHIND = 1;
const PRECREATE_PARTITION_MONTHS_AHEAD = 2;
const REQUEST_ROLLUP_WINDOW_MS = 60_000;
const REQUEST_ROLLUP_BUCKET_UPPER_BOUNDS_MS = [50, 100, 250, 500, 1000, 2000, 5000] as const;
const REQUEST_ROLLUP_BUCKET_COLUMN_NAMES = [
  'latency_bucket_le_50',
  'latency_bucket_le_100',
  'latency_bucket_le_250',
  'latency_bucket_le_500',
  'latency_bucket_le_1000',
  'latency_bucket_le_2000',
  'latency_bucket_le_5000',
] as const;
const REQUEST_ROLLUP_SKIPPED_ROUTE_FAMILIES = new Set<string>([
  '/console/observability/*',
  '/console/session/*',
  '/console/org/*',
  '/console/projects/*',
  '/console/environments/*',
  '/console/healthz/*',
  '/console/readyz/*',
]);
const LEGACY_ROUTER_REQUEST_COMPLETED_EVENT_TYPE = 'router.request.completed';

const OBSERVABILITY_LEVELS = new Set<ConsoleObservabilityLevel>([
  'DEBUG',
  'INFO',
  'WARN',
  'ERROR',
  'FATAL',
]);
const OBSERVABILITY_SOURCES = new Set<ConsoleObservabilitySource>([
  'WEBHOOK',
  'BILLING',
  'APPROVAL',
  'SYSTEM',
]);

interface EventsCursor {
  sortMs: number;
  eventId: string;
}

interface NormalizedInsertEvent {
  eventId: string;
  schemaVersion: number;
  source: ConsoleObservabilitySource;
  ingestedAtMs: number;
  timestampMs: number;
  projectId: string | null;
  environmentId: string | null;
  service: string;
  component: string;
  level: ConsoleObservabilityLevel;
  eventType: string;
  message: string;
  requestId: string | null;
  traceId: string | null;
  metadata: Record<string, unknown>;
  redactionVersion: number;
  redactionApplied: boolean;
}

interface NormalizedRequestMetric {
  timestampMs: number;
  projectId: string;
  environmentId: string;
  service: string;
  routeFamily: string;
  method: string;
  statusCode: number;
  statusClass: string;
  latencyMs: number;
  errorCount: number;
  histogramCounts: number[];
}

export interface PostgresConsoleObservabilityRetentionCleanupResult {
  cutoffMs: number;
  deletedEvents: number;
  deletedDedup: number;
  deletedIngestWindows: number;
  deletedRequestRollups: number;
}

export interface PostgresConsoleObservabilitySchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export interface PostgresConsoleObservabilityRetentionCleanupOptions
  extends PostgresConsoleObservabilitySchemaOptions,
    Pick<InMemoryConsoleObservabilityServiceOptions, 'now'> {
  namespace?: string;
  orgId: string;
  ensureSchema?: boolean;
  ttlMs?: number;
  batchSize?: number;
}

function normalizeString(raw: unknown): string {
  return String(raw || '').trim();
}

function toNullableString(raw: unknown): string | null {
  const value = normalizeString(raw);
  return value || null;
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
  if (!OBSERVABILITY_SOURCES.has(value)) {
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
      // no-op
    }
  }
  return {};
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

function normalizePositiveInteger(raw: unknown, fallback: number): number {
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) return fallback;
  return Math.floor(value);
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
  return {
    sortMs,
    eventId,
  };
}

function toIso(rawMs: unknown): string {
  const value = Number(rawMs);
  if (!Number.isFinite(value) || value < 0) return new Date(0).toISOString();
  return new Date(value).toISOString();
}

function toNumber(raw: unknown, fallback = 0): number {
  const value = Number(raw);
  if (!Number.isFinite(value)) return fallback;
  return value;
}

function toEscapedLikePattern(raw: unknown): string | null {
  const value = normalizeString(raw);
  if (!value) return null;
  return `%${value.replace(/[\\%_]/g, '\\$&')}%`;
}

function parseEventRow(row: PgRow): ConsoleObservabilityEvent {
  const levelRaw = normalizeString(row.level).toUpperCase() as ConsoleObservabilityLevel;
  const projectId = toNullableString(row.project_id);
  const environmentId = toNullableString(row.environment_id);
  const requestId = toNullableString(row.request_id);
  const traceId = toNullableString(row.trace_id);

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
    metadata: parseJsonObject(row.metadata),
  };
}

function monthStartUtcMs(inputMs: number): number {
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

async function ensureEventsPartition(q: Queryable, monthStartMsValue: number): Promise<void> {
  const rangeStartMs = monthStartUtcMs(monthStartMsValue);
  const rangeEndMs = addUtcMonths(rangeStartMs, 1);
  const tableName = buildEventsPartitionTableName(rangeStartMs);
  await q.query(`
    CREATE TABLE IF NOT EXISTS ${tableName}
    PARTITION OF console_observability_events
    FOR VALUES FROM (${rangeStartMs}) TO (${rangeEndMs})
  `);
}

async function ensureEventsPartitionsForRange(
  q: Queryable,
  rangeStartMs: number,
  rangeEndMs: number,
): Promise<void> {
  let monthStartMsValue = monthStartUtcMs(rangeStartMs);
  const endMonthStartMsValue = monthStartUtcMs(rangeEndMs);
  while (monthStartMsValue <= endMonthStartMsValue) {
    await ensureEventsPartition(q, monthStartMsValue);
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
    await ensureEventsPartitionsForRange(q, minCreatedAtMs, maxCreatedAtMs);
  }

  const dedupeCopy = await q.query(`
    INSERT INTO console_observability_event_dedup (namespace, org_id, event_id, created_at_ms)
    SELECT namespace, org_id, event_id, created_at_ms
      FROM console_observability_events_legacy
    ON CONFLICT (namespace, org_id, event_id) DO NOTHING
  `);
  const eventsCopy = await q.query(`
    INSERT INTO console_observability_events
      (namespace, org_id, event_id, schema_version, source, ingested_at_ms, timestamp_ms,
       project_id, environment_id, service, component, level, event_type, message,
       request_id, trace_id, metadata, redaction_version, redaction_applied, created_at_ms)
    SELECT namespace, org_id, event_id, schema_version, source, ingested_at_ms, timestamp_ms,
           project_id, environment_id, service, component, level, event_type, message,
           request_id, trace_id, metadata, redaction_version, redaction_applied, created_at_ms
      FROM console_observability_events_legacy
    ON CONFLICT (namespace, org_id, created_at_ms, event_id) DO NOTHING
  `);

  await q.query('DROP TABLE IF EXISTS console_observability_events_legacy');
  logger.info(
    `[console-observability][postgres] migrated legacy events table rows: dedupe=${Number(
      dedupeCopy.rowCount || 0,
    )} events=${Number(eventsCopy.rowCount || 0)}`,
  );
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
  const service = ensureRequiredString('service', input.service);
  const component = ensureRequiredString('component', input.component);
  const level = ensureLevel(input.level);
  const eventType = ensureRequiredString('eventType', input.eventType);
  const message = ensureRequiredString('message', input.message);

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
    projectId: toNullableString(input.projectId),
    environmentId: toNullableString(input.environmentId),
    service,
    component,
    level,
    eventType,
    message,
    requestId: toNullableString(input.requestId),
    traceId: toNullableString(input.traceId),
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

function resolveBoundedQueryWindow(
  request: { from?: unknown; to?: unknown },
  now: Date,
  queryMaxWindowMs: number,
): { fromMs: number; toMs: number } {
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

function toServiceHealthStatus(recentFailureCount: number): ConsoleObservabilityServiceHealth['status'] {
  if (recentFailureCount >= 5) return 'FAILING';
  if (recentFailureCount > 0) return 'DEGRADED';
  return 'HEALTHY';
}

function appendProjectEnvironmentFilters(
  where: string[],
  values: unknown[],
  valueIndex: number,
  request: { projectId?: unknown; environmentId?: unknown },
): number {
  const projectId = normalizeString(request.projectId);
  if (projectId) {
    valueIndex += 1;
    values.push(projectId);
    where.push(`project_id = $${valueIndex}`);
  }
  const environmentId = normalizeString(request.environmentId);
  if (environmentId) {
    valueIndex += 1;
    values.push(environmentId);
    where.push(`environment_id = $${valueIndex}`);
  }
  return valueIndex;
}

function appendRollupProjectEnvironmentFilters(
  where: string[],
  values: unknown[],
  valueIndex: number,
  request: { projectId?: unknown; environmentId?: unknown },
): number {
  const projectId = normalizeString(request.projectId);
  if (projectId) {
    valueIndex += 1;
    values.push(projectId);
    where.push(`project_id = $${valueIndex}`);
  }
  const environmentId = normalizeString(request.environmentId);
  if (environmentId) {
    valueIndex += 1;
    values.push(environmentId);
    where.push(`environment_id = $${valueIndex}`);
  }
  return valueIndex;
}

function toStatusClass(statusCode: number): string {
  if (statusCode >= 500) return '5xx';
  if (statusCode >= 400) return '4xx';
  if (statusCode >= 300) return '3xx';
  if (statusCode >= 200) return '2xx';
  if (statusCode >= 100) return '1xx';
  return '0xx';
}

function toRouteFamily(route: string): string {
  const path = normalizeString(route).split('?')[0] || '/';
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const parts = normalizedPath.split('/').filter(Boolean);
  if (parts.length === 0) return '/';
  if (parts[0] !== 'console') return '/other/*';
  if (parts.length === 1) return '/console/*';
  return `/console/${parts[1]}/*`;
}

function toMetricService(routeFamily: string): string {
  const parts = routeFamily.split('/').filter(Boolean);
  if (parts.length < 2 || parts[0] !== 'console') return 'console-router';
  return parts[1];
}

function shouldCaptureRequestMetric(input: {
  routeFamily: string;
  method: string;
  statusCode: number;
}): boolean {
  const method = normalizeString(input.method).toUpperCase();
  if (!method || method === 'OPTIONS') return false;
  if ((method === 'GET' || method === 'HEAD') && input.statusCode < 400) return false;
  if (REQUEST_ROLLUP_SKIPPED_ROUTE_FAMILIES.has(input.routeFamily)) return false;
  return true;
}

function buildLatencyHistogramCounts(latencyMs: number): number[] {
  const counts = REQUEST_ROLLUP_BUCKET_UPPER_BOUNDS_MS.map(() => 0);
  for (let idx = 0; idx < REQUEST_ROLLUP_BUCKET_UPPER_BOUNDS_MS.length; idx += 1) {
    if (latencyMs <= REQUEST_ROLLUP_BUCKET_UPPER_BOUNDS_MS[idx]) {
      counts[idx] = 1;
      return counts;
    }
  }
  counts[counts.length - 1] = 1;
  return counts;
}

function percentileFromHistogram(counts: number[], quantile: number): number {
  const total = counts.reduce((sum, value) => sum + Math.max(0, Math.floor(value)), 0);
  if (total <= 0) return 0;
  const threshold = Math.max(1, Math.ceil(total * quantile));
  let cumulative = 0;
  for (let idx = 0; idx < REQUEST_ROLLUP_BUCKET_UPPER_BOUNDS_MS.length; idx += 1) {
    cumulative += Math.max(0, Math.floor(counts[idx] || 0));
    if (cumulative >= threshold) {
      return REQUEST_ROLLUP_BUCKET_UPPER_BOUNDS_MS[idx];
    }
  }
  return REQUEST_ROLLUP_BUCKET_UPPER_BOUNDS_MS[REQUEST_ROLLUP_BUCKET_UPPER_BOUNDS_MS.length - 1];
}

function normalizeRequestMetricForInsert(
  input: ConsoleObservabilityRequestMetricInput,
): NormalizedRequestMetric | null {
  const route = normalizeString(input.route);
  const method = normalizeString(input.method).toUpperCase();
  const statusCode = Math.max(0, Math.floor(Number(input.statusCode || 0)));
  const latencyMs = Math.max(0, Number(input.latencyMs || 0));
  const timestampMs = parseIsoToMs(input.timestamp) ?? nowMs(new Date());
  const routeFamily = toRouteFamily(route);
  if (!shouldCaptureRequestMetric({ routeFamily, method, statusCode })) {
    return null;
  }
  return {
    timestampMs,
    projectId: normalizeString(input.projectId),
    environmentId: normalizeString(input.environmentId),
    service: toMetricService(routeFamily),
    routeFamily,
    method,
    statusCode,
    statusClass: toStatusClass(statusCode),
    latencyMs,
    errorCount: statusCode >= 500 ? 1 : 0,
    histogramCounts: buildLatencyHistogramCounts(latencyMs),
  };
}

async function reserveIngestBudget(input: {
  q: Queryable;
  namespace: string;
  orgId: string;
  requestedCount: number;
  nowValueMs: number;
  maxEventsPerMinute: number;
}): Promise<void> {
  if (input.maxEventsPerMinute <= 0) return;
  if (input.requestedCount <= 0) return;

  const windowStartMs = input.nowValueMs - (input.nowValueMs % INGEST_WINDOW_MS);
  const budget = await input.q.query(
    `INSERT INTO console_observability_ingest_windows
      (namespace, org_id, window_start_ms, accepted_count, updated_at_ms)
     VALUES
      ($1, $2, $3, $4, $5)
     ON CONFLICT (namespace, org_id, window_start_ms)
     DO UPDATE SET
      accepted_count = console_observability_ingest_windows.accepted_count + EXCLUDED.accepted_count,
      updated_at_ms = EXCLUDED.updated_at_ms
     WHERE
      console_observability_ingest_windows.accepted_count + EXCLUDED.accepted_count <= $6
     RETURNING accepted_count`,
    [
      input.namespace,
      input.orgId,
      windowStartMs,
      input.requestedCount,
      input.nowValueMs,
      input.maxEventsPerMinute,
    ],
  );

  if ((budget.rowCount || 0) <= 0) {
    throw new ConsoleObservabilityError(
      'rate_limited',
      429,
      `Observability ingest rate exceeded for org ${input.orgId}`,
    );
  }

  await input.q.query(
    `DELETE FROM console_observability_ingest_windows
      WHERE namespace = $1
        AND org_id = $2
        AND window_start_ms < $3`,
    [input.namespace, input.orgId, windowStartMs - INGEST_WINDOW_MS * 10],
  );
}

async function pruneRetentionForTenant(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    cutoffMs: number;
    batchSize: number;
  },
): Promise<PostgresConsoleObservabilityRetentionCleanupResult> {
  const deleteEvents = await q.query(
    `WITH stale AS (
       SELECT namespace, org_id, created_at_ms, event_id
         FROM console_observability_events
        WHERE namespace = $1
          AND org_id = $2
          AND created_at_ms < $3
        ORDER BY created_at_ms ASC, event_id ASC
        LIMIT $4
     )
     DELETE FROM console_observability_events target
      USING stale
      WHERE target.namespace = stale.namespace
        AND target.org_id = stale.org_id
        AND target.created_at_ms = stale.created_at_ms
        AND target.event_id = stale.event_id`,
    [input.namespace, input.orgId, input.cutoffMs, input.batchSize],
  );

  const deleteDedup = await q.query(
    `WITH stale AS (
       SELECT ctid
         FROM console_observability_event_dedup
        WHERE namespace = $1
          AND org_id = $2
          AND created_at_ms < $3
        LIMIT $4
     )
     DELETE FROM console_observability_event_dedup target
      USING stale
      WHERE target.ctid = stale.ctid`,
    [input.namespace, input.orgId, input.cutoffMs, input.batchSize],
  );

  const deleteIngestWindows = await q.query(
    `DELETE FROM console_observability_ingest_windows
      WHERE namespace = $1
        AND org_id = $2
        AND window_start_ms < $3`,
    [input.namespace, input.orgId, input.cutoffMs],
  );

  const deleteRequestRollups = await q.query(
    `DELETE FROM console_observability_request_rollups_minute
      WHERE namespace = $1
        AND org_id = $2
        AND window_start_ms < $3`,
    [input.namespace, input.orgId, input.cutoffMs],
  );

  return {
    cutoffMs: input.cutoffMs,
    deletedEvents: Number(deleteEvents.rowCount || 0),
    deletedDedup: Number(deleteDedup.rowCount || 0),
    deletedIngestWindows: Number(deleteIngestWindows.rowCount || 0),
    deletedRequestRollups: Number(deleteRequestRollups.rowCount || 0),
  };
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
        CHECK (source IN ('WEBHOOK', 'BILLING', 'APPROVAL', 'SYSTEM')),
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

    const nowValue = nowMs(new Date());
    await ensureEventsPartitionsForRange(
      pool,
      addUtcMonths(monthStartUtcMs(nowValue), -PRECREATE_PARTITION_MONTHS_BEHIND),
      addUtcMonths(monthStartUtcMs(nowValue), PRECREATE_PARTITION_MONTHS_AHEAD),
    );
    await migrateLegacyRowsIntoPartitionedEvents(pool, options.logger);
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_OBSERVABILITY_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }

  options.logger.info('[console-observability][postgres] Schema ready');
}

export interface PostgresConsoleObservabilityServiceOptions
  extends PostgresConsoleObservabilitySchemaOptions,
    Pick<InMemoryConsoleObservabilityServiceOptions, 'now'> {
  namespace?: string;
  ensureSchema?: boolean;
  queryMaxWindowMs?: number;
}

export async function createPostgresConsoleObservabilityService(
  options: PostgresConsoleObservabilityServiceOptions,
): Promise<ConsoleObservabilityService> {
  const postgresUrl = normalizeString(options.postgresUrl);
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres console observability service');
  }

  const namespace = ensureNamespace(options.namespace);
  const now = options.now || (() => new Date());
  const queryMaxWindowMs = normalizePositiveInteger(
    options.queryMaxWindowMs,
    DEFAULT_QUERY_MAX_WINDOW_MS,
  );
  if (options.ensureSchema !== false) {
    await ensureConsoleObservabilityPostgresSchema({
      postgresUrl,
      logger: options.logger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);
  const withTenantTx = <T>(
    orgId: string,
    fn: (q: Queryable) => Promise<T>,
  ): Promise<T> => withConsoleTenantContextTx(pool, { namespace, orgId }, fn);

  async function getSummary(
    ctx: ConsoleObservabilityContext,
    request: GetConsoleObservabilitySummaryRequest = {},
  ): Promise<ConsoleObservabilitySummary> {
    const orgId = ensureRequiredString('ctx.orgId', ctx.orgId);
    const eventWhere: string[] = ['namespace = $1', 'org_id = $2'];
    const eventValues: unknown[] = [namespace, orgId];
    let eventValueIndex = eventValues.length;
    const rollupWhere: string[] = ['namespace = $1', 'org_id = $2'];
    const rollupValues: unknown[] = [namespace, orgId];
    let rollupValueIndex = rollupValues.length;

    const window = resolveBoundedQueryWindow(request, now(), queryMaxWindowMs);
    eventValueIndex += 1;
    eventValues.push(window.fromMs);
    eventWhere.push(`created_at_ms >= $${eventValueIndex}`);
    eventValueIndex += 1;
    eventValues.push(window.toMs);
    eventWhere.push(`created_at_ms <= $${eventValueIndex}`);
    eventValueIndex = appendProjectEnvironmentFilters(
      eventWhere,
      eventValues,
      eventValueIndex,
      request,
    );

    rollupValueIndex += 1;
    rollupValues.push(window.fromMs);
    rollupWhere.push(`window_start_ms >= $${rollupValueIndex}`);
    rollupValueIndex += 1;
    rollupValues.push(window.toMs);
    rollupWhere.push(`window_start_ms <= $${rollupValueIndex}`);
    rollupValueIndex = appendRollupProjectEnvironmentFilters(
      rollupWhere,
      rollupValues,
      rollupValueIndex,
      request,
    );

    const rollupBucketSelect = REQUEST_ROLLUP_BUCKET_COLUMN_NAMES.map(
      (column) => `COALESCE(SUM(${column}), 0)::bigint AS ${column}`,
    ).join(',\n             ');

    return withTenantTx(orgId, async (q) => {
      const requestAgg = await q.query(
        `SELECT
           COALESCE(SUM(request_count), 0)::double precision AS request_count,
           COALESCE(SUM(error_count), 0)::double precision AS request_error_count,
           ${rollupBucketSelect}
           FROM console_observability_request_rollups_minute
          WHERE ${rollupWhere.join(' AND ')}`,
        rollupValues,
      );
      const requestRow = (requestAgg.rows?.[0] || {}) as PgRow;
      const requestCount = Math.max(0, toNumber(requestRow.request_count, 0));
      const requestErrorCount = Math.max(0, toNumber(requestRow.request_error_count, 0));
      const histogramCounts = REQUEST_ROLLUP_BUCKET_COLUMN_NAMES.map((column) =>
        Math.max(0, Math.floor(toNumber(requestRow[column], 0))),
      );

      const deadLetterAgg = await q.query(
        `SELECT
           COUNT(*) FILTER (WHERE event_type = 'webhook.delivery.dead_letter')::bigint AS dead_letter_count
           FROM console_observability_events
          WHERE ${eventWhere.join(' AND ')}`,
        eventValues,
      );
      const deadLetterRow = (deadLetterAgg.rows?.[0] || {}) as PgRow;

      const requestFailureServices = await q.query(
        `SELECT DISTINCT service
           FROM console_observability_request_rollups_minute
          WHERE ${rollupWhere.join(' AND ')}
            AND error_count > 0`,
        rollupValues,
      );
      const incidentFailureServices = await q.query(
        `SELECT DISTINCT service
           FROM console_observability_events
          WHERE ${eventWhere.join(' AND ')}
            AND level IN ('ERROR', 'FATAL')`,
        eventValues,
      );
      const failingServiceSet = new Set<string>();
      for (const row of requestFailureServices.rows as PgRow[]) {
        const service = normalizeString(row.service);
        if (service) failingServiceSet.add(service);
      }
      for (const row of incidentFailureServices.rows as PgRow[]) {
        const service = normalizeString(row.service);
        if (service) failingServiceSet.add(service);
      }

      const errorRate = requestCount > 0 ? requestErrorCount / requestCount : 0;
      return {
        generatedAt: now().toISOString(),
        status: { state: 'ok' },
        errorRate,
        p95LatencyMs: percentileFromHistogram(histogramCounts, 0.95),
        failingServices: failingServiceSet.size,
        deadLetterCount: Math.max(0, Math.floor(toNumber(deadLetterRow.dead_letter_count, 0))),
      };
    });
  }

  async function listEvents(
    ctx: ConsoleObservabilityContext,
    request: ListConsoleObservabilityEventsRequest = {},
  ): Promise<ConsoleObservabilityEventsPage> {
    const orgId = ensureRequiredString('ctx.orgId', ctx.orgId);
    const where: string[] = ['namespace = $1', 'org_id = $2'];
    const values: unknown[] = [namespace, orgId];
    let valueIndex = values.length;

    const pushEq = (column: string, raw: unknown): void => {
      const value = normalizeString(raw);
      if (!value) return;
      valueIndex += 1;
      values.push(value);
      where.push(`${column} = $${valueIndex}`);
    };

    const window = resolveBoundedQueryWindow(request, now(), queryMaxWindowMs);
    valueIndex += 1;
    values.push(window.fromMs);
    where.push(`created_at_ms >= $${valueIndex}`);
    valueIndex += 1;
    values.push(window.toMs);
    where.push(`created_at_ms <= $${valueIndex}`);

    pushEq('level', request.level);
    pushEq('service', request.service);
    pushEq('event_type', request.eventType);
    pushEq('project_id', request.projectId);
    pushEq('environment_id', request.environmentId);
    const searchPattern = toEscapedLikePattern(request.query);
    if (searchPattern) {
      valueIndex += 1;
      values.push(searchPattern);
      where.push(
        `(event_id ILIKE $${valueIndex} ESCAPE '\\' OR service ILIKE $${valueIndex} ESCAPE '\\' OR component ILIKE $${valueIndex} ESCAPE '\\' OR event_type ILIKE $${valueIndex} ESCAPE '\\' OR message ILIKE $${valueIndex} ESCAPE '\\' OR COALESCE(request_id, '') ILIKE $${valueIndex} ESCAPE '\\' OR COALESCE(trace_id, '') ILIKE $${valueIndex} ESCAPE '\\' OR CAST(metadata AS TEXT) ILIKE $${valueIndex} ESCAPE '\\')`,
      );
    }
    const whereClause = where.join(' AND ');
    const countValues = [...values];

    const cursor = parseEventsCursor(request.cursor);
    let cursorClause = '';
    if (cursor) {
      values.push(cursor.sortMs, cursor.eventId);
      cursorClause = ` AND (created_at_ms < $${values.length - 1} OR (created_at_ms = $${
        values.length - 1
      } AND event_id < $${values.length}))`;
    }

    const limit = normalizeLimit(request.limit);
    values.push(limit + 1);

    return withTenantTx(orgId, async (q) => {
      const countOut = await q.query(
        `SELECT COUNT(*)::bigint AS total_count
           FROM console_observability_events
          WHERE ${whereClause}`,
        countValues,
      );
      const totalCount = Math.max(
        0,
        Math.floor(toNumber(((countOut.rows?.[0] || {}) as PgRow).total_count, 0)),
      );
      const totalPages = Math.max(1, Math.ceil(totalCount / limit));
      const out = await q.query(
        `SELECT *
           FROM console_observability_events
          WHERE ${whereClause}${cursorClause}
          ORDER BY created_at_ms DESC, event_id DESC
          LIMIT $${values.length}`,
        values,
      );
      const rows = out.rows as PgRow[];
      const hasMore = rows.length > limit;
      const pageRows = hasMore ? rows.slice(0, limit) : rows;
      const events = pageRows.map((row) => parseEventRow(row));
      const last = pageRows[pageRows.length - 1];
      const nextCursor =
        hasMore && last
          ? encodeEventsCursor(
              Number((last as { created_at_ms?: unknown }).created_at_ms || 0),
              normalizeString((last as { event_id?: unknown }).event_id),
            )
          : undefined;
      return {
        status: {
          state: 'ok',
        },
        events,
        totalPages,
        ...(nextCursor ? { nextCursor } : {}),
      };
    });
  }

  async function getTimeseries(
    ctx: ConsoleObservabilityContext,
    request: GetConsoleObservabilityTimeseriesRequest = {},
  ): Promise<ConsoleObservabilityTimeseries> {
    const orgId = ensureRequiredString('ctx.orgId', ctx.orgId);
    const where: string[] = ['namespace = $1', 'org_id = $2'];
    const values: unknown[] = [namespace, orgId];
    let valueIndex = values.length;

    const window = resolveBoundedQueryWindow(request, now(), queryMaxWindowMs);
    valueIndex += 1;
    values.push(window.fromMs);
    const fromParam = valueIndex;
    where.push(`window_start_ms >= $${valueIndex}`);
    valueIndex += 1;
    values.push(window.toMs);
    const toParam = valueIndex;
    where.push(`window_start_ms <= $${valueIndex}`);
    valueIndex = appendRollupProjectEnvironmentFilters(where, values, valueIndex, request);

    const service = normalizeString(request.service);
    if (service) {
      valueIndex += 1;
      values.push(service);
      where.push(`service = $${valueIndex}`);
    }
    const bucketMinutes = normalizeBucketMinutes(request.bucketMinutes);
    const bucketMs = bucketMinutes * 60 * 1000;
    values.push(bucketMs);
    const bucketParam = values.length;

    return withTenantTx(orgId, async (q) => {
      const out = await q.query(
        `WITH filtered AS (
           SELECT
             window_start_ms,
             request_count,
             error_count,
             latency_bucket_le_50,
             latency_bucket_le_100,
             latency_bucket_le_250,
             latency_bucket_le_500,
             latency_bucket_le_1000,
             latency_bucket_le_2000,
             latency_bucket_le_5000
             FROM console_observability_request_rollups_minute
            WHERE ${where.join(' AND ')}
         ),
         bucketed AS (
           SELECT
             $${fromParam}::bigint
             + ((window_start_ms - $${fromParam}::bigint) / $${bucketParam}::bigint) * $${bucketParam}::bigint
             AS bucket_start_ms,
             request_count,
             error_count,
             latency_bucket_le_50,
             latency_bucket_le_100,
             latency_bucket_le_250,
             latency_bucket_le_500,
             latency_bucket_le_1000,
             latency_bucket_le_2000,
             latency_bucket_le_5000
             FROM filtered
         ),
         agg AS (
           SELECT
             bucket_start_ms,
             COALESCE(SUM(error_count), 0)::bigint AS error_count,
             COALESCE(SUM(request_count), 0)::bigint AS request_count,
             COALESCE(SUM(latency_bucket_le_50), 0)::bigint AS latency_bucket_le_50,
             COALESCE(SUM(latency_bucket_le_100), 0)::bigint AS latency_bucket_le_100,
             COALESCE(SUM(latency_bucket_le_250), 0)::bigint AS latency_bucket_le_250,
             COALESCE(SUM(latency_bucket_le_500), 0)::bigint AS latency_bucket_le_500,
             COALESCE(SUM(latency_bucket_le_1000), 0)::bigint AS latency_bucket_le_1000,
             COALESCE(SUM(latency_bucket_le_2000), 0)::bigint AS latency_bucket_le_2000,
             COALESCE(SUM(latency_bucket_le_5000), 0)::bigint AS latency_bucket_le_5000
             FROM bucketed
            GROUP BY bucket_start_ms
         ),
         series AS (
           SELECT generate_series(
             $${fromParam}::bigint,
             $${toParam}::bigint,
             $${bucketParam}::bigint
           ) AS bucket_start_ms
         )
         SELECT
           series.bucket_start_ms,
           COALESCE(agg.error_count, 0) AS error_count,
           COALESCE(agg.request_count, 0) AS request_count,
           COALESCE(agg.latency_bucket_le_50, 0) AS latency_bucket_le_50,
           COALESCE(agg.latency_bucket_le_100, 0) AS latency_bucket_le_100,
           COALESCE(agg.latency_bucket_le_250, 0) AS latency_bucket_le_250,
           COALESCE(agg.latency_bucket_le_500, 0) AS latency_bucket_le_500,
           COALESCE(agg.latency_bucket_le_1000, 0) AS latency_bucket_le_1000,
           COALESCE(agg.latency_bucket_le_2000, 0) AS latency_bucket_le_2000,
           COALESCE(agg.latency_bucket_le_5000, 0) AS latency_bucket_le_5000
           FROM series
           LEFT JOIN agg ON agg.bucket_start_ms = series.bucket_start_ms
          ORDER BY series.bucket_start_ms ASC`,
        values,
      );
      const buckets: ConsoleObservabilityTimeseriesBucket[] = (out.rows as PgRow[]).map((row) => {
        const bucketStartMs = Math.max(window.fromMs, Math.floor(toNumber(row.bucket_start_ms, 0)));
        const bucketEndMs = Math.min(window.toMs, bucketStartMs + bucketMs - 1);
        const histogramCounts = REQUEST_ROLLUP_BUCKET_COLUMN_NAMES.map((column) =>
          Math.max(0, Math.floor(toNumber(row[column], 0))),
        );
        return {
          start: toIso(bucketStartMs),
          end: toIso(Math.max(bucketStartMs, bucketEndMs)),
          errorCount: Math.max(0, Math.floor(toNumber(row.error_count, 0))),
          requestCount: Math.max(0, Math.floor(toNumber(row.request_count, 0))),
          p50LatencyMs: percentileFromHistogram(histogramCounts, 0.5),
          p95LatencyMs: percentileFromHistogram(histogramCounts, 0.95),
        };
      });

      return {
        status: { state: 'ok' },
        buckets,
      };
    });
  }

  async function listServices(
    ctx: ConsoleObservabilityContext,
    request: ListConsoleObservabilityServicesRequest = {},
  ): Promise<ConsoleObservabilityServicesView> {
    const orgId = ensureRequiredString('ctx.orgId', ctx.orgId);
    const eventWhere: string[] = ['namespace = $1', 'org_id = $2'];
    const eventValues: unknown[] = [namespace, orgId];
    let eventValueIndex = eventValues.length;
    const rollupWhere: string[] = ['namespace = $1', 'org_id = $2'];
    const rollupValues: unknown[] = [namespace, orgId];
    let rollupValueIndex = rollupValues.length;

    const window = resolveBoundedQueryWindow(request, now(), queryMaxWindowMs);
    eventValueIndex += 1;
    eventValues.push(window.fromMs);
    eventWhere.push(`created_at_ms >= $${eventValueIndex}`);
    eventValueIndex += 1;
    eventValues.push(window.toMs);
    eventWhere.push(`created_at_ms <= $${eventValueIndex}`);
    eventValueIndex = appendProjectEnvironmentFilters(
      eventWhere,
      eventValues,
      eventValueIndex,
      request,
    );

    rollupValueIndex += 1;
    rollupValues.push(window.fromMs);
    rollupWhere.push(`window_start_ms >= $${rollupValueIndex}`);
    rollupValueIndex += 1;
    rollupValues.push(window.toMs);
    rollupWhere.push(`window_start_ms <= $${rollupValueIndex}`);
    rollupValueIndex = appendRollupProjectEnvironmentFilters(
      rollupWhere,
      rollupValues,
      rollupValueIndex,
      request,
    );

    const limit = normalizeLimit(request.limit);
    eventValues.push(limit);
    rollupValues.push(limit);

    return withTenantTx(orgId, async (q) => {
      const maxRowLimit = Math.max(limit * 2, limit);
      const requestFailureRows = await q.query(
        `SELECT
           service,
           COALESCE(SUM(error_count), 0)::bigint AS recent_failure_count,
           MAX(CASE WHEN error_count > 0 THEN window_start_ms ELSE NULL END) AS latest_incident_ms
           FROM console_observability_request_rollups_minute
          WHERE ${rollupWhere.join(' AND ')}
          GROUP BY service
          ORDER BY recent_failure_count DESC, latest_incident_ms DESC NULLS LAST, service ASC
          LIMIT $${rollupValues.length}`,
        rollupValues,
      );

      const eventFailureRows = await q.query(
        `SELECT
           service,
           COUNT(*) FILTER (WHERE level IN ('ERROR', 'FATAL'))::bigint AS recent_failure_count,
           MAX(created_at_ms) FILTER (WHERE level IN ('ERROR', 'FATAL')) AS latest_incident_ms
           FROM console_observability_events
          WHERE ${eventWhere.join(' AND ')}
          GROUP BY service
          ORDER BY recent_failure_count DESC, latest_incident_ms DESC NULLS LAST, service ASC
          LIMIT $${eventValues.length}`,
        eventValues,
      );

      const merged = new Map<
        string,
        {
          recentFailureCount: number;
          latestIncidentMs: number;
        }
      >();
      for (const row of requestFailureRows.rows as PgRow[]) {
        const service = normalizeString(row.service);
        if (!service) continue;
        merged.set(service, {
          recentFailureCount: Math.max(0, Math.floor(toNumber(row.recent_failure_count, 0))),
          latestIncidentMs: Math.max(0, Math.floor(toNumber(row.latest_incident_ms, 0))),
        });
      }
      for (const row of eventFailureRows.rows as PgRow[]) {
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

      const sorted = [...merged.entries()]
        .sort((a, b) => {
          const failureDelta = b[1].recentFailureCount - a[1].recentFailureCount;
          if (failureDelta !== 0) return failureDelta;
          const incidentDelta = b[1].latestIncidentMs - a[1].latestIncidentMs;
          if (incidentDelta !== 0) return incidentDelta;
          return a[0].localeCompare(b[0]);
        })
        .slice(0, maxRowLimit);
      const services: ConsoleObservabilityServiceHealth[] = sorted.slice(0, limit).map(([service, row]) => ({
        service,
        status: toServiceHealthStatus(row.recentFailureCount),
        recentFailureCount: row.recentFailureCount,
        ...(row.latestIncidentMs > 0 ? { latestIncidentAt: toIso(row.latestIncidentMs) } : {}),
      }));

      return {
        status: { state: 'ok' },
        services,
      };
    });
  }

  return {
    getSummary,
    getTimeseries,
    listServices,
    listEvents,
  };
}

export interface ConsoleObservabilityIngestionService {
  appendEvent(
    ctx: ConsoleObservabilityIngestionContext,
    event: ConsoleObservabilityEventEnvelope,
  ): Promise<ConsoleObservabilityEventIngestResult>;
  appendEvents(
    ctx: ConsoleObservabilityIngestionContext,
    events: ConsoleObservabilityEventEnvelope[],
  ): Promise<ConsoleObservabilityEventIngestResult>;
  observeRequestMetric?(
    ctx: ConsoleObservabilityIngestionContext,
    metric: ConsoleObservabilityRequestMetricInput,
  ): Promise<void>;
}

export interface PostgresConsoleObservabilityIngestionServiceOptions
  extends PostgresConsoleObservabilitySchemaOptions,
    Pick<InMemoryConsoleObservabilityServiceOptions, 'now'> {
  namespace?: string;
  ensureSchema?: boolean;
  redactionPolicy?: ConsoleObservabilityMetadataRedactionPolicy;
  maxBatchSize?: number;
  maxEventsPerMinute?: number;
  retentionTtlMs?: number;
  retentionPruneIntervalMs?: number;
  retentionBatchSize?: number;
}

export async function runPostgresConsoleObservabilityRetentionCleanup(
  options: PostgresConsoleObservabilityRetentionCleanupOptions,
): Promise<PostgresConsoleObservabilityRetentionCleanupResult> {
  const postgresUrl = normalizeString(options.postgresUrl);
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres console observability retention cleanup');
  }
  const namespace = ensureNamespace(options.namespace);
  const orgId = ensureRequiredString('orgId', options.orgId);
  const now = options.now || (() => new Date());
  const ttlMs = normalizePositiveInteger(options.ttlMs, DEFAULT_RETENTION_TTL_MS);
  const batchSize = normalizePositiveInteger(options.batchSize, DEFAULT_RETENTION_BATCH_SIZE);

  if (options.ensureSchema !== false) {
    await ensureConsoleObservabilityPostgresSchema({
      postgresUrl,
      logger: options.logger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);
  return withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) => {
    const cutoffMs = Math.max(0, nowMs(now()) - ttlMs);
    return pruneRetentionForTenant(q, {
      namespace,
      orgId,
      cutoffMs,
      batchSize,
    });
  });
}

export async function createPostgresConsoleObservabilityIngestionService(
  options: PostgresConsoleObservabilityIngestionServiceOptions,
): Promise<ConsoleObservabilityIngestionService> {
  const postgresUrl = normalizeString(options.postgresUrl);
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres console observability ingestion service');
  }

  const namespace = ensureNamespace(options.namespace);
  const redactionPolicy = options.redactionPolicy;
  const now = options.now || (() => new Date());
  const maxBatchSize = normalizePositiveInteger(
    options.maxBatchSize,
    DEFAULT_INGEST_MAX_BATCH_SIZE,
  );
  const maxEventsPerMinute = normalizePositiveInteger(
    options.maxEventsPerMinute,
    DEFAULT_INGEST_MAX_EVENTS_PER_MINUTE,
  );
  const retentionTtlMs = normalizePositiveInteger(options.retentionTtlMs, DEFAULT_RETENTION_TTL_MS);
  const retentionPruneIntervalMs = normalizePositiveInteger(
    options.retentionPruneIntervalMs,
    DEFAULT_RETENTION_PRUNE_INTERVAL_MS,
  );
  const retentionBatchSize = normalizePositiveInteger(
    options.retentionBatchSize,
    DEFAULT_RETENTION_BATCH_SIZE,
  );

  if (options.ensureSchema !== false) {
    await ensureConsoleObservabilityPostgresSchema({
      postgresUrl,
      logger: options.logger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);
  const ensuredPartitionMonths = new Set<number>();
  const nextRetentionRunAtByOrg = new Map<string, number>();

  const withTenantTx = <T>(
    orgId: string,
    fn: (q: Queryable) => Promise<T>,
  ): Promise<T> => withConsoleTenantContextTx(pool, { namespace, orgId }, fn);

  async function observeRequestMetricInTx(
    q: Queryable,
    orgId: string,
    metric: ConsoleObservabilityRequestMetricInput,
  ): Promise<void> {
    const normalized = normalizeRequestMetricForInsert(metric);
    if (!normalized) return;
    const windowStartMs =
      normalized.timestampMs - (normalized.timestampMs % REQUEST_ROLLUP_WINDOW_MS);
    const [b50, b100, b250, b500, b1000, b2000, b5000] = normalized.histogramCounts;
    await q.query(
      `INSERT INTO console_observability_request_rollups_minute
        (namespace, org_id, window_start_ms, project_id, environment_id, service, route_family, method, status_class,
         request_count, error_count, latency_sum_ms, latency_max_ms,
         latency_bucket_le_50, latency_bucket_le_100, latency_bucket_le_250, latency_bucket_le_500,
         latency_bucket_le_1000, latency_bucket_le_2000, latency_bucket_le_5000)
       VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8, $9,
         $10, $11, $12, $13,
         $14, $15, $16, $17,
         $18, $19, $20)
       ON CONFLICT (
         namespace, org_id, window_start_ms, project_id, environment_id, service, route_family, method, status_class
       )
       DO UPDATE SET
         request_count = console_observability_request_rollups_minute.request_count + EXCLUDED.request_count,
         error_count = console_observability_request_rollups_minute.error_count + EXCLUDED.error_count,
         latency_sum_ms = console_observability_request_rollups_minute.latency_sum_ms + EXCLUDED.latency_sum_ms,
         latency_max_ms = GREATEST(
           console_observability_request_rollups_minute.latency_max_ms,
           EXCLUDED.latency_max_ms
         ),
         latency_bucket_le_50 =
           console_observability_request_rollups_minute.latency_bucket_le_50
           + EXCLUDED.latency_bucket_le_50,
         latency_bucket_le_100 =
           console_observability_request_rollups_minute.latency_bucket_le_100
           + EXCLUDED.latency_bucket_le_100,
         latency_bucket_le_250 =
           console_observability_request_rollups_minute.latency_bucket_le_250
           + EXCLUDED.latency_bucket_le_250,
         latency_bucket_le_500 =
           console_observability_request_rollups_minute.latency_bucket_le_500
           + EXCLUDED.latency_bucket_le_500,
         latency_bucket_le_1000 =
           console_observability_request_rollups_minute.latency_bucket_le_1000
           + EXCLUDED.latency_bucket_le_1000,
         latency_bucket_le_2000 =
           console_observability_request_rollups_minute.latency_bucket_le_2000
           + EXCLUDED.latency_bucket_le_2000,
         latency_bucket_le_5000 =
           console_observability_request_rollups_minute.latency_bucket_le_5000
           + EXCLUDED.latency_bucket_le_5000`,
      [
        namespace,
        orgId,
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
      ],
    );
  }

  function ensureNotLegacyRouterTimingEvent(event: ConsoleObservabilityEventEnvelope): void {
    if (normalizeString(event.eventType) !== LEGACY_ROUTER_REQUEST_COMPLETED_EVENT_TYPE) return;
    throw new ConsoleObservabilityError(
      'invalid_body',
      400,
      `Event type ${LEGACY_ROUTER_REQUEST_COMPLETED_EVENT_TYPE} is no longer accepted`,
    );
  }

  async function appendEvents(
    ctx: ConsoleObservabilityIngestionContext,
    events: ConsoleObservabilityEventEnvelope[],
  ): Promise<ConsoleObservabilityEventIngestResult> {
    const orgId = ensureRequiredString('ctx.orgId', ctx.orgId);
    if (!Array.isArray(events) || events.length === 0) {
      return { accepted: 0, deduplicated: 0 };
    }
    if (events.length > maxBatchSize) {
      throw new ConsoleObservabilityError(
        'rate_limited',
        429,
        `Observability ingest batch exceeds max batch size (${maxBatchSize})`,
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
      ensureNotLegacyRouterTimingEvent(event);
      normalizedEvents.push(normalizeEnvelopeForInsert(event, redactionPolicy));
    }

    return withTenantTx(orgId, async (q) => {
      const nowValueMs = nowMs(now());

      if (normalizedEvents.length > 0) {
        await reserveIngestBudget({
          q,
          namespace,
          orgId,
          requestedCount: normalizedEvents.length,
          nowValueMs,
          maxEventsPerMinute,
        });
      }

      const partitionMonthsToEnsure = new Set<number>();
      for (const normalized of normalizedEvents) {
        partitionMonthsToEnsure.add(monthStartUtcMs(normalized.ingestedAtMs));
      }
      for (const partitionMonth of partitionMonthsToEnsure) {
        if (ensuredPartitionMonths.has(partitionMonth)) continue;
        await ensureEventsPartition(q, partitionMonth);
        ensuredPartitionMonths.add(partitionMonth);
      }

      let accepted = 0;
      let deduplicated = 0;
      for (const normalized of normalizedEvents) {
        const createdAtMs = normalized.ingestedAtMs;
        const dedupeReservation = await q.query(
          `INSERT INTO console_observability_event_dedup
            (namespace, org_id, event_id, created_at_ms)
           VALUES
            ($1, $2, $3, $4)
           ON CONFLICT (namespace, org_id, event_id) DO NOTHING
           RETURNING event_id`,
          [namespace, orgId, normalized.eventId, createdAtMs],
        );
        if ((dedupeReservation.rowCount || 0) <= 0) {
          deduplicated += 1;
          continue;
        }

        const out = await q.query(
          `INSERT INTO console_observability_events
            (namespace, org_id, event_id, schema_version, source, ingested_at_ms, timestamp_ms,
             project_id, environment_id, service, component, level, event_type, message,
             request_id, trace_id, metadata, redaction_version, redaction_applied, created_at_ms)
           VALUES
            ($1, $2, $3, $4, $5, $6, $7,
             $8, $9, $10, $11, $12, $13, $14,
             $15, $16, $17, $18, $19, $20)
           ON CONFLICT (namespace, org_id, created_at_ms, event_id) DO NOTHING
           RETURNING event_id`,
          [
            namespace,
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
            normalized.metadata,
            normalized.redactionVersion,
            normalized.redactionApplied,
            createdAtMs,
          ],
        );
        if ((out.rowCount || 0) > 0) {
          accepted += 1;
        } else {
          deduplicated += 1;
        }
      }

      if (retentionTtlMs > 0) {
        const nextRunAt = Number(nextRetentionRunAtByOrg.get(orgId) || 0);
        if (nowValueMs >= nextRunAt) {
          await pruneRetentionForTenant(q, {
            namespace,
            orgId,
            cutoffMs: Math.max(0, nowValueMs - retentionTtlMs),
            batchSize: retentionBatchSize,
          });
          nextRetentionRunAtByOrg.set(orgId, nowValueMs + retentionPruneIntervalMs);
        }
      }

      return { accepted, deduplicated };
    });
  }

  async function appendEvent(
    ctx: ConsoleObservabilityIngestionContext,
    event: ConsoleObservabilityEventEnvelope,
  ): Promise<ConsoleObservabilityEventIngestResult> {
    return appendEvents(ctx, [event]);
  }

  async function observeRequestMetric(
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
    await withTenantTx(orgId, async (q) => {
      const nowValueMs = nowMs(now());
      await observeRequestMetricInTx(q, orgId, metric);
      if (retentionTtlMs > 0) {
        const nextRunAt = Number(nextRetentionRunAtByOrg.get(orgId) || 0);
        if (nowValueMs >= nextRunAt) {
          await pruneRetentionForTenant(q, {
            namespace,
            orgId,
            cutoffMs: Math.max(0, nowValueMs - retentionTtlMs),
            batchSize: retentionBatchSize,
          });
          nextRetentionRunAtByOrg.set(orgId, nowValueMs + retentionPruneIntervalMs);
        }
      }
    });
  }

  return {
    appendEvent,
    appendEvents,
    observeRequestMetric,
  };
}
