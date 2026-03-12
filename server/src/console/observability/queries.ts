import { getPostgresPool } from '../../storage/postgres';
import { ensureConsoleNamespace as ensureNamespace } from '../shared/postgresNormalize';
import { withConsoleTenantContextTx } from '../shared/postgresTenantContext';
import { ConsoleObservabilityError } from './errors';
import {
  REQUEST_ROLLUP_BUCKET_COLUMN_NAMES,
  percentileFromConsoleObservabilityHistogram,
} from './requestRollups';
import {
  ensureConsoleObservabilityPostgresSchema,
  type PostgresConsoleObservabilitySchemaOptions,
} from './schema';
import type {
  ConsoleObservabilityContext,
  ConsoleObservabilityService,
  InMemoryConsoleObservabilityServiceOptions,
} from './service';
import type {
  ConsoleObservabilityEvent,
  ConsoleObservabilityEventsPage,
  ConsoleObservabilityLevel,
  ConsoleObservabilityServiceHealth,
  ConsoleObservabilityServicesView,
  ConsoleObservabilitySummary,
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

const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 200;
const DEFAULT_BUCKET_MINUTES = 5;
const MAX_BUCKET_MINUTES = 60;
const DEFAULT_QUERY_MAX_WINDOW_MS = 1000 * 60 * 60 * 24 * 7;

const OBSERVABILITY_LEVELS = new Set<ConsoleObservabilityLevel>([
  'DEBUG',
  'INFO',
  'WARN',
  'ERROR',
  'FATAL',
]);

interface EventsCursor {
  sortMs: number;
  eventId: string;
}

export interface PostgresConsoleObservabilityServiceOptions
  extends PostgresConsoleObservabilitySchemaOptions,
    Pick<InMemoryConsoleObservabilityServiceOptions, 'now'> {
  namespace?: string;
  ensureSchema?: boolean;
  queryMaxWindowMs?: number;
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
        p95LatencyMs: percentileFromConsoleObservabilityHistogram(histogramCounts, 0.95),
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
          p50LatencyMs: percentileFromConsoleObservabilityHistogram(histogramCounts, 0.5),
          p95LatencyMs: percentileFromConsoleObservabilityHistogram(histogramCounts, 0.95),
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
