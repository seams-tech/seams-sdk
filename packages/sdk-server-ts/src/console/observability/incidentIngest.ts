import { getPostgresPool } from '../../storage/postgres';
import { ensureConsoleNamespace as ensureNamespace } from '../shared/postgresNormalize';
import { withConsoleTenantContextTx } from '../shared/postgresTenantContext';
import { ConsoleObservabilityError } from './errors';
import { redactConsoleObservabilityMetadata } from './redaction';
import {
  REQUEST_ROLLUP_WINDOW_MS,
  normalizeConsoleObservabilityRequestMetricForInsert,
} from './requestRollups';
import {
  maybeRunConsoleObservabilityRetentionForTenant,
  type PostgresConsoleObservabilityRetentionCleanupResult,
} from './retention';
import {
  ensureConsoleObservabilityEventsPartition,
  ensureConsoleObservabilityPostgresSchema,
  monthStartUtcMs,
  type PostgresConsoleObservabilitySchemaOptions,
} from './schema';
import type { InMemoryConsoleObservabilityServiceOptions } from './service';
import type {
  ConsoleObservabilityEventEnvelope,
  ConsoleObservabilityEventIngestResult,
  ConsoleObservabilityIngestionContext,
  ConsoleObservabilityLevel,
  ConsoleObservabilityMetadataRedactionPolicy,
  ConsoleObservabilityRequestMetricInput,
  ConsoleObservabilitySource,
} from './types';
import { CONSOLE_OBSERVABILITY_SOURCE_SET } from './policy';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;

const DEFAULT_INGEST_MAX_BATCH_SIZE = 200;
const DEFAULT_INGEST_MAX_EVENTS_PER_MINUTE = 10_000;
const DEFAULT_RETENTION_TTL_MS = 1000 * 60 * 60 * 24 * 30;
const DEFAULT_RETENTION_PRUNE_INTERVAL_MS = 1000 * 60 * 5;
const DEFAULT_RETENTION_BATCH_SIZE = 1_000;
const INGEST_WINDOW_MS = 60_000;
const RETIRED_ROUTER_REQUEST_COMPLETED_EVENT_TYPE = 'router.request.completed';

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
  if (!['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL'].includes(value)) {
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

function ensureNotRetiredRouterTimingEvent(event: ConsoleObservabilityEventEnvelope): void {
  if (normalizeString(event.eventType) !== RETIRED_ROUTER_REQUEST_COMPLETED_EVENT_TYPE) return;
  throw new ConsoleObservabilityError(
    'invalid_body',
    400,
    `Event type ${RETIRED_ROUTER_REQUEST_COMPLETED_EVENT_TYPE} is no longer accepted`,
  );
}

async function observeRequestMetricInTx(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    metric: ConsoleObservabilityRequestMetricInput;
  },
): Promise<void> {
  const normalized = normalizeConsoleObservabilityRequestMetricForInsert(input.metric);
  if (!normalized) return;
  const windowStartMs = normalized.timestampMs - (normalized.timestampMs % REQUEST_ROLLUP_WINDOW_MS);
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
    ],
  );
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
      ensureNotRetiredRouterTimingEvent(event);
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
        await ensureConsoleObservabilityEventsPartition(q, partitionMonth);
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

      await maybeRunConsoleObservabilityRetentionForTenant(q, {
        namespace,
        orgId,
        nowValueMs,
        ttlMs: retentionTtlMs,
        pruneIntervalMs: retentionPruneIntervalMs,
        batchSize: retentionBatchSize,
        nextRunAtByOrg: nextRetentionRunAtByOrg,
      });

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
      await observeRequestMetricInTx(q, {
        namespace,
        orgId,
        metric,
      });
      await maybeRunConsoleObservabilityRetentionForTenant(q, {
        namespace,
        orgId,
        nowValueMs,
        ttlMs: retentionTtlMs,
        pruneIntervalMs: retentionPruneIntervalMs,
        batchSize: retentionBatchSize,
        nextRunAtByOrg: nextRetentionRunAtByOrg,
      });
    });
  }

  return {
    appendEvent,
    appendEvents,
    observeRequestMetric,
  };
}
