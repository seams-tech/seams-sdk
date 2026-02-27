import type { NormalizedLogger } from '../../core/logger';
import { getPostgresPool } from '../../storage/postgres';
import {
  ensureConsoleNamespace as ensureNamespace,
  toConsoleIso as toIso,
  toConsoleNumber as toNumber,
} from '../shared/postgresNormalize';
import { ConsoleWebhookError } from './errors';
import {
  coerceIsoDate,
  defaultDispatchWebhook,
  makeId,
  makeSecretPreview,
  makeSigningSecret,
  normalizeEventCategory,
  signPayload,
  toDispatchHeaders,
  truncateResponseBody,
} from './shared';
import type {
  ConsoleWebhookDelivery,
  ConsoleWebhookDeliveryAttempt,
  ConsoleWebhookDeadLetter,
  ConsoleWebhookEndpoint,
  ConsoleWebhookPage,
  ConsoleWebhookSubscription,
  CreateConsoleWebhookEndpointRequest,
  EmitConsoleWebhookEventRequest,
  EmitConsoleWebhookEventResult,
  ListConsoleWebhookDeliveriesRequest,
  ListConsoleWebhookAttemptsRequest,
  ListConsoleWebhookDeadLettersRequest,
  ReplayConsoleWebhookDeliveryRequest,
  ReplayConsoleWebhookDeliveryResult,
  UpdateConsoleWebhookEndpointRequest,
} from './types';
import type {
  ConsoleWebhookService,
  ConsoleWebhooksContext,
  WebhookDispatchAdapter,
} from './service';
import {
  encodePaginationCursor,
  normalizePaginationLimit,
  parsePaginationCursor,
} from './pagination';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_WEBHOOKS_MIGRATION_LOCK_ID = 9452360123584;

interface StoredWebhookEndpoint extends ConsoleWebhookEndpoint {
  signingSecret: string;
}

interface StoredWebhookDelivery extends ConsoleWebhookDelivery {
  payload: Record<string, unknown>;
}

interface StoredWebhookDeliveryAttempt extends ConsoleWebhookDeliveryAttempt {
  attemptedAtMs: number;
}

interface StoredWebhookDeadLetter extends ConsoleWebhookDeadLetter {
  movedToDlqAtMs: number;
}

interface DeliveryAttemptResult {
  status: ConsoleWebhookDelivery['status'];
  responseStatus: number | null;
  responseBody: string | null;
  errorMessage: string | null;
  attemptedAtMs: number;
}

function nowMs(now: Date): number {
  return now.getTime();
}

function toNullableNumber(v: unknown): number | null {
  if (v === null || v === undefined) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function parseBigintCursorId(id: string): string {
  const value = String(id || '').trim();
  if (!/^\d+$/.test(value)) {
    throw new ConsoleWebhookError('invalid_query', 400, 'Invalid cursor value');
  }
  return value;
}

function parseSubscriptions(raw: unknown): ConsoleWebhookSubscription[] {
  const parsed = (() => {
    if (Array.isArray(raw)) return raw;
    if (typeof raw === 'string') {
      try {
        const json = JSON.parse(raw);
        return Array.isArray(json) ? json : [];
      } catch {
        return [];
      }
    }
    return [];
  })();

  const values: ConsoleWebhookSubscription[] = [];
  const seen = new Set<string>();
  for (const item of parsed) {
    const value = String(item || '')
      .trim()
      .toLowerCase();
    if (
      value !== 'wallet' &&
      value !== 'policy' &&
      value !== 'auth' &&
      value !== 'tx' &&
      value !== 'billing'
    ) {
      continue;
    }
    if (seen.has(value)) continue;
    seen.add(value);
    values.push(value as ConsoleWebhookSubscription);
  }
  return values;
}

function parsePayload(raw: unknown): Record<string, unknown> {
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

function parseEndpointRow(row: PgRow): StoredWebhookEndpoint {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    url: String(row.url || ''),
    subscriptions: parseSubscriptions(row.subscriptions),
    status: String(row.status || 'ACTIVE') as ConsoleWebhookEndpoint['status'],
    secretVersion: toNumber(row.secret_version),
    secretPreview: String(row.secret_preview || ''),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
    signingSecret: String(row.signing_secret || ''),
  };
}

function parseDeliveryRow(row: PgRow): StoredWebhookDelivery {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    endpointId: String(row.endpoint_id || ''),
    eventId: String(row.event_id || ''),
    eventType: String(row.event_type || ''),
    status: String(row.status || 'FAILED') as ConsoleWebhookDelivery['status'],
    attemptCount: toNumber(row.attempt_count),
    replayCount: toNumber(row.replay_count),
    responseStatus: toNullableNumber(row.response_status),
    responseBody: row.response_body == null ? null : String(row.response_body),
    errorMessage: row.error_message == null ? null : String(row.error_message),
    deliveredAt: toIso(toNullableNumber(row.delivered_at_ms)),
    lastAttemptAt: toIso(toNullableNumber(row.last_attempt_at_ms)),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
    payload: parsePayload(row.payload_json),
  };
}

function parseDeliveryAttemptRow(row: PgRow): StoredWebhookDeliveryAttempt {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    endpointId: String(row.endpoint_id || ''),
    deliveryId: String(row.delivery_id || ''),
    attemptNo: toNumber(row.attempt_no),
    status: String(row.status || 'FAILED') as ConsoleWebhookDelivery['status'],
    responseStatus: toNullableNumber(row.response_status),
    responseBody: row.response_body == null ? null : String(row.response_body),
    errorMessage: row.error_message == null ? null : String(row.error_message),
    attemptedAt: toIso(toNumber(row.attempted_at_ms)) || new Date(0).toISOString(),
    attemptedAtMs: toNumber(row.attempted_at_ms),
    isReplay: Boolean(row.is_replay),
  };
}

function parseDeadLetterRow(row: PgRow): StoredWebhookDeadLetter {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    endpointId: String(row.endpoint_id || ''),
    deliveryId: String(row.delivery_id || ''),
    eventId: String(row.event_id || ''),
    eventType: String(row.event_type || ''),
    failedAttempts: toNumber(row.failed_attempts),
    lastResponseStatus: toNullableNumber(row.last_response_status),
    lastErrorMessage: row.last_error_message == null ? null : String(row.last_error_message),
    movedToDlqAt: toIso(toNumber(row.moved_to_dlq_at_ms)) || new Date(0).toISOString(),
    movedToDlqAtMs: toNumber(row.moved_to_dlq_at_ms),
    resolvedAt: toIso(toNullableNumber(row.resolved_at_ms)),
  };
}

function toPublicEndpoint(input: StoredWebhookEndpoint): ConsoleWebhookEndpoint {
  return {
    id: input.id,
    orgId: input.orgId,
    url: input.url,
    subscriptions: [...input.subscriptions],
    status: input.status,
    secretVersion: input.secretVersion,
    secretPreview: input.secretPreview,
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
  };
}

function toPublicDelivery(input: StoredWebhookDelivery): ConsoleWebhookDelivery {
  return {
    id: input.id,
    orgId: input.orgId,
    endpointId: input.endpointId,
    eventId: input.eventId,
    eventType: input.eventType,
    status: input.status,
    attemptCount: input.attemptCount,
    replayCount: input.replayCount,
    responseStatus: input.responseStatus,
    responseBody: input.responseBody,
    errorMessage: input.errorMessage,
    deliveredAt: input.deliveredAt,
    lastAttemptAt: input.lastAttemptAt,
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
  };
}

function toPublicAttempt(input: StoredWebhookDeliveryAttempt): ConsoleWebhookDeliveryAttempt {
  return {
    id: input.id,
    orgId: input.orgId,
    endpointId: input.endpointId,
    deliveryId: input.deliveryId,
    attemptNo: input.attemptNo,
    status: input.status,
    responseStatus: input.responseStatus,
    responseBody: input.responseBody,
    errorMessage: input.errorMessage,
    attemptedAt: input.attemptedAt,
    isReplay: input.isReplay,
  };
}

function toPublicDeadLetter(input: StoredWebhookDeadLetter): ConsoleWebhookDeadLetter {
  return {
    id: input.id,
    orgId: input.orgId,
    endpointId: input.endpointId,
    deliveryId: input.deliveryId,
    eventId: input.eventId,
    eventType: input.eventType,
    failedAttempts: input.failedAttempts,
    lastResponseStatus: input.lastResponseStatus,
    lastErrorMessage: input.lastErrorMessage,
    movedToDlqAt: input.movedToDlqAt,
    resolvedAt: input.resolvedAt,
  };
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

async function withTx<T>(pool: PgPool, fn: (q: Queryable) => Promise<T>): Promise<T> {
  await pool.query('BEGIN');
  try {
    const result = await fn(pool);
    await pool.query('COMMIT');
    return result;
  } catch (error: unknown) {
    try {
      await pool.query('ROLLBACK');
    } catch {
      // no-op
    }
    throw error;
  }
}

async function dispatchDelivery(input: {
  endpoint: StoredWebhookEndpoint;
  delivery: StoredWebhookDelivery;
  dispatcher: WebhookDispatchAdapter;
  now: Date;
}): Promise<DeliveryAttemptResult> {
  const timestamp = String(Math.floor(input.now.getTime() / 1000));
  const eventPayload = {
    id: input.delivery.eventId,
    type: input.delivery.eventType,
    createdAt: coerceIsoDate(input.now),
    data: input.delivery.payload,
  };
  const body = JSON.stringify(eventPayload);
  const signature = await signPayload(input.endpoint.signingSecret, `${timestamp}.${body}`);
  const headers = toDispatchHeaders({
    endpointId: input.endpoint.id,
    eventId: input.delivery.eventId,
    eventType: input.delivery.eventType,
    signature,
    timestamp,
  });
  const dispatchResult = await input.dispatcher.dispatch({
    endpointId: input.endpoint.id,
    endpointUrl: input.endpoint.url,
    eventId: input.delivery.eventId,
    eventType: input.delivery.eventType,
    headers,
    body,
  });

  return {
    status: dispatchResult.ok ? 'SUCCEEDED' : 'FAILED',
    responseStatus:
      Number.isInteger(dispatchResult.statusCode) && dispatchResult.statusCode > 0
        ? dispatchResult.statusCode
        : null,
    responseBody: truncateResponseBody(dispatchResult.responseBody),
    errorMessage: dispatchResult.ok
      ? null
      : dispatchResult.errorMessage || `HTTP ${dispatchResult.statusCode || 0}`,
    attemptedAtMs: nowMs(input.now),
  };
}

async function persistDeliveryAttempt(
  q: Queryable,
  input: {
    namespace: string;
    delivery: StoredWebhookDelivery;
    endpoint: StoredWebhookEndpoint;
    isReplay: boolean;
    now: Date;
    attemptResult: DeliveryAttemptResult;
  },
): Promise<StoredWebhookDelivery> {
  const nextAttemptNo = input.delivery.attemptCount + 1;
  await q.query(
    `INSERT INTO console_webhook_attempts
      (namespace, delivery_id, org_id, endpoint_id, attempt_no, status, response_status, response_body, error_message, attempted_at_ms, is_replay)
     VALUES
      ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
    [
      input.namespace,
      input.delivery.id,
      input.delivery.orgId,
      input.delivery.endpointId,
      nextAttemptNo,
      input.attemptResult.status,
      input.attemptResult.responseStatus,
      input.attemptResult.responseBody,
      input.attemptResult.errorMessage,
      input.attemptResult.attemptedAtMs,
      input.isReplay,
    ],
  );

  const updated = await queryOne(
    q,
    `UPDATE console_webhook_deliveries
        SET status = $3,
            attempt_count = attempt_count + 1,
            replay_count = replay_count + $4,
            response_status = $5,
            response_body = $6,
            error_message = $7,
            delivered_at_ms = CASE WHEN $3 = 'SUCCEEDED' THEN $8 ELSE delivered_at_ms END,
            last_attempt_at_ms = $8,
            updated_at_ms = $8
      WHERE namespace = $1 AND id = $2
      RETURNING *`,
    [
      input.namespace,
      input.delivery.id,
      input.attemptResult.status,
      input.isReplay ? 1 : 0,
      input.attemptResult.responseStatus,
      input.attemptResult.responseBody,
      input.attemptResult.errorMessage,
      input.attemptResult.attemptedAtMs,
    ],
  );
  if (!updated) {
    throw new ConsoleWebhookError(
      'delivery_not_found',
      404,
      `Webhook delivery ${input.delivery.id} was not found`,
    );
  }
  const nextDelivery = parseDeliveryRow(updated);

  if (input.attemptResult.status === 'FAILED') {
    await q.query(
      `INSERT INTO console_webhook_dead_letters
        (namespace, id, org_id, endpoint_id, delivery_id, event_id, event_type,
         failed_attempts, last_response_status, last_error_message, payload_json, moved_to_dlq_at_ms, resolved_at_ms)
       VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, NULL)
       ON CONFLICT (namespace, delivery_id)
       DO UPDATE SET
         failed_attempts = EXCLUDED.failed_attempts,
         last_response_status = EXCLUDED.last_response_status,
         last_error_message = EXCLUDED.last_error_message,
         payload_json = EXCLUDED.payload_json,
         moved_to_dlq_at_ms = EXCLUDED.moved_to_dlq_at_ms,
         resolved_at_ms = NULL`,
      [
        input.namespace,
        makeId('whdlq', input.now),
        input.delivery.orgId,
        input.endpoint.id,
        input.delivery.id,
        input.delivery.eventId,
        input.delivery.eventType,
        nextDelivery.attemptCount,
        input.attemptResult.responseStatus,
        input.attemptResult.errorMessage,
        JSON.stringify(input.delivery.payload),
        input.attemptResult.attemptedAtMs,
      ],
    );
  } else {
    await q.query(
      `UPDATE console_webhook_dead_letters
          SET resolved_at_ms = $3
        WHERE namespace = $1 AND delivery_id = $2 AND resolved_at_ms IS NULL`,
      [input.namespace, input.delivery.id, input.attemptResult.attemptedAtMs],
    );
  }

  return nextDelivery;
}

export interface PostgresConsoleWebhookSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleWebhooksPostgresSchema(
  options: PostgresConsoleWebhookSchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_WEBHOOKS_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_webhook_endpoints (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        url TEXT NOT NULL,
        subscriptions JSONB NOT NULL,
        status TEXT NOT NULL,
        signing_secret TEXT NOT NULL,
        secret_version INTEGER NOT NULL,
        secret_preview TEXT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        CHECK (status IN ('ACTIVE', 'DISABLED')),
        CHECK (jsonb_typeof(subscriptions) = 'array')
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_webhook_endpoints_org_created_idx
      ON console_webhook_endpoints (namespace, org_id, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_webhook_endpoints_subscriptions_gin_idx
      ON console_webhook_endpoints USING GIN (subscriptions)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_webhook_deliveries (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        endpoint_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        status TEXT NOT NULL,
        attempt_count INTEGER NOT NULL,
        replay_count INTEGER NOT NULL,
        response_status INTEGER,
        response_body TEXT,
        error_message TEXT,
        payload_json JSONB NOT NULL,
        delivered_at_ms BIGINT,
        last_attempt_at_ms BIGINT,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        CHECK (status IN ('SUCCEEDED', 'FAILED')),
        FOREIGN KEY (namespace, endpoint_id)
          REFERENCES console_webhook_endpoints(namespace, id)
          ON DELETE CASCADE
      )
    `);
    await pool.query('DROP INDEX IF EXISTS console_webhook_deliveries_endpoint_created_idx');
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_webhook_deliveries_endpoint_page_idx
      ON console_webhook_deliveries (namespace, org_id, endpoint_id, created_at_ms DESC, id DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_webhook_deliveries_event_idx
      ON console_webhook_deliveries (namespace, event_id)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_webhook_attempts (
        id BIGSERIAL PRIMARY KEY,
        namespace TEXT NOT NULL,
        delivery_id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        endpoint_id TEXT NOT NULL,
        attempt_no INTEGER NOT NULL,
        status TEXT NOT NULL,
        response_status INTEGER,
        response_body TEXT,
        error_message TEXT,
        attempted_at_ms BIGINT NOT NULL,
        is_replay BOOLEAN NOT NULL,
        CHECK (status IN ('SUCCEEDED', 'FAILED')),
        FOREIGN KEY (namespace, delivery_id)
          REFERENCES console_webhook_deliveries(namespace, id)
          ON DELETE CASCADE
      )
    `);
    await pool.query('DROP INDEX IF EXISTS console_webhook_attempts_delivery_attempt_idx');
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_webhook_attempts_endpoint_page_idx
      ON console_webhook_attempts (namespace, org_id, endpoint_id, attempted_at_ms DESC, id DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_webhook_attempts_endpoint_delivery_page_idx
      ON console_webhook_attempts (namespace, org_id, endpoint_id, delivery_id, attempted_at_ms DESC, id DESC)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_webhook_dead_letters (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        endpoint_id TEXT NOT NULL,
        delivery_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        failed_attempts INTEGER NOT NULL,
        last_response_status INTEGER,
        last_error_message TEXT,
        payload_json JSONB NOT NULL,
        moved_to_dlq_at_ms BIGINT NOT NULL,
        resolved_at_ms BIGINT,
        PRIMARY KEY (namespace, id),
        UNIQUE (namespace, delivery_id),
        FOREIGN KEY (namespace, delivery_id)
          REFERENCES console_webhook_deliveries(namespace, id)
          ON DELETE CASCADE
      )
    `);
    await pool.query('DROP INDEX IF EXISTS console_webhook_dead_letters_unresolved_idx');
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_webhook_dead_letters_endpoint_page_idx
      ON console_webhook_dead_letters (namespace, org_id, endpoint_id, moved_to_dlq_at_ms DESC, id DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_webhook_dead_letters_unresolved_endpoint_page_idx
      ON console_webhook_dead_letters (namespace, org_id, endpoint_id, moved_to_dlq_at_ms DESC, id DESC)
      WHERE resolved_at_ms IS NULL
    `);
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_WEBHOOKS_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }
  options.logger.info('[console-webhooks][postgres] Schema ready');
}

export interface PostgresConsoleWebhookServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
  dispatcher?: WebhookDispatchAdapter;
}

export async function createPostgresConsoleWebhookService(
  options: PostgresConsoleWebhookServiceOptions,
): Promise<ConsoleWebhookService> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) throw new Error('Missing POSTGRES_URL for Postgres console webhook service');

  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const nowFn = options.now || (() => new Date());
  const dispatcher: WebhookDispatchAdapter = options.dispatcher || {
    dispatch: defaultDispatchWebhook,
  };

  if (options.ensureSchema !== false) {
    await ensureConsoleWebhooksPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);

  async function findEndpoint(
    q: Queryable,
    input: { orgId: string; endpointId: string },
  ): Promise<StoredWebhookEndpoint | null> {
    const row = await queryOne(
      q,
      `SELECT *
         FROM console_webhook_endpoints
        WHERE namespace = $1 AND org_id = $2 AND id = $3`,
      [namespace, input.orgId, input.endpointId],
    );
    return row ? parseEndpointRow(row) : null;
  }

  async function findDelivery(
    q: Queryable,
    input: { orgId: string; endpointId: string; deliveryId: string },
  ): Promise<StoredWebhookDelivery | null> {
    const row = await queryOne(
      q,
      `SELECT *
         FROM console_webhook_deliveries
        WHERE namespace = $1 AND org_id = $2 AND endpoint_id = $3 AND id = $4`,
      [namespace, input.orgId, input.endpointId, input.deliveryId],
    );
    return row ? parseDeliveryRow(row) : null;
  }

  async function findLatestReplayableDelivery(
    q: Queryable,
    input: { orgId: string; endpointId: string },
  ): Promise<StoredWebhookDelivery | null> {
    const row = await queryOne(
      q,
      `SELECT *
         FROM console_webhook_deliveries
        WHERE namespace = $1 AND org_id = $2 AND endpoint_id = $3 AND status <> 'SUCCEEDED'
        ORDER BY created_at_ms DESC
        LIMIT 1`,
      [namespace, input.orgId, input.endpointId],
    );
    return row ? parseDeliveryRow(row) : null;
  }

  return {
    async listEndpoints(ctx: ConsoleWebhooksContext): Promise<ConsoleWebhookEndpoint[]> {
      const out = await pool.query(
        `SELECT *
           FROM console_webhook_endpoints
          WHERE namespace = $1 AND org_id = $2
          ORDER BY created_at_ms DESC`,
        [namespace, ctx.orgId],
      );
      return out.rows.map((row) => toPublicEndpoint(parseEndpointRow(row as PgRow)));
    },

    async createEndpoint(
      ctx: ConsoleWebhooksContext,
      request: CreateConsoleWebhookEndpointRequest,
    ): Promise<ConsoleWebhookEndpoint> {
      const now = nowFn();
      const signingSecret = makeSigningSecret(now);
      const row = await queryOne(
        pool,
        `INSERT INTO console_webhook_endpoints
          (namespace, id, org_id, url, subscriptions, status, signing_secret, secret_version, secret_preview, created_at_ms, updated_at_ms)
         VALUES
          ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $10)
         RETURNING *`,
        [
          namespace,
          makeId('wh', now),
          ctx.orgId,
          request.url,
          JSON.stringify(request.subscriptions),
          request.status || 'ACTIVE',
          signingSecret,
          1,
          makeSecretPreview(signingSecret),
          nowMs(now),
        ],
      );
      if (!row) {
        throw new ConsoleWebhookError('internal', 500, 'Failed to create webhook endpoint');
      }
      return toPublicEndpoint(parseEndpointRow(row));
    },

    async updateEndpoint(
      ctx: ConsoleWebhooksContext,
      endpointId: string,
      request: UpdateConsoleWebhookEndpointRequest,
    ): Promise<ConsoleWebhookEndpoint | null> {
      const current = await findEndpoint(pool, { orgId: ctx.orgId, endpointId });
      if (!current) return null;

      const now = nowFn();
      const nextUrl = request.url !== undefined ? request.url : current.url;
      const nextSubscriptions =
        request.subscriptions !== undefined ? request.subscriptions : current.subscriptions;
      const nextStatus = request.status !== undefined ? request.status : current.status;

      const row = await queryOne(
        pool,
        `UPDATE console_webhook_endpoints
            SET url = $4,
                subscriptions = $5::jsonb,
                status = $6,
                updated_at_ms = $7
          WHERE namespace = $1 AND org_id = $2 AND id = $3
          RETURNING *`,
        [
          namespace,
          ctx.orgId,
          endpointId,
          nextUrl,
          JSON.stringify(nextSubscriptions),
          nextStatus,
          nowMs(now),
        ],
      );
      if (!row) return null;
      return toPublicEndpoint(parseEndpointRow(row));
    },

    async deleteEndpoint(
      ctx: ConsoleWebhooksContext,
      endpointId: string,
    ): Promise<{ removed: boolean }> {
      const out = await pool.query(
        `DELETE FROM console_webhook_endpoints
          WHERE namespace = $1 AND org_id = $2 AND id = $3
          RETURNING id`,
        [namespace, ctx.orgId, endpointId],
      );
      return { removed: out.rows.length > 0 };
    },

    async listDeliveries(
      ctx: ConsoleWebhooksContext,
      endpointId: string,
      request: ListConsoleWebhookDeliveriesRequest = {},
    ): Promise<ConsoleWebhookPage<ConsoleWebhookDelivery>> {
      const endpoint = await findEndpoint(pool, { orgId: ctx.orgId, endpointId });
      if (!endpoint) {
        throw new ConsoleWebhookError(
          'webhook_not_found',
          404,
          `Webhook endpoint ${endpointId} was not found`,
        );
      }

      const limit = normalizePaginationLimit(request.limit);
      const cursor = parsePaginationCursor(request.cursor);
      const values: unknown[] = [namespace, ctx.orgId, endpointId];
      let cursorClause = '';
      if (cursor) {
        values.push(cursor.sortMs, cursor.id);
        cursorClause = ` AND (created_at_ms < $${values.length - 1} OR (created_at_ms = $${values.length - 1} AND id < $${values.length}))`;
      }
      values.push(limit + 1);

      const out = await pool.query(
        `SELECT *
           FROM console_webhook_deliveries
          WHERE namespace = $1 AND org_id = $2 AND endpoint_id = $3${cursorClause}
          ORDER BY created_at_ms DESC, id DESC
          LIMIT $${values.length}`,
        values,
      );

      const rows = out.rows.map((row) => parseDeliveryRow(row as PgRow));
      const hasMore = rows.length > limit;
      const pageItems = hasMore ? rows.slice(0, limit) : rows;
      const nextCursor = hasMore
        ? encodePaginationCursor(
            Date.parse(pageItems[pageItems.length - 1].createdAt),
            pageItems[pageItems.length - 1].id,
          )
        : undefined;
      return {
        items: pageItems.map(toPublicDelivery),
        ...(nextCursor ? { nextCursor } : {}),
      };
    },

    async listAttempts(
      ctx: ConsoleWebhooksContext,
      endpointId: string,
      request: ListConsoleWebhookAttemptsRequest,
    ): Promise<ConsoleWebhookPage<ConsoleWebhookDeliveryAttempt>> {
      const endpoint = await findEndpoint(pool, { orgId: ctx.orgId, endpointId });
      if (!endpoint) {
        throw new ConsoleWebhookError(
          'webhook_not_found',
          404,
          `Webhook endpoint ${endpointId} was not found`,
        );
      }

      const deliveryId = String(request.deliveryId || '').trim();
      if (deliveryId) {
        const delivery = await findDelivery(pool, {
          orgId: ctx.orgId,
          endpointId,
          deliveryId,
        });
        if (!delivery) {
          throw new ConsoleWebhookError(
            'delivery_not_found',
            404,
            `Webhook delivery ${deliveryId} was not found`,
          );
        }
      }

      const limit = normalizePaginationLimit(request.limit);
      const cursor = parsePaginationCursor(request.cursor);
      const values: unknown[] = [namespace, ctx.orgId, endpointId];
      let whereClause = 'namespace = $1 AND org_id = $2 AND endpoint_id = $3';
      if (deliveryId) {
        values.push(deliveryId);
        whereClause += ` AND delivery_id = $${values.length}`;
      }
      if (cursor) {
        values.push(cursor.sortMs, parseBigintCursorId(cursor.id));
        whereClause += ` AND (attempted_at_ms < $${values.length - 1} OR (attempted_at_ms = $${values.length - 1} AND id < $${values.length}))`;
      }
      values.push(limit + 1);

      const out = await pool.query(
        `SELECT *
           FROM console_webhook_attempts
          WHERE ${whereClause}
          ORDER BY attempted_at_ms DESC, id DESC
          LIMIT $${values.length}`,
        values,
      );

      const rows = out.rows.map((row) => parseDeliveryAttemptRow(row as PgRow));
      const hasMore = rows.length > limit;
      const pageItems = hasMore ? rows.slice(0, limit) : rows;
      const nextCursor = hasMore
        ? encodePaginationCursor(
            pageItems[pageItems.length - 1].attemptedAtMs,
            pageItems[pageItems.length - 1].id,
          )
        : undefined;
      return {
        items: pageItems.map(toPublicAttempt),
        ...(nextCursor ? { nextCursor } : {}),
      };
    },

    async listDeadLetters(
      ctx: ConsoleWebhooksContext,
      endpointId: string,
      request: ListConsoleWebhookDeadLettersRequest,
    ): Promise<ConsoleWebhookPage<ConsoleWebhookDeadLetter>> {
      const endpoint = await findEndpoint(pool, { orgId: ctx.orgId, endpointId });
      if (!endpoint) {
        throw new ConsoleWebhookError(
          'webhook_not_found',
          404,
          `Webhook endpoint ${endpointId} was not found`,
        );
      }

      const deliveryId = String(request.deliveryId || '').trim();
      if (deliveryId) {
        const delivery = await findDelivery(pool, {
          orgId: ctx.orgId,
          endpointId,
          deliveryId,
        });
        if (!delivery) {
          throw new ConsoleWebhookError(
            'delivery_not_found',
            404,
            `Webhook delivery ${deliveryId} was not found`,
          );
        }
      }

      const values: unknown[] = [namespace, ctx.orgId, endpointId];
      let whereClause = 'namespace = $1 AND org_id = $2 AND endpoint_id = $3';
      if (deliveryId) {
        values.push(deliveryId);
        whereClause += ` AND delivery_id = $${values.length}`;
      }
      if (!request.includeResolved) {
        whereClause += ' AND resolved_at_ms IS NULL';
      }
      const cursor = parsePaginationCursor(request.cursor);
      if (cursor) {
        values.push(cursor.sortMs, cursor.id);
        whereClause += ` AND (moved_to_dlq_at_ms < $${values.length - 1} OR (moved_to_dlq_at_ms = $${values.length - 1} AND id < $${values.length}))`;
      }
      const limit = normalizePaginationLimit(request.limit);
      values.push(limit + 1);

      const out = await pool.query(
        `SELECT *
           FROM console_webhook_dead_letters
          WHERE ${whereClause}
          ORDER BY moved_to_dlq_at_ms DESC, id DESC
          LIMIT $${values.length}`,
        values,
      );
      const rows = out.rows.map((row) => parseDeadLetterRow(row as PgRow));
      const hasMore = rows.length > limit;
      const pageItems = hasMore ? rows.slice(0, limit) : rows;
      const nextCursor = hasMore
        ? encodePaginationCursor(
            pageItems[pageItems.length - 1].movedToDlqAtMs,
            pageItems[pageItems.length - 1].id,
          )
        : undefined;
      return {
        items: pageItems.map(toPublicDeadLetter),
        ...(nextCursor ? { nextCursor } : {}),
      };
    },

    async replayDelivery(
      ctx: ConsoleWebhooksContext,
      endpointId: string,
      request: ReplayConsoleWebhookDeliveryRequest,
    ): Promise<ReplayConsoleWebhookDeliveryResult> {
      const endpoint = await findEndpoint(pool, { orgId: ctx.orgId, endpointId });
      if (!endpoint) {
        return {
          replayed: false,
          delivery: null,
          reason: 'endpoint_not_found',
        };
      }

      const target = request.deliveryId
        ? await findDelivery(pool, {
            orgId: ctx.orgId,
            endpointId,
            deliveryId: request.deliveryId,
          })
        : await findLatestReplayableDelivery(pool, {
            orgId: ctx.orgId,
            endpointId,
          });

      if (!target) {
        return {
          replayed: false,
          delivery: null,
          reason: request.deliveryId ? 'delivery_not_found' : 'no_replayable_delivery',
        };
      }

      const now = nowFn();
      const attemptResult = await dispatchDelivery({
        endpoint,
        delivery: target,
        dispatcher,
        now,
      });
      const updated = await withTx(pool, async (q) =>
        persistDeliveryAttempt(q, {
          namespace,
          delivery: target,
          endpoint,
          isReplay: true,
          now,
          attemptResult,
        }),
      );

      return {
        replayed: true,
        delivery: toPublicDelivery(updated),
      };
    },

    async emitEvent(
      ctx: ConsoleWebhooksContext,
      request: EmitConsoleWebhookEventRequest,
    ): Promise<EmitConsoleWebhookEventResult> {
      const eventType = String(request.eventType || '').trim();
      if (!eventType) {
        throw new ConsoleWebhookError('invalid_event_type', 400, 'eventType is required');
      }
      if (
        !request.payload ||
        typeof request.payload !== 'object' ||
        Array.isArray(request.payload)
      ) {
        throw new ConsoleWebhookError('invalid_payload', 400, 'payload must be a JSON object');
      }

      const category = normalizeEventCategory(eventType);
      const now = nowFn();
      const eventId = String(request.eventId || '').trim() || makeId('wevt', now);
      if (!category) {
        return {
          eventId,
          attempted: 0,
          delivered: 0,
          failed: 0,
        };
      }

      const endpointRows = await pool.query(
        `SELECT *
           FROM console_webhook_endpoints
          WHERE namespace = $1
            AND org_id = $2
            AND status = 'ACTIVE'
            AND subscriptions ? $3
          ORDER BY created_at_ms DESC`,
        [namespace, ctx.orgId, category],
      );
      const endpoints = endpointRows.rows.map((row) => parseEndpointRow(row as PgRow));

      let delivered = 0;
      let failed = 0;
      for (const endpoint of endpoints) {
        const createdAt = nowFn();
        const createdAtMs = nowMs(createdAt);
        const inserted = await queryOne(
          pool,
          `INSERT INTO console_webhook_deliveries
            (namespace, id, org_id, endpoint_id, event_id, event_type, status, attempt_count, replay_count,
             response_status, response_body, error_message, payload_json, delivered_at_ms, last_attempt_at_ms, created_at_ms, updated_at_ms)
           VALUES
            ($1, $2, $3, $4, $5, $6, 'FAILED', 0, 0, NULL, NULL, NULL, $7::jsonb, NULL, NULL, $8, $8)
           RETURNING *`,
          [
            namespace,
            makeId('whd', createdAt),
            ctx.orgId,
            endpoint.id,
            eventId,
            eventType,
            JSON.stringify(request.payload),
            createdAtMs,
          ],
        );
        if (!inserted) {
          throw new ConsoleWebhookError('internal', 500, 'Failed to create webhook delivery');
        }
        const delivery = parseDeliveryRow(inserted);
        const attemptNow = nowFn();
        const attemptResult = await dispatchDelivery({
          endpoint,
          delivery,
          dispatcher,
          now: attemptNow,
        });

        const updated = await withTx(pool, async (q) =>
          persistDeliveryAttempt(q, {
            namespace,
            delivery,
            endpoint,
            isReplay: false,
            now: attemptNow,
            attemptResult,
          }),
        );
        if (updated.status === 'SUCCEEDED') delivered += 1;
        else failed += 1;
      }

      return {
        eventId,
        attempted: endpoints.length,
        delivered,
        failed,
      };
    },
  };
}
