import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  normalizeConsoleWebhookEventCategory,
  type ConsoleWebhookEventCategory,
} from '@shared/console/webhookEventCategories';
import type { NormalizedLogger } from '../../core/logger';
import {
  d1Integer as toNumber,
  d1ChangedRows,
  formatD1ExecStatement,
  queryD1All as queryRows,
  queryD1One as queryFirstRow,
  type D1Row,
} from '../../storage/d1Sql';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
import { ConsoleWebhookError } from './errors';
import {
  appendConsoleWebhookObservabilitySignals,
  normalizeConsoleWebhookEndpointDegradedThreshold,
  type ConsoleWebhookObservabilityOptions,
  type ConsoleWebhookObservabilitySignal,
} from './observability';
import {
  encodePaginationCursor,
  normalizePaginationLimit,
  parsePaginationCursor,
} from './pagination';
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
  ConsoleWebhookService,
  WebhookDispatchAdapter,
} from './service';
import type {
  ConsoleWebhooksContext,
  ConsoleWebhookDelivery,
  ConsoleWebhookDeliveryAttempt,
  ConsoleWebhookDeadLetter,
  ConsoleWebhookDeliveryStatus,
  ConsoleWebhookEndpoint,
  ConsoleWebhookEndpointStatus,
  ConsoleWebhookPage,
  CreateConsoleWebhookEndpointRequest,
  EmitConsoleWebhookEventRequest,
  EmitConsoleWebhookEventResult,
  ListConsoleWebhookAttemptsRequest,
  ListConsoleWebhookDeadLettersRequest,
  ListConsoleWebhookDeliveriesRequest,
  ReplayConsoleWebhookDeliveryRequest,
  ReplayConsoleWebhookDeliveryResult,
  UpdateConsoleWebhookEndpointRequest,
} from './types';


const WEBHOOK_SECRET_ENVELOPE_VERSION = 'console-webhook-secret:aes-gcm:v1';
const WEBHOOK_SECRET_AAD_DOMAIN = 'seams/console-webhook-secret/aes-gcm/v1';
const WEBHOOK_SECRET_NONCE_LENGTH = 12;
const WEBHOOK_SECRET_KEY_LENGTH_BYTES = 32;
const WEBHOOK_SECRET_SEAL_MAGIC = new Uint8Array([0x73, 0x77, 0x68, 0x73, 0x01]);

export interface ConsoleWebhookSealedSecret {
  readonly ciphertextB64u: string;
  readonly keyId: string;
  readonly envelopeVersion: string;
}

export interface ConsoleWebhookSecretSealInput {
  readonly orgId: string;
  readonly endpointId: string;
  readonly plaintextSecret: string;
}

export interface ConsoleWebhookSecretOpenInput {
  readonly orgId: string;
  readonly endpointId: string;
  readonly sealedSecret: ConsoleWebhookSealedSecret;
}

export interface ConsoleWebhookSecretCipher {
  sealConsoleWebhookSecret(
    input: ConsoleWebhookSecretSealInput,
  ): Promise<ConsoleWebhookSealedSecret>;
  openConsoleWebhookSecret(input: ConsoleWebhookSecretOpenInput): Promise<string>;
}

export interface AesGcmConsoleWebhookSecretCipherOptions {
  readonly keyId: string;
  readonly keyBytes: Uint8Array;
}

interface StoredWebhookEndpoint extends ConsoleWebhookEndpoint {
  readonly sealedSecret: ConsoleWebhookSealedSecret;
}

interface StoredWebhookDelivery extends ConsoleWebhookDelivery {
  readonly payload: Record<string, unknown>;
  readonly createdAtMs: number;
}

interface StoredWebhookDeliveryAttempt extends ConsoleWebhookDeliveryAttempt {
  readonly attemptedAtMs: number;
}

interface StoredWebhookDeadLetter extends ConsoleWebhookDeadLetter {
  readonly movedToDlqAtMs: number;
}

interface DeliveryAttemptResult {
  readonly status: ConsoleWebhookDeliveryStatus;
  readonly responseStatus: number | null;
  readonly responseBody: string | null;
  readonly errorMessage: string | null;
  readonly attemptedAtMs: number;
}

interface D1ConsoleWebhookState {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
  readonly dispatcher: WebhookDispatchAdapter;
  readonly secretCipher: ConsoleWebhookSecretCipher;
  readonly observabilityOptions: ConsoleWebhookObservabilityOptions;
  readonly endpointDegradedThreshold: number;
}

export const CONSOLE_WEBHOOKS_D1_RUNTIME = Symbol('consoleWebhooksD1Runtime');

export interface ConsoleWebhooksD1Runtime {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

export type ConsoleWebhookD1Service = ConsoleWebhookService & {
  readonly [CONSOLE_WEBHOOKS_D1_RUNTIME]: ConsoleWebhooksD1Runtime;
};

export interface D1ConsoleWebhookSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1ConsoleWebhookServiceOptions extends ConsoleWebhookObservabilityOptions {
  readonly database: D1DatabaseLike;
  readonly secretCipher: ConsoleWebhookSecretCipher;
  readonly namespace?: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
  readonly dispatcher?: WebhookDispatchAdapter;
}

export interface D1ConsoleWebhookRetryDispatchOptions extends ConsoleWebhookObservabilityOptions {
  readonly database: D1DatabaseLike;
  readonly secretCipher: ConsoleWebhookSecretCipher;
  readonly namespace?: string;
  readonly orgIds?: readonly string[];
  readonly limit?: number;
  readonly maxAttempts?: number;
  readonly initialBackoffMs?: number;
  readonly maxBackoffMs?: number;
  readonly ensureSchema?: boolean;
  readonly logger?: NormalizedLogger;
  readonly now?: () => Date;
  readonly dispatcher?: WebhookDispatchAdapter;
  readonly workerId?: string;
  readonly claimTtlMs?: number;
}

export interface D1ConsoleWebhookRetryDispatchResult {
  readonly namespace: string;
  readonly orgCount: number;
  readonly attemptedCount: number;
  readonly deliveredCount: number;
  readonly failedCount: number;
  readonly skippedCount: number;
  readonly failures: readonly {
    readonly orgId: string;
    readonly deliveryId: string;
    readonly message: string;
  }[];
}

export const CONSOLE_WEBHOOKS_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS webhook_endpoints (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      url TEXT NOT NULL,
      status TEXT NOT NULL,
      signing_secret_ciphertext_b64u TEXT NOT NULL,
      signing_secret_key_id TEXT NOT NULL,
      signing_secret_envelope_version TEXT NOT NULL,
      secret_version INTEGER NOT NULL,
      secret_preview TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, id),
      CHECK (length(namespace) > 0),
      CHECK (length(org_id) > 0),
      CHECK (length(id) > 0),
      CHECK (url GLOB 'http://*' OR url GLOB 'https://*'),
      CHECK (status IN ('ACTIVE', 'DISABLED')),
      CHECK (length(signing_secret_ciphertext_b64u) > 0),
      CHECK (signing_secret_ciphertext_b64u NOT GLOB '*[^A-Za-z0-9_-]*'),
      CHECK (length(signing_secret_key_id) > 0),
      CHECK (length(signing_secret_envelope_version) > 0),
      CHECK (secret_version > 0),
      CHECK (length(secret_preview) > 0),
      CHECK (created_at_ms > 0),
      CHECK (updated_at_ms >= created_at_ms)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS webhook_endpoint_categories (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      endpoint_id TEXT NOT NULL,
      category TEXT NOT NULL,
      PRIMARY KEY (namespace, org_id, endpoint_id, category),
      CHECK (length(namespace) > 0),
      CHECK (length(org_id) > 0),
      CHECK (length(endpoint_id) > 0),
      CHECK (category IN ('wallet', 'policy', 'auth', 'tx', 'billing', 'session')),
      FOREIGN KEY (namespace, org_id, endpoint_id)
        REFERENCES webhook_endpoints(namespace, org_id, id)
        ON DELETE CASCADE
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS webhook_deliveries (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      endpoint_id TEXT NOT NULL,
      event_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      status TEXT NOT NULL,
      attempt_count INTEGER NOT NULL,
      replay_count INTEGER NOT NULL,
      response_status INTEGER,
      response_body TEXT,
      error_message TEXT,
      payload_json TEXT NOT NULL,
      delivered_at_ms INTEGER,
      last_attempt_at_ms INTEGER,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      retry_claimed_by TEXT,
      retry_claim_expires_at_ms INTEGER,
      PRIMARY KEY (namespace, org_id, id),
      CHECK (status IN ('SUCCEEDED', 'FAILED')),
      CHECK (attempt_count >= 0),
      CHECK (replay_count >= 0),
      CHECK (json_valid(payload_json)),
      FOREIGN KEY (namespace, org_id, endpoint_id)
        REFERENCES webhook_endpoints(namespace, org_id, id)
        ON DELETE CASCADE
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS webhook_attempts (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      endpoint_id TEXT NOT NULL,
      delivery_id TEXT NOT NULL,
      attempt_no INTEGER NOT NULL,
      status TEXT NOT NULL,
      response_status INTEGER,
      response_body TEXT,
      error_message TEXT,
      attempted_at_ms INTEGER NOT NULL,
      is_replay INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, id),
      UNIQUE (namespace, org_id, delivery_id, attempt_no),
      CHECK (attempt_no > 0),
      CHECK (status IN ('SUCCEEDED', 'FAILED')),
      CHECK (is_replay IN (0, 1)),
      FOREIGN KEY (namespace, org_id, delivery_id)
        REFERENCES webhook_deliveries(namespace, org_id, id)
        ON DELETE CASCADE
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS webhook_dead_letters (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      endpoint_id TEXT NOT NULL,
      delivery_id TEXT NOT NULL,
      event_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      failed_attempts INTEGER NOT NULL,
      last_response_status INTEGER,
      last_error_message TEXT,
      payload_json TEXT NOT NULL,
      moved_to_dlq_at_ms INTEGER NOT NULL,
      resolved_at_ms INTEGER,
      PRIMARY KEY (namespace, org_id, id),
      UNIQUE (namespace, org_id, delivery_id),
      CHECK (failed_attempts > 0),
      CHECK (json_valid(payload_json)),
      FOREIGN KEY (namespace, org_id, delivery_id)
        REFERENCES webhook_deliveries(namespace, org_id, id)
        ON DELETE CASCADE
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS webhook_endpoints_org_created_idx
      ON webhook_endpoints (namespace, org_id, created_at_ms DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS webhook_endpoint_categories_lookup_idx
      ON webhook_endpoint_categories (namespace, org_id, category, endpoint_id)
  `,
  `
    CREATE INDEX IF NOT EXISTS webhook_deliveries_endpoint_page_idx
      ON webhook_deliveries (namespace, org_id, endpoint_id, created_at_ms DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS webhook_deliveries_event_idx
      ON webhook_deliveries (namespace, org_id, event_id)
  `,
  `
    CREATE INDEX IF NOT EXISTS webhook_deliveries_retry_claim_idx
      ON webhook_deliveries (
        namespace,
        org_id,
        status,
        retry_claim_expires_at_ms,
        last_attempt_at_ms,
        created_at_ms,
        id
      )
  `,
  `
    CREATE INDEX IF NOT EXISTS webhook_attempts_endpoint_page_idx
      ON webhook_attempts (namespace, org_id, endpoint_id, attempted_at_ms DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS webhook_attempts_endpoint_delivery_page_idx
      ON webhook_attempts (namespace, org_id, endpoint_id, delivery_id, attempted_at_ms DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS webhook_dead_letters_endpoint_page_idx
      ON webhook_dead_letters (namespace, org_id, endpoint_id, moved_to_dlq_at_ms DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS webhook_dead_letters_unresolved_endpoint_page_idx
      ON webhook_dead_letters (namespace, org_id, endpoint_id, moved_to_dlq_at_ms DESC, id DESC)
      WHERE resolved_at_ms IS NULL
  `,
] as const);

export async function ensureConsoleWebhooksD1Schema(
  options: D1ConsoleWebhookSchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_WEBHOOKS_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export function getConsoleWebhooksD1Runtime(
  service: ConsoleWebhookService | null | undefined,
): ConsoleWebhooksD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (service as Partial<ConsoleWebhookD1Service>)[CONSOLE_WEBHOOKS_D1_RUNTIME] || null;
}

export function createAesGcmConsoleWebhookSecretCipher(
  options: AesGcmConsoleWebhookSecretCipherOptions,
): ConsoleWebhookSecretCipher {
  return new AesGcmConsoleWebhookSecretCipher(options);
}

export async function createD1ConsoleWebhookService(
  options: D1ConsoleWebhookServiceOptions,
): Promise<ConsoleWebhookD1Service> {
  const endpointDegradedThreshold = normalizeConsoleWebhookEndpointDegradedThreshold(
    options.endpointDegradedThreshold,
  );
  const state: D1ConsoleWebhookState = {
    database: options.database,
    namespace: ensureNamespace(options.namespace),
    now: options.now || defaultNow,
    dispatcher: options.dispatcher || { dispatch: defaultDispatchWebhook },
    secretCipher: options.secretCipher,
    endpointDegradedThreshold,
    observabilityOptions: {
      observabilityIngestion: options.observabilityIngestion,
      observabilityLogger: options.observabilityLogger || console,
      endpointDegradedThreshold,
    },
  };
  if (options.ensureSchema !== false) {
    await ensureConsoleWebhooksD1Schema({ database: state.database });
  }
  return new D1ConsoleWebhookServiceImpl(state);
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

function toIso(ms: number | null): string | null {
  if (ms === null) return null;
  return new Date(ms).toISOString();
}


function toNullableNumber(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : null;
}

function normalizePositiveInteger(input: unknown, fallback: number, max: number): number {
  const parsed = Math.floor(Number(input));
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(parsed, max);
}

function normalizeNonNegativeInteger(input: unknown, fallback: number): number {
  const parsed = Math.floor(Number(input));
  if (!Number.isFinite(parsed) || parsed < 0) return fallback;
  return parsed;
}

function normalizeWebhookRetryOrgIds(orgIds: readonly string[] | undefined): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const orgId of Array.isArray(orgIds) ? orgIds : []) {
    const normalized = String(orgId || '').trim();
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
}


function computeWebhookRetryBackoffMs(input: {
  readonly attemptCount: number;
  readonly initialBackoffMs: number;
  readonly maxBackoffMs: number;
}): number {
  if (input.initialBackoffMs <= 0 || input.maxBackoffMs <= 0) return 0;
  const exponent = Math.max(0, input.attemptCount - 1);
  const scaled = input.initialBackoffMs * 2 ** exponent;
  if (!Number.isFinite(scaled)) return input.maxBackoffMs;
  return Math.min(input.maxBackoffMs, Math.max(0, Math.floor(scaled)));
}

function isWebhookRetryDue(input: {
  readonly delivery: StoredWebhookDelivery;
  readonly nowMs: number;
  readonly initialBackoffMs: number;
  readonly maxBackoffMs: number;
}): boolean {
  const lastAttemptMs = Date.parse(String(input.delivery.lastAttemptAt || ''));
  const createdAtMs = Date.parse(String(input.delivery.createdAt || ''));
  const anchorMs = Number.isFinite(lastAttemptMs)
    ? lastAttemptMs
    : Number.isFinite(createdAtMs)
      ? createdAtMs
      : input.nowMs;
  const backoffMs = computeWebhookRetryBackoffMs({
    attemptCount: input.delivery.attemptCount,
    initialBackoffMs: input.initialBackoffMs,
    maxBackoffMs: input.maxBackoffMs,
  });
  return anchorMs + backoffMs <= input.nowMs;
}

function parseEndpointStatus(raw: unknown): ConsoleWebhookEndpointStatus {
  const value = String(raw || '').trim();
  switch (value) {
    case 'DISABLED':
    case 'ACTIVE':
      return value;
    default:
      return 'ACTIVE';
  }
}

function parseDeliveryStatus(raw: unknown): ConsoleWebhookDeliveryStatus {
  const value = String(raw || '').trim();
  switch (value) {
    case 'SUCCEEDED':
    case 'FAILED':
      return value;
    default:
      return 'FAILED';
  }
}

function parsePayload(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return { ...(raw as Record<string, unknown>) };
  }
  if (typeof raw !== 'string') return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return { ...(parsed as Record<string, unknown>) };
    }
  } catch {
    return {};
  }
  return {};
}

function normalizeEventCategories(
  input: readonly unknown[] | undefined,
): ConsoleWebhookEventCategory[] {
  const out: ConsoleWebhookEventCategory[] = [];
  const seen = new Set<string>();
  for (const entry of Array.isArray(input) ? input : []) {
    const value = normalizeConsoleWebhookEventCategory(entry);
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

function parseEndpointRow(input: {
  readonly row: D1Row;
  readonly eventCategories: readonly ConsoleWebhookEventCategory[];
}): StoredWebhookEndpoint {
  const createdAtMs = toNumber(input.row.created_at_ms);
  const updatedAtMs = toNumber(input.row.updated_at_ms);
  return {
    id: String(input.row.id || ''),
    orgId: String(input.row.org_id || ''),
    url: String(input.row.url || ''),
    eventCategories: [...input.eventCategories],
    status: parseEndpointStatus(input.row.status),
    secretVersion: Math.max(1, toNumber(input.row.secret_version, 1)),
    secretPreview: String(input.row.secret_preview || ''),
    createdAt: toIso(createdAtMs) || new Date(0).toISOString(),
    updatedAt: toIso(updatedAtMs) || new Date(0).toISOString(),
    sealedSecret: {
      ciphertextB64u: String(input.row.signing_secret_ciphertext_b64u || ''),
      keyId: String(input.row.signing_secret_key_id || ''),
      envelopeVersion: String(input.row.signing_secret_envelope_version || ''),
    },
  };
}

function parseDeliveryRow(row: D1Row): StoredWebhookDelivery {
  const createdAtMs = toNumber(row.created_at_ms);
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    endpointId: String(row.endpoint_id || ''),
    eventId: String(row.event_id || ''),
    eventType: String(row.event_type || ''),
    status: parseDeliveryStatus(row.status),
    attemptCount: toNumber(row.attempt_count),
    replayCount: toNumber(row.replay_count),
    responseStatus: toNullableNumber(row.response_status),
    responseBody: row.response_body == null ? null : String(row.response_body),
    errorMessage: row.error_message == null ? null : String(row.error_message),
    deliveredAt: toIso(toNullableNumber(row.delivered_at_ms)),
    lastAttemptAt: toIso(toNullableNumber(row.last_attempt_at_ms)),
    createdAt: toIso(createdAtMs) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
    createdAtMs,
    payload: parsePayload(row.payload_json),
  };
}

function parseDeliveryAttemptRow(row: D1Row): StoredWebhookDeliveryAttempt {
  const attemptedAtMs = toNumber(row.attempted_at_ms);
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    endpointId: String(row.endpoint_id || ''),
    deliveryId: String(row.delivery_id || ''),
    attemptNo: toNumber(row.attempt_no),
    status: parseDeliveryStatus(row.status),
    responseStatus: toNullableNumber(row.response_status),
    responseBody: row.response_body == null ? null : String(row.response_body),
    errorMessage: row.error_message == null ? null : String(row.error_message),
    attemptedAt: toIso(attemptedAtMs) || new Date(0).toISOString(),
    attemptedAtMs,
    isReplay: toNumber(row.is_replay) === 1,
  };
}

function parseDeadLetterRow(row: D1Row): StoredWebhookDeadLetter {
  const movedToDlqAtMs = toNumber(row.moved_to_dlq_at_ms);
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
    movedToDlqAt: toIso(movedToDlqAtMs) || new Date(0).toISOString(),
    movedToDlqAtMs,
    resolvedAt: toIso(toNullableNumber(row.resolved_at_ms)),
  };
}

function toPublicEndpoint(input: StoredWebhookEndpoint): ConsoleWebhookEndpoint {
  return {
    id: input.id,
    orgId: input.orgId,
    url: input.url,
    eventCategories: [...input.eventCategories],
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

function toArrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(ab).set(bytes);
  return ab;
}

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function requireCrypto(): Crypto {
  if (
    typeof globalThis.crypto === 'undefined' ||
    typeof globalThis.crypto.getRandomValues !== 'function' ||
    !globalThis.crypto.subtle
  ) {
    throw new Error('WebCrypto getRandomValues and subtle are required for webhook secret sealing');
  }
  return globalThis.crypto;
}

function aadForWebhookSecret(input: {
  readonly orgId: string;
  readonly endpointId: string;
  readonly keyId: string;
}): Uint8Array {
  return new TextEncoder().encode(
    `${WEBHOOK_SECRET_AAD_DOMAIN}\n${input.orgId}\n${input.endpointId}\n${input.keyId}`,
  );
}

async function importAesGcmKey(keyBytes: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  if (keyBytes.byteLength !== WEBHOOK_SECRET_KEY_LENGTH_BYTES) {
    throw new Error(`webhook secret KEK must be ${WEBHOOK_SECRET_KEY_LENGTH_BYTES} bytes`);
  }
  return await requireCrypto().subtle.importKey(
    'raw',
    toArrayBufferCopy(keyBytes),
    { name: 'AES-GCM' },
    false,
    usages,
  );
}

class AesGcmConsoleWebhookSecretCipher implements ConsoleWebhookSecretCipher {
  private readonly keyId: string;
  private readonly keyBytes: Uint8Array;

  constructor(options: AesGcmConsoleWebhookSecretCipherOptions) {
    const keyId = String(options.keyId || '').trim();
    if (!keyId) throw new Error('webhook secret cipher keyId is required');
    if (!(options.keyBytes instanceof Uint8Array)) {
      throw new Error('webhook secret cipher keyBytes must be Uint8Array');
    }
    if (options.keyBytes.byteLength !== WEBHOOK_SECRET_KEY_LENGTH_BYTES) {
      throw new Error(`webhook secret keyBytes must be ${WEBHOOK_SECRET_KEY_LENGTH_BYTES} bytes`);
    }
    this.keyId = keyId;
    this.keyBytes = new Uint8Array(options.keyBytes);
  }

  async sealConsoleWebhookSecret(
    input: ConsoleWebhookSecretSealInput,
  ): Promise<ConsoleWebhookSealedSecret> {
    const plaintextSecret = String(input.plaintextSecret || '').trim();
    if (!plaintextSecret) throw new Error('webhook signing secret is required');
    const crypto = requireCrypto();
    const nonce = crypto.getRandomValues(new Uint8Array(WEBHOOK_SECRET_NONCE_LENGTH));
    const key = await importAesGcmKey(this.keyBytes, ['encrypt']);
    const aad = aadForWebhookSecret({
      orgId: input.orgId,
      endpointId: input.endpointId,
      keyId: this.keyId,
    });
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: toArrayBufferCopy(nonce),
          additionalData: toArrayBufferCopy(aad),
          tagLength: 128,
        },
        key,
        new TextEncoder().encode(plaintextSecret),
      ),
    );
    return {
      ciphertextB64u: base64UrlEncode(
        concatBytes([WEBHOOK_SECRET_SEAL_MAGIC, nonce, ciphertext]),
      ),
      keyId: this.keyId,
      envelopeVersion: WEBHOOK_SECRET_ENVELOPE_VERSION,
    };
  }

  async openConsoleWebhookSecret(input: ConsoleWebhookSecretOpenInput): Promise<string> {
    if (input.sealedSecret.envelopeVersion !== WEBHOOK_SECRET_ENVELOPE_VERSION) {
      throw new Error('unsupported webhook secret envelope version');
    }
    if (input.sealedSecret.keyId !== this.keyId) {
      throw new Error(`webhook secret keyId ${input.sealedSecret.keyId} is not configured`);
    }
    const envelope = base64UrlDecode(input.sealedSecret.ciphertextB64u);
    const minLength =
      WEBHOOK_SECRET_SEAL_MAGIC.byteLength + WEBHOOK_SECRET_NONCE_LENGTH + 16;
    if (envelope.byteLength < minLength) throw new Error('webhook secret envelope is too short');
    for (let i = 0; i < WEBHOOK_SECRET_SEAL_MAGIC.byteLength; i += 1) {
      if (envelope[i] !== WEBHOOK_SECRET_SEAL_MAGIC[i]) {
        throw new Error('webhook secret envelope has invalid magic');
      }
    }
    const nonceStart = WEBHOOK_SECRET_SEAL_MAGIC.byteLength;
    const ciphertextStart = nonceStart + WEBHOOK_SECRET_NONCE_LENGTH;
    const nonce = envelope.slice(nonceStart, ciphertextStart);
    const ciphertext = envelope.slice(ciphertextStart);
    const key = await importAesGcmKey(this.keyBytes, ['decrypt']);
    const aad = aadForWebhookSecret({
      orgId: input.orgId,
      endpointId: input.endpointId,
      keyId: this.keyId,
    });
    const plaintext = await requireCrypto().subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBufferCopy(nonce),
        additionalData: toArrayBufferCopy(aad),
        tagLength: 128,
      },
      key,
      toArrayBufferCopy(ciphertext),
    );
    return new TextDecoder().decode(plaintext);
  }
}

async function countUnresolvedDeadLetters(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly endpointId: string;
}): Promise<number> {
  const row = await queryFirstRow(
    input.database,
    `SELECT COUNT(*) AS count
       FROM webhook_dead_letters
      WHERE namespace = ?
        AND org_id = ?
        AND endpoint_id = ?
        AND resolved_at_ms IS NULL`,
    [input.namespace, input.orgId, input.endpointId],
  );
  return toNumber(row?.count);
}

async function listEndpointCategories(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly endpointId: string;
}): Promise<ConsoleWebhookEventCategory[]> {
  const rows = await queryRows(
    input.database,
    `SELECT category
       FROM webhook_endpoint_categories
      WHERE namespace = ?
        AND org_id = ?
        AND endpoint_id = ?
      ORDER BY category ASC`,
    [input.namespace, input.orgId, input.endpointId],
  );
  return normalizeEventCategories(rows.map((row) => row.category));
}

async function parseEndpointFromRow(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly row: D1Row;
}): Promise<StoredWebhookEndpoint> {
  const orgId = String(input.row.org_id || '');
  const endpointId = String(input.row.id || '');
  const eventCategories = await listEndpointCategories({
    database: input.database,
    namespace: input.namespace,
    orgId,
    endpointId,
  });
  return parseEndpointRow({
    row: input.row,
    eventCategories,
  });
}

async function findEndpoint(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly endpointId: string;
}): Promise<StoredWebhookEndpoint | null> {
  const row = await queryFirstRow(
    input.database,
    `SELECT *
       FROM webhook_endpoints
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?`,
    [input.namespace, input.orgId, input.endpointId],
  );
  if (!row) return null;
  return await parseEndpointFromRow({
    database: input.database,
    namespace: input.namespace,
    row,
  });
}

async function findDelivery(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly endpointId: string;
  readonly deliveryId: string;
}): Promise<StoredWebhookDelivery | null> {
  const row = await queryFirstRow(
    input.database,
    `SELECT *
       FROM webhook_deliveries
      WHERE namespace = ?
        AND org_id = ?
        AND endpoint_id = ?
        AND id = ?`,
    [input.namespace, input.orgId, input.endpointId, input.deliveryId],
  );
  return row ? parseDeliveryRow(row) : null;
}

async function findLatestReplayableDelivery(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly endpointId: string;
}): Promise<StoredWebhookDelivery | null> {
  const row = await queryFirstRow(
    input.database,
    `SELECT *
       FROM webhook_deliveries
      WHERE namespace = ?
        AND org_id = ?
        AND endpoint_id = ?
        AND status <> 'SUCCEEDED'
      ORDER BY created_at_ms DESC, id DESC
      LIMIT 1`,
    [input.namespace, input.orgId, input.endpointId],
  );
  return row ? parseDeliveryRow(row) : null;
}

async function dispatchDelivery(input: {
  readonly endpoint: StoredWebhookEndpoint;
  readonly delivery: StoredWebhookDelivery;
  readonly dispatcher: WebhookDispatchAdapter;
  readonly secretCipher: ConsoleWebhookSecretCipher;
  readonly now: Date;
}): Promise<DeliveryAttemptResult> {
  let dispatchResult: Awaited<ReturnType<WebhookDispatchAdapter['dispatch']>>;
  try {
    const timestamp = String(Math.floor(input.now.getTime() / 1000));
    const eventPayload = {
      id: input.delivery.eventId,
      type: input.delivery.eventType,
      createdAt: coerceIsoDate(input.now),
      data: input.delivery.payload,
    };
    const body = JSON.stringify(eventPayload);
    const signingSecret = await input.secretCipher.openConsoleWebhookSecret({
      orgId: input.endpoint.orgId,
      endpointId: input.endpoint.id,
      sealedSecret: input.endpoint.sealedSecret,
    });
    const signature = await signPayload(signingSecret, `${timestamp}.${body}`);
    const headers = toDispatchHeaders({
      endpointId: input.endpoint.id,
      eventId: input.delivery.eventId,
      eventType: input.delivery.eventType,
      signature,
      timestamp,
    });
    dispatchResult = await input.dispatcher.dispatch({
      endpointId: input.endpoint.id,
      endpointUrl: input.endpoint.url,
      eventId: input.delivery.eventId,
      eventType: input.delivery.eventType,
      headers,
      body,
    });
  } catch (error: unknown) {
    dispatchResult = {
      ok: false,
      statusCode: 0,
      errorMessage: error instanceof Error ? error.message : String(error),
    };
  }

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
  state: D1ConsoleWebhookState,
  input: {
    readonly delivery: StoredWebhookDelivery;
    readonly endpoint: StoredWebhookEndpoint;
    readonly isReplay: boolean;
    readonly now: Date;
    readonly attemptResult: DeliveryAttemptResult;
  },
): Promise<{
  readonly delivery: StoredWebhookDelivery;
  readonly signals: ConsoleWebhookObservabilitySignal[];
}> {
  const nextAttemptNo = input.delivery.attemptCount + 1;
  const attemptId = makeId('whatt', input.now);
  const unresolvedDeadLetterCountBefore =
    input.attemptResult.status === 'FAILED'
      ? await countUnresolvedDeadLetters({
          database: state.database,
          namespace: state.namespace,
          orgId: input.delivery.orgId,
          endpointId: input.endpoint.id,
        })
      : 0;
  const existingDeadLetter =
    input.attemptResult.status === 'FAILED'
      ? await queryFirstRow(
          state.database,
          `SELECT *
             FROM webhook_dead_letters
            WHERE namespace = ?
              AND org_id = ?
              AND delivery_id = ?`,
          [state.namespace, input.delivery.orgId, input.delivery.id],
        )
      : null;

  const statements = [
    state.database
      .prepare(
        `INSERT INTO webhook_attempts
          (namespace, org_id, id, endpoint_id, delivery_id, attempt_no, status, response_status, response_body, error_message, attempted_at_ms, is_replay)
         VALUES
          (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        state.namespace,
        input.delivery.orgId,
        attemptId,
        input.endpoint.id,
        input.delivery.id,
        nextAttemptNo,
        input.attemptResult.status,
        input.attemptResult.responseStatus,
        input.attemptResult.responseBody,
        input.attemptResult.errorMessage,
        input.attemptResult.attemptedAtMs,
        input.isReplay ? 1 : 0,
      ),
    state.database
      .prepare(
        `UPDATE webhook_deliveries
            SET status = ?,
                attempt_count = attempt_count + 1,
                replay_count = replay_count + ?,
                response_status = ?,
                response_body = ?,
                error_message = ?,
                delivered_at_ms = CASE WHEN ? = 'SUCCEEDED' THEN ? ELSE delivered_at_ms END,
                last_attempt_at_ms = ?,
                updated_at_ms = ?,
                retry_claimed_by = NULL,
                retry_claim_expires_at_ms = NULL
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?`,
      )
      .bind(
        input.attemptResult.status,
        input.isReplay ? 1 : 0,
        input.attemptResult.responseStatus,
        input.attemptResult.responseBody,
        input.attemptResult.errorMessage,
        input.attemptResult.status,
        input.attemptResult.attemptedAtMs,
        input.attemptResult.attemptedAtMs,
        input.attemptResult.attemptedAtMs,
        state.namespace,
        input.delivery.orgId,
        input.delivery.id,
      ),
  ];

  if (input.attemptResult.status === 'FAILED') {
    statements.push(
      state.database
        .prepare(
          `INSERT INTO webhook_dead_letters
            (namespace, org_id, id, endpoint_id, delivery_id, event_id, event_type,
             failed_attempts, last_response_status, last_error_message, payload_json, moved_to_dlq_at_ms, resolved_at_ms)
           VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
           ON CONFLICT (namespace, org_id, delivery_id)
           DO UPDATE SET
             failed_attempts = excluded.failed_attempts,
             last_response_status = excluded.last_response_status,
             last_error_message = excluded.last_error_message,
             payload_json = excluded.payload_json,
             moved_to_dlq_at_ms = excluded.moved_to_dlq_at_ms,
             resolved_at_ms = NULL`,
        )
        .bind(
          state.namespace,
          input.delivery.orgId,
          makeId('whdlq', input.now),
          input.endpoint.id,
          input.delivery.id,
          input.delivery.eventId,
          input.delivery.eventType,
          nextAttemptNo,
          input.attemptResult.responseStatus,
          input.attemptResult.errorMessage,
          JSON.stringify(input.delivery.payload),
          input.attemptResult.attemptedAtMs,
        ),
    );
  } else {
    statements.push(
      state.database
        .prepare(
          `UPDATE webhook_dead_letters
              SET resolved_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND delivery_id = ?
              AND resolved_at_ms IS NULL`,
        )
        .bind(
          input.attemptResult.attemptedAtMs,
          state.namespace,
          input.delivery.orgId,
          input.delivery.id,
        ),
    );
  }

  await state.database.batch(statements);
  const updated = await findDelivery({
    database: state.database,
    namespace: state.namespace,
    orgId: input.delivery.orgId,
    endpointId: input.endpoint.id,
    deliveryId: input.delivery.id,
  });
  if (!updated) {
    throw new ConsoleWebhookError(
      'delivery_not_found',
      404,
      `Webhook delivery ${input.delivery.id} was not found`,
    );
  }

  const signals: ConsoleWebhookObservabilitySignal[] = [];
  if (input.attemptResult.status === 'FAILED') {
    const unresolvedDeadLetterCountAfter = await countUnresolvedDeadLetters({
      database: state.database,
      namespace: state.namespace,
      orgId: input.delivery.orgId,
      endpointId: input.endpoint.id,
    });
    const existingResolvedAt = existingDeadLetter
      ? toNullableNumber(existingDeadLetter.resolved_at_ms)
      : null;
    if (!existingDeadLetter || existingResolvedAt !== null) {
      signals.push({
        kind: 'DEAD_LETTER',
        orgId: input.delivery.orgId,
        endpointId: input.endpoint.id,
        deliveryId: input.delivery.id,
        webhookEventId: input.delivery.eventId,
        webhookEventType: input.delivery.eventType,
        failedAttempts: updated.attemptCount,
        lastResponseStatus: input.attemptResult.responseStatus,
        lastErrorMessage: input.attemptResult.errorMessage,
        movedToDlqAt:
          toIso(input.attemptResult.attemptedAtMs) || new Date(0).toISOString(),
      });
    }
    if (
      unresolvedDeadLetterCountBefore < state.endpointDegradedThreshold &&
      unresolvedDeadLetterCountAfter >= state.endpointDegradedThreshold
    ) {
      signals.push({
        kind: 'ENDPOINT_DEGRADED',
        orgId: input.delivery.orgId,
        endpointId: input.endpoint.id,
        unresolvedDeadLetterCount: unresolvedDeadLetterCountAfter,
        degradationThreshold: state.endpointDegradedThreshold,
        latestDeliveryId: input.delivery.id,
        latestWebhookEventId: input.delivery.eventId,
        latestWebhookEventType: input.delivery.eventType,
        lastResponseStatus: input.attemptResult.responseStatus,
        lastErrorMessage: input.attemptResult.errorMessage,
        degradedAt: toIso(input.attemptResult.attemptedAtMs) || new Date(0).toISOString(),
      });
    }
  }

  return {
    delivery: updated,
    signals,
  };
}

async function listD1WebhookRetryEndpoints(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
}): Promise<Map<string, StoredWebhookEndpoint>> {
  const rows = await queryRows(
    input.database,
    `SELECT *
       FROM webhook_endpoints
      WHERE namespace = ?
        AND org_id = ?
        AND status = 'ACTIVE'`,
    [input.namespace, input.orgId],
  );
  const endpoints = new Map<string, StoredWebhookEndpoint>();
  for (const row of rows) {
    const endpoint = await parseEndpointFromRow({
      database: input.database,
      namespace: input.namespace,
      row,
    });
    endpoints.set(endpoint.id, endpoint);
  }
  return endpoints;
}

async function listD1WebhookRetryCandidates(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly maxAttempts: number;
  readonly nowMs: number;
  readonly limit: number;
}): Promise<StoredWebhookDelivery[]> {
  const rows = await queryRows(
    input.database,
    `SELECT *
       FROM webhook_deliveries
      WHERE namespace = ?
        AND org_id = ?
        AND status = 'FAILED'
        AND attempt_count < ?
        AND (
          retry_claim_expires_at_ms IS NULL
          OR retry_claim_expires_at_ms <= ?
        )
      ORDER BY COALESCE(last_attempt_at_ms, created_at_ms) ASC, id ASC
      LIMIT ?`,
    [input.namespace, input.orgId, input.maxAttempts, input.nowMs, input.limit],
  );
  return rows.map(parseDeliveryRow);
}

async function claimD1WebhookRetryDelivery(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly delivery: StoredWebhookDelivery;
  readonly maxAttempts: number;
  readonly nowMs: number;
  readonly workerId: string;
  readonly claimExpiresAtMs: number;
}): Promise<StoredWebhookDelivery | null> {
  const result = await input.database
    .prepare(
      `UPDATE webhook_deliveries
          SET retry_claimed_by = ?,
              retry_claim_expires_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND id = ?
          AND status = 'FAILED'
          AND attempt_count < ?
          AND (
            retry_claim_expires_at_ms IS NULL
            OR retry_claim_expires_at_ms <= ?
          )`,
    )
    .bind(
      input.workerId,
      input.claimExpiresAtMs,
      input.namespace,
      input.orgId,
      input.delivery.id,
      input.maxAttempts,
      input.nowMs,
    )
    .run();
  if (d1ChangedRows(result) < 1) return null;
  const claimed = await findDelivery({
    database: input.database,
    namespace: input.namespace,
    orgId: input.orgId,
    endpointId: input.delivery.endpointId,
    deliveryId: input.delivery.id,
  });
  if (!claimed || claimed.status !== 'FAILED' || claimed.attemptCount >= input.maxAttempts) {
    return null;
  }
  return claimed;
}

function buildD1WebhookRetryExhaustedSignal(input: {
  readonly orgId: string;
  readonly endpoint: StoredWebhookEndpoint;
  readonly delivery: StoredWebhookDelivery;
  readonly maxAttempts: number;
  readonly nowMs: number;
}): ConsoleWebhookObservabilitySignal {
  return {
    kind: 'RETRY_EXHAUSTED',
    orgId: input.orgId,
    endpointId: input.endpoint.id,
    deliveryId: input.delivery.id,
    webhookEventId: input.delivery.eventId,
    webhookEventType: input.delivery.eventType,
    failedAttempts: input.delivery.attemptCount,
    maxAttempts: input.maxAttempts,
    lastResponseStatus: input.delivery.responseStatus,
    lastErrorMessage: input.delivery.errorMessage,
    exhaustedAt: input.delivery.lastAttemptAt || toIso(input.nowMs) || new Date(input.nowMs).toISOString(),
  };
}

export async function runD1ConsoleWebhookRetryDispatch(
  options: D1ConsoleWebhookRetryDispatchOptions,
): Promise<D1ConsoleWebhookRetryDispatchResult> {
  const namespace = ensureNamespace(options.namespace);
  const orgIds = normalizeWebhookRetryOrgIds(options.orgIds);
  if (orgIds.length === 0) {
    throw new Error('Webhook retry dispatch requires at least one orgId');
  }

  const logger = (options.logger || console) as NormalizedLogger;
  const endpointDegradedThreshold = normalizeConsoleWebhookEndpointDegradedThreshold(
    options.endpointDegradedThreshold,
  );
  const observabilityOptions: ConsoleWebhookObservabilityOptions = {
    observabilityIngestion: options.observabilityIngestion,
    observabilityLogger: options.observabilityLogger || logger,
    endpointDegradedThreshold,
  };
  const nowFn = options.now || defaultNow;
  const dispatcher: WebhookDispatchAdapter = options.dispatcher || {
    dispatch: defaultDispatchWebhook,
  };
  const limit = normalizePositiveInteger(options.limit, 100, 1000);
  const maxAttempts = normalizePositiveInteger(options.maxAttempts, 5, 25);
  const initialBackoffMs = normalizeNonNegativeInteger(options.initialBackoffMs, 60_000);
  const maxBackoffMs = Math.max(
    initialBackoffMs,
    normalizeNonNegativeInteger(options.maxBackoffMs, 3_600_000),
  );
  const claimTtlMs = normalizePositiveInteger(options.claimTtlMs, 60_000, 3_600_000);
  const workerId = String(options.workerId || `webhook-retry-${Date.now()}`).trim();
  const state: D1ConsoleWebhookState = {
    database: options.database,
    namespace,
    now: nowFn,
    dispatcher,
    secretCipher: options.secretCipher,
    endpointDegradedThreshold,
    observabilityOptions,
  };

  if (options.ensureSchema !== false) {
    await ensureConsoleWebhooksD1Schema({ database: options.database });
  }

  let attemptedCount = 0;
  let deliveredCount = 0;
  let failedCount = 0;
  let skippedCount = 0;
  const failures: Array<{
    readonly orgId: string;
    readonly deliveryId: string;
    readonly message: string;
  }> = [];

  for (const orgId of orgIds) {
    const nowForQuery = nowFn();
    const nowForQueryMs = nowMs(nowForQuery);
    const endpoints = await listD1WebhookRetryEndpoints({
      database: options.database,
      namespace,
      orgId,
    });
    const candidates = await listD1WebhookRetryCandidates({
      database: options.database,
      namespace,
      orgId,
      maxAttempts,
      nowMs: nowForQueryMs,
      limit: Math.max(1, limit * 4),
    });

    let attemptedForOrg = 0;
    for (const candidate of candidates) {
      if (attemptedForOrg >= limit) break;
      const now = nowFn();
      const retryNowMs = nowMs(now);
      if (
        !isWebhookRetryDue({
          delivery: candidate,
          nowMs: retryNowMs,
          initialBackoffMs,
          maxBackoffMs,
        })
      ) {
        skippedCount += 1;
        continue;
      }

      const endpoint = endpoints.get(candidate.endpointId);
      if (!endpoint) {
        skippedCount += 1;
        continue;
      }

      const claimed = await claimD1WebhookRetryDelivery({
        database: options.database,
        namespace,
        orgId,
        delivery: candidate,
        maxAttempts,
        nowMs: retryNowMs,
        workerId,
        claimExpiresAtMs: retryNowMs + claimTtlMs,
      });
      if (!claimed) {
        skippedCount += 1;
        continue;
      }

      const attemptResult = await dispatchDelivery({
        endpoint,
        delivery: claimed,
        dispatcher,
        secretCipher: options.secretCipher,
        now,
      });
      attemptedCount += 1;
      attemptedForOrg += 1;

      try {
        const persisted = await persistDeliveryAttempt(state, {
          delivery: claimed,
          endpoint,
          isReplay: false,
          now,
          attemptResult,
        });
        const signals = [...persisted.signals];
        if (
          persisted.delivery.status === 'FAILED' &&
          persisted.delivery.attemptCount >= maxAttempts
        ) {
          signals.push(
            buildD1WebhookRetryExhaustedSignal({
              orgId,
              endpoint,
              delivery: persisted.delivery,
              maxAttempts,
              nowMs: retryNowMs,
            }),
          );
        }
        await appendConsoleWebhookObservabilitySignals(
          observabilityOptions,
          {
            orgId,
            actorUserId: 'system-webhook-retry-dispatch',
            roles: ['ops'],
          },
          signals,
        );
        if (persisted.delivery.status === 'SUCCEEDED') deliveredCount += 1;
        else failedCount += 1;
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        failures.push({
          orgId,
          deliveryId: claimed.id,
          message,
        });
        logger.warn('[console-webhooks][d1] retry dispatch failed', {
          namespace,
          orgId,
          deliveryId: claimed.id,
          message,
        });
      }
    }
  }

  return {
    namespace,
    orgCount: orgIds.length,
    attemptedCount,
    deliveredCount,
    failedCount,
    skippedCount,
    failures,
  };
}

async function requireEndpoint(input: {
  readonly state: D1ConsoleWebhookState;
  readonly orgId: string;
  readonly endpointId: string;
}): Promise<StoredWebhookEndpoint> {
  const endpoint = await findEndpoint({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.orgId,
    endpointId: input.endpointId,
  });
  if (endpoint) return endpoint;
  throw new ConsoleWebhookError(
    'webhook_not_found',
    404,
    `Webhook endpoint ${input.endpointId} was not found`,
  );
}

class D1ConsoleWebhookServiceImpl implements ConsoleWebhookD1Service {
  readonly [CONSOLE_WEBHOOKS_D1_RUNTIME]: ConsoleWebhooksD1Runtime;

  private readonly state: D1ConsoleWebhookState;

  constructor(state: D1ConsoleWebhookState) {
    this.state = state;
    this[CONSOLE_WEBHOOKS_D1_RUNTIME] = {
      database: state.database,
      namespace: state.namespace,
      now: state.now,
    };
    this.listEndpoints = this.listEndpoints.bind(this);
    this.createEndpoint = this.createEndpoint.bind(this);
    this.updateEndpoint = this.updateEndpoint.bind(this);
    this.deleteEndpoint = this.deleteEndpoint.bind(this);
    this.listDeliveries = this.listDeliveries.bind(this);
    this.listAttempts = this.listAttempts.bind(this);
    this.listDeadLetters = this.listDeadLetters.bind(this);
    this.replayDelivery = this.replayDelivery.bind(this);
    this.emitEvent = this.emitEvent.bind(this);
  }

  async listEndpoints(ctx: ConsoleWebhooksContext): Promise<ConsoleWebhookEndpoint[]> {
    const rows = await queryRows(
      this.state.database,
      `SELECT *
         FROM webhook_endpoints
        WHERE namespace = ?
          AND org_id = ?
        ORDER BY created_at_ms DESC, id DESC`,
      [this.state.namespace, ctx.orgId],
    );
    const endpoints: ConsoleWebhookEndpoint[] = [];
    for (const row of rows) {
      endpoints.push(
        toPublicEndpoint(
          await parseEndpointFromRow({
            database: this.state.database,
            namespace: this.state.namespace,
            row,
          }),
        ),
      );
    }
    return endpoints;
  }

  async createEndpoint(
    ctx: ConsoleWebhooksContext,
    request: CreateConsoleWebhookEndpointRequest,
  ): Promise<ConsoleWebhookEndpoint> {
    const now = this.state.now();
    const endpointId = makeId('wh', now);
    const signingSecret = makeSigningSecret(now);
    const sealedSecret = await this.state.secretCipher.sealConsoleWebhookSecret({
      orgId: ctx.orgId,
      endpointId,
      plaintextSecret: signingSecret,
    });
    const eventCategories = normalizeEventCategories(request.eventCategories);
    const createdAtMs = nowMs(now);
    await this.state.database.batch([
      this.state.database
        .prepare(
          `INSERT INTO webhook_endpoints
            (namespace, org_id, id, url, status, signing_secret_ciphertext_b64u,
             signing_secret_key_id, signing_secret_envelope_version, secret_version,
             secret_preview, created_at_ms, updated_at_ms)
           VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
        )
        .bind(
          this.state.namespace,
          ctx.orgId,
          endpointId,
          request.url,
          request.status || 'ACTIVE',
          sealedSecret.ciphertextB64u,
          sealedSecret.keyId,
          sealedSecret.envelopeVersion,
          makeSecretPreview(signingSecret),
          createdAtMs,
          createdAtMs,
        ),
      ...eventCategories.map((category) =>
        this.state.database
          .prepare(
            `INSERT INTO webhook_endpoint_categories
              (namespace, org_id, endpoint_id, category)
             VALUES
              (?, ?, ?, ?)`,
          )
          .bind(this.state.namespace, ctx.orgId, endpointId, category),
      ),
    ]);
    const endpoint = await findEndpoint({
      database: this.state.database,
      namespace: this.state.namespace,
      orgId: ctx.orgId,
      endpointId,
    });
    if (!endpoint) {
      throw new ConsoleWebhookError('internal', 500, 'Failed to create webhook endpoint');
    }
    return toPublicEndpoint(endpoint);
  }

  async updateEndpoint(
    ctx: ConsoleWebhooksContext,
    endpointId: string,
    request: UpdateConsoleWebhookEndpointRequest,
  ): Promise<ConsoleWebhookEndpoint | null> {
    const current = await findEndpoint({
      database: this.state.database,
      namespace: this.state.namespace,
      orgId: ctx.orgId,
      endpointId,
    });
    if (!current) return null;

    const now = this.state.now();
    const nextUrl = request.url !== undefined ? request.url : current.url;
    const nextStatus = request.status !== undefined ? request.status : current.status;
    const nextEventCategories =
      request.eventCategories !== undefined
        ? normalizeEventCategories(request.eventCategories)
        : current.eventCategories;
    const statements = [
      this.state.database
        .prepare(
          `UPDATE webhook_endpoints
              SET url = ?,
                  status = ?,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?`,
        )
        .bind(nextUrl, nextStatus, nowMs(now), this.state.namespace, ctx.orgId, endpointId),
      this.state.database
        .prepare(
          `DELETE FROM webhook_endpoint_categories
            WHERE namespace = ?
              AND org_id = ?
              AND endpoint_id = ?`,
        )
        .bind(this.state.namespace, ctx.orgId, endpointId),
      ...nextEventCategories.map((category) =>
        this.state.database
          .prepare(
            `INSERT INTO webhook_endpoint_categories
              (namespace, org_id, endpoint_id, category)
             VALUES
              (?, ?, ?, ?)`,
          )
          .bind(this.state.namespace, ctx.orgId, endpointId, category),
      ),
    ];
    await this.state.database.batch(statements);
    const updated = await findEndpoint({
      database: this.state.database,
      namespace: this.state.namespace,
      orgId: ctx.orgId,
      endpointId,
    });
    return updated ? toPublicEndpoint(updated) : null;
  }

  async deleteEndpoint(
    ctx: ConsoleWebhooksContext,
    endpointId: string,
  ): Promise<{ removed: boolean; endpoint: ConsoleWebhookEndpoint | null }> {
    const current = await findEndpoint({
      database: this.state.database,
      namespace: this.state.namespace,
      orgId: ctx.orgId,
      endpointId,
    });
    if (!current) return { removed: false, endpoint: null };
    await this.state.database.batch([
      this.state.database
        .prepare(
          `DELETE FROM webhook_endpoint_categories
            WHERE namespace = ?
              AND org_id = ?
              AND endpoint_id = ?`,
        )
        .bind(this.state.namespace, ctx.orgId, endpointId),
      this.state.database
        .prepare(
          `DELETE FROM webhook_attempts
            WHERE namespace = ?
              AND org_id = ?
              AND endpoint_id = ?`,
        )
        .bind(this.state.namespace, ctx.orgId, endpointId),
      this.state.database
        .prepare(
          `DELETE FROM webhook_dead_letters
            WHERE namespace = ?
              AND org_id = ?
              AND endpoint_id = ?`,
        )
        .bind(this.state.namespace, ctx.orgId, endpointId),
      this.state.database
        .prepare(
          `DELETE FROM webhook_deliveries
            WHERE namespace = ?
              AND org_id = ?
              AND endpoint_id = ?`,
        )
        .bind(this.state.namespace, ctx.orgId, endpointId),
      this.state.database
        .prepare(
          `DELETE FROM webhook_endpoints
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?`,
        )
        .bind(this.state.namespace, ctx.orgId, endpointId),
    ]);
    return {
      removed: true,
      endpoint: toPublicEndpoint(current),
    };
  }

  async listDeliveries(
    ctx: ConsoleWebhooksContext,
    endpointId: string,
    request: ListConsoleWebhookDeliveriesRequest = {},
  ): Promise<ConsoleWebhookPage<ConsoleWebhookDelivery>> {
    await requireEndpoint({ state: this.state, orgId: ctx.orgId, endpointId });
    const limit = normalizePaginationLimit(request.limit);
    const cursor = parsePaginationCursor(request.cursor);
    const values: unknown[] = [this.state.namespace, ctx.orgId, endpointId];
    let cursorClause = '';
    if (cursor) {
      values.push(cursor.sortMs, cursor.sortMs, cursor.id);
      cursorClause = ` AND (created_at_ms < ? OR (created_at_ms = ? AND id < ?))`;
    }
    values.push(limit + 1);
    const rows = await queryRows(
      this.state.database,
      `SELECT *
         FROM webhook_deliveries
        WHERE namespace = ?
          AND org_id = ?
          AND endpoint_id = ?${cursorClause}
        ORDER BY created_at_ms DESC, id DESC
        LIMIT ?`,
      values,
    );
    const deliveries = rows.map(parseDeliveryRow);
    const hasMore = deliveries.length > limit;
    const items = hasMore ? deliveries.slice(0, limit) : deliveries;
    const nextCursor = hasMore
      ? encodePaginationCursor(items[items.length - 1].createdAtMs, items[items.length - 1].id)
      : undefined;
    return {
      items: items.map(toPublicDelivery),
      ...(nextCursor ? { nextCursor } : {}),
    };
  }

  async listAttempts(
    ctx: ConsoleWebhooksContext,
    endpointId: string,
    request: ListConsoleWebhookAttemptsRequest,
  ): Promise<ConsoleWebhookPage<ConsoleWebhookDeliveryAttempt>> {
    await requireEndpoint({ state: this.state, orgId: ctx.orgId, endpointId });
    const deliveryId = String(request.deliveryId || '').trim();
    if (deliveryId) {
      const delivery = await findDelivery({
        database: this.state.database,
        namespace: this.state.namespace,
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
    const values: unknown[] = [this.state.namespace, ctx.orgId, endpointId];
    let whereSql = 'namespace = ? AND org_id = ? AND endpoint_id = ?';
    if (deliveryId) {
      values.push(deliveryId);
      whereSql += ' AND delivery_id = ?';
    }
    if (cursor) {
      values.push(cursor.sortMs, cursor.sortMs, cursor.id);
      whereSql += ' AND (attempted_at_ms < ? OR (attempted_at_ms = ? AND id < ?))';
    }
    values.push(limit + 1);
    const rows = await queryRows(
      this.state.database,
      `SELECT *
         FROM webhook_attempts
        WHERE ${whereSql}
        ORDER BY attempted_at_ms DESC, id DESC
        LIMIT ?`,
      values,
    );
    const attempts = rows.map(parseDeliveryAttemptRow);
    const hasMore = attempts.length > limit;
    const items = hasMore ? attempts.slice(0, limit) : attempts;
    const nextCursor = hasMore
      ? encodePaginationCursor(items[items.length - 1].attemptedAtMs, items[items.length - 1].id)
      : undefined;
    return {
      items: items.map(toPublicAttempt),
      ...(nextCursor ? { nextCursor } : {}),
    };
  }

  async listDeadLetters(
    ctx: ConsoleWebhooksContext,
    endpointId: string,
    request: ListConsoleWebhookDeadLettersRequest,
  ): Promise<ConsoleWebhookPage<ConsoleWebhookDeadLetter>> {
    await requireEndpoint({ state: this.state, orgId: ctx.orgId, endpointId });
    const deliveryId = String(request.deliveryId || '').trim();
    if (deliveryId) {
      const delivery = await findDelivery({
        database: this.state.database,
        namespace: this.state.namespace,
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

    const values: unknown[] = [this.state.namespace, ctx.orgId, endpointId];
    let whereSql = 'namespace = ? AND org_id = ? AND endpoint_id = ?';
    if (deliveryId) {
      values.push(deliveryId);
      whereSql += ' AND delivery_id = ?';
    }
    if (!request.includeResolved) {
      whereSql += ' AND resolved_at_ms IS NULL';
    }
    const cursor = parsePaginationCursor(request.cursor);
    if (cursor) {
      values.push(cursor.sortMs, cursor.sortMs, cursor.id);
      whereSql += ' AND (moved_to_dlq_at_ms < ? OR (moved_to_dlq_at_ms = ? AND id < ?))';
    }
    const limit = normalizePaginationLimit(request.limit);
    values.push(limit + 1);
    const rows = await queryRows(
      this.state.database,
      `SELECT *
         FROM webhook_dead_letters
        WHERE ${whereSql}
        ORDER BY moved_to_dlq_at_ms DESC, id DESC
        LIMIT ?`,
      values,
    );
    const deadLetters = rows.map(parseDeadLetterRow);
    const hasMore = deadLetters.length > limit;
    const items = hasMore ? deadLetters.slice(0, limit) : deadLetters;
    const nextCursor = hasMore
      ? encodePaginationCursor(items[items.length - 1].movedToDlqAtMs, items[items.length - 1].id)
      : undefined;
    return {
      items: items.map(toPublicDeadLetter),
      ...(nextCursor ? { nextCursor } : {}),
    };
  }

  async replayDelivery(
    ctx: ConsoleWebhooksContext,
    endpointId: string,
    request: ReplayConsoleWebhookDeliveryRequest,
  ): Promise<ReplayConsoleWebhookDeliveryResult> {
    const endpoint = await findEndpoint({
      database: this.state.database,
      namespace: this.state.namespace,
      orgId: ctx.orgId,
      endpointId,
    });
    if (!endpoint) {
      return {
        replayed: false,
        delivery: null,
        reason: 'endpoint_not_found',
      };
    }
    const target = request.deliveryId
      ? await findDelivery({
          database: this.state.database,
          namespace: this.state.namespace,
          orgId: ctx.orgId,
          endpointId,
          deliveryId: request.deliveryId,
        })
      : await findLatestReplayableDelivery({
          database: this.state.database,
          namespace: this.state.namespace,
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

    const now = this.state.now();
    const attemptResult = await dispatchDelivery({
      endpoint,
      delivery: target,
      dispatcher: this.state.dispatcher,
      secretCipher: this.state.secretCipher,
      now,
    });
    const persisted = await persistDeliveryAttempt(this.state, {
      delivery: target,
      endpoint,
      isReplay: true,
      now,
      attemptResult,
    });
    await appendConsoleWebhookObservabilitySignals(
      this.state.observabilityOptions,
      ctx,
      persisted.signals,
    );
    return {
      replayed: true,
      delivery: toPublicDelivery(persisted.delivery),
    };
  }

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
    const eventId = String(request.eventId || '').trim() || makeId('wevt', this.state.now());
    if (!category) {
      return {
        eventId,
        attempted: 0,
        delivered: 0,
        failed: 0,
      };
    }

    const endpointRows = await queryRows(
      this.state.database,
      `SELECT e.*
         FROM webhook_endpoints e
         JOIN webhook_endpoint_categories c
           ON c.namespace = e.namespace
          AND c.org_id = e.org_id
          AND c.endpoint_id = e.id
        WHERE e.namespace = ?
          AND e.org_id = ?
          AND e.status = 'ACTIVE'
          AND c.category = ?
        ORDER BY e.created_at_ms DESC, e.id DESC`,
      [this.state.namespace, ctx.orgId, category],
    );
    const endpoints: StoredWebhookEndpoint[] = [];
    for (const row of endpointRows) {
      endpoints.push(
        await parseEndpointFromRow({
          database: this.state.database,
          namespace: this.state.namespace,
          row,
        }),
      );
    }

    let delivered = 0;
    let failed = 0;
    for (const endpoint of endpoints) {
      const createdAt = this.state.now();
      const createdAtMs = nowMs(createdAt);
      const delivery: StoredWebhookDelivery = {
        id: makeId('whd', createdAt),
        orgId: ctx.orgId,
        endpointId: endpoint.id,
        eventId,
        eventType,
        status: 'FAILED',
        attemptCount: 0,
        replayCount: 0,
        responseStatus: null,
        responseBody: null,
        errorMessage: null,
        deliveredAt: null,
        lastAttemptAt: null,
        createdAt: coerceIsoDate(createdAt),
        updatedAt: coerceIsoDate(createdAt),
        createdAtMs,
        payload: { ...request.payload },
      };
      await this.state.database
        .prepare(
          `INSERT INTO webhook_deliveries
            (namespace, org_id, id, endpoint_id, event_id, event_type, status,
             attempt_count, replay_count, response_status, response_body, error_message,
             payload_json, delivered_at_ms, last_attempt_at_ms, created_at_ms, updated_at_ms)
           VALUES
            (?, ?, ?, ?, ?, ?, 'FAILED', 0, 0, NULL, NULL, NULL, ?, NULL, NULL, ?, ?)`,
        )
        .bind(
          this.state.namespace,
          ctx.orgId,
          delivery.id,
          endpoint.id,
          eventId,
          eventType,
          JSON.stringify(request.payload),
          createdAtMs,
          createdAtMs,
        )
        .run();
      const attemptNow = this.state.now();
      const attemptResult = await dispatchDelivery({
        endpoint,
        delivery,
        dispatcher: this.state.dispatcher,
        secretCipher: this.state.secretCipher,
        now: attemptNow,
      });
      const persisted = await persistDeliveryAttempt(this.state, {
        delivery,
        endpoint,
        isReplay: false,
        now: attemptNow,
        attemptResult,
      });
      await appendConsoleWebhookObservabilitySignals(
        this.state.observabilityOptions,
        ctx,
        persisted.signals,
      );
      if (persisted.delivery.status === 'SUCCEEDED') delivered += 1;
      else failed += 1;
    }

    return {
      eventId,
      attempted: endpoints.length,
      delivered,
      failed,
    };
  }
}
