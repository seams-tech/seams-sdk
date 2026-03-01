import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  RedisTcpClient,
  UpstashRedisRestClient,
  redisDel,
  redisGetJson,
  redisSetJson,
} from '../../../core/ThresholdService/kv';
import { getPostgresPool } from '../../../storage/postgres';
import { createInMemoryPrfSessionSealIdempotencyStore } from './idempotency';
import type {
  PrfSessionSealIdempotencyStore,
  PrfSessionSealRouteResult,
  PrfSessionSealServiceIdempotencyOptions,
} from './types';

const DEFAULT_KEY_PREFIX = 'threshold-ecdsa:prf-seal:idempotency:';
const DEFAULT_POSTGRES_NAMESPACE = 'threshold-ecdsa:prf-seal:idempotency';

type StoredEntry = {
  result: PrfSessionSealRouteResult;
  expiresAtMs: number;
};

function toPositiveInt(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return undefined;
  return Math.floor(parsed);
}

function normalizeResult(raw: unknown): PrfSessionSealRouteResult | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
  if (obj.ok === true) {
    const ciphertext = toOptionalTrimmedString(obj.ciphertext);
    if (!ciphertext) return null;
    const keyVersion = toOptionalTrimmedString(obj.keyVersion);
    const expiresAtMs = toPositiveInt(obj.expiresAtMs);
    const remainingUses = toPositiveInt(obj.remainingUses);
    return {
      ok: true,
      ciphertext,
      ...(keyVersion ? { keyVersion } : {}),
      ...(expiresAtMs !== undefined ? { expiresAtMs } : {}),
      ...(remainingUses !== undefined ? { remainingUses } : {}),
    };
  }

  if (obj.ok === false) {
    const code = toOptionalTrimmedString(obj.code);
    const message = toOptionalTrimmedString(obj.message);
    if (!code || !message) return null;
    return {
      ok: false,
      code,
      message,
    };
  }

  return null;
}

function normalizeStoredEntry(raw: unknown): StoredEntry | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
  const result = normalizeResult(obj.result);
  const expiresAtMs = toPositiveInt(obj.expiresAtMs);
  if (!result || expiresAtMs === undefined) return null;
  return { result, expiresAtMs };
}

function prefixedKey(prefix: string, keyRaw: string): string {
  const key = toOptionalTrimmedString(keyRaw);
  if (!key) return '';
  return prefix ? `${prefix}${key}` : key;
}

function ttlMsUntilExpiry(expiresAtMs: number, nowMs: number): number {
  const ttlMs = Math.floor(expiresAtMs - nowMs);
  return ttlMs > 0 ? ttlMs : 0;
}

export interface CreateUpstashPrfSessionSealIdempotencyStoreOptions {
  url: string;
  token: string;
  keyPrefix?: string;
  nowMs?: () => number;
}

class UpstashPrfSessionSealIdempotencyStore implements PrfSessionSealIdempotencyStore {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;
  private readonly nowMs: () => number;

  constructor(options: CreateUpstashPrfSessionSealIdempotencyStoreOptions) {
    this.client = new UpstashRedisRestClient({
      url: options.url,
      token: options.token,
    });
    this.keyPrefix = toOptionalTrimmedString(options.keyPrefix) || DEFAULT_KEY_PREFIX;
    this.nowMs = options.nowMs || Date.now;
  }

  async get(input: { key: string; nowMs: number }): Promise<PrfSessionSealRouteResult | null> {
    const key = prefixedKey(this.keyPrefix, input.key);
    if (!key) return null;
    const raw = await this.client.getJson(key);
    const entry = normalizeStoredEntry(raw);
    if (!entry) return null;
    if (entry.expiresAtMs <= input.nowMs) {
      try {
        await this.client.del(key);
      } catch {}
      return null;
    }
    return entry.result;
  }

  async set(input: { key: string; result: PrfSessionSealRouteResult; expiresAtMs: number }): Promise<void> {
    const key = prefixedKey(this.keyPrefix, input.key);
    if (!key) return;
    const expiresAtMs = toPositiveInt(input.expiresAtMs);
    if (expiresAtMs === undefined) return;
    const normalizedResult = normalizeResult(input.result);
    if (!normalizedResult) return;
    const ttlMs = ttlMsUntilExpiry(expiresAtMs, this.nowMs());
    if (ttlMs <= 0) return;
    await this.client.setJson(
      key,
      {
        result: normalizedResult,
        expiresAtMs,
      },
      ttlMs,
    );
  }
}

export interface CreateRedisTcpPrfSessionSealIdempotencyStoreOptions {
  redisUrl: string;
  keyPrefix?: string;
  nowMs?: () => number;
}

class RedisTcpPrfSessionSealIdempotencyStore implements PrfSessionSealIdempotencyStore {
  private readonly client: RedisTcpClient;
  private readonly keyPrefix: string;
  private readonly nowMs: () => number;

  constructor(options: CreateRedisTcpPrfSessionSealIdempotencyStoreOptions) {
    this.client = new RedisTcpClient(options.redisUrl);
    this.keyPrefix = toOptionalTrimmedString(options.keyPrefix) || DEFAULT_KEY_PREFIX;
    this.nowMs = options.nowMs || Date.now;
  }

  async get(input: { key: string; nowMs: number }): Promise<PrfSessionSealRouteResult | null> {
    const key = prefixedKey(this.keyPrefix, input.key);
    if (!key) return null;
    const raw = await redisGetJson(this.client, key);
    const entry = normalizeStoredEntry(raw);
    if (!entry) return null;
    if (entry.expiresAtMs <= input.nowMs) {
      try {
        await redisDel(this.client, key);
      } catch {}
      return null;
    }
    return entry.result;
  }

  async set(input: { key: string; result: PrfSessionSealRouteResult; expiresAtMs: number }): Promise<void> {
    const key = prefixedKey(this.keyPrefix, input.key);
    if (!key) return;
    const expiresAtMs = toPositiveInt(input.expiresAtMs);
    if (expiresAtMs === undefined) return;
    const normalizedResult = normalizeResult(input.result);
    if (!normalizedResult) return;
    const ttlMs = ttlMsUntilExpiry(expiresAtMs, this.nowMs());
    if (ttlMs <= 0) return;
    await redisSetJson(
      this.client,
      key,
      {
        result: normalizedResult,
        expiresAtMs,
      },
      ttlMs,
    );
  }
}

export function createUpstashPrfSessionSealIdempotencyStore(
  options: CreateUpstashPrfSessionSealIdempotencyStoreOptions,
): PrfSessionSealIdempotencyStore {
  return new UpstashPrfSessionSealIdempotencyStore(options);
}

export function createRedisTcpPrfSessionSealIdempotencyStore(
  options: CreateRedisTcpPrfSessionSealIdempotencyStoreOptions,
): PrfSessionSealIdempotencyStore {
  return new RedisTcpPrfSessionSealIdempotencyStore(options);
}

export interface CreatePostgresPrfSessionSealIdempotencyStoreOptions {
  postgresUrl: string;
  namespace?: string;
}

class PostgresPrfSessionSealIdempotencyStore implements PrfSessionSealIdempotencyStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly schemaReady: Promise<void>;
  private readonly namespace: string;

  constructor(options: CreatePostgresPrfSessionSealIdempotencyStoreOptions) {
    this.poolPromise = getPostgresPool(options.postgresUrl);
    this.namespace = toOptionalTrimmedString(options.namespace) || DEFAULT_POSTGRES_NAMESPACE;
    this.schemaReady = this.ensureSchema();
  }

  private async ensureSchema(): Promise<void> {
    const pool = await this.poolPromise;
    await pool.query(`
      CREATE TABLE IF NOT EXISTS threshold_ecdsa_prf_seal_idempotency (
        namespace TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        result_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, idempotency_key)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS threshold_ecdsa_prf_seal_idempotency_expires_idx
      ON threshold_ecdsa_prf_seal_idempotency (namespace, expires_at_ms)
    `);
  }

  async get(input: { key: string; nowMs: number }): Promise<PrfSessionSealRouteResult | null> {
    const key = toOptionalTrimmedString(input.key);
    if (!key) return null;
    await this.schemaReady;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT result_json, expires_at_ms
        FROM threshold_ecdsa_prf_seal_idempotency
        WHERE namespace = $1 AND idempotency_key = $2
        LIMIT 1
      `,
      [this.namespace, key],
    );
    const row = rows[0] as { result_json?: unknown; expires_at_ms?: unknown } | undefined;
    if (!row) return null;
    const expiresAtMs =
      typeof row.expires_at_ms === 'number' ? row.expires_at_ms : Number(row.expires_at_ms);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= input.nowMs) {
      await pool.query(
        `
          DELETE FROM threshold_ecdsa_prf_seal_idempotency
          WHERE namespace = $1 AND idempotency_key = $2
        `,
        [this.namespace, key],
      );
      return null;
    }
    return normalizeResult(row.result_json);
  }

  async set(input: { key: string; result: PrfSessionSealRouteResult; expiresAtMs: number }): Promise<void> {
    const key = toOptionalTrimmedString(input.key);
    if (!key) return;
    const expiresAtMs = toPositiveInt(input.expiresAtMs);
    if (expiresAtMs === undefined) return;
    const result = normalizeResult(input.result);
    if (!result) return;
    await this.schemaReady;
    const pool = await this.poolPromise;
    const updatedAtMs = Date.now();
    await pool.query(
      `
        INSERT INTO threshold_ecdsa_prf_seal_idempotency (
          namespace,
          idempotency_key,
          result_json,
          expires_at_ms,
          updated_at_ms
        )
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (namespace, idempotency_key)
        DO UPDATE SET
          result_json = EXCLUDED.result_json,
          expires_at_ms = EXCLUDED.expires_at_ms,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [this.namespace, key, result, expiresAtMs, updatedAtMs],
    );
  }
}

export function createPostgresPrfSessionSealIdempotencyStore(
  options: CreatePostgresPrfSessionSealIdempotencyStoreOptions,
): PrfSessionSealIdempotencyStore {
  const postgresUrl = toOptionalTrimmedString(options.postgresUrl);
  if (!postgresUrl) {
    throw new Error('Postgres PRF session-seal idempotency requires postgresUrl');
  }
  return new PostgresPrfSessionSealIdempotencyStore({
    postgresUrl,
    namespace: options.namespace,
  });
}

export interface CreatePrfSessionSealIdempotencyFromEnvInput {
  idempotencyKind?: string | null;
  upstashUrl?: string | null;
  upstashToken?: string | null;
  redisUrl?: string | null;
  keyPrefix?: string | null;
  postgresUrl?: string | null;
  postgresNamespace?: string | null;
  ttlMs?: number | null;
}

export function resolvePrfSessionSealIdempotencyFromEnv(
  input: CreatePrfSessionSealIdempotencyFromEnvInput,
): PrfSessionSealServiceIdempotencyOptions {
  const idempotencyKind = toOptionalTrimmedString(input.idempotencyKind || '').toLowerCase();
  const upstashUrl = toOptionalTrimmedString(input.upstashUrl || '');
  const upstashToken = toOptionalTrimmedString(input.upstashToken || '');
  const redisUrl = toOptionalTrimmedString(input.redisUrl || '');
  const postgresUrl = toOptionalTrimmedString(input.postgresUrl || '');
  const postgresNamespace =
    toOptionalTrimmedString(input.postgresNamespace || '') || DEFAULT_POSTGRES_NAMESPACE;
  const keyPrefix = toOptionalTrimmedString(input.keyPrefix || '') || DEFAULT_KEY_PREFIX;
  const ttlMs = toPositiveInt(input.ttlMs);

  const selectedKind =
    idempotencyKind ||
    (upstashUrl || upstashToken
      ? 'upstash-redis-rest'
      : redisUrl
        ? 'redis-tcp'
        : postgresUrl
          ? 'postgres'
          : 'in-memory');

  let store: PrfSessionSealIdempotencyStore;
  if (selectedKind === 'upstash-redis-rest') {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        'Upstash PRF session-seal idempotency requires both upstashUrl and upstashToken',
      );
    }
    store = createUpstashPrfSessionSealIdempotencyStore({
      url: upstashUrl,
      token: upstashToken,
      keyPrefix,
    });
  } else if (selectedKind === 'redis-tcp') {
    if (!redisUrl) {
      throw new Error('Redis TCP PRF session-seal idempotency requires redisUrl');
    }
    store = createRedisTcpPrfSessionSealIdempotencyStore({
      redisUrl,
      keyPrefix,
    });
  } else if (selectedKind === 'postgres') {
    if (!postgresUrl) {
      throw new Error('Postgres PRF session-seal idempotency requires postgresUrl');
    }
    store = createPostgresPrfSessionSealIdempotencyStore({
      postgresUrl,
      namespace: postgresNamespace,
    });
  } else if (selectedKind === 'in-memory') {
    store = createInMemoryPrfSessionSealIdempotencyStore();
  } else {
    throw new Error(
      `Unsupported PRF session-seal idempotency kind "${selectedKind}". Expected in-memory, upstash-redis-rest, redis-tcp, or postgres.`,
    );
  }

  return {
    store,
    ...(ttlMs ? { ttlMs } : {}),
  };
}
