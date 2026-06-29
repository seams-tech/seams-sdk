import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  RedisTcpClient,
  UpstashRedisRestClient,
  redisDel,
  redisGetJson,
  redisSetJson,
} from '../../../core/ThresholdService/kv';
import { createInMemorySigningSessionSealIdempotencyStore } from './idempotency';
import {
  parseCurrentSigningSessionSealIdempotencyRouteResult,
  parseCurrentSigningSessionSealIdempotencyStoredEntry,
} from './idempotencyRecords';
import type {
  SigningSessionSealIdempotencyStore,
  SigningSessionSealRouteResult,
  SigningSessionSealServiceIdempotencyOptions,
} from './signingSessionSeal.types';

const DEFAULT_KEY_PREFIX = 'threshold:signing-session-seal:idempotency:';

function toPositiveInt(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return undefined;
  return Math.floor(parsed);
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

export interface CreateUpstashSigningSessionSealIdempotencyStoreOptions {
  url: string;
  token: string;
  keyPrefix?: string;
  nowMs?: () => number;
}

class UpstashSigningSessionSealIdempotencyStore implements SigningSessionSealIdempotencyStore {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;
  private readonly nowMs: () => number;

  constructor(options: CreateUpstashSigningSessionSealIdempotencyStoreOptions) {
    this.client = new UpstashRedisRestClient({
      url: options.url,
      token: options.token,
    });
    this.keyPrefix = toOptionalTrimmedString(options.keyPrefix) || DEFAULT_KEY_PREFIX;
    this.nowMs = options.nowMs || Date.now;
  }

  async get(input: { key: string; nowMs: number }): Promise<SigningSessionSealRouteResult | null> {
    const key = prefixedKey(this.keyPrefix, input.key);
    if (!key) return null;
    const raw = await this.client.getJson(key);
    const entry = parseCurrentSigningSessionSealIdempotencyStoredEntry(raw);
    if (!entry) return null;
    if (entry.expiresAtMs <= input.nowMs) {
      try {
        await this.client.del(key);
      } catch {}
      return null;
    }
    return entry.result;
  }

  async set(input: { key: string; result: SigningSessionSealRouteResult; expiresAtMs: number }): Promise<void> {
    const key = prefixedKey(this.keyPrefix, input.key);
    if (!key) return;
    const expiresAtMs = toPositiveInt(input.expiresAtMs);
    if (expiresAtMs === undefined) return;
    const normalizedResult = parseCurrentSigningSessionSealIdempotencyRouteResult(input.result);
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

export interface CreateRedisTcpSigningSessionSealIdempotencyStoreOptions {
  redisUrl: string;
  keyPrefix?: string;
  nowMs?: () => number;
}

class RedisTcpSigningSessionSealIdempotencyStore implements SigningSessionSealIdempotencyStore {
  private readonly client: RedisTcpClient;
  private readonly keyPrefix: string;
  private readonly nowMs: () => number;

  constructor(options: CreateRedisTcpSigningSessionSealIdempotencyStoreOptions) {
    this.client = new RedisTcpClient(options.redisUrl);
    this.keyPrefix = toOptionalTrimmedString(options.keyPrefix) || DEFAULT_KEY_PREFIX;
    this.nowMs = options.nowMs || Date.now;
  }

  async get(input: { key: string; nowMs: number }): Promise<SigningSessionSealRouteResult | null> {
    const key = prefixedKey(this.keyPrefix, input.key);
    if (!key) return null;
    const raw = await redisGetJson(this.client, key);
    const entry = parseCurrentSigningSessionSealIdempotencyStoredEntry(raw);
    if (!entry) return null;
    if (entry.expiresAtMs <= input.nowMs) {
      try {
        await redisDel(this.client, key);
      } catch {}
      return null;
    }
    return entry.result;
  }

  async set(input: { key: string; result: SigningSessionSealRouteResult; expiresAtMs: number }): Promise<void> {
    const key = prefixedKey(this.keyPrefix, input.key);
    if (!key) return;
    const expiresAtMs = toPositiveInt(input.expiresAtMs);
    if (expiresAtMs === undefined) return;
    const normalizedResult = parseCurrentSigningSessionSealIdempotencyRouteResult(input.result);
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

export function createUpstashSigningSessionSealIdempotencyStore(
  options: CreateUpstashSigningSessionSealIdempotencyStoreOptions,
): SigningSessionSealIdempotencyStore {
  return new UpstashSigningSessionSealIdempotencyStore(options);
}

export function createRedisTcpSigningSessionSealIdempotencyStore(
  options: CreateRedisTcpSigningSessionSealIdempotencyStoreOptions,
): SigningSessionSealIdempotencyStore {
  return new RedisTcpSigningSessionSealIdempotencyStore(options);
}

export interface CreateSigningSessionSealIdempotencyFromEnvInput {
  idempotencyKind?: string | null;
  upstashUrl?: string | null;
  upstashToken?: string | null;
  redisUrl?: string | null;
  keyPrefix?: string | null;
  ttlMs?: number | null;
}

export function resolveSigningSessionSealIdempotencyFromEnv(
  input: CreateSigningSessionSealIdempotencyFromEnvInput,
): SigningSessionSealServiceIdempotencyOptions {
  const idempotencyKind = toOptionalTrimmedString(input.idempotencyKind || '').toLowerCase();
  const upstashUrl = toOptionalTrimmedString(input.upstashUrl || '');
  const upstashToken = toOptionalTrimmedString(input.upstashToken || '');
  const redisUrl = toOptionalTrimmedString(input.redisUrl || '');
  const keyPrefix = toOptionalTrimmedString(input.keyPrefix || '') || DEFAULT_KEY_PREFIX;
  const ttlMs = toPositiveInt(input.ttlMs);

  const selectedKind =
    idempotencyKind ||
    (upstashUrl || upstashToken
      ? 'upstash-redis-rest'
      : redisUrl
        ? 'redis-tcp'
        : 'in-memory');

  let store: SigningSessionSealIdempotencyStore;
  if (selectedKind === 'upstash-redis-rest') {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        'Upstash signing session-seal idempotency requires both upstashUrl and upstashToken',
      );
    }
    store = createUpstashSigningSessionSealIdempotencyStore({
      url: upstashUrl,
      token: upstashToken,
      keyPrefix,
    });
  } else if (selectedKind === 'redis-tcp') {
    if (!redisUrl) {
      throw new Error('Redis TCP signing session-seal idempotency requires redisUrl');
    }
    store = createRedisTcpSigningSessionSealIdempotencyStore({
      redisUrl,
      keyPrefix,
    });
  } else if (selectedKind === 'in-memory') {
    store = createInMemorySigningSessionSealIdempotencyStore();
  } else {
    throw new Error(
      `Unsupported signing session-seal idempotency kind "${selectedKind}". Expected in-memory, upstash-redis-rest, or redis-tcp.`,
    );
  }

  return {
    store,
    ...(ttlMs ? { ttlMs } : {}),
  };
}
