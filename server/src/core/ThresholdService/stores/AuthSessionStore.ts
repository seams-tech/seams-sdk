import type { NormalizedLogger } from '../../logger';
import type {
  ThresholdEcdsaSigningRootMetadata,
  ThresholdStoreConfigInput,
} from '../../types';
import { RedisTcpClient, UpstashRedisRestClient, redisGetJson, redisSetJson } from '../kv';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { getPostgresPool, getPostgresUrlFromConfig } from '../../../storage/postgres';
import {
  isObject,
  toThresholdEcdsaAuthPrefix,
  toThresholdEcdsaPrefixFromBase,
  toThresholdEd25519AuthPrefix,
  toThresholdEd25519PrefixFromBase,
  parseEd25519AuthSessionRecord,
} from '../validation';
import {
  createCloudflareDurableObjectThresholdEcdsaStores,
  createCloudflareDurableObjectThresholdEd25519Stores,
} from './CloudflareDurableObjectStore';

export type Ed25519AuthSessionRecord = {
  expiresAtMs: number;
  relayerKeyId: string;
  userId: string;
  rpId: string;
  participantIds: number[];
} & Partial<ThresholdEcdsaSigningRootMetadata>;

export type ThresholdEd25519AuthConsumeUsesResult =
  | { ok: true; remainingUses: number }
  | { ok: false; code: string; message: string };

export type Ed25519AuthSessionStatus = {
  record: Ed25519AuthSessionRecord;
  expiresAtMs: number;
  remainingUses: number;
};

export interface Ed25519AuthSessionStore {
  putSession(
    id: string,
    record: Ed25519AuthSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void>;
  getSession(id: string): Promise<Ed25519AuthSessionRecord | null>;
  getSessionStatus(id: string): Promise<Ed25519AuthSessionStatus | null>;
  /**
   * Consume one use from the session counter without fetching the session record.
   *
   * This enables session-token-only authorization flows where scope/expiry are enforced from
   * signed JWT claims instead of a KV-stored record, reducing KV read-after-write consistency issues.
   */
  consumeUseCount(id: string): Promise<ThresholdEd25519AuthConsumeUsesResult>;
  consumeUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<ThresholdEd25519AuthConsumeUsesResult>;
}

class InMemoryEd25519AuthSessionStore implements Ed25519AuthSessionStore {
  private readonly keyPrefix: string;
  private readonly map = new Map<
    string,
    {
      record: Ed25519AuthSessionRecord;
      remainingUses: number;
      expiresAtMs: number;
      consumedIdempotencyKeys: Set<string>;
    }
  >();

  constructor(input: { keyPrefix?: string }) {
    this.keyPrefix = toThresholdEd25519AuthPrefix(input.keyPrefix);
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  async putSession(
    id: string,
    record: Ed25519AuthSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    const key = this.key(id);
    const ttlMs = Math.max(0, Number(opts.ttlMs) || 0);
    const expiresAtMs = Date.now() + ttlMs;
    this.map.set(key, {
      record,
      remainingUses: Math.max(0, Number(opts.remainingUses) || 0),
      expiresAtMs,
      consumedIdempotencyKeys: new Set(),
    });
  }

  async getSession(id: string): Promise<Ed25519AuthSessionRecord | null> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return null;
    }
    return entry.record;
  }

  async getSessionStatus(id: string): Promise<Ed25519AuthSessionStatus | null> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return null;
    }
    return {
      record: entry.record,
      expiresAtMs: entry.expiresAtMs,
      remainingUses: entry.remainingUses,
    };
  }

  async consumeUseCount(id: string): Promise<ThresholdEd25519AuthConsumeUsesResult> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry)
      return { ok: false, code: 'unauthorized', message: 'threshold session expired or invalid' };
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }
    if (entry.remainingUses <= 0) {
      return { ok: false, code: 'unauthorized', message: 'threshold session exhausted' };
    }
    entry.remainingUses -= 1;
    return { ok: true, remainingUses: entry.remainingUses };
  }

  async consumeUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<ThresholdEd25519AuthConsumeUsesResult> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry)
      return { ok: false, code: 'unauthorized', message: 'threshold session expired or invalid' };
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }
    const consumeKey = String(idempotencyKey || '').trim();
    if (consumeKey && entry.consumedIdempotencyKeys.has(consumeKey)) {
      return { ok: true, remainingUses: entry.remainingUses };
    }
    if (entry.remainingUses <= 0) {
      return { ok: false, code: 'unauthorized', message: 'threshold session exhausted' };
    }
    entry.remainingUses -= 1;
    if (consumeKey) entry.consumedIdempotencyKeys.add(consumeKey);
    return { ok: true, remainingUses: entry.remainingUses };
  }
}

function normalizeConsumeOnceKey(value: string): string {
  return String(value || '')
    .trim()
    .replace(/[^A-Za-z0-9._:-]/g, '_')
    .slice(0, 512);
}

function parseRedisConsumeOnceResult(raw: unknown): ThresholdEd25519AuthConsumeUsesResult {
  const text = String(raw ?? '').trim();
  if (text.startsWith('ok:')) {
    const remainingUses = Number(text.slice(3));
    if (!Number.isFinite(remainingUses)) {
      return { ok: false, code: 'internal', message: 'Redis consume-once returned invalid uses' };
    }
    return { ok: true, remainingUses };
  }
  if (text.startsWith('err:')) {
    const message = text.slice(4) || 'threshold session authorization failed';
    return { ok: false, code: 'unauthorized', message };
  }
  return { ok: false, code: 'internal', message: 'Redis consume-once returned invalid response' };
}

const CONSUME_ONCE_LUA = `
local uses_key = KEYS[1]
local marker_key = KEYS[2]
if redis.call('EXISTS', marker_key) == 1 then
  local current = redis.call('GET', uses_key)
  if not current then
    return 'err:threshold session expired or invalid'
  end
  return 'ok:' .. tostring(current)
end
local current = tonumber(redis.call('GET', uses_key) or '')
if current == nil then
  return 'err:threshold session expired or invalid'
end
if current <= 0 then
  return 'err:threshold session exhausted'
end
local remaining = redis.call('INCRBY', uses_key, -1)
local ttl = redis.call('TTL', uses_key)
if ttl and ttl > 0 then
  redis.call('SET', marker_key, '1', 'EX', ttl)
else
  redis.call('SET', marker_key, '1', 'EX', 60)
end
return 'ok:' .. tostring(remaining)
`;

class UpstashRedisRestEd25519AuthSessionStore implements Ed25519AuthSessionStore {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;

  constructor(input: { url: string; token: string; keyPrefix?: string }) {
    const url = toOptionalTrimmedString(input.url);
    const token = toOptionalTrimmedString(input.token);
    if (!url) throw new Error('Upstash auth session store missing url');
    if (!token) throw new Error('Upstash auth session store missing token');
    this.client = new UpstashRedisRestClient({ url, token });
    this.keyPrefix = toThresholdEd25519AuthPrefix(input.keyPrefix);
  }

  private metaKey(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private usesKey(id: string): string {
    return `${this.keyPrefix}${id}:uses`;
  }

  private consumeOnceKey(id: string, idempotencyKey: string): string {
    return `${this.usesKey(id)}:once:${normalizeConsumeOnceKey(idempotencyKey)}`;
  }

  async putSession(
    id: string,
    record: Ed25519AuthSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    const ttlMs = Math.max(0, Number(opts.ttlMs) || 0);
    await this.client.setJson(this.metaKey(id), record, ttlMs);
    await this.client.setRaw(
      this.usesKey(id),
      String(Math.max(0, Number(opts.remainingUses) || 0)),
      ttlMs,
    );
  }

  async getSession(id: string): Promise<Ed25519AuthSessionRecord | null> {
    const raw = await this.client.getJson(this.metaKey(id));
    return parseEd25519AuthSessionRecord(raw);
  }

  async getSessionStatus(id: string): Promise<Ed25519AuthSessionStatus | null> {
    const record = parseEd25519AuthSessionRecord(await this.client.getJson(this.metaKey(id)));
    if (!record) return null;
    const remainingUsesRaw = await this.client.getRaw(this.usesKey(id));
    const remainingUses =
      typeof remainingUsesRaw === 'number' ? remainingUsesRaw : Number(remainingUsesRaw);
    if (!Number.isFinite(remainingUses)) return null;
    return {
      record,
      expiresAtMs: record.expiresAtMs,
      remainingUses,
    };
  }

  async consumeUseCount(id: string): Promise<ThresholdEd25519AuthConsumeUsesResult> {
    try {
      const remainingUses = await this.client.incrby(this.usesKey(id), -1);
      if (remainingUses < 0) {
        return { ok: false, code: 'unauthorized', message: 'threshold session exhausted' };
      }
      return { ok: true, remainingUses };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to consume threshold session',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async consumeUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<ThresholdEd25519AuthConsumeUsesResult> {
    try {
      const raw = await this.client.eval(
        CONSUME_ONCE_LUA,
        [this.usesKey(id), this.consumeOnceKey(id, idempotencyKey)],
        [],
      );
      return parseRedisConsumeOnceResult(raw);
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to consume threshold session',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }
}

class RedisTcpEd25519AuthSessionStore implements Ed25519AuthSessionStore {
  private readonly client: RedisTcpClient;
  private readonly keyPrefix: string;

  constructor(input: { redisUrl: string; keyPrefix?: string }) {
    const url = toOptionalTrimmedString(input.redisUrl);
    if (!url) throw new Error('redis-tcp auth session store missing redisUrl');
    this.client = new RedisTcpClient(url);
    this.keyPrefix = toThresholdEd25519AuthPrefix(input.keyPrefix);
  }

  private metaKey(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private usesKey(id: string): string {
    return `${this.keyPrefix}${id}:uses`;
  }

  private consumeOnceKey(id: string, idempotencyKey: string): string {
    return `${this.usesKey(id)}:once:${normalizeConsumeOnceKey(idempotencyKey)}`;
  }

  async putSession(
    id: string,
    record: Ed25519AuthSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    const ttlMs = Math.max(0, Number(opts.ttlMs) || 0);
    await redisSetJson(this.client, this.metaKey(id), record, ttlMs);
    const ttlSeconds = Math.max(1, Math.ceil(ttlMs / 1000));
    const uses = String(Math.max(0, Number(opts.remainingUses) || 0));
    const resp = await this.client.send(['SET', this.usesKey(id), uses, 'EX', String(ttlSeconds)]);
    if (resp.type === 'error') throw new Error(`Redis SET error: ${resp.value}`);
  }

  async getSession(id: string): Promise<Ed25519AuthSessionRecord | null> {
    const raw = await redisGetJson(this.client, this.metaKey(id));
    return parseEd25519AuthSessionRecord(raw);
  }

  async getSessionStatus(id: string): Promise<Ed25519AuthSessionStatus | null> {
    const record = parseEd25519AuthSessionRecord(await redisGetJson(this.client, this.metaKey(id)));
    if (!record) return null;
    const resp = await this.client.send(['GET', this.usesKey(id)]);
    if (resp.type === 'error') throw new Error(`Redis GET error: ${resp.value}`);
    if (resp.type !== 'bulk' || resp.value == null) return null;
    const remainingUses = Number(resp.value);
    if (!Number.isFinite(remainingUses)) return null;
    return {
      record,
      expiresAtMs: record.expiresAtMs,
      remainingUses,
    };
  }

  async consumeUseCount(id: string): Promise<ThresholdEd25519AuthConsumeUsesResult> {
    try {
      const resp = await this.client.send(['INCRBY', this.usesKey(id), '-1']);
      if (resp.type === 'error')
        return { ok: false, code: 'internal', message: `Redis INCRBY error: ${resp.value}` };
      const remainingUses = resp.type === 'integer' ? resp.value : Number(resp.value ?? 0);
      if (!Number.isFinite(remainingUses)) {
        return { ok: false, code: 'internal', message: 'Redis INCRBY returned non-integer value' };
      }
      if (remainingUses < 0) {
        return { ok: false, code: 'unauthorized', message: 'threshold session exhausted' };
      }
      return { ok: true, remainingUses };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to consume threshold session',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async consumeUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<ThresholdEd25519AuthConsumeUsesResult> {
    try {
      const resp = await this.client.send([
        'EVAL',
        CONSUME_ONCE_LUA,
        '2',
        this.usesKey(id),
        this.consumeOnceKey(id, idempotencyKey),
      ]);
      if (resp.type === 'error') {
        return { ok: false, code: 'internal', message: `Redis EVAL error: ${resp.value}` };
      }
      const raw = resp.type === 'integer' ? String(resp.value) : resp.value;
      return parseRedisConsumeOnceResult(raw);
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to consume threshold session',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }
}

class PostgresEd25519AuthSessionStore implements Ed25519AuthSessionStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async putSession(
    id: string,
    record: Ed25519AuthSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    const ttlMs = Math.max(0, Number(opts.ttlMs) || 0);
    const expiresAtMs = Date.now() + ttlMs;
    const remainingUses = Math.max(0, Number(opts.remainingUses) || 0);
    const storedRecord = { ...record, expiresAtMs };
    const parsed = parseEd25519AuthSessionRecord(storedRecord);
    if (!parsed) throw new Error('Invalid threshold auth session record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO threshold_ed25519_sessions (namespace, kind, session_id, record_json, expires_at_ms, remaining_uses)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (namespace, kind, session_id)
        DO UPDATE SET record_json = EXCLUDED.record_json, expires_at_ms = EXCLUDED.expires_at_ms, remaining_uses = EXCLUDED.remaining_uses
      `,
      [this.namespace, 'auth', id, parsed, expiresAtMs, remainingUses],
    );
  }

  async getSession(id: string): Promise<Ed25519AuthSessionRecord | null> {
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM threshold_ed25519_sessions
        WHERE namespace = $1 AND kind = $2 AND session_id = $3 AND expires_at_ms > $4
        LIMIT 1
      `,
      [this.namespace, 'auth', id, nowMs],
    );
    return parseEd25519AuthSessionRecord(rows[0]?.record_json);
  }

  async getSessionStatus(id: string): Promise<Ed25519AuthSessionStatus | null> {
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const { rows } = await pool.query(
      `
        SELECT record_json, expires_at_ms, remaining_uses
        FROM threshold_ed25519_sessions
        WHERE namespace = $1 AND kind = $2 AND session_id = $3 AND expires_at_ms > $4
        LIMIT 1
      `,
      [this.namespace, 'auth', id, nowMs],
    );
    const row = rows[0];
    if (!row) return null;
    const record = parseEd25519AuthSessionRecord(row.record_json);
    const expiresAtMs =
      typeof row.expires_at_ms === 'number' ? row.expires_at_ms : Number(row.expires_at_ms);
    const remainingUses =
      typeof row.remaining_uses === 'number' ? row.remaining_uses : Number(row.remaining_uses);
    if (!record || !Number.isFinite(expiresAtMs) || !Number.isFinite(remainingUses)) return null;
    return {
      record,
      expiresAtMs,
      remainingUses,
    };
  }

  private async explainMissing(
    id: string,
    nowMs: number,
  ): Promise<{ code: string; message: string }> {
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT expires_at_ms, remaining_uses
        FROM threshold_ed25519_sessions
        WHERE namespace = $1 AND kind = $2 AND session_id = $3
        LIMIT 1
      `,
      [this.namespace, 'auth', id],
    );
    const row = rows[0];
    if (!row) return { code: 'unauthorized', message: 'threshold session expired or invalid' };
    const expiresAtMs =
      typeof row.expires_at_ms === 'number' ? row.expires_at_ms : Number(row.expires_at_ms);
    const remainingUses =
      typeof row.remaining_uses === 'number' ? row.remaining_uses : Number(row.remaining_uses);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs)
      return { code: 'unauthorized', message: 'threshold session expired' };
    if (Number.isFinite(remainingUses) && remainingUses <= 0)
      return { code: 'unauthorized', message: 'threshold session exhausted' };
    return { code: 'unauthorized', message: 'threshold session expired or invalid' };
  }

  async consumeUseCount(id: string): Promise<ThresholdEd25519AuthConsumeUsesResult> {
    try {
      const pool = await this.poolPromise;
      const nowMs = Date.now();
      const { rows } = await pool.query(
        `
          UPDATE threshold_ed25519_sessions
          SET remaining_uses = remaining_uses - 1
          WHERE namespace = $1 AND kind = $2 AND session_id = $3 AND expires_at_ms > $4 AND remaining_uses > 0
          RETURNING remaining_uses
        `,
        [this.namespace, 'auth', id, nowMs],
      );
      const row = rows[0];
      if (!row) {
        const reason = await this.explainMissing(id, nowMs);
        return { ok: false, code: reason.code, message: reason.message };
      }
      const remainingUses =
        typeof row.remaining_uses === 'number' ? row.remaining_uses : Number(row.remaining_uses);
      if (!Number.isFinite(remainingUses))
        return { ok: false, code: 'internal', message: 'Postgres returned invalid remainingUses' };
      return { ok: true, remainingUses };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to consume threshold session',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async consumeUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<ThresholdEd25519AuthConsumeUsesResult> {
    const consumeKey = normalizeConsumeOnceKey(idempotencyKey);
    if (!consumeKey) return await this.consumeUseCount(id);
    const pool = await this.poolPromise;
    const client =
      typeof pool.connect === 'function'
        ? await pool.connect()
        : {
            query: pool.query.bind(pool),
            release: () => undefined,
          };
    const nowMs = Date.now();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        `
          SELECT expires_at_ms, remaining_uses
          FROM threshold_ed25519_sessions
          WHERE namespace = $1 AND kind = $2 AND session_id = $3
          FOR UPDATE
        `,
        [this.namespace, 'auth', id],
      );
      const row = rows[0];
      if (!row) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'unauthorized', message: 'threshold session expired or invalid' };
      }
      const expiresAtMs =
        typeof row.expires_at_ms === 'number' ? row.expires_at_ms : Number(row.expires_at_ms);
      const remainingUses =
        typeof row.remaining_uses === 'number' ? row.remaining_uses : Number(row.remaining_uses);
      if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
      }
      if (!Number.isFinite(remainingUses)) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'internal', message: 'Postgres returned invalid remainingUses' };
      }

      const existing = await client.query(
        `
          SELECT 1
          FROM threshold_ed25519_auth_consumptions
          WHERE namespace = $1 AND session_id = $2 AND idempotency_key = $3 AND expires_at_ms > $4
          LIMIT 1
        `,
        [this.namespace, id, consumeKey, nowMs],
      );
      if (existing.rows[0]) {
        await client.query('COMMIT');
        return { ok: true, remainingUses };
      }
      if (remainingUses <= 0) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'unauthorized', message: 'threshold session exhausted' };
      }
      const updatedRemainingUses = remainingUses - 1;
      await client.query(
        `
          UPDATE threshold_ed25519_sessions
          SET remaining_uses = $5
          WHERE namespace = $1 AND kind = $2 AND session_id = $3 AND expires_at_ms > $4
        `,
        [this.namespace, 'auth', id, nowMs, updatedRemainingUses],
      );
      await client.query(
        `
          INSERT INTO threshold_ed25519_auth_consumptions (namespace, session_id, idempotency_key, expires_at_ms)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (namespace, session_id, idempotency_key) DO NOTHING
        `,
        [this.namespace, id, consumeKey, expiresAtMs],
      );
      await client.query('COMMIT');
      return { ok: true, remainingUses: updatedRemainingUses };
    } catch (e: unknown) {
      await client.query('ROLLBACK').catch(() => undefined);
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to consume threshold session',
      );
      return { ok: false, code: 'internal', message: msg };
    } finally {
      client.release();
    }
  }
}

export function createEd25519AuthSessionStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): Ed25519AuthSessionStore {
  const doStores = createCloudflareDurableObjectThresholdEd25519Stores({
    config: input.config,
    logger: input.logger,
  });
  if (doStores) return doStores.authSessionStore;

  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix =
    toOptionalTrimmedString(config.THRESHOLD_ED25519_AUTH_PREFIX) ||
    toThresholdEd25519PrefixFromBase(basePrefix, 'auth') ||
    '';

  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error(
        '[threshold-ed25519] In-memory auth session store is not supported in this runtime; configure Upstash/Redis or Durable Objects',
      );
    }
    return new InMemoryEd25519AuthSessionStore({ keyPrefix: envPrefix || undefined });
  }
  if (kind === 'upstash-redis-rest') {
    return new UpstashRedisRestEd25519AuthSessionStore({
      url:
        toOptionalTrimmedString(config.url) ||
        toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL),
      token:
        toOptionalTrimmedString(config.token) ||
        toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error(
          '[threshold-ed25519] redis-tcp auth session store is not supported in this runtime; configure Upstash/Redis REST or Durable Objects',
        );
      }
      input.logger.warn(
        '[threshold-ed25519] redis-tcp auth session store is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryEd25519AuthSessionStore({ keyPrefix: envPrefix || undefined });
    }
    return new RedisTcpEd25519AuthSessionStore({
      redisUrl:
        toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error(
        '[threshold-ed25519] postgres auth session store is not supported in this runtime',
      );
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl)
      throw new Error(
        '[threshold-ed25519] postgres auth session store enabled but POSTGRES_URL is not set',
      );
    input.logger.info('[threshold-ed25519] Using Postgres store for threshold auth sessions');
    return new PostgresEd25519AuthSessionStore({
      postgresUrl,
      namespace: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }

  // Env-shaped config: prefer Redis/Upstash for auth session storage (TTL + counters) to avoid Postgres churn.
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        'Upstash auth session store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set',
      );
    }
    input.logger.info('[threshold-ed25519] Using Upstash REST store for threshold auth sessions');
    return new UpstashRedisRestEd25519AuthSessionStore({
      url: upstashUrl,
      token: upstashToken,
      keyPrefix: envPrefix || undefined,
    });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error(
          '[threshold-ed25519] REDIS_URL is set but TCP Redis is not supported in this runtime; use Upstash/Redis REST or Durable Objects',
        );
      }
      input.logger.warn(
        '[threshold-ed25519] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryEd25519AuthSessionStore({ keyPrefix: envPrefix || undefined });
    }
    input.logger.info('[threshold-ed25519] Using redis-tcp store for threshold auth sessions');
    return new RedisTcpEd25519AuthSessionStore({ redisUrl, keyPrefix: envPrefix || undefined });
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error(
        '[threshold-ed25519] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    }
    input.logger.info('[threshold-ed25519] Using Postgres store for threshold auth sessions');
    return new PostgresEd25519AuthSessionStore({ postgresUrl, namespace: envPrefix || '' });
  }

  if (requirePersistent) {
    throw new Error(
      '[threshold-ed25519] Threshold auth sessions require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or Durable Objects',
    );
  }
  input.logger.info(
    '[threshold-ed25519] Using in-memory auth session store for threshold sessions (non-persistent)',
  );
  return new InMemoryEd25519AuthSessionStore({ keyPrefix: envPrefix || undefined });
}

export function createEcdsaAuthSessionStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): Ed25519AuthSessionStore {
  const doStores = createCloudflareDurableObjectThresholdEcdsaStores({
    config: input.config,
    logger: input.logger,
  });
  if (doStores) return doStores.authSessionStore;

  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix = toThresholdEcdsaAuthPrefix(
    toOptionalTrimmedString(config.THRESHOLD_ECDSA_AUTH_PREFIX) ||
      toThresholdEcdsaPrefixFromBase(basePrefix, 'auth'),
  );

  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error(
        '[threshold-ecdsa] In-memory auth session store is not supported in this runtime; configure Upstash/Redis or Durable Objects',
      );
    }
    return new InMemoryEd25519AuthSessionStore({ keyPrefix: envPrefix });
  }
  if (kind === 'upstash-redis-rest') {
    return new UpstashRedisRestEd25519AuthSessionStore({
      url:
        toOptionalTrimmedString(config.url) ||
        toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL),
      token:
        toOptionalTrimmedString(config.token) ||
        toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error(
          '[threshold-ecdsa] redis-tcp auth session store is not supported in this runtime; configure Upstash/Redis REST or Durable Objects',
        );
      }
      input.logger.warn(
        '[threshold-ecdsa] redis-tcp auth session store is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryEd25519AuthSessionStore({ keyPrefix: envPrefix });
    }
    return new RedisTcpEd25519AuthSessionStore({
      redisUrl:
        toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error(
        '[threshold-ecdsa] postgres auth session store is not supported in this runtime',
      );
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl)
      throw new Error(
        '[threshold-ecdsa] postgres auth session store enabled but POSTGRES_URL is not set',
      );
    input.logger.info('[threshold-ecdsa] Using Postgres store for threshold auth sessions');
    return new PostgresEd25519AuthSessionStore({
      postgresUrl,
      namespace: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }

  // Env-shaped config: prefer Redis/Upstash for auth session storage (TTL + counters) to avoid Postgres churn.
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        'Upstash auth session store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set',
      );
    }
    input.logger.info('[threshold-ecdsa] Using Upstash REST store for threshold auth sessions');
    return new UpstashRedisRestEd25519AuthSessionStore({
      url: upstashUrl,
      token: upstashToken,
      keyPrefix: envPrefix,
    });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error(
          '[threshold-ecdsa] REDIS_URL is set but TCP Redis is not supported in this runtime; use Upstash/Redis REST or Durable Objects',
        );
      }
      input.logger.warn(
        '[threshold-ecdsa] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryEd25519AuthSessionStore({ keyPrefix: envPrefix });
    }
    input.logger.info('[threshold-ecdsa] Using redis-tcp store for threshold auth sessions');
    return new RedisTcpEd25519AuthSessionStore({ redisUrl, keyPrefix: envPrefix });
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error(
        '[threshold-ecdsa] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    }
    input.logger.info('[threshold-ecdsa] Using Postgres store for threshold auth sessions');
    return new PostgresEd25519AuthSessionStore({ postgresUrl, namespace: envPrefix });
  }

  if (requirePersistent) {
    throw new Error(
      '[threshold-ecdsa] Threshold auth sessions require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or Durable Objects',
    );
  }
  input.logger.info(
    '[threshold-ecdsa] Using in-memory auth session store for threshold sessions (non-persistent)',
  );
  return new InMemoryEd25519AuthSessionStore({ keyPrefix: envPrefix });
}
