import type { NormalizedLogger } from '../../logger';
import type {
  ThresholdEd25519AuthorityScope,
  ThresholdEcdsaSigningRootMetadata,
  ThresholdStoreConfigInput,
} from '../../types';
import { RedisTcpClient, UpstashRedisRestClient, redisGetJson, redisSetJson } from '../kv';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  WALLET_SESSION_FAILURE_CODES,
  type WalletSessionFailureCode,
} from '@shared/utils/walletSessionFailure';
import {
  isObject,
  toThresholdEcdsaWalletSessionPrefix,
  toThresholdEcdsaPrefixFromBase,
  toThresholdEd25519WalletSessionPrefix,
  toThresholdEd25519PrefixFromBase,
  parseEd25519WalletSessionRecord,
  parseEcdsaWalletSessionRecord,
} from '../validation';
import {
  createCloudflareDurableObjectThresholdEcdsaStores,
  createCloudflareDurableObjectThresholdEd25519Stores,
} from './CloudflareDurableObjectStore';
import { readNonDurableObjectThresholdStoreKind } from './StoreConfig';
import { secureRandomIdFragment } from '../secureRandomId';
import type { EcdsaKeyHandle } from '../../keyMaterialBrands';

export type Ed25519WalletSessionRecord = {
  expiresAtMs: number;
  relayerKeyId: string;
  userId: string;
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  authorityScope: ThresholdEd25519AuthorityScope;
  participantIds: number[];
} & Partial<ThresholdEcdsaSigningRootMetadata>;

type EcdsaWalletSessionRecordCore = {
  expiresAtMs: number;
  relayerKeyId: string;
  walletId: string;
  keyHandle: EcdsaKeyHandle;
  participantIds: number[];
};

export type EcdsaWalletSessionRecord = EcdsaWalletSessionRecordCore &
  (
    | {
        signingRootId?: never;
        signingRootVersion?: never;
        walletKeyVersion?: never;
        derivationVersion?: never;
      }
    | ThresholdEcdsaSigningRootMetadata
  );

export type WalletSessionRecord = Ed25519WalletSessionRecord | EcdsaWalletSessionRecord;

export type WalletSessionConsumeUsesResult =
  | { ok: true; remainingUses: number }
  | { ok: false; code: string; message: string };

export type WalletSessionConsumedUseResult =
  | { ok: true; consumed: boolean }
  | { ok: false; code: string; message: string };

export type WalletSessionReplayGuardResult =
  | { ok: true }
  | { ok: false; code: string; message: string };

export type WalletSessionStatus<TRecord extends WalletSessionRecord> = {
  record: TRecord;
  expiresAtMs: number;
  remainingUses: number;
};

export type WalletSessionStatusLookupResult<TRecord extends WalletSessionRecord> =
  | { ok: true; status: WalletSessionStatus<TRecord> }
  | {
      ok: false;
      code: Extract<
        WalletSessionFailureCode,
        | typeof WALLET_SESSION_FAILURE_CODES.missing
        | typeof WALLET_SESSION_FAILURE_CODES.expired
        | typeof WALLET_SESSION_FAILURE_CODES.unavailable
      >;
    };

export type Ed25519WalletSessionStatus = WalletSessionStatus<Ed25519WalletSessionRecord>;
export type EcdsaWalletSessionStatus = WalletSessionStatus<EcdsaWalletSessionRecord>;
const EXPORT_REPLAY_GUARD_CLOCK_SKEW_MS = 5 * 60_000;
const EXPORT_REPLAY_GUARD_MIN_RETENTION_MS = 24 * 60 * 60_000;
type WalletSessionStoreConfigRecord = Record<string, unknown>;

export interface WalletSessionStore<TRecord extends WalletSessionRecord> {
  putSession(
    id: string,
    record: TRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void>;
  getSession(id: string): Promise<TRecord | null>;
  getSessionStatus(id: string): Promise<WalletSessionStatusLookupResult<TRecord>>;
  /**
   * Consume one use from the session counter without fetching the session record.
   *
   * This enables session-token-only authorization flows where scope/expiry are enforced from
   * signed JWT claims instead of a KV-stored record, reducing KV read-after-write consistency issues.
   */
  consumeUseCount(id: string): Promise<WalletSessionConsumeUsesResult>;
  consumeUseCountOnce(id: string, idempotencyKey: string): Promise<WalletSessionConsumeUsesResult>;
  hasConsumedUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<WalletSessionConsumedUseResult>;
  reserveReplayGuard(
    scopeId: string,
    replayKey: string,
    expiresAtMs: number,
  ): Promise<WalletSessionReplayGuardResult>;
}

export type Ed25519WalletSessionStore = WalletSessionStore<Ed25519WalletSessionRecord>;
export type EcdsaWalletSessionStore = WalletSessionStore<EcdsaWalletSessionRecord>;
export type WalletSessionRecordParser<TRecord extends WalletSessionRecord> = (
  raw: unknown,
) => TRecord | null;

class InMemoryWalletSessionStore<
  TRecord extends WalletSessionRecord,
> implements WalletSessionStore<TRecord> {
  private readonly keyPrefix: string;
  private readonly map = new Map<
    string,
    {
      record: TRecord;
      remainingUses: number;
      expiresAtMs: number;
      consumedIdempotencyKeys: Set<string>;
    }
  >();
  private readonly replayGuards = new Map<string, number>();

  constructor(input: { keyPrefix?: string }) {
    this.keyPrefix = toThresholdEd25519WalletSessionPrefix(input.keyPrefix);
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private replayGuardKey(scopeId: string, replayKey: string): string {
    return `${this.keyPrefix}replay:${normalizeConsumeOnceKey(scopeId)}:${normalizeConsumeOnceKey(replayKey)}`;
  }

  async putSession(
    id: string,
    record: TRecord,
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

  async getSession(id: string): Promise<TRecord | null> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry) return null;
    if (entry.expiresAtMs <= Date.now()) {
      this.map.delete(key);
      return null;
    }
    return entry.record;
  }

  async getSessionStatus(id: string): Promise<WalletSessionStatusLookupResult<TRecord>> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry) return { ok: false, code: 'wallet_session_missing' };
    if (entry.expiresAtMs <= Date.now()) {
      this.map.delete(key);
      return { ok: false, code: 'wallet_session_expired' };
    }
    return {
      ok: true,
      status: {
        record: entry.record,
        expiresAtMs: entry.expiresAtMs,
        remainingUses: entry.remainingUses,
      },
    };
  }

  async consumeUseCount(id: string): Promise<WalletSessionConsumeUsesResult> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry)
      return { ok: false, code: 'wallet_session_missing', message: 'Wallet Session is missing' };
    if (entry.expiresAtMs <= Date.now()) {
      this.map.delete(key);
      return { ok: false, code: 'wallet_session_expired', message: 'Wallet Session expired' };
    }
    if (entry.remainingUses <= 0) {
      return { ok: false, code: 'wallet_budget_exhausted', message: 'Wallet Session exhausted' };
    }
    entry.remainingUses -= 1;
    return { ok: true, remainingUses: entry.remainingUses };
  }

  async consumeUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<WalletSessionConsumeUsesResult> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry)
      return { ok: false, code: 'wallet_session_missing', message: 'Wallet Session is missing' };
    if (entry.expiresAtMs <= Date.now()) {
      this.map.delete(key);
      return { ok: false, code: 'wallet_session_expired', message: 'Wallet Session expired' };
    }
    const consumeKey = String(idempotencyKey || '').trim();
    if (consumeKey && entry.consumedIdempotencyKeys.has(consumeKey)) {
      return { ok: true, remainingUses: entry.remainingUses };
    }
    if (entry.remainingUses <= 0) {
      return { ok: false, code: 'wallet_budget_exhausted', message: 'Wallet Session exhausted' };
    }
    entry.remainingUses -= 1;
    if (consumeKey) entry.consumedIdempotencyKeys.add(consumeKey);
    return { ok: true, remainingUses: entry.remainingUses };
  }

  async hasConsumedUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<WalletSessionConsumedUseResult> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry) {
      return { ok: false, code: 'wallet_session_missing', message: 'Wallet Session is missing' };
    }
    if (entry.expiresAtMs <= Date.now()) {
      this.map.delete(key);
      return { ok: false, code: 'wallet_session_expired', message: 'Wallet Session expired' };
    }
    const consumeKey = String(idempotencyKey || '').trim();
    return { ok: true, consumed: !!consumeKey && entry.consumedIdempotencyKeys.has(consumeKey) };
  }

  async reserveReplayGuard(
    scopeId: string,
    replayKey: string,
    expiresAtMs: number,
  ): Promise<WalletSessionReplayGuardResult> {
    const key = this.replayGuardKey(scopeId, replayKey);
    if (!key) return replayGuardInvalid();
    const nowMs = Date.now();
    const existingExpiresAtMs = this.replayGuards.get(key);
    if (existingExpiresAtMs !== undefined && existingExpiresAtMs > nowMs) {
      return replayGuardDuplicate();
    }
    if (existingExpiresAtMs !== undefined) this.replayGuards.delete(key);
    const ttlMs = replayGuardTtlMs(expiresAtMs, nowMs);
    if (ttlMs <= 0) return replayGuardExpired();
    this.replayGuards.set(key, nowMs + ttlMs);
    return { ok: true };
  }
}

function normalizeConsumeOnceKey(value: string): string {
  return String(value || '')
    .trim()
    .replace(/[^A-Za-z0-9._:-]/g, '_')
    .slice(0, 512);
}

function replayGuardTtlMs(expiresAtMs: number, nowMs = Date.now()): number {
  const expires = Number(expiresAtMs);
  if (!Number.isFinite(expires)) return 0;
  const retainUntilMs = expires + EXPORT_REPLAY_GUARD_CLOCK_SKEW_MS;
  if (retainUntilMs <= nowMs) return 0;
  return Math.max(EXPORT_REPLAY_GUARD_MIN_RETENTION_MS, Math.floor(retainUntilMs - nowMs));
}

function replayGuardInvalid(): WalletSessionReplayGuardResult {
  return { ok: false, code: 'invalid_body', message: 'Invalid replay guard key' };
}

function replayGuardExpired(): WalletSessionReplayGuardResult {
  return {
    ok: false,
    code: 'export_authorization_expired',
    message: 'Export authorization expired',
  };
}

function replayGuardDuplicate(): WalletSessionReplayGuardResult {
  return {
    ok: false,
    code: 'export_nonce_replay',
    message: 'Export authorization nonce already used',
  };
}

function parseRedisReplayGuardResult(raw: unknown): WalletSessionReplayGuardResult {
  const text = String(raw ?? '').trim();
  if (text === 'ok') return { ok: true };
  if (text === 'duplicate') return replayGuardDuplicate();
  if (text === 'expired') return replayGuardExpired();
  return { ok: false, code: 'internal', message: 'Redis replay guard returned invalid response' };
}

function parseRedisConsumeOnceResult(raw: unknown): WalletSessionConsumeUsesResult {
  const text = String(raw ?? '').trim();
  if (text.startsWith('ok:')) {
    const remainingUses = Number(text.slice(3));
    if (!Number.isFinite(remainingUses)) {
      return { ok: false, code: 'internal', message: 'Redis consume-once returned invalid uses' };
    }
    return { ok: true, remainingUses };
  }
  if (text === 'wallet_session_missing') {
    return { ok: false, code: 'wallet_session_missing', message: 'Wallet Session is missing' };
  }
  if (text === 'wallet_budget_exhausted') {
    return {
      ok: false,
      code: 'wallet_budget_exhausted',
      message: 'Wallet Session signing budget is exhausted',
    };
  }
  return { ok: false, code: 'internal', message: 'Redis consume-once returned invalid response' };
}

function parseRedisConsumedUseResult(raw: unknown): WalletSessionConsumedUseResult {
  const value = typeof raw === 'number' ? raw : Number(String(raw ?? '').trim());
  if (!Number.isFinite(value)) {
    return {
      ok: false,
      code: 'internal',
      message: 'Redis consumed-use check returned invalid response',
    };
  }
  return { ok: true, consumed: value > 0 };
}

function redisRawValue(resp: { type: string; value?: unknown }): unknown {
  if (resp.type === 'integer') return String(resp.value);
  return resp.value;
}

function parseRedisJsonObject(raw: unknown): Record<string, unknown> | null {
  const text = String(raw ?? '').trim();
  if (!text) return null;
  try {
    const parsed = JSON.parse(text);
    return isObject(parsed) ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

const CONSUME_ONCE_EXISTS_LUA = `
local marker_key = KEYS[1]
return redis.call('EXISTS', marker_key)
`;

const CONSUME_USE_COUNT_LUA = `
local uses_key = KEYS[1]
local current = tonumber(redis.call('GET', uses_key) or '')
if current == nil then
  return 'wallet_session_missing'
end
if current <= 0 then
  return 'wallet_budget_exhausted'
end
return 'ok:' .. tostring(redis.call('INCRBY', uses_key, -1))
`;

const CONSUME_ONCE_LUA = `
local uses_key = KEYS[1]
local marker_key = KEYS[2]
if redis.call('EXISTS', marker_key) == 1 then
  local current = redis.call('GET', uses_key)
  if not current then
    return 'wallet_session_missing'
  end
  return 'ok:' .. tostring(current)
end
local current = tonumber(redis.call('GET', uses_key) or '')
if current == nil then
  return 'wallet_session_missing'
end
if current <= 0 then
  return 'wallet_budget_exhausted'
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

const REPLAY_GUARD_LUA = `
local key = KEYS[1]
local ttl_seconds = tonumber(ARGV[1] or '')
if ttl_seconds == nil or ttl_seconds <= 0 then
  return 'expired'
end
if redis.call('EXISTS', key) == 1 then
  return 'duplicate'
end
redis.call('SET', key, '1', 'EX', ttl_seconds)
return 'ok'
`;

class UpstashRedisRestWalletSessionStore<
  TRecord extends WalletSessionRecord,
> implements WalletSessionStore<TRecord> {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;
  private readonly parseRecord: WalletSessionRecordParser<TRecord>;

  constructor(input: {
    url: string;
    token: string;
    keyPrefix?: string;
    parseRecord?: WalletSessionRecordParser<TRecord>;
  }) {
    const url = toOptionalTrimmedString(input.url);
    const token = toOptionalTrimmedString(input.token);
    if (!url) throw new Error('Upstash wallet session store missing url');
    if (!token) throw new Error('Upstash wallet session store missing token');
    this.client = new UpstashRedisRestClient({ url, token });
    this.keyPrefix = toThresholdEd25519WalletSessionPrefix(input.keyPrefix);
    this.parseRecord =
      input.parseRecord || (parseEd25519WalletSessionRecord as WalletSessionRecordParser<TRecord>);
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

  private replayGuardKey(scopeId: string, replayKey: string): string {
    return `${this.keyPrefix}replay:${normalizeConsumeOnceKey(scopeId)}:${normalizeConsumeOnceKey(replayKey)}`;
  }

  async putSession(
    id: string,
    record: TRecord,
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

  async getSession(id: string): Promise<TRecord | null> {
    const raw = await this.client.getJson(this.metaKey(id));
    return this.parseRecord(raw);
  }

  async getSessionStatus(id: string): Promise<WalletSessionStatusLookupResult<TRecord>> {
    try {
      const record = this.parseRecord(await this.client.getJson(this.metaKey(id)));
      if (!record) return { ok: false, code: 'wallet_session_missing' };
      if (record.expiresAtMs <= Date.now()) {
        return { ok: false, code: 'wallet_session_expired' };
      }
      const remainingUses = Number(await this.client.getRaw(this.usesKey(id)));
      if (!Number.isSafeInteger(remainingUses) || remainingUses < 0) {
        return { ok: false, code: 'wallet_session_unavailable' };
      }
      return {
        ok: true,
        status: {
          record,
          expiresAtMs: record.expiresAtMs,
          remainingUses,
        },
      };
    } catch {
      return { ok: false, code: 'wallet_session_unavailable' };
    }
  }

  async consumeUseCount(id: string): Promise<WalletSessionConsumeUsesResult> {
    try {
      const raw = await this.client.eval(CONSUME_USE_COUNT_LUA, [this.usesKey(id)], []);
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

  async consumeUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<WalletSessionConsumeUsesResult> {
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

  async hasConsumedUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<WalletSessionConsumedUseResult> {
    const consumeKey = normalizeConsumeOnceKey(idempotencyKey);
    if (!consumeKey) return { ok: true, consumed: false };
    try {
      const raw = await this.client.eval(
        CONSUME_ONCE_EXISTS_LUA,
        [this.consumeOnceKey(id, consumeKey)],
        [],
      );
      return parseRedisConsumedUseResult(raw);
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to check consumed threshold session operation',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async reserveReplayGuard(
    scopeId: string,
    replayKey: string,
    expiresAtMs: number,
  ): Promise<WalletSessionReplayGuardResult> {
    try {
      const ttlMs = replayGuardTtlMs(expiresAtMs);
      if (ttlMs <= 0) return replayGuardExpired();
      const raw = await this.client.eval(
        REPLAY_GUARD_LUA,
        [this.replayGuardKey(scopeId, replayKey)],
        [String(Math.max(1, Math.ceil(ttlMs / 1000)))],
      );
      return parseRedisReplayGuardResult(raw);
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to reserve replay guard',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }
}

class RedisTcpWalletSessionStore<
  TRecord extends WalletSessionRecord,
> implements WalletSessionStore<TRecord> {
  private readonly client: RedisTcpClient;
  private readonly keyPrefix: string;
  private readonly parseRecord: WalletSessionRecordParser<TRecord>;

  constructor(input: {
    redisUrl: string;
    keyPrefix?: string;
    parseRecord?: WalletSessionRecordParser<TRecord>;
  }) {
    const url = toOptionalTrimmedString(input.redisUrl);
    if (!url) throw new Error('redis-tcp wallet session store missing redisUrl');
    this.client = new RedisTcpClient(url);
    this.keyPrefix = toThresholdEd25519WalletSessionPrefix(input.keyPrefix);
    this.parseRecord =
      input.parseRecord || (parseEd25519WalletSessionRecord as WalletSessionRecordParser<TRecord>);
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

  private replayGuardKey(scopeId: string, replayKey: string): string {
    return `${this.keyPrefix}replay:${normalizeConsumeOnceKey(scopeId)}:${normalizeConsumeOnceKey(replayKey)}`;
  }

  async putSession(
    id: string,
    record: TRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    const ttlMs = Math.max(0, Number(opts.ttlMs) || 0);
    await redisSetJson(this.client, this.metaKey(id), record, ttlMs);
    const ttlSeconds = Math.max(1, Math.ceil(ttlMs / 1000));
    const uses = String(Math.max(0, Number(opts.remainingUses) || 0));
    const resp = await this.client.send(['SET', this.usesKey(id), uses, 'EX', String(ttlSeconds)]);
    if (resp.type === 'error') throw new Error(`Redis SET error: ${resp.value}`);
  }

  async getSession(id: string): Promise<TRecord | null> {
    const raw = await redisGetJson(this.client, this.metaKey(id));
    return this.parseRecord(raw);
  }

  async getSessionStatus(id: string): Promise<WalletSessionStatusLookupResult<TRecord>> {
    try {
      const record = this.parseRecord(await redisGetJson(this.client, this.metaKey(id)));
      if (!record) return { ok: false, code: 'wallet_session_missing' };
      if (record.expiresAtMs <= Date.now()) {
        return { ok: false, code: 'wallet_session_expired' };
      }
      const usesResponse = await this.client.send(['GET', this.usesKey(id)]);
      if (usesResponse.type === 'error') return { ok: false, code: 'wallet_session_unavailable' };
      const remainingUses = Number(redisRawValue(usesResponse));
      if (!Number.isSafeInteger(remainingUses) || remainingUses < 0) {
        return { ok: false, code: 'wallet_session_unavailable' };
      }
      return {
        ok: true,
        status: {
          record,
          expiresAtMs: record.expiresAtMs,
          remainingUses,
        },
      };
    } catch {
      return { ok: false, code: 'wallet_session_unavailable' };
    }
  }

  async consumeUseCount(id: string): Promise<WalletSessionConsumeUsesResult> {
    try {
      const resp = await this.client.send(['EVAL', CONSUME_USE_COUNT_LUA, '1', this.usesKey(id)]);
      if (resp.type === 'error')
        return { ok: false, code: 'internal', message: `Redis EVAL error: ${resp.value}` };
      return parseRedisConsumeOnceResult(redisRawValue(resp));
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
  ): Promise<WalletSessionConsumeUsesResult> {
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

  async hasConsumedUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<WalletSessionConsumedUseResult> {
    const consumeKey = normalizeConsumeOnceKey(idempotencyKey);
    if (!consumeKey) return { ok: true, consumed: false };
    try {
      const resp = await this.client.send(['EXISTS', this.consumeOnceKey(id, consumeKey)]);
      if (resp.type === 'error') {
        return { ok: false, code: 'internal', message: `Redis EXISTS error: ${resp.value}` };
      }
      return parseRedisConsumedUseResult(resp.value);
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to check consumed threshold session operation',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async reserveReplayGuard(
    scopeId: string,
    replayKey: string,
    expiresAtMs: number,
  ): Promise<WalletSessionReplayGuardResult> {
    try {
      const ttlMs = replayGuardTtlMs(expiresAtMs);
      if (ttlMs <= 0) return replayGuardExpired();
      const resp = await this.client.send([
        'SET',
        this.replayGuardKey(scopeId, replayKey),
        '1',
        'NX',
        'EX',
        String(Math.max(1, Math.ceil(ttlMs / 1000))),
      ]);
      if (resp.type === 'error') {
        return { ok: false, code: 'internal', message: `Redis SET error: ${resp.value}` };
      }
      if (resp.type === 'bulk' && resp.value === null) return replayGuardDuplicate();
      if (resp.type === 'simple' && resp.value === 'OK') return { ok: true };
      return {
        ok: false,
        code: 'internal',
        message: 'Redis replay guard returned invalid response',
      };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to reserve replay guard',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }
}

export function createEd25519WalletSessionStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): Ed25519WalletSessionStore {
  const doStores = createCloudflareDurableObjectThresholdEd25519Stores({
    config: input.config,
    logger: input.logger,
  });
  if (doStores) return doStores.walletSessionStore;

  const config = (isObject(input.config) ? input.config : {}) as WalletSessionStoreConfigRecord;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix =
    toOptionalTrimmedString(config.THRESHOLD_ED25519_WALLET_SESSION_PREFIX) ||
    toThresholdEd25519PrefixFromBase(basePrefix, 'wallet-session') ||
    '';

  const kind = readNonDurableObjectThresholdStoreKind(config, 'threshold-ed25519');
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error(
        '[threshold-ed25519] In-memory wallet session store is not supported in this runtime; configure Upstash/Redis or Durable Objects',
      );
    }
    return new InMemoryWalletSessionStore<Ed25519WalletSessionRecord>({
      keyPrefix: envPrefix || undefined,
    });
  }
  if (kind === 'upstash-redis-rest') {
    return new UpstashRedisRestWalletSessionStore<Ed25519WalletSessionRecord>({
      url:
        toOptionalTrimmedString(config.url) ||
        toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL),
      token:
        toOptionalTrimmedString(config.token) ||
        toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
      parseRecord: parseEd25519WalletSessionRecord,
    });
  }
  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error(
          '[threshold-ed25519] redis-tcp wallet session store is not supported in this runtime; configure Upstash/Redis REST or Durable Objects',
        );
      }
      input.logger.warn(
        '[threshold-ed25519] redis-tcp wallet session store is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryWalletSessionStore<Ed25519WalletSessionRecord>({
        keyPrefix: envPrefix || undefined,
      });
    }
    return new RedisTcpWalletSessionStore<Ed25519WalletSessionRecord>({
      redisUrl:
        toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
      parseRecord: parseEd25519WalletSessionRecord,
    });
  }
  // Env-shaped config: prefer Redis/Upstash for wallet session storage (TTL + counters).
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        'Upstash wallet session store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set',
      );
    }
    input.logger.info('[threshold-ed25519] Using Upstash REST store for Wallet Session records');
    return new UpstashRedisRestWalletSessionStore<Ed25519WalletSessionRecord>({
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
      return new InMemoryWalletSessionStore<Ed25519WalletSessionRecord>({
        keyPrefix: envPrefix || undefined,
      });
    }
    input.logger.info('[threshold-ed25519] Using redis-tcp store for Wallet Session records');
    return new RedisTcpWalletSessionStore<Ed25519WalletSessionRecord>({
      redisUrl,
      keyPrefix: envPrefix || undefined,
    });
  }

  if (requirePersistent) {
    throw new Error(
      '[threshold-ed25519] Wallet Session records require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or Durable Objects',
    );
  }
  input.logger.info('[threshold-ed25519] Using in-memory Wallet Session store (non-persistent)');
  return new InMemoryWalletSessionStore<Ed25519WalletSessionRecord>({
    keyPrefix: envPrefix || undefined,
  });
}

export function createEcdsaWalletSessionStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): EcdsaWalletSessionStore {
  const doStores = createCloudflareDurableObjectThresholdEcdsaStores({
    config: input.config,
    logger: input.logger,
  });
  if (doStores) return doStores.walletSessionStore;

  const config = (isObject(input.config) ? input.config : {}) as WalletSessionStoreConfigRecord;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix = toThresholdEcdsaWalletSessionPrefix(
    toOptionalTrimmedString(config.THRESHOLD_ECDSA_WALLET_SESSION_PREFIX) ||
      toThresholdEcdsaPrefixFromBase(basePrefix, 'wallet-session'),
  );

  const kind = readNonDurableObjectThresholdStoreKind(config, 'threshold-ecdsa');
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error(
        '[threshold-ecdsa] In-memory wallet session store is not supported in this runtime; configure Upstash/Redis or Durable Objects',
      );
    }
    return new InMemoryWalletSessionStore<EcdsaWalletSessionRecord>({ keyPrefix: envPrefix });
  }
  if (kind === 'upstash-redis-rest') {
    return new UpstashRedisRestWalletSessionStore<EcdsaWalletSessionRecord>({
      url:
        toOptionalTrimmedString(config.url) ||
        toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL),
      token:
        toOptionalTrimmedString(config.token) ||
        toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
      parseRecord: parseEcdsaWalletSessionRecord,
    });
  }
  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error(
          '[threshold-ecdsa] redis-tcp wallet session store is not supported in this runtime; configure Upstash/Redis REST or Durable Objects',
        );
      }
      input.logger.warn(
        '[threshold-ecdsa] redis-tcp wallet session store is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryWalletSessionStore<EcdsaWalletSessionRecord>({ keyPrefix: envPrefix });
    }
    return new RedisTcpWalletSessionStore<EcdsaWalletSessionRecord>({
      redisUrl:
        toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
      parseRecord: parseEcdsaWalletSessionRecord,
    });
  }
  // Env-shaped config: prefer Redis/Upstash for wallet session storage (TTL + counters).
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        'Upstash wallet session store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set',
      );
    }
    input.logger.info('[threshold-ecdsa] Using Upstash REST store for Wallet Session records');
    return new UpstashRedisRestWalletSessionStore<EcdsaWalletSessionRecord>({
      url: upstashUrl,
      token: upstashToken,
      keyPrefix: envPrefix,
      parseRecord: parseEcdsaWalletSessionRecord,
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
      return new InMemoryWalletSessionStore<EcdsaWalletSessionRecord>({ keyPrefix: envPrefix });
    }
    input.logger.info('[threshold-ecdsa] Using redis-tcp store for Wallet Session records');
    return new RedisTcpWalletSessionStore<EcdsaWalletSessionRecord>({
      redisUrl,
      keyPrefix: envPrefix,
      parseRecord: parseEcdsaWalletSessionRecord,
    });
  }

  if (requirePersistent) {
    throw new Error(
      '[threshold-ecdsa] Wallet Session records require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or Durable Objects',
    );
  }
  input.logger.info('[threshold-ecdsa] Using in-memory Wallet Session store (non-persistent)');
  return new InMemoryWalletSessionStore<EcdsaWalletSessionRecord>({ keyPrefix: envPrefix });
}
