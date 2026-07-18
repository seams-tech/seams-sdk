import type { NormalizedLogger } from '../../logger';
import type { RouterAbEcdsaDerivationNormalSigningScopeV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type {
  ThresholdEcdsaSigningRootMetadata,
  ThresholdStoreConfigInput,
} from '../../types';
import { RedisTcpClient, UpstashRedisRestClient, redisSetJson } from '../kv';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  isObject,
  parseRouterAbEcdsaDerivationPoolFillSessionRecord,
  toThresholdEcdsaPresignPrefix,
  toThresholdEcdsaPrefixFromBase,
} from '../validation';
import { createCloudflareDurableObjectThresholdEcdsaStores } from './CloudflareDurableObjectStore';
import { readNonDurableObjectThresholdStoreKind } from './StoreConfig';

export type RouterAbEcdsaDerivationPoolFillSessionStage = 'triples' | 'triples_done' | 'presign' | 'done';

export type RouterAbEcdsaDerivationPoolFillSessionDestination = {
  kind: 'router_ab_ecdsa_derivation_signing_worker_pool';
  routerAbEcdsaDerivation: {
    scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
    expiresAtMs: number;
  };
};

export type RouterAbEcdsaDerivationPoolFillSessionRecord = {
  expiresAtMs: number;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  relayerKeyId: string;
  presignPoolKey: string;
  poolFill: RouterAbEcdsaDerivationPoolFillSessionDestination;
  ownerInstanceId?: string;
  participantIds: number[];
  clientParticipantId: number;
  relayerParticipantId: number;
  stage: RouterAbEcdsaDerivationPoolFillSessionStage;
  version: number;
  createdAtMs: number;
  updatedAtMs: number;
} & ThresholdEcdsaSigningRootMetadata;

export type RouterAbEcdsaDerivationPoolFillSessionCasResult =
  | { ok: true; record: RouterAbEcdsaDerivationPoolFillSessionRecord }
  | { ok: false; code: 'not_found' | 'expired' | 'version_mismatch' };

export interface RouterAbEcdsaDerivationPoolFillSessionStore {
  createSession(
    id: string,
    record: RouterAbEcdsaDerivationPoolFillSessionRecord,
    ttlMs: number,
  ): Promise<{ ok: true } | { ok: false; code: 'exists' }>;
  getSession(id: string): Promise<RouterAbEcdsaDerivationPoolFillSessionRecord | null>;
  advanceSessionCas(input: {
    id: string;
    expectedVersion: number;
    nextRecord: RouterAbEcdsaDerivationPoolFillSessionRecord;
    ttlMs: number;
  }): Promise<RouterAbEcdsaDerivationPoolFillSessionCasResult>;
  deleteSession(id: string): Promise<void>;
}

type ThresholdEcdsaSigningStoreConfigRecord = Record<string, unknown>;

export class InMemoryRouterAbEcdsaDerivationPoolFillSessionStore implements RouterAbEcdsaDerivationPoolFillSessionStore {
  private readonly map = new Map<
    string,
    { value: RouterAbEcdsaDerivationPoolFillSessionRecord; expiresAtMs: number }
  >();

  async createSession(
    id: string,
    record: RouterAbEcdsaDerivationPoolFillSessionRecord,
    ttlMs: number,
  ): Promise<{ ok: true } | { ok: false; code: 'exists' }> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing presignSessionId');

    const parsed = parseRouterAbEcdsaDerivationPoolFillSessionRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA derivation pool-fill session record');

    const existing = this.map.get(key);
    const nowMs = Date.now();
    if (existing && existing.expiresAtMs > nowMs) {
      return { ok: false, code: 'exists' };
    }

    const expiresAtMs = nowMs + Math.max(0, Number(ttlMs) || 0);
    this.map.set(key, { value: parsed, expiresAtMs });
    return { ok: true };
  }

  async getSession(id: string): Promise<RouterAbEcdsaDerivationPoolFillSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return null;
    }
    return entry.value;
  }

  async advanceSessionCas(input: {
    id: string;
    expectedVersion: number;
    nextRecord: RouterAbEcdsaDerivationPoolFillSessionRecord;
    ttlMs: number;
  }): Promise<RouterAbEcdsaDerivationPoolFillSessionCasResult> {
    const key = toOptionalTrimmedString(input.id);
    if (!key) return { ok: false, code: 'not_found' };
    const entry = this.map.get(key);
    if (!entry) return { ok: false, code: 'not_found' };

    const nowMs = Date.now();
    if (nowMs > entry.expiresAtMs) {
      this.map.delete(key);
      return { ok: false, code: 'expired' };
    }

    const expectedVersion = Math.floor(Number(input.expectedVersion));
    if (!Number.isFinite(expectedVersion) || expectedVersion < 1) {
      return { ok: false, code: 'version_mismatch' };
    }
    if (entry.value.version !== expectedVersion) {
      return { ok: false, code: 'version_mismatch' };
    }

    const parsed = parseRouterAbEcdsaDerivationPoolFillSessionRecord(input.nextRecord);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA derivation pool-fill session record');
    const expiresAtMs = nowMs + Math.max(0, Number(input.ttlMs) || 0);
    this.map.set(key, { value: parsed, expiresAtMs });
    return { ok: true, record: parsed };
  }

  async deleteSession(id: string): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) return;
    this.map.delete(key);
  }
}

class UpstashRedisRestRouterAbEcdsaDerivationPoolFillSessionStore implements RouterAbEcdsaDerivationPoolFillSessionStore {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;

  constructor(input: { url: string; token: string; keyPrefix: string }) {
    this.client = new UpstashRedisRestClient({ url: input.url, token: input.token });
    this.keyPrefix = input.keyPrefix;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  async createSession(
    id: string,
    record: RouterAbEcdsaDerivationPoolFillSessionRecord,
    ttlMs: number,
  ): Promise<{ ok: true } | { ok: false; code: 'exists' }> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing presignSessionId');
    const parsed = parseRouterAbEcdsaDerivationPoolFillSessionRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA derivation pool-fill session record');
    try {
      const raw = await this.client.eval(
        ECDSA_PRESIGN_SESSION_CREATE_LUA,
        [this.key(key)],
        [JSON.stringify(parsed), String(toRedisMilliseconds(ttlMs)), String(Date.now())],
      );
      if (raw === 'ok') return { ok: true };
      if (raw === 'exists') return { ok: false, code: 'exists' };
      throw new Error(`[threshold-ecdsa] Unexpected Upstash CAS-create result: ${String(raw)}`);
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || '',
      );
      if (isEvalUnsupportedError(msg)) {
        throw new Error(
          '[threshold-ecdsa] Upstash EVAL is required for atomic presign-session CAS; ensure scripting is enabled',
        );
      }
      throw e;
    }
  }

  async getSession(id: string): Promise<RouterAbEcdsaDerivationPoolFillSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const record = parseRouterAbEcdsaDerivationPoolFillSessionRecordFromRaw(await this.client.getJson(this.key(key)));
    if (!record) return null;
    if (Date.now() > record.expiresAtMs) {
      await this.client.del(this.key(key));
      return null;
    }
    return record;
  }

  async advanceSessionCas(input: {
    id: string;
    expectedVersion: number;
    nextRecord: RouterAbEcdsaDerivationPoolFillSessionRecord;
    ttlMs: number;
  }): Promise<RouterAbEcdsaDerivationPoolFillSessionCasResult> {
    const key = toOptionalTrimmedString(input.id);
    if (!key) return { ok: false, code: 'not_found' };
    const expectedVersion = Math.floor(Number(input.expectedVersion));
    if (!Number.isFinite(expectedVersion) || expectedVersion < 1)
      return { ok: false, code: 'version_mismatch' };
    const parsed = parseRouterAbEcdsaDerivationPoolFillSessionRecord(input.nextRecord);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA derivation pool-fill session record');
    try {
      const raw = await this.client.eval(
        ECDSA_PRESIGN_SESSION_CAS_LUA,
        [this.key(key)],
        [
          String(expectedVersion),
          JSON.stringify(parsed),
          String(toRedisMilliseconds(input.ttlMs)),
          String(Date.now()),
        ],
      );
      return parsePresignSessionCasLuaResult(raw);
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || '',
      );
      if (isEvalUnsupportedError(msg)) {
        throw new Error(
          '[threshold-ecdsa] Upstash EVAL is required for atomic presign-session CAS; ensure scripting is enabled',
        );
      }
      throw e;
    }
  }

  async deleteSession(id: string): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) return;
    await this.client.del(this.key(key));
  }
}

class RedisTcpRouterAbEcdsaDerivationPoolFillSessionStore implements RouterAbEcdsaDerivationPoolFillSessionStore {
  private readonly client: RedisTcpClient;
  private readonly keyPrefix: string;

  constructor(input: { redisUrl: string; keyPrefix: string }) {
    const url = toOptionalTrimmedString(input.redisUrl);
    if (!url) throw new Error('redis-tcp presign session store missing redisUrl');
    this.client = new RedisTcpClient(url);
    this.keyPrefix = input.keyPrefix;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  async createSession(
    id: string,
    record: RouterAbEcdsaDerivationPoolFillSessionRecord,
    ttlMs: number,
  ): Promise<{ ok: true } | { ok: false; code: 'exists' }> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing presignSessionId');
    const parsed = parseRouterAbEcdsaDerivationPoolFillSessionRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA derivation pool-fill session record');
    const evalResp = await this.client.send([
      'EVAL',
      ECDSA_PRESIGN_SESSION_CREATE_LUA,
      '1',
      this.key(key),
      JSON.stringify(parsed),
      String(toRedisMilliseconds(ttlMs)),
      String(Date.now()),
    ]);
    if (evalResp.type === 'bulk' || evalResp.type === 'simple') {
      const raw = evalResp.value;
      if (raw === 'ok') return { ok: true };
      if (raw === 'exists') return { ok: false, code: 'exists' };
      throw new Error(`[threshold-ecdsa] Unexpected redis CAS-create result: ${String(raw)}`);
    }
    if (evalResp.type === 'error') {
      if (isEvalUnsupportedError(evalResp.value)) {
        throw new Error(
          '[threshold-ecdsa] Redis EVAL is required for atomic presign-session CAS; enable scripting permissions',
        );
      }
      throw new Error(`Redis EVAL error: ${evalResp.value}`);
    }
    throw new Error(
      `[threshold-ecdsa] Redis EVAL returned unexpected response type: ${evalResp.type}`,
    );
  }

  async getSession(id: string): Promise<RouterAbEcdsaDerivationPoolFillSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const raw = await this.client.send(['GET', this.key(key)]);
    if (raw.type === 'error') throw new Error(`Redis GET error: ${raw.value}`);
    if (raw.type !== 'bulk' || raw.value === null) return null;
    const record = parseRouterAbEcdsaDerivationPoolFillSessionRecordFromRaw(raw.value);
    if (!record) return null;
    if (Date.now() > record.expiresAtMs) {
      await this.deleteSession(key);
      return null;
    }
    return record;
  }

  async advanceSessionCas(input: {
    id: string;
    expectedVersion: number;
    nextRecord: RouterAbEcdsaDerivationPoolFillSessionRecord;
    ttlMs: number;
  }): Promise<RouterAbEcdsaDerivationPoolFillSessionCasResult> {
    const key = toOptionalTrimmedString(input.id);
    if (!key) return { ok: false, code: 'not_found' };
    const expectedVersion = Math.floor(Number(input.expectedVersion));
    if (!Number.isFinite(expectedVersion) || expectedVersion < 1)
      return { ok: false, code: 'version_mismatch' };
    const parsed = parseRouterAbEcdsaDerivationPoolFillSessionRecord(input.nextRecord);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA derivation pool-fill session record');
    const evalResp = await this.client.send([
      'EVAL',
      ECDSA_PRESIGN_SESSION_CAS_LUA,
      '1',
      this.key(key),
      String(expectedVersion),
      JSON.stringify(parsed),
      String(toRedisMilliseconds(input.ttlMs)),
      String(Date.now()),
    ]);
    if (evalResp.type === 'bulk' || evalResp.type === 'simple') {
      return parsePresignSessionCasLuaResult(evalResp.value);
    }
    if (evalResp.type === 'error') {
      if (isEvalUnsupportedError(evalResp.value)) {
        throw new Error(
          '[threshold-ecdsa] Redis EVAL is required for atomic presign-session CAS; enable scripting permissions',
        );
      }
      throw new Error(`Redis EVAL error: ${evalResp.value}`);
    }
    throw new Error(
      `[threshold-ecdsa] Redis EVAL returned unexpected response type: ${evalResp.type}`,
    );
  }

  async deleteSession(id: string): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) return;
    const resp = await this.client.send(['DEL', this.key(key)]);
    if (resp.type === 'error') throw new Error(`Redis DEL error: ${resp.value}`);
  }
}

function parseJson(raw: string): unknown | null {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

const ECDSA_PRESIGN_SESSION_CREATE_LUA = `
local key = KEYS[1]
local value = ARGV[1]
local ttlMs = tonumber(ARGV[2]) or 0
local nowMs = tonumber(ARGV[3]) or 0

local existing = redis.call('GET', key)
if existing then
  local ok, decoded = pcall(cjson.decode, existing)
  if ok and type(decoded) == 'table' then
    local expiresAtMs = tonumber(decoded['expiresAtMs']) or 0
    if expiresAtMs > nowMs then
      return 'exists'
    end
  else
    return 'exists'
  end
end

if ttlMs > 0 then
  redis.call('SET', key, value, 'PX', ttlMs)
else
  redis.call('SET', key, value)
end
return 'ok'
`.trim();

const ECDSA_PRESIGN_SESSION_CAS_LUA = `
local key = KEYS[1]
local expectedVersion = tonumber(ARGV[1]) or -1
local nextValue = ARGV[2]
local ttlMs = tonumber(ARGV[3]) or 0
local nowMs = tonumber(ARGV[4]) or 0

local raw = redis.call('GET', key)
if not raw then
  return '__err__:not_found'
end

local ok, decoded = pcall(cjson.decode, raw)
if (not ok) or type(decoded) ~= 'table' then
  return '__err__:not_found'
end

local expiresAtMs = tonumber(decoded['expiresAtMs']) or 0
if expiresAtMs <= nowMs then
  redis.call('DEL', key)
  return '__err__:expired'
end

local version = tonumber(decoded['version']) or -1
if version ~= expectedVersion then
  return '__err__:version_mismatch'
end

if ttlMs > 0 then
  redis.call('SET', key, nextValue, 'PX', ttlMs)
else
  redis.call('SET', key, nextValue)
end

return nextValue
`.trim();

function toRedisMilliseconds(ms: number): number {
  return Math.max(1, Math.ceil(Math.max(0, Number(ms) || 0)));
}

function parseRouterAbEcdsaDerivationPoolFillSessionRecordFromRaw(raw: unknown): RouterAbEcdsaDerivationPoolFillSessionRecord | null {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === 'string') {
    return parseRouterAbEcdsaDerivationPoolFillSessionRecord(
      parseJson(raw),
    ) as RouterAbEcdsaDerivationPoolFillSessionRecord | null;
  }
  return parseRouterAbEcdsaDerivationPoolFillSessionRecord(raw) as RouterAbEcdsaDerivationPoolFillSessionRecord | null;
}

function parsePresignSessionCasLuaResult(raw: unknown): RouterAbEcdsaDerivationPoolFillSessionCasResult {
  if (typeof raw === 'string' && raw.startsWith('__err__:')) {
    const codeRaw = raw.slice('__err__:'.length).trim();
    const code =
      codeRaw === 'expired'
        ? 'expired'
        : codeRaw === 'version_mismatch'
          ? 'version_mismatch'
          : 'not_found';
    return { ok: false, code };
  }
  const record = parseRouterAbEcdsaDerivationPoolFillSessionRecordFromRaw(raw);
  if (!record) return { ok: false, code: 'not_found' };
  return { ok: true, record };
}

function isEvalUnsupportedError(message: string): boolean {
  const m = String(message || '').toLowerCase();
  if (!m) return false;
  return (
    m.includes('unknown command') ||
    m.includes('err unknown command') ||
    m.includes('noperm') ||
    m.includes('command is not allowed')
  );
}

export function createThresholdEcdsaSigningStores(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): {
  poolFillSessionStore: RouterAbEcdsaDerivationPoolFillSessionStore;
} {
  const doStores = createCloudflareDurableObjectThresholdEcdsaStores({
    config: input.config,
    logger: input.logger,
  });
  if (doStores) {
    return {
      poolFillSessionStore: doStores.poolFillSessionStore,
    };
  }

  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const presignPrefix = toThresholdEcdsaPresignPrefix(
    toOptionalTrimmedString(config.THRESHOLD_ECDSA_PRESIGN_PREFIX) ||
      toThresholdEcdsaPrefixFromBase(basePrefix, 'presign'),
  );

  const kind = readNonDurableObjectThresholdStoreKind(config, 'threshold-ecdsa');
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error(
        '[threshold-ecdsa] In-memory presign stores are not supported in this runtime; configure Upstash/Redis REST or Durable Objects',
      );
    }
    return {
      poolFillSessionStore: new InMemoryRouterAbEcdsaDerivationPoolFillSessionStore(),
    };
  }

  if (kind === 'upstash-redis-rest') {
    const url =
      toOptionalTrimmedString(config.url) ||
      toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
    const token =
      toOptionalTrimmedString(config.token) ||
      toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
    if (!url || !token)
      throw new Error(
        '[threshold-ecdsa] upstash-redis-rest selected but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not set',
      );
    return {
      poolFillSessionStore: new UpstashRedisRestRouterAbEcdsaDerivationPoolFillSessionStore({
        url,
        token,
        keyPrefix: presignPrefix,
      }),
    };
  }

  if (kind === 'redis-tcp') {
    const redisUrl =
      toOptionalTrimmedString(config.redisUrl) ||
      toOptionalTrimmedString(config.REDIS_URL);
    if (!redisUrl) throw new Error('[threshold-ecdsa] redis-tcp selected but REDIS_URL is not set');
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error(
          '[threshold-ecdsa] redis-tcp presign stores are not supported in this runtime; configure Upstash/Redis REST or Durable Objects',
        );
      }
      input.logger.warn(
        '[threshold-ecdsa] redis-tcp is not supported in this runtime; falling back to in-memory',
      );
      return {
        poolFillSessionStore: new InMemoryRouterAbEcdsaDerivationPoolFillSessionStore(),
      };
    }
    return {
      poolFillSessionStore: new RedisTcpRouterAbEcdsaDerivationPoolFillSessionStore({
        redisUrl,
        keyPrefix: presignPrefix,
      }),
    };
  }

  // Env-shaped config: prefer Redis/Upstash for presign pools because records churn heavily.
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        '[threshold-ecdsa] Upstash selected but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set',
      );
    }
    input.logger.info('[threshold-ecdsa] Using Upstash REST for presign pool');
    return {
      poolFillSessionStore: new UpstashRedisRestRouterAbEcdsaDerivationPoolFillSessionStore({
        url: upstashUrl,
        token: upstashToken,
        keyPrefix: presignPrefix,
      }),
    };
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
      return {
        poolFillSessionStore: new InMemoryRouterAbEcdsaDerivationPoolFillSessionStore(),
      };
    }
    input.logger.info('[threshold-ecdsa] Using redis-tcp for presign pool');
    return {
      poolFillSessionStore: new RedisTcpRouterAbEcdsaDerivationPoolFillSessionStore({
        redisUrl,
        keyPrefix: presignPrefix,
      }),
    };
  }

  if (requirePersistent) {
    throw new Error(
      '[threshold-ecdsa] Presign stores require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or Durable Objects',
    );
  }

  input.logger.info(
    '[threshold-ecdsa] Using in-memory presign pool (non-persistent)',
  );
  return {
    poolFillSessionStore: new InMemoryRouterAbEcdsaDerivationPoolFillSessionStore(),
  };
}
