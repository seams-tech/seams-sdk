import type { NormalizedLogger } from '../../logger';
import type {
  ThresholdEd25519AuthorityScope,
  ThresholdEcdsaSigningRootMetadata,
  ThresholdStoreConfigInput,
} from '../../types';
import {
  RedisTcpClient,
  UpstashRedisRestClient,
  redisEval,
  redisGetJson,
  redisGetRaw,
  redisGetdelJson,
  redisSetJson,
} from '../kv';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  toThresholdEcdsaPrefixFromBase,
  toThresholdEcdsaSessionPrefix,
  toThresholdEd25519SessionPrefix,
  toThresholdEd25519PrefixFromBase,
  parseThresholdEd25519MpcSessionRecord,
  parseThresholdEcdsaMpcSessionRecord,
  parseThresholdEd25519CoordinatorSigningSessionRecord,
  parseThresholdEd25519SigningSessionRecord,
  isObject,
} from '../validation';
import {
  createCloudflareDurableObjectThresholdEcdsaStores,
  createCloudflareDurableObjectThresholdEd25519Stores,
} from './CloudflareDurableObjectStore';
import { readNonDurableObjectThresholdStoreKind } from './StoreConfig';

export type ThresholdEd25519Commitments = { hiding: string; binding: string };

export type ThresholdEd25519CommitmentsById = Record<string, ThresholdEd25519Commitments>;

export type ThresholdEd25519SigningShareMaterial =
  | {
      kind: 'key_store';
    }
  | {
      kind: 'embedded_cosigner_share';
      relayerSigningShareB64u: string;
    };

export type ThresholdEd25519MpcSessionRecord = {
  expiresAtMs: number;
  ecdsaThresholdKeyId?: string;
  keyHandle?: string;
  relayerKeyId: string;
  purpose: string;
  intentDigestB64u: string;
  signingDigestB64u: string;
  userId: string;
  authorityScope: ThresholdEd25519AuthorityScope;
  clientVerifyingShareB64u?: string;
  participantIds: number[];
} & Partial<ThresholdEcdsaSigningRootMetadata>;

export type ThresholdEcdsaMpcSessionRecord = {
  expiresAtMs: number;
  ecdsaThresholdKeyId?: string;
  keyHandle?: string;
  relayerKeyId: string;
  purpose: string;
  intentDigestB64u: string;
  signingDigestB64u: string;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  clientVerifyingShareB64u?: string;
  participantIds: number[];
} & Partial<ThresholdEcdsaSigningRootMetadata>;

export type ThresholdMpcSessionRecord =
  | ThresholdEd25519MpcSessionRecord
  | ThresholdEcdsaMpcSessionRecord;

export type ThresholdReadMpcSessionResult<TRecord extends ThresholdMpcSessionRecord> = {
  record: TRecord;
  version: string;
};

export type ThresholdClaimMpcSessionResult<TRecord extends ThresholdMpcSessionRecord> =
  | { ok: true; record: TRecord }
  | { ok: false; code: 'not_found' | 'expired' | 'version_mismatch' | 'invalid_record' };

export type ThresholdEd25519ReadMpcSessionResult =
  ThresholdReadMpcSessionResult<ThresholdEd25519MpcSessionRecord>;
export type ThresholdEcdsaReadMpcSessionResult =
  ThresholdReadMpcSessionResult<ThresholdEcdsaMpcSessionRecord>;
export type ThresholdEd25519ClaimMpcSessionResult =
  ThresholdClaimMpcSessionResult<ThresholdEd25519MpcSessionRecord>;
export type ThresholdEcdsaClaimMpcSessionResult =
  ThresholdClaimMpcSessionResult<ThresholdEcdsaMpcSessionRecord>;

export type ThresholdEd25519SigningSessionRecord = {
  expiresAtMs: number;
  mpcSessionId: string;
  relayerKeyId: string;
  signingDigestB64u: string;
  userId: string;
  authorityScope: ThresholdEd25519AuthorityScope;
  commitmentsById: ThresholdEd25519CommitmentsById;
  signingShare: ThresholdEd25519SigningShareMaterial;
  relayerNoncesB64u: string;
  participantIds: number[];
};

export type ThresholdEd25519CoordinatorSigningSessionRecord = {
  mode: 'cosigner';
  expiresAtMs: number;
  mpcSessionId: string;
  relayerKeyId: string;
  signingDigestB64u: string;
  userId: string;
  authorityScope: ThresholdEd25519AuthorityScope;
  commitmentsById: ThresholdEd25519CommitmentsById;
  participantIds: number[];
  groupPublicKey: string;
  cosignerIds: number[];
  cosignerRelayerUrlsById: Record<string, string>;
  cosignerCoordinatorGrantsById: Record<string, string>;
  relayerVerifyingSharesById: Record<string, string>;
};


export interface ThresholdMpcSessionStore<TRecord extends ThresholdMpcSessionRecord> {
  putMpcSession(id: string, record: TRecord, ttlMs: number): Promise<void>;
  readMpcSession(id: string): Promise<ThresholdReadMpcSessionResult<TRecord> | null>;
  claimMpcSession(id: string, version: string): Promise<ThresholdClaimMpcSessionResult<TRecord>>;
  takeMpcSession(id: string): Promise<TRecord | null>;
}

export interface ThresholdEd25519SessionStore
  extends ThresholdMpcSessionStore<ThresholdEd25519MpcSessionRecord> {
  putSigningSession(
    id: string,
    record: ThresholdEd25519SigningSessionRecord,
    ttlMs: number,
  ): Promise<void>;
  takeSigningSession(id: string): Promise<ThresholdEd25519SigningSessionRecord | null>;
  putCoordinatorSigningSession(
    id: string,
    record: ThresholdEd25519CoordinatorSigningSessionRecord,
    ttlMs: number,
  ): Promise<void>;
  takeCoordinatorSigningSession(
    id: string,
  ): Promise<ThresholdEd25519CoordinatorSigningSessionRecord | null>;
}

export type ThresholdEcdsaSessionStore =
  ThresholdMpcSessionStore<ThresholdEcdsaMpcSessionRecord>;

type ThresholdSessionStoreConfigRecord = Record<string, unknown>;

function parseRawJson(raw: string | null): unknown | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function stableStoreVersion(value: unknown): string {
  return JSON.stringify(value);
}


type ThresholdMpcSessionRecordParser<TRecord extends ThresholdMpcSessionRecord> = (
  raw: unknown,
) => TRecord | null;

class InMemoryThresholdEd25519SessionStore<
  TMpcRecord extends ThresholdMpcSessionRecord = ThresholdEd25519MpcSessionRecord,
> {
  private readonly map = new Map<string, { value: unknown; expiresAtMs: number }>();
  private readonly keyPrefix: string;
  private readonly coordinatorPrefix: string;
  private readonly parseMpcSessionRecord: ThresholdMpcSessionRecordParser<TMpcRecord>;

  constructor(input: {
    keyPrefix?: string;
    parseMpcSessionRecord?: ThresholdMpcSessionRecordParser<TMpcRecord>;
  }) {
    this.keyPrefix = toThresholdEd25519SessionPrefix(input.keyPrefix);
    this.coordinatorPrefix = `${this.keyPrefix}coord:`;
    this.parseMpcSessionRecord =
      input.parseMpcSessionRecord ||
      (parseThresholdEd25519MpcSessionRecord as ThresholdMpcSessionRecordParser<TMpcRecord>);
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private coordKey(id: string): string {
    return `${this.coordinatorPrefix}${id}`;
  }


  private getRaw(key: string): unknown | null {
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return null;
    }
    return entry.value;
  }

  async putMpcSession(
    id: string,
    record: TMpcRecord,
    ttlMs: number,
  ): Promise<void> {
    const key = this.key(id);
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    this.map.set(key, { value: record, expiresAtMs });
  }

  async readMpcSession(id: string): Promise<ThresholdReadMpcSessionResult<TMpcRecord> | null> {
    const key = this.key(id);
    const raw = this.getRaw(key);
    const record = this.parseMpcSessionRecord(raw);
    return record ? { record, version: stableStoreVersion(raw) } : null;
  }

  async claimMpcSession(
    id: string,
    version: string,
  ): Promise<ThresholdClaimMpcSessionResult<TMpcRecord>> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry) return { ok: false, code: 'not_found' };
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return { ok: false, code: 'expired' };
    }
    if (stableStoreVersion(entry.value) !== version) {
      return { ok: false, code: 'version_mismatch' };
    }
    const record = this.parseMpcSessionRecord(entry.value);
    this.map.delete(key);
    return record ? { ok: true, record } : { ok: false, code: 'invalid_record' };
  }

  async takeMpcSession(id: string): Promise<TMpcRecord | null> {
    const key = this.key(id);
    const raw = this.getRaw(key);
    this.map.delete(key);
    return this.parseMpcSessionRecord(raw);
  }

  async putSigningSession(
    id: string,
    record: ThresholdEd25519SigningSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    const key = this.key(id);
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    this.map.set(key, { value: record, expiresAtMs });
  }

  async takeSigningSession(id: string): Promise<ThresholdEd25519SigningSessionRecord | null> {
    const key = this.key(id);
    const raw = this.getRaw(key);
    this.map.delete(key);
    return parseThresholdEd25519SigningSessionRecord(raw);
  }

  async putCoordinatorSigningSession(
    id: string,
    record: ThresholdEd25519CoordinatorSigningSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    const key = this.coordKey(id);
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    this.map.set(key, { value: record, expiresAtMs });
  }

  async takeCoordinatorSigningSession(
    id: string,
  ): Promise<ThresholdEd25519CoordinatorSigningSessionRecord | null> {
    const key = this.coordKey(id);
    const raw = this.getRaw(key);
    this.map.delete(key);
    return parseThresholdEd25519CoordinatorSigningSessionRecord(raw);
  }

}

class UpstashRedisRestThresholdEd25519SessionStore<
  TMpcRecord extends ThresholdMpcSessionRecord = ThresholdEd25519MpcSessionRecord,
> {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;
  private readonly coordinatorPrefix: string;
  private readonly parseMpcSessionRecord: ThresholdMpcSessionRecordParser<TMpcRecord>;

  constructor(input: {
    url: string;
    token: string;
    keyPrefix?: string;
    parseMpcSessionRecord?: ThresholdMpcSessionRecordParser<TMpcRecord>;
  }) {
    const url = toOptionalTrimmedString(input.url);
    const token = toOptionalTrimmedString(input.token);
    if (!url) throw new Error('Upstash session store missing url');
    if (!token) throw new Error('Upstash session store missing token');
    this.client = new UpstashRedisRestClient({ url, token });
    this.keyPrefix = toThresholdEd25519SessionPrefix(input.keyPrefix);
    this.coordinatorPrefix = `${this.keyPrefix}coord:`;
    this.parseMpcSessionRecord =
      input.parseMpcSessionRecord ||
      (parseThresholdEd25519MpcSessionRecord as ThresholdMpcSessionRecordParser<TMpcRecord>);
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private coordKey(id: string): string {
    return `${this.coordinatorPrefix}${id}`;
  }

  async putMpcSession(
    id: string,
    record: TMpcRecord,
    ttlMs: number,
  ): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing mpcSessionId');
    await this.client.setJson(this.key(k), record, ttlMs);
  }

  async readMpcSession(id: string): Promise<ThresholdReadMpcSessionResult<TMpcRecord> | null> {
    const k = id;
    if (!k) return null;
    const raw = await this.client.getRaw(this.key(k));
    const version = typeof raw === 'string' ? raw : stableStoreVersion(raw);
    const record = this.parseMpcSessionRecord(
      typeof raw === 'string' ? parseRawJson(raw) : raw,
    );
    return record ? { record, version } : null;
  }

  async claimMpcSession(
    id: string,
    version: string,
  ): Promise<ThresholdClaimMpcSessionResult<TMpcRecord>> {
    const k = id;
    if (!k) return { ok: false, code: 'not_found' };
    const raw = await this.client.eval(
      "local v=redis.call('GET', KEYS[1]); if not v then return '__err__:not_found' end; local decoded=cjson.decode(v); local expires=tonumber(decoded['expiresAtMs']) or 0; if expires <= tonumber(ARGV[2]) then redis.call('DEL', KEYS[1]); return '__err__:expired' end; if v ~= ARGV[1] then return '__err__:version_mismatch' end; redis.call('DEL', KEYS[1]); return v",
      [this.key(k)],
      [version, String(Date.now())],
    );
    if (raw === '__err__:not_found') return { ok: false, code: 'not_found' };
    if (raw === '__err__:expired') return { ok: false, code: 'expired' };
    if (raw === '__err__:version_mismatch') return { ok: false, code: 'version_mismatch' };
    const parsed = this.parseMpcSessionRecord(
      parseRawJson(typeof raw === 'string' ? raw : null),
    );
    return parsed ? { ok: true, record: parsed } : { ok: false, code: 'invalid_record' };
  }

  async takeMpcSession(id: string): Promise<TMpcRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await this.client.getdelJson(this.key(k));
    return this.parseMpcSessionRecord(raw);
  }

  async putSigningSession(
    id: string,
    record: ThresholdEd25519SigningSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing signingSessionId');
    await this.client.setJson(this.key(k), record, ttlMs);
  }

  async takeSigningSession(id: string): Promise<ThresholdEd25519SigningSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await this.client.getdelJson(this.key(k));
    return parseThresholdEd25519SigningSessionRecord(raw);
  }

  async putCoordinatorSigningSession(
    id: string,
    record: ThresholdEd25519CoordinatorSigningSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing coordinator signingSessionId');
    await this.client.setJson(this.coordKey(k), record, ttlMs);
  }

  async takeCoordinatorSigningSession(
    id: string,
  ): Promise<ThresholdEd25519CoordinatorSigningSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await this.client.getdelJson(this.coordKey(k));
    return parseThresholdEd25519CoordinatorSigningSessionRecord(raw);
  }
}

class RedisTcpThresholdEd25519SessionStore<
  TMpcRecord extends ThresholdMpcSessionRecord = ThresholdEd25519MpcSessionRecord,
> {
  private readonly client: RedisTcpClient;
  private readonly keyPrefix: string;
  private readonly coordinatorPrefix: string;
  private readonly parseMpcSessionRecord: ThresholdMpcSessionRecordParser<TMpcRecord>;

  constructor(input: {
    redisUrl: string;
    keyPrefix?: string;
    parseMpcSessionRecord?: ThresholdMpcSessionRecordParser<TMpcRecord>;
  }) {
    const url = toOptionalTrimmedString(input.redisUrl);
    if (!url) throw new Error('redis-tcp session store missing redisUrl');
    this.client = new RedisTcpClient(url);
    this.keyPrefix = toThresholdEd25519SessionPrefix(input.keyPrefix);
    this.coordinatorPrefix = `${this.keyPrefix}coord:`;
    this.parseMpcSessionRecord =
      input.parseMpcSessionRecord ||
      (parseThresholdEd25519MpcSessionRecord as ThresholdMpcSessionRecordParser<TMpcRecord>);
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private coordKey(id: string): string {
    return `${this.coordinatorPrefix}${id}`;
  }

  async putMpcSession(
    id: string,
    record: TMpcRecord,
    ttlMs: number,
  ): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing mpcSessionId');
    await redisSetJson(this.client, this.key(k), record, ttlMs);
  }

  async readMpcSession(id: string): Promise<ThresholdReadMpcSessionResult<TMpcRecord> | null> {
    const k = id;
    if (!k) return null;
    const raw = await redisGetRaw(this.client, this.key(k));
    const record = this.parseMpcSessionRecord(parseRawJson(raw));
    return record && raw ? { record, version: raw } : null;
  }

  async claimMpcSession(
    id: string,
    version: string,
  ): Promise<ThresholdClaimMpcSessionResult<TMpcRecord>> {
    const k = id;
    if (!k) return { ok: false, code: 'not_found' };
    const raw = await redisEval(
      this.client,
      "local v=redis.call('GET', KEYS[1]); if not v then return '__err__:not_found' end; local decoded=cjson.decode(v); local expires=tonumber(decoded['expiresAtMs']) or 0; if expires <= tonumber(ARGV[2]) then redis.call('DEL', KEYS[1]); return '__err__:expired' end; if v ~= ARGV[1] then return '__err__:version_mismatch' end; redis.call('DEL', KEYS[1]); return v",
      [this.key(k)],
      [version, String(Date.now())],
    );
    const value = raw.type === 'bulk' ? raw.value : raw.type === 'simple' ? raw.value : null;
    if (value === '__err__:not_found') return { ok: false, code: 'not_found' };
    if (value === '__err__:expired') return { ok: false, code: 'expired' };
    if (value === '__err__:version_mismatch') return { ok: false, code: 'version_mismatch' };
    const parsed = this.parseMpcSessionRecord(parseRawJson(value));
    return parsed ? { ok: true, record: parsed } : { ok: false, code: 'invalid_record' };
  }

  async takeMpcSession(id: string): Promise<TMpcRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await redisGetdelJson(this.client, this.key(k));
    return this.parseMpcSessionRecord(raw);
  }

  async putSigningSession(
    id: string,
    record: ThresholdEd25519SigningSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing signingSessionId');
    await redisSetJson(this.client, this.key(k), record, ttlMs);
  }

  async takeSigningSession(id: string): Promise<ThresholdEd25519SigningSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await redisGetdelJson(this.client, this.key(k));
    return parseThresholdEd25519SigningSessionRecord(raw);
  }

  async putCoordinatorSigningSession(
    id: string,
    record: ThresholdEd25519CoordinatorSigningSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing coordinator signingSessionId');
    await redisSetJson(this.client, this.coordKey(k), record, ttlMs);
  }

  async takeCoordinatorSigningSession(
    id: string,
  ): Promise<ThresholdEd25519CoordinatorSigningSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await redisGetdelJson(this.client, this.coordKey(k));
    return parseThresholdEd25519CoordinatorSigningSessionRecord(raw);
  }

}

export function createThresholdEd25519SessionStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): ThresholdEd25519SessionStore {
  const doStores = createCloudflareDurableObjectThresholdEd25519Stores({
    config: input.config,
    logger: input.logger,
  });
  if (doStores) return doStores.sessionStore;

  const config = (isObject(input.config) ? input.config : {}) as ThresholdSessionStoreConfigRecord;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix =
    toOptionalTrimmedString(config.THRESHOLD_ED25519_SESSION_PREFIX) ||
    toThresholdEd25519PrefixFromBase(basePrefix, 'sess') ||
    '';

  // Explicit config object
  const kind = readNonDurableObjectThresholdStoreKind(config, 'threshold-ed25519');
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error(
        '[threshold-ed25519] In-memory session store is not supported in this runtime; configure Upstash/Redis or Durable Objects',
      );
    }
    return new InMemoryThresholdEd25519SessionStore({ keyPrefix: envPrefix || undefined });
  }
  if (kind === 'upstash-redis-rest') {
    return new UpstashRedisRestThresholdEd25519SessionStore({
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
          '[threshold-ed25519] redis-tcp session store is not supported in this runtime; configure Upstash/Redis REST or Durable Objects',
        );
      }
      input.logger.warn(
        '[threshold-ed25519] redis-tcp session store is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryThresholdEd25519SessionStore({ keyPrefix: envPrefix || undefined });
    }
    return new RedisTcpThresholdEd25519SessionStore({
      redisUrl:
        toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  // Env-shaped config: prefer Redis/Upstash for session storage (TTL + lower churn).
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        'Upstash session store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set',
      );
    }
    input.logger.info(
      '[threshold-ed25519] Using Upstash REST session store for signing session persistence',
    );
    return new UpstashRedisRestThresholdEd25519SessionStore({
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
      return new InMemoryThresholdEd25519SessionStore({ keyPrefix: envPrefix || undefined });
    }
    input.logger.info(
      '[threshold-ed25519] Using redis-tcp session store for signing session persistence',
    );
    return new RedisTcpThresholdEd25519SessionStore({
      redisUrl,
      keyPrefix: envPrefix || undefined,
    });
  }

  if (requirePersistent) {
    throw new Error(
      '[threshold-ed25519] Threshold signing sessions require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or Durable Objects',
    );
  }
  input.logger.info(
    '[threshold-ed25519] Using in-memory session store for threshold signing sessions (non-persistent)',
  );
  return new InMemoryThresholdEd25519SessionStore({ keyPrefix: envPrefix || undefined });
}

export function createThresholdEcdsaSessionStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): ThresholdEcdsaSessionStore {
  const doStores = createCloudflareDurableObjectThresholdEcdsaStores({
    config: input.config,
    logger: input.logger,
  });
  if (doStores) return doStores.sessionStore;

  const config = (isObject(input.config) ? input.config : {}) as ThresholdSessionStoreConfigRecord;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix = toThresholdEcdsaSessionPrefix(
    toOptionalTrimmedString(config.THRESHOLD_ECDSA_SESSION_PREFIX) ||
      toThresholdEcdsaPrefixFromBase(basePrefix, 'sess'),
  );

  // Explicit config object
  const kind = readNonDurableObjectThresholdStoreKind(config, 'threshold-ecdsa');
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error(
        '[threshold-ecdsa] In-memory session store is not supported in this runtime; configure Upstash/Redis or Durable Objects',
      );
    }
    return new InMemoryThresholdEd25519SessionStore<ThresholdEcdsaMpcSessionRecord>({
      keyPrefix: envPrefix,
      parseMpcSessionRecord: parseThresholdEcdsaMpcSessionRecord,
    });
  }
  if (kind === 'upstash-redis-rest') {
    return new UpstashRedisRestThresholdEd25519SessionStore<ThresholdEcdsaMpcSessionRecord>({
      url:
        toOptionalTrimmedString(config.url) ||
        toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL),
      token:
        toOptionalTrimmedString(config.token) ||
        toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
      parseMpcSessionRecord: parseThresholdEcdsaMpcSessionRecord,
    });
  }
  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error(
          '[threshold-ecdsa] redis-tcp session store is not supported in this runtime; configure Upstash/Redis REST or Durable Objects',
        );
      }
      input.logger.warn(
        '[threshold-ecdsa] redis-tcp session store is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryThresholdEd25519SessionStore<ThresholdEcdsaMpcSessionRecord>({
        keyPrefix: envPrefix,
        parseMpcSessionRecord: parseThresholdEcdsaMpcSessionRecord,
      });
    }
    return new RedisTcpThresholdEd25519SessionStore<ThresholdEcdsaMpcSessionRecord>({
      redisUrl:
        toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
      parseMpcSessionRecord: parseThresholdEcdsaMpcSessionRecord,
    });
  }
  // Env-shaped config: prefer Redis/Upstash for session storage (TTL + lower churn).
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        'Upstash session store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set',
      );
    }
    input.logger.info(
      '[threshold-ecdsa] Using Upstash REST session store for signing session persistence',
    );
    return new UpstashRedisRestThresholdEd25519SessionStore<ThresholdEcdsaMpcSessionRecord>({
      url: upstashUrl,
      token: upstashToken,
      keyPrefix: envPrefix,
      parseMpcSessionRecord: parseThresholdEcdsaMpcSessionRecord,
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
      return new InMemoryThresholdEd25519SessionStore<ThresholdEcdsaMpcSessionRecord>({
        keyPrefix: envPrefix,
        parseMpcSessionRecord: parseThresholdEcdsaMpcSessionRecord,
      });
    }
    input.logger.info(
      '[threshold-ecdsa] Using redis-tcp session store for signing session persistence',
    );
    return new RedisTcpThresholdEd25519SessionStore<ThresholdEcdsaMpcSessionRecord>({
      redisUrl,
      keyPrefix: envPrefix,
      parseMpcSessionRecord: parseThresholdEcdsaMpcSessionRecord,
    });
  }

  if (requirePersistent) {
    throw new Error(
      '[threshold-ecdsa] Threshold signing sessions require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or Durable Objects',
    );
  }
  input.logger.info(
    '[threshold-ecdsa] Using in-memory session store for threshold signing sessions (non-persistent)',
  );
  return new InMemoryThresholdEd25519SessionStore<ThresholdEcdsaMpcSessionRecord>({
    keyPrefix: envPrefix,
    parseMpcSessionRecord: parseThresholdEcdsaMpcSessionRecord,
  });
}
