import type { NormalizedLogger } from '../../logger';
import type { ThresholdEcdsaSigningRootMetadata, ThresholdStoreConfigInput } from '../../types';
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
import { getPostgresPool, getPostgresUrlFromConfig } from '../../../storage/postgres';
import {
  parseCurrentThresholdEd25519CoordinatorSigningSessionRecord,
  parseCurrentThresholdEd25519MpcSessionRecord,
  parseCurrentThresholdEd25519SigningSessionRecord,
  parseCurrentThresholdEd25519StoreSessionRow,
} from '../postgresRecords';
import {
  toThresholdEcdsaPrefixFromBase,
  toThresholdEcdsaSessionPrefix,
  toThresholdEd25519SessionPrefix,
  toThresholdEd25519PrefixFromBase,
  parseThresholdEd25519MpcSessionRecord,
  parseRouterAbEd25519PresignRecord,
  parseThresholdEd25519CoordinatorSigningSessionRecord,
  parseThresholdEd25519SigningSessionRecord,
  isObject,
  type ParsedRouterAbEd25519PresignRecord,
} from '../validation';
import {
  createCloudflareDurableObjectThresholdEcdsaStores,
  createCloudflareDurableObjectThresholdEd25519Stores,
} from './CloudflareDurableObjectStore';

export type ThresholdEd25519Commitments = { hiding: string; binding: string };

export type ThresholdEd25519CommitmentsById = Record<string, ThresholdEd25519Commitments>;

export type ThresholdEd25519MpcSessionRecord = {
  expiresAtMs: number;
  ecdsaThresholdKeyId?: string;
  keyHandle?: string;
  relayerKeyId: string;
  purpose: string;
  intentDigestB64u: string;
  signingDigestB64u: string;
  userId: string;
  rpId: string;
  clientVerifyingShareB64u?: string;
  participantIds: number[];
} & Partial<ThresholdEcdsaSigningRootMetadata>;

export type ThresholdEd25519ReadMpcSessionResult = {
  record: ThresholdEd25519MpcSessionRecord;
  version: string;
};

export type ThresholdEd25519ClaimMpcSessionResult =
  | { ok: true; record: ThresholdEd25519MpcSessionRecord }
  | { ok: false; code: 'not_found' | 'expired' | 'version_mismatch' | 'invalid_record' };

export type ThresholdEd25519SigningSessionRecord = {
  expiresAtMs: number;
  mpcSessionId: string;
  relayerKeyId: string;
  signingDigestB64u: string;
  userId: string;
  rpId: string;
  commitmentsById: ThresholdEd25519CommitmentsById;
  /**
   * Optional relayer signing share material for internal flows (e.g. relayer-fleet cosigners).
   * For normal relayer signing sessions this should be re-derived from key material instead.
   */
  relayerSigningShareB64u?: string;
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
  rpId: string;
  commitmentsById: ThresholdEd25519CommitmentsById;
  participantIds: number[];
  groupPublicKey: string;
  cosignerIds: number[];
  cosignerRelayerUrlsById: Record<string, string>;
  cosignerCoordinatorGrantsById: Record<string, string>;
  relayerVerifyingSharesById: Record<string, string>;
};

export type RouterAbEd25519PresignRecord = ParsedRouterAbEd25519PresignRecord;

export type RouterAbEd25519PresignExpectedScope = {
  thresholdSessionId: string;
  walletSigningSessionId: string;
  relayerKeyId: string;
  nearAccountId: string;
  nearNetworkId: string;
  signerPublicKey: string;
  rpcPolicyId: string;
  rpId: string;
  runtimePolicyScope: RouterAbEd25519PresignRecord['runtimePolicyScope'];
  participantIds: readonly number[];
  groupPublicKey: string;
};

export type RouterAbEd25519TakePresignForFinalizeResult =
  | { ok: true; record: RouterAbEd25519PresignRecord }
  | { ok: false; code: 'not_found' | 'expired' | 'scope_mismatch' | 'invalid_record' };

export type RouterAbEd25519PresignCapacity = {
  walletSigningSessionMax: number;
  globalMax: number;
};

export type RouterAbEd25519PutPresignWithCapacityResult =
  | { ok: true }
  | { ok: false; code: 'capacity_exceeded' };

export type RouterAbEd25519CheckPresignCapacityResult =
  | { ok: true }
  | { ok: false; code: 'capacity_exceeded' };

export type RouterAbEd25519PresignRefillRateLimitBucket = {
  kind: 'wallet_signing_session' | 'threshold_session' | 'account_relayer_key' | 'request_origin';
  key: string;
};

export type RouterAbEd25519PresignRefillRateLimitPolicy = {
  windowMs: number;
  maxCost: number;
};

export type RouterAbEd25519ConsumePresignRefillRateLimitResult =
  | { ok: true }
  | { ok: false; code: 'rate_limited' };

export interface ThresholdEd25519SessionStore {
  putMpcSession(id: string, record: ThresholdEd25519MpcSessionRecord, ttlMs: number): Promise<void>;
  readMpcSession(id: string): Promise<ThresholdEd25519ReadMpcSessionResult | null>;
  claimMpcSession(id: string, version: string): Promise<ThresholdEd25519ClaimMpcSessionResult>;
  takeMpcSession(id: string): Promise<ThresholdEd25519MpcSessionRecord | null>;
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
  putPresign(id: string, record: RouterAbEd25519PresignRecord, ttlMs: number): Promise<void>;
  putPresignWithCapacity(
    id: string,
    record: RouterAbEd25519PresignRecord,
    ttlMs: number,
    capacity: RouterAbEd25519PresignCapacity,
  ): Promise<RouterAbEd25519PutPresignWithCapacityResult>;
  checkPresignCapacity(
    walletSigningSessionId: string,
    capacity: RouterAbEd25519PresignCapacity,
  ): Promise<RouterAbEd25519CheckPresignCapacityResult>;
  consumePresignRefillRateLimit(
    bucket: RouterAbEd25519PresignRefillRateLimitBucket,
    policy: RouterAbEd25519PresignRefillRateLimitPolicy,
    cost: number,
  ): Promise<RouterAbEd25519ConsumePresignRefillRateLimitResult>;
  takePresignForFinalize(
    id: string,
    expectedScope: RouterAbEd25519PresignExpectedScope,
  ): Promise<RouterAbEd25519TakePresignForFinalizeResult>;
}

function runtimePolicyScopesMatch(
  left: RouterAbEd25519PresignRecord['runtimePolicyScope'],
  right: RouterAbEd25519PresignExpectedScope['runtimePolicyScope'],
): boolean {
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

function participantIdsMatch(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((id, index) => id === right[index]);
}

function presignRecordMatchesExpectedScope(
  record: RouterAbEd25519PresignRecord,
  expected: RouterAbEd25519PresignExpectedScope,
): boolean {
  return (
    record.thresholdSessionId === expected.thresholdSessionId &&
    record.walletSigningSessionId === expected.walletSigningSessionId &&
    record.relayerKeyId === expected.relayerKeyId &&
    record.nearAccountId === expected.nearAccountId &&
    record.nearNetworkId === expected.nearNetworkId &&
    record.signerPublicKey === expected.signerPublicKey &&
    record.rpcPolicyId === expected.rpcPolicyId &&
    record.rpId === expected.rpId &&
    record.groupPublicKey === expected.groupPublicKey &&
    runtimePolicyScopesMatch(record.runtimePolicyScope, expected.runtimePolicyScope) &&
    participantIdsMatch(record.participantIds, expected.participantIds)
  );
}

function parseStoredPresignRecord(raw: unknown): RouterAbEd25519PresignRecord | null {
  return parseRouterAbEd25519PresignRecord(raw);
}

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

function positiveIntegerCapacity(value: number, fieldName: string): number {
  const normalized = Math.floor(Number(value));
  if (!Number.isSafeInteger(normalized) || normalized < 1) {
    throw new Error(`${fieldName} must be a positive integer`);
  }
  return normalized;
}

function positiveIntegerLimit(value: number, fieldName: string): number {
  const normalized = Math.floor(Number(value));
  if (!Number.isSafeInteger(normalized) || normalized < 1) {
    throw new Error(`${fieldName} must be a positive integer`);
  }
  return normalized;
}

function presignRateLimitWindowKey(input: {
  prefix: string;
  bucket: RouterAbEd25519PresignRefillRateLimitBucket;
  policy: RouterAbEd25519PresignRefillRateLimitPolicy;
  nowMs: number;
}): string {
  const key = toOptionalTrimmedString(input.bucket.key);
  if (!key) throw new Error('presign refill rate limit bucket key is required');
  const windowMs = positiveIntegerLimit(input.policy.windowMs, 'windowMs');
  const windowStartMs = Math.floor(input.nowMs / windowMs) * windowMs;
  return `${input.prefix}${input.bucket.kind}:${encodeURIComponent(key)}:${windowStartMs}`;
}

function ttlSeconds(ttlMs: number): number {
  return Math.max(1, Math.ceil(Math.max(0, Number(ttlMs) || 0) / 1000));
}

class InMemoryThresholdEd25519SessionStore implements ThresholdEd25519SessionStore {
  private readonly map = new Map<string, { value: unknown; expiresAtMs: number }>();
  private readonly keyPrefix: string;
  private readonly coordinatorPrefix: string;
  private readonly presignPrefix: string;
  private readonly presignRateLimitPrefix: string;

  constructor(input: { keyPrefix?: string }) {
    this.keyPrefix = toThresholdEd25519SessionPrefix(input.keyPrefix);
    this.coordinatorPrefix = `${this.keyPrefix}coord:`;
    this.presignPrefix = `${this.keyPrefix}presign:`;
    this.presignRateLimitPrefix = `${this.keyPrefix}presign-rate:`;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private coordKey(id: string): string {
    return `${this.coordinatorPrefix}${id}`;
  }

  private presignKey(id: string): string {
    return `${this.presignPrefix}${id}`;
  }

  private presignGlobalIndexKey(): string {
    return `${this.presignPrefix}idx:global`;
  }

  private presignWalletIndexKey(walletSigningSessionId: string): string {
    return `${this.presignPrefix}idx:wallet:${encodeURIComponent(walletSigningSessionId)}`;
  }

  private pruneExpiredPresigns(nowMs: number): void {
    for (const [key, entry] of this.map.entries()) {
      if (!key.startsWith(this.presignPrefix)) continue;
      const parsed = parseStoredPresignRecord(entry.value);
      if (!parsed || entry.expiresAtMs <= nowMs || parsed.expiresAtMs <= nowMs) {
        this.map.delete(key);
      }
    }
  }

  private presignCounts(
    walletSigningSessionId: string,
    nowMs: number,
  ): {
    wallet: number;
    global: number;
  } {
    this.pruneExpiredPresigns(nowMs);
    let wallet = 0;
    let global = 0;
    for (const [key, entry] of this.map.entries()) {
      if (!key.startsWith(this.presignPrefix) || entry.expiresAtMs <= nowMs) continue;
      const parsed = parseStoredPresignRecord(entry.value);
      if (!parsed || parsed.expiresAtMs <= nowMs) continue;
      global += 1;
      if (parsed.walletSigningSessionId === walletSigningSessionId) wallet += 1;
    }
    return { wallet, global };
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
    record: ThresholdEd25519MpcSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    const key = this.key(id);
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    this.map.set(key, { value: record, expiresAtMs });
  }

  async readMpcSession(id: string): Promise<ThresholdEd25519ReadMpcSessionResult | null> {
    const key = this.key(id);
    const raw = this.getRaw(key);
    const record = parseThresholdEd25519MpcSessionRecord(raw);
    return record ? { record, version: stableStoreVersion(raw) } : null;
  }

  async claimMpcSession(
    id: string,
    version: string,
  ): Promise<ThresholdEd25519ClaimMpcSessionResult> {
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
    const record = parseThresholdEd25519MpcSessionRecord(entry.value);
    this.map.delete(key);
    return record ? { ok: true, record } : { ok: false, code: 'invalid_record' };
  }

  async takeMpcSession(id: string): Promise<ThresholdEd25519MpcSessionRecord | null> {
    const key = this.key(id);
    const raw = this.getRaw(key);
    this.map.delete(key);
    return parseThresholdEd25519MpcSessionRecord(raw);
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

  async putPresign(
    id: string,
    record: RouterAbEd25519PresignRecord,
    ttlMs: number,
  ): Promise<void> {
    const parsed = parseStoredPresignRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B Ed25519 presign record');
    const key = this.presignKey(id);
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    this.map.set(key, { value: { ...parsed, expiresAtMs }, expiresAtMs });
  }

  async putPresignWithCapacity(
    id: string,
    record: RouterAbEd25519PresignRecord,
    ttlMs: number,
    capacity: RouterAbEd25519PresignCapacity,
  ): Promise<RouterAbEd25519PutPresignWithCapacityResult> {
    const parsed = parseStoredPresignRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B Ed25519 presign record');
    const walletMax = positiveIntegerCapacity(
      capacity.walletSigningSessionMax,
      'walletSigningSessionMax',
    );
    const globalMax = positiveIntegerCapacity(capacity.globalMax, 'globalMax');
    const counts = this.presignCounts(parsed.walletSigningSessionId, Date.now());
    if (counts.wallet >= walletMax || counts.global >= globalMax) {
      return { ok: false, code: 'capacity_exceeded' };
    }
    await this.putPresign(id, parsed, ttlMs);
    return { ok: true };
  }

  async checkPresignCapacity(
    walletSigningSessionId: string,
    capacity: RouterAbEd25519PresignCapacity,
  ): Promise<RouterAbEd25519CheckPresignCapacityResult> {
    const walletId = toOptionalTrimmedString(walletSigningSessionId);
    if (!walletId) return { ok: false, code: 'capacity_exceeded' };
    const walletMax = positiveIntegerCapacity(
      capacity.walletSigningSessionMax,
      'walletSigningSessionMax',
    );
    const globalMax = positiveIntegerCapacity(capacity.globalMax, 'globalMax');
    const counts = this.presignCounts(walletId, Date.now());
    return counts.wallet >= walletMax || counts.global >= globalMax
      ? { ok: false, code: 'capacity_exceeded' }
      : { ok: true };
  }

  async consumePresignRefillRateLimit(
    bucket: RouterAbEd25519PresignRefillRateLimitBucket,
    policy: RouterAbEd25519PresignRefillRateLimitPolicy,
    cost: number,
  ): Promise<RouterAbEd25519ConsumePresignRefillRateLimitResult> {
    const nowMs = Date.now();
    const costInt = positiveIntegerLimit(cost, 'cost');
    const maxCost = positiveIntegerLimit(policy.maxCost, 'maxCost');
    const windowMs = positiveIntegerLimit(policy.windowMs, 'windowMs');
    const key = presignRateLimitWindowKey({
      prefix: this.presignRateLimitPrefix,
      bucket,
      policy,
      nowMs,
    });
    const entry = this.map.get(key);
    const current =
      entry && entry.expiresAtMs > nowMs && typeof entry.value === 'number' ? entry.value : 0;
    const next = current + costInt;
    if (next > maxCost) return { ok: false, code: 'rate_limited' };
    this.map.set(key, { value: next, expiresAtMs: nowMs + windowMs });
    return { ok: true };
  }

  async takePresignForFinalize(
    id: string,
    expectedScope: RouterAbEd25519PresignExpectedScope,
  ): Promise<RouterAbEd25519TakePresignForFinalizeResult> {
    const key = this.presignKey(id);
    const entry = this.map.get(key);
    if (!entry) return { ok: false, code: 'not_found' };
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return { ok: false, code: 'expired' };
    }
    const parsed = parseStoredPresignRecord(entry.value);
    if (!parsed) {
      this.map.delete(key);
      return { ok: false, code: 'invalid_record' };
    }
    if (!presignRecordMatchesExpectedScope(parsed, expectedScope)) {
      return { ok: false, code: 'scope_mismatch' };
    }
    this.map.delete(key);
    return { ok: true, record: parsed };
  }
}

class UpstashRedisRestThresholdEd25519SessionStore implements ThresholdEd25519SessionStore {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;
  private readonly coordinatorPrefix: string;
  private readonly presignPrefix: string;
  private readonly presignRateLimitPrefix: string;

  constructor(input: { url: string; token: string; keyPrefix?: string }) {
    const url = toOptionalTrimmedString(input.url);
    const token = toOptionalTrimmedString(input.token);
    if (!url) throw new Error('Upstash session store missing url');
    if (!token) throw new Error('Upstash session store missing token');
    this.client = new UpstashRedisRestClient({ url, token });
    this.keyPrefix = toThresholdEd25519SessionPrefix(input.keyPrefix);
    this.coordinatorPrefix = `${this.keyPrefix}coord:`;
    this.presignPrefix = `${this.keyPrefix}presign:`;
    this.presignRateLimitPrefix = `${this.keyPrefix}presign-rate:`;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private coordKey(id: string): string {
    return `${this.coordinatorPrefix}${id}`;
  }

  private presignKey(id: string): string {
    return `${this.presignPrefix}${id}`;
  }

  private presignGlobalIndexKey(): string {
    return `${this.presignPrefix}idx:global`;
  }

  private presignWalletIndexKey(walletSigningSessionId: string): string {
    return `${this.presignPrefix}idx:wallet:${encodeURIComponent(walletSigningSessionId)}`;
  }

  async putMpcSession(
    id: string,
    record: ThresholdEd25519MpcSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing mpcSessionId');
    await this.client.setJson(this.key(k), record, ttlMs);
  }

  async readMpcSession(id: string): Promise<ThresholdEd25519ReadMpcSessionResult | null> {
    const k = id;
    if (!k) return null;
    const raw = await this.client.getRaw(this.key(k));
    const version = typeof raw === 'string' ? raw : stableStoreVersion(raw);
    const record = parseThresholdEd25519MpcSessionRecord(
      typeof raw === 'string' ? parseRawJson(raw) : raw,
    );
    return record ? { record, version } : null;
  }

  async claimMpcSession(
    id: string,
    version: string,
  ): Promise<ThresholdEd25519ClaimMpcSessionResult> {
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
    const parsed = parseThresholdEd25519MpcSessionRecord(
      parseRawJson(typeof raw === 'string' ? raw : null),
    );
    return parsed ? { ok: true, record: parsed } : { ok: false, code: 'invalid_record' };
  }

  async takeMpcSession(id: string): Promise<ThresholdEd25519MpcSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await this.client.getdelJson(this.key(k));
    return parseThresholdEd25519MpcSessionRecord(raw);
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

  async putPresign(
    id: string,
    record: RouterAbEd25519PresignRecord,
    ttlMs: number,
  ): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing presignId');
    const parsed = parseStoredPresignRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B Ed25519 presign record');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    await this.client.setJson(this.presignKey(k), { ...parsed, expiresAtMs }, ttlMs);
  }

  async putPresignWithCapacity(
    id: string,
    record: RouterAbEd25519PresignRecord,
    ttlMs: number,
    capacity: RouterAbEd25519PresignCapacity,
  ): Promise<RouterAbEd25519PutPresignWithCapacityResult> {
    const k = id;
    if (!k) throw new Error('Missing presignId');
    const parsed = parseStoredPresignRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B Ed25519 presign record');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    const walletMax = positiveIntegerCapacity(
      capacity.walletSigningSessionMax,
      'walletSigningSessionMax',
    );
    const globalMax = positiveIntegerCapacity(capacity.globalMax, 'globalMax');
    const result = await this.client.eval(
      [
        'local presignKey = KEYS[1]',
        'local walletIndexKey = KEYS[2]',
        'local globalIndexKey = KEYS[3]',
        'local recordJson = ARGV[1]',
        'local ttlSeconds = tonumber(ARGV[2])',
        'local expiresAtMs = tonumber(ARGV[3])',
        'local nowMs = tonumber(ARGV[4])',
        'local walletMax = tonumber(ARGV[5])',
        'local globalMax = tonumber(ARGV[6])',
        'local presignId = ARGV[7]',
        "redis.call('ZREMRANGEBYSCORE', walletIndexKey, '-inf', nowMs)",
        "redis.call('ZREMRANGEBYSCORE', globalIndexKey, '-inf', nowMs)",
        "if redis.call('EXISTS', presignKey) == 0 then",
        "  if redis.call('ZCARD', walletIndexKey) >= walletMax then return 'capacity_exceeded' end",
        "  if redis.call('ZCARD', globalIndexKey) >= globalMax then return 'capacity_exceeded' end",
        'end',
        "redis.call('SET', presignKey, recordJson, 'EX', ttlSeconds)",
        "redis.call('ZADD', walletIndexKey, expiresAtMs, presignId)",
        "redis.call('ZADD', globalIndexKey, expiresAtMs, presignId)",
        "redis.call('EXPIRE', walletIndexKey, ttlSeconds)",
        "redis.call('EXPIRE', globalIndexKey, ttlSeconds)",
        "return 'ok'",
      ].join('\n'),
      [
        this.presignKey(k),
        this.presignWalletIndexKey(parsed.walletSigningSessionId),
        this.presignGlobalIndexKey(),
      ],
      [
        JSON.stringify({ ...parsed, expiresAtMs }),
        String(ttlSeconds(ttlMs)),
        String(Math.floor(expiresAtMs)),
        String(Date.now()),
        String(walletMax),
        String(globalMax),
        k,
      ],
    );
    return result === 'ok' ? { ok: true } : { ok: false, code: 'capacity_exceeded' };
  }

  async checkPresignCapacity(
    walletSigningSessionId: string,
    capacity: RouterAbEd25519PresignCapacity,
  ): Promise<RouterAbEd25519CheckPresignCapacityResult> {
    const walletId = toOptionalTrimmedString(walletSigningSessionId);
    if (!walletId) return { ok: false, code: 'capacity_exceeded' };
    const walletMax = positiveIntegerCapacity(
      capacity.walletSigningSessionMax,
      'walletSigningSessionMax',
    );
    const globalMax = positiveIntegerCapacity(capacity.globalMax, 'globalMax');
    const result = await this.client.eval(
      [
        'local walletIndexKey = KEYS[1]',
        'local globalIndexKey = KEYS[2]',
        'local nowMs = tonumber(ARGV[1])',
        'local walletMax = tonumber(ARGV[2])',
        'local globalMax = tonumber(ARGV[3])',
        "redis.call('ZREMRANGEBYSCORE', walletIndexKey, '-inf', nowMs)",
        "redis.call('ZREMRANGEBYSCORE', globalIndexKey, '-inf', nowMs)",
        "if redis.call('ZCARD', walletIndexKey) >= walletMax then return 'capacity_exceeded' end",
        "if redis.call('ZCARD', globalIndexKey) >= globalMax then return 'capacity_exceeded' end",
        "return 'ok'",
      ].join('\n'),
      [this.presignWalletIndexKey(walletId), this.presignGlobalIndexKey()],
      [String(Date.now()), String(walletMax), String(globalMax)],
    );
    return result === 'ok' ? { ok: true } : { ok: false, code: 'capacity_exceeded' };
  }

  async consumePresignRefillRateLimit(
    bucket: RouterAbEd25519PresignRefillRateLimitBucket,
    policy: RouterAbEd25519PresignRefillRateLimitPolicy,
    cost: number,
  ): Promise<RouterAbEd25519ConsumePresignRefillRateLimitResult> {
    const nowMs = Date.now();
    const costInt = positiveIntegerLimit(cost, 'cost');
    const maxCost = positiveIntegerLimit(policy.maxCost, 'maxCost');
    const windowMs = positiveIntegerLimit(policy.windowMs, 'windowMs');
    const key = presignRateLimitWindowKey({
      prefix: this.presignRateLimitPrefix,
      bucket,
      policy,
      nowMs,
    });
    const result = await this.client.eval(
      [
        "local current = redis.call('INCRBY', KEYS[1], ARGV[1])",
        "if current == tonumber(ARGV[1]) then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end",
        "if current > tonumber(ARGV[3]) then return 'rate_limited' end",
        "return 'ok'",
      ].join('\n'),
      [key],
      [String(costInt), String(windowMs), String(maxCost)],
    );
    return result === 'ok' ? { ok: true } : { ok: false, code: 'rate_limited' };
  }

  async takePresignForFinalize(
    id: string,
    expectedScope: RouterAbEd25519PresignExpectedScope,
  ): Promise<RouterAbEd25519TakePresignForFinalizeResult> {
    const k = id;
    if (!k) return { ok: false, code: 'not_found' };
    const key = this.presignKey(k);
    const raw = await this.client.getRaw(key);
    const parsed = parseStoredPresignRecord(parseRawJson(typeof raw === 'string' ? raw : null));
    if (!parsed) return { ok: false, code: 'not_found' };
    if (Date.now() > parsed.expiresAtMs) {
      await this.client.del(key);
      await this.client.eval(
        "redis.call('ZREM', KEYS[1], ARGV[1]); redis.call('ZREM', KEYS[2], ARGV[1]); return 'ok'",
        [this.presignWalletIndexKey(parsed.walletSigningSessionId), this.presignGlobalIndexKey()],
        [k],
      );
      return { ok: false, code: 'expired' };
    }
    if (!presignRecordMatchesExpectedScope(parsed, expectedScope)) {
      return { ok: false, code: 'scope_mismatch' };
    }
    const deleted = await this.client.eval(
      "local v=redis.call('GET', KEYS[1]); if v == ARGV[1] then redis.call('DEL', KEYS[1]); redis.call('ZREM', KEYS[2], ARGV[2]); redis.call('ZREM', KEYS[3], ARGV[2]); return v else return nil end",
      [
        key,
        this.presignWalletIndexKey(parsed.walletSigningSessionId),
        this.presignGlobalIndexKey(),
      ],
      [raw as string, k],
    );
    const deletedRaw = typeof deleted === 'string' ? deleted : null;
    const deletedParsed = parseStoredPresignRecord(parseRawJson(deletedRaw));
    return deletedParsed ? { ok: true, record: deletedParsed } : { ok: false, code: 'not_found' };
  }
}

class RedisTcpThresholdEd25519SessionStore implements ThresholdEd25519SessionStore {
  private readonly client: RedisTcpClient;
  private readonly keyPrefix: string;
  private readonly coordinatorPrefix: string;
  private readonly presignPrefix: string;
  private readonly presignRateLimitPrefix: string;

  constructor(input: { redisUrl: string; keyPrefix?: string }) {
    const url = toOptionalTrimmedString(input.redisUrl);
    if (!url) throw new Error('redis-tcp session store missing redisUrl');
    this.client = new RedisTcpClient(url);
    this.keyPrefix = toThresholdEd25519SessionPrefix(input.keyPrefix);
    this.coordinatorPrefix = `${this.keyPrefix}coord:`;
    this.presignPrefix = `${this.keyPrefix}presign:`;
    this.presignRateLimitPrefix = `${this.keyPrefix}presign-rate:`;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private coordKey(id: string): string {
    return `${this.coordinatorPrefix}${id}`;
  }

  private presignKey(id: string): string {
    return `${this.presignPrefix}${id}`;
  }

  private presignGlobalIndexKey(): string {
    return `${this.presignPrefix}idx:global`;
  }

  private presignWalletIndexKey(walletSigningSessionId: string): string {
    return `${this.presignPrefix}idx:wallet:${encodeURIComponent(walletSigningSessionId)}`;
  }

  async putMpcSession(
    id: string,
    record: ThresholdEd25519MpcSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing mpcSessionId');
    await redisSetJson(this.client, this.key(k), record, ttlMs);
  }

  async readMpcSession(id: string): Promise<ThresholdEd25519ReadMpcSessionResult | null> {
    const k = id;
    if (!k) return null;
    const raw = await redisGetRaw(this.client, this.key(k));
    const record = parseThresholdEd25519MpcSessionRecord(parseRawJson(raw));
    return record && raw ? { record, version: raw } : null;
  }

  async claimMpcSession(
    id: string,
    version: string,
  ): Promise<ThresholdEd25519ClaimMpcSessionResult> {
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
    const parsed = parseThresholdEd25519MpcSessionRecord(parseRawJson(value));
    return parsed ? { ok: true, record: parsed } : { ok: false, code: 'invalid_record' };
  }

  async takeMpcSession(id: string): Promise<ThresholdEd25519MpcSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await redisGetdelJson(this.client, this.key(k));
    return parseThresholdEd25519MpcSessionRecord(raw);
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

  async putPresign(
    id: string,
    record: RouterAbEd25519PresignRecord,
    ttlMs: number,
  ): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing presignId');
    const parsed = parseStoredPresignRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B Ed25519 presign record');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    await redisSetJson(this.client, this.presignKey(k), { ...parsed, expiresAtMs }, ttlMs);
  }

  async putPresignWithCapacity(
    id: string,
    record: RouterAbEd25519PresignRecord,
    ttlMs: number,
    capacity: RouterAbEd25519PresignCapacity,
  ): Promise<RouterAbEd25519PutPresignWithCapacityResult> {
    const k = id;
    if (!k) throw new Error('Missing presignId');
    const parsed = parseStoredPresignRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B Ed25519 presign record');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    const walletMax = positiveIntegerCapacity(
      capacity.walletSigningSessionMax,
      'walletSigningSessionMax',
    );
    const globalMax = positiveIntegerCapacity(capacity.globalMax, 'globalMax');
    const result = await redisEval(
      this.client,
      [
        'local presignKey = KEYS[1]',
        'local walletIndexKey = KEYS[2]',
        'local globalIndexKey = KEYS[3]',
        'local recordJson = ARGV[1]',
        'local ttlSeconds = tonumber(ARGV[2])',
        'local expiresAtMs = tonumber(ARGV[3])',
        'local nowMs = tonumber(ARGV[4])',
        'local walletMax = tonumber(ARGV[5])',
        'local globalMax = tonumber(ARGV[6])',
        'local presignId = ARGV[7]',
        "redis.call('ZREMRANGEBYSCORE', walletIndexKey, '-inf', nowMs)",
        "redis.call('ZREMRANGEBYSCORE', globalIndexKey, '-inf', nowMs)",
        "if redis.call('EXISTS', presignKey) == 0 then",
        "  if redis.call('ZCARD', walletIndexKey) >= walletMax then return 'capacity_exceeded' end",
        "  if redis.call('ZCARD', globalIndexKey) >= globalMax then return 'capacity_exceeded' end",
        'end',
        "redis.call('SET', presignKey, recordJson, 'EX', ttlSeconds)",
        "redis.call('ZADD', walletIndexKey, expiresAtMs, presignId)",
        "redis.call('ZADD', globalIndexKey, expiresAtMs, presignId)",
        "redis.call('EXPIRE', walletIndexKey, ttlSeconds)",
        "redis.call('EXPIRE', globalIndexKey, ttlSeconds)",
        "return 'ok'",
      ].join('\n'),
      [
        this.presignKey(k),
        this.presignWalletIndexKey(parsed.walletSigningSessionId),
        this.presignGlobalIndexKey(),
      ],
      [
        JSON.stringify({ ...parsed, expiresAtMs }),
        String(ttlSeconds(ttlMs)),
        String(Math.floor(expiresAtMs)),
        String(Date.now()),
        String(walletMax),
        String(globalMax),
        k,
      ],
    );
    return result.type === 'bulk' && result.value === 'ok'
      ? { ok: true }
      : { ok: false, code: 'capacity_exceeded' };
  }

  async checkPresignCapacity(
    walletSigningSessionId: string,
    capacity: RouterAbEd25519PresignCapacity,
  ): Promise<RouterAbEd25519CheckPresignCapacityResult> {
    const walletId = toOptionalTrimmedString(walletSigningSessionId);
    if (!walletId) return { ok: false, code: 'capacity_exceeded' };
    const walletMax = positiveIntegerCapacity(
      capacity.walletSigningSessionMax,
      'walletSigningSessionMax',
    );
    const globalMax = positiveIntegerCapacity(capacity.globalMax, 'globalMax');
    const result = await redisEval(
      this.client,
      [
        'local walletIndexKey = KEYS[1]',
        'local globalIndexKey = KEYS[2]',
        'local nowMs = tonumber(ARGV[1])',
        'local walletMax = tonumber(ARGV[2])',
        'local globalMax = tonumber(ARGV[3])',
        "redis.call('ZREMRANGEBYSCORE', walletIndexKey, '-inf', nowMs)",
        "redis.call('ZREMRANGEBYSCORE', globalIndexKey, '-inf', nowMs)",
        "if redis.call('ZCARD', walletIndexKey) >= walletMax then return 'capacity_exceeded' end",
        "if redis.call('ZCARD', globalIndexKey) >= globalMax then return 'capacity_exceeded' end",
        "return 'ok'",
      ].join('\n'),
      [this.presignWalletIndexKey(walletId), this.presignGlobalIndexKey()],
      [String(Date.now()), String(walletMax), String(globalMax)],
    );
    return result.type === 'bulk' && result.value === 'ok'
      ? { ok: true }
      : { ok: false, code: 'capacity_exceeded' };
  }

  async consumePresignRefillRateLimit(
    bucket: RouterAbEd25519PresignRefillRateLimitBucket,
    policy: RouterAbEd25519PresignRefillRateLimitPolicy,
    cost: number,
  ): Promise<RouterAbEd25519ConsumePresignRefillRateLimitResult> {
    const nowMs = Date.now();
    const costInt = positiveIntegerLimit(cost, 'cost');
    const maxCost = positiveIntegerLimit(policy.maxCost, 'maxCost');
    const windowMs = positiveIntegerLimit(policy.windowMs, 'windowMs');
    const key = presignRateLimitWindowKey({
      prefix: this.presignRateLimitPrefix,
      bucket,
      policy,
      nowMs,
    });
    const result = await redisEval(
      this.client,
      [
        "local current = redis.call('INCRBY', KEYS[1], ARGV[1])",
        "if current == tonumber(ARGV[1]) then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end",
        "if current > tonumber(ARGV[3]) then return 'rate_limited' end",
        "return 'ok'",
      ].join('\n'),
      [key],
      [String(costInt), String(windowMs), String(maxCost)],
    );
    return result.type === 'bulk' && result.value === 'ok'
      ? { ok: true }
      : { ok: false, code: 'rate_limited' };
  }

  async takePresignForFinalize(
    id: string,
    expectedScope: RouterAbEd25519PresignExpectedScope,
  ): Promise<RouterAbEd25519TakePresignForFinalizeResult> {
    const k = id;
    if (!k) return { ok: false, code: 'not_found' };
    const key = this.presignKey(k);
    const raw = await redisGetRaw(this.client, key);
    if (raw === null) return { ok: false, code: 'not_found' };
    const parsed = parseStoredPresignRecord(parseRawJson(raw));
    if (!parsed) return { ok: false, code: 'not_found' };
    if (Date.now() > parsed.expiresAtMs) {
      await redisEval(
        this.client,
        "redis.call('DEL', KEYS[1]); redis.call('ZREM', KEYS[2], ARGV[1]); redis.call('ZREM', KEYS[3], ARGV[1]); return nil",
        [
          key,
          this.presignWalletIndexKey(parsed.walletSigningSessionId),
          this.presignGlobalIndexKey(),
        ],
        [k],
      );
      return { ok: false, code: 'expired' };
    }
    if (!presignRecordMatchesExpectedScope(parsed, expectedScope)) {
      return { ok: false, code: 'scope_mismatch' };
    }
    const deleted = await redisEval(
      this.client,
      "local v=redis.call('GET', KEYS[1]); if v == ARGV[1] then redis.call('DEL', KEYS[1]); redis.call('ZREM', KEYS[2], ARGV[2]); redis.call('ZREM', KEYS[3], ARGV[2]); return v else return nil end",
      [
        key,
        this.presignWalletIndexKey(parsed.walletSigningSessionId),
        this.presignGlobalIndexKey(),
      ],
      [raw, k],
    );
    const deletedRaw = deleted.type === 'bulk' ? deleted.value : null;
    const deletedParsed = parseStoredPresignRecord(parseRawJson(deletedRaw));
    return deletedParsed ? { ok: true, record: deletedParsed } : { ok: false, code: 'not_found' };
  }
}

class PostgresThresholdEd25519SessionStore implements ThresholdEd25519SessionStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  private async insertOrUpdate(input: {
    kind: 'mpc' | 'signing' | 'coordinator' | 'presign' | 'presign_rate';
    sessionId: string;
    record: unknown;
    expiresAtMs: number;
  }): Promise<void> {
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO threshold_ed25519_sessions (namespace, kind, session_id, record_json, expires_at_ms)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (namespace, kind, session_id)
        DO UPDATE SET record_json = EXCLUDED.record_json, expires_at_ms = EXCLUDED.expires_at_ms
      `,
      [this.namespace, input.kind, input.sessionId, input.record, Math.floor(input.expiresAtMs)],
    );
  }

  private async takeRow(
    kind: 'mpc' | 'signing' | 'coordinator',
    sessionId: string,
  ): Promise<{ record_json?: unknown; expires_at_ms?: unknown } | null> {
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const { rows } = await pool.query(
      `
        DELETE FROM threshold_ed25519_sessions
        WHERE namespace = $1 AND kind = $2 AND session_id = $3 AND expires_at_ms > $4
        RETURNING record_json, expires_at_ms
      `,
      [this.namespace, kind, sessionId, nowMs],
    );
    return rows[0] ?? null;
  }

  private async connectForPresignTransaction(): Promise<{
    query: (text: string, values?: unknown[]) => Promise<{ rows: any[]; rowCount?: number }>;
    release: () => void;
  }> {
    const pool = await this.poolPromise;
    if (typeof pool.connect !== 'function') {
      throw new Error('Postgres threshold Ed25519 presign store requires transaction support');
    }
    return await pool.connect();
  }

  async putMpcSession(
    id: string,
    record: ThresholdEd25519MpcSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing mpcSessionId');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    const parsed = parseCurrentThresholdEd25519MpcSessionRecord(record);
    if (!parsed) throw new Error('Invalid threshold ed25519 mpc session record');
    const storedRecord = { ...parsed, expiresAtMs } satisfies ThresholdEd25519MpcSessionRecord;
    await this.insertOrUpdate({ kind: 'mpc', sessionId: k, record: storedRecord, expiresAtMs });
  }

  async readMpcSession(id: string): Promise<ThresholdEd25519ReadMpcSessionResult | null> {
    const k = id;
    if (!k) return null;
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const { rows } = await pool.query(
      `
        SELECT record_json, record_json::text AS version, expires_at_ms
        FROM threshold_ed25519_sessions
        WHERE namespace = $1 AND kind = $2 AND session_id = $3 AND expires_at_ms > $4
        LIMIT 1
      `,
      [this.namespace, 'mpc', k, nowMs],
    );
    const row = rows[0] as
      | { record_json?: unknown; version?: unknown; expires_at_ms?: unknown }
      | undefined;
    const parsed = row
      ? parseCurrentThresholdEd25519StoreSessionRow({
          kind: 'mpc',
          recordJson: row.record_json,
          expiresAtMs: row.expires_at_ms,
        })
      : null;
    const version = typeof row?.version === 'string' ? row.version : null;
    return parsed?.kind === 'mpc' && version ? { record: parsed.record, version } : null;
  }

  async claimMpcSession(
    id: string,
    version: string,
  ): Promise<ThresholdEd25519ClaimMpcSessionResult> {
    const k = id;
    if (!k) return { ok: false, code: 'not_found' };
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const { rows } = await pool.query(
      `
        DELETE FROM threshold_ed25519_sessions
        WHERE namespace = $1
          AND kind = $2
          AND session_id = $3
          AND expires_at_ms > $4
          AND record_json::text = $5
        RETURNING record_json, expires_at_ms
      `,
      [this.namespace, 'mpc', k, nowMs, version],
    );
    const row = rows[0] as { record_json?: unknown; expires_at_ms?: unknown } | undefined;
    if (!row) {
      const current = await this.readMpcSession(k);
      return current ? { ok: false, code: 'version_mismatch' } : { ok: false, code: 'not_found' };
    }
    const parsed = parseCurrentThresholdEd25519StoreSessionRow({
      kind: 'mpc',
      recordJson: row.record_json,
      expiresAtMs: row.expires_at_ms,
    });
    return parsed?.kind === 'mpc'
      ? { ok: true, record: parsed.record }
      : { ok: false, code: 'invalid_record' };
  }

  async takeMpcSession(id: string): Promise<ThresholdEd25519MpcSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const row = await this.takeRow('mpc', k);
    const parsed = row
      ? parseCurrentThresholdEd25519StoreSessionRow({
          kind: 'mpc',
          recordJson: row.record_json,
          expiresAtMs: row.expires_at_ms,
        })
      : null;
    return parsed?.kind === 'mpc' ? parsed.record : null;
  }

  async putSigningSession(
    id: string,
    record: ThresholdEd25519SigningSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing signingSessionId');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    const parsed = parseCurrentThresholdEd25519SigningSessionRecord(record);
    if (!parsed) throw new Error('Invalid threshold ed25519 signing session record');
    const storedRecord = { ...parsed, expiresAtMs } satisfies ThresholdEd25519SigningSessionRecord;
    await this.insertOrUpdate({ kind: 'signing', sessionId: k, record: storedRecord, expiresAtMs });
  }

  async takeSigningSession(id: string): Promise<ThresholdEd25519SigningSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const row = await this.takeRow('signing', k);
    const parsed = row
      ? parseCurrentThresholdEd25519StoreSessionRow({
          kind: 'signing',
          recordJson: row.record_json,
          expiresAtMs: row.expires_at_ms,
        })
      : null;
    return parsed?.kind === 'signing' ? parsed.record : null;
  }

  async putCoordinatorSigningSession(
    id: string,
    record: ThresholdEd25519CoordinatorSigningSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing coordinator signingSessionId');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    const parsed = parseCurrentThresholdEd25519CoordinatorSigningSessionRecord(record);
    if (!parsed) throw new Error('Invalid threshold ed25519 coordinator signing session record');
    const storedRecord = {
      ...parsed,
      expiresAtMs,
    } satisfies ThresholdEd25519CoordinatorSigningSessionRecord;
    await this.insertOrUpdate({
      kind: 'coordinator',
      sessionId: k,
      record: storedRecord,
      expiresAtMs,
    });
  }

  async takeCoordinatorSigningSession(
    id: string,
  ): Promise<ThresholdEd25519CoordinatorSigningSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const row = await this.takeRow('coordinator', k);
    const parsed = row
      ? parseCurrentThresholdEd25519StoreSessionRow({
          kind: 'coordinator',
          recordJson: row.record_json,
          expiresAtMs: row.expires_at_ms,
        })
      : null;
    return parsed?.kind === 'coordinator' ? parsed.record : null;
  }

  async putPresign(
    id: string,
    record: RouterAbEd25519PresignRecord,
    ttlMs: number,
  ): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing presignId');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    const parsed = parseStoredPresignRecord({ ...record, expiresAtMs });
    if (!parsed) throw new Error('Invalid Router A/B Ed25519 presign record');
    await this.insertOrUpdate({ kind: 'presign', sessionId: k, record: parsed, expiresAtMs });
  }

  async putPresignWithCapacity(
    id: string,
    record: RouterAbEd25519PresignRecord,
    ttlMs: number,
    capacity: RouterAbEd25519PresignCapacity,
  ): Promise<RouterAbEd25519PutPresignWithCapacityResult> {
    const k = id;
    if (!k) throw new Error('Missing presignId');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    const parsed = parseStoredPresignRecord({ ...record, expiresAtMs });
    if (!parsed) throw new Error('Invalid Router A/B Ed25519 presign record');
    const walletMax = positiveIntegerCapacity(
      capacity.walletSigningSessionMax,
      'walletSigningSessionMax',
    );
    const globalMax = positiveIntegerCapacity(capacity.globalMax, 'globalMax');
    const client = await this.connectForPresignTransaction();
    try {
      await client.query('BEGIN');
      await client.query('LOCK TABLE threshold_ed25519_sessions IN SHARE ROW EXCLUSIVE MODE');
      const nowMs = Date.now();
      await client.query(
        'DELETE FROM threshold_ed25519_sessions WHERE namespace = $1 AND kind = $2 AND expires_at_ms <= $3',
        [this.namespace, 'presign', nowMs],
      );
      const globalRows = await client.query(
        'SELECT COUNT(*) AS count FROM threshold_ed25519_sessions WHERE namespace = $1 AND kind = $2 AND expires_at_ms > $3',
        [this.namespace, 'presign', nowMs],
      );
      const walletRows = await client.query(
        "SELECT COUNT(*) AS count FROM threshold_ed25519_sessions WHERE namespace = $1 AND kind = $2 AND expires_at_ms > $3 AND record_json->>'walletSigningSessionId' = $4",
        [this.namespace, 'presign', nowMs, parsed.walletSigningSessionId],
      );
      const globalCount = Number(globalRows.rows[0]?.count);
      const walletCount = Number(walletRows.rows[0]?.count);
      if (
        !Number.isFinite(globalCount) ||
        !Number.isFinite(walletCount) ||
        globalCount >= globalMax ||
        walletCount >= walletMax
      ) {
        await client.query('COMMIT');
        return { ok: false, code: 'capacity_exceeded' };
      }
      await client.query(
        `
          INSERT INTO threshold_ed25519_sessions (namespace, kind, session_id, record_json, expires_at_ms)
          VALUES ($1, $2, $3, $4, $5)
          ON CONFLICT (namespace, kind, session_id)
          DO UPDATE SET record_json = EXCLUDED.record_json, expires_at_ms = EXCLUDED.expires_at_ms
        `,
        [this.namespace, 'presign', k, parsed, Math.floor(expiresAtMs)],
      );
      await client.query('COMMIT');
      return { ok: true };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async checkPresignCapacity(
    walletSigningSessionId: string,
    capacity: RouterAbEd25519PresignCapacity,
  ): Promise<RouterAbEd25519CheckPresignCapacityResult> {
    const walletId = toOptionalTrimmedString(walletSigningSessionId);
    if (!walletId) return { ok: false, code: 'capacity_exceeded' };
    const walletMax = positiveIntegerCapacity(
      capacity.walletSigningSessionMax,
      'walletSigningSessionMax',
    );
    const globalMax = positiveIntegerCapacity(capacity.globalMax, 'globalMax');
    const nowMs = Date.now();
    const pool = await this.poolPromise;
    const globalRows = await pool.query(
      'SELECT COUNT(*) AS count FROM threshold_ed25519_sessions WHERE namespace = $1 AND kind = $2 AND expires_at_ms > $3',
      [this.namespace, 'presign', nowMs],
    );
    const walletRows = await pool.query(
      "SELECT COUNT(*) AS count FROM threshold_ed25519_sessions WHERE namespace = $1 AND kind = $2 AND expires_at_ms > $3 AND record_json->>'walletSigningSessionId' = $4",
      [this.namespace, 'presign', nowMs, walletId],
    );
    const globalCount = Number(globalRows.rows[0]?.count);
    const walletCount = Number(walletRows.rows[0]?.count);
    return !Number.isFinite(globalCount) ||
      !Number.isFinite(walletCount) ||
      globalCount >= globalMax ||
      walletCount >= walletMax
      ? { ok: false, code: 'capacity_exceeded' }
      : { ok: true };
  }

  async consumePresignRefillRateLimit(
    bucket: RouterAbEd25519PresignRefillRateLimitBucket,
    policy: RouterAbEd25519PresignRefillRateLimitPolicy,
    cost: number,
  ): Promise<RouterAbEd25519ConsumePresignRefillRateLimitResult> {
    const nowMs = Date.now();
    const costInt = positiveIntegerLimit(cost, 'cost');
    const maxCost = positiveIntegerLimit(policy.maxCost, 'maxCost');
    const windowMs = positiveIntegerLimit(policy.windowMs, 'windowMs');
    const sessionId = presignRateLimitWindowKey({
      prefix: '',
      bucket,
      policy,
      nowMs,
    });
    const client = await this.connectForPresignTransaction();
    try {
      await client.query('BEGIN');
      const expiresAtMs = nowMs + windowMs;
      const { rows } = await client.query(
        `
          SELECT record_json, expires_at_ms
          FROM threshold_ed25519_sessions
          WHERE namespace = $1 AND kind = $2 AND session_id = $3
          FOR UPDATE
        `,
        [this.namespace, 'presign_rate', sessionId],
      );
      const rawCount = Number(rows[0]?.record_json?.count);
      const rawExpiresAtMs = Number(rows[0]?.expires_at_ms);
      const current =
        Number.isFinite(rawCount) && Number.isFinite(rawExpiresAtMs) && rawExpiresAtMs > nowMs
          ? rawCount
          : 0;
      const next = current + costInt;
      if (next > maxCost) {
        await client.query('COMMIT');
        return { ok: false, code: 'rate_limited' };
      }
      await client.query(
        `
          INSERT INTO threshold_ed25519_sessions (namespace, kind, session_id, record_json, expires_at_ms)
          VALUES ($1, $2, $3, $4, $5)
          ON CONFLICT (namespace, kind, session_id)
          DO UPDATE SET record_json = EXCLUDED.record_json, expires_at_ms = EXCLUDED.expires_at_ms
        `,
        [
          this.namespace,
          'presign_rate',
          sessionId,
          { kind: 'router_ab_ed25519_presign_refill_rate_limit_v2', count: next },
          Math.floor(expiresAtMs),
        ],
      );
      await client.query('COMMIT');
      return { ok: true };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async takePresignForFinalize(
    id: string,
    expectedScope: RouterAbEd25519PresignExpectedScope,
  ): Promise<RouterAbEd25519TakePresignForFinalizeResult> {
    const k = id;
    if (!k) return { ok: false, code: 'not_found' };
    const client = await this.connectForPresignTransaction();
    try {
      await client.query('BEGIN');
      const nowMs = Date.now();
      const { rows } = await client.query(
        `
          SELECT record_json, expires_at_ms
          FROM threshold_ed25519_sessions
          WHERE namespace = $1 AND kind = $2 AND session_id = $3
          FOR UPDATE
        `,
        [this.namespace, 'presign', k],
      );
      const row = rows[0] ?? null;
      if (!row) {
        await client.query('COMMIT');
        return { ok: false, code: 'not_found' };
      }
      const expiresAtMs = Number(row.expires_at_ms);
      if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) {
        await client.query(
          'DELETE FROM threshold_ed25519_sessions WHERE namespace = $1 AND kind = $2 AND session_id = $3',
          [this.namespace, 'presign', k],
        );
        await client.query('COMMIT');
        return { ok: false, code: 'expired' };
      }
      const parsed = parseStoredPresignRecord({
        ...(isObject(row.record_json) ? row.record_json : {}),
        expiresAtMs,
      });
      if (!parsed) {
        await client.query(
          'DELETE FROM threshold_ed25519_sessions WHERE namespace = $1 AND kind = $2 AND session_id = $3',
          [this.namespace, 'presign', k],
        );
        await client.query('COMMIT');
        return { ok: false, code: 'invalid_record' };
      }
      if (!presignRecordMatchesExpectedScope(parsed, expectedScope)) {
        await client.query('COMMIT');
        return { ok: false, code: 'scope_mismatch' };
      }
      await client.query(
        'DELETE FROM threshold_ed25519_sessions WHERE namespace = $1 AND kind = $2 AND session_id = $3',
        [this.namespace, 'presign', k],
      );
      await client.query('COMMIT');
      return { ok: true, record: parsed };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
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

  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix =
    toOptionalTrimmedString(config.THRESHOLD_ED25519_SESSION_PREFIX) ||
    toThresholdEd25519PrefixFromBase(basePrefix, 'sess') ||
    '';

  // Explicit config object
  const kind = toOptionalTrimmedString(config.kind);
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
  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error(
        '[threshold-ed25519] postgres session store is not supported in this runtime',
      );
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl)
      throw new Error(
        '[threshold-ed25519] postgres session store enabled but POSTGRES_URL is not set',
      );
    input.logger.info(
      '[threshold-ed25519] Using Postgres session store for signing session persistence',
    );
    return new PostgresThresholdEd25519SessionStore({
      postgresUrl,
      namespace: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }

  // Env-shaped config: prefer Redis/Upstash for session storage (TTL + lower Postgres churn).
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

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error(
        '[threshold-ed25519] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    }
    input.logger.info(
      '[threshold-ed25519] Using Postgres session store for signing session persistence',
    );
    return new PostgresThresholdEd25519SessionStore({ postgresUrl, namespace: envPrefix || '' });
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
}): ThresholdEd25519SessionStore {
  const doStores = createCloudflareDurableObjectThresholdEcdsaStores({
    config: input.config,
    logger: input.logger,
  });
  if (doStores) return doStores.sessionStore;

  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix = toThresholdEcdsaSessionPrefix(
    toOptionalTrimmedString(config.THRESHOLD_ECDSA_SESSION_PREFIX) ||
      toThresholdEcdsaPrefixFromBase(basePrefix, 'sess'),
  );

  // Explicit config object
  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error(
        '[threshold-ecdsa] In-memory session store is not supported in this runtime; configure Upstash/Redis or Durable Objects',
      );
    }
    return new InMemoryThresholdEd25519SessionStore({ keyPrefix: envPrefix });
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
          '[threshold-ecdsa] redis-tcp session store is not supported in this runtime; configure Upstash/Redis REST or Durable Objects',
        );
      }
      input.logger.warn(
        '[threshold-ecdsa] redis-tcp session store is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryThresholdEd25519SessionStore({ keyPrefix: envPrefix });
    }
    return new RedisTcpThresholdEd25519SessionStore({
      redisUrl:
        toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error('[threshold-ecdsa] postgres session store is not supported in this runtime');
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl)
      throw new Error(
        '[threshold-ecdsa] postgres session store enabled but POSTGRES_URL is not set',
      );
    input.logger.info(
      '[threshold-ecdsa] Using Postgres session store for signing session persistence',
    );
    return new PostgresThresholdEd25519SessionStore({
      postgresUrl,
      namespace: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }

  // Env-shaped config: prefer Redis/Upstash for session storage (TTL + lower Postgres churn).
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
    return new UpstashRedisRestThresholdEd25519SessionStore({
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
      return new InMemoryThresholdEd25519SessionStore({ keyPrefix: envPrefix });
    }
    input.logger.info(
      '[threshold-ecdsa] Using redis-tcp session store for signing session persistence',
    );
    return new RedisTcpThresholdEd25519SessionStore({ redisUrl, keyPrefix: envPrefix });
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error(
        '[threshold-ecdsa] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    }
    input.logger.info(
      '[threshold-ecdsa] Using Postgres session store for signing session persistence',
    );
    return new PostgresThresholdEd25519SessionStore({ postgresUrl, namespace: envPrefix });
  }

  if (requirePersistent) {
    throw new Error(
      '[threshold-ecdsa] Threshold signing sessions require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or Durable Objects',
    );
  }
  input.logger.info(
    '[threshold-ecdsa] Using in-memory session store for threshold signing sessions (non-persistent)',
  );
  return new InMemoryThresholdEd25519SessionStore({ keyPrefix: envPrefix });
}
