import type { NormalizedLogger } from '../../logger';
import type {
  EcdsaHssRoleLocalKeyRecord,
  ThresholdEd25519AuthorityScope,
  ThresholdStoreConfigInput,
} from '../../types';
import {
  RedisTcpClient,
  UpstashRedisRestClient,
  redisDel,
  redisGetJson,
  redisSetJson,
} from '../kv';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import {
  isObject,
  toThresholdEcdsaKeyPrefix,
  toThresholdEcdsaPrefixFromBase,
  toThresholdEd25519KeyPrefix,
  toThresholdEd25519PrefixFromBase,
  parseThresholdEd25519KeyRecord,
  parseEcdsaHssRoleLocalKeyRecord,
} from '../validation';
import {
  createCloudflareDurableObjectThresholdEcdsaStores,
  createCloudflareDurableObjectThresholdEd25519Stores,
} from './CloudflareDurableObjectStore';
import { readNonDurableObjectThresholdStoreKind } from './StoreConfig';

type ThresholdEcdsaSharedIdentityGuard = {
  contextKey: string;
  identityValue: string;
};
type ThresholdEcdsaStoredKeyRecord = EcdsaHssRoleLocalKeyRecord;
type ThresholdEcdsaStoredKeyRecordWithHandle = ThresholdEcdsaStoredKeyRecord & {
  keyHandle: string;
};

type ThresholdKeyStoreConfigRecord = Record<string, unknown>;

const ECDSA_SHARED_IDENTITY_CONFLICT_MESSAGE =
  '[threshold-ecdsa] EVM-family key identity already exists for wallet/rp/signing root';
const ECDSA_KEY_HANDLE_CONFLICT_MESSAGE =
  '[threshold-ecdsa] ECDSA key handle already exists in this namespace';
const ECDSA_KEY_HANDLE_INTEGRITY_MESSAGE =
  '[threshold-ecdsa] ECDSA key handle does not match threshold key identity';

const REDIS_ECDSA_SHARED_IDENTITY_PUT_SCRIPT = `
local existing = redis.call("GET", KEYS[2])
if existing and existing ~= ARGV[2] then
  return "identity_conflict"
end
local existingKeyHandle = redis.call("GET", KEYS[3])
if existingKeyHandle and existingKeyHandle ~= ARGV[3] then
  return "key_handle_conflict"
end
redis.call("SET", KEYS[1], ARGV[1])
redis.call("SET", KEYS[2], ARGV[2])
redis.call("SET", KEYS[3], ARGV[3])
return "ok"
`;

const REDIS_ECDSA_SHARED_IDENTITY_DEL_SCRIPT = `
redis.call("DEL", KEYS[1])
if redis.call("GET", KEYS[2]) == ARGV[1] then
  redis.call("DEL", KEYS[2])
end
if redis.call("GET", KEYS[3]) == ARGV[2] then
  redis.call("DEL", KEYS[3])
end
return "ok"
`;

function ecdsaIdentityPart(value: unknown): string {
  return encodeURIComponent(String(value ?? '').trim());
}

function ecdsaSigningRootVersion(record: ThresholdEcdsaStoredKeyRecord): string {
  return String(record.signingRootVersion || '').trim() || 'default';
}

async function deriveThresholdEcdsaRecordKeyHandle(
  record: ThresholdEcdsaStoredKeyRecord,
): Promise<string> {
  return String(
    await deriveThresholdEcdsaKeyHandle({
      ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
      signingRootId: record.signingRootId,
      signingRootVersion: ecdsaSigningRootVersion(record),
    }),
  );
}

async function withEcdsaHssRoleLocalRecordKeyHandle(
  record: EcdsaHssRoleLocalKeyRecord,
): Promise<EcdsaHssRoleLocalKeyRecord & { keyHandle: string }> {
  const parsed = parseEcdsaHssRoleLocalKeyRecord(record);
  if (!parsed) throw new Error('Invalid threshold-ecdsa role-local key record');
  const keyHandle = await deriveThresholdEcdsaRecordKeyHandle(parsed);
  if (parsed.keyHandle !== keyHandle) {
    throw new Error(ECDSA_KEY_HANDLE_INTEGRITY_MESSAGE);
  }
  return { ...parsed, keyHandle };
}

async function parseStoredEcdsaHssRoleLocalKeyRecord(
  raw: unknown,
): Promise<(EcdsaHssRoleLocalKeyRecord & { keyHandle: string }) | null> {
  const parsed = parseEcdsaHssRoleLocalKeyRecord(raw);
  return parsed ? await withEcdsaHssRoleLocalRecordKeyHandle(parsed) : null;
}

function thresholdEcdsaSharedIdentityGuard(
  record: ThresholdEcdsaStoredKeyRecord,
): ThresholdEcdsaSharedIdentityGuard {
  return {
    contextKey: [
      'evm-family',
      record.walletId,
      record.walletKeyId,
      record.signingRootId,
      ecdsaSigningRootVersion(record),
    ]
      .map(ecdsaIdentityPart)
      .join('|'),
    identityValue: [
      record.ecdsaThresholdKeyId,
      String(record.ethereumAddress || '')
        .trim()
        .toLowerCase(),
      record.relayerKeyId,
    ]
      .map(ecdsaIdentityPart)
      .join('|'),
  };
}

function assertNoThresholdEcdsaSharedIdentityConflict(
  incoming: ThresholdEcdsaStoredKeyRecord,
  existing: ThresholdEcdsaStoredKeyRecord,
): void {
  const incomingGuard = thresholdEcdsaSharedIdentityGuard(incoming);
  const existingGuard = thresholdEcdsaSharedIdentityGuard(existing);
  if (
    incomingGuard.contextKey === existingGuard.contextKey &&
    incomingGuard.identityValue !== existingGuard.identityValue
  ) {
    throw new Error(ECDSA_SHARED_IDENTITY_CONFLICT_MESSAGE);
  }
}

function thresholdEcdsaSharedIdentityIndexKey(
  keyPrefix: string,
  guard: ThresholdEcdsaSharedIdentityGuard,
): string {
  return `${keyPrefix}shared-identity:${guard.contextKey}`;
}

function thresholdEcdsaKeyHandleIndexKey(keyPrefix: string, keyHandle: string): string {
  return `${keyPrefix}key-handle:${ecdsaIdentityPart(keyHandle)}`;
}

async function upstashSetEcdsaRecordWithIdentityGuard(args: {
  client: UpstashRedisRestClient;
  recordKey: string;
  identityKey: string;
  keyHandleKey: string;
  record: ThresholdEcdsaStoredKeyRecord;
  identityValue: string;
  keyHandleValue: string;
}): Promise<void> {
  const result = await args.client.eval(
    REDIS_ECDSA_SHARED_IDENTITY_PUT_SCRIPT,
    [args.recordKey, args.identityKey, args.keyHandleKey],
    [JSON.stringify(args.record), args.identityValue, args.keyHandleValue],
  );
  if (String(result || '') === 'identity_conflict') {
    throw new Error(ECDSA_SHARED_IDENTITY_CONFLICT_MESSAGE);
  }
  if (String(result || '') === 'key_handle_conflict') {
    throw new Error(ECDSA_KEY_HANDLE_CONFLICT_MESSAGE);
  }
}

async function upstashDeleteEcdsaRecordWithIdentityGuard(args: {
  client: UpstashRedisRestClient;
  recordKey: string;
  identityKey: string;
  keyHandleKey: string;
  identityValue: string;
  keyHandleValue: string;
}): Promise<void> {
  await args.client.eval(
    REDIS_ECDSA_SHARED_IDENTITY_DEL_SCRIPT,
    [args.recordKey, args.identityKey, args.keyHandleKey],
    [args.identityValue, args.keyHandleValue],
  );
}

async function redisSetEcdsaRecordWithIdentityGuard(args: {
  client: RedisTcpClient;
  recordKey: string;
  identityKey: string;
  keyHandleKey: string;
  record: ThresholdEcdsaStoredKeyRecord;
  identityValue: string;
  keyHandleValue: string;
}): Promise<void> {
  const resp = await args.client.send([
    'EVAL',
    REDIS_ECDSA_SHARED_IDENTITY_PUT_SCRIPT,
    '3',
    args.recordKey,
    args.identityKey,
    args.keyHandleKey,
    JSON.stringify(args.record),
    args.identityValue,
    args.keyHandleValue,
  ]);
  if (resp.type === 'error') throw new Error(`Redis EVAL error: ${resp.value}`);
  const result = resp.type === 'bulk' || resp.type === 'simple' ? resp.value : '';
  if (result === 'identity_conflict') {
    throw new Error(ECDSA_SHARED_IDENTITY_CONFLICT_MESSAGE);
  }
  if (result === 'key_handle_conflict') {
    throw new Error(ECDSA_KEY_HANDLE_CONFLICT_MESSAGE);
  }
}

async function redisDeleteEcdsaRecordWithIdentityGuard(args: {
  client: RedisTcpClient;
  recordKey: string;
  identityKey: string;
  keyHandleKey: string;
  identityValue: string;
  keyHandleValue: string;
}): Promise<void> {
  const resp = await args.client.send([
    'EVAL',
    REDIS_ECDSA_SHARED_IDENTITY_DEL_SCRIPT,
    '3',
    args.recordKey,
    args.identityKey,
    args.keyHandleKey,
    args.identityValue,
    args.keyHandleValue,
  ]);
  if (resp.type === 'error') throw new Error(`Redis EVAL error: ${resp.value}`);
}

async function redisGetString(client: RedisTcpClient, key: string): Promise<string | null> {
  const resp = await client.send(['GET', key]);
  if (resp.type === 'bulk' || resp.type === 'simple') return toOptionalTrimmedString(resp.value);
  if (resp.type === 'error') throw new Error(`Redis GET error: ${resp.value}`);
  return null;
}

export type ThresholdEd25519KeyRecord = {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  authorityScope: ThresholdEd25519AuthorityScope;
  publicKey: string;
  relayerSigningShareB64u: string;
  relayerVerifyingShareB64u: string;
  keyVersion: string;
  recoveryExportCapable: true;
};

export interface ThresholdEd25519KeyStore {
  get(relayerKeyId: string): Promise<ThresholdEd25519KeyRecord | null>;
  put(relayerKeyId: string, record: ThresholdEd25519KeyRecord): Promise<void>;
  del(relayerKeyId: string): Promise<void>;
}

export interface ThresholdEcdsaIntegratedKeyStore {
  getRoleLocalByKeyHandle(keyHandle: string): Promise<EcdsaHssRoleLocalKeyRecord | null>;
  putRoleLocalByKeyHandle(record: EcdsaHssRoleLocalKeyRecord): Promise<void>;
  deleteByKeyHandle(keyHandle: string): Promise<void>;
}

class InMemoryThresholdEd25519KeyStore implements ThresholdEd25519KeyStore {
  private readonly map = new Map<string, ThresholdEd25519KeyRecord>();

  async get(relayerKeyId: string): Promise<ThresholdEd25519KeyRecord | null> {
    const id = relayerKeyId;
    if (!id) return null;
    return this.map.get(id) || null;
  }

  async put(relayerKeyId: string, record: ThresholdEd25519KeyRecord): Promise<void> {
    const id = relayerKeyId;
    if (!id) throw new Error('Missing relayerKeyId');
    this.map.set(id, record);
  }

  async del(relayerKeyId: string): Promise<void> {
    const id = relayerKeyId;
    if (!id) return;
    this.map.delete(id);
  }
}

class UpstashRedisRestThresholdEd25519KeyStore implements ThresholdEd25519KeyStore {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;

  constructor(input: { url: string; token: string; keyPrefix?: string }) {
    const url = toOptionalTrimmedString(input.url);
    const token = toOptionalTrimmedString(input.token);
    if (!url) throw new Error('Upstash key store missing url');
    if (!token) throw new Error('Upstash key store missing token');
    this.client = new UpstashRedisRestClient({ url, token });
    this.keyPrefix = toThresholdEd25519KeyPrefix(input.keyPrefix);
  }

  private key(relayerKeyId: string): string {
    return `${this.keyPrefix}${relayerKeyId}`;
  }

  async get(relayerKeyId: string): Promise<ThresholdEd25519KeyRecord | null> {
    const id = relayerKeyId;
    if (!id) return null;
    const raw = await this.client.getJson(this.key(id));
    return parseThresholdEd25519KeyRecord(raw);
  }

  async put(relayerKeyId: string, record: ThresholdEd25519KeyRecord): Promise<void> {
    const id = relayerKeyId;
    if (!id) throw new Error('Missing relayerKeyId');
    await this.client.setJson(this.key(id), record);
  }

  async del(relayerKeyId: string): Promise<void> {
    const id = relayerKeyId;
    if (!id) return;
    await this.client.del(this.key(id));
  }
}

class RedisTcpThresholdEd25519KeyStore implements ThresholdEd25519KeyStore {
  private readonly keyPrefix: string;
  private readonly client: RedisTcpClient;

  constructor(input: { redisUrl: string; keyPrefix?: string }) {
    const url = toOptionalTrimmedString(input.redisUrl);
    if (!url) throw new Error('redis-tcp key store missing redisUrl');
    this.client = new RedisTcpClient(url);
    this.keyPrefix = toThresholdEd25519KeyPrefix(input.keyPrefix);
  }

  private key(relayerKeyId: string): string {
    return `${this.keyPrefix}${relayerKeyId}`;
  }

  async get(relayerKeyId: string): Promise<ThresholdEd25519KeyRecord | null> {
    const id = relayerKeyId;
    if (!id) return null;
    const raw = await redisGetJson(this.client, this.key(id));
    return parseThresholdEd25519KeyRecord(raw);
  }

  async put(relayerKeyId: string, record: ThresholdEd25519KeyRecord): Promise<void> {
    const id = relayerKeyId;
    if (!id) throw new Error('Missing relayerKeyId');
    await redisSetJson(this.client, this.key(id), record);
  }

  async del(relayerKeyId: string): Promise<void> {
    const id = relayerKeyId;
    if (!id) return;
    await redisDel(this.client, this.key(id));
  }
}

class InMemoryThresholdEcdsaIntegratedKeyStore implements ThresholdEcdsaIntegratedKeyStore {
  private readonly recordsByKeyHandle = new Map<string, ThresholdEcdsaStoredKeyRecord>();
  private readonly namespace: string;

  constructor(input?: { namespace?: string }) {
    this.namespace = toOptionalTrimmedString(input?.namespace) || 'default';
  }

  private key(keyHandle: string): string {
    return `${this.namespace}:${keyHandle}`;
  }

  async getRoleLocalByKeyHandle(keyHandle: string): Promise<EcdsaHssRoleLocalKeyRecord | null> {
    const handle = toOptionalTrimmedString(keyHandle);
    if (!handle) return null;
    return await parseStoredEcdsaHssRoleLocalKeyRecord(
      this.recordsByKeyHandle.get(this.key(handle)),
    );
  }

  async putRoleLocalByKeyHandle(record: EcdsaHssRoleLocalKeyRecord): Promise<void> {
    const parsed = await withEcdsaHssRoleLocalRecordKeyHandle(record);
    const mapKey = this.key(parsed.keyHandle);
    for (const [storedKey, storedRecord] of this.recordsByKeyHandle.entries()) {
      if (storedKey === mapKey) continue;
      const existing = await parseStoredEcdsaHssRoleLocalKeyRecord(storedRecord);
      if (!existing) continue;
      if (existing.ecdsaThresholdKeyId === parsed.ecdsaThresholdKeyId) continue;
      if (existing.keyHandle === parsed.keyHandle) {
        throw new Error(ECDSA_KEY_HANDLE_CONFLICT_MESSAGE);
      }
      assertNoThresholdEcdsaSharedIdentityConflict(parsed, existing);
    }
    for (const [storedKey, storedRecord] of this.recordsByKeyHandle.entries()) {
      const existing = await parseStoredEcdsaHssRoleLocalKeyRecord(storedRecord);
      if (existing?.ecdsaThresholdKeyId === parsed.ecdsaThresholdKeyId && storedKey !== mapKey) {
        this.recordsByKeyHandle.delete(storedKey);
      }
    }
    this.recordsByKeyHandle.set(mapKey, parsed);
  }

  async deleteByKeyHandle(keyHandle: string): Promise<void> {
    const handle = toOptionalTrimmedString(keyHandle);
    if (!handle) return;
    this.recordsByKeyHandle.delete(this.key(handle));
  }
}

class UpstashRedisRestThresholdEcdsaIntegratedKeyStore implements ThresholdEcdsaIntegratedKeyStore {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;

  constructor(input: { url: string; token: string; keyPrefix?: string }) {
    const url = toOptionalTrimmedString(input.url);
    const token = toOptionalTrimmedString(input.token);
    if (!url) throw new Error('Upstash key store missing url');
    if (!token) throw new Error('Upstash key store missing token');
    this.client = new UpstashRedisRestClient({ url, token });
    this.keyPrefix = toThresholdEcdsaKeyPrefix(input.keyPrefix);
  }

  private recordKey(keyHandle: string): string {
    return `${this.keyPrefix}${keyHandle}`;
  }

  async getRoleLocalByKeyHandle(keyHandle: string): Promise<EcdsaHssRoleLocalKeyRecord | null> {
    const handle = toOptionalTrimmedString(keyHandle);
    if (!handle) return null;
    const direct = await parseStoredEcdsaHssRoleLocalKeyRecord(
      await this.client.getJson(this.recordKey(handle)),
    );
    if (direct) {
      if (direct.keyHandle !== handle) throw new Error(ECDSA_KEY_HANDLE_INTEGRITY_MESSAGE);
      return direct;
    }
    const recordKey = toOptionalTrimmedString(
      await this.client.getRaw(thresholdEcdsaKeyHandleIndexKey(this.keyPrefix, handle)),
    );
    if (!recordKey) return null;
    return await parseStoredEcdsaHssRoleLocalKeyRecord(await this.client.getJson(recordKey));
  }

  async putRoleLocalByKeyHandle(record: EcdsaHssRoleLocalKeyRecord): Promise<void> {
    const parsed = await withEcdsaHssRoleLocalRecordKeyHandle(record);
    const guard = thresholdEcdsaSharedIdentityGuard(parsed);
    const recordKey = this.recordKey(parsed.keyHandle);
    await upstashSetEcdsaRecordWithIdentityGuard({
      client: this.client,
      recordKey,
      identityKey: thresholdEcdsaSharedIdentityIndexKey(this.keyPrefix, guard),
      keyHandleKey: thresholdEcdsaKeyHandleIndexKey(this.keyPrefix, parsed.keyHandle),
      record: parsed,
      identityValue: guard.identityValue,
      keyHandleValue: recordKey,
    });
  }

  async deleteByKeyHandle(keyHandle: string): Promise<void> {
    const handle = toOptionalTrimmedString(keyHandle);
    if (!handle) return;
    const keyHandleKey = thresholdEcdsaKeyHandleIndexKey(this.keyPrefix, handle);
    const canonicalRecordKey = this.recordKey(handle);
    const canonicalRecord = await parseStoredEcdsaHssRoleLocalKeyRecord(
      await this.client.getJson(canonicalRecordKey),
    );
    const recordKey = canonicalRecord
      ? canonicalRecordKey
      : toOptionalTrimmedString(await this.client.getRaw(keyHandleKey));
    if (!recordKey) {
      await this.client.del(canonicalRecordKey);
      return;
    }
    const record =
      canonicalRecord ||
      (await parseStoredEcdsaHssRoleLocalKeyRecord(await this.client.getJson(recordKey)));
    if (!record) {
      await this.client.del(keyHandleKey);
      await this.client.del(canonicalRecordKey);
      return;
    }
    const guard = thresholdEcdsaSharedIdentityGuard(record);
    await upstashDeleteEcdsaRecordWithIdentityGuard({
      client: this.client,
      recordKey,
      identityKey: thresholdEcdsaSharedIdentityIndexKey(this.keyPrefix, guard),
      keyHandleKey,
      identityValue: guard.identityValue,
      keyHandleValue: recordKey,
    });
  }
}

class RedisTcpThresholdEcdsaIntegratedKeyStore implements ThresholdEcdsaIntegratedKeyStore {
  private readonly keyPrefix: string;
  private readonly client: RedisTcpClient;

  constructor(input: { redisUrl: string; keyPrefix?: string }) {
    const url = toOptionalTrimmedString(input.redisUrl);
    if (!url) throw new Error('redis-tcp key store missing redisUrl');
    this.client = new RedisTcpClient(url);
    this.keyPrefix = toThresholdEcdsaKeyPrefix(input.keyPrefix);
  }

  private recordKey(keyHandle: string): string {
    return `${this.keyPrefix}${keyHandle}`;
  }

  async getRoleLocalByKeyHandle(keyHandle: string): Promise<EcdsaHssRoleLocalKeyRecord | null> {
    const handle = toOptionalTrimmedString(keyHandle);
    if (!handle) return null;
    const direct = await parseStoredEcdsaHssRoleLocalKeyRecord(
      await redisGetJson(this.client, this.recordKey(handle)),
    );
    if (direct) {
      if (direct.keyHandle !== handle) throw new Error(ECDSA_KEY_HANDLE_INTEGRITY_MESSAGE);
      return direct;
    }
    const recordKey = await redisGetString(
      this.client,
      thresholdEcdsaKeyHandleIndexKey(this.keyPrefix, handle),
    );
    if (!recordKey) return null;
    return await parseStoredEcdsaHssRoleLocalKeyRecord(await redisGetJson(this.client, recordKey));
  }

  async putRoleLocalByKeyHandle(record: EcdsaHssRoleLocalKeyRecord): Promise<void> {
    const parsed = await withEcdsaHssRoleLocalRecordKeyHandle(record);
    const guard = thresholdEcdsaSharedIdentityGuard(parsed);
    const recordKey = this.recordKey(parsed.keyHandle);
    await redisSetEcdsaRecordWithIdentityGuard({
      client: this.client,
      recordKey,
      identityKey: thresholdEcdsaSharedIdentityIndexKey(this.keyPrefix, guard),
      keyHandleKey: thresholdEcdsaKeyHandleIndexKey(this.keyPrefix, parsed.keyHandle),
      record: parsed,
      identityValue: guard.identityValue,
      keyHandleValue: recordKey,
    });
  }

  async deleteByKeyHandle(keyHandle: string): Promise<void> {
    const handle = toOptionalTrimmedString(keyHandle);
    if (!handle) return;
    const keyHandleKey = thresholdEcdsaKeyHandleIndexKey(this.keyPrefix, handle);
    const canonicalRecordKey = this.recordKey(handle);
    const canonicalRecord = await parseStoredEcdsaHssRoleLocalKeyRecord(
      await redisGetJson(this.client, canonicalRecordKey),
    );
    const recordKey = canonicalRecord
      ? canonicalRecordKey
      : await redisGetString(this.client, keyHandleKey);
    if (!recordKey) {
      await redisDel(this.client, canonicalRecordKey);
      return;
    }
    const record =
      canonicalRecord ||
      (await parseStoredEcdsaHssRoleLocalKeyRecord(await redisGetJson(this.client, recordKey)));
    if (!record) {
      await redisDel(this.client, keyHandleKey);
      await redisDel(this.client, canonicalRecordKey);
      return;
    }
    const guard = thresholdEcdsaSharedIdentityGuard(record);
    await redisDeleteEcdsaRecordWithIdentityGuard({
      client: this.client,
      recordKey,
      identityKey: thresholdEcdsaSharedIdentityIndexKey(this.keyPrefix, guard),
      keyHandleKey,
      identityValue: guard.identityValue,
      keyHandleValue: recordKey,
    });
  }
}

export function createThresholdEd25519KeyStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): ThresholdEd25519KeyStore {
  const doStores = createCloudflareDurableObjectThresholdEd25519Stores({
    config: input.config,
    logger: input.logger,
  });
  if (doStores) return doStores.keyStore;

  const config = (isObject(input.config) ? input.config : {}) as ThresholdKeyStoreConfigRecord;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix =
    toOptionalTrimmedString(config.THRESHOLD_ED25519_KEYSTORE_PREFIX) ||
    toThresholdEd25519PrefixFromBase(basePrefix, 'key') ||
    '';

  // Explicit config object
  const kind = readNonDurableObjectThresholdStoreKind(config, 'threshold-ed25519');
  if (kind === 'in-memory') return new InMemoryThresholdEd25519KeyStore();
  if (kind === 'upstash-redis-rest') {
    return new UpstashRedisRestThresholdEd25519KeyStore({
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
      input.logger.warn(
        '[threshold-ed25519] redis-tcp key store is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryThresholdEd25519KeyStore();
    }
    return new RedisTcpThresholdEd25519KeyStore({
      redisUrl:
        toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }

  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        'Upstash key store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set',
      );
    }
    input.logger.info(
      '[threshold-ed25519] Using Upstash REST key store for relayer signing share persistence',
    );
    return new UpstashRedisRestThresholdEd25519KeyStore({
      url: upstashUrl,
      token: upstashToken,
      keyPrefix: envPrefix || undefined,
    });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      input.logger.warn(
        '[threshold-ed25519] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryThresholdEd25519KeyStore();
    }
    input.logger.info(
      '[threshold-ed25519] Using redis-tcp key store for relayer signing share persistence',
    );
    return new RedisTcpThresholdEd25519KeyStore({ redisUrl, keyPrefix: envPrefix || undefined });
  }

  input.logger.info(
    '[threshold-ed25519] Using in-memory key store for relayer signing share (non-persistent)',
  );
  return new InMemoryThresholdEd25519KeyStore();
}

export function createThresholdEcdsaKeyStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): ThresholdEcdsaIntegratedKeyStore {
  const doStores = createCloudflareDurableObjectThresholdEcdsaStores({
    config: input.config,
    logger: input.logger,
  });
  if (doStores) return doStores.keyStore;

  const config = (isObject(input.config) ? input.config : {}) as ThresholdKeyStoreConfigRecord;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix = toThresholdEcdsaKeyPrefix(
    toOptionalTrimmedString(config.THRESHOLD_ECDSA_KEYSTORE_PREFIX) ||
      toThresholdEcdsaPrefixFromBase(basePrefix, 'key'),
  );

  // Explicit config object
  const kind = readNonDurableObjectThresholdStoreKind(config, 'threshold-ecdsa');
  if (kind === 'in-memory') {
    return new InMemoryThresholdEcdsaIntegratedKeyStore({
      namespace: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'upstash-redis-rest') {
    return new UpstashRedisRestThresholdEcdsaIntegratedKeyStore({
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
      input.logger.warn(
        '[threshold-ecdsa] redis-tcp key store is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryThresholdEcdsaIntegratedKeyStore({
        namespace: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
      });
    }
    return new RedisTcpThresholdEcdsaIntegratedKeyStore({
      redisUrl:
        toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }

  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        'Upstash key store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set',
      );
    }
    input.logger.info(
      '[threshold-ecdsa] Using Upstash REST key store for integrated key persistence',
    );
    return new UpstashRedisRestThresholdEcdsaIntegratedKeyStore({
      url: upstashUrl,
      token: upstashToken,
      keyPrefix: envPrefix,
    });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      input.logger.warn(
        '[threshold-ecdsa] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryThresholdEcdsaIntegratedKeyStore({ namespace: envPrefix || undefined });
    }
    input.logger.info('[threshold-ecdsa] Using redis-tcp key store for integrated key persistence');
    return new RedisTcpThresholdEcdsaIntegratedKeyStore({ redisUrl, keyPrefix: envPrefix });
  }

  input.logger.info(
    '[threshold-ecdsa] Using in-memory key store for integrated ECDSA key records (non-persistent)',
  );
  return new InMemoryThresholdEcdsaIntegratedKeyStore({ namespace: envPrefix || undefined });
}
