import type { NormalizedLogger } from '../../logger';
import type {
  ThresholdEcdsaIntegratedKeyRecord,
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
import { getPostgresPool, getPostgresUrlFromConfig } from '../../../storage/postgres';
import {
  isObject,
  toThresholdEcdsaKeyPrefix,
  toThresholdEcdsaPrefixFromBase,
  toThresholdEd25519KeyPrefix,
  toThresholdEd25519PrefixFromBase,
  parseThresholdEcdsaIntegratedKeyRecord,
  parseThresholdEd25519KeyRecord,
} from '../validation';
import {
  createCloudflareDurableObjectThresholdEcdsaStores,
  createCloudflareDurableObjectThresholdEd25519Stores,
} from './CloudflareDurableObjectStore';

export type ThresholdEd25519KeyRecord = {
  nearAccountId: string;
  rpId: string;
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
  get(ecdsaThresholdKeyId: string): Promise<ThresholdEcdsaIntegratedKeyRecord | null>;
  put(
    ecdsaThresholdKeyId: string,
    record: ThresholdEcdsaIntegratedKeyRecord,
  ): Promise<void>;
  del(ecdsaThresholdKeyId: string): Promise<void>;
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

class PostgresThresholdEd25519KeyStore implements ThresholdEd25519KeyStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async get(relayerKeyId: string): Promise<ThresholdEd25519KeyRecord | null> {
    const id = relayerKeyId;
    if (!id) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      'SELECT record_json FROM threshold_ed25519_keys WHERE namespace = $1 AND relayer_key_id = $2 LIMIT 1',
      [this.namespace, id],
    );
    return parseThresholdEd25519KeyRecord(rows[0]?.record_json);
  }

  async put(relayerKeyId: string, record: ThresholdEd25519KeyRecord): Promise<void> {
    const id = relayerKeyId;
    if (!id) throw new Error('Missing relayerKeyId');
    const parsed = parseThresholdEd25519KeyRecord(record);
    if (!parsed) throw new Error('Invalid threshold key record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO threshold_ed25519_keys (namespace, relayer_key_id, record_json)
        VALUES ($1, $2, $3)
        ON CONFLICT (namespace, relayer_key_id)
        DO UPDATE SET record_json = EXCLUDED.record_json
      `,
      [this.namespace, id, parsed],
    );
  }

  async del(relayerKeyId: string): Promise<void> {
    const id = relayerKeyId;
    if (!id) return;
    const pool = await this.poolPromise;
    await pool.query(
      'DELETE FROM threshold_ed25519_keys WHERE namespace = $1 AND relayer_key_id = $2',
      [this.namespace, id],
    );
  }
}

class InMemoryThresholdEcdsaIntegratedKeyStore implements ThresholdEcdsaIntegratedKeyStore {
  private readonly map = new Map<string, ThresholdEcdsaIntegratedKeyRecord>();

  async get(ecdsaThresholdKeyId: string): Promise<ThresholdEcdsaIntegratedKeyRecord | null> {
    const id = ecdsaThresholdKeyId;
    if (!id) return null;
    return this.map.get(id) || null;
  }

  async put(
    ecdsaThresholdKeyId: string,
    record: ThresholdEcdsaIntegratedKeyRecord,
  ): Promise<void> {
    const id = ecdsaThresholdKeyId;
    if (!id) throw new Error('Missing ecdsaThresholdKeyId');
    this.map.set(id, record);
  }

  async del(ecdsaThresholdKeyId: string): Promise<void> {
    const id = ecdsaThresholdKeyId;
    if (!id) return;
    this.map.delete(id);
  }
}

class UpstashRedisRestThresholdEcdsaIntegratedKeyStore
  implements ThresholdEcdsaIntegratedKeyStore
{
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

  private key(ecdsaThresholdKeyId: string): string {
    return `${this.keyPrefix}${ecdsaThresholdKeyId}`;
  }

  async get(ecdsaThresholdKeyId: string): Promise<ThresholdEcdsaIntegratedKeyRecord | null> {
    const id = ecdsaThresholdKeyId;
    if (!id) return null;
    const raw = await this.client.getJson(this.key(id));
    return parseThresholdEcdsaIntegratedKeyRecord(raw);
  }

  async put(
    ecdsaThresholdKeyId: string,
    record: ThresholdEcdsaIntegratedKeyRecord,
  ): Promise<void> {
    const id = ecdsaThresholdKeyId;
    if (!id) throw new Error('Missing ecdsaThresholdKeyId');
    await this.client.setJson(this.key(id), record);
  }

  async del(ecdsaThresholdKeyId: string): Promise<void> {
    const id = ecdsaThresholdKeyId;
    if (!id) return;
    await this.client.del(this.key(id));
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

  private key(ecdsaThresholdKeyId: string): string {
    return `${this.keyPrefix}${ecdsaThresholdKeyId}`;
  }

  async get(ecdsaThresholdKeyId: string): Promise<ThresholdEcdsaIntegratedKeyRecord | null> {
    const id = ecdsaThresholdKeyId;
    if (!id) return null;
    const raw = await redisGetJson(this.client, this.key(id));
    return parseThresholdEcdsaIntegratedKeyRecord(raw);
  }

  async put(
    ecdsaThresholdKeyId: string,
    record: ThresholdEcdsaIntegratedKeyRecord,
  ): Promise<void> {
    const id = ecdsaThresholdKeyId;
    if (!id) throw new Error('Missing ecdsaThresholdKeyId');
    await redisSetJson(this.client, this.key(id), record);
  }

  async del(ecdsaThresholdKeyId: string): Promise<void> {
    const id = ecdsaThresholdKeyId;
    if (!id) return;
    await redisDel(this.client, this.key(id));
  }
}

class PostgresThresholdEcdsaIntegratedKeyStore implements ThresholdEcdsaIntegratedKeyStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;
  private ensureTablePromise: Promise<void> | null = null;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  private async ensureTable(): Promise<void> {
    if (!this.ensureTablePromise) {
      this.ensureTablePromise = (async () => {
        const pool = await this.poolPromise;
        await pool.query(`
          CREATE TABLE IF NOT EXISTS threshold_ecdsa_keys (
            namespace TEXT NOT NULL,
            relayer_key_id TEXT NOT NULL,
            record_json JSONB NOT NULL,
            PRIMARY KEY (namespace, relayer_key_id)
          )
        `);
      })().catch((error) => {
        this.ensureTablePromise = null;
        throw error;
      });
    }
    await this.ensureTablePromise;
  }

  async get(ecdsaThresholdKeyId: string): Promise<ThresholdEcdsaIntegratedKeyRecord | null> {
    const id = ecdsaThresholdKeyId;
    if (!id) return null;
    await this.ensureTable();
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      'SELECT record_json FROM threshold_ecdsa_keys WHERE namespace = $1 AND relayer_key_id = $2 LIMIT 1',
      [this.namespace, id],
    );
    return parseThresholdEcdsaIntegratedKeyRecord(rows[0]?.record_json);
  }

  async put(
    ecdsaThresholdKeyId: string,
    record: ThresholdEcdsaIntegratedKeyRecord,
  ): Promise<void> {
    const id = ecdsaThresholdKeyId;
    if (!id) throw new Error('Missing ecdsaThresholdKeyId');
    const parsed = parseThresholdEcdsaIntegratedKeyRecord(record);
    if (!parsed) throw new Error('Invalid threshold-ecdsa integrated key record');
    await this.ensureTable();
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO threshold_ecdsa_keys (namespace, relayer_key_id, record_json)
        VALUES ($1, $2, $3)
        ON CONFLICT (namespace, relayer_key_id)
        DO UPDATE SET record_json = EXCLUDED.record_json
      `,
      [this.namespace, id, parsed],
    );
  }

  async del(ecdsaThresholdKeyId: string): Promise<void> {
    const id = ecdsaThresholdKeyId;
    if (!id) return;
    await this.ensureTable();
    const pool = await this.poolPromise;
    await pool.query(
      'DELETE FROM threshold_ecdsa_keys WHERE namespace = $1 AND relayer_key_id = $2',
      [this.namespace, id],
    );
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

  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix =
    toOptionalTrimmedString(config.THRESHOLD_ED25519_KEYSTORE_PREFIX) ||
    toThresholdEd25519PrefixFromBase(basePrefix, 'key') ||
    '';

  // Explicit config object
  const kind = toOptionalTrimmedString(config.kind);
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
  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error('[threshold-ed25519] postgres key store is not supported in this runtime');
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl)
      throw new Error('[threshold-ed25519] postgres key store enabled but POSTGRES_URL is not set');
    input.logger.info(
      '[threshold-ed25519] Using Postgres key store for relayer signing share persistence',
    );
    return new PostgresThresholdEd25519KeyStore({
      postgresUrl,
      namespace: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }

  // Env-shaped config
  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error(
        '[threshold-ed25519] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    }
    input.logger.info(
      '[threshold-ed25519] Using Postgres key store for relayer signing share persistence',
    );
    return new PostgresThresholdEd25519KeyStore({ postgresUrl, namespace: envPrefix || '' });
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

  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix = toThresholdEcdsaKeyPrefix(
    toOptionalTrimmedString(config.THRESHOLD_ECDSA_KEYSTORE_PREFIX) ||
      toThresholdEcdsaPrefixFromBase(basePrefix, 'key'),
  );

  // Explicit config object
  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'in-memory') return new InMemoryThresholdEcdsaIntegratedKeyStore();
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
      return new InMemoryThresholdEcdsaIntegratedKeyStore();
    }
    return new RedisTcpThresholdEcdsaIntegratedKeyStore({
      redisUrl:
        toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error('[threshold-ecdsa] postgres key store is not supported in this runtime');
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl)
      throw new Error('[threshold-ecdsa] postgres key store enabled but POSTGRES_URL is not set');
    input.logger.info(
      '[threshold-ecdsa] Using Postgres key store for integrated key persistence',
    );
    return new PostgresThresholdEcdsaIntegratedKeyStore({
      postgresUrl,
      namespace: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }

  // Env-shaped config
  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error(
        '[threshold-ecdsa] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    }
    input.logger.info(
      '[threshold-ecdsa] Using Postgres key store for integrated key persistence',
    );
    return new PostgresThresholdEcdsaIntegratedKeyStore({ postgresUrl, namespace: envPrefix });
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
      return new InMemoryThresholdEcdsaIntegratedKeyStore();
    }
    input.logger.info(
      '[threshold-ecdsa] Using redis-tcp key store for integrated key persistence',
    );
    return new RedisTcpThresholdEcdsaIntegratedKeyStore({ redisUrl, keyPrefix: envPrefix });
  }

  input.logger.info(
    '[threshold-ecdsa] Using in-memory key store for integrated ECDSA key records (non-persistent)',
  );
  return new InMemoryThresholdEcdsaIntegratedKeyStore();
}
