import type {
  CloudflareDurableObjectNamespaceLike,
  ThresholdStoreConfigInput,
} from './types';
import {
  THRESHOLD_DO_OBJECT_NAME_DEFAULT,
  THRESHOLD_PREFIX_DEFAULT,
} from './defaultConfigsServer';
import type { NormalizedLogger } from './logger';
import {
  getPostgresPool,
  getPostgresUrlFromConfig,
  type PgQueryExecutor,
} from '../storage/postgres';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  walletIdFromString,
  type WalletAuthMethodRecord as SharedWalletAuthMethodRecord,
} from '@shared/utils/registrationIntent';

export type WalletAuthMethodRecord = SharedWalletAuthMethodRecord;

export interface WalletAuthMethodStore {
  put(record: WalletAuthMethodRecord): Promise<void>;
  getPasskey(input: {
    rpId: string;
    credentialIdB64u: string;
  }): Promise<WalletAuthMethodRecord | null>;
  getEmailOtp(input: {
    walletId: string;
    rpId: string;
    emailHashHex: string;
  }): Promise<WalletAuthMethodRecord | null>;
  listForWallet(input: {
    walletId: string;
    rpId: string;
  }): Promise<WalletAuthMethodRecord[]>;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function trimString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function toPrefixWithColon(prefix: unknown, defaultPrefix: string): string {
  const p = toOptionalTrimmedString(prefix);
  if (!p) return defaultPrefix;
  return p.endsWith(':') ? p : `${p}:`;
}

function walletAuthMethodId(record: WalletAuthMethodRecord): string {
  return record.kind === 'passkey'
    ? `passkey:${record.rpId}:${record.credentialIdB64u}`
    : `email_otp:${record.walletId}:${record.rpId}:${record.emailHashHex}`;
}

export function resolveWalletAuthMethodStoreNamespace(
  config: Record<string, unknown>,
): string {
  const explicit = toOptionalTrimmedString(config.WALLET_AUTH_METHOD_PREFIX);
  if (explicit) return toPrefixWithColon(explicit, '');
  const base = toOptionalTrimmedString(config.THRESHOLD_PREFIX) || THRESHOLD_PREFIX_DEFAULT;
  return `${toPrefixWithColon(base, `${THRESHOLD_PREFIX_DEFAULT}:`)}wallet-auth-method:`;
}

export function normalizeWalletAuthMethod(
  raw: unknown,
): WalletAuthMethodRecord | null {
  if (!isObject(raw)) return null;
  const version = trimString(raw.version);
  const kind = trimString(raw.kind);
  const status = trimString(raw.status);
  const walletId = walletIdFromString(trimString(raw.walletId));
  const rpId = trimString(raw.rpId);
  const createdAtMs = Math.floor(Number(raw.createdAtMs));
  const updatedAtMs = Math.floor(Number(raw.updatedAtMs));
  if (
    version !== 'wallet_auth_method_v1' ||
    (kind !== 'passkey' && kind !== 'email_otp') ||
    (status !== 'active' && status !== 'revoked') ||
    !walletId ||
    !rpId ||
    !Number.isSafeInteger(createdAtMs) ||
    !Number.isSafeInteger(updatedAtMs)
  ) {
    return null;
  }
  if (kind === 'passkey') {
    const credentialIdB64u = trimString(raw.credentialIdB64u);
    const credentialPublicKeyB64u = trimString(raw.credentialPublicKeyB64u);
    const counter = Math.floor(Number(raw.counter));
    if (!credentialIdB64u || !credentialPublicKeyB64u || !Number.isSafeInteger(counter)) {
      return null;
    }
    return {
      version: 'wallet_auth_method_v1',
      kind: 'passkey',
      status,
      walletId,
      rpId,
      credentialIdB64u,
      credentialPublicKeyB64u,
      counter,
      createdAtMs,
      updatedAtMs,
    };
  }
  const emailHashHex = trimString(raw.emailHashHex);
  const registrationAuthorityId = trimString(raw.registrationAuthorityId);
  if (!emailHashHex || !registrationAuthorityId) return null;
  return {
    version: 'wallet_auth_method_v1',
    kind: 'email_otp',
    status,
    walletId,
    rpId,
    emailHashHex,
    registrationAuthorityId,
    createdAtMs,
    updatedAtMs,
  };
}

export async function putWalletAuthMethodWithExecutor(input: {
  executor: PgQueryExecutor;
  namespace: string;
  record: WalletAuthMethodRecord;
}): Promise<void> {
  const { record } = input;
  await input.executor.query(
    `
      INSERT INTO wallet_auth_methods
        (
          namespace,
          wallet_id,
          rp_id,
          kind,
          status,
          wallet_auth_method_id,
          auth_identifier_key,
          credential_id_b64u,
          credential_public_key_b64u,
          signer_slot,
          email_hash_hex,
          challenge_id,
          record_json,
          created_at_ms,
          updated_at_ms
        )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, $10, $11, $12::jsonb, $13, $14)
      ON CONFLICT (namespace, wallet_auth_method_id) DO UPDATE SET
        wallet_id = EXCLUDED.wallet_id,
        rp_id = EXCLUDED.rp_id,
        kind = EXCLUDED.kind,
        status = EXCLUDED.status,
        auth_identifier_key = EXCLUDED.auth_identifier_key,
        credential_id_b64u = EXCLUDED.credential_id_b64u,
        credential_public_key_b64u = EXCLUDED.credential_public_key_b64u,
        signer_slot = EXCLUDED.signer_slot,
        email_hash_hex = EXCLUDED.email_hash_hex,
        challenge_id = EXCLUDED.challenge_id,
        record_json = EXCLUDED.record_json,
        created_at_ms = LEAST(wallet_auth_methods.created_at_ms, EXCLUDED.created_at_ms),
        updated_at_ms = GREATEST(wallet_auth_methods.updated_at_ms, EXCLUDED.updated_at_ms)
    `,
    [
      input.namespace,
      record.walletId,
      record.rpId,
      record.kind,
      record.status,
      walletAuthMethodId(record),
      record.kind === 'passkey' ? record.credentialIdB64u : record.emailHashHex,
      record.kind === 'passkey' ? record.credentialIdB64u : null,
      record.kind === 'passkey' ? record.credentialPublicKeyB64u : null,
      record.kind === 'email_otp' ? record.emailHashHex : null,
      record.kind === 'email_otp' ? record.registrationAuthorityId : null,
      JSON.stringify(record),
      record.createdAtMs,
      record.updatedAtMs,
    ],
  );
}

class InMemoryWalletAuthMethodStore implements WalletAuthMethodStore {
  private readonly records = new Map<string, WalletAuthMethodRecord>();

  constructor(private readonly namespace: string) {}

  async put(record: WalletAuthMethodRecord): Promise<void> {
    this.records.set(`${this.namespace}${walletAuthMethodId(record)}`, record);
  }

  async getPasskey(input: {
    rpId: string;
    credentialIdB64u: string;
  }): Promise<WalletAuthMethodRecord | null> {
    return (
      this.records.get(`${this.namespace}passkey:${input.rpId}:${input.credentialIdB64u}`) || null
    );
  }

  async getEmailOtp(input: {
    walletId: string;
    rpId: string;
    emailHashHex: string;
  }): Promise<WalletAuthMethodRecord | null> {
    return (
      this.records.get(
        `${this.namespace}email_otp:${input.walletId}:${input.rpId}:${input.emailHashHex}`,
      ) || null
    );
  }

  async listForWallet(input: {
    walletId: string;
    rpId: string;
  }): Promise<WalletAuthMethodRecord[]> {
    return [...this.records.values()].filter(
      (record) => record.walletId === input.walletId && record.rpId === input.rpId,
    );
  }
}

class PostgresWalletAuthMethodStore implements WalletAuthMethodStore {
  private readonly poolPromise: ReturnType<typeof getPostgresPool>;

  constructor(private readonly input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
  }

  async put(record: WalletAuthMethodRecord): Promise<void> {
    const pool = await this.poolPromise;
    await putWalletAuthMethodWithExecutor({
      executor: pool,
      namespace: this.input.namespace,
      record,
    });
  }

  async getPasskey(input: {
    rpId: string;
    credentialIdB64u: string;
  }): Promise<WalletAuthMethodRecord | null> {
    const pool = await this.poolPromise;
    const result = await pool.query(
      `
        SELECT record_json
        FROM wallet_auth_methods
        WHERE namespace = $1 AND wallet_auth_method_id = $2
        LIMIT 1
      `,
      [this.input.namespace, `passkey:${input.rpId}:${input.credentialIdB64u}`],
    );
    return normalizeWalletAuthMethod(result.rows[0]?.record_json);
  }

  async getEmailOtp(input: {
    walletId: string;
    rpId: string;
    emailHashHex: string;
  }): Promise<WalletAuthMethodRecord | null> {
    const pool = await this.poolPromise;
    const result = await pool.query(
      `
        SELECT record_json
        FROM wallet_auth_methods
        WHERE namespace = $1 AND wallet_auth_method_id = $2
        LIMIT 1
      `,
      [this.input.namespace, `email_otp:${input.walletId}:${input.rpId}:${input.emailHashHex}`],
    );
    return normalizeWalletAuthMethod(result.rows[0]?.record_json);
  }

  async listForWallet(input: {
    walletId: string;
    rpId: string;
  }): Promise<WalletAuthMethodRecord[]> {
    const pool = await this.poolPromise;
    const result = await pool.query(
      `
        SELECT record_json
        FROM wallet_auth_methods
        WHERE namespace = $1 AND wallet_id = $2 AND rp_id = $3
        ORDER BY created_at_ms ASC
      `,
      [this.input.namespace, input.walletId, input.rpId],
    );
    return result.rows
      .map((row) => normalizeWalletAuthMethod(row.record_json))
      .filter((record): record is WalletAuthMethodRecord => Boolean(record));
  }
}

type DurableObjectStubLike = { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };

class CloudflareDurableObjectWalletAuthMethodStore
  implements WalletAuthMethodStore
{
  private readonly stub: DurableObjectStubLike;

  constructor(private readonly input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    prefix: string;
  }) {
    const id = input.namespace.idFromName(input.objectName);
    this.stub = input.namespace.get(id) as unknown as DurableObjectStubLike;
  }

  private key(id: string): string {
    return `${this.input.prefix}auth-method:${id}`;
  }

  private walletIndexKey(input: { walletId: string; rpId: string }): string {
    return `${this.input.prefix}wallet-index:${input.rpId}:${input.walletId}`;
  }

  private async request<T>(body: unknown): Promise<T> {
    const response = await this.stub.fetch('https://threshold-store.invalid/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      throw new Error(`Wallet auth-method DO store HTTP ${response.status}: ${await response.text()}`);
    }
    return (await response.json().catch(() => null)) as T;
  }

  async put(record: WalletAuthMethodRecord): Promise<void> {
    const key = this.key(walletAuthMethodId(record));
    const indexKey = this.walletIndexKey(record);
    const current = await this.request<{ value?: unknown }>({ op: 'get', key: indexKey });
    const keys = Array.isArray(current?.value)
      ? current.value.filter((value): value is string => typeof value === 'string' && value.length > 0)
      : [];
    const nextKeys = keys.includes(key) ? keys : [...keys, key];
    await this.request({ op: 'set', key, value: record });
    await this.request({ op: 'set', key: indexKey, value: nextKeys });
  }

  async getPasskey(input: {
    rpId: string;
    credentialIdB64u: string;
  }): Promise<WalletAuthMethodRecord | null> {
    const result = await this.request<{ value?: unknown }>({
      op: 'get',
      key: this.key(`passkey:${input.rpId}:${input.credentialIdB64u}`),
    });
    return normalizeWalletAuthMethod(result?.value);
  }

  async getEmailOtp(input: {
    walletId: string;
    rpId: string;
    emailHashHex: string;
  }): Promise<WalletAuthMethodRecord | null> {
    const result = await this.request<{ value?: unknown }>({
      op: 'get',
      key: this.key(`email_otp:${input.walletId}:${input.rpId}:${input.emailHashHex}`),
    });
    return normalizeWalletAuthMethod(result?.value);
  }

  async listForWallet(input: {
    walletId: string;
    rpId: string;
  }): Promise<WalletAuthMethodRecord[]> {
    const current = await this.request<{ value?: unknown }>({
      op: 'get',
      key: this.walletIndexKey(input),
    });
    const keys = Array.isArray(current?.value)
      ? current.value.filter((value): value is string => typeof value === 'string' && value.length > 0)
      : [];
    const records: WalletAuthMethodRecord[] = [];
    for (const key of keys) {
      const result = await this.request<{ value?: unknown }>({ op: 'get', key });
      const record = normalizeWalletAuthMethod(result?.value);
      if (record) records.push(record);
    }
    return records;
  }
}

function resolveDoNamespaceFromConfig(
  config: Record<string, unknown>,
): CloudflareDurableObjectNamespaceLike | null {
  const isNamespace = (value: unknown): value is CloudflareDurableObjectNamespaceLike =>
    isObject(value) && typeof value.idFromName === 'function' && typeof value.get === 'function';
  if (isNamespace(config.namespace)) return config.namespace;
  if (isNamespace(config.durableObjectNamespace)) return config.durableObjectNamespace;
  if (isNamespace(config.THRESHOLD_DO_NAMESPACE)) return config.THRESHOLD_DO_NAMESPACE;
  return null;
}

export function createWalletAuthMethodStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): WalletAuthMethodStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const namespace = resolveWalletAuthMethodStoreNamespace(config);
  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'cloudflare-do') {
    const durableObjectNamespace = resolveDoNamespaceFromConfig(config);
    if (!durableObjectNamespace) {
      throw new Error(
        'cloudflare-do wallet auth-method store selected but no Durable Object namespace was provided',
      );
    }
    const objectName =
      trimString(config.objectName) || trimString(config.name) || THRESHOLD_DO_OBJECT_NAME_DEFAULT;
    input.logger.info('[wallet-auth-method] Using Cloudflare Durable Object store');
    return new CloudflareDurableObjectWalletAuthMethodStore({
      namespace: durableObjectNamespace,
      objectName,
      prefix: namespace,
    });
  }
  const postgresUrl = getPostgresUrlFromConfig(config);
  if (kind === 'postgres' || postgresUrl) {
    if (!input.isNode) {
      throw new Error('[wallet-auth-method] Postgres store is not supported in this runtime');
    }
    if (!postgresUrl) {
      throw new Error('[wallet-auth-method] postgres store enabled but POSTGRES_URL is not set');
    }
    input.logger.info('[wallet-auth-method] Using Postgres store');
    return new PostgresWalletAuthMethodStore({ postgresUrl, namespace });
  }
  input.logger.info('[wallet-auth-method] Using in-memory store');
  return new InMemoryWalletAuthMethodStore(namespace);
}
