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
  walletSubjectIdFromString,
  type WalletAuthMethodBinding,
} from '@shared/utils/registrationIntent';

export type WalletAuthMethodBindingRecord = WalletAuthMethodBinding;

export interface WalletAuthMethodBindingStore {
  putBinding(record: WalletAuthMethodBindingRecord): Promise<void>;
  getPasskeyBinding(input: {
    rpId: string;
    credentialIdB64u: string;
  }): Promise<WalletAuthMethodBindingRecord | null>;
  listForWallet(input: {
    walletSubjectId: string;
    rpId: string;
  }): Promise<WalletAuthMethodBindingRecord[]>;
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

function bindingKey(record: WalletAuthMethodBindingRecord): string {
  return record.kind === 'passkey'
    ? `passkey:${record.rpId}:${record.credentialIdB64u}`
    : `email_otp:${record.rpId}:${record.emailHashHex}`;
}

export function resolveWalletAuthMethodBindingStoreNamespace(
  config: Record<string, unknown>,
): string {
  const explicit = toOptionalTrimmedString(config.WALLET_AUTH_METHOD_BINDING_PREFIX);
  if (explicit) return toPrefixWithColon(explicit, '');
  const base = toOptionalTrimmedString(config.THRESHOLD_PREFIX) || THRESHOLD_PREFIX_DEFAULT;
  return `${toPrefixWithColon(base, `${THRESHOLD_PREFIX_DEFAULT}:`)}wallet-auth-method:`;
}

export function normalizeWalletAuthMethodBinding(
  raw: unknown,
): WalletAuthMethodBindingRecord | null {
  if (!isObject(raw)) return null;
  const version = trimString(raw.version);
  const kind = trimString(raw.kind);
  const status = trimString(raw.status);
  const walletSubjectId = walletSubjectIdFromString(trimString(raw.walletSubjectId));
  const rpId = trimString(raw.rpId);
  const createdAtMs = Math.floor(Number(raw.createdAtMs));
  const updatedAtMs = Math.floor(Number(raw.updatedAtMs));
  if (
    version !== 'wallet_auth_method_binding_v1' ||
    (kind !== 'passkey' && kind !== 'email_otp') ||
    (status !== 'active' && status !== 'revoked') ||
    !walletSubjectId ||
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
      version: 'wallet_auth_method_binding_v1',
      kind: 'passkey',
      status,
      walletSubjectId,
      rpId,
      credentialIdB64u,
      credentialPublicKeyB64u,
      counter,
      createdAtMs,
      updatedAtMs,
    };
  }
  const emailHashHex = trimString(raw.emailHashHex);
  const challengeId = trimString(raw.challengeId);
  if (!emailHashHex || !challengeId) return null;
  return {
    version: 'wallet_auth_method_binding_v1',
    kind: 'email_otp',
    status,
    walletSubjectId,
    rpId,
    emailHashHex,
    challengeId,
    createdAtMs,
    updatedAtMs,
  };
}

export async function putWalletAuthMethodBindingWithExecutor(input: {
  executor: PgQueryExecutor;
  namespace: string;
  record: WalletAuthMethodBindingRecord;
}): Promise<void> {
  const { record } = input;
  await input.executor.query(
    `
      INSERT INTO wallet_auth_method_bindings
        (
          namespace,
          wallet_subject_id,
          rp_id,
          kind,
          status,
          binding_key,
          credential_id_b64u,
          email_hash_hex,
          record_json,
          created_at_ms,
          updated_at_ms
        )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)
      ON CONFLICT (namespace, binding_key) DO UPDATE SET
        wallet_subject_id = EXCLUDED.wallet_subject_id,
        rp_id = EXCLUDED.rp_id,
        kind = EXCLUDED.kind,
        status = EXCLUDED.status,
        credential_id_b64u = EXCLUDED.credential_id_b64u,
        email_hash_hex = EXCLUDED.email_hash_hex,
        record_json = EXCLUDED.record_json,
        created_at_ms = LEAST(wallet_auth_method_bindings.created_at_ms, EXCLUDED.created_at_ms),
        updated_at_ms = GREATEST(wallet_auth_method_bindings.updated_at_ms, EXCLUDED.updated_at_ms)
    `,
    [
      input.namespace,
      record.walletSubjectId,
      record.rpId,
      record.kind,
      record.status,
      bindingKey(record),
      record.kind === 'passkey' ? record.credentialIdB64u : null,
      record.kind === 'email_otp' ? record.emailHashHex : null,
      JSON.stringify(record),
      record.createdAtMs,
      record.updatedAtMs,
    ],
  );
}

class InMemoryWalletAuthMethodBindingStore implements WalletAuthMethodBindingStore {
  private readonly records = new Map<string, WalletAuthMethodBindingRecord>();

  constructor(private readonly namespace: string) {}

  async putBinding(record: WalletAuthMethodBindingRecord): Promise<void> {
    this.records.set(`${this.namespace}${bindingKey(record)}`, record);
  }

  async getPasskeyBinding(input: {
    rpId: string;
    credentialIdB64u: string;
  }): Promise<WalletAuthMethodBindingRecord | null> {
    return this.records.get(`${this.namespace}passkey:${input.rpId}:${input.credentialIdB64u}`) || null;
  }

  async listForWallet(input: {
    walletSubjectId: string;
    rpId: string;
  }): Promise<WalletAuthMethodBindingRecord[]> {
    return [...this.records.values()].filter(
      (record) => record.walletSubjectId === input.walletSubjectId && record.rpId === input.rpId,
    );
  }
}

class PostgresWalletAuthMethodBindingStore implements WalletAuthMethodBindingStore {
  private readonly poolPromise: ReturnType<typeof getPostgresPool>;

  constructor(private readonly input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
  }

  async putBinding(record: WalletAuthMethodBindingRecord): Promise<void> {
    const pool = await this.poolPromise;
    await putWalletAuthMethodBindingWithExecutor({
      executor: pool,
      namespace: this.input.namespace,
      record,
    });
  }

  async getPasskeyBinding(input: {
    rpId: string;
    credentialIdB64u: string;
  }): Promise<WalletAuthMethodBindingRecord | null> {
    const pool = await this.poolPromise;
    const result = await pool.query(
      `
        SELECT record_json
        FROM wallet_auth_method_bindings
        WHERE namespace = $1 AND binding_key = $2
        LIMIT 1
      `,
      [this.input.namespace, `passkey:${input.rpId}:${input.credentialIdB64u}`],
    );
    return normalizeWalletAuthMethodBinding(result.rows[0]?.record_json);
  }

  async listForWallet(input: {
    walletSubjectId: string;
    rpId: string;
  }): Promise<WalletAuthMethodBindingRecord[]> {
    const pool = await this.poolPromise;
    const result = await pool.query(
      `
        SELECT record_json
        FROM wallet_auth_method_bindings
        WHERE namespace = $1 AND wallet_subject_id = $2 AND rp_id = $3
        ORDER BY created_at_ms ASC
      `,
      [this.input.namespace, input.walletSubjectId, input.rpId],
    );
    return result.rows
      .map((row) => normalizeWalletAuthMethodBinding(row.record_json))
      .filter((record): record is WalletAuthMethodBindingRecord => Boolean(record));
  }
}

type DurableObjectStubLike = { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };

class CloudflareDurableObjectWalletAuthMethodBindingStore
  implements WalletAuthMethodBindingStore
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
    return `${this.input.prefix}binding:${id}`;
  }

  private walletIndexKey(input: { walletSubjectId: string; rpId: string }): string {
    return `${this.input.prefix}wallet-index:${input.rpId}:${input.walletSubjectId}`;
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

  async putBinding(record: WalletAuthMethodBindingRecord): Promise<void> {
    const key = this.key(bindingKey(record));
    const indexKey = this.walletIndexKey(record);
    const current = await this.request<{ value?: unknown }>({ op: 'get', key: indexKey });
    const keys = Array.isArray(current?.value)
      ? current.value.filter((value): value is string => typeof value === 'string' && value.length > 0)
      : [];
    const nextKeys = keys.includes(key) ? keys : [...keys, key];
    await this.request({ op: 'set', key, value: record });
    await this.request({ op: 'set', key: indexKey, value: nextKeys });
  }

  async getPasskeyBinding(input: {
    rpId: string;
    credentialIdB64u: string;
  }): Promise<WalletAuthMethodBindingRecord | null> {
    const result = await this.request<{ value?: unknown }>({
      op: 'get',
      key: this.key(`passkey:${input.rpId}:${input.credentialIdB64u}`),
    });
    return normalizeWalletAuthMethodBinding(result?.value);
  }

  async listForWallet(input: {
    walletSubjectId: string;
    rpId: string;
  }): Promise<WalletAuthMethodBindingRecord[]> {
    const current = await this.request<{ value?: unknown }>({
      op: 'get',
      key: this.walletIndexKey(input),
    });
    const keys = Array.isArray(current?.value)
      ? current.value.filter((value): value is string => typeof value === 'string' && value.length > 0)
      : [];
    const records: WalletAuthMethodBindingRecord[] = [];
    for (const key of keys) {
      const result = await this.request<{ value?: unknown }>({ op: 'get', key });
      const record = normalizeWalletAuthMethodBinding(result?.value);
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

export function createWalletAuthMethodBindingStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): WalletAuthMethodBindingStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const namespace = resolveWalletAuthMethodBindingStoreNamespace(config);
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
    return new CloudflareDurableObjectWalletAuthMethodBindingStore({
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
    return new PostgresWalletAuthMethodBindingStore({ postgresUrl, namespace });
  }
  input.logger.info('[wallet-auth-method] Using in-memory store');
  return new InMemoryWalletAuthMethodBindingStore(namespace);
}
