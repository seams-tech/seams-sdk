import type {
  CloudflareDurableObjectNamespaceLike,
  ThresholdStoreConfigInput,
} from './types';
import {
  THRESHOLD_DO_OBJECT_NAME_DEFAULT,
  THRESHOLD_PREFIX_DEFAULT,
} from './defaultConfigsServer';
import type { NormalizedLogger } from './logger';
import { resolveD1DatabaseFromConfig } from '../storage/d1Sql';
import type { D1DatabaseLike } from '../storage/tenantRoute';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  D1WalletAuthMethodStore,
  normalizeWalletAuthMethod,
  walletAuthMethodId,
} from './d1WalletAuthMethodStore';
import type {
  D1WalletAuthMethodStoreOptions,
  WalletAuthMethodRecord,
  WalletAuthMethodStore,
} from './d1WalletAuthMethodStore';

export {
  D1WalletAuthMethodStore,
  WALLET_AUTH_METHOD_STORE_D1_SCHEMA_SQL,
  ensureWalletAuthMethodStoreD1Schema,
  normalizeWalletAuthMethod,
} from './d1WalletAuthMethodStore';
export type {
  D1WalletAuthMethodStoreOptions,
  D1WalletAuthMethodStoreSchemaOptions,
  WalletAuthMethodRecord,
  WalletAuthMethodStore,
} from './d1WalletAuthMethodStore';

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

export function resolveWalletAuthMethodStoreNamespace(
  config: Record<string, unknown>,
): string {
  const explicit = toOptionalTrimmedString(config.WALLET_AUTH_METHOD_PREFIX);
  if (explicit) return toPrefixWithColon(explicit, '');
  const base = toOptionalTrimmedString(config.THRESHOLD_PREFIX) || THRESHOLD_PREFIX_DEFAULT;
  return `${toPrefixWithColon(base, `${THRESHOLD_PREFIX_DEFAULT}:`)}wallet-auth-method:`;
}

function requireD1ScopeString(input: unknown, field: string): string {
  const normalized = toOptionalTrimmedString(input);
  if (!normalized) throw new Error(`${field} is required for D1 wallet auth-method store`);
  return normalized;
}

function d1ScopeFromConfig(input: {
  readonly config: Record<string, unknown>;
  readonly namespace: string;
}): Omit<D1WalletAuthMethodStoreOptions, 'database'> {
  return {
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.config.orgId || input.config.ORG_ID, 'orgId'),
    projectId: requireD1ScopeString(input.config.projectId || input.config.PROJECT_ID, 'projectId'),
    envId: requireD1ScopeString(input.config.envId || input.config.ENV_ID, 'envId'),
  };
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
    emailHashHex: string;
  }): Promise<WalletAuthMethodRecord | null> {
    return (
      this.records.get(`${this.namespace}email_otp:${input.walletId}:${input.emailHashHex}`) ||
      null
    );
  }

  async listForWallet(input: {
    walletId: string;
    rpId?: string;
  }): Promise<WalletAuthMethodRecord[]> {
    return [...this.records.values()].filter(
      (record) =>
        record.walletId === input.walletId &&
        (record.kind === 'email_otp' || !input.rpId || record.rpId === input.rpId),
    );
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

  private walletIndexKey(input: { walletId: string; rpId?: string }): string {
    return `${this.input.prefix}wallet-index:${input.rpId || '*'}:${input.walletId}`;
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
    const indexKey = this.walletIndexKey({
      walletId: record.walletId,
      ...(record.kind === 'passkey' ? { rpId: record.rpId } : {}),
    });
    const allWalletIndexKey = this.walletIndexKey({ walletId: record.walletId });
    const current = await this.request<{ value?: unknown }>({ op: 'get', key: indexKey });
    const keys = Array.isArray(current?.value)
      ? current.value.filter((value): value is string => typeof value === 'string' && value.length > 0)
      : [];
    const nextKeys = keys.includes(key) ? keys : [...keys, key];
    const allCurrent = await this.request<{ value?: unknown }>({ op: 'get', key: allWalletIndexKey });
    const allKeys = Array.isArray(allCurrent?.value)
      ? allCurrent.value.filter((value): value is string => typeof value === 'string' && value.length > 0)
      : [];
    const nextAllKeys = allKeys.includes(key) ? allKeys : [...allKeys, key];
    await this.request({ op: 'set', key, value: record });
    await this.request({ op: 'set', key: indexKey, value: nextKeys });
    await this.request({ op: 'set', key: allWalletIndexKey, value: nextAllKeys });
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
    emailHashHex: string;
  }): Promise<WalletAuthMethodRecord | null> {
    const result = await this.request<{ value?: unknown }>({
      op: 'get',
      key: this.key(`email_otp:${input.walletId}:${input.emailHashHex}`),
    });
    return normalizeWalletAuthMethod(result?.value);
  }

  async listForWallet(input: {
    walletId: string;
    rpId?: string;
  }): Promise<WalletAuthMethodRecord[]> {
    const current = await this.request<{ value?: unknown }>({
      op: 'get',
      key: this.walletIndexKey({ walletId: input.walletId }),
    });
    const keys = Array.isArray(current?.value)
      ? current.value.filter((value): value is string => typeof value === 'string' && value.length > 0)
      : [];
    const records: WalletAuthMethodRecord[] = [];
    for (const key of keys) {
      const result = await this.request<{ value?: unknown }>({ op: 'get', key });
      const record = normalizeWalletAuthMethod(result?.value);
      if (
        record &&
        (record.kind === 'email_otp' || !input.rpId || record.rpId === input.rpId)
      ) {
        records.push(record);
      }
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
  if (kind === 'd1') {
    const database = resolveD1DatabaseFromConfig(config);
    if (!database) {
      throw new Error(
        '[wallet-auth-method] D1 store selected but no D1 database was provided',
      );
    }
    input.logger.info('[wallet-auth-method] Using D1 store');
    return new D1WalletAuthMethodStore({
      database,
      ...d1ScopeFromConfig({ config, namespace }),
    });
  }
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
  if (kind) throw new Error(`[wallet-auth-method] Unknown wallet auth-method store kind: ${kind}`);
  input.logger.info('[wallet-auth-method] Using in-memory store');
  return new InMemoryWalletAuthMethodStore(namespace);
}
