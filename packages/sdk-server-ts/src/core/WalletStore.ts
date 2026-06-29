import type { NormalizedLogger } from './logger';
import type {
  CloudflareDurableObjectNamespaceLike,
  ThresholdEcdsaChainTarget,
  ThresholdStoreConfigInput,
  WalletRegistrationEcdsaWalletKey,
  WalletId,
} from './types';
import {
  THRESHOLD_DO_OBJECT_NAME_DEFAULT,
  THRESHOLD_PREFIX_DEFAULT,
} from './defaultConfigsServer';
import { resolveD1DatabaseFromConfig } from '../storage/d1Sql';
import type { D1DatabaseLike } from '../storage/tenantRoute';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { parseWalletId } from '@shared/utils/domainIds';
import { D1WalletStore } from './d1WalletStore';
import type { D1WalletStoreOptions } from './d1WalletStore';

export {
  D1WalletStore,
  WALLET_STORE_D1_SCHEMA_SQL,
  buildWalletEcdsaSignerRecord,
  ensureWalletStoreD1Schema,
} from './d1WalletStore';
export type { D1WalletStoreOptions, D1WalletStoreSchemaOptions } from './d1WalletStore';

export type WalletRecord = {
  version: 'wallet_v1';
  walletId: WalletId;
  createdAtMs: number;
  updatedAtMs: number;
};

export type WalletEd25519SignerRecord = {
  version: 'wallet_signer_ed25519_v1';
  walletId: WalletId;
  signerId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  recoveryExportCapable: boolean;
  clientParticipantId?: number;
  relayerParticipantId?: number;
  participantIds?: number[];
  createdAtMs: number;
  updatedAtMs: number;
};

export type WalletEcdsaSignerRecord = {
  version: 'wallet_signer_ecdsa_v1';
  walletId: WalletId;
  walletKeyId: string;
  signerId: string;
  chainTargetKey: string;
  chainTarget: ThresholdEcdsaChainTarget;
  walletKey: WalletRegistrationEcdsaWalletKey;
  createdAtMs: number;
  updatedAtMs: number;
};

export type WalletSignerRecord =
  | WalletEd25519SignerRecord
  | WalletEcdsaSignerRecord;

export interface WalletStore {
  getWallet(input: { walletId: WalletId }): Promise<WalletRecord | null>;
  putSubject(record: WalletRecord): Promise<void>;
  putSigner(record: WalletSignerRecord): Promise<void>;
  putSigners(records: readonly WalletSignerRecord[]): Promise<void>;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return Boolean(v && typeof v === 'object' && !Array.isArray(v));
}

function trimString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function toPrefixWithColon(prefix: unknown, defaultPrefix: string): string {
  const p = toOptionalTrimmedString(prefix);
  if (!p) return defaultPrefix;
  return p.endsWith(':') ? p : `${p}:`;
}

export function resolveWalletStoreNamespace(config: Record<string, unknown>): string {
  const explicit = toOptionalTrimmedString(config.WALLET_PREFIX);
  if (explicit) return toPrefixWithColon(explicit, '');
  const base = toOptionalTrimmedString(config.THRESHOLD_PREFIX) || THRESHOLD_PREFIX_DEFAULT;
  const baseWithColon = toPrefixWithColon(base, `${THRESHOLD_PREFIX_DEFAULT}:`);
  return `${baseWithColon}wallet:`;
}

function resolveDoNamespaceFromConfig(
  config: Record<string, unknown>,
): CloudflareDurableObjectNamespaceLike | null {
  const isNamespace = (value: unknown): value is CloudflareDurableObjectNamespaceLike =>
    isObject(value) && typeof value.idFromName === 'function' && typeof value.get === 'function';
  const direct = config.namespace;
  if (isNamespace(direct)) return direct;
  const durableObjectNamespace = config.durableObjectNamespace;
  if (isNamespace(durableObjectNamespace)) return durableObjectNamespace;
  const envStyle = config.THRESHOLD_DO_NAMESPACE;
  if (isNamespace(envStyle)) return envStyle;
  return null;
}

function signerFamily(record: WalletSignerRecord): 'ed25519' | 'ecdsa' {
  return record.version === 'wallet_signer_ed25519_v1' ? 'ed25519' : 'ecdsa';
}

function normalizeTimestampMs(value: unknown): number | null {
  const numberValue = Number(value);
  if (!Number.isFinite(numberValue) || numberValue < 0) return null;
  return Math.floor(numberValue);
}

function parseWalletRecord(raw: unknown): WalletRecord | null {
  if (!isObject(raw)) return null;
  if (raw.version !== 'wallet_v1') return null;
  const walletId = parseWalletId(raw.walletId);
  const createdAtMs = normalizeTimestampMs(raw.createdAtMs);
  const updatedAtMs = normalizeTimestampMs(raw.updatedAtMs);
  if (!walletId.ok || createdAtMs == null || updatedAtMs == null) return null;
  return {
    version: 'wallet_v1',
    walletId: walletId.value,
    createdAtMs,
    updatedAtMs,
  };
}

function requireD1ScopeString(input: unknown, field: string): string {
  const normalized = toOptionalTrimmedString(input);
  if (!normalized) throw new Error(`${field} is required for D1 wallet store`);
  return normalized;
}

function d1ScopeFromConfig(input: {
  readonly config: Record<string, unknown>;
  readonly namespace: string;
}): Omit<D1WalletStoreOptions, 'database'> {
  return {
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.config.orgId || input.config.ORG_ID, 'orgId'),
    projectId: requireD1ScopeString(input.config.projectId || input.config.PROJECT_ID, 'projectId'),
    envId: requireD1ScopeString(input.config.envId || input.config.ENV_ID, 'envId'),
  };
}

export function buildWalletEd25519SignerId(input: {
  nearAccountId: string;
  signerSlot: number;
}): string {
  return `ed25519:${String(input.nearAccountId || '').trim()}:${Math.max(1, Math.floor(Number(input.signerSlot) || 1))}`;
}

class InMemoryWalletStore implements WalletStore {
  private readonly subjects = new Map<string, WalletRecord>();
  private readonly signers = new Map<string, WalletSignerRecord>();

  constructor(private readonly prefix: string) {}

  async getWallet(input: { walletId: WalletId }): Promise<WalletRecord | null> {
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return null;
    return this.subjects.get(`${this.prefix}${walletId}`) ?? null;
  }

  async putSubject(record: WalletRecord): Promise<void> {
    this.subjects.set(`${this.prefix}${record.walletId}`, record);
  }

  async putSigner(record: WalletSignerRecord): Promise<void> {
    this.signers.set(
      `${this.prefix}${record.walletId}:${signerFamily(record)}:${record.signerId}`,
      record,
    );
  }

  async putSigners(records: readonly WalletSignerRecord[]): Promise<void> {
    for (const record of records) {
      await this.putSigner(record);
    }
  }
}

type DurableObjectStubLike = { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };

class CloudflareDurableObjectWalletStore implements WalletStore {
  private readonly stub: DurableObjectStubLike;

  constructor(private readonly input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    prefix: string;
  }) {
    const id = input.namespace.idFromName(input.objectName);
    this.stub = input.namespace.get(id) as unknown as DurableObjectStubLike;
  }

  private key(scope: 'subject' | 'signer', id: string): string {
    return `${this.input.prefix}${scope}:${id}`;
  }

  private async put(key: string, value: unknown): Promise<void> {
    const response = await this.stub.fetch('https://threshold-store.invalid/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ op: 'set', key, value }),
    });
    if (!response.ok) {
      throw new Error(`Wallet DO store HTTP ${response.status}: ${await response.text()}`);
    }
  }

  async putSubject(record: WalletRecord): Promise<void> {
    await this.put(this.key('subject', record.walletId), record);
  }

  async getWallet(input: { walletId: WalletId }): Promise<WalletRecord | null> {
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return null;
    const response = await this.stub.fetch('https://threshold-store.invalid/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ op: 'get', key: this.key('subject', walletId) }),
    });
    if (!response.ok) return null;
    const current = (await response.json().catch(() => null)) as { value?: unknown } | null;
    return parseWalletRecord(current?.value);
  }

  async putSigner(record: WalletSignerRecord): Promise<void> {
    await this.put(
      this.key('signer', `${record.walletId}:${signerFamily(record)}:${record.signerId}`),
      record,
    );
  }

  async putSigners(records: readonly WalletSignerRecord[]): Promise<void> {
    for (const record of records) {
      await this.putSigner(record);
    }
  }
}

export function createWalletStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): WalletStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const prefix = resolveWalletStoreNamespace(config);
  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'd1') {
    const database = resolveD1DatabaseFromConfig(config);
    if (!database) {
      throw new Error('[wallet] D1 store selected but no D1 database was provided');
    }
    input.logger.info('[wallet] Using D1 store');
    return new D1WalletStore({
      database,
      ...d1ScopeFromConfig({ config, namespace: prefix }),
    });
  }
  if (kind === 'cloudflare-do') {
    const namespace = resolveDoNamespaceFromConfig(config);
    if (!namespace) {
      throw new Error(
        'cloudflare-do wallet store selected but no Durable Object namespace was provided',
      );
    }
    const objectName =
      trimString(config.objectName) || trimString(config.name) || THRESHOLD_DO_OBJECT_NAME_DEFAULT;
    input.logger.info('[wallet] Using Cloudflare Durable Object store');
    return new CloudflareDurableObjectWalletStore({ namespace, objectName, prefix });
  }
  if (kind) throw new Error(`[wallet] Unknown wallet store kind: ${kind}`);
  input.logger.info('[wallet] Using in-memory store (non-persistent)');
  return new InMemoryWalletStore(prefix);
}
