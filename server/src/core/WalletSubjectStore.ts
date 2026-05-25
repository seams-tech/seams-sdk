import { thresholdEcdsaChainTargetKey } from './thresholdEcdsaChainTarget';
import type { NormalizedLogger } from './logger';
import type {
  CloudflareDurableObjectNamespaceLike,
  ThresholdEcdsaChainTarget,
  ThresholdStoreConfigInput,
  WalletRegistrationEcdsaWalletKey,
  WalletSubjectId,
} from './types';
import {
  THRESHOLD_DO_OBJECT_NAME_DEFAULT,
  THRESHOLD_PREFIX_DEFAULT,
} from './defaultConfigsServer';
import {
  getPostgresPool,
  getPostgresUrlFromConfig,
  type PgQueryExecutor,
} from '../storage/postgres';
import { toOptionalTrimmedString } from '@shared/utils/validation';

export type WalletSubjectRecord = {
  version: 'wallet_subject_v1';
  walletSubjectId: WalletSubjectId;
  rpId: string;
  createdAtMs: number;
  updatedAtMs: number;
};

export type WalletSubjectAuthenticatorRecord = {
  version: 'wallet_authenticator_v1';
  walletSubjectId: WalletSubjectId;
  rpId: string;
  credentialIdB64u: string;
  credentialPublicKeyB64u: string;
  counter: number;
  createdAtMs: number;
  updatedAtMs: number;
};

export type WalletSubjectEd25519SignerRecord = {
  version: 'wallet_signer_ed25519_v1';
  walletSubjectId: WalletSubjectId;
  rpId: string;
  signerId: string;
  nearAccountId: string;
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

export type WalletSubjectEcdsaSignerRecord = {
  version: 'wallet_signer_ecdsa_v1';
  walletSubjectId: WalletSubjectId;
  rpId: string;
  signerId: string;
  chainTargetKey: string;
  chainTarget: ThresholdEcdsaChainTarget;
  walletKey: WalletRegistrationEcdsaWalletKey;
  createdAtMs: number;
  updatedAtMs: number;
};

export type WalletSubjectSignerRecord =
  | WalletSubjectEd25519SignerRecord
  | WalletSubjectEcdsaSignerRecord;

export interface WalletSubjectStore {
  putSubject(record: WalletSubjectRecord): Promise<void>;
  putAuthenticator(record: WalletSubjectAuthenticatorRecord): Promise<void>;
  putSigner(record: WalletSubjectSignerRecord): Promise<void>;
  putSigners(records: readonly WalletSubjectSignerRecord[]): Promise<void>;
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

export function resolveWalletSubjectStoreNamespace(config: Record<string, unknown>): string {
  const explicit = toOptionalTrimmedString(config.WALLET_SUBJECT_PREFIX);
  if (explicit) return toPrefixWithColon(explicit, '');
  const base = toOptionalTrimmedString(config.THRESHOLD_PREFIX) || THRESHOLD_PREFIX_DEFAULT;
  const baseWithColon = toPrefixWithColon(base, `${THRESHOLD_PREFIX_DEFAULT}:`);
  return `${baseWithColon}wallet-subject:`;
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

function signerFamily(record: WalletSubjectSignerRecord): 'ed25519' | 'ecdsa' {
  return record.version === 'wallet_signer_ed25519_v1' ? 'ed25519' : 'ecdsa';
}

function recordChainTargetKey(record: WalletSubjectSignerRecord): string | null {
  return record.version === 'wallet_signer_ecdsa_v1' ? record.chainTargetKey : null;
}

export function buildWalletSubjectEd25519SignerId(input: {
  nearAccountId: string;
  signerSlot: number;
}): string {
  return `ed25519:${String(input.nearAccountId || '').trim()}:${Math.max(1, Math.floor(Number(input.signerSlot) || 1))}`;
}

export function buildWalletSubjectEcdsaSignerRecord(input: {
  walletSubjectId: WalletSubjectId;
  walletKey: WalletRegistrationEcdsaWalletKey;
  createdAtMs: number;
  updatedAtMs: number;
}): WalletSubjectEcdsaSignerRecord {
  const chainTargetKey = thresholdEcdsaChainTargetKey(input.walletKey.chainTarget);
  return {
    version: 'wallet_signer_ecdsa_v1',
    walletSubjectId: input.walletSubjectId,
    rpId: input.walletKey.rpId,
    signerId: `ecdsa:${chainTargetKey}`,
    chainTargetKey,
    chainTarget: input.walletKey.chainTarget,
    walletKey: input.walletKey,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
}

export async function putWalletSubjectRecordWithExecutor(input: {
  executor: PgQueryExecutor;
  namespace: string;
  record: WalletSubjectRecord;
}): Promise<void> {
  const { record } = input;
  await input.executor.query(
    `
      INSERT INTO wallet_subjects
        (namespace, wallet_subject_id, rp_id, record_json, created_at_ms, updated_at_ms)
      VALUES ($1, $2, $3, $4::jsonb, $5, $6)
      ON CONFLICT (namespace, wallet_subject_id) DO UPDATE SET
        rp_id = EXCLUDED.rp_id,
        record_json = EXCLUDED.record_json,
        created_at_ms = LEAST(wallet_subjects.created_at_ms, EXCLUDED.created_at_ms),
        updated_at_ms = GREATEST(wallet_subjects.updated_at_ms, EXCLUDED.updated_at_ms)
    `,
    [
      input.namespace,
      record.walletSubjectId,
      record.rpId,
      JSON.stringify(record),
      record.createdAtMs,
      record.updatedAtMs,
    ],
  );
}

export async function putWalletSubjectAuthenticatorRecordWithExecutor(input: {
  executor: PgQueryExecutor;
  namespace: string;
  record: WalletSubjectAuthenticatorRecord;
}): Promise<void> {
  const { record } = input;
  await input.executor.query(
    `
      INSERT INTO wallet_authenticators
        (
          namespace,
          wallet_subject_id,
          rp_id,
          credential_id_b64u,
          record_json,
          created_at_ms,
          updated_at_ms
        )
      VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
      ON CONFLICT (namespace, wallet_subject_id, credential_id_b64u) DO UPDATE SET
        rp_id = EXCLUDED.rp_id,
        record_json = EXCLUDED.record_json,
        created_at_ms = LEAST(wallet_authenticators.created_at_ms, EXCLUDED.created_at_ms),
        updated_at_ms = GREATEST(wallet_authenticators.updated_at_ms, EXCLUDED.updated_at_ms)
    `,
    [
      input.namespace,
      record.walletSubjectId,
      record.rpId,
      record.credentialIdB64u,
      JSON.stringify(record),
      record.createdAtMs,
      record.updatedAtMs,
    ],
  );
}

export async function putWalletSubjectSignerRecordWithExecutor(input: {
  executor: PgQueryExecutor;
  namespace: string;
  record: WalletSubjectSignerRecord;
}): Promise<void> {
  const { record } = input;
  await input.executor.query(
    `
      INSERT INTO wallet_signers
        (
          namespace,
          wallet_subject_id,
          signer_family,
          signer_id,
          chain_target_key,
          record_json,
          created_at_ms,
          updated_at_ms
        )
      VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
      ON CONFLICT (namespace, wallet_subject_id, signer_family, signer_id) DO UPDATE SET
        chain_target_key = EXCLUDED.chain_target_key,
        record_json = EXCLUDED.record_json,
        created_at_ms = LEAST(wallet_signers.created_at_ms, EXCLUDED.created_at_ms),
        updated_at_ms = GREATEST(wallet_signers.updated_at_ms, EXCLUDED.updated_at_ms)
    `,
    [
      input.namespace,
      record.walletSubjectId,
      signerFamily(record),
      record.signerId,
      recordChainTargetKey(record),
      JSON.stringify(record),
      record.createdAtMs,
      record.updatedAtMs,
    ],
  );
}

class InMemoryWalletSubjectStore implements WalletSubjectStore {
  private readonly subjects = new Map<string, WalletSubjectRecord>();
  private readonly authenticators = new Map<string, WalletSubjectAuthenticatorRecord>();
  private readonly signers = new Map<string, WalletSubjectSignerRecord>();

  constructor(private readonly prefix: string) {}

  async putSubject(record: WalletSubjectRecord): Promise<void> {
    this.subjects.set(`${this.prefix}${record.walletSubjectId}`, record);
  }

  async putAuthenticator(record: WalletSubjectAuthenticatorRecord): Promise<void> {
    this.authenticators.set(
      `${this.prefix}${record.walletSubjectId}:${record.credentialIdB64u}`,
      record,
    );
  }

  async putSigner(record: WalletSubjectSignerRecord): Promise<void> {
    this.signers.set(
      `${this.prefix}${record.walletSubjectId}:${signerFamily(record)}:${record.signerId}`,
      record,
    );
  }

  async putSigners(records: readonly WalletSubjectSignerRecord[]): Promise<void> {
    for (const record of records) {
      await this.putSigner(record);
    }
  }
}

class PostgresWalletSubjectStore implements WalletSubjectStore {
  private readonly poolPromise: ReturnType<typeof getPostgresPool>;

  constructor(private readonly input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
  }

  async putSubject(record: WalletSubjectRecord): Promise<void> {
    const pool = await this.poolPromise;
    await putWalletSubjectRecordWithExecutor({
      executor: pool,
      namespace: this.input.namespace,
      record,
    });
  }

  async putAuthenticator(record: WalletSubjectAuthenticatorRecord): Promise<void> {
    const pool = await this.poolPromise;
    await putWalletSubjectAuthenticatorRecordWithExecutor({
      executor: pool,
      namespace: this.input.namespace,
      record,
    });
  }

  async putSigner(record: WalletSubjectSignerRecord): Promise<void> {
    const pool = await this.poolPromise;
    await putWalletSubjectSignerRecordWithExecutor({
      executor: pool,
      namespace: this.input.namespace,
      record,
    });
  }

  async putSigners(records: readonly WalletSubjectSignerRecord[]): Promise<void> {
    for (const record of records) {
      await this.putSigner(record);
    }
  }
}

type DurableObjectStubLike = { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };

class CloudflareDurableObjectWalletSubjectStore implements WalletSubjectStore {
  private readonly stub: DurableObjectStubLike;

  constructor(private readonly input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    prefix: string;
  }) {
    const id = input.namespace.idFromName(input.objectName);
    this.stub = input.namespace.get(id) as unknown as DurableObjectStubLike;
  }

  private key(scope: 'subject' | 'authenticator' | 'signer', id: string): string {
    return `${this.input.prefix}${scope}:${id}`;
  }

  private async put(key: string, value: unknown): Promise<void> {
    const response = await this.stub.fetch('https://threshold-store.invalid/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ op: 'set', key, value }),
    });
    if (!response.ok) {
      throw new Error(`Wallet subject DO store HTTP ${response.status}: ${await response.text()}`);
    }
  }

  async putSubject(record: WalletSubjectRecord): Promise<void> {
    await this.put(this.key('subject', record.walletSubjectId), record);
  }

  async putAuthenticator(record: WalletSubjectAuthenticatorRecord): Promise<void> {
    await this.put(
      this.key('authenticator', `${record.walletSubjectId}:${record.credentialIdB64u}`),
      record,
    );
  }

  async putSigner(record: WalletSubjectSignerRecord): Promise<void> {
    await this.put(
      this.key('signer', `${record.walletSubjectId}:${signerFamily(record)}:${record.signerId}`),
      record,
    );
  }

  async putSigners(records: readonly WalletSubjectSignerRecord[]): Promise<void> {
    for (const record of records) {
      await this.putSigner(record);
    }
  }
}

export function createWalletSubjectStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): WalletSubjectStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const prefix = resolveWalletSubjectStoreNamespace(config);
  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'cloudflare-do') {
    const namespace = resolveDoNamespaceFromConfig(config);
    if (!namespace) {
      throw new Error(
        'cloudflare-do wallet-subject store selected but no Durable Object namespace was provided',
      );
    }
    const objectName =
      trimString(config.objectName) || trimString(config.name) || THRESHOLD_DO_OBJECT_NAME_DEFAULT;
    input.logger.info('[wallet-subject] Using Cloudflare Durable Object store');
    return new CloudflareDurableObjectWalletSubjectStore({ namespace, objectName, prefix });
  }
  const postgresUrl = getPostgresUrlFromConfig(config);
  if (kind === 'postgres' || postgresUrl) {
    if (!input.isNode) {
      throw new Error('[wallet-subject] Postgres store is not supported in this runtime');
    }
    if (!postgresUrl) {
      throw new Error('[wallet-subject] postgres store enabled but POSTGRES_URL is not set');
    }
    input.logger.info('[wallet-subject] Using Postgres store');
    return new PostgresWalletSubjectStore({ postgresUrl, namespace: prefix });
  }
  input.logger.info('[wallet-subject] Using in-memory store (non-persistent)');
  return new InMemoryWalletSubjectStore(prefix);
}
