import { toOptionalTrimmedString } from '@shared/utils/validation';
import { parseWalletId } from '@shared/utils/domainIds';
import { formatD1ExecStatement, parseD1JsonColumn } from '../storage/d1Sql';
import type { D1DatabaseLike } from '../storage/tenantRoute';
import type { WalletId, WalletRegistrationEcdsaWalletKey } from './types';
import { thresholdEcdsaChainTargetKey } from './thresholdEcdsaChainTarget';
import type {
  WalletEcdsaSignerRecord,
  WalletRecord,
  WalletSignerRecord,
  WalletStore,
} from './WalletStore';

export type {
  WalletEcdsaSignerRecord,
  WalletRecord,
  WalletSignerRecord,
  WalletStore,
} from './WalletStore';

export interface D1WalletStoreSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1WalletStoreOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema?: boolean;
}

type NormalizedD1WalletStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema: boolean;
};

type D1WalletStoreScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

type D1WalletRow = {
  readonly record_json?: unknown;
};

export const WALLET_STORE_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS wallets (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      wallet_id TEXT NOT NULL,
      record_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, project_id, env_id, wallet_id),
      CHECK (length(wallet_id) > 0),
      CHECK (json_valid(record_json)),
      CHECK (created_at_ms >= 0),
      CHECK (updated_at_ms >= created_at_ms),
      CHECK (COALESCE(json_extract(record_json, '$.version') = 'wallet_v1', 0)),
      CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0))
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS wallet_signers (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      wallet_id TEXT NOT NULL,
      signer_family TEXT NOT NULL,
      signer_id TEXT NOT NULL,
      chain_target_key TEXT,
      record_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        signer_family,
        signer_id
      ),
      CHECK (length(wallet_id) > 0),
      CHECK (signer_family IN ('ed25519', 'ecdsa')),
      CHECK (length(signer_id) > 0),
      CHECK (json_valid(record_json)),
      CHECK (created_at_ms >= 0),
      CHECK (updated_at_ms >= created_at_ms),
      CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
      CHECK (COALESCE(json_extract(record_json, '$.signerId') = signer_id, 0)),
      CHECK (
        (
          signer_family = 'ed25519'
          AND chain_target_key IS NULL
          AND substr(signer_id, 1, 8) = 'ed25519:'
          AND COALESCE(
            json_extract(record_json, '$.version') = 'wallet_signer_ed25519_v1',
            0
          )
        )
        OR
        (
          signer_family = 'ecdsa'
          AND chain_target_key IS NOT NULL
          AND length(chain_target_key) > 0
          AND signer_id = 'ecdsa:' || chain_target_key
          AND COALESCE(
            json_extract(record_json, '$.version') = 'wallet_signer_ecdsa_v1',
            0
          )
          AND COALESCE(json_extract(record_json, '$.chainTargetKey') = chain_target_key, 0)
        )
      )
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS wallet_signers_wallet_idx
      ON wallet_signers (namespace, org_id, project_id, env_id, wallet_id, signer_family)
  `,
  `
    CREATE INDEX IF NOT EXISTS wallet_signers_chain_target_idx
      ON wallet_signers (
        namespace,
        org_id,
        project_id,
        env_id,
        signer_family,
        chain_target_key
      )
  `,
] as const);

export async function ensureWalletStoreD1Schema(
  options: D1WalletStoreSchemaOptions,
): Promise<void> {
  for (const statement of WALLET_STORE_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
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

function normalizeD1WalletStoreOptions(
  input: D1WalletStoreOptions,
): NormalizedD1WalletStoreOptions {
  return {
    database: input.database,
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.orgId, 'orgId'),
    projectId: requireD1ScopeString(input.projectId, 'projectId'),
    envId: requireD1ScopeString(input.envId, 'envId'),
    ensureSchema: input.ensureSchema !== false,
  };
}

function assertNeverWalletSignerRecord(record: never): never {
  throw new Error(`Unexpected wallet signer record: ${JSON.stringify(record)}`);
}

function signerFamily(record: WalletSignerRecord): 'ed25519' | 'ecdsa' {
  return record.version === 'wallet_signer_ed25519_v1' ? 'ed25519' : 'ecdsa';
}

function recordChainTargetKey(record: WalletSignerRecord): string | null {
  return record.version === 'wallet_signer_ecdsa_v1' ? record.chainTargetKey : null;
}

function ensureWalletSignerRecord(record: WalletSignerRecord): WalletSignerRecord {
  switch (record.version) {
    case 'wallet_signer_ed25519_v1':
    case 'wallet_signer_ecdsa_v1':
      if (!toOptionalTrimmedString(record.walletId)) throw new Error('walletId is required');
      if (!toOptionalTrimmedString(record.signerId)) throw new Error('signerId is required');
      return record;
    default:
      return assertNeverWalletSignerRecord(record);
  }
}

export function buildWalletEcdsaSignerRecord(input: {
  readonly walletId: WalletId;
  readonly walletKey: WalletRegistrationEcdsaWalletKey;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): WalletEcdsaSignerRecord {
  const chainTargetKey = thresholdEcdsaChainTargetKey(input.walletKey.chainTarget);
  return {
    version: 'wallet_signer_ecdsa_v1',
    walletId: input.walletId,
    walletKeyId: input.walletKey.walletKeyId,
    signerId: `ecdsa:${chainTargetKey}`,
    chainTargetKey,
    chainTarget: input.walletKey.chainTarget,
    walletKey: input.walletKey,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
}

export class D1WalletStore implements WalletStore {
  readonly adapterKind = 'd1';
  private readonly database: D1DatabaseLike;
  private readonly scope: D1WalletStoreScope;
  private readonly ensureSchemaOnUse: boolean;
  private schemaReady = false;

  constructor(input: D1WalletStoreOptions) {
    const normalized = normalizeD1WalletStoreOptions(input);
    this.database = normalized.database;
    this.scope = {
      namespace: normalized.namespace,
      orgId: normalized.orgId,
      projectId: normalized.projectId,
      envId: normalized.envId,
    };
    this.ensureSchemaOnUse = normalized.ensureSchema;
  }

  private async ensureSchema(): Promise<void> {
    if (!this.ensureSchemaOnUse || this.schemaReady) return;
    await ensureWalletStoreD1Schema({ database: this.database });
    this.schemaReady = true;
  }

  async getWallet(input: { walletId: WalletId }): Promise<WalletRecord | null> {
    await this.ensureSchema();
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return null;
    const row = await this.database
      .prepare(
        `SELECT record_json
           FROM wallets
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND wallet_id = ?
          LIMIT 1`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        walletId,
      )
      .first<D1WalletRow>();
    return parseWalletRecord(parseD1JsonColumn(row?.record_json));
  }

  async putSubject(record: WalletRecord): Promise<void> {
    await this.ensureSchema();
    const parsed = parseWalletRecord(record);
    if (!parsed) throw new Error('Invalid wallet record');
    await this.database
      .prepare(
        `INSERT INTO wallets (
          namespace,
          org_id,
          project_id,
          env_id,
          wallet_id,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (namespace, org_id, project_id, env_id, wallet_id)
        DO UPDATE SET
          record_json = EXCLUDED.record_json,
          created_at_ms = MIN(wallets.created_at_ms, EXCLUDED.created_at_ms),
          updated_at_ms = MAX(wallets.updated_at_ms, EXCLUDED.updated_at_ms)`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        parsed.walletId,
        JSON.stringify(parsed),
        parsed.createdAtMs,
        parsed.updatedAtMs,
      )
      .run();
  }

  async putSigner(record: WalletSignerRecord): Promise<void> {
    await this.ensureSchema();
    const parsed = ensureWalletSignerRecord(record);
    await this.database
      .prepare(
        `INSERT INTO wallet_signers (
          namespace,
          org_id,
          project_id,
          env_id,
          wallet_id,
          signer_family,
          signer_id,
          chain_target_key,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (
          namespace,
          org_id,
          project_id,
          env_id,
          wallet_id,
          signer_family,
          signer_id
        )
        DO UPDATE SET
          chain_target_key = EXCLUDED.chain_target_key,
          record_json = EXCLUDED.record_json,
          created_at_ms = MIN(wallet_signers.created_at_ms, EXCLUDED.created_at_ms),
          updated_at_ms = MAX(wallet_signers.updated_at_ms, EXCLUDED.updated_at_ms)`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        parsed.walletId,
        signerFamily(parsed),
        parsed.signerId,
        recordChainTargetKey(parsed),
        JSON.stringify(parsed),
        parsed.createdAtMs,
        parsed.updatedAtMs,
      )
      .run();
  }

  async putSigners(records: readonly WalletSignerRecord[]): Promise<void> {
    for (const record of records) {
      await this.putSigner(record);
    }
  }
}
