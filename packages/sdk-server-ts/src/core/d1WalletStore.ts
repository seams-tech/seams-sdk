import { toOptionalTrimmedString } from '@shared/utils/validation';
import { parseWalletId } from '@shared/utils/domainIds';
import { d1ChangedRows, formatD1ExecStatement, parseD1JsonColumn } from '../storage/d1Sql';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../storage/tenantRoute';
import type { WalletId, WalletRegistrationEcdsaWalletKey } from './registrationContracts';
import { alphabetizeStringify } from '@shared/utils/digests';
import { thresholdEcdsaChainTargetKey } from './thresholdEcdsaChainTarget';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import {
  parseRouterAbEd25519YaoRecoveryActivationResultV1,
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationResultV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import type {
  WalletEd25519YaoActiveCapabilityRecord,
  WalletEd25519SignerRecord,
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

export type D1WalletStoreScope = {
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

function equalBytes(left: readonly number[], right: readonly number[]): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function parseWalletEd25519YaoActiveCapabilityRecord(
  raw: unknown,
): WalletEd25519YaoActiveCapabilityRecord | null {
  if (!isObject(raw)) return null;
  const nearAccountId = toOptionalTrimmedString(raw.nearAccountId);
  if (!nearAccountId) return null;
  let runtimePolicyScope;
  try {
    runtimePolicyScope = normalizeRuntimePolicyScope(raw.runtimePolicyScope);
  } catch {
    return null;
  }
  switch (raw.version) {
    case 'wallet_ed25519_yao_registration_capability_v1': {
      const admissionRequest = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(
        raw.admissionRequest,
      );
      const activationResult = parseRouterAbEd25519YaoRegistrationActivationResultV1(
        raw.activationResult,
      );
      if (
        !admissionRequest.ok ||
        !activationResult.ok ||
        !Array.isArray(raw.activeCapabilityBinding) ||
        !equalBytes(raw.activeCapabilityBinding, activationResult.value.binding.session_id)
      ) {
        return null;
      }
      return {
        version: 'wallet_ed25519_yao_registration_capability_v1',
        activeCapabilityBinding: [...activationResult.value.binding.session_id],
        nearAccountId,
        admissionRequest: admissionRequest.value,
        activationResult: activationResult.value,
        runtimePolicyScope,
      };
    }
    case 'wallet_ed25519_yao_recovery_capability_v1': {
      const admissionRequest = parseRouterAbEd25519YaoRecoveryAdmissionRequestV1(
        raw.admissionRequest,
      );
      const activationResult = parseRouterAbEd25519YaoRecoveryActivationResultV1(
        raw.activationResult,
      );
      if (
        !admissionRequest.ok ||
        !activationResult.ok ||
        !Array.isArray(raw.activeCapabilityBinding) ||
        !equalBytes(
          raw.activeCapabilityBinding,
          admissionRequest.value.replacement_capability_binding,
        )
      ) {
        return null;
      }
      return {
        version: 'wallet_ed25519_yao_recovery_capability_v1',
        activeCapabilityBinding: [...admissionRequest.value.replacement_capability_binding],
        nearAccountId,
        admissionRequest: admissionRequest.value,
        activationResult: activationResult.value,
        runtimePolicyScope,
      };
    }
    default:
      return null;
  }
}

export function parseWalletEd25519SignerRecord(raw: unknown): WalletEd25519SignerRecord | null {
  if (!isObject(raw) || raw.version !== 'wallet_signer_ed25519_v1') return null;
  const walletId = parseWalletId(raw.walletId);
  const signerId = toOptionalTrimmedString(raw.signerId);
  const nearAccountId = toOptionalTrimmedString(raw.nearAccountId);
  const nearEd25519SigningKeyId = toOptionalTrimmedString(raw.nearEd25519SigningKeyId);
  const thresholdSessionId = toOptionalTrimmedString(raw.thresholdSessionId);
  const publicKey = toOptionalTrimmedString(raw.publicKey);
  const signingWorkerId = toOptionalTrimmedString(raw.signingWorkerId);
  const keyVersion = toOptionalTrimmedString(raw.keyVersion);
  const signingRootId = toOptionalTrimmedString(raw.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(raw.signingRootVersion);
  const signerSlot = Math.floor(Number(raw.signerSlot));
  const createdAtMs = normalizeTimestampMs(raw.createdAtMs);
  const updatedAtMs = normalizeTimestampMs(raw.updatedAtMs);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds);
  const activeYaoCapability = parseWalletEd25519YaoActiveCapabilityRecord(
    raw.activeYaoCapability,
  );
  let runtimePolicyScope;
  try {
    runtimePolicyScope = normalizeRuntimePolicyScope(raw.runtimePolicyScope);
  } catch {
    return null;
  }
  const expectedSigningRoot = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
  if (
    !walletId.ok ||
    !signerId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !thresholdSessionId ||
    !publicKey ||
    !signingWorkerId ||
    !keyVersion ||
    !signingRootId ||
    !signingRootVersion ||
    signingRootId !== expectedSigningRoot.signingRootId ||
    signingRootVersion !== expectedSigningRoot.signingRootVersion ||
    !participantIds ||
    !activeYaoCapability ||
    participantIds.length !== 2 ||
    participantIds[0] === participantIds[1] ||
    !Number.isSafeInteger(signerSlot) ||
    signerSlot <= 0 ||
    createdAtMs == null ||
    updatedAtMs == null ||
    raw.recoveryExportCapable !== true
  ) {
    return null;
  }
  const firstParticipantId = participantIds[0];
  const secondParticipantId = participantIds[1];
  if (firstParticipantId === undefined || secondParticipantId === undefined) return null;
  const capabilityApplication = activeYaoCapability.admissionRequest.application_binding;
  const capabilityScope = activeYaoCapability.admissionRequest.scope;
  const capabilityParticipants = activeYaoCapability.admissionRequest.participant_ids;
  if (
    activeYaoCapability.nearAccountId !== nearAccountId ||
    capabilityApplication.wallet_id !== walletId.value ||
    capabilityApplication.near_ed25519_signing_key_id !== nearEd25519SigningKeyId ||
    capabilityApplication.key_creation_signer_slot !== signerSlot ||
    capabilityApplication.signing_root_id !== signingRootId ||
    capabilityScope.account_id !== walletId.value ||
    capabilityScope.root_share_epoch !== signingRootVersion ||
    capabilityScope.signing_worker_id !== signingWorkerId ||
    capabilityParticipants[0] !== firstParticipantId ||
    capabilityParticipants[1] !== secondParticipantId ||
    alphabetizeStringify(activeYaoCapability.runtimePolicyScope) !==
      alphabetizeStringify(runtimePolicyScope)
  ) {
    return null;
  }
  return {
    version: 'wallet_signer_ed25519_v1',
    walletId: walletId.value,
    signerId,
    nearAccountId,
    nearEd25519SigningKeyId,
    thresholdSessionId,
    signerSlot,
    publicKey,
    signingWorkerId,
    keyVersion,
    recoveryExportCapable: true,
    participantIds: [firstParticipantId, secondParticipantId],
    signingRootId,
    signingRootVersion,
    runtimePolicyScope,
    activeYaoCapability,
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

export function prepareD1WalletPutSubjectStatement(input: {
  readonly database: D1DatabaseLike;
  readonly scope: D1WalletStoreScope;
  readonly record: WalletRecord;
}): D1PreparedStatementLike {
  const parsed = parseWalletRecord(input.record);
  if (!parsed) throw new Error('Invalid wallet record');
  return input.database
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
      input.scope.namespace,
      input.scope.orgId,
      input.scope.projectId,
      input.scope.envId,
      parsed.walletId,
      JSON.stringify(parsed),
      parsed.createdAtMs,
      parsed.updatedAtMs,
    );
}

export function prepareD1WalletPutSignerStatement(input: {
  readonly database: D1DatabaseLike;
  readonly scope: D1WalletStoreScope;
  readonly record: WalletSignerRecord;
}): D1PreparedStatementLike {
  const parsed = ensureWalletSignerRecord(input.record);
  return input.database
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
      input.scope.namespace,
      input.scope.orgId,
      input.scope.projectId,
      input.scope.envId,
      parsed.walletId,
      signerFamily(parsed),
      parsed.signerId,
      recordChainTargetKey(parsed),
      JSON.stringify(parsed),
      parsed.createdAtMs,
      parsed.updatedAtMs,
    );
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
    evmFamilySigningKeySlotId: input.walletKey.evmFamilySigningKeySlotId,
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

  async getEd25519Signer(input: {
    walletId: WalletId;
    nearAccountId: string;
    nearEd25519SigningKeyId: string;
  }): Promise<WalletEd25519SignerRecord | null> {
    await this.ensureSchema();
    const walletId = toOptionalTrimmedString(input.walletId);
    const nearAccountId = toOptionalTrimmedString(input.nearAccountId);
    const nearEd25519SigningKeyId = toOptionalTrimmedString(input.nearEd25519SigningKeyId);
    if (!walletId || !nearAccountId || !nearEd25519SigningKeyId) return null;
    const result = await this.database
      .prepare(
        `SELECT record_json
           FROM wallet_signers
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND wallet_id = ?
            AND signer_family = 'ed25519'
            AND json_extract(record_json, '$.nearAccountId') = ?
            AND json_extract(record_json, '$.nearEd25519SigningKeyId') = ?
          LIMIT 2`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        walletId,
        nearAccountId,
        nearEd25519SigningKeyId,
      )
      .all<D1WalletRow>();
    const rows = result.results || [];
    if (rows.length !== 1) return null;
    return parseWalletEd25519SignerRecord(parseD1JsonColumn(rows[0]?.record_json));
  }

  async getEd25519SignerBySlot(input: {
    walletId: WalletId;
    signerSlot: number;
  }): Promise<WalletEd25519SignerRecord | null> {
    await this.ensureSchema();
    const walletId = toOptionalTrimmedString(input.walletId);
    const signerSlot = Math.floor(Number(input.signerSlot));
    if (!walletId || !Number.isSafeInteger(signerSlot) || signerSlot <= 0) return null;
    const result = await this.database
      .prepare(
        `SELECT record_json
           FROM wallet_signers
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND wallet_id = ?
            AND signer_family = 'ed25519'
            AND json_extract(record_json, '$.signerSlot') = ?
          LIMIT 2`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        walletId,
        signerSlot,
      )
      .all<D1WalletRow>();
    const rows = result.results || [];
    if (rows.length === 0) return null;
    if (rows.length !== 1) throw new Error('Wallet has duplicate Ed25519 signer slots');
    const signer = parseWalletEd25519SignerRecord(parseD1JsonColumn(rows[0]?.record_json));
    if (!signer || signer.signerSlot !== signerSlot) {
      throw new Error('Wallet Ed25519 signer slot record is invalid');
    }
    return signer;
  }

  async listEd25519Signers(): Promise<readonly WalletEd25519SignerRecord[]> {
    await this.ensureSchema();
    const result = await this.database
      .prepare(
        `SELECT record_json
           FROM wallet_signers
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND signer_family = 'ed25519'
          ORDER BY wallet_id, signer_id`,
      )
      .bind(this.scope.namespace, this.scope.orgId, this.scope.projectId, this.scope.envId)
      .all<D1WalletRow>();
    const signers: WalletEd25519SignerRecord[] = [];
    for (const row of result.results || []) {
      const signer = parseWalletEd25519SignerRecord(parseD1JsonColumn(row.record_json));
      if (!signer) throw new Error('Wallet Ed25519 signer record is invalid');
      signers.push(signer);
    }
    return signers;
  }

  async putSubject(record: WalletRecord): Promise<void> {
    await this.ensureSchema();
    await prepareD1WalletPutSubjectStatement({
      database: this.database,
      scope: this.scope,
      record,
    }).run();
  }

  async putSigner(record: WalletSignerRecord): Promise<void> {
    await this.ensureSchema();
    await prepareD1WalletPutSignerStatement({
      database: this.database,
      scope: this.scope,
      record,
    }).run();
  }

  async putEd25519SignerIfSlotAvailable(record: WalletEd25519SignerRecord): Promise<boolean> {
    await this.ensureSchema();
    const parsed = parseWalletEd25519SignerRecord(record);
    if (!parsed) throw new Error('Invalid Ed25519 wallet signer record');
    const result = await this.database
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
        SELECT ?, ?, ?, ?, ?, 'ed25519', ?, NULL, ?, ?, ?
        WHERE NOT EXISTS (
          SELECT 1
            FROM wallet_signers
           WHERE namespace = ?
             AND org_id = ?
             AND project_id = ?
             AND env_id = ?
             AND wallet_id = ?
             AND signer_family = 'ed25519'
             AND json_extract(record_json, '$.signerSlot') = ?
        )`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        parsed.walletId,
        parsed.signerId,
        JSON.stringify(parsed),
        parsed.createdAtMs,
        parsed.updatedAtMs,
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        parsed.walletId,
        parsed.signerSlot,
      )
      .run();
    return d1ChangedRows(result) === 1;
  }

  async putSigners(records: readonly WalletSignerRecord[]): Promise<void> {
    for (const record of records) {
      await this.putSigner(record);
    }
  }
}
