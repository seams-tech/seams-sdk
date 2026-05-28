import { toTrimmedString } from '@shared/utils/validation';
import { SIGNER_KINDS } from '@shared/utils/signerDomain';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import type { KeyMaterialKind, KeyMaterialRecord } from '../keyMaterial.types';
import {
  buildEnvelopeAAD,
  normalizePayloadEnvelope,
  normalizeStoredPayloadRecord,
  sanitizePayload,
} from '../keyMaterialEnvelope';
import type {
  AccountRef,
  AccountSignerRecord,
  AccountSignerStatus,
  ChainAccountRecord,
  DBConstraintErrorCode,
  EnqueueSignerOperationInput,
  LastProfileState,
  LocalWalletAuthMethodRecord,
  NonceLaneLeaseStoreRecord,
  NonceLaneLeaseStoreRecordState,
  NonceLaneLockStoreRecord,
  ProfileAuthenticatorRecord,
  ProfileContinuitySnapshot,
  ProfileRecoveryEmailRecord,
  ProfileRecord,
  SignerMutationOptions,
  SignerOperationStatus,
  SignerOperationType,
  SignerOpOutboxRecord,
  UpsertChainAccountInput,
  UpsertProfileInput,
  UserPreferences,
} from '../passkeyClientDB.types';
import {
  planAccountSignerActivation,
  type ActivateAccountSignerInput,
  type ActivateAccountSignerResult,
  type StageAccountSignerInput,
  type StageAccountSignerResult,
} from '../accountSignerLifecycle';
import { parseLastProfileState } from '../lastProfileState';
import {
  normalizeIndexedDbAccountAddress,
  normalizeIndexedDbAccountModel,
  normalizeIndexedDbChainIdKey,
  normalizeLastUserScope,
  toIndexedDbChainTargetKey,
} from '../normalization';
import {
  SEAMS_WALLET_INDEXES,
  SEAMS_WALLET_STORES,
} from '../schemaNames';
import type { SeamsWalletDBManager, SeamsWalletTransactionContext } from './manager';

type AppStateRow<T = unknown> = {
  key: string;
  value: T;
};

type WalletRow = {
  wallet_id: string;
  rp_id: string;
  status: 'active';
  created_at: number;
  updated_at: number;
  record: ProfileRecord;
};

type WalletAuthMethodBaseRow = {
  wallet_auth_method_id: string;
  wallet_id: string;
  kind: LocalWalletAuthMethodRecord['kind'];
  auth_method: LocalWalletAuthMethodRecord['kind'];
  rp_id: string;
  auth_identifier_key: string;
  status: LocalWalletAuthMethodRecord['status'];
  updated_at: number;
  record: LocalWalletAuthMethodRecord;
};

type WalletPasskeyAuthMethodRow = WalletAuthMethodBaseRow & {
  kind: 'passkey';
  auth_method: 'passkey';
  record: LocalWalletAuthMethodRecord & { kind: 'passkey' };
  credential_id_b64u: string;
  credential_public_key_b64u: string;
  signer_slot: number;
  authenticator: ProfileAuthenticatorRecord;
  email_hash_hex?: never;
  challenge_id?: never;
};

type WalletEmailOtpAuthMethodRow = WalletAuthMethodBaseRow & {
  kind: 'email_otp';
  auth_method: 'email_otp';
  record: LocalWalletAuthMethodRecord & { kind: 'email_otp' };
  email_hash_hex: string;
  challenge_id: string;
  credential_id_b64u?: never;
  credential_public_key_b64u?: never;
  signer_slot?: never;
  authenticator?: never;
};

type WalletAuthMethodRow = WalletPasskeyAuthMethodRow | WalletEmailOtpAuthMethodRow;

type ChainAccountProjectionRow = {
  wallet_id: string;
  near_account_id: string;
  signer_slot: number;
  profile_id: string;
  chain_id_key: string;
  account_address: string;
  account_model: string;
  is_primary: boolean;
  updated_at: number;
  record: ChainAccountRecord;
};

type WalletSignerRow = {
  wallet_signer_id: string;
  wallet_id: string;
  kind: string;
  chain_target_key: string;
  near_signer_slot?: number;
  key_handle?: string;
  ecdsa_threshold_key_id?: string;
  threshold_owner_address?: string;
  status: AccountSignerStatus;
  updated_at: number;
  record: AccountSignerRecord;
};

type SignerOpsOutboxRow = {
  op_id: string;
  idempotency_key: string;
  status: SignerOperationStatus;
  next_attempt_at: number;
  wallet_id: string;
  chain_target_key: string;
  updated_at: number;
  record: SignerOpOutboxRecord;
};

type RecoveryEmailRow = {
  wallet_id: string;
  hash_hex: string;
  email: string;
  added_at: number;
  updated_at: number;
};

type NonceLaneLeaseRow = {
  lease_id: string;
  lane_key: string;
  account_id: string;
  state: NonceLaneLeaseStoreRecordState;
  expires_at_ms: number;
  record: NonceLaneLeaseStoreRecord;
};

type NonceLaneLockRow = {
  lock_key: string;
  owner_id: string;
  fencing_token: string;
  acquired_at_ms: number;
  expires_at_ms: number;
  updated_at_ms: number;
};

type KeyMaterialRow = {
  key_material_id: string;
  wallet_id: string;
  wallet_signer_id: string;
  chain_target_key: string;
  key_handle: string;
  public_key: string;
  updated_at: number;
  record: KeyMaterialRecord;
};

export type StoreWalletRegistrationFinalizeBatchInput = {
  profiles: readonly UpsertProfileInput[];
  initialAuthMethod: LocalWalletAuthMethodRecord;
  authenticators: readonly ProfileAuthenticatorRecord[];
  signerActivations: readonly ActivateAccountSignerInput[];
  keyMaterials: readonly KeyMaterialRecord[];
  lastProfileState?: {
    profileId: string;
    activeSignerSlot: number;
    scope?: string | null;
  };
};

export type StoreWalletSignerFinalizeBatchInput = {
  profiles: readonly UpsertProfileInput[];
  signerActivations: readonly ActivateAccountSignerInput[];
  keyMaterials: readonly KeyMaterialRecord[];
  lastProfileState?: {
    profileId: string;
    activeSignerSlot: number;
    scope?: string | null;
  };
};

export type StoreWalletRegistrationFinalizeBatchResult = {
  signerActivations: ActivateAccountSignerResult[];
};

const DEFAULT_NONCE_LANE_LOCK_TTL_MS = 5_000;
const DEFAULT_NONCE_LANE_LOCK_WAIT_TIMEOUT_MS = 3_000;
const DEFAULT_NONCE_LANE_LOCK_POLL_MS = 25;
const LAST_PROFILE_STATE_APP_STATE_KEY = 'lastProfileState';
const DEFAULT_WALLET_RP_ID = 'local';
const CHAIN_ACCOUNT_PROJECTION_SIGNER_SLOT = 0;

export class SeamsWalletDBConstraintError extends Error {
  readonly code: DBConstraintErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(code: DBConstraintErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'SeamsWalletDBConstraintError';
    this.code = code;
    this.details = details;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function createRandomToken(prefix: string): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const suffix = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${prefix}-${suffix}`;
}

function nonceLeaseAccountId(record: NonceLaneLeaseStoreRecord): string {
  if (record.family === 'near') return record.accountId;
  return record.accountId || record.sender;
}

function nonceLeaseRow(record: NonceLaneLeaseStoreRecord): NonceLaneLeaseRow {
  const leaseId = toTrimmedString(record.leaseId || '');
  const laneKey = toTrimmedString(record.laneKey || '');
  const accountId = toTrimmedString(nonceLeaseAccountId(record) || '');
  if (!leaseId || !laneKey || !accountId) {
    throw new Error('[SeamsWalletDB] nonce lease requires leaseId, laneKey, and account identity');
  }
  return {
    lease_id: leaseId,
    lane_key: laneKey,
    account_id: accountId,
    state: record.state,
    expires_at_ms: Math.floor(Number(record.expiresAtMs)),
    record,
  };
}

function parseNonceLeaseRow(value: unknown): NonceLaneLeaseStoreRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Partial<NonceLaneLeaseRow>;
  const record = row.record;
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  if (row.lease_id !== record.leaseId) return null;
  if (row.lane_key !== record.laneKey) return null;
  if (row.account_id !== nonceLeaseAccountId(record)) return null;
  if (row.state !== record.state) return null;
  if (row.expires_at_ms !== Math.floor(Number(record.expiresAtMs))) return null;
  return record;
}

function profileRecoveryEmailFromRow(value: unknown): ProfileRecoveryEmailRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Partial<RecoveryEmailRow>;
  const profileId = toTrimmedString(row.wallet_id || '');
  const hashHex = toTrimmedString(row.hash_hex || '');
  const email = toTrimmedString(row.email || '');
  const addedAt = Math.floor(Number(row.added_at));
  if (!profileId || !hashHex || !email || !Number.isSafeInteger(addedAt)) return null;
  return {
    profileId,
    hashHex,
    email,
    addedAt,
  };
}

function keyRangeUpperBound(value: number): IDBKeyRange {
  return IDBKeyRange.upperBound(value);
}

async function deleteRowsByIndex(args: {
  store: any;
  indexName: string;
  key: IDBValidKey | IDBKeyRange;
}): Promise<void> {
  let cursor = await args.store.index(args.indexName).openCursor(args.key);
  while (cursor) {
    await cursor.delete();
    cursor = await cursor.continue();
  }
}

function scopedLastProfileStateAppStateKey(scope?: string | null): string {
  const normalized = normalizeLastUserScope(scope);
  return normalized
    ? `${LAST_PROFILE_STATE_APP_STATE_KEY}::${normalized}`
    : LAST_PROFILE_STATE_APP_STATE_KEY;
}

function chainAccountProjectionId(args: { chainIdKey: string; accountAddress: string }): string {
  return `${args.chainIdKey}\0${args.accountAddress}`;
}

function walletSignerId(args: {
  chainIdKey: string;
  accountAddress: string;
  signerId: string;
}): string {
  return [args.chainIdKey, args.accountAddress, args.signerId].join('\0');
}

function signerChainTargetKey(args: { chainIdKey: string; accountAddress: string }): string {
  return [args.chainIdKey, args.accountAddress].join('\0');
}

function normalizeEcdsaChainTargetKey(value: unknown): string {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (!obj) return '';
  const kind = toTrimmedString(obj.kind || '');
  const chainId = Number(obj.chainId);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) return '';
  if (kind === 'evm') {
    if (toTrimmedString(obj.namespace || '') !== 'eip155') return '';
    return toIndexedDbChainTargetKey({
      kind: 'evm',
      namespace: 'eip155',
      chainId,
      networkSlug: toTrimmedString(obj.networkSlug || ''),
    });
  }
  if (kind === 'tempo') {
    return toIndexedDbChainTargetKey({
      kind: 'tempo',
      chainId,
      networkSlug: toTrimmedString(obj.networkSlug || ''),
    });
  }
  return '';
}

type WalletSignerScalarMirrors = {
  chainTargetKey: string;
  nearSignerSlot?: number;
  keyHandle?: string;
  ecdsaThresholdKeyId?: string;
  thresholdOwnerAddress?: string;
};

function walletSignerScalarMirrors(record: AccountSignerRecord): WalletSignerScalarMirrors {
  if (record.signerKind === SIGNER_KINDS.thresholdEcdsa) {
    const metadata = record.metadata || {};
    const keyHandle = toTrimmedString(metadata.keyHandle || '');
    const ecdsaThresholdKeyId = toTrimmedString(metadata.ecdsaThresholdKeyId || '');
    const thresholdOwnerAddress = normalizeIndexedDbAccountAddress(
      metadata.thresholdOwnerAddress || metadata.ownerAddress || '',
    );
    const chainTargetKey = normalizeEcdsaChainTargetKey(metadata.chainTarget);
    if (!keyHandle || !ecdsaThresholdKeyId || !thresholdOwnerAddress || !chainTargetKey) {
      throw new Error(
        '[SeamsWalletDB] threshold ECDSA signer requires keyHandle, ecdsaThresholdKeyId, thresholdOwnerAddress, and chainTarget',
      );
    }
    return {
      chainTargetKey,
      keyHandle,
      ecdsaThresholdKeyId,
      thresholdOwnerAddress,
    };
  }

  const signerSlot = Number(record.signerSlot);
  if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
    throw new Error('[SeamsWalletDB] Ed25519 signer requires a positive signerSlot');
  }
  return {
    chainTargetKey: signerChainTargetKey({
      chainIdKey: record.chainIdKey,
      accountAddress: record.accountAddress,
    }),
    nearSignerSlot: signerSlot,
  };
}

function shouldWriteNearAccountProjection(args: {
  accountModel: string;
  chainIdKey: string;
}): boolean {
  return args.accountModel === 'near-native' || args.chainIdKey.startsWith('near:');
}

function makeConstraintError(
  code: DBConstraintErrorCode,
  message: string,
  details?: Record<string, unknown>,
): SeamsWalletDBConstraintError {
  return new SeamsWalletDBConstraintError(code, message, details);
}

function profileRow(input: UpsertProfileInput, existing?: ProfileRecord): WalletRow {
  const profileId = toTrimmedString(input.profileId || '');
  if (!profileId) throw new Error('[SeamsWalletDB] profileId is required');
  const now = Date.now();
  const passkeyCredential = input.passkeyCredential?.rawId
    ? input.passkeyCredential
    : existing?.passkeyCredential;
  const record: ProfileRecord = {
    profileId,
    defaultSignerSlot: input.defaultSignerSlot ?? existing?.defaultSignerSlot ?? 1,
    ...(passkeyCredential ? { passkeyCredential } : {}),
    preferences: input.preferences ?? existing?.preferences,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };
  return {
    wallet_id: profileId,
    rp_id: DEFAULT_WALLET_RP_ID,
    status: 'active',
    created_at: record.createdAt,
    updated_at: record.updatedAt,
    record,
  };
}

function parseProfileRow(value: unknown): ProfileRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Partial<WalletRow>;
  const record = row.record;
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  if (row.wallet_id !== record.profileId) return null;
  if (row.created_at !== record.createdAt) return null;
  if (row.updated_at !== record.updatedAt) return null;
  return record;
}

function walletAuthMethodIdentifier(record: LocalWalletAuthMethodRecord): string {
  switch (record.kind) {
    case 'passkey':
      return toTrimmedString(record.credentialIdB64u || '');
    case 'email_otp':
      return toTrimmedString(record.emailHashHex || '');
    default: {
      const _exhaustive: never = record;
      throw new Error(`[SeamsWalletDB] Unsupported auth-method binding: ${String(_exhaustive)}`);
    }
  }
}

function walletAuthMethodId(record: LocalWalletAuthMethodRecord): string {
  return [
    toTrimmedString(record.walletId || ''),
    record.kind,
    toTrimmedString(record.rpId || ''),
    walletAuthMethodIdentifier(record),
  ].join('\0');
}

function walletAuthMethodFields(
  record: LocalWalletAuthMethodRecord,
): WalletAuthMethodBaseRow {
  if (record.version !== 'wallet_auth_method_v1') {
    throw new Error('[SeamsWalletDB] auth-method binding version is invalid');
  }
  const walletId = toTrimmedString(record.walletId || '');
  const rpId = toTrimmedString(record.rpId || '');
  const authIdentifierKey = walletAuthMethodIdentifier(record);
  const createdAtMs = Math.floor(Number(record.createdAtMs));
  const updatedAtMs = Math.floor(Number(record.updatedAtMs));
  if (!walletId || !rpId || !authIdentifierKey) {
    throw new Error(
      '[SeamsWalletDB] auth-method binding requires walletId, rpId, and branch identifier',
    );
  }
  if (record.status !== 'active' && record.status !== 'revoked') {
    throw new Error('[SeamsWalletDB] auth-method binding status is invalid');
  }
  if (record.localStatus !== 'synced' && record.localStatus !== 'pending') {
    throw new Error('[SeamsWalletDB] auth-method binding localStatus is invalid');
  }
  if (!Number.isSafeInteger(createdAtMs)) {
    throw new Error('[SeamsWalletDB] auth-method binding createdAtMs is invalid');
  }
  if (!Number.isSafeInteger(updatedAtMs)) {
    throw new Error('[SeamsWalletDB] auth-method binding updatedAtMs is invalid');
  }
  if (record.kind === 'passkey') {
    if (record.emailHashHex != null || record.challengeId != null) {
      throw new Error('[SeamsWalletDB] passkey auth-method binding has Email OTP fields');
    }
    if (!toTrimmedString(record.credentialPublicKeyB64u || '')) {
      throw new Error('[SeamsWalletDB] passkey auth-method binding requires credential public key');
    }
    if (!Number.isSafeInteger(record.counter) || record.counter < 0) {
      throw new Error('[SeamsWalletDB] passkey auth-method binding counter is invalid');
    }
  }
  if (record.kind === 'email_otp') {
    if (
      record.credentialIdB64u != null ||
      record.credentialPublicKeyB64u != null ||
      record.counter != null
    ) {
      throw new Error('[SeamsWalletDB] Email OTP auth-method binding has passkey fields');
    }
    if (!toTrimmedString(record.challengeId || '')) {
      throw new Error('[SeamsWalletDB] Email OTP auth-method binding requires challengeId');
    }
  }
  return {
    wallet_auth_method_id: walletAuthMethodId(record),
    wallet_id: walletId,
    kind: record.kind,
    auth_method: record.kind,
    rp_id: rpId,
    auth_identifier_key: authIdentifierKey,
    status: record.status,
    updated_at: updatedAtMs,
    record,
  };
}

function isoTimestampFromMs(ms: number): string {
  return new Date(ms).toISOString();
}

function timestampMsFromIso(value: string, fallbackMs: number): number {
  const parsed = Date.parse(value);
  return Number.isSafeInteger(parsed) ? parsed : fallbackMs;
}

function normalizeAuthenticatorRecord(record: ProfileAuthenticatorRecord): ProfileAuthenticatorRecord {
  const profileId = toTrimmedString(record.profileId || '');
  const credentialId = toTrimmedString(record.credentialId || '');
  const signerSlot = Number(record.signerSlot);
  if (!profileId || !credentialId) {
    throw new Error('[SeamsWalletDB] profileId and credentialId are required for authenticators');
  }
  if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
    throw new Error('[SeamsWalletDB] authenticator signerSlot must be an integer >= 1');
  }
  const credentialPublicKey = record.credentialPublicKey;
  if (!(credentialPublicKey instanceof Uint8Array) || credentialPublicKey.byteLength === 0) {
    throw new Error('[SeamsWalletDB] authenticator credentialPublicKey must be a non-empty Uint8Array');
  }
  return {
    profileId,
    signerSlot,
    credentialId,
    credentialPublicKey,
    ...(Array.isArray(record.transports) ? { transports: record.transports } : {}),
    ...(record.name ? { name: String(record.name) } : {}),
    registered: toTrimmedString(record.registered || ''),
    syncedAt: toTrimmedString(record.syncedAt || ''),
  };
}

function passkeyAuthenticatorFromBinding(
  record: LocalWalletAuthMethodRecord & { kind: 'passkey' },
  signerSlot: number,
): ProfileAuthenticatorRecord {
  const normalizedSignerSlot = Number(signerSlot);
  if (!Number.isSafeInteger(normalizedSignerSlot) || normalizedSignerSlot < 1) {
    throw new Error('[SeamsWalletDB] passkey auth-method signerSlot must be an integer >= 1');
  }
  return normalizeAuthenticatorRecord({
    profileId: record.walletId,
    signerSlot: normalizedSignerSlot,
    credentialId: record.credentialIdB64u,
    credentialPublicKey: base64UrlDecode(record.credentialPublicKeyB64u),
    registered: isoTimestampFromMs(record.createdAtMs),
    syncedAt: isoTimestampFromMs(record.updatedAtMs),
  });
}

function passkeyBindingFromAuthenticator(
  authenticator: ProfileAuthenticatorRecord,
  existing?: LocalWalletAuthMethodRecord & { kind: 'passkey' },
): LocalWalletAuthMethodRecord & { kind: 'passkey' } {
  const normalized = normalizeAuthenticatorRecord(authenticator);
  const credentialPublicKeyB64u = base64UrlEncode(normalized.credentialPublicKey);
  if (existing) {
    if (existing.walletId !== normalized.profileId) {
      throw new Error('[SeamsWalletDB] passkey auth-method walletId does not match authenticator profileId');
    }
    if (existing.credentialIdB64u !== normalized.credentialId) {
      throw new Error('[SeamsWalletDB] passkey auth-method credentialId does not match authenticator credentialId');
    }
    if (existing.credentialPublicKeyB64u !== credentialPublicKeyB64u) {
      throw new Error('[SeamsWalletDB] passkey auth-method public key does not match authenticator public key');
    }
    return existing;
  }
  const nowMs = Date.now();
  return {
    version: 'wallet_auth_method_v1',
    kind: 'passkey',
    status: 'active',
    localStatus: 'synced',
    walletId: walletIdFromString(normalized.profileId),
    rpId: DEFAULT_WALLET_RP_ID,
    credentialIdB64u: normalized.credentialId,
    credentialPublicKeyB64u,
    counter: 0,
    createdAtMs: timestampMsFromIso(normalized.registered, nowMs),
    updatedAtMs: timestampMsFromIso(normalized.syncedAt, nowMs),
  };
}

function passkeyAuthMethodRow(input: {
  binding: LocalWalletAuthMethodRecord & { kind: 'passkey' };
  authenticator: ProfileAuthenticatorRecord;
}): WalletPasskeyAuthMethodRow {
  const base = walletAuthMethodFields(input.binding);
  const authenticator = normalizeAuthenticatorRecord(input.authenticator);
  const credentialPublicKeyB64u = base64UrlEncode(authenticator.credentialPublicKey);
  if (base.kind !== 'passkey') {
    throw new Error('[SeamsWalletDB] passkey auth-method row requires a passkey binding');
  }
  if (authenticator.profileId !== base.wallet_id) {
    throw new Error('[SeamsWalletDB] passkey auth-method authenticator profileId mismatch');
  }
  if (authenticator.credentialId !== input.binding.credentialIdB64u) {
    throw new Error('[SeamsWalletDB] passkey auth-method authenticator credentialId mismatch');
  }
  if (credentialPublicKeyB64u !== input.binding.credentialPublicKeyB64u) {
    throw new Error('[SeamsWalletDB] passkey auth-method authenticator public key mismatch');
  }
  return {
    ...base,
    kind: 'passkey',
    auth_method: 'passkey',
    record: input.binding,
    credential_id_b64u: input.binding.credentialIdB64u,
    credential_public_key_b64u: input.binding.credentialPublicKeyB64u,
    signer_slot: authenticator.signerSlot,
    authenticator,
  };
}

function emailOtpAuthMethodRow(
  record: LocalWalletAuthMethodRecord & { kind: 'email_otp' },
): WalletEmailOtpAuthMethodRow {
  const base = walletAuthMethodFields(record);
  if (base.kind !== 'email_otp') {
    throw new Error('[SeamsWalletDB] Email OTP auth-method row requires an Email OTP binding');
  }
  return {
    ...base,
    kind: 'email_otp',
    auth_method: 'email_otp',
    record,
    email_hash_hex: record.emailHashHex,
    challenge_id: record.challengeId,
  };
}

function walletAuthMethodRowFromBinding(
  record: LocalWalletAuthMethodRecord,
  signerSlot: number,
): WalletAuthMethodRow {
  switch (record.kind) {
    case 'passkey':
      return passkeyAuthMethodRow({
        binding: record,
        authenticator: passkeyAuthenticatorFromBinding(record, signerSlot),
      });
    case 'email_otp':
      return emailOtpAuthMethodRow(record);
    default: {
      const _exhaustive: never = record;
      throw new Error(`[SeamsWalletDB] Unsupported auth-method row: ${String(_exhaustive)}`);
    }
  }
}

function walletAuthMethodRowFromAuthenticator(
  record: ProfileAuthenticatorRecord,
  existing?: WalletPasskeyAuthMethodRow,
): WalletPasskeyAuthMethodRow {
  const authenticator = normalizeAuthenticatorRecord(record);
  return passkeyAuthMethodRow({
    binding: passkeyBindingFromAuthenticator(authenticator, existing?.record),
    authenticator,
  });
}

function parseWalletAuthMethodStorageRow(value: unknown): WalletAuthMethodRow | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Partial<WalletAuthMethodRow>;
  const record = row.record;
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  let normalized: WalletAuthMethodRow;
  try {
    if (record.kind === 'passkey') {
      if (!row.authenticator) return null;
      normalized = passkeyAuthMethodRow({
        binding: record,
        authenticator: row.authenticator,
      });
    } else if (record.kind === 'email_otp') {
      normalized = emailOtpAuthMethodRow(record);
    } else {
      return null;
    }
  } catch {
    return null;
  }
  if (row.wallet_auth_method_id !== normalized.wallet_auth_method_id) return null;
  if (row.wallet_id !== normalized.wallet_id) return null;
  if (row.kind !== normalized.kind) return null;
  if (row.auth_method !== normalized.auth_method) return null;
  if (row.rp_id !== normalized.rp_id) return null;
  if (row.auth_identifier_key !== normalized.auth_identifier_key) return null;
  if (row.status !== normalized.status) return null;
  if (row.updated_at !== normalized.updated_at) return null;
  if (normalized.kind === 'passkey') {
    if (row.credential_id_b64u !== normalized.credential_id_b64u) return null;
    if (row.credential_public_key_b64u !== normalized.credential_public_key_b64u) return null;
    if (row.signer_slot !== normalized.signer_slot) return null;
  } else {
    if (row.email_hash_hex !== normalized.email_hash_hex) return null;
    if (row.challenge_id !== normalized.challenge_id) return null;
  }
  return normalized;
}

function parseWalletAuthMethodRow(
  value: unknown,
): LocalWalletAuthMethodRecord | null {
  const row = parseWalletAuthMethodStorageRow(value);
  if (!row) return null;
  return row.record;
}

function parseAuthenticatorRow(value: unknown): ProfileAuthenticatorRecord | null {
  const row = parseWalletAuthMethodStorageRow(value);
  if (!row || row.kind !== 'passkey') return null;
  return row.authenticator;
}

function passkeyCredentialIndexKey(row: WalletPasskeyAuthMethodRow): string {
  return ['passkey', row.rp_id, row.credential_id_b64u].join('\0');
}

function walletAuthMethodRowsForRegistrationFinalize(
  input: StoreWalletRegistrationFinalizeBatchInput,
): WalletAuthMethodRow[] {
  const authenticators = input.authenticators.map((authenticator) =>
    normalizeAuthenticatorRecord(authenticator),
  );
  const rows = new Map<string, WalletAuthMethodRow>();
  const credentialRows = new Map<string, WalletPasskeyAuthMethodRow>();

  if (input.initialAuthMethod.kind === 'passkey') {
    const matchingAuthenticator = authenticators.find(
      (authenticator) =>
        authenticator.profileId === input.initialAuthMethod.walletId &&
        authenticator.credentialId === input.initialAuthMethod.credentialIdB64u,
    );
    if (!matchingAuthenticator) {
      throw new Error(
        '[SeamsWalletDB] passkey registration finalize requires matching authenticator material',
      );
    }
    const row = passkeyAuthMethodRow({
      binding: input.initialAuthMethod,
      authenticator: matchingAuthenticator,
    });
    rows.set(row.wallet_auth_method_id, row);
    credentialRows.set(passkeyCredentialIndexKey(row), row);
  } else {
    const row = emailOtpAuthMethodRow(input.initialAuthMethod);
    rows.set(row.wallet_auth_method_id, row);
  }

  for (const authenticator of authenticators) {
    const row = walletAuthMethodRowFromAuthenticator(authenticator);
    const credentialKey = passkeyCredentialIndexKey(row);
    const existingCredentialRow = credentialRows.get(credentialKey);
    if (existingCredentialRow) {
      if (existingCredentialRow.credential_public_key_b64u !== row.credential_public_key_b64u) {
        throw new Error('[SeamsWalletDB] duplicate passkey credential has conflicting public key');
      }
      if (existingCredentialRow.wallet_auth_method_id === row.wallet_auth_method_id) {
        rows.set(row.wallet_auth_method_id, row);
        credentialRows.set(credentialKey, row);
      }
      continue;
    }
    rows.set(row.wallet_auth_method_id, row);
    credentialRows.set(credentialKey, row);
  }

  return [...rows.values()];
}

function chainAccountProjectionRow(
  input: UpsertChainAccountInput,
  existing?: ChainAccountRecord,
): ChainAccountProjectionRow {
  const profileId = toTrimmedString(input.profileId || '');
  const chainIdKey = normalizeIndexedDbChainIdKey(input.chainIdKey);
  const accountAddress = normalizeIndexedDbAccountAddress(input.accountAddress);
  const accountModel = normalizeIndexedDbAccountModel(input.accountModel);
  if (!profileId || !chainIdKey || !accountAddress) {
    throw new Error('[SeamsWalletDB] profileId, chainIdKey, and accountAddress are required');
  }
  if (!accountModel) {
    throw new Error('[SeamsWalletDB] accountModel is required');
  }
  const now = Date.now();
  const record: ChainAccountRecord = {
    profileId,
    chainIdKey,
    accountAddress,
    accountModel,
    isPrimary: input.isPrimary ?? existing?.isPrimary ?? false,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };
  return {
    wallet_id: profileId,
    near_account_id: chainAccountProjectionId({ chainIdKey, accountAddress }),
    signer_slot: CHAIN_ACCOUNT_PROJECTION_SIGNER_SLOT,
    profile_id: profileId,
    chain_id_key: chainIdKey,
    account_address: accountAddress,
    account_model: accountModel,
    is_primary: !!record.isPrimary,
    updated_at: record.updatedAt,
    record,
  };
}

function parseChainAccountProjectionRow(value: unknown): ChainAccountRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Partial<ChainAccountProjectionRow>;
  const record = row.record;
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  if (row.wallet_id !== record.profileId) return null;
  if (row.profile_id !== record.profileId) return null;
  if (row.chain_id_key !== record.chainIdKey) return null;
  if (row.account_address !== record.accountAddress) return null;
  if (row.account_model !== record.accountModel) return null;
  if (row.is_primary !== !!record.isPrimary) return null;
  if (row.updated_at !== record.updatedAt) return null;
  if (
    row.near_account_id !==
    chainAccountProjectionId({
      chainIdKey: record.chainIdKey,
      accountAddress: record.accountAddress,
    })
  ) {
    return null;
  }
  return record;
}

function accountSignerRow(record: AccountSignerRecord): WalletSignerRow {
  const profileId = toTrimmedString(record.profileId || '');
  const chainIdKey = normalizeIndexedDbChainIdKey(record.chainIdKey);
  const accountAddress = normalizeIndexedDbAccountAddress(record.accountAddress);
  const signerId = toTrimmedString(record.signerId || '');
  const signerKind = toTrimmedString(record.signerKind || '');
  if (!profileId || !chainIdKey || !accountAddress || !signerId || !signerKind) {
    throw new Error(
      '[SeamsWalletDB] signer requires profileId, chainIdKey, accountAddress, signerId, and signerKind',
    );
  }
  const mirrors = walletSignerScalarMirrors({
    ...record,
    profileId,
    chainIdKey,
    accountAddress,
    signerId,
  });
  return {
    wallet_signer_id: walletSignerId({ chainIdKey, accountAddress, signerId }),
    wallet_id: profileId,
    kind: signerKind,
    chain_target_key: mirrors.chainTargetKey,
    ...(mirrors.nearSignerSlot != null ? { near_signer_slot: mirrors.nearSignerSlot } : {}),
    ...(mirrors.keyHandle ? { key_handle: mirrors.keyHandle } : {}),
    ...(mirrors.ecdsaThresholdKeyId
      ? { ecdsa_threshold_key_id: mirrors.ecdsaThresholdKeyId }
      : {}),
    ...(mirrors.thresholdOwnerAddress
      ? { threshold_owner_address: mirrors.thresholdOwnerAddress }
      : {}),
    status: record.status,
    updated_at: record.updatedAt,
    record: {
      ...record,
      profileId,
      chainIdKey,
      accountAddress,
      signerId,
    },
  };
}

function parseAccountSignerRow(value: unknown): AccountSignerRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Partial<WalletSignerRow>;
  const record = row.record;
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  if (
    row.wallet_signer_id !==
    walletSignerId({
      chainIdKey: record.chainIdKey,
      accountAddress: record.accountAddress,
      signerId: record.signerId,
    })
  ) {
    return null;
  }
  if (row.wallet_id !== record.profileId) return null;
  if (row.kind !== record.signerKind) return null;
  let mirrors: WalletSignerScalarMirrors;
  try {
    mirrors = walletSignerScalarMirrors(record);
  } catch {
    return null;
  }
  if (row.chain_target_key !== mirrors.chainTargetKey) return null;
  if (row.near_signer_slot !== mirrors.nearSignerSlot) return null;
  if (row.key_handle !== mirrors.keyHandle) return null;
  if (row.ecdsa_threshold_key_id !== mirrors.ecdsaThresholdKeyId) return null;
  if (row.threshold_owner_address !== mirrors.thresholdOwnerAddress) return null;
  if (row.status !== record.status) return null;
  if (row.updated_at !== record.updatedAt) return null;
  return record;
}

function signerOutboxRow(record: SignerOpOutboxRecord): SignerOpsOutboxRow {
  const opId = toTrimmedString(record.opId || '');
  const idempotencyKey = toTrimmedString(record.idempotencyKey || '');
  const chainIdKey = normalizeIndexedDbChainIdKey(record.chainIdKey);
  const accountAddress = normalizeIndexedDbAccountAddress(record.accountAddress);
  const signerId = toTrimmedString(record.signerId || '');
  if (!opId || !idempotencyKey || !chainIdKey || !accountAddress || !signerId) {
    throw new Error(
      '[SeamsWalletDB] signer op requires opId, idempotencyKey, chainIdKey, accountAddress, and signerId',
    );
  }
  return {
    op_id: opId,
    idempotency_key: idempotencyKey,
    status: record.status,
    next_attempt_at: record.nextAttemptAt,
    wallet_id: toTrimmedString(String(record.payload?.profileId || '')),
    chain_target_key: signerChainTargetKey({ chainIdKey, accountAddress }),
    updated_at: record.updatedAt,
    record: {
      ...record,
      opId,
      idempotencyKey,
      chainIdKey,
      accountAddress,
      signerId,
    },
  };
}

function parseSignerOutboxRow(value: unknown): SignerOpOutboxRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Partial<SignerOpsOutboxRow>;
  const record = row.record;
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  if (row.op_id !== record.opId) return null;
  if (row.idempotency_key !== record.idempotencyKey) return null;
  if (row.status !== record.status) return null;
  if (row.next_attempt_at !== record.nextAttemptAt) return null;
  if (
    row.chain_target_key !==
    signerChainTargetKey({ chainIdKey: record.chainIdKey, accountAddress: record.accountAddress })
  ) {
    return null;
  }
  return record;
}

function keyMaterialId(args: {
  walletSignerId: string;
  keyKind: string;
}): string {
  return [args.walletSignerId, args.keyKind].join('\0');
}

function walletSignerIdForKeyMaterial(record: KeyMaterialRecord): string {
  return walletSignerId({
    chainIdKey: record.chainIdKey,
    accountAddress: record.accountAddress,
    signerId: record.signerId,
  });
}

function keyMaterialRow(data: KeyMaterialRecord): KeyMaterialRow {
  const profileId = toTrimmedString(data.profileId || '');
  const signerId = toTrimmedString(data.signerId || '');
  const wrapKeySalt = toTrimmedString(data.wrapKeySalt || '');
  const chainIdKey = toTrimmedString(data.chainIdKey || '').toLowerCase();
  const accountAddress = normalizeIndexedDbAccountAddress(data.accountAddress);
  const keyKind = toTrimmedString(data.keyKind || '');
  const algorithm = toTrimmedString(data.algorithm || '');
  const publicKey = toTrimmedString(data.publicKey || '');
  if (!profileId) {
    throw new Error('[SeamsWalletDB] Missing profileId for key material record');
  }
  if (!Number.isSafeInteger(data.signerSlot) || data.signerSlot < 1) {
    throw new Error('[SeamsWalletDB] Invalid signerSlot for key material record');
  }
  if (!chainIdKey) {
    throw new Error('[SeamsWalletDB] Missing chainIdKey for key material record');
  }
  if (!accountAddress) {
    throw new Error('[SeamsWalletDB] Missing accountAddress for key material record');
  }
  if (!signerId) {
    throw new Error('[SeamsWalletDB] Missing signerId for key material record');
  }
  if (!keyKind) {
    throw new Error('[SeamsWalletDB] Missing keyKind for key material record');
  }
  if (!algorithm) {
    throw new Error('[SeamsWalletDB] Missing algorithm for key material record');
  }
  if (!publicKey) {
    throw new Error('[SeamsWalletDB] Missing publicKey for key material record');
  }
  if (typeof data.timestamp !== 'number') {
    throw new Error('[SeamsWalletDB] Missing timestamp for key material record');
  }
  if (!Number.isSafeInteger(data.schemaVersion) || data.schemaVersion < 1) {
    throw new Error('[SeamsWalletDB] Invalid schemaVersion for key material record');
  }

  const expectedAAD = buildEnvelopeAAD({
    profileId,
    signerSlot: data.signerSlot,
    chainIdKey,
    accountAddress,
    keyKind,
    schemaVersion: data.schemaVersion,
    signerId,
  });
  const payloadEnvelope = normalizePayloadEnvelope(
    data.payloadEnvelope,
    expectedAAD,
    `${profileId}/${data.signerSlot}/${chainIdKey}/${keyKind}`,
  );
  const payload = sanitizePayload(data.payload);
  const record: KeyMaterialRecord = {
    profileId,
    signerSlot: data.signerSlot,
    chainIdKey,
    accountAddress,
    keyKind,
    algorithm,
    publicKey,
    signerId,
    ...(wrapKeySalt ? { wrapKeySalt } : {}),
    ...(payload ? { payload } : {}),
    ...(payloadEnvelope ? { payloadEnvelope } : {}),
    timestamp: data.timestamp,
    schemaVersion: data.schemaVersion,
  };
  const walletSignerId = walletSignerIdForKeyMaterial(record);
  const chainTargetKey = signerChainTargetKey({ chainIdKey, accountAddress });
  return {
    key_material_id: keyMaterialId({ walletSignerId, keyKind }),
    wallet_id: profileId,
    wallet_signer_id: walletSignerId,
    chain_target_key: chainTargetKey,
    key_handle: signerId,
    public_key: publicKey,
    updated_at: data.timestamp,
    record,
  };
}

function signerKeyMaterialPairKey(args: {
  profileId: string;
  chainIdKey: string;
  accountAddress: string;
  signerId: string;
  signerSlot: number;
}): string {
  return [
    toTrimmedString(args.profileId || ''),
    normalizeIndexedDbChainIdKey(args.chainIdKey),
    normalizeIndexedDbAccountAddress(args.accountAddress),
    toTrimmedString(args.signerId || ''),
    String(Number(args.signerSlot)),
  ].join('\0');
}

function assertSignerKeyMaterialPairs(args: {
  signers: readonly AccountSignerRecord[];
  keyMaterials: readonly KeyMaterialRecord[];
}): void {
  const signerKeys = new Set(
    args.signers.map((signer) =>
      signerKeyMaterialPairKey({
        profileId: signer.profileId,
        chainIdKey: signer.chainIdKey,
        accountAddress: signer.accountAddress,
        signerId: signer.signerId,
        signerSlot: signer.signerSlot,
      }),
    ),
  );
  const keyMaterialKeys = new Set(
    args.keyMaterials
      .filter((keyMaterial) => keyMaterial.keyKind === 'threshold_share_v1')
      .map((keyMaterial) =>
        signerKeyMaterialPairKey({
          profileId: keyMaterial.profileId,
          chainIdKey: keyMaterial.chainIdKey,
          accountAddress: keyMaterial.accountAddress,
          signerId: keyMaterial.signerId,
          signerSlot: keyMaterial.signerSlot,
        }),
      ),
  );
  const missingSigner = args.signers.find(
    (signer) =>
      signer.status === 'active' &&
      !keyMaterialKeys.has(
        signerKeyMaterialPairKey({
          profileId: signer.profileId,
          chainIdKey: signer.chainIdKey,
          accountAddress: signer.accountAddress,
          signerId: signer.signerId,
          signerSlot: signer.signerSlot,
        }),
      ),
  );
  if (missingSigner) {
    throw new Error(
      `[SeamsWalletDB] active signer ${missingSigner.signerId} requires matching threshold key material`,
    );
  }
  const orphanedKeyMaterial = args.keyMaterials.find(
    (keyMaterial) =>
      keyMaterial.keyKind === 'threshold_share_v1' &&
      !signerKeys.has(
        signerKeyMaterialPairKey({
          profileId: keyMaterial.profileId,
          chainIdKey: keyMaterial.chainIdKey,
          accountAddress: keyMaterial.accountAddress,
          signerId: keyMaterial.signerId,
          signerSlot: keyMaterial.signerSlot,
        }),
      ),
  );
  if (orphanedKeyMaterial) {
    throw new Error(
      `[SeamsWalletDB] threshold key material for signer ${orphanedKeyMaterial.signerId} has no matching signer activation`,
    );
  }
}

function parseKeyMaterialRow(value: unknown): KeyMaterialRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Partial<KeyMaterialRow>;
  const record = normalizeStoredPayloadRecord(row.record as KeyMaterialRecord);
  if (!record) return null;
  if (
    row.key_material_id !==
    keyMaterialId({
      walletSignerId: walletSignerIdForKeyMaterial(record),
      keyKind: record.keyKind,
    })
  ) {
    return null;
  }
  if (row.wallet_id !== record.profileId) return null;
  if (row.wallet_signer_id !== walletSignerIdForKeyMaterial(record)) return null;
  if (
    row.chain_target_key !==
    signerChainTargetKey({
      chainIdKey: record.chainIdKey,
      accountAddress: record.accountAddress,
    })
  ) {
    return null;
  }
  if (row.key_handle !== toTrimmedString(record.signerId || '')) return null;
  if (row.public_key !== record.publicKey) return null;
  return record;
}

function signerKeyMaterialPairKeyForSigner(signer: AccountSignerRecord): string {
  return signerKeyMaterialPairKey({
    profileId: signer.profileId,
    chainIdKey: signer.chainIdKey,
    accountAddress: signer.accountAddress,
    signerId: signer.signerId,
    signerSlot: signer.signerSlot,
  });
}

function signerKeyMaterialPairKeyForMaterial(keyMaterial: KeyMaterialRecord): string {
  return signerKeyMaterialPairKey({
    profileId: keyMaterial.profileId,
    chainIdKey: keyMaterial.chainIdKey,
    accountAddress: keyMaterial.accountAddress,
    signerId: keyMaterial.signerId,
    signerSlot: keyMaterial.signerSlot,
  });
}

function collectSignerKeyMaterialProfileIds(args: {
  signers: readonly AccountSignerRecord[];
  keyMaterials: readonly KeyMaterialRecord[];
}): string[] {
  const profileIds = new Set<string>();
  for (const signer of args.signers) {
    const profileId = toTrimmedString(signer.profileId || '');
    if (profileId) profileIds.add(profileId);
  }
  for (const keyMaterial of args.keyMaterials) {
    const profileId = toTrimmedString(keyMaterial.profileId || '');
    if (profileId) profileIds.add(profileId);
  }
  return [...profileIds];
}

async function readActiveSignersForProfilesInTransaction(
  ctx: SeamsWalletTransactionContext,
  profileIds: readonly string[],
): Promise<AccountSignerRecord[]> {
  const store = ctx.store(SEAMS_WALLET_STORES.walletSigners);
  const signers: AccountSignerRecord[] = [];
  for (const profileId of profileIds) {
    const rows = (await store
      .index(SEAMS_WALLET_INDEXES.walletId)
      .getAll(profileId)) as unknown[];
    for (const row of rows) {
      const parsed = parseAccountSignerRow(row);
      if (parsed?.status === 'active') signers.push(parsed);
    }
  }
  return signers;
}

async function readThresholdKeyMaterialsForProfilesInTransaction(
  ctx: SeamsWalletTransactionContext,
  profileIds: readonly string[],
): Promise<KeyMaterialRecord[]> {
  const store = ctx.store(SEAMS_WALLET_STORES.keyMaterial);
  const keyMaterials: KeyMaterialRecord[] = [];
  for (const profileId of profileIds) {
    const rows = (await store
      .index(SEAMS_WALLET_INDEXES.walletId)
      .getAll(profileId)) as unknown[];
    for (const row of rows) {
      const parsed = parseKeyMaterialRow(row);
      if (parsed?.keyKind === 'threshold_share_v1') keyMaterials.push(parsed);
    }
  }
  return keyMaterials;
}

function mergeKeyMaterialsById(args: {
  existing: readonly KeyMaterialRecord[];
  incoming: readonly KeyMaterialRecord[];
}): KeyMaterialRecord[] {
  const merged = new Map<string, KeyMaterialRecord>();
  for (const keyMaterial of args.existing) {
    merged.set(
      keyMaterialId({
        walletSignerId: walletSignerIdForKeyMaterial(keyMaterial),
        keyKind: keyMaterial.keyKind,
      }),
      keyMaterial,
    );
  }
  for (const keyMaterial of args.incoming) {
    merged.set(
      keyMaterialId({
        walletSignerId: walletSignerIdForKeyMaterial(keyMaterial),
        keyKind: keyMaterial.keyKind,
      }),
      keyMaterial,
    );
  }
  return [...merged.values()];
}

async function assertSignerKeyMaterialPairsInTransaction(args: {
  ctx: SeamsWalletTransactionContext;
  signers: readonly AccountSignerRecord[];
  keyMaterials: readonly KeyMaterialRecord[];
}): Promise<void> {
  const profileIds = collectSignerKeyMaterialProfileIds({
    signers: args.signers,
    keyMaterials: args.keyMaterials,
  });
  if (profileIds.length === 0) return;
  const activeSigners = await readActiveSignersForProfilesInTransaction(args.ctx, profileIds);
  const activeSignerKeys = new Set(activeSigners.map(signerKeyMaterialPairKeyForSigner));
  const existingKeyMaterials = (
    await readThresholdKeyMaterialsForProfilesInTransaction(args.ctx, profileIds)
  ).filter((keyMaterial) =>
    activeSignerKeys.has(signerKeyMaterialPairKeyForMaterial(keyMaterial)),
  );
  assertSignerKeyMaterialPairs({
    signers: activeSigners,
    keyMaterials: mergeKeyMaterialsById({
      existing: existingKeyMaterials,
      incoming: args.keyMaterials,
    }),
  });
}

function isUsableKeyMaterialForRead(record: KeyMaterialRecord): boolean {
  if (record.keyKind !== 'threshold_share_v1' || record.algorithm !== 'ed25519') return true;
  const payload = record.payload || {};
  return (
    !!toTrimmedString(payload.relayerKeyId || '') &&
    !!toTrimmedString(payload.keyVersion || '')
  );
}

function selectKeyMaterialForRead(args: {
  matches: readonly KeyMaterialRecord[];
  activeSigners: readonly AccountSignerRecord[];
}): KeyMaterialRecord | null {
  const activeSignerKeys = new Set(args.activeSigners.map(signerKeyMaterialPairKeyForSigner));
  const activeMatches = args.matches.filter((record) =>
    activeSignerKeys.has(signerKeyMaterialPairKeyForMaterial(record)),
  );
  const usableActive = activeMatches.find(isUsableKeyMaterialForRead);
  if (usableActive) return usableActive;
  const usable = args.matches.find(isUsableKeyMaterialForRead);
  if (usable) return usable;
  return [...args.matches].sort((a, b) => b.timestamp - a.timestamp)[0] || null;
}

export class SeamsWalletRepositories {
  constructor(private readonly manager: SeamsWalletDBManager) {}

  async getAppState<T = unknown>(key: string): Promise<T | undefined> {
    const normalizedKey = toTrimmedString(key || '');
    if (!normalizedKey) return undefined;
    const db = await this.manager.getDB();
    const row = (await db.get(SEAMS_WALLET_STORES.appState, normalizedKey)) as
      | AppStateRow<T>
      | undefined;
    return row?.value;
  }

  async setAppState<T = unknown>(key: string, value: T): Promise<void> {
    const normalizedKey = toTrimmedString(key || '');
    if (!normalizedKey) return;
    await this.manager.runTransaction([SEAMS_WALLET_STORES.appState], 'readwrite', async (ctx) => {
      await ctx.store(SEAMS_WALLET_STORES.appState).put({ key: normalizedKey, value });
    });
  }

  async getProfile(profileId: string): Promise<ProfileRecord | null> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return null;
    const db = await this.manager.getDB();
    return parseProfileRow(await db.get(SEAMS_WALLET_STORES.wallets, normalizedProfileId));
  }

  async listProfiles(args?: { limit?: number }): Promise<ProfileRecord[]> {
    const db = await this.manager.getDB();
    const limit =
      Number.isSafeInteger(args?.limit) && Number(args?.limit) > 0
        ? Number(args?.limit)
        : undefined;
    const rows = (limit
      ? await db.getAll(SEAMS_WALLET_STORES.wallets, undefined, limit)
      : await db.getAll(SEAMS_WALLET_STORES.wallets)) as unknown[];
    return rows.flatMap((row) => {
      const parsed = parseProfileRow(row);
      return parsed ? [parsed] : [];
    });
  }

  async upsertProfile(input: UpsertProfileInput): Promise<ProfileRecord> {
    const profileId = toTrimmedString(input.profileId || '');
    if (!profileId) throw new Error('[SeamsWalletDB] profileId is required');
    let written: ProfileRecord | null = null;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.wallets],
      'readwrite',
      async (ctx) => {
        const store = ctx.store(SEAMS_WALLET_STORES.wallets);
        const existing = parseProfileRow(await store.get(profileId)) || undefined;
        const next = profileRow(input, existing);
        written = next.record;
        await store.put(next);
      },
    );
    if (!written) throw new Error('[SeamsWalletDB] profile write did not complete');
    return written;
  }

  async upsertWalletAuthMethod(
    record: LocalWalletAuthMethodRecord,
  ): Promise<LocalWalletAuthMethodRecord> {
    const fields = walletAuthMethodFields(record);
    let written: LocalWalletAuthMethodRecord | null = null;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.wallets, SEAMS_WALLET_STORES.walletAuthMethods],
      'readwrite',
      async (ctx) => {
        const profile = parseProfileRow(
          await ctx.store(SEAMS_WALLET_STORES.wallets).get(fields.wallet_id),
        );
        if (!profile) {
          throw makeConstraintError(
            'MISSING_PROFILE',
            `Cannot upsert auth-method binding for unknown wallet: ${fields.wallet_id}`,
            { profileId: fields.wallet_id, authIdentifierKey: fields.auth_identifier_key },
          );
        }
        const store = ctx.store(SEAMS_WALLET_STORES.walletAuthMethods);
        const existing = parseWalletAuthMethodStorageRow(await store.get(fields.wallet_auth_method_id));
        const row =
          record.kind === 'passkey' && existing?.kind === 'passkey'
            ? passkeyAuthMethodRow({ binding: record, authenticator: existing.authenticator })
            : walletAuthMethodRowFromBinding(record, profile.defaultSignerSlot);
        await store.put(row);
        written = row.record;
      },
    );
    if (!written) throw new Error('[SeamsWalletDB] auth-method write did not complete');
    return written;
  }

  async getWalletAuthMethod(args: {
    kind: LocalWalletAuthMethodRecord['kind'];
    rpId: string;
    authIdentifierKey: string;
  }): Promise<LocalWalletAuthMethodRecord | null> {
    const kind = args.kind;
    const rpId = toTrimmedString(args.rpId || '');
    const authIdentifierKey = toTrimmedString(args.authIdentifierKey || '');
    if (!rpId || !authIdentifierKey) return null;
    const db = await this.manager.getDB();
    return parseWalletAuthMethodRow(
      await db
        .transaction(SEAMS_WALLET_STORES.walletAuthMethods, 'readonly')
        .store.index(SEAMS_WALLET_INDEXES.kindRpIdAuthIdentifier)
        .get([kind, rpId, authIdentifierKey]),
    );
  }

  async listWalletAuthMethodsForWallet(
    walletId: string,
  ): Promise<LocalWalletAuthMethodRecord[]> {
    const normalizedWalletId = toTrimmedString(walletId || '');
    if (!normalizedWalletId) return [];
    const db = await this.manager.getDB();
    const rows = (await db
      .transaction(SEAMS_WALLET_STORES.walletAuthMethods, 'readonly')
      .store.index(SEAMS_WALLET_INDEXES.walletId)
      .getAll(normalizedWalletId)) as unknown[];
    return rows.flatMap((row) => {
      const parsed = parseWalletAuthMethodRow(row);
      return parsed ? [parsed] : [];
    });
  }

  async upsertChainAccount(input: UpsertChainAccountInput): Promise<ChainAccountRecord> {
    const profileId = toTrimmedString(input.profileId || '');
    const chainIdKey = normalizeIndexedDbChainIdKey(input.chainIdKey);
    const accountAddress = normalizeIndexedDbAccountAddress(input.accountAddress);
    if (!profileId || !chainIdKey || !accountAddress) {
      throw new Error('[SeamsWalletDB] profileId, chainIdKey, and accountAddress are required');
    }
    let written: ChainAccountRecord | null = null;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.wallets, SEAMS_WALLET_STORES.nearAccountProjections],
      'readwrite',
      async (ctx) => {
        const profile = parseProfileRow(
          await ctx.store(SEAMS_WALLET_STORES.wallets).get(profileId),
        );
        if (!profile) {
          throw new Error(
            `[SeamsWalletDB] Cannot upsert chain account for unknown profile: ${profileId}`,
          );
        }
        const store = ctx.store(SEAMS_WALLET_STORES.nearAccountProjections);
        const projectionId = chainAccountProjectionId({ chainIdKey, accountAddress });
        const existing = parseChainAccountProjectionRow(
          await store.get([profileId, projectionId, CHAIN_ACCOUNT_PROJECTION_SIGNER_SLOT]),
        ) || undefined;
        const next = chainAccountProjectionRow(input, existing);
        written = next.record;

        if (next.record.isPrimary) {
          const rows = (await store.index(SEAMS_WALLET_INDEXES.profileId).getAll(profileId)) as
            | unknown[]
            | undefined;
          for (const row of rows || []) {
            const parsed = parseChainAccountProjectionRow(row);
            if (!parsed || parsed.chainIdKey !== chainIdKey || !parsed.isPrimary) continue;
            if (parsed.accountAddress === accountAddress) continue;
            await store.put(
              chainAccountProjectionRow(
                {
                  profileId: parsed.profileId,
                  chainIdKey: parsed.chainIdKey,
                  accountAddress: parsed.accountAddress,
                  accountModel: parsed.accountModel,
                  isPrimary: false,
                },
                parsed,
              ),
            );
          }
        }

        await store.put(next);
      },
    );
    if (!written) throw new Error('[SeamsWalletDB] chain-account write did not complete');
    return written;
  }

  async listChainAccountsByProfile(profileId: string): Promise<ChainAccountRecord[]> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return [];
    const db = await this.manager.getDB();
    const tx = db.transaction(SEAMS_WALLET_STORES.nearAccountProjections, 'readonly');
    const rows = (await tx.store
      .index(SEAMS_WALLET_INDEXES.profileId)
      .getAll(normalizedProfileId)) as unknown[];
    await tx.done;
    return rows.flatMap((row) => {
      const parsed = parseChainAccountProjectionRow(row);
      return parsed ? [parsed] : [];
    });
  }

  async listChainAccountsByProfileAndChain(
    profileId: string,
    chainIdKey: string,
  ): Promise<ChainAccountRecord[]> {
    const normalizedChainIdKey = normalizeIndexedDbChainIdKey(chainIdKey);
    if (!normalizedChainIdKey) return [];
    const rows = await this.listChainAccountsByProfile(profileId);
    return rows.filter((row) => row.chainIdKey === normalizedChainIdKey);
  }

  async getChainAccount(input: {
    profileId: string;
    chainIdKey: string;
    accountAddress: string;
  }): Promise<ChainAccountRecord | null> {
    const profileId = toTrimmedString(input.profileId || '');
    const chainIdKey = normalizeIndexedDbChainIdKey(input.chainIdKey);
    const accountAddress = normalizeIndexedDbAccountAddress(input.accountAddress);
    if (!profileId || !chainIdKey || !accountAddress) return null;
    const db = await this.manager.getDB();
    return parseChainAccountProjectionRow(
      await db.get(SEAMS_WALLET_STORES.nearAccountProjections, [
        profileId,
        chainAccountProjectionId({ chainIdKey, accountAddress }),
        CHAIN_ACCOUNT_PROJECTION_SIGNER_SLOT,
      ]),
    );
  }

  async resolveProfileAccountContext(
    accountRef: AccountRef,
  ): Promise<{ profileId: string; accountRef: AccountRef } | null> {
    const chainIdKey = normalizeIndexedDbChainIdKey(accountRef.chainIdKey);
    const accountAddress = normalizeIndexedDbAccountAddress(accountRef.accountAddress);
    if (!chainIdKey || !accountAddress) return null;
    const db = await this.manager.getDB();
    const rows = (await db.getAll(SEAMS_WALLET_STORES.nearAccountProjections)) as unknown[];
    const match = rows
      .flatMap((row) => {
        const parsed = parseChainAccountProjectionRow(row);
        return parsed ? [parsed] : [];
      })
      .find((row) => row.chainIdKey === chainIdKey && row.accountAddress === accountAddress);
    if (!match?.profileId) return null;
    return {
      profileId: match.profileId,
      accountRef: { chainIdKey, accountAddress },
    };
  }

  async listChainAccountsByChain(chainIdKey: string): Promise<ChainAccountRecord[]> {
    const normalizedChainIdKey = normalizeIndexedDbChainIdKey(chainIdKey);
    if (!normalizedChainIdKey) return [];
    const db = await this.manager.getDB();
    const rows = (await db.getAll(SEAMS_WALLET_STORES.nearAccountProjections)) as unknown[];
    return rows.flatMap((row) => {
      const parsed = parseChainAccountProjectionRow(row);
      return parsed && parsed.chainIdKey === normalizedChainIdKey ? [parsed] : [];
    });
  }

  private buildAccountSignerRecord(args: {
    profileId: string;
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
    signerSlot: number;
    signerType: string;
    signerKind: AccountSignerRecord['signerKind'];
    signerAuthMethod: AccountSignerRecord['signerAuthMethod'];
    signerSource: AccountSignerRecord['signerSource'];
    status: AccountSignerStatus;
    existing?: AccountSignerRecord;
    now: number;
    removedAt?: number;
    revocationReason?: string;
    metadata?: Record<string, unknown>;
  }): AccountSignerRecord {
    const removedAt =
      args.status === 'revoked'
        ? args.removedAt ?? args.existing?.removedAt ?? args.now
        : undefined;
    return {
      profileId: args.profileId,
      chainIdKey: args.chainIdKey,
      accountAddress: args.accountAddress,
      signerId: args.signerId,
      signerSlot: args.signerSlot,
      signerType: args.signerType,
      signerKind: args.signerKind,
      signerAuthMethod: args.signerAuthMethod,
      signerSource: args.signerSource,
      status: args.status,
      addedAt: args.existing?.addedAt ?? args.now,
      updatedAt: args.now,
      ...(removedAt != null ? { removedAt } : {}),
      ...(args.revocationReason
        ? { revocationReason: toTrimmedString(args.revocationReason) }
        : args.existing?.revocationReason
          ? { revocationReason: args.existing.revocationReason }
          : {}),
      ...(args.metadata != null
        ? { metadata: args.metadata }
        : args.existing?.metadata != null
          ? { metadata: args.existing.metadata }
          : {}),
    };
  }

  private assertSignerWriteInvariants(args: {
    next: AccountSignerRecord;
    accountModel: string;
    existingStatus?: AccountSignerStatus;
    activeSigners: AccountSignerRecord[];
  }): void {
    const { next } = args;
    if (next.status !== 'revoked') {
      if (!next.signerKind || !next.signerAuthMethod || !next.signerSource) {
        throw makeConstraintError(
          'MISSING_SIGNER_KIND',
          'Active and pending account signers require signerKind, signerAuthMethod, and signerSource',
          {
            chainIdKey: next.chainIdKey,
            accountAddress: next.accountAddress,
            signerId: next.signerId,
            status: next.status,
          },
        );
      }
    }
    if (next.status === 'revoked' && next.removedAt == null) {
      throw makeConstraintError(
        'REVOKED_SIGNER_REQUIRES_REMOVED_AT',
        `Revoked signer ${next.signerId} must include removedAt`,
        {
          chainIdKey: next.chainIdKey,
          accountAddress: next.accountAddress,
          signerId: next.signerId,
        },
      );
    }
    if (next.status === 'active') {
      const conflictingSlot = args.activeSigners.find(
        (row) => row.signerId !== next.signerId && row.signerSlot === next.signerSlot,
      );
      if (conflictingSlot) {
        throw makeConstraintError(
          'DUPLICATE_ACTIVE_SIGNER_SLOT',
          `Active signer slot ${next.signerSlot} is already used for ${next.chainIdKey}/${next.accountAddress}`,
          {
            chainIdKey: next.chainIdKey,
            accountAddress: next.accountAddress,
            signerId: next.signerId,
            signerSlot: next.signerSlot,
            conflictingSignerId: conflictingSlot.signerId,
          },
        );
      }
    }
    if (args.existingStatus && args.existingStatus !== next.status) {
      const allowed: Record<AccountSignerStatus, ReadonlySet<AccountSignerStatus>> = {
        pending: new Set<AccountSignerStatus>(['pending', 'active', 'revoked']),
        active: new Set<AccountSignerStatus>(['active', 'revoked']),
        revoked: new Set<AccountSignerStatus>(['revoked']),
      };
      if (!allowed[args.existingStatus]?.has(next.status)) {
        throw makeConstraintError(
          'INVALID_SIGNER_STATUS_TRANSITION',
          `Invalid signer status transition ${args.existingStatus} -> ${next.status}`,
          {
            chainIdKey: next.chainIdKey,
            accountAddress: next.accountAddress,
            signerId: next.signerId,
            previousStatus: args.existingStatus,
            nextStatus: next.status,
          },
        );
      }
    }
    if (next.status === 'active' && String(next.signerKind || '') === 'threshold-ecdsa') {
      const metadata = next.metadata || {};
      if (!toTrimmedString(metadata.keyHandle)) {
        throw makeConstraintError(
          'INVALID_SIGNER_METADATA',
          'Active threshold ECDSA signer requires metadata.keyHandle',
          {
            chainIdKey: next.chainIdKey,
            accountAddress: next.accountAddress,
            signerId: next.signerId,
          },
        );
      }
      if (!toTrimmedString(metadata.ecdsaThresholdKeyId)) {
        throw makeConstraintError(
          'INVALID_SIGNER_METADATA',
          'Active threshold ECDSA signer requires metadata.ecdsaThresholdKeyId',
          {
            chainIdKey: next.chainIdKey,
            accountAddress: next.accountAddress,
            signerId: next.signerId,
          },
        );
      }
      const thresholdOwnerAddress = normalizeIndexedDbAccountAddress(metadata.thresholdOwnerAddress);
      if (!thresholdOwnerAddress || thresholdOwnerAddress !== next.accountAddress) {
        throw makeConstraintError(
          'INVALID_SIGNER_METADATA',
          'Active threshold ECDSA signer requires metadata.thresholdOwnerAddress matching accountAddress',
          {
            chainIdKey: next.chainIdKey,
            accountAddress: next.accountAddress,
            signerId: next.signerId,
          },
        );
      }
      const chainTargetKey = normalizeEcdsaChainTargetKey(metadata.chainTarget);
      if (!chainTargetKey) {
        throw makeConstraintError(
          'INVALID_SIGNER_METADATA',
          'Active threshold ECDSA signer requires metadata.chainTarget',
          {
            chainIdKey: next.chainIdKey,
            accountAddress: next.accountAddress,
            signerId: next.signerId,
          },
        );
      }
      if (chainTargetKey !== next.chainIdKey) {
        throw makeConstraintError(
          'INVALID_SIGNER_METADATA',
          'Active threshold ECDSA signer metadata.chainTarget must match chainIdKey',
          {
            chainIdKey: next.chainIdKey,
            chainTargetKey,
            accountAddress: next.accountAddress,
            signerId: next.signerId,
          },
        );
      }
    }
  }

  private async enqueueSignerOperationInTransaction(
    store: any,
    input: EnqueueSignerOperationInput,
  ): Promise<SignerOpOutboxRecord> {
    const opId = toTrimmedString(input.opId || '');
    const idempotencyKey = toTrimmedString(input.idempotencyKey || '');
    const chainIdKey = normalizeIndexedDbChainIdKey(input.chainIdKey);
    const accountAddress = normalizeIndexedDbAccountAddress(input.accountAddress);
    const signerId = toTrimmedString(input.signerId || '');
    if (!opId || !idempotencyKey || !chainIdKey || !accountAddress || !signerId) {
      throw new Error(
        '[SeamsWalletDB] opId, idempotencyKey, chainIdKey, accountAddress, and signerId are required',
      );
    }

    const existing = parseSignerOutboxRow(await store.get(opId));
    if (!existing) {
      const byIdempotency = parseSignerOutboxRow(
        await store.index(SEAMS_WALLET_INDEXES.idempotencyKey).get(idempotencyKey),
      );
      if (byIdempotency) return byIdempotency;
    }

    const now = Date.now();
    const next: SignerOpOutboxRecord = {
      opId,
      idempotencyKey,
      opType: input.opType,
      chainIdKey,
      accountAddress,
      signerId,
      payload: input.payload ?? existing?.payload,
      status: input.status ?? existing?.status ?? 'queued',
      attemptCount: input.attemptCount ?? existing?.attemptCount ?? 0,
      nextAttemptAt: input.nextAttemptAt ?? existing?.nextAttemptAt ?? now,
      lastError: input.lastError ?? existing?.lastError,
      txHash: input.txHash ?? existing?.txHash,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    await store.put(signerOutboxRow(next));
    return next;
  }

  private async activateAccountSignerInTransaction(
    ctx: SeamsWalletTransactionContext,
    input: ActivateAccountSignerInput,
  ): Promise<ActivateAccountSignerResult> {
    const profileId = toTrimmedString(input.account.profileId || '');
    const chainIdKey = normalizeIndexedDbChainIdKey(input.account.chainIdKey);
    const accountAddress = normalizeIndexedDbAccountAddress(input.account.accountAddress);
    const accountModel = normalizeIndexedDbAccountModel(input.account.accountModel);
    const signerId = toTrimmedString(input.signer.signerId || '');
    const signerKind = toTrimmedString(
      input.signer.signerKind || '',
    ) as AccountSignerRecord['signerKind'];
    const signerAuthMethod = toTrimmedString(
      input.signer.signerAuthMethod || '',
    ) as AccountSignerRecord['signerAuthMethod'];
    const signerSource = toTrimmedString(
      input.signer.signerSource || '',
    ) as AccountSignerRecord['signerSource'];
    if (
      !profileId ||
      !chainIdKey ||
      !accountAddress ||
      !accountModel ||
      !signerId ||
      !signerKind ||
      !signerAuthMethod ||
      !signerSource
    ) {
      throw new Error(
        '[SeamsWalletDB] profileId, chainIdKey, accountAddress, accountModel, signerId, signerKind, signerAuthMethod, and signerSource are required',
      );
    }

    const signerStore = ctx.store(SEAMS_WALLET_STORES.walletSigners);
    const profile = parseProfileRow(
      await ctx.store(SEAMS_WALLET_STORES.wallets).get(profileId),
    );
    if (!profile) {
      throw makeConstraintError(
        'MISSING_PROFILE',
        `Cannot upsert signer without profile row: ${profileId}`,
        { profileId, chainIdKey, accountAddress, signerId },
      );
    }
    if (shouldWriteNearAccountProjection({ accountModel, chainIdKey })) {
      const chainAccountStore = ctx.store(SEAMS_WALLET_STORES.nearAccountProjections);
      const existingChainAccount = parseChainAccountProjectionRow(
        await chainAccountStore.get([
          profileId,
          chainAccountProjectionId({ chainIdKey, accountAddress }),
          CHAIN_ACCOUNT_PROJECTION_SIGNER_SLOT,
        ]),
      );
      const chainAccount = chainAccountProjectionRow({
        profileId,
        chainIdKey,
        accountAddress,
        accountModel,
        isPrimary: input.selectAsActive === true ? true : existingChainAccount?.isPrimary ?? true,
      }, existingChainAccount || undefined);
      await chainAccountStore.put(chainAccount);
    }

    const activeRows = (await signerStore
      .index(SEAMS_WALLET_INDEXES.status)
      .getAll('active')) as unknown[];
    const activeSigners = activeRows.flatMap((row) => {
      const parsed = parseAccountSignerRow(row);
      return parsed &&
        parsed.chainIdKey === chainIdKey &&
        parsed.accountAddress === accountAddress
        ? [parsed]
        : [];
    });
    const plan = planAccountSignerActivation({
      activeSigners,
      signer: { signerId, signerKind, signerAuthMethod, signerSource },
      activationPolicy: input.activationPolicy,
      ...(input.preferredSlot != null ? { preferredSlot: input.preferredSlot } : {}),
    });
    const existingSigner = parseAccountSignerRow(
      await signerStore.get(walletSignerId({ chainIdKey, accountAddress, signerId })),
    );
    if (existingSigner && existingSigner.profileId !== profileId) {
      throw makeConstraintError(
        'CHAIN_ACCOUNT_PROFILE_MISMATCH',
        `Signer row belongs to a different profile for ${chainIdKey}/${accountAddress}/${signerId}`,
        { expectedProfileId: profileId, existingProfileId: existingSigner.profileId },
      );
    }
    const now = Date.now();
    const signer = this.buildAccountSignerRecord({
      profileId,
      chainIdKey,
      accountAddress,
      signerId,
      signerSlot: plan.signerSlot,
      signerType: input.signer.signerType,
      signerKind,
      signerAuthMethod,
      signerSource,
      status: 'active',
      existing: existingSigner || undefined,
      now,
      ...(input.signer.metadata ? { metadata: input.signer.metadata } : {}),
    });
    this.assertSignerWriteInvariants({
      next: signer,
      accountModel,
      existingStatus: existingSigner?.status,
      activeSigners,
    });
    await signerStore.put(accountSignerRow(signer));
    if (input.selectAsActive ?? true) {
      await ctx.store(SEAMS_WALLET_STORES.appState).put({
        key: scopedLastProfileStateAppStateKey(),
        value: { profileId, activeSignerSlot: plan.signerSlot },
      });
    }
    if (input.mutation?.routeThroughOutbox ?? false) {
      const opId =
        toTrimmedString(input.mutation?.opId || '') || createRandomToken('add-signer');
      const idempotencyKey =
        toTrimmedString(input.mutation?.idempotencyKey || '') ||
        `add-signer:${signer.chainIdKey}:${signer.accountAddress}:${signer.signerId}:${signer.signerSlot}`;
      await this.enqueueSignerOperationInTransaction(
        ctx.store(SEAMS_WALLET_STORES.signerOpsOutbox),
        {
          opId,
          idempotencyKey,
          opType: 'add-signer',
          chainIdKey: signer.chainIdKey,
          accountAddress: signer.accountAddress,
          signerId: signer.signerId,
          payload: this.signerOutboxPayload(signer, input.mutation),
          status: input.mutation?.outboxStatus || 'queued',
        },
      );
    }
    return { signer, signerSlot: plan.signerSlot };
  }

  async activateAccountSigner(
    input: ActivateAccountSignerInput,
  ): Promise<ActivateAccountSignerResult> {
    let result: ActivateAccountSignerResult | null = null;
    await this.manager.runTransaction(
      [
        SEAMS_WALLET_STORES.wallets,
        SEAMS_WALLET_STORES.nearAccountProjections,
        SEAMS_WALLET_STORES.walletSigners,
        SEAMS_WALLET_STORES.appState,
        SEAMS_WALLET_STORES.signerOpsOutbox,
      ],
      'readwrite',
      async (ctx) => {
        result = await this.activateAccountSignerInTransaction(ctx, input);
      },
    );
    if (!result) throw new Error('[SeamsWalletDB] signer activation did not complete');
    return result;
  }

  async stageAccountSigner(input: StageAccountSignerInput): Promise<StageAccountSignerResult> {
    return this.writePreparedAccountSigner({
      account: input.account,
      signer: input.signer,
      status: 'pending',
      signerSlot: input.signer.signerSlot,
      mutation: input.mutation,
    });
  }

  private async writePreparedAccountSigner(input: {
    account: StageAccountSignerInput['account'];
    signer: StageAccountSignerInput['signer'];
    status: AccountSignerStatus;
    signerSlot: number;
    mutation?: SignerMutationOptions;
  }): Promise<StageAccountSignerResult> {
    const profileId = toTrimmedString(input.account.profileId || '');
    const chainIdKey = normalizeIndexedDbChainIdKey(input.account.chainIdKey);
    const accountAddress = normalizeIndexedDbAccountAddress(input.account.accountAddress);
    const accountModel = normalizeIndexedDbAccountModel(input.account.accountModel);
    const signerId = toTrimmedString(input.signer.signerId || '');
    const signerSlot = Number(input.signerSlot);
    const signerKind = toTrimmedString(
      input.signer.signerKind || '',
    ) as AccountSignerRecord['signerKind'];
    const signerAuthMethod = toTrimmedString(
      input.signer.signerAuthMethod || '',
    ) as AccountSignerRecord['signerAuthMethod'];
    const signerSource = toTrimmedString(
      input.signer.signerSource || '',
    ) as AccountSignerRecord['signerSource'];
    if (
      !profileId ||
      !chainIdKey ||
      !accountAddress ||
      !accountModel ||
      !signerId ||
      !signerKind ||
      !signerAuthMethod ||
      !signerSource
    ) {
      throw new Error(
        '[SeamsWalletDB] profileId, chainIdKey, accountAddress, accountModel, signerId, signerKind, signerAuthMethod, and signerSource are required',
      );
    }
    if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
      throw new Error('[SeamsWalletDB] signerSlot must be an integer >= 1');
    }

    let result: StageAccountSignerResult | null = null;
    await this.manager.runTransaction(
      [
        SEAMS_WALLET_STORES.wallets,
        SEAMS_WALLET_STORES.nearAccountProjections,
        SEAMS_WALLET_STORES.walletSigners,
        SEAMS_WALLET_STORES.signerOpsOutbox,
      ],
      'readwrite',
      async (ctx) => {
        const profile = parseProfileRow(
          await ctx.store(SEAMS_WALLET_STORES.wallets).get(profileId),
        );
        if (!profile) {
          throw makeConstraintError(
            'MISSING_PROFILE',
            `Cannot upsert signer without profile row: ${profileId}`,
            { profileId, chainIdKey, accountAddress, signerId },
          );
        }
        const chainAccountStore = ctx.store(SEAMS_WALLET_STORES.nearAccountProjections);
        const existingChainAccount = parseChainAccountProjectionRow(
          await chainAccountStore.get([
            profileId,
            chainAccountProjectionId({ chainIdKey, accountAddress }),
            CHAIN_ACCOUNT_PROJECTION_SIGNER_SLOT,
          ]),
        );
        const chainAccount = chainAccountProjectionRow(
          {
            profileId,
            chainIdKey,
            accountAddress,
            accountModel,
            isPrimary: existingChainAccount?.isPrimary,
          },
          existingChainAccount || undefined,
        );
        await chainAccountStore.put(chainAccount);
        const signerStore = ctx.store(SEAMS_WALLET_STORES.walletSigners);
        const existingSigner = parseAccountSignerRow(
          await signerStore.get(walletSignerId({ chainIdKey, accountAddress, signerId })),
        );
        if (existingSigner && existingSigner.profileId !== profileId) {
          throw makeConstraintError(
            'CHAIN_ACCOUNT_PROFILE_MISMATCH',
            `Signer row belongs to a different profile for ${chainIdKey}/${accountAddress}/${signerId}`,
            { expectedProfileId: profileId, existingProfileId: existingSigner.profileId },
          );
        }
        const activeRows = (await signerStore
          .index(SEAMS_WALLET_INDEXES.status)
          .getAll('active')) as unknown[];
        const activeSigners = activeRows.flatMap((row) => {
          const parsed = parseAccountSignerRow(row);
          return parsed &&
            parsed.chainIdKey === chainIdKey &&
            parsed.accountAddress === accountAddress
            ? [parsed]
            : [];
        });
        const now = Date.now();
        const signer = this.buildAccountSignerRecord({
          profileId,
          chainIdKey,
          accountAddress,
          signerId,
          signerSlot,
          signerType: input.signer.signerType,
          signerKind,
          signerAuthMethod,
          signerSource,
          status: input.status,
          existing: existingSigner || undefined,
          now,
          ...(input.signer.metadata ? { metadata: input.signer.metadata } : {}),
        });
        this.assertSignerWriteInvariants({
          next: signer,
          accountModel,
          existingStatus: existingSigner?.status,
          activeSigners,
        });
        await signerStore.put(accountSignerRow(signer));
        if (input.mutation?.routeThroughOutbox ?? false) {
          const opId =
            toTrimmedString(input.mutation?.opId || '') || createRandomToken('add-signer');
          const idempotencyKey =
            toTrimmedString(input.mutation?.idempotencyKey || '') ||
            `add-signer:${signer.chainIdKey}:${signer.accountAddress}:${signer.signerId}:${signer.signerSlot}`;
          await this.enqueueSignerOperationInTransaction(
            ctx.store(SEAMS_WALLET_STORES.signerOpsOutbox),
            {
              opId,
              idempotencyKey,
              opType: 'add-signer',
              chainIdKey: signer.chainIdKey,
              accountAddress: signer.accountAddress,
              signerId: signer.signerId,
              payload: this.signerOutboxPayload(signer, input.mutation),
              status: input.mutation?.outboxStatus || 'queued',
            },
          );
        }
        result = { signer, signerSlot };
      },
    );
    if (!result) throw new Error('[SeamsWalletDB] signer write did not complete');
    return result;
  }

  private signerOutboxPayload(
    signer: AccountSignerRecord,
    mutation?: SignerMutationOptions,
  ): Record<string, unknown> {
    return {
      profileId: signer.profileId,
      signerSlot: signer.signerSlot,
      signerType: signer.signerType,
      signerKind: signer.signerKind,
      signerAuthMethod: signer.signerAuthMethod,
      signerSource: signer.signerSource,
      ...(signer.metadata ? { signerMetadata: signer.metadata } : {}),
      ...(mutation?.outboxPayload ? mutation.outboxPayload : {}),
    };
  }

  async listAccountSigners(args: {
    chainIdKey: string;
    accountAddress: string;
    status?: AccountSignerStatus;
  }): Promise<AccountSignerRecord[]> {
    const chainIdKey = normalizeIndexedDbChainIdKey(args.chainIdKey);
    const accountAddress = normalizeIndexedDbAccountAddress(args.accountAddress);
    if (!chainIdKey || !accountAddress) return [];
    const db = await this.manager.getDB();
    const rows = args.status
      ? ((await db
          .transaction(SEAMS_WALLET_STORES.walletSigners, 'readonly')
          .store.index(SEAMS_WALLET_INDEXES.status)
          .getAll(args.status)) as unknown[])
      : ((await db.getAll(SEAMS_WALLET_STORES.walletSigners)) as unknown[]);
    return rows.flatMap((row) => {
      const parsed = parseAccountSignerRow(row);
      return parsed && parsed.chainIdKey === chainIdKey && parsed.accountAddress === accountAddress
        ? [parsed]
        : [];
    });
  }

  async listAccountSignersByProfile(args: {
    profileId: string;
    status?: AccountSignerStatus;
  }): Promise<AccountSignerRecord[]> {
    const profileId = toTrimmedString(args.profileId || '');
    if (!profileId) return [];
    const db = await this.manager.getDB();
    const rows = (await db
      .transaction(SEAMS_WALLET_STORES.walletSigners, 'readonly')
      .store.index(SEAMS_WALLET_INDEXES.walletId)
      .getAll(profileId)) as unknown[];
    return rows.flatMap((row) => {
      const parsed = parseAccountSignerRow(row);
      return parsed && (!args.status || parsed.status === args.status) ? [parsed] : [];
    });
  }

  async getAccountSigner(args: {
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
  }): Promise<AccountSignerRecord | null> {
    const chainIdKey = normalizeIndexedDbChainIdKey(args.chainIdKey);
    const accountAddress = normalizeIndexedDbAccountAddress(args.accountAddress);
    const signerId = toTrimmedString(args.signerId || '');
    if (!chainIdKey || !accountAddress || !signerId) return null;
    const db = await this.manager.getDB();
    return parseAccountSignerRow(
      await db.get(
        SEAMS_WALLET_STORES.walletSigners,
        walletSignerId({ chainIdKey, accountAddress, signerId }),
      ),
    );
  }

  async setAccountSignerStatus(args: {
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
    status: AccountSignerStatus;
    removedAt?: number;
    revocationReason?: string;
    mutation?: SignerMutationOptions;
  }): Promise<AccountSignerRecord | null> {
    const existing = await this.getAccountSigner(args);
    if (!existing) return null;
    const chainAccount = await this.getChainAccount({
      profileId: existing.profileId,
      chainIdKey: existing.chainIdKey,
      accountAddress: existing.accountAddress,
    });
    if (!chainAccount) {
      throw makeConstraintError(
        'MISSING_CHAIN_ACCOUNT',
        `Cannot update signer status without chain account row: ${existing.profileId}/${existing.chainIdKey}/${existing.accountAddress}`,
        {
          profileId: existing.profileId,
          chainIdKey: existing.chainIdKey,
          accountAddress: existing.accountAddress,
          signerId: existing.signerId,
        },
      );
    }
    let updated: AccountSignerRecord | null = null;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.walletSigners, SEAMS_WALLET_STORES.signerOpsOutbox],
      'readwrite',
      async (ctx) => {
        const signerStore = ctx.store(SEAMS_WALLET_STORES.walletSigners);
        const activeRows = (await signerStore
          .index(SEAMS_WALLET_INDEXES.status)
          .getAll('active')) as unknown[];
        const activeSigners = activeRows.flatMap((row) => {
          const parsed = parseAccountSignerRow(row);
          return parsed &&
            parsed.chainIdKey === existing.chainIdKey &&
            parsed.accountAddress === existing.accountAddress
            ? [parsed]
            : [];
        });
        const next = this.buildAccountSignerRecord({
          ...existing,
          status: args.status,
          existing,
          now: Date.now(),
          ...(args.removedAt != null ? { removedAt: args.removedAt } : {}),
          ...(args.revocationReason ? { revocationReason: args.revocationReason } : {}),
        });
        this.assertSignerWriteInvariants({
          next,
          accountModel: chainAccount.accountModel,
          existingStatus: existing.status,
          activeSigners,
        });
        await signerStore.put(accountSignerRow(next));
        if (args.mutation?.routeThroughOutbox ?? true) {
          const opType: SignerOperationType =
            args.status === 'revoked' ? 'revoke-signer' : 'add-signer';
          const opId = toTrimmedString(args.mutation?.opId || '') || createRandomToken(opType);
          const idempotencyKey =
            toTrimmedString(args.mutation?.idempotencyKey || '') ||
            `signer-status:${args.status}:${next.chainIdKey}:${next.accountAddress}:${next.signerId}`;
          await this.enqueueSignerOperationInTransaction(
            ctx.store(SEAMS_WALLET_STORES.signerOpsOutbox),
            {
              opId,
              idempotencyKey,
              opType,
              chainIdKey: next.chainIdKey,
              accountAddress: next.accountAddress,
              signerId: next.signerId,
              payload: {
                profileId: next.profileId,
                signerSlot: next.signerSlot,
                status: next.status,
                ...(next.removedAt != null ? { removedAt: next.removedAt } : {}),
                ...(next.revocationReason ? { revocationReason: next.revocationReason } : {}),
                ...(args.mutation?.outboxPayload ? args.mutation.outboxPayload : {}),
              },
              status: args.mutation?.outboxStatus || 'queued',
            },
          );
        }
        updated = next;
      },
    );
    return updated;
  }

  async enqueueSignerOperation(input: EnqueueSignerOperationInput): Promise<SignerOpOutboxRecord> {
    let record: SignerOpOutboxRecord | null = null;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.signerOpsOutbox],
      'readwrite',
      async (ctx) => {
        record = await this.enqueueSignerOperationInTransaction(
          ctx.store(SEAMS_WALLET_STORES.signerOpsOutbox),
          input,
        );
      },
    );
    if (!record) throw new Error('[SeamsWalletDB] signer op enqueue did not complete');
    return record;
  }

  async listSignerOperations(args?: {
    statuses?: SignerOperationStatus[];
    dueBefore?: number;
    limit?: number;
  }): Promise<SignerOpOutboxRecord[]> {
    const statuses =
      args?.statuses && args.statuses.length > 0
        ? args.statuses
        : (['queued', 'submitted', 'failed'] as SignerOperationStatus[]);
    const dueBeforeRaw = typeof args?.dueBefore === 'number' ? args.dueBefore : Date.now();
    const dueBefore = Number.isFinite(dueBeforeRaw) ? dueBeforeRaw : Number.MAX_SAFE_INTEGER;
    const limit =
      Number.isSafeInteger(args?.limit) && Number(args?.limit) > 0 ? Number(args?.limit) : 100;
    const db = await this.manager.getDB();
    const collected: SignerOpOutboxRecord[] = [];
    for (const status of statuses) {
      const tx = db.transaction(SEAMS_WALLET_STORES.signerOpsOutbox, 'readonly');
      const rows = (await tx.store
        .index(SEAMS_WALLET_INDEXES.statusNextAttemptAt)
        .getAll(IDBKeyRange.bound([status, Number.MIN_SAFE_INTEGER], [status, dueBefore]))) as
        | unknown[]
        | undefined;
      await tx.done;
      collected.push(...(rows || []).flatMap((row) => {
        const parsed = parseSignerOutboxRow(row);
        return parsed ? [parsed] : [];
      }));
    }
    collected.sort((a, b) => {
      const timeDelta = (a.nextAttemptAt || 0) - (b.nextAttemptAt || 0);
      if (timeDelta !== 0) return timeDelta;
      return String(a.opId || '').localeCompare(String(b.opId || ''));
    });
    return collected.slice(0, limit);
  }

  async setSignerOperationStatus(args: {
    opId: string;
    status: SignerOperationStatus;
    attemptDelta?: number;
    nextAttemptAt?: number;
    lastError?: string | null;
    txHash?: string | null;
  }): Promise<SignerOpOutboxRecord | null> {
    const opId = toTrimmedString(args.opId || '');
    if (!opId) return null;
    let updated: SignerOpOutboxRecord | null = null;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.signerOpsOutbox],
      'readwrite',
      async (ctx) => {
        const store = ctx.store(SEAMS_WALLET_STORES.signerOpsOutbox);
        const existing = parseSignerOutboxRow(await store.get(opId));
        if (!existing) return;
        const attemptDelta = Number.isFinite(args.attemptDelta) ? Number(args.attemptDelta) : 0;
        const attemptCount = Math.max(0, (existing.attemptCount || 0) + attemptDelta);
        const next: SignerOpOutboxRecord = {
          ...existing,
          status: args.status,
          attemptCount,
          nextAttemptAt:
            typeof args.nextAttemptAt === 'number' ? args.nextAttemptAt : existing.nextAttemptAt,
          ...(args.lastError === null
            ? { lastError: undefined }
            : typeof args.lastError === 'string'
              ? { lastError: args.lastError }
              : { lastError: existing.lastError }),
          ...(args.txHash === null
            ? { txHash: undefined }
            : typeof args.txHash === 'string'
              ? { txHash: args.txHash }
              : { txHash: existing.txHash }),
          updatedAt: Date.now(),
        };
        await store.put(signerOutboxRow(next));
        updated = next;
      },
    );
    return updated;
  }

  async getProfileContinuitySnapshot(
    profileId: string,
  ): Promise<ProfileContinuitySnapshot | null> {
    const profile = await this.getProfile(profileId);
    if (!profile) return null;
    return {
      profile,
      chainAccounts: await this.listChainAccountsByProfile(profile.profileId),
      accountSigners: await this.listAccountSignersByProfile({ profileId: profile.profileId }),
    };
  }

  async listProfileAuthenticators(profileId: string): Promise<ProfileAuthenticatorRecord[]> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return [];
    const db = await this.manager.getDB();
    const tx = db.transaction(SEAMS_WALLET_STORES.walletAuthMethods, 'readonly');
    const rows = (await tx.store
      .index(SEAMS_WALLET_INDEXES.walletIdKind)
      .getAll([normalizedProfileId, 'passkey'])) as unknown[];
    await tx.done;
    return rows.flatMap((row) => {
      const parsed = parseAuthenticatorRow(row);
      return parsed ? [parsed] : [];
    });
  }

  async upsertProfileAuthenticator(record: ProfileAuthenticatorRecord): Promise<void> {
    const normalized = normalizeAuthenticatorRecord(record);
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.wallets, SEAMS_WALLET_STORES.walletAuthMethods],
      'readwrite',
      async (ctx) => {
        const profile = parseProfileRow(
          await ctx.store(SEAMS_WALLET_STORES.wallets).get(normalized.profileId),
        );
        if (!profile) {
          throw makeConstraintError(
            'MISSING_PROFILE',
            `Cannot upsert authenticator for unknown profile: ${normalized.profileId}`,
            { profileId: normalized.profileId, credentialId: normalized.credentialId },
          );
        }
        const store = ctx.store(SEAMS_WALLET_STORES.walletAuthMethods);
        const existing = parseWalletAuthMethodStorageRow(
          await store
            .index(SEAMS_WALLET_INDEXES.passkeyRpIdCredentialId)
            .get(['passkey', DEFAULT_WALLET_RP_ID, normalized.credentialId]),
        );
        const row = walletAuthMethodRowFromAuthenticator(
          normalized,
          existing?.kind === 'passkey' ? existing : undefined,
        );
        await store.put(row);
      },
    );
  }

  async getProfileAuthenticatorByCredentialId(
    profileId: string,
    credentialId: string,
  ): Promise<ProfileAuthenticatorRecord | null> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedCredentialId = toTrimmedString(credentialId || '');
    if (!normalizedProfileId || !normalizedCredentialId) return null;
    const db = await this.manager.getDB();
    const row = parseAuthenticatorRow(
      await db
        .transaction(SEAMS_WALLET_STORES.walletAuthMethods, 'readonly')
        .store.index(SEAMS_WALLET_INDEXES.passkeyRpIdCredentialId)
        .get(['passkey', DEFAULT_WALLET_RP_ID, normalizedCredentialId]),
    );
    return row?.profileId === normalizedProfileId ? row : null;
  }

  async persistWalletRegistrationFinalize(
    input: StoreWalletRegistrationFinalizeBatchInput,
  ): Promise<StoreWalletRegistrationFinalizeBatchResult> {
    const authMethodRows = walletAuthMethodRowsForRegistrationFinalize(input);
    const keyMaterialRows = input.keyMaterials.map((keyMaterial) => keyMaterialRow(keyMaterial));
    const signerActivations: ActivateAccountSignerResult[] = [];
    await this.manager.runTransaction(
      [
        SEAMS_WALLET_STORES.appState,
        SEAMS_WALLET_STORES.wallets,
        SEAMS_WALLET_STORES.walletAuthMethods,
        SEAMS_WALLET_STORES.walletSigners,
        SEAMS_WALLET_STORES.nearAccountProjections,
        SEAMS_WALLET_STORES.signerOpsOutbox,
        SEAMS_WALLET_STORES.keyMaterial,
      ],
      'readwrite',
      async (ctx) => {
        const profileStore = ctx.store(SEAMS_WALLET_STORES.wallets);
        for (const profile of input.profiles) {
          const profileId = toTrimmedString(profile.profileId || '');
          if (!profileId) throw new Error('[SeamsWalletDB] profileId is required');
          const existing = parseProfileRow(await profileStore.get(profileId)) || undefined;
          await profileStore.put(profileRow(profile, existing));
        }

        const authMethodStore = ctx.store(SEAMS_WALLET_STORES.walletAuthMethods);
        for (const row of authMethodRows) {
          const profile = parseProfileRow(await profileStore.get(row.wallet_id));
          if (!profile) {
            throw makeConstraintError(
              'MISSING_PROFILE',
              `Cannot upsert auth method for unknown wallet: ${row.wallet_id}`,
              {
                profileId: row.wallet_id,
                authIdentifierKey: row.auth_identifier_key,
              },
            );
          }
          await authMethodStore.put(row);
        }

        for (const activation of input.signerActivations) {
          signerActivations.push(await this.activateAccountSignerInTransaction(ctx, activation));
        }
        await assertSignerKeyMaterialPairsInTransaction({
          ctx,
          signers: signerActivations.map((activation) => activation.signer),
          keyMaterials: input.keyMaterials,
        });

        const keyMaterialStore = ctx.store(SEAMS_WALLET_STORES.keyMaterial);
        for (const row of keyMaterialRows) {
          await keyMaterialStore.put(row);
        }

        if (input.lastProfileState) {
          await ctx.store(SEAMS_WALLET_STORES.appState).put({
            key: scopedLastProfileStateAppStateKey(input.lastProfileState.scope),
            value: {
              profileId: input.lastProfileState.profileId,
              activeSignerSlot: input.lastProfileState.activeSignerSlot,
              ...(input.lastProfileState.scope
                ? { scope: normalizeLastUserScope(input.lastProfileState.scope) }
                : {}),
            },
          });
        }
      },
    );
    return { signerActivations };
  }

  async persistWalletSignerFinalize(
    input: StoreWalletSignerFinalizeBatchInput,
  ): Promise<StoreWalletRegistrationFinalizeBatchResult> {
    const keyMaterialRows = input.keyMaterials.map((keyMaterial) => keyMaterialRow(keyMaterial));
    const signerActivations: ActivateAccountSignerResult[] = [];
    await this.manager.runTransaction(
      [
        SEAMS_WALLET_STORES.appState,
        SEAMS_WALLET_STORES.wallets,
        SEAMS_WALLET_STORES.walletSigners,
        SEAMS_WALLET_STORES.nearAccountProjections,
        SEAMS_WALLET_STORES.signerOpsOutbox,
        SEAMS_WALLET_STORES.keyMaterial,
      ],
      'readwrite',
      async (ctx) => {
        const profileStore = ctx.store(SEAMS_WALLET_STORES.wallets);
        for (const profile of input.profiles) {
          const profileId = toTrimmedString(profile.profileId || '');
          if (!profileId) throw new Error('[SeamsWalletDB] profileId is required');
          const existing = parseProfileRow(await profileStore.get(profileId)) || undefined;
          await profileStore.put(profileRow(profile, existing));
        }

        for (const activation of input.signerActivations) {
          signerActivations.push(await this.activateAccountSignerInTransaction(ctx, activation));
        }
        await assertSignerKeyMaterialPairsInTransaction({
          ctx,
          signers: signerActivations.map((activation) => activation.signer),
          keyMaterials: input.keyMaterials,
        });

        const keyMaterialStore = ctx.store(SEAMS_WALLET_STORES.keyMaterial);
        for (const row of keyMaterialRows) {
          await keyMaterialStore.put(row);
        }

        if (input.lastProfileState) {
          await ctx.store(SEAMS_WALLET_STORES.appState).put({
            key: scopedLastProfileStateAppStateKey(input.lastProfileState.scope),
            value: {
              profileId: input.lastProfileState.profileId,
              activeSignerSlot: input.lastProfileState.activeSignerSlot,
              ...(input.lastProfileState.scope
                ? { scope: normalizeLastUserScope(input.lastProfileState.scope) }
                : {}),
            },
          });
        }
      },
    );
    return { signerActivations };
  }

  async clearProfileAuthenticators(profileId: string): Promise<void> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.walletAuthMethods],
      'readwrite',
      async (ctx) => {
        const store = ctx.store(SEAMS_WALLET_STORES.walletAuthMethods);
        let cursor = await store
          .index(SEAMS_WALLET_INDEXES.walletIdKind)
          .openCursor(IDBKeyRange.only([normalizedProfileId, 'passkey']));
        while (cursor) {
          await cursor.delete();
          cursor = await cursor.continue();
        }
      },
    );
  }

  async selectProfileAuthenticatorsForPrompt(args: {
    profileId: string;
    authenticators: ProfileAuthenticatorRecord[];
    selectedCredentialRawId?: string;
    accountLabel?: string;
  }): Promise<{
    authenticatorsForPrompt: ProfileAuthenticatorRecord[];
    wrongPasskeyError?: string;
  }> {
    const profileId = toTrimmedString(args.profileId || '');
    const authenticators = Array.isArray(args.authenticators) ? args.authenticators : [];
    if (!profileId || authenticators.length <= 1) {
      return { authenticatorsForPrompt: authenticators };
    }

    const lastProfileState = await this.getLastProfileState().catch(() => null);
    if (!lastProfileState || lastProfileState.profileId !== profileId) {
      return { authenticatorsForPrompt: authenticators };
    }

    const expectedSignerSlot = Number(lastProfileState.activeSignerSlot);
    const bySignerSlot = authenticators.filter((authenticator) => {
      return authenticator.signerSlot === expectedSignerSlot;
    });
    const expectedCredentialId = toTrimmedString(
      bySignerSlot[0]?.credentialId || authenticators[0]?.credentialId || '',
    );
    const byCredentialId = expectedCredentialId
      ? authenticators.filter((authenticator) => authenticator.credentialId === expectedCredentialId)
      : [];
    const authenticatorsForPrompt =
      byCredentialId.length > 0
        ? byCredentialId
        : bySignerSlot.length > 0
          ? bySignerSlot
          : authenticators;

    const selectedCredentialRawId = toTrimmedString(args.selectedCredentialRawId || '');
    const accountLabel = toTrimmedString(args.accountLabel || profileId);
    const wrongPasskeyError =
      selectedCredentialRawId &&
      expectedCredentialId &&
      selectedCredentialRawId !== expectedCredentialId
        ? `You have multiple passkeys for account ${accountLabel}, ` +
          'but used a different passkey than the most recently logged-in one. ' +
          'Please use the passkey for the most recently active signer.'
        : undefined;

    return { authenticatorsForPrompt, wrongPasskeyError };
  }

  async updatePreferences(args: {
    profileId: string;
    preferences: Partial<UserPreferences>;
  }): Promise<UserPreferences | null> {
    const profileId = toTrimmedString(args.profileId || '');
    if (!profileId) return null;
    let updatedPreferences: UserPreferences | null = null;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.wallets],
      'readwrite',
      async (ctx) => {
        const store = ctx.store(SEAMS_WALLET_STORES.wallets);
        const profile = parseProfileRow(await store.get(profileId));
        if (!profile) return;
        updatedPreferences = {
          ...(profile.preferences || {}),
          ...args.preferences,
        } as UserPreferences;
        const next = profileRow(
          {
            profileId: profile.profileId,
            defaultSignerSlot: profile.defaultSignerSlot,
            preferences: updatedPreferences,
            ...(profile.passkeyCredential ? { passkeyCredential: profile.passkeyCredential } : {}),
          },
          profile,
        );
        await store.put(next);
      },
    );
    return updatedPreferences;
  }

  async deleteProfileData(profileId: string, scope?: string | null): Promise<void> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return;
    await this.manager.runTransaction(
      [
        SEAMS_WALLET_STORES.appState,
        SEAMS_WALLET_STORES.wallets,
        SEAMS_WALLET_STORES.walletAuthMethods,
        SEAMS_WALLET_STORES.walletSigners,
        SEAMS_WALLET_STORES.nearAccountProjections,
        SEAMS_WALLET_STORES.signerOpsOutbox,
        SEAMS_WALLET_STORES.recoveryEmails,
        SEAMS_WALLET_STORES.keyMaterial,
      ],
      'readwrite',
      async (ctx) => {
        const appStateStore = ctx.store(SEAMS_WALLET_STORES.appState);
        const unscopedLastProfile = parseLastProfileState(
          (await appStateStore.get(scopedLastProfileStateAppStateKey()))?.value,
        );
        if (unscopedLastProfile?.profileId === normalizedProfileId) {
          await appStateStore.put({ key: scopedLastProfileStateAppStateKey(), value: null });
        }
        const scopedKey = scopedLastProfileStateAppStateKey(scope);
        if (scopedKey !== scopedLastProfileStateAppStateKey()) {
          const scopedLastProfile = parseLastProfileState((await appStateStore.get(scopedKey))?.value);
          if (scopedLastProfile?.profileId === normalizedProfileId) {
            await appStateStore.put({ key: scopedKey, value: null });
          }
        }

        await ctx.store(SEAMS_WALLET_STORES.wallets).delete(normalizedProfileId);
        await deleteRowsByIndex({
          store: ctx.store(SEAMS_WALLET_STORES.walletAuthMethods),
          indexName: SEAMS_WALLET_INDEXES.walletId,
          key: IDBKeyRange.only(normalizedProfileId),
        });
        await deleteRowsByIndex({
          store: ctx.store(SEAMS_WALLET_STORES.walletSigners),
          indexName: SEAMS_WALLET_INDEXES.walletId,
          key: IDBKeyRange.only(normalizedProfileId),
        });
        await deleteRowsByIndex({
          store: ctx.store(SEAMS_WALLET_STORES.nearAccountProjections),
          indexName: SEAMS_WALLET_INDEXES.profileId,
          key: IDBKeyRange.only(normalizedProfileId),
        });
        await deleteRowsByIndex({
          store: ctx.store(SEAMS_WALLET_STORES.signerOpsOutbox),
          indexName: SEAMS_WALLET_INDEXES.walletId,
          key: IDBKeyRange.only(normalizedProfileId),
        });
        await deleteRowsByIndex({
          store: ctx.store(SEAMS_WALLET_STORES.recoveryEmails),
          indexName: SEAMS_WALLET_INDEXES.walletId,
          key: IDBKeyRange.only(normalizedProfileId),
        });
        await deleteRowsByIndex({
          store: ctx.store(SEAMS_WALLET_STORES.keyMaterial),
          indexName: SEAMS_WALLET_INDEXES.walletId,
          key: IDBKeyRange.only(normalizedProfileId),
        });
      },
    );
  }

  async getLastProfileState(scope?: string | null): Promise<LastProfileState | null> {
    const key = scopedLastProfileStateAppStateKey(scope);
    const scopedRaw = await this.getAppState<unknown>(key).catch(() => undefined);
    return parseLastProfileState(scopedRaw);
  }

  async setLastProfileState(state: LastProfileState | null, scope?: string | null): Promise<void> {
    const key = scopedLastProfileStateAppStateKey(scope);
    const normalizedState = state ? parseLastProfileState(state) : null;
    if (state && !normalizedState) {
      throw new Error('[SeamsWalletDB] invalid last profile state');
    }
    await this.setAppState(key, normalizedState);
  }

  async setLastProfileStateForProfile(
    profileId: string,
    activeSignerSlot: number,
    scope?: string | null,
  ): Promise<void> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedActiveSignerSlot = Number(activeSignerSlot);
    if (!normalizedProfileId) {
      throw new Error('[SeamsWalletDB] profileId is required');
    }
    if (!Number.isSafeInteger(normalizedActiveSignerSlot) || normalizedActiveSignerSlot < 1) {
      throw new Error('[SeamsWalletDB] activeSignerSlot must be an integer >= 1');
    }
    const normalizedScope = normalizeLastUserScope(scope);
    await this.setLastProfileState(
      {
        profileId: normalizedProfileId,
        activeSignerSlot: normalizedActiveSignerSlot,
        ...(normalizedScope ? { scope: normalizedScope } : {}),
      },
      normalizedScope,
    );
  }

  async clearLastProfileSelection(scope?: string | null): Promise<void> {
    await this.setLastProfileState(null, scope);
  }

  async upsertRecoveryEmails(
    walletId: string,
    entries: Array<{ hashHex: string; email: string }>,
  ): Promise<void> {
    const normalizedWalletId = toTrimmedString(walletId || '');
    if (!normalizedWalletId || entries.length === 0) return;
    const now = Date.now();
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.recoveryEmails],
      'readwrite',
      async (ctx) => {
        const store = ctx.store(SEAMS_WALLET_STORES.recoveryEmails);
        for (const entry of entries) {
          const hashHex = toTrimmedString(entry.hashHex || '');
          const email = toTrimmedString(entry.email || '');
          if (!hashHex) continue;
          const row: RecoveryEmailRow = {
            wallet_id: normalizedWalletId,
            hash_hex: hashHex,
            email: email || hashHex,
            added_at: now,
            updated_at: now,
          };
          await store.put(row);
        }
      },
    );
  }

  async listRecoveryEmails(walletId: string): Promise<ProfileRecoveryEmailRecord[]> {
    const normalizedWalletId = toTrimmedString(walletId || '');
    if (!normalizedWalletId) return [];
    const db = await this.manager.getDB();
    const tx = db.transaction(SEAMS_WALLET_STORES.recoveryEmails, 'readonly');
    const rows = (await tx.store
      .index(SEAMS_WALLET_INDEXES.walletId)
      .getAll(normalizedWalletId)) as unknown[];
    await tx.done;
    return rows.flatMap((row) => {
      const parsed = profileRecoveryEmailFromRow(row);
      return parsed ? [parsed] : [];
    });
  }

  async storeKeyMaterial(data: KeyMaterialRecord): Promise<void> {
    const row = keyMaterialRow(data);
    await this.manager.runTransaction([SEAMS_WALLET_STORES.keyMaterial], 'readwrite', async (ctx) => {
      await ctx.store(SEAMS_WALLET_STORES.keyMaterial).put(row);
    });
  }

  async getKeyMaterial(
    profileId: string,
    signerSlot: number,
    chainIdKey: string,
    keyKind: KeyMaterialKind,
  ): Promise<KeyMaterialRecord | null> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedChainIdKey = toTrimmedString(chainIdKey || '').toLowerCase();
    const normalizedKeyKind = toTrimmedString(keyKind || '');
    if (!normalizedProfileId || !normalizedChainIdKey || !normalizedKeyKind) return null;
    let selected: KeyMaterialRecord | null = null;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.keyMaterial, SEAMS_WALLET_STORES.walletSigners],
      'readonly',
      async (ctx) => {
        const keyMaterialRows = (await ctx
          .store(SEAMS_WALLET_STORES.keyMaterial)
          .index(SEAMS_WALLET_INDEXES.walletId)
          .getAll(normalizedProfileId)) as unknown[];
        const matches = keyMaterialRows.flatMap((row) => {
          const parsed = parseKeyMaterialRow(row);
          return parsed &&
            parsed.signerSlot === signerSlot &&
            parsed.chainIdKey === normalizedChainIdKey &&
            parsed.keyKind === normalizedKeyKind
            ? [parsed]
            : [];
        });
        if (matches.length === 0) {
          selected = null;
          return;
        }
        const signerRows = (await ctx
          .store(SEAMS_WALLET_STORES.walletSigners)
          .index(SEAMS_WALLET_INDEXES.walletId)
          .getAll(normalizedProfileId)) as unknown[];
        const activeSigners = signerRows.flatMap((row) => {
          const parsed = parseAccountSignerRow(row);
          return parsed?.status === 'active' &&
            parsed.signerSlot === signerSlot &&
            parsed.chainIdKey === normalizedChainIdKey
            ? [parsed]
            : [];
        });
        selected = selectKeyMaterialForRead({ matches, activeSigners });
      }
    );
    return selected;
  }

  async listKeyMaterialByProfile(
    profileId: string,
    chainIdKey?: string,
  ): Promise<KeyMaterialRecord[]> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedChainIdKey = toTrimmedString(chainIdKey || '').toLowerCase();
    if (!normalizedProfileId) return [];
    const db = await this.manager.getDB();
    const tx = db.transaction(SEAMS_WALLET_STORES.keyMaterial, 'readonly');
    const rows = (await tx.store
      .index(SEAMS_WALLET_INDEXES.walletId)
      .getAll(normalizedProfileId)) as unknown[];
    await tx.done;
    const records = rows.flatMap((row) => {
      const parsed = parseKeyMaterialRow(row);
      return parsed ? [parsed] : [];
    });
    if (!normalizedChainIdKey) return records;
    return records.filter((record) => record.chainIdKey === normalizedChainIdKey);
  }

  async listKeyMaterialByProfileAndSignerSlot(
    profileId: string,
    signerSlot: number,
    chainIdKey?: string,
  ): Promise<KeyMaterialRecord[]> {
    if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) return [];
    const records = await this.listKeyMaterialByProfile(profileId, chainIdKey);
    return records.filter((record) => record.signerSlot === signerSlot);
  }

  async deleteKeyMaterial(
    profileId: string,
    signerSlot: number,
    chainIdKey: string,
    keyKind: KeyMaterialKind,
  ): Promise<void> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedChainIdKey = toTrimmedString(chainIdKey || '').toLowerCase();
    const normalizedKeyKind = toTrimmedString(keyKind || '');
    if (!normalizedProfileId || !normalizedChainIdKey || !normalizedKeyKind) return;
    if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) return;
    await this.manager.runTransaction([SEAMS_WALLET_STORES.keyMaterial], 'readwrite', async (ctx) => {
      const store = ctx.store(SEAMS_WALLET_STORES.keyMaterial);
      const rows = (await store
        .index(SEAMS_WALLET_INDEXES.walletId)
        .getAll(normalizedProfileId)) as unknown[];
      for (const row of rows) {
        const parsed = parseKeyMaterialRow(row);
        if (
          parsed &&
          parsed.signerSlot === signerSlot &&
          parsed.chainIdKey === normalizedChainIdKey &&
          parsed.keyKind === normalizedKeyKind
        ) {
          await store.delete(keyMaterialId({
            walletSignerId: walletSignerIdForKeyMaterial(parsed),
            keyKind: parsed.keyKind,
          }));
        }
      }
    });
  }

  async readNonceLaneLeaseRecords(laneKey: string): Promise<NonceLaneLeaseStoreRecord[]> {
    const normalizedLaneKey = toTrimmedString(laneKey || '');
    if (!normalizedLaneKey) return [];
    const db = await this.manager.getDB();
    const tx = db.transaction(SEAMS_WALLET_STORES.nonceLaneLeases, 'readonly');
    const rows = (await tx.store
      .index(SEAMS_WALLET_INDEXES.laneKey)
      .getAll(normalizedLaneKey)) as unknown[];
    await tx.done;
    return rows.flatMap((row) => {
      const parsed = parseNonceLeaseRow(row);
      return parsed ? [parsed] : [];
    });
  }

  async listNonceLaneLeaseRecords(args?: {
    accountId?: string;
  }): Promise<NonceLaneLeaseStoreRecord[]> {
    const accountId = toTrimmedString(args?.accountId || '');
    const db = await this.manager.getDB();
    const tx = db.transaction(SEAMS_WALLET_STORES.nonceLaneLeases, 'readonly');
    const rows = (accountId
      ? await tx.store.index(SEAMS_WALLET_INDEXES.accountId).getAll(accountId)
      : await tx.store.getAll()) as unknown[];
    await tx.done;
    return rows.flatMap((row) => {
      const parsed = parseNonceLeaseRow(row);
      return parsed ? [parsed] : [];
    });
  }

  async upsertNonceLaneLeaseRecord(record: NonceLaneLeaseStoreRecord): Promise<void> {
    const row = nonceLeaseRow(record);
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.nonceLaneLeases],
      'readwrite',
      async (ctx) => {
        await ctx.store(SEAMS_WALLET_STORES.nonceLaneLeases).put(row);
      },
    );
  }

  async removeNonceLaneLeaseRecord(input: { leaseId: string }): Promise<void> {
    const leaseId = toTrimmedString(input.leaseId || '');
    if (!leaseId) return;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.nonceLaneLeases],
      'readwrite',
      async (ctx) => {
        await ctx.store(SEAMS_WALLET_STORES.nonceLaneLeases).delete(leaseId);
      },
    );
  }

  async clearNonceLaneLeaseRecordsForAccount(accountId: string): Promise<void> {
    const normalizedAccountId = toTrimmedString(accountId || '');
    if (!normalizedAccountId) return;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.nonceLaneLeases],
      'readwrite',
      async (ctx) => {
        const store = ctx.store(SEAMS_WALLET_STORES.nonceLaneLeases);
        const rows = (await store
          .index(SEAMS_WALLET_INDEXES.accountId)
          .getAll(normalizedAccountId)) as unknown[];
        for (const row of rows) {
          const parsed = parseNonceLeaseRow(row);
          if (parsed) await store.delete(parsed.leaseId);
        }
      },
    );
  }

  async clearAllNonceLaneLeaseRecords(): Promise<void> {
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.nonceLaneLeases],
      'readwrite',
      async (ctx) => {
        await ctx.store(SEAMS_WALLET_STORES.nonceLaneLeases).clear();
      },
    );
  }

  async pruneExpiredNonceLaneLeaseRecords(nowMs: number): Promise<void> {
    const normalizedNow = Math.floor(Number(nowMs));
    if (!Number.isSafeInteger(normalizedNow)) return;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.nonceLaneLeases],
      'readwrite',
      async (ctx) => {
        const store = ctx.store(SEAMS_WALLET_STORES.nonceLaneLeases);
        const rows = (await store
          .index(SEAMS_WALLET_INDEXES.expiresAtMs)
          .getAll(keyRangeUpperBound(normalizedNow))) as unknown[];
        for (const row of rows) {
          const parsed = parseNonceLeaseRow(row);
          if (parsed) await store.delete(parsed.leaseId);
        }
      },
    );
  }

  async withNonceLaneCoordinationLock<T>(
    input: {
      lockKey: string;
      ownerId: string;
      ttlMs?: number;
      waitTimeoutMs?: number;
    },
    task: () => Promise<T>,
  ): Promise<T> {
    const lockKey = toTrimmedString(input.lockKey || '');
    const ownerId = toTrimmedString(input.ownerId || '');
    if (!lockKey || !ownerId) {
      throw new Error('[SeamsWalletDB] nonce lane lock requires lockKey and ownerId');
    }
    const ttlMs = Math.max(1, Math.floor(Number(input.ttlMs) || DEFAULT_NONCE_LANE_LOCK_TTL_MS));
    const waitTimeoutMs = Math.max(
      1,
      Math.floor(Number(input.waitTimeoutMs) || DEFAULT_NONCE_LANE_LOCK_WAIT_TIMEOUT_MS),
    );
    const fencingToken = createRandomToken('nonce-lane-lock');
    const deadlineMs = Date.now() + waitTimeoutMs;

    const tryAcquire = async (): Promise<boolean> => {
      let acquired = false;
      await this.manager.runTransaction(
        [SEAMS_WALLET_STORES.nonceLaneLocks],
        'readwrite',
        async (ctx) => {
          const store = ctx.store(SEAMS_WALLET_STORES.nonceLaneLocks);
          const nowMs = Date.now();
          const existing = (await store.get(lockKey)) as NonceLaneLockRow | undefined;
          if (existing && Number(existing.expires_at_ms) > nowMs) return;
          const next: NonceLaneLockRow = {
            lock_key: lockKey,
            owner_id: ownerId,
            fencing_token: fencingToken,
            acquired_at_ms: nowMs,
            expires_at_ms: nowMs + ttlMs,
            updated_at_ms: nowMs,
          };
          await store.put(next);
          acquired = true;
        },
      );
      return acquired;
    };

    while (!(await tryAcquire())) {
      if (Date.now() >= deadlineMs) {
        const error = new Error('[SeamsWalletDB] durable nonce lane lock timed out') as Error & {
          code?: string;
        };
        error.code = 'durable_lock_timeout';
        throw error;
      }
      await sleep(DEFAULT_NONCE_LANE_LOCK_POLL_MS);
    }

    try {
      return await task();
    } finally {
      await this.manager
        .runTransaction([SEAMS_WALLET_STORES.nonceLaneLocks], 'readwrite', async (ctx) => {
          const store = ctx.store(SEAMS_WALLET_STORES.nonceLaneLocks);
          const existing = (await store.get(lockKey)) as NonceLaneLockRow | undefined;
          if (existing?.fencing_token === fencingToken) {
            await store.delete(lockKey);
          }
        })
        .catch(() => undefined);
    }
  }
}
