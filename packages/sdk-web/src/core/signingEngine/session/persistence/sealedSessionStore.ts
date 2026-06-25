import { normalizeInteger, normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  decodeJwtPayloadRecord,
  ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
} from '@shared/utils/sessionTokens';
import {
  signingSessionSealsRepository,
  type StoredRawSealedRecordEntry,
} from '../../../indexedDB/seamsWalletDB/signingSessionSeals';
import {
  SIGNING_SESSION_SEALED_RECORD_VERSION,
  SIGNING_SESSION_SEAL_ALG,
  SIGNING_SESSION_SEAL_STORAGE_SCOPE,
  SIGNING_SESSION_SECRET_KIND,
  type SealedSigningSessionEcdsaRestoreMetadata,
  type SealedSigningSessionEd25519RestoreMetadata,
  type SealedSigningSessionRecord,
} from '@shared/utils/signingSessionSeal';
import {
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { parseRouterAbEd25519NormalSigningState } from '../../threshold/ed25519/routerAbNormalSigningState';
import {
  exactSealedSessionFilterForIdentity,
  type DeleteDurableSealedSessionCommand,
} from './durableSealedSessionCommands';
import {
  clearStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget,
  clearStoredThresholdEcdsaSessionRecordsForWalletKeyHandle,
} from './records';

export type SigningSessionRestoreLease = {
  v: 1;
  leaseKey: string;
  signingGrantId: string;
  ownerId: string;
  attemptId: string;
  startedAtMs: number;
  expiresAtMs: number;
};

export type SigningSessionRestoreLeaseHandle = SigningSessionRestoreLease & {
  thresholdSessionId: string;
};

export type SigningSessionSealedStoreRecord = SealedSigningSessionRecord & {
  storeKey: string;
  curve: 'ed25519' | 'ecdsa';
};
export type CurrentEd25519SealedSessionRecord = SigningSessionSealedStoreRecord & {
  curve: 'ed25519';
  walletId: string;
  relayerUrl: string;
  ed25519Restore: SealedSigningSessionEd25519RestoreMetadata;
};

export type CurrentEcdsaSealedSessionRecord = SigningSessionSealedStoreRecord & {
  curve: 'ecdsa';
  walletId: string;
  subjectId?: never;
  signingRootId?: never;
  signingRootVersion?: never;
  relayerUrl: string;
  ecdsaRestore: SealedSigningSessionEcdsaRestoreMetadata;
};

export type CurrentSealedSessionRecord =
  | CurrentEd25519SealedSessionRecord
  | CurrentEcdsaSealedSessionRecord;
export type RawSealedSessionRecord = Record<string, unknown>;

export type SealedSessionRecordClassificationReason =
  | 'invalid_payload'
  | 'invalid_header'
  | 'invalid_identity'
  | 'missing_signing_root_id'
  | 'missing_participant_ids'
  | 'missing_restore_metadata'
  | 'missing_wallet_session_jwt';

export type CurrentSealedSessionRecordClassification = {
  kind: 'current';
  record: CurrentSealedSessionRecord;
};

export type DeleteRequiredSealedSessionRecordClassification = {
  kind: 'delete_required';
  storeKey: string | null;
  walletId: string | null;
  reason: SealedSessionRecordClassificationReason;
  safeSummary: Record<string, unknown>;
};

export type RebuildRequiredSealedSessionRecordClassification = {
  kind: 'rebuild_required';
  storeKey: string | null;
  walletId: string | null;
  reason: SealedSessionRecordClassificationReason;
  safeSummary: Record<string, unknown>;
};

export type UserActionRequiredSealedSessionRecordClassification = {
  kind: 'user_action_required';
  storeKey: string | null;
  walletId: string | null;
  reason: SealedSessionRecordClassificationReason;
  safeSummary: Record<string, unknown>;
};

export type MalformedSealedSessionRecordClassification = {
  kind: 'malformed';
  storeKey: string | null;
  walletId: string | null;
  reason: SealedSessionRecordClassificationReason;
  safeSummary: Record<string, unknown>;
};

export type SealedSessionRecordClassification =
  | CurrentSealedSessionRecordClassification
  | DeleteRequiredSealedSessionRecordClassification
  | RebuildRequiredSealedSessionRecordClassification
  | UserActionRequiredSealedSessionRecordClassification
  | MalformedSealedSessionRecordClassification;

export class SealedSessionRecordUserActionRequiredError extends Error {
  readonly classification: UserActionRequiredSealedSessionRecordClassification;

  constructor(classification: UserActionRequiredSealedSessionRecordClassification) {
    super(
      `[SigningSessionSealedStore] sealed session record requires user action: ${classification.reason}`,
    );
    this.name = 'SealedSessionRecordUserActionRequiredError';
    this.classification = classification;
  }
}
// Sealed records are indexed by threshold session id, but that id can appear
// on more than one lane. Every read/delete/lease must name the intended lane.
export type SigningSessionSealedRecordFilter =
  | {
      authMethod: 'passkey' | 'email_otp';
      curve: 'ed25519';
    }
  | {
      authMethod: 'passkey' | 'email_otp';
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    };

export type ListExactSigningSessionSealedRecordsForWalletFilter = SigningSessionSealedRecordFilter;

export type ListEcdsaSigningSessionSealedRecordsForWalletFilter = {
  authMethod?: 'passkey' | 'email_otp';
  curve: 'ecdsa';
};

type BuildCurrentSealedSessionRecordCommonInput = {
  thresholdSessionId: string;
  sealedSecretB64u: string;
  authMethod: 'passkey' | 'email_otp';
  signingGrantId: string;
  thresholdSessionIds?: {
    ed25519?: string;
    ecdsa?: string;
  };
  keyVersion?: string;
  shamirPrimeB64u?: string;
  issuedAtMs?: number;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs?: number;
};

export type BuildCurrentEd25519SealedSessionRecordInput =
  BuildCurrentSealedSessionRecordCommonInput & {
    curve: 'ed25519';
    walletId: string;
    userId?: string;
    subjectId?: never;
    signingRootId?: string;
    signingRootVersion?: string;
    relayerUrl: string;
    ecdsaRestore?: SealedSigningSessionEcdsaRestoreMetadata;
    ed25519Restore: SealedSigningSessionEd25519RestoreMetadata;
  };

export type BuildCurrentEcdsaSealedSessionRecordInput =
  BuildCurrentSealedSessionRecordCommonInput & {
    curve: 'ecdsa';
    subjectId?: never;
    walletId: string;
    userId?: string;
    signingRootId?: never;
    signingRootVersion?: never;
    relayerUrl: string;
    ecdsaRestore: SealedSigningSessionEcdsaRestoreMetadata;
    ed25519Restore?: SealedSigningSessionEd25519RestoreMetadata;
  };

export type BuildCurrentSealedSessionRecordInput =
  | BuildCurrentEd25519SealedSessionRecordInput
  | BuildCurrentEcdsaSealedSessionRecordInput;

export type BuildCurrentSealedSessionRecordBaseInput = {
  thresholdSessionId: string;
  sealedSecretB64u: string;
  authMethod: 'passkey' | 'email_otp';
  signingGrantId: string;
  thresholdSessionIds?: {
    ed25519?: string;
    ecdsa?: string;
  };
  subjectId?: string;
  walletId?: string;
  userId?: string;
  signingRootId?: string;
  signingRootVersion?: string;
  relayerUrl?: string;
  keyVersion?: string;
  shamirPrimeB64u?: string;
  ecdsaRestore?: SealedSigningSessionEcdsaRestoreMetadata;
  ed25519Restore?: SealedSigningSessionEd25519RestoreMetadata;
  issuedAtMs?: number;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs?: number;
};

export type SealedStoreResolvedSigningSessionIdentity =
  | {
      walletId: string;
      authMethod: 'passkey' | 'email_otp';
      curve: 'ed25519';
      chain: 'near';
      signingGrantId: string;
      thresholdSessionId: string;
      updatedAtMs: number;
    }
  | {
      walletId: string;
      authMethod: 'passkey' | 'email_otp';
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
      signingGrantId: string;
      thresholdSessionId: string;
      updatedAtMs: number;
    };

export type PublishResolvedIdentityInput =
  | (Omit<
      Extract<SealedStoreResolvedSigningSessionIdentity, { curve: 'ed25519' }>,
      'updatedAtMs'
    > & {
      updatedAtMs?: number;
    })
  | (Omit<Extract<SealedStoreResolvedSigningSessionIdentity, { curve: 'ecdsa' }>, 'updatedAtMs'> & {
      updatedAtMs?: number;
    });

export type ExactResolvedSessionIdentity = SealedStoreResolvedSigningSessionIdentity;

export type ResolvedIdentityDeleteReason =
  | 'durable_record_deleted'
  | 'invalid_persisted_record'
  | 'same_lane_replaced'
  | 'same_scope_replaced';

type DeleteResolvedIdentityCommand = {
  kind: 'delete_resolved_identity';
  identity: ExactResolvedSessionIdentity;
  deleteReason: ResolvedIdentityDeleteReason;
};

type DeleteExactSealedSessionOptions =
  | {
      deleteResolvedIdentity: true;
      resolvedIdentityDeleteReason: ResolvedIdentityDeleteReason;
    }
  | {
      deleteResolvedIdentity: false;
      resolvedIdentityDeleteReason?: never;
    };

const DEFAULT_RESTORE_LEASE_TTL_MS = 15_000;
const SEALED_RECORD_PAYLOAD_FIELD = 'sealed_record';
const resolvedIdentitiesByPurposeKey = new Map<string, SealedStoreResolvedSigningSessionIdentity>();
const resolvedIdentityKeysByListKey = new Map<string, Set<string>>();

function createRandomId(prefix: string): string {
  return secureRandomId(prefix, 32, 'sealed signing session restore IDs');
}

function normalizeThresholdSessionIds(value: unknown): {
  ed25519?: string;
  ecdsa?: string;
} {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : {};
  const ed25519 = normalizeOptionalNonEmptyString(obj.ed25519);
  const ecdsa = normalizeOptionalNonEmptyString(obj.ecdsa);
  return {
    ...(ed25519 ? { ed25519 } : {}),
    ...(ecdsa ? { ecdsa } : {}),
  };
}

function normalizeThresholdSessionIdsFromStoredRecord(value: unknown): {
  ed25519?: string;
  ecdsa?: string;
} {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : {};
  const current = normalizeThresholdSessionIds(obj.thresholdSessionIds);
  if (current.ed25519 || current.ecdsa) return current;
  const legacyThresholdSessionId = normalizeOptionalNonEmptyString(obj.thresholdSessionId);
  const curve = normalizeCurve(obj.curve);
  if (!legacyThresholdSessionId || !curve) return {};
  return curve === 'ed25519'
    ? { ed25519: legacyThresholdSessionId }
    : { ecdsa: legacyThresholdSessionId };
}

function legacySigningGrantFieldName(): string {
  return ['wallet', 'SigningSessionId'].join('');
}

function normalizeStoredSigningGrantId(value: unknown): string | undefined {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : {};
  return (
    normalizeOptionalNonEmptyString(obj.signingGrantId) ||
    normalizeOptionalNonEmptyString(obj[legacySigningGrantFieldName()])
  );
}

function normalizeCurve(value: unknown): 'ed25519' | 'ecdsa' | undefined {
  const curve = String(value || '').trim();
  return curve === 'ed25519' || curve === 'ecdsa' ? curve : undefined;
}

function storagePayloadFromSealedStoreRow(value: unknown): unknown {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  return obj && SEALED_RECORD_PAYLOAD_FIELD in obj ? obj[SEALED_RECORD_PAYLOAD_FIELD] : value;
}

function optionalStringForIndex(value: unknown): string | undefined {
  return normalizeOptionalNonEmptyString(value);
}

function sealedRecordStorageRow(record: CurrentSealedSessionRecord): Record<string, unknown> {
  const ecdsaChainTarget = record.ecdsaRestore?.chainTarget;
  const ecdsaThresholdSessionId = optionalStringForIndex(record.thresholdSessionIds.ecdsa);
  const ed25519ThresholdSessionId = optionalStringForIndex(record.thresholdSessionIds.ed25519);
  return {
    store_key: record.storeKey,
    wallet_id: record.walletId,
    user_id: optionalStringForIndex(record.userId),
    auth_method: record.authMethod,
    curve: record.curve,
    signing_root_id: optionalStringForIndex(record.signingRootId),
    signing_root_version: optionalStringForIndex(record.signingRootVersion),
    signing_grant_id: record.signingGrantId,
    ed25519_threshold_session_id: ed25519ThresholdSessionId,
    ecdsa_threshold_session_id: ecdsaThresholdSessionId,
    threshold_session_id: ecdsaThresholdSessionId || ed25519ThresholdSessionId,
    key_handle: optionalStringForIndex(record.ecdsaRestore?.keyHandle),
    chain_target_key: ecdsaChainTarget ? thresholdEcdsaChainTargetKey(ecdsaChainTarget) : undefined,
    expires_at_ms: record.expiresAtMs,
    updated_at: record.updatedAtMs,
    [SEALED_RECORD_PAYLOAD_FIELD]: record,
  };
}

function restoreLeaseStorageRow(lease: SigningSessionRestoreLease): Record<string, unknown> {
  return {
    lease_key: lease.leaseKey,
    signing_grant_id: lease.signingGrantId,
    owner_id: lease.ownerId,
    attempt_id: lease.attemptId,
    started_at_ms: lease.startedAtMs,
    expires_at_ms: lease.expiresAtMs,
    lease,
  };
}

function normalizeEthereumAddress(value: unknown): `0x${string}` | undefined {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  return /^0x[0-9a-f]{40}$/.test(normalized) ? (normalized as `0x${string}`) : undefined;
}

function resolveSealedRecordCurve(args: {
  curve?: 'ed25519' | 'ecdsa';
  thresholdSessionIds: { ed25519?: string; ecdsa?: string };
}): 'ed25519' | 'ecdsa' | null {
  if (args.curve) return args.curve;
  if (args.thresholdSessionIds.ecdsa) return 'ecdsa';
  if (args.thresholdSessionIds.ed25519) return 'ed25519';
  return null;
}

function normalizeEcdsaRestoreMetadata(
  value: unknown,
): SealedSigningSessionEcdsaRestoreMetadata | undefined {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (!obj) return undefined;
  let chainTarget: ThresholdEcdsaChainTarget | null = null;
  try {
    chainTarget = thresholdEcdsaChainTargetFromRequest(
      obj.chainTarget && typeof obj.chainTarget === 'object' && !Array.isArray(obj.chainTarget)
        ? (obj.chainTarget as Record<string, unknown>)
        : {},
    );
  } catch {
    chainTarget = null;
  }
  const sessionKindRaw = String(obj.sessionKind || '').trim();
  const sessionKind =
    sessionKindRaw === 'cookie' || sessionKindRaw === 'jwt' ? sessionKindRaw : undefined;
  const rpId = normalizeOptionalNonEmptyString(obj.rpId);
  const walletKeyId = normalizeOptionalNonEmptyString(obj.walletKeyId);
  const credentialIdB64u = normalizeOptionalNonEmptyString(obj.credentialIdB64u);
  const providerSubjectId = normalizeOptionalNonEmptyString(obj.providerSubjectId);
  const authSubjectId = normalizeOptionalNonEmptyString(obj.authSubjectId);
  const keyHandle = normalizeOptionalNonEmptyString(obj.keyHandle);
  const ecdsaThresholdKeyId = normalizeOptionalNonEmptyString(obj.ecdsaThresholdKeyId);
  const ethereumAddress = normalizeEthereumAddress(obj.ethereumAddress);
  const relayerKeyId = normalizeOptionalNonEmptyString(obj.relayerKeyId);
  const thresholdEcdsaPublicKeyB64u = normalizeOptionalNonEmptyString(
    obj.thresholdEcdsaPublicKeyB64u,
  );
  const participantIds = Array.isArray(obj.participantIds)
    ? obj.participantIds
        .map((participantId) => Math.floor(Number(participantId)))
        .filter((participantId) => Number.isFinite(participantId) && participantId > 0)
    : [];
  if (
    !chainTarget ||
    !sessionKind ||
    !keyHandle ||
    !ethereumAddress ||
    !relayerKeyId ||
    !participantIds.length
  ) {
    return undefined;
  }
  const authBranch =
    credentialIdB64u && rpId
      ? ({ rpId, credentialIdB64u } as const)
      : walletKeyId && (providerSubjectId || authSubjectId)
        ? ({
            walletKeyId,
            ...(providerSubjectId ? { providerSubjectId } : {}),
            ...(authSubjectId ? { authSubjectId } : {}),
          } as const)
        : null;
  if (!authBranch) return undefined;
  const walletSessionJwt = normalizeOptionalNonEmptyString(obj.walletSessionJwt);
  const clientVerifyingShareB64u = normalizeOptionalNonEmptyString(obj.clientVerifyingShareB64u);
  return {
    chainTarget,
    ...authBranch,
    ...(walletSessionJwt ? { walletSessionJwt } : {}),
    sessionKind,
    keyHandle,
    ...(ecdsaThresholdKeyId ? { ecdsaThresholdKeyId } : {}),
    ethereumAddress,
    relayerKeyId,
    ...(clientVerifyingShareB64u ? { clientVerifyingShareB64u } : {}),
    ...(thresholdEcdsaPublicKeyB64u ? { thresholdEcdsaPublicKeyB64u } : {}),
    participantIds,
    ...(obj.runtimePolicyScope && typeof obj.runtimePolicyScope === 'object'
      ? { runtimePolicyScope: obj.runtimePolicyScope }
      : {}),
  };
}

function normalizeEd25519RestoreMetadata(
  value: unknown,
): SealedSigningSessionEd25519RestoreMetadata | undefined {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (!obj) return undefined;
  const nearAccountId = normalizeOptionalNonEmptyString(obj.nearAccountId);
  const nearEd25519SigningKeyId = normalizeOptionalNonEmptyString(obj.nearEd25519SigningKeyId);
  const rpId = normalizeOptionalNonEmptyString(obj.rpId);
  const credentialIdB64u = normalizeOptionalNonEmptyString(obj.credentialIdB64u);
  const providerSubjectId = normalizeOptionalNonEmptyString(obj.providerSubjectId);
  const authSubjectId = normalizeOptionalNonEmptyString(obj.authSubjectId);
  const relayerKeyId = normalizeOptionalNonEmptyString(obj.relayerKeyId);
  const sessionKindRaw = String(obj.sessionKind || '').trim();
  const sessionKind =
    sessionKindRaw === 'cookie' || sessionKindRaw === 'jwt' ? sessionKindRaw : undefined;
  const participantIds = Array.isArray(obj.participantIds)
    ? obj.participantIds
        .map((participantId) => Math.floor(Number(participantId)))
        .filter((participantId) => Number.isFinite(participantId) && participantId > 0)
    : [];
  const clientVerifyingShareB64u = normalizeOptionalNonEmptyString(obj.clientVerifyingShareB64u);
  const ed25519WorkerMaterialHandle = normalizeOptionalNonEmptyString(obj.ed25519WorkerMaterialHandle);
  const ed25519WorkerMaterialBindingDigest = normalizeOptionalNonEmptyString(
    obj.ed25519WorkerMaterialBindingDigest,
  );
  const sealedWorkerMaterialRef = normalizeOptionalNonEmptyString(obj.sealedWorkerMaterialRef);
  const sealedWorkerMaterialB64u = normalizeOptionalNonEmptyString(obj.sealedWorkerMaterialB64u);
  const materialFormatVersion = normalizeOptionalNonEmptyString(obj.materialFormatVersion);
  const materialKeyId = normalizeOptionalNonEmptyString(obj.materialKeyId);
  const materialCreatedAtMs = normalizeInteger(obj.materialCreatedAtMs);
  const signerSlot = normalizeInteger(obj.signerSlot);
  const keyVersion = normalizeOptionalNonEmptyString(obj.keyVersion);
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(obj.routerAbNormalSigning);
  if (
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !rpId ||
    !relayerKeyId ||
    !sessionKind ||
    !participantIds.length ||
    signerSlot == null ||
    signerSlot <= 0
  ) {
    return undefined;
  }
  const walletSessionJwt = normalizeOptionalNonEmptyString(obj.walletSessionJwt);
  return {
    nearAccountId,
    nearEd25519SigningKeyId,
    rpId,
    ...(credentialIdB64u ? { credentialIdB64u } : {}),
    ...(providerSubjectId ? { providerSubjectId } : {}),
    ...(authSubjectId ? { authSubjectId } : {}),
    relayerKeyId,
    participantIds,
    ...(walletSessionJwt ? { walletSessionJwt } : {}),
    sessionKind,
    ...(obj.runtimePolicyScope && typeof obj.runtimePolicyScope === 'object'
      ? { runtimePolicyScope: obj.runtimePolicyScope }
      : {}),
    ...(clientVerifyingShareB64u ? { clientVerifyingShareB64u } : {}),
    ...(ed25519WorkerMaterialHandle ? { ed25519WorkerMaterialHandle } : {}),
    ...(ed25519WorkerMaterialBindingDigest ? { ed25519WorkerMaterialBindingDigest } : {}),
    ...(sealedWorkerMaterialRef ? { sealedWorkerMaterialRef } : {}),
    ...(sealedWorkerMaterialB64u ? { sealedWorkerMaterialB64u } : {}),
    ...(materialFormatVersion ? { materialFormatVersion } : {}),
    ...(materialKeyId ? { materialKeyId } : {}),
    ...(materialCreatedAtMs != null && materialCreatedAtMs > 0 ? { materialCreatedAtMs } : {}),
    signerSlot,
    ...(keyVersion ? { keyVersion } : {}),
    ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
  };
}

function ed25519WorkerMaterialMissingFields(value: unknown): string[] {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : {};
  const missing: string[] = [];
  if (!normalizeOptionalNonEmptyString(obj.nearAccountId)) {
    missing.push('nearAccountId');
  }
  if (!normalizeOptionalNonEmptyString(obj.nearEd25519SigningKeyId)) {
    missing.push('nearEd25519SigningKeyId');
  }
  if (!normalizeOptionalNonEmptyString(obj.clientVerifyingShareB64u)) {
    missing.push('clientVerifyingShareB64u');
  }
  if (!normalizeOptionalNonEmptyString(obj.ed25519WorkerMaterialBindingDigest)) {
    missing.push('ed25519WorkerMaterialBindingDigest');
  }
  if (!normalizeOptionalNonEmptyString(obj.sealedWorkerMaterialRef)) {
    missing.push('sealedWorkerMaterialRef');
  }
  if (!normalizeOptionalNonEmptyString(obj.materialFormatVersion)) {
    missing.push('materialFormatVersion');
  }
  if (!normalizeOptionalNonEmptyString(obj.materialKeyId)) {
    missing.push('materialKeyId');
  }
  const materialCreatedAtMs = normalizeInteger(obj.materialCreatedAtMs);
  if (materialCreatedAtMs == null || materialCreatedAtMs <= 0) {
    missing.push('materialCreatedAtMs');
  }
  const signerSlot = normalizeInteger(obj.signerSlot);
  if (signerSlot == null || signerSlot <= 0) {
    missing.push('signerSlot');
  }
  if (!normalizeOptionalNonEmptyString(obj.keyVersion)) {
    missing.push('keyVersion');
  }
  return missing;
}

function ed25519RestoreHasWorkerMaterial(value: unknown): boolean {
  return ed25519WorkerMaterialMissingFields(value).length === 0;
}

function ed25519RestoreHasRawMaterial(value: unknown): boolean {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  return Boolean(normalizeOptionalNonEmptyString(obj?.xClientBaseB64u));
}

type SealedRecordStoreKeyInput =
  | {
      signingGrantId: string;
      authMethod: 'passkey' | 'email_otp';
      curve: 'ed25519';
    }
  | {
      signingGrantId: string;
      authMethod: 'passkey' | 'email_otp';
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    };

function makeSealedRecordStoreKey(args: SealedRecordStoreKeyInput): string {
  if (args.curve === 'ecdsa') {
    return [
      args.signingGrantId,
      args.authMethod,
      args.curve,
      thresholdEcdsaChainTargetKey(args.chainTarget),
    ]
      .map(sealedStoreKeyPart)
      .join(':');
  }
  return [args.signingGrantId, args.authMethod, args.curve].map(sealedStoreKeyPart).join(':');
}

function sealedStoreKeyPart(value: unknown): string {
  return encodeURIComponent(String(value || '').trim());
}

function makeResolvedIdentityKey(identity: SealedStoreResolvedSigningSessionIdentity): string {
  const chainKey =
    identity.curve === 'ecdsa'
      ? thresholdEcdsaChainTargetKey(identity.chainTarget)
      : identity.chain;
  return [
    identity.walletId,
    identity.authMethod,
    identity.curve,
    chainKey,
    identity.signingGrantId,
    identity.thresholdSessionId,
  ]
    .map(sealedStoreKeyPart)
    .join(':');
}

type ResolvedIdentityListKeyInput =
  | {
      walletId: string;
      authMethod?: 'passkey' | 'email_otp';
      curve: 'ed25519';
    }
  | {
      walletId: string;
      authMethod?: 'passkey' | 'email_otp';
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    };

function makeResolvedIdentityListKey(args: ResolvedIdentityListKeyInput): string {
  return [
    args.walletId,
    args.authMethod || '*',
    args.curve,
    args.curve === 'ecdsa' ? thresholdEcdsaChainTargetKey(args.chainTarget) : 'near',
  ]
    .map(sealedStoreKeyPart)
    .join(':');
}

function resolvedIdentityIndexKeys(identity: SealedStoreResolvedSigningSessionIdentity): string[] {
  if (identity.curve === 'ecdsa') {
    const base = {
      walletId: identity.walletId,
      curve: identity.curve,
      chainTarget: identity.chainTarget,
    } as const;
    return [
      makeResolvedIdentityListKey(base),
      makeResolvedIdentityListKey({ ...base, authMethod: identity.authMethod }),
    ];
  }
  const base = {
    walletId: identity.walletId,
    curve: identity.curve,
  } as const;
  return [
    makeResolvedIdentityListKey(base),
    makeResolvedIdentityListKey({ ...base, authMethod: identity.authMethod }),
  ];
}

function indexResolvedIdentity(
  key: string,
  identity: SealedStoreResolvedSigningSessionIdentity,
): void {
  for (const listKey of resolvedIdentityIndexKeys(identity)) {
    const keys = resolvedIdentityKeysByListKey.get(listKey) || new Set<string>();
    keys.add(key);
    resolvedIdentityKeysByListKey.set(listKey, keys);
  }
}

function unindexResolvedIdentity(
  key: string,
  identity: SealedStoreResolvedSigningSessionIdentity,
): void {
  for (const listKey of resolvedIdentityIndexKeys(identity)) {
    const keys = resolvedIdentityKeysByListKey.get(listKey);
    if (!keys) continue;
    keys.delete(key);
    if (!keys.size) resolvedIdentityKeysByListKey.delete(listKey);
  }
}

function setResolvedIdentity(
  key: string,
  identity: SealedStoreResolvedSigningSessionIdentity,
): void {
  const existing = resolvedIdentitiesByPurposeKey.get(key);
  if (existing) unindexResolvedIdentity(key, existing);
  resolvedIdentitiesByPurposeKey.set(key, identity);
  indexResolvedIdentity(key, identity);
}

function deleteResolvedIdentityByKey(key: string, _reason: ResolvedIdentityDeleteReason): void {
  const existing = resolvedIdentitiesByPurposeKey.get(key);
  if (!existing) return;
  unindexResolvedIdentity(key, existing);
  resolvedIdentitiesByPurposeKey.delete(key);
}

function sameResolvedIdentityLane(
  a: SealedStoreResolvedSigningSessionIdentity,
  b: SealedStoreResolvedSigningSessionIdentity,
): boolean {
  return (
    a.walletId === b.walletId &&
    a.authMethod === b.authMethod &&
    a.curve === b.curve &&
    (a.curve !== 'ecdsa' ||
      b.curve !== 'ecdsa' ||
      thresholdEcdsaChainTargetsEqual(a.chainTarget, b.chainTarget))
  );
}

function cloneResolvedIdentity(
  identity: SealedStoreResolvedSigningSessionIdentity,
): SealedStoreResolvedSigningSessionIdentity {
  return { ...identity } as SealedStoreResolvedSigningSessionIdentity;
}

function normalizeAuthMethod(value: unknown): 'passkey' | 'email_otp' | undefined {
  const authMethod = String(value || '').trim();
  return authMethod === 'passkey' || authMethod === 'email_otp' ? authMethod : undefined;
}

function normalizeEcdsaChain(value: unknown): 'tempo' | 'evm' | undefined {
  const chain = String(value || '').trim();
  return chain === 'tempo' || chain === 'evm' ? chain : undefined;
}

function normalizeResolvedIdentity(
  value: PublishResolvedIdentityInput,
): SealedStoreResolvedSigningSessionIdentity | null {
  const walletId = normalizeOptionalNonEmptyString(value.walletId);
  const authMethod = normalizeAuthMethod(value.authMethod);
  const curve = normalizeCurve(value.curve);
  const signingGrantId = normalizeOptionalNonEmptyString(value.signingGrantId);
  const thresholdSessionId = normalizeOptionalNonEmptyString(value.thresholdSessionId);
  const updatedAtMs = normalizeInteger(value.updatedAtMs ?? Date.now());
  if (
    !walletId ||
    !authMethod ||
    !curve ||
    !signingGrantId ||
    !thresholdSessionId ||
    updatedAtMs == null ||
    updatedAtMs <= 0
  ) {
    return null;
  }
  if (curve === 'ed25519') {
    return {
      walletId,
      authMethod,
      curve: 'ed25519',
      chain: 'near',
      signingGrantId,
      thresholdSessionId,
      updatedAtMs,
    };
  }
  const ecdsaValue = value as Extract<PublishResolvedIdentityInput, { curve: 'ecdsa' }>;
  let chainTarget: ThresholdEcdsaChainTarget | null = null;
  try {
    chainTarget = thresholdEcdsaChainTargetFromRequest(
      ecdsaValue.chainTarget &&
        typeof ecdsaValue.chainTarget === 'object' &&
        !Array.isArray(ecdsaValue.chainTarget)
        ? (ecdsaValue.chainTarget as Record<string, unknown>)
        : {},
    );
  } catch {
    chainTarget = null;
  }
  if (!chainTarget) return null;
  return {
    walletId,
    authMethod,
    curve: 'ecdsa',
    chainTarget,
    signingGrantId,
    thresholdSessionId,
    updatedAtMs,
  };
}

export function parseResolvedIdentityDeleteReason(
  value: unknown,
): ResolvedIdentityDeleteReason | null {
  switch (value) {
    case 'durable_record_deleted':
    case 'invalid_persisted_record':
    case 'same_lane_replaced':
    case 'same_scope_replaced':
      return value;
    default:
      return null;
  }
}

export function parseExactResolvedSessionIdentity(
  value: PublishResolvedIdentityInput,
): ExactResolvedSessionIdentity | null {
  const identity = normalizeResolvedIdentity(value);
  return identity ? cloneResolvedIdentity(identity) : null;
}

function createDeleteResolvedIdentityCommand(args: {
  identity: ExactResolvedSessionIdentity;
  deleteReason: ResolvedIdentityDeleteReason;
}): DeleteResolvedIdentityCommand {
  return {
    kind: 'delete_resolved_identity',
    identity: args.identity,
    deleteReason: args.deleteReason,
  };
}

function resolvedIdentitiesForSealedRecord(
  record: SigningSessionSealedStoreRecord,
): PublishResolvedIdentityInput[] {
  const walletId = normalizeOptionalNonEmptyString(record.walletId);
  if (!walletId) return [];
  const identities: PublishResolvedIdentityInput[] = [];
  const ecdsaThresholdSessionId = normalizeOptionalNonEmptyString(record.thresholdSessionIds.ecdsa);
  const ecdsaChainTarget = record.ecdsaRestore?.chainTarget;
  if (ecdsaThresholdSessionId && ecdsaChainTarget) {
    identities.push({
      walletId,
      authMethod: record.authMethod,
      curve: 'ecdsa',
      chainTarget: ecdsaChainTarget,
      signingGrantId: record.signingGrantId,
      thresholdSessionId: ecdsaThresholdSessionId,
      updatedAtMs: record.updatedAtMs,
    });
  }
  const ed25519ThresholdSessionId = normalizeOptionalNonEmptyString(
    record.thresholdSessionIds.ed25519,
  );
  if (ed25519ThresholdSessionId) {
    identities.push({
      walletId,
      authMethod: record.authMethod,
      curve: 'ed25519',
      chain: 'near',
      signingGrantId: record.signingGrantId,
      thresholdSessionId: ed25519ThresholdSessionId,
      updatedAtMs: record.updatedAtMs,
    });
  }
  return identities;
}

function publishResolvedIdentityForSealedRecord(record: SigningSessionSealedStoreRecord): void {
  // A durable seal can carry both the ECDSA lane and its Ed25519 companion.
  // The sealed store is the single local owner for publishing those runtime
  // identities so available signing lane reads do not reconstruct them from volatile records.
  for (const identity of resolvedIdentitiesForSealedRecord(record)) {
    publishResolvedIdentity(identity);
  }
}

function deleteResolvedIdentityForSealedRecord(
  record: SigningSessionSealedStoreRecord,
  reason: ResolvedIdentityDeleteReason,
): void {
  for (const identity of resolvedIdentitiesForSealedRecord(record)) {
    const exactIdentity = parseExactResolvedSessionIdentity(identity);
    if (!exactIdentity) continue;
    deleteResolvedIdentity(
      createDeleteResolvedIdentityCommand({
        identity: exactIdentity,
        deleteReason: reason,
      }),
    );
  }
}

function sealedRecordAccountKeys(record: SigningSessionSealedStoreRecord): Set<string> {
  const keys = new Set<string>();
  const walletId = normalizeOptionalNonEmptyString(record.walletId);
  if (walletId) keys.add(walletId);
  return keys;
}

function sealedRecordsShareAccount(
  left: SigningSessionSealedStoreRecord,
  right: SigningSessionSealedStoreRecord,
): boolean {
  const leftKeys = sealedRecordAccountKeys(left);
  if (!leftKeys.size) return false;
  for (const key of sealedRecordAccountKeys(right)) {
    if (leftKeys.has(key)) return true;
  }
  return false;
}

function sealedRecordsHaveSamePurpose(
  left: SigningSessionSealedStoreRecord,
  right: SigningSessionSealedStoreRecord,
): boolean {
  if (!sealedRecordsShareAccount(left, right)) return false;
  if (left.authMethod !== right.authMethod || left.curve !== right.curve) return false;
  if (left.curve === 'ecdsa') {
    const leftKeyHandle = normalizeOptionalNonEmptyString(left.ecdsaRestore?.keyHandle);
    const rightKeyHandle = normalizeOptionalNonEmptyString(right.ecdsaRestore?.keyHandle);
    if (!leftKeyHandle || !rightKeyHandle || leftKeyHandle !== rightKeyHandle) return false;
    const leftTarget = left.ecdsaRestore?.chainTarget;
    const rightTarget = right.ecdsaRestore?.chainTarget;
    if (!leftTarget || !rightTarget) return false;
    if (!thresholdEcdsaChainTargetsEqual(leftTarget, rightTarget)) return false;
  }
  return true;
}

export function publishResolvedIdentity(
  input: PublishResolvedIdentityInput,
): SealedStoreResolvedSigningSessionIdentity | null {
  const identity = normalizeResolvedIdentity(input);
  if (!identity) return null;
  // A wallet/auth/curve/chain has exactly one selected runtime identity. Reauth
  // may mint a new threshold session without rewriting durable seals, so replace
  // stale selections here instead of letting lane resolution see both.
  const listKey =
    identity.curve === 'ecdsa'
      ? makeResolvedIdentityListKey({
          walletId: identity.walletId,
          authMethod: identity.authMethod,
          curve: 'ecdsa',
          chainTarget: identity.chainTarget,
        })
      : makeResolvedIdentityListKey({
          walletId: identity.walletId,
          authMethod: identity.authMethod,
          curve: 'ed25519',
        });
  for (const key of [...(resolvedIdentityKeysByListKey.get(listKey) || [])]) {
    const existing = resolvedIdentitiesByPurposeKey.get(key);
    if (existing && sameResolvedIdentityLane(existing, identity)) {
      deleteResolvedIdentityByKey(key, 'same_lane_replaced');
    }
  }
  setResolvedIdentity(makeResolvedIdentityKey(identity), identity);
  return cloneResolvedIdentity(identity);
}

function deleteResolvedIdentity(command: DeleteResolvedIdentityCommand): void {
  deleteResolvedIdentityByKey(makeResolvedIdentityKey(command.identity), command.deleteReason);
}

function normalizeParticipantIds(value: unknown): number[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((participantId) => Math.floor(Number(participantId)))
    .filter((participantId) => Number.isFinite(participantId) && participantId > 0);
}

function asRawSealedSessionRecord(value: unknown): RawSealedSessionRecord | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as RawSealedSessionRecord)
    : null;
}

function isCurrentThresholdEcdsaSessionJwt(args: {
  jwt: string;
  expectedWalletId: string;
  expectedKeyHandle: string;
}): boolean {
  const payload = decodeJwtPayloadRecord(args.jwt);
  if (!payload || payload.kind !== ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND) return false;
  const walletId = normalizeOptionalNonEmptyString(payload.walletId);
  const keyHandle = normalizeOptionalNonEmptyString(payload.keyHandle);
  return walletId === args.expectedWalletId && keyHandle === args.expectedKeyHandle;
}

function buildSealedSessionSafeSummary(
  obj: RawSealedSessionRecord | null,
): Record<string, unknown> {
  return {
    authMethod: normalizeOptionalNonEmptyString(obj?.authMethod) || null,
    curve: normalizeOptionalNonEmptyString(obj?.curve) || null,
    storeKey: normalizeOptionalNonEmptyString(obj?.storeKey) || null,
    walletId:
      normalizeOptionalNonEmptyString(obj?.walletId) ||
      normalizeOptionalNonEmptyString(obj?.userId) ||
      null,
    signingGrantId: normalizeStoredSigningGrantId(obj) || null,
    thresholdSessionIds: normalizeThresholdSessionIdsFromStoredRecord(obj),
    hasEcdsaRestore: Boolean(asRawSealedSessionRecord(obj?.ecdsaRestore)),
    hasEd25519Restore: Boolean(asRawSealedSessionRecord(obj?.ed25519Restore)),
    ...(asRawSealedSessionRecord(obj?.ed25519Restore)
      ? {
          ed25519WorkerMaterialMissingFields: ed25519WorkerMaterialMissingFields(
            obj?.ed25519Restore,
          ),
        }
      : {}),
    issuedAtMs: normalizeInteger(obj?.issuedAtMs),
    expiresAtMs: normalizeInteger(obj?.expiresAtMs),
    remainingUses: normalizeInteger(obj?.remainingUses),
    updatedAtMs: normalizeInteger(obj?.updatedAtMs),
  };
}

function classifyNonCurrentRecord(
  kind: Exclude<SealedSessionRecordClassification['kind'], 'current'>,
  obj: RawSealedSessionRecord | null,
  reason: SealedSessionRecordClassificationReason,
): Exclude<SealedSessionRecordClassification, CurrentSealedSessionRecordClassification> {
  return {
    kind,
    storeKey: normalizeOptionalNonEmptyString(obj?.storeKey) || null,
    walletId:
      normalizeOptionalNonEmptyString(obj?.walletId) ||
      normalizeOptionalNonEmptyString(obj?.userId) ||
      null,
    reason,
    safeSummary: buildSealedSessionSafeSummary(obj),
  };
}

export function classifyRawSealedSessionRecord(raw: unknown): SealedSessionRecordClassification {
  raw = storagePayloadFromSealedStoreRow(raw);
  const obj = asRawSealedSessionRecord(raw);
  if (!obj) return classifyNonCurrentRecord('malformed', null, 'invalid_payload');
  if (Number(obj.v) !== SIGNING_SESSION_SEALED_RECORD_VERSION) {
    return classifyNonCurrentRecord('malformed', obj, 'invalid_header');
  }
  if (String(obj.alg || '').trim() !== SIGNING_SESSION_SEAL_ALG) {
    return classifyNonCurrentRecord('malformed', obj, 'invalid_header');
  }
  if (String(obj.storageScope || '').trim() !== SIGNING_SESSION_SEAL_STORAGE_SCOPE) {
    return classifyNonCurrentRecord('malformed', obj, 'invalid_header');
  }
  if (String(obj.secretKind || '').trim() !== SIGNING_SESSION_SECRET_KIND) {
    return classifyNonCurrentRecord('malformed', obj, 'invalid_header');
  }

  const authMethod = String(obj.authMethod || '').trim();
  const signingGrantId = normalizeStoredSigningGrantId(obj);
  const thresholdSessionIds = normalizeThresholdSessionIdsFromStoredRecord(obj);
  const sealedSecretB64u = normalizeOptionalNonEmptyString(obj.sealedSecretB64u);
  const curve = normalizeCurve(obj.curve);
  const subjectId = normalizeOptionalNonEmptyString(obj.subjectId);
  const walletId = normalizeOptionalNonEmptyString(obj.walletId);
  const signingRootId = normalizeOptionalNonEmptyString(obj.signingRootId);
  const signingRootVersion =
    normalizeOptionalNonEmptyString(obj.signingRootVersion) || (signingRootId ? 'default' : null);
  const relayerUrl = normalizeOptionalNonEmptyString(obj.relayerUrl);
  const keyVersion = normalizeOptionalNonEmptyString(obj.keyVersion);
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(obj.shamirPrimeB64u);
  const issuedAtMs = normalizeInteger(obj.issuedAtMs);
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  const remainingUses = normalizeInteger(obj.remainingUses);
  const updatedAtMs = normalizeInteger(obj.updatedAtMs);

  if (!signingGrantId || !sealedSecretB64u) {
    return classifyNonCurrentRecord('malformed', obj, 'invalid_identity');
  }
  if (authMethod !== 'passkey' && authMethod !== 'email_otp') {
    return classifyNonCurrentRecord('malformed', obj, 'invalid_identity');
  }
  if (!thresholdSessionIds.ed25519 && !thresholdSessionIds.ecdsa) {
    return classifyNonCurrentRecord('malformed', obj, 'invalid_identity');
  }
  if (!walletId) {
    return classifyNonCurrentRecord('malformed', obj, 'invalid_identity');
  }
  const recordCurve = resolveSealedRecordCurve({ curve, thresholdSessionIds });
  if (!recordCurve) return classifyNonCurrentRecord('malformed', obj, 'invalid_identity');
  if (issuedAtMs == null || issuedAtMs <= 0) {
    return classifyNonCurrentRecord('malformed', obj, 'invalid_identity');
  }
  if (expiresAtMs == null || expiresAtMs <= 0) {
    return classifyNonCurrentRecord('malformed', obj, 'invalid_identity');
  }
  if (remainingUses == null || remainingUses < 0) {
    return classifyNonCurrentRecord('malformed', obj, 'invalid_identity');
  }
  if (updatedAtMs == null || updatedAtMs <= 0) {
    return classifyNonCurrentRecord('malformed', obj, 'invalid_identity');
  }

  const ecdsaRestoreObj = asRawSealedSessionRecord(obj.ecdsaRestore);
  const ed25519RestoreObj = asRawSealedSessionRecord(obj.ed25519Restore);
  const ecdsaRestore = normalizeEcdsaRestoreMetadata(obj.ecdsaRestore);
  const ed25519Restore = normalizeEd25519RestoreMetadata(obj.ed25519Restore);

  if (recordCurve === 'ecdsa') {
    if (subjectId) return classifyNonCurrentRecord('delete_required', obj, 'invalid_identity');
    if (!ecdsaRestoreObj || !relayerUrl) {
      return classifyNonCurrentRecord('rebuild_required', obj, 'missing_restore_metadata');
    }
    if (!normalizeParticipantIds(ecdsaRestoreObj.participantIds).length) {
      return classifyNonCurrentRecord('delete_required', obj, 'missing_participant_ids');
    }
    if (!ecdsaRestore) {
      return classifyNonCurrentRecord('rebuild_required', obj, 'missing_restore_metadata');
    }
    if (ecdsaRestore.sessionKind === 'jwt') {
      const walletSessionJwt = normalizeOptionalNonEmptyString(ecdsaRestoreObj.walletSessionJwt);
      if (!walletSessionJwt) {
        return classifyNonCurrentRecord('delete_required', obj, 'missing_wallet_session_jwt');
      }
      if (
        !isCurrentThresholdEcdsaSessionJwt({
          jwt: walletSessionJwt,
          expectedWalletId: walletId,
          expectedKeyHandle: ecdsaRestore.keyHandle,
        })
      ) {
        return classifyNonCurrentRecord('delete_required', obj, 'invalid_identity');
      }
    }
    const storeKey = makeSealedRecordStoreKey({
      signingGrantId,
      authMethod,
      curve: 'ecdsa',
      chainTarget: ecdsaRestore.chainTarget,
    });
    const providedStoreKey = normalizeOptionalNonEmptyString(obj.storeKey);
    if (providedStoreKey && providedStoreKey !== storeKey) {
      return classifyNonCurrentRecord('malformed', obj, 'invalid_identity');
    }
    return {
      kind: 'current',
      record: {
        v: SIGNING_SESSION_SEALED_RECORD_VERSION,
        alg: SIGNING_SESSION_SEAL_ALG,
        storageScope: SIGNING_SESSION_SEAL_STORAGE_SCOPE,
        authMethod,
        secretKind: SIGNING_SESSION_SECRET_KIND,
        storeKey,
        signingGrantId,
        thresholdSessionIds,
        sealedSecretB64u,
        curve: 'ecdsa',
        walletId,
        relayerUrl,
        ...(keyVersion ? { keyVersion } : {}),
        ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
        ecdsaRestore,
        ...(ed25519Restore &&
        !ed25519RestoreHasRawMaterial(ed25519RestoreObj) &&
        ed25519RestoreHasWorkerMaterial(ed25519RestoreObj)
          ? { ed25519Restore }
          : {}),
        issuedAtMs,
        expiresAtMs,
        remainingUses,
        updatedAtMs,
      },
    };
  }

  if (!ed25519RestoreObj || !relayerUrl) {
    return classifyNonCurrentRecord('rebuild_required', obj, 'missing_restore_metadata');
  }
  if (!normalizeParticipantIds(ed25519RestoreObj.participantIds).length) {
    return classifyNonCurrentRecord('delete_required', obj, 'missing_participant_ids');
  }
  if (!ed25519Restore) {
    return classifyNonCurrentRecord('rebuild_required', obj, 'missing_restore_metadata');
  }
  if (normalizeOptionalNonEmptyString(ed25519RestoreObj.xClientBaseB64u)) {
    return classifyNonCurrentRecord('delete_required', obj, 'missing_restore_metadata');
  }
  if (!ed25519RestoreHasWorkerMaterial(ed25519RestoreObj)) {
    return classifyNonCurrentRecord('delete_required', obj, 'missing_restore_metadata');
  }
  if (
    authMethod === 'email_otp' &&
    ed25519Restore.sessionKind === 'jwt' &&
    !normalizeOptionalNonEmptyString(ed25519RestoreObj.walletSessionJwt)
  ) {
    return classifyNonCurrentRecord('delete_required', obj, 'missing_wallet_session_jwt');
  }
  const storeKey = makeSealedRecordStoreKey({
    signingGrantId,
    authMethod,
    curve: 'ed25519',
  });
  const providedStoreKey = normalizeOptionalNonEmptyString(obj.storeKey);
  if (providedStoreKey && providedStoreKey !== storeKey) {
    return classifyNonCurrentRecord('malformed', obj, 'invalid_identity');
  }
  return {
    kind: 'current',
    record: {
      v: SIGNING_SESSION_SEALED_RECORD_VERSION,
      alg: SIGNING_SESSION_SEAL_ALG,
      storageScope: SIGNING_SESSION_SEAL_STORAGE_SCOPE,
      authMethod,
      secretKind: SIGNING_SESSION_SECRET_KIND,
      storeKey,
      signingGrantId,
      thresholdSessionIds,
      sealedSecretB64u,
      curve: 'ed25519',
      ...(subjectId ? { subjectId } : {}),
      walletId,
      ...(signingRootId ? { signingRootId } : {}),
      ...(signingRootVersion ? { signingRootVersion } : {}),
      relayerUrl,
      ...(keyVersion ? { keyVersion } : {}),
      ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
      ...(ecdsaRestore ? { ecdsaRestore } : {}),
      ed25519Restore,
      issuedAtMs,
      expiresAtMs,
      remainingUses,
      updatedAtMs,
    },
  };
}

function normalizeSigningSessionSealedStoreRecord(
  value: unknown,
): CurrentSealedSessionRecord | null {
  const classification = classifyRawSealedSessionRecord(storagePayloadFromSealedStoreRow(value));
  return classification.kind === 'current' ? classification.record : null;
}

function rawThresholdSessionIdsFromSealedStoreRow(value: unknown): {
  ed25519?: string;
  ecdsa?: string;
} {
  const payload = storagePayloadFromSealedStoreRow(value);
  const obj =
    payload && typeof payload === 'object' && !Array.isArray(payload)
      ? (payload as Record<string, unknown>)
      : null;
  return normalizeThresholdSessionIdsFromStoredRecord(obj);
}

function sealedSessionCurrentSummary(record: CurrentSealedSessionRecord): Record<string, unknown> {
  return {
    storeKey: record.storeKey,
    walletId: record.walletId || null,
    authMethod: record.authMethod,
    curve: record.curve,
    signingGrantId: record.signingGrantId,
    thresholdSessionIds: record.thresholdSessionIds,
    updatedAtMs: record.updatedAtMs,
  };
}

function logSealedSessionCurrentRecord(args: {
  operation: string;
  record: CurrentSealedSessionRecord;
}): void {
  console.debug('[SigningSessionSealedStore] sealed record boundary outcome', {
    operation: args.operation,
    outcome: 'current',
    ...sealedSessionCurrentSummary(args.record),
  });
}

function logSealedSessionDeletedRecord(args: {
  operation: string;
  storeKey: string | null;
  walletId: string | null;
  reason: string;
  safeSummary?: Record<string, unknown>;
}): void {
  console.info('[SigningSessionSealedStore] sealed record boundary outcome', {
    operation: args.operation,
    outcome: 'deleted',
    storeKey: args.storeKey,
    walletId: args.walletId,
    reason: args.reason,
    ...(args.safeSummary ? { safeSummary: args.safeSummary } : {}),
  });
}

function logSealedSessionClassification(args: {
  operation: string;
  classification: Exclude<
    SealedSessionRecordClassification,
    CurrentSealedSessionRecordClassification
  >;
}): void {
  const outcome =
    args.classification.kind === 'rebuild_required'
      ? 'rebuilt'
      : args.classification.kind === 'malformed'
        ? 'malformed'
        : 'rejected';
  const payload = {
    operation: args.operation,
    outcome,
    classificationKind: args.classification.kind,
    ...args.classification,
  };
  if (outcome === 'rebuilt') {
    console.info('[SigningSessionSealedStore] sealed record boundary outcome', payload);
    return;
  }
  console.warn('[SigningSessionSealedStore] sealed record boundary outcome', payload);
}

export function buildCurrentSealedSessionRecord(
  args: BuildCurrentSealedSessionRecordInput,
): CurrentSealedSessionRecord | null {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const curve = normalizeCurve(args.curve);
  const authMethod =
    args.authMethod === 'passkey' || args.authMethod === 'email_otp' ? args.authMethod : undefined;
  const thresholdSessionIds = thresholdSessionIdsForWrite({
    thresholdSessionId,
    curve,
    thresholdSessionIds: args.thresholdSessionIds,
  });
  const signingGrantId = normalizeOptionalNonEmptyString(args.signingGrantId);
  const subjectId = normalizeOptionalNonEmptyString(args.subjectId);
  const walletId = normalizeOptionalNonEmptyString(args.walletId);
  const sealedSecretB64u = normalizeOptionalNonEmptyString(args.sealedSecretB64u);
  const expiresAtMs = normalizeInteger(args.expiresAtMs);
  const remainingUses = normalizeInteger(args.remainingUses);
  const issuedAtMs = normalizeInteger(args.issuedAtMs ?? Date.now());
  const updatedAtMs = normalizeInteger(args.updatedAtMs ?? Date.now());
  if (!thresholdSessionId || !signingGrantId || !sealedSecretB64u) return null;
  if (!curve || !authMethod) return null;
  if (!thresholdSessionIds.ed25519 && !thresholdSessionIds.ecdsa) return null;
  if (issuedAtMs == null || issuedAtMs <= 0) return null;
  if (expiresAtMs == null || expiresAtMs <= 0) return null;
  if (remainingUses == null || remainingUses < 0) return null;
  if (updatedAtMs == null || updatedAtMs <= 0) return null;
  const ecdsaRestore = normalizeEcdsaRestoreMetadata(args.ecdsaRestore);
  const ed25519Restore = normalizeEd25519RestoreMetadata(args.ed25519Restore);
  if (curve === 'ecdsa') {
    if (!ecdsaRestore?.chainTarget || !walletId) return null;
    if (subjectId) return null;
  }
  const signingRootIdForWrite =
    curve === 'ed25519' ? normalizeOptionalNonEmptyString(args.signingRootId) : undefined;
  const signingRootVersionForWrite =
    curve === 'ed25519' ? normalizeOptionalNonEmptyString(args.signingRootVersion) : undefined;

  const classification = classifyRawSealedSessionRecord({
    v: SIGNING_SESSION_SEALED_RECORD_VERSION,
    alg: SIGNING_SESSION_SEAL_ALG,
    storageScope: SIGNING_SESSION_SEAL_STORAGE_SCOPE,
    authMethod,
    secretKind: SIGNING_SESSION_SECRET_KIND,
    signingGrantId,
    thresholdSessionIds,
    sealedSecretB64u,
    curve,
    ...(curve === 'ed25519' && subjectId ? { subjectId } : {}),
    ...(walletId ? { walletId } : {}),
    ...(signingRootIdForWrite ? { signingRootId: signingRootIdForWrite } : {}),
    ...(signingRootVersionForWrite ? { signingRootVersion: signingRootVersionForWrite } : {}),
    ...(normalizeOptionalNonEmptyString(args.relayerUrl)
      ? { relayerUrl: normalizeOptionalNonEmptyString(args.relayerUrl) }
      : {}),
    ...(normalizeOptionalNonEmptyString(args.keyVersion)
      ? { keyVersion: normalizeOptionalNonEmptyString(args.keyVersion) }
      : {}),
    ...(normalizeOptionalNonEmptyString(args.shamirPrimeB64u)
      ? { shamirPrimeB64u: normalizeOptionalNonEmptyString(args.shamirPrimeB64u) }
      : {}),
    ...(ecdsaRestore ? { ecdsaRestore } : {}),
    ...(ed25519Restore ? { ed25519Restore } : {}),
    issuedAtMs,
    expiresAtMs,
    remainingUses,
    updatedAtMs,
  });
  if (classification.kind !== 'current') {
    logSealedSessionClassification({
      operation: 'build current sealed session record',
      classification,
    });
    return null;
  }
  return classification.record;
}

function normalizeSigningSessionRestoreLease(value: unknown): SigningSessionRestoreLease | null {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (!obj) return null;
  if (obj.lease && typeof obj.lease === 'object' && !Array.isArray(obj.lease)) {
    return normalizeSigningSessionRestoreLease(obj.lease);
  }
  if (Number(obj.v) !== 1) return null;
  const leaseKey = normalizeOptionalNonEmptyString(obj.leaseKey);
  const signingGrantId = normalizeOptionalNonEmptyString(obj.signingGrantId);
  const ownerId = normalizeOptionalNonEmptyString(obj.ownerId);
  const attemptId = normalizeOptionalNonEmptyString(obj.attemptId);
  const startedAtMs = normalizeInteger(obj.startedAtMs);
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  if (!leaseKey || !signingGrantId || !ownerId || !attemptId) return null;
  if (startedAtMs == null || startedAtMs <= 0) return null;
  if (expiresAtMs == null || expiresAtMs <= startedAtMs) return null;
  return {
    v: 1,
    leaseKey,
    signingGrantId,
    ownerId,
    attemptId,
    startedAtMs,
    expiresAtMs,
  };
}

function makeSigningSessionRestoreLease(args: {
  leaseKey: string;
  signingGrantId: string;
  ownerId: string;
  nowMs: number;
  ttlMs: number;
}): SigningSessionRestoreLease {
  return {
    v: 1,
    leaseKey: args.leaseKey,
    signingGrantId: args.signingGrantId,
    ownerId: args.ownerId,
    attemptId: createRandomId('restore-attempt'),
    startedAtMs: args.nowMs,
    expiresAtMs: args.nowMs + args.ttlMs,
  };
}

function thresholdSessionIdsForWrite(args: {
  thresholdSessionId: string;
  curve?: 'ed25519' | 'ecdsa';
  thresholdSessionIds?: {
    ed25519?: string;
    ecdsa?: string;
  };
}): { ed25519?: string; ecdsa?: string } {
  const explicit = normalizeThresholdSessionIds(args.thresholdSessionIds);
  if (explicit.ed25519 || explicit.ecdsa) return explicit;
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return {};
  const curve = normalizeCurve(args.curve) || 'ecdsa';
  return curve === 'ed25519' ? { ed25519: thresholdSessionId } : { ecdsa: thresholdSessionId };
}

function recordMatchesFilter(
  record: SigningSessionSealedStoreRecord,
  thresholdSessionId: string,
  filter: SigningSessionSealedRecordFilter,
): boolean {
  if (record.authMethod !== filter.authMethod) return false;
  // Some Email OTP seals bind a single secret to both ECDSA and Ed25519 lane ids.
  // The requested curve is enforced by the thresholdSessionIds map below.
  if (record.thresholdSessionIds[filter.curve] !== thresholdSessionId) return false;
  if (
    filter.curve === 'ecdsa' &&
    (!record.ecdsaRestore?.chainTarget ||
      !thresholdEcdsaChainTargetsEqual(record.ecdsaRestore.chainTarget, filter.chainTarget))
  ) {
    return false;
  }
  return true;
}

function requireSealedRecordPurpose(
  filter: SigningSessionSealedRecordFilter | undefined,
  operation: string,
): SigningSessionSealedRecordFilter {
  if (filter?.authMethod && filter.curve === 'ed25519') return filter;
  if (filter?.authMethod && filter.curve === 'ecdsa' && filter.chainTarget) {
    return filter;
  }
  console.warn('[SigningSessionSealedStore] rejected ambiguous sealed record access', {
    operation,
  });
  throw new Error(
    `[SigningSessionSealedStore] ${operation} requires an explicit authMethod, curve, and ECDSA chain target`,
  );
}

async function collectRawSealedRecordEntriesByThresholdSessionId(
  thresholdSessionId: string,
): Promise<StoredRawSealedRecordEntry[]> {
  const entries =
    await signingSessionSealsRepository.collectRawSealedRecordEntriesByThresholdSessionId(
      thresholdSessionId,
    );
  if (entries.length) return entries;
  const allEntries = await signingSessionSealsRepository.collectAllRawSealedRecordEntries();
  return allEntries.filter((entry) => {
    const record = normalizeSigningSessionSealedStoreRecord(entry.value);
    const rawThresholdSessionIds = rawThresholdSessionIdsFromSealedStoreRow(entry.value);
    return (
      record?.thresholdSessionIds.ed25519 === thresholdSessionId ||
      record?.thresholdSessionIds.ecdsa === thresholdSessionId ||
      rawThresholdSessionIds.ed25519 === thresholdSessionId ||
      rawThresholdSessionIds.ecdsa === thresholdSessionId
    );
  });
}

async function readRecordByThresholdSessionId(
  thresholdSessionId: string,
  filter: SigningSessionSealedRecordFilter,
  operation: string,
): Promise<CurrentSealedSessionRecord | null> {
  const entries = await collectRawSealedRecordEntriesByThresholdSessionId(thresholdSessionId);

  let selected: CurrentSealedSessionRecord | null = null;
  const deletePrimaryKeys: unknown[] = [];
  for (const entry of entries) {
    const classification = classifyRawSealedSessionRecord(entry.value);
    if (classification.kind === 'current') {
      if (recordMatchesFilter(classification.record, thresholdSessionId, filter)) {
        selected = classification.record;
      }
      continue;
    }
    logSealedSessionClassification({ operation, classification });
    if (classification.kind === 'delete_required' || classification.kind === 'malformed') {
      deletePrimaryKeys.push(entry.primaryKey);
      logSealedSessionDeletedRecord({
        operation,
        storeKey: classification.storeKey,
        walletId: classification.walletId,
        reason: classification.reason,
        safeSummary: classification.safeSummary,
      });
    }
    if (classification.kind === 'user_action_required') {
      await signingSessionSealsRepository.deleteSealedRecords(deletePrimaryKeys);
      throw new SealedSessionRecordUserActionRequiredError(classification);
    }
  }
  await signingSessionSealsRepository.deleteSealedRecords(deletePrimaryKeys);
  return selected;
}

async function deleteRecordByThresholdSessionId(
  thresholdSessionId: string,
  filter: SigningSessionSealedRecordFilter,
): Promise<void> {
  try {
    const entries = await collectRawSealedRecordEntriesByThresholdSessionId(thresholdSessionId);
    const deletePrimaryKeys: unknown[] = [];
    for (const entry of entries) {
      const record = normalizeSigningSessionSealedStoreRecord(entry.value);
      if (record?.storeKey && recordMatchesFilter(record, thresholdSessionId, filter)) {
        deletePrimaryKeys.push(entry.primaryKey);
        logSealedSessionDeletedRecord({
          operation: 'delete',
          storeKey: record.storeKey,
          walletId: record.walletId || null,
          reason: 'explicit_delete',
          safeSummary: sealedSessionCurrentSummary(record),
        });
      }
    }
    await signingSessionSealsRepository.deleteSealedRecords(deletePrimaryKeys);
  } catch {}
}

async function listSameScopeRecords(
  record: CurrentSealedSessionRecord,
): Promise<CurrentSealedSessionRecord[]> {
  if (!sealedRecordAccountKeys(record).size || !record.authMethod) return [];
  try {
    const all = await signingSessionSealsRepository.collectAllRawSealedRecordEntries();
    const records: CurrentSealedSessionRecord[] = [];
    for (const entry of all) {
      const existing = normalizeSigningSessionSealedStoreRecord(entry.value);
      if (!existing) continue;
      if (existing.storeKey === record.storeKey) continue;
      if (sealedRecordsHaveSamePurpose(existing, record)) {
        records.push(existing);
      }
    }
    return records;
  } catch {
    return [];
  }
}

export async function readExactSealedSession(
  thresholdSessionIdRaw: string,
  filter: SigningSessionSealedRecordFilter,
): Promise<CurrentSealedSessionRecord | null> {
  const purpose = requireSealedRecordPurpose(filter, 'read');
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  return await readRecordByThresholdSessionId(thresholdSessionId, purpose, 'read');
}

export async function listExactSealedSessionsForWallet(args: {
  walletId: string;
  filter: ListExactSigningSessionSealedRecordsForWalletFilter;
}): Promise<CurrentSealedSessionRecord[]> {
  const walletId = normalizeOptionalNonEmptyString(args.walletId);
  if (!walletId) return [];
  const purpose = requireSealedRecordPurpose(args.filter, 'list exact account records');
  const chainTarget = args.filter.curve === 'ecdsa' ? args.filter.chainTarget : undefined;
  const values = await signingSessionSealsRepository.collectAllRawSealedRecordEntries();
  const deletePrimaryKeys: unknown[] = [];
  try {
    const records: CurrentSealedSessionRecord[] = [];
    const seen = new Set<string>();
    for (const value of values) {
      const classification = classifyRawSealedSessionRecord(value.value);
      if (classification.kind !== 'current') {
        logSealedSessionClassification({
          operation: 'list exact account records',
          classification,
        });
        if (classification.kind === 'delete_required' || classification.kind === 'malformed') {
          deletePrimaryKeys.push(value.primaryKey);
          logSealedSessionDeletedRecord({
            operation: 'list exact account records',
            storeKey: classification.storeKey,
            walletId: classification.walletId,
            reason: classification.reason,
            safeSummary: classification.safeSummary,
          });
        }
        if (classification.kind === 'user_action_required') {
          await signingSessionSealsRepository.deleteSealedRecords(deletePrimaryKeys);
          throw new SealedSessionRecordUserActionRequiredError(classification);
        }
        continue;
      }
      const record = classification.record;
      if (record.walletId !== walletId) continue;
      if (record.authMethod !== purpose.authMethod) continue;
      if (!record.thresholdSessionIds[purpose.curve]) continue;
      if (
        chainTarget &&
        (!record.ecdsaRestore?.chainTarget ||
          !thresholdEcdsaChainTargetsEqual(record.ecdsaRestore.chainTarget, chainTarget))
      ) {
        continue;
      }
      if (seen.has(record.storeKey)) continue;
      seen.add(record.storeKey);
      records.push(record);
    }
    await signingSessionSealsRepository.deleteSealedRecords(deletePrimaryKeys);
    return records;
  } finally {
    await signingSessionSealsRepository.deleteSealedRecords(deletePrimaryKeys);
  }
}

export async function listEcdsaSealedSessionsForWallet(args: {
  walletId: string;
  filter: ListEcdsaSigningSessionSealedRecordsForWalletFilter;
}): Promise<CurrentSealedSessionRecord[]> {
  const walletId = normalizeOptionalNonEmptyString(args.walletId);
  if (!walletId) return [];
  if (args.filter.curve !== 'ecdsa') {
    console.warn('[SigningSessionSealedStore] rejected non-ECDSA wallet-scoped list', {
      operation: 'list wallet ecdsa records',
    });
    return [];
  }
  const values = await signingSessionSealsRepository.collectAllRawSealedRecordEntries();
  const deletePrimaryKeys: unknown[] = [];
  try {
    const records: CurrentSealedSessionRecord[] = [];
    const seen = new Set<string>();
    for (const value of values) {
      const classification = classifyRawSealedSessionRecord(value.value);
      if (classification.kind !== 'current') {
        logSealedSessionClassification({
          operation: 'list wallet ecdsa records',
          classification,
        });
        if (classification.kind === 'delete_required' || classification.kind === 'malformed') {
          deletePrimaryKeys.push(value.primaryKey);
          logSealedSessionDeletedRecord({
            operation: 'list wallet ecdsa records',
            storeKey: classification.storeKey,
            walletId: classification.walletId,
            reason: classification.reason,
            safeSummary: classification.safeSummary,
          });
        }
        if (classification.kind === 'user_action_required') {
          await signingSessionSealsRepository.deleteSealedRecords(deletePrimaryKeys);
          throw new SealedSessionRecordUserActionRequiredError(classification);
        }
        continue;
      }
      const record = classification.record;
      if (record.walletId !== walletId) continue;
      if (args.filter.authMethod && record.authMethod !== args.filter.authMethod) continue;
      if (!record.thresholdSessionIds.ecdsa) continue;
      if (!record.ecdsaRestore?.chainTarget) continue;
      if (seen.has(record.storeKey)) continue;
      seen.add(record.storeKey);
      records.push(record);
    }
    await signingSessionSealsRepository.deleteSealedRecords(deletePrimaryKeys);
    return records;
  } finally {
    await signingSessionSealsRepository.deleteSealedRecords(deletePrimaryKeys);
  }
}

export async function writeExactSealedSession(record: CurrentSealedSessionRecord): Promise<void> {
  const classification = classifyRawSealedSessionRecord(record);
  if (classification.kind !== 'current') {
    logSealedSessionClassification({
      operation: 'write exact sealed session',
      classification,
    });
    return;
  }
  const currentRecord = classification.record;
  logSealedSessionCurrentRecord({
    operation: 'write exact sealed session',
    record: currentRecord,
  });

  const staleRecords = await listSameScopeRecords(currentRecord);
  for (const staleRecord of staleRecords) {
    deleteResolvedIdentityForSealedRecord(staleRecord, 'same_scope_replaced');
    logSealedSessionDeletedRecord({
      operation: 'write exact sealed session',
      storeKey: staleRecord.storeKey,
      walletId: staleRecord.walletId || null,
      reason: 'same_scope_replaced',
      safeSummary: sealedSessionCurrentSummary(staleRecord),
    });
  }
  await signingSessionSealsRepository.replaceSealedRecord({
    row: sealedRecordStorageRow(currentRecord),
    staleStoreKeys: staleRecords.map((record) => record.storeKey),
  });
  publishResolvedIdentityForSealedRecord(currentRecord);
}

export async function updateExactSealedSessionPolicy(args: {
  thresholdSessionId: string;
  filter: SigningSessionSealedRecordFilter;
  expiresAtMs?: number;
  remainingUses?: number;
  updatedAtMs?: number;
}): Promise<void> {
  const purpose = requireSealedRecordPurpose(args.filter, 'update policy');
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return;
  const existing = await readExactSealedSession(thresholdSessionId, purpose);
  if (!existing) return;
  const expiresAtMs = normalizeInteger(args.expiresAtMs ?? existing.expiresAtMs);
  const remainingUses = normalizeInteger(args.remainingUses ?? existing.remainingUses);
  const updatedAtMs = normalizeInteger(args.updatedAtMs ?? Date.now());
  if (expiresAtMs == null || expiresAtMs <= 0) return;
  if (remainingUses == null || remainingUses < 0) return;
  if (updatedAtMs == null || updatedAtMs <= 0) return;
  await writeExactSealedSession({
    ...existing,
    expiresAtMs,
    remainingUses,
    updatedAtMs,
  });
}

export async function deleteExactSealedSession(
  thresholdSessionIdRaw: string,
  filter: SigningSessionSealedRecordFilter,
  options: DeleteExactSealedSessionOptions,
): Promise<void> {
  const purpose = requireSealedRecordPurpose(filter, 'delete');
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return;
  const record = await readRecordByThresholdSessionId(thresholdSessionId, purpose, 'delete');
  await deleteRecordByThresholdSessionId(thresholdSessionId, purpose);
  if (record?.signingGrantId && options.deleteResolvedIdentity) {
    deleteResolvedIdentityForSealedRecord(record, options.resolvedIdentityDeleteReason);
    await signingSessionSealsRepository.deleteRestoreLease(record.storeKey);
  }
}

export async function deleteDurableSealedSessionRecord(
  command: DeleteDurableSealedSessionCommand,
): Promise<void> {
  const filter = exactSealedSessionFilterForIdentity(command.durableRecord);
  const existingRecord =
    command.durableRecord.curve === 'ecdsa'
      ? await readExactSealedSession(command.durableRecord.thresholdSessionId, filter).catch(
          () => null,
        )
      : null;
  const options: DeleteExactSealedSessionOptions = command.preserveResolvedIdentity
    ? { deleteResolvedIdentity: false }
    : { deleteResolvedIdentity: true, resolvedIdentityDeleteReason: 'durable_record_deleted' };
  await deleteExactSealedSession(command.durableRecord.thresholdSessionId, filter, options);
  if (command.durableRecord.curve !== 'ecdsa') return;

  clearStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget({
    thresholdSessionId: command.durableRecord.thresholdSessionId,
    chainTarget: command.durableRecord.chainTarget,
  });

  const keyHandleInvalidatesAllSessions =
    command.deleteReason === 'account_removed' ||
    command.deleteReason === 'device_removed' ||
    command.deleteReason === 'invalid_persisted_record' ||
    command.deleteReason === 'migration_rejected' ||
    command.deleteReason === 'trusted_persisted_delete';
  if (!keyHandleInvalidatesAllSessions) return;
  if (!existingRecord || existingRecord.curve !== 'ecdsa') return;
  const walletId = normalizeOptionalNonEmptyString(existingRecord.walletId);
  const keyHandle = normalizeOptionalNonEmptyString(existingRecord.ecdsaRestore?.keyHandle);
  if (!walletId || !keyHandle) return;
  clearStoredThresholdEcdsaSessionRecordsForWalletKeyHandle({
    walletId,
    keyHandle,
  });
}

export async function acquireSigningSessionRestoreLease(
  args: {
    thresholdSessionId: string;
    ownerId?: string;
    nowMs?: number;
    ttlMs?: number;
  } & SigningSessionSealedRecordFilter,
): Promise<SigningSessionRestoreLeaseHandle | null> {
  const purpose = requireSealedRecordPurpose(args, 'acquire restore lease');
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return null;
  const nowMs = normalizeInteger(args.nowMs ?? Date.now()) ?? Date.now();
  const ttlMs = Math.max(
    1,
    normalizeInteger(args.ttlMs ?? DEFAULT_RESTORE_LEASE_TTL_MS) ?? DEFAULT_RESTORE_LEASE_TTL_MS,
  );
  const ownerId = normalizeOptionalNonEmptyString(args.ownerId) || createRandomId('restore-owner');
  return await signingSessionSealsRepository.withRestoreLeaseTransaction(
    thresholdSessionId,
    async (tx) => {
      const records: SigningSessionSealedStoreRecord[] = [];
      for (const entry of tx.entries) {
        const normalized = normalizeSigningSessionSealedStoreRecord(entry.value);
        if (
          normalized?.storeKey &&
          !records.some((record) => record.storeKey === normalized.storeKey)
        ) {
          records.push(normalized);
        }
      }
      const record =
        records.find((candidate) => recordMatchesFilter(candidate, thresholdSessionId, purpose)) ||
        null;
      if (!record) {
        tx.abort();
        return null;
      }

      const existing = normalizeSigningSessionRestoreLease(
        await tx.getRawRestoreLease(record.storeKey),
      );
      if (existing && existing.expiresAtMs > nowMs && existing.ownerId !== ownerId) {
        tx.abort();
        return null;
      }

      const lease = makeSigningSessionRestoreLease({
        leaseKey: record.storeKey,
        signingGrantId: record.signingGrantId,
        ownerId,
        nowMs,
        ttlMs,
      });
      tx.putRestoreLease(restoreLeaseStorageRow(lease));
      return {
        ...lease,
        thresholdSessionId,
      };
    },
  );
}

export async function releaseSigningSessionRestoreLease(
  lease: SigningSessionRestoreLeaseHandle | null | undefined,
): Promise<void> {
  if (!lease?.signingGrantId || !lease.ownerId || !lease.attemptId) return;
  await signingSessionSealsRepository.deleteRestoreLeaseIf({
    leaseKey: lease.leaseKey,
    shouldDelete: (rawLease) => {
      const existing = normalizeSigningSessionRestoreLease(rawLease);
      return existing?.ownerId === lease.ownerId && existing.attemptId === lease.attemptId;
    },
  });
}

export async function clearAllSealedSessions(): Promise<void> {
  resolvedIdentitiesByPurposeKey.clear();
  resolvedIdentityKeysByListKey.clear();
  await signingSessionSealsRepository.clearAll();
}
