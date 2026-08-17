import { normalizeInteger, normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  mpcMaterialActivationRefsEqual,
  parseMpcMaterialActivationRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import type { Ed25519DurableMaterialLocator } from '../sealedRecovery/materialActivationKey';
import {
  signingSessionSealsRepository,
  type StoredRawSealedRecordEntry,
} from '../../../indexedDB/seamsWalletDB/signingSessionSeals';
import {
  SIGNING_SESSION_SEALED_RECORD_VERSION,
  SIGNING_SESSION_SEAL_ALG,
  SIGNING_SESSION_SEAL_GROUP_ID,
  SIGNING_SESSION_SEAL_STORAGE_SCOPE,
  SIGNING_SESSION_SECRET_KIND,
  type SealedSigningSessionEcdsaRestoreMetadata,
  type SealedSigningSessionEcdsaRestoreSource,
  type SealedSigningSessionRecord,
} from '@shared/utils/signingSessionSeal';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import {
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  parseRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from '../../threshold/ed25519/routerAbNormalSigningState';
import {
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaDerivationNormalSigningStateV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  exactSealedSessionFilterForIdentity,
  type DeleteDurableSealedSessionCommand,
} from './durableSealedSessionCommands';
import {
  parseEcdsaRoleLocalPersistedMaterialRef,
  type EcdsaRoleLocalPersistedMaterialRef,
} from '../keyMaterialBrands';
import { ecdsaSealedRecordStoreKey } from './ecdsaSealedRecordKey';
import {
  parseEmailOtpWalletAuthAuthority,
  parseWalletAuthAuthorityRef,
  type EmailOtpWalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';

export type SigningSessionRestoreLease = {
  v: 1;
  leaseKey: string;
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

export type Ed25519SealedRecordThresholdSessionIds = {
  ed25519: string;
  ecdsa?: string;
};

export type EcdsaSealedRecordThresholdSessionIds = {
  ed25519?: string;
  ecdsa: string;
};

type CurrentEd25519RestoreMetadataBase = {
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  rpId: string;
  relayerKeyId: string;
  participantIds: number[];
  runtimePolicyScope?: unknown;
  signerSlot: number;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type CurrentEd25519RestoreMetadata =
  | (CurrentEd25519RestoreMetadataBase & {
      credentialIdB64u: string;
      materialActivation: MpcMaterialActivationRef;
      providerSubjectId?: never;
      emailHashHex?: never;
    })
  | (CurrentEd25519RestoreMetadataBase & {
      provider: 'google' | 'email';
      providerSubjectId: string;
      emailHashHex: string;
      materialActivation: MpcMaterialActivationRef;
      credentialIdB64u?: never;
    });

export type CurrentEd25519SealedSessionRecord = Omit<
  Extract<SigningSessionSealedStoreRecord, { curve: 'ed25519' }>,
  | 'curve'
  | 'thresholdSessionIds'
  | 'walletId'
  | 'relayerUrl'
  | 'ed25519Restore'
  | 'ecdsaRestore'
> & {
  curve: 'ed25519';
  thresholdSessionIds: Ed25519SealedRecordThresholdSessionIds;
  walletId: string;
  relayerUrl: string;
  ed25519Restore: CurrentEd25519RestoreMetadata;
  ecdsaRestore?: SealedSigningSessionEcdsaRestoreMetadata;
};

export type CurrentEcdsaSealedSessionRecord = Omit<
  Extract<SigningSessionSealedStoreRecord, { curve: 'ecdsa' }>,
  | 'curve'
  | 'thresholdSessionIds'
  | 'walletId'
  | 'relayerUrl'
  | 'signingRootId'
  | 'signingRootVersion'
  | 'ecdsaRestore'
  | 'ed25519Restore'
> & {
  curve: 'ecdsa';
  thresholdSessionIds: EcdsaSealedRecordThresholdSessionIds;
  walletId: string;
  signingRootId?: never;
  signingRootVersion?: never;
  relayerUrl: string;
  ecdsaRestore: SealedSigningSessionEcdsaRestoreMetadata;
  ed25519Restore?: CurrentEd25519RestoreMetadata;
};

const ECDSA_INACTIVE_SEALED_MATERIAL_RECORD_KIND = 'ecdsa_inactive_sealed_material_v1' as const;

type EcdsaInactiveSealedMaterialRecordBase = {
  recordKind: typeof ECDSA_INACTIVE_SEALED_MATERIAL_RECORD_KIND;
  storeKey: string;
  curve: 'ecdsa';
  walletId: string;
  relayerUrl: string;
  alg: typeof SIGNING_SESSION_SEAL_ALG;
  storageScope: typeof SIGNING_SESSION_SEAL_STORAGE_SCOPE;
  secretKind: typeof SIGNING_SESSION_SECRET_KIND;
  sealedSecretB64u: string;
  keyVersion: string;
  groupId: typeof SIGNING_SESSION_SEAL_GROUP_ID;
  updatedAtMs: number;
  issuedAtMs?: never;
  expiresAtMs?: never;
  remainingUses?: never;
  thresholdSessionIds?: never;
  authorizationRetirementReason: 'expired' | 'exhausted';
  ed25519Restore?: never;
};

type EcdsaInactiveMaterialPublicRestoreBase = {
  chainTarget: ThresholdEcdsaChainTarget;
  signingRootId: string;
  signingRootVersion: string;
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  ethereumAddress: string;
  relayerKeyId: string;
  thresholdEcdsaPublicKeyB64u: string;
  participantIds: number[];
  runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  clientVerifyingShareB64u?: never;
};

export type EcdsaInactiveMaterialPublicRestore =
  | (EcdsaInactiveMaterialPublicRestoreBase & {
      source: Exclude<SealedSigningSessionEcdsaRestoreSource, 'email_otp'>;
      authority: WalletAuthAuthorityRef;
      rpId: string;
      credentialIdB64u: string;
      roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef;
      providerSubjectId?: never;
      emailHashHex?: never;
    })
  | (EcdsaInactiveMaterialPublicRestoreBase & {
      source: 'email_otp';
      provider: 'google' | 'email';
      providerSubjectId: string;
      emailHashHex: string;
      authority: WalletAuthAuthorityRef;
      emailOtpAuthority: EmailOtpWalletAuthAuthority;
      roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef;
      rpId?: never;
      credentialIdB64u?: never;
    });

export type EcdsaInactiveSealedMaterialRecord = EcdsaInactiveSealedMaterialRecordBase &
  (
    | {
        authMethod: 'passkey';
        ecdsaRestore: Exclude<EcdsaInactiveMaterialPublicRestore, { source: 'email_otp' }>;
      }
    | {
        authMethod: 'email_otp';
        ecdsaRestore: Extract<EcdsaInactiveMaterialPublicRestore, { source: 'email_otp' }>;
      }
  );

export type EcdsaDurableLaneRecord =
  | SigningSessionSealedStoreRecord
  | EcdsaInactiveSealedMaterialRecord;

export type CurrentSealedSessionRecord =
  | CurrentEd25519SealedSessionRecord
  | CurrentEcdsaSealedSessionRecord;
export type RawSealedSessionRecord = Record<string, unknown>;

export type SealedSessionRecordClassificationReason =
  | 'invalid_payload'
  | 'invalid_header'
  | 'invalid_identity'
  | 'owned_by_lane_holder_store'
  | 'missing_signing_root_id'
  | 'missing_participant_ids'
  | 'missing_restore_metadata';

export type CurrentSealedSessionRecordClassification = {
  kind: 'current';
  record: CurrentSealedSessionRecord;
};

export type EcdsaInactiveSealedMaterialRecordClassification = {
  kind: 'ecdsa_inactive_material';
  record: EcdsaInactiveSealedMaterialRecord;
};

type NonCurrentSealedSessionRecordClassificationKind =
  | 'delete_required'
  | 'rebuild_required'
  | 'user_action_required'
  | 'unrelated_record'
  | 'malformed';

type NonCurrentSealedSessionRecordClassification = {
  [K in NonCurrentSealedSessionRecordClassificationKind]: {
    kind: K;
    storeKey: string | null;
    walletId: string | null;
    reason: SealedSessionRecordClassificationReason;
    safeSummary: Record<string, unknown>;
  };
}[NonCurrentSealedSessionRecordClassificationKind];

export type SealedSessionRecordClassification =
  | CurrentSealedSessionRecordClassification
  | EcdsaInactiveSealedMaterialRecordClassification
  | NonCurrentSealedSessionRecordClassification;

class SealedSessionRecordUserActionRequiredError extends Error {
  readonly classification: Extract<
    NonCurrentSealedSessionRecordClassification,
    { kind: 'user_action_required' }
  >;

  constructor(
    classification: Extract<
      NonCurrentSealedSessionRecordClassification,
      { kind: 'user_action_required' }
    >,
  ) {
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

export type ListEcdsaSigningSessionSealedRecordsForWalletFilter = {
  authMethod?: 'passkey' | 'email_otp';
  curve: 'ecdsa';
};

type BuildCurrentSealedSessionRecordCommonInput = {
  thresholdSessionId: string;
  sealedSecretB64u: string;
  authMethod: 'passkey' | 'email_otp';
  keyVersion: string;
  groupId: typeof SIGNING_SESSION_SEAL_GROUP_ID;
  issuedAtMs: number;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs: number;
};

export type BuildCurrentEd25519SealedSessionRecordInput =
  BuildCurrentSealedSessionRecordCommonInput & {
    curve: 'ed25519';
    thresholdSessionIds: Ed25519SealedRecordThresholdSessionIds;
    walletId: string;
    signingRootId?: string;
    signingRootVersion?: string;
    relayerUrl: string;
    ecdsaRestore?: SealedSigningSessionEcdsaRestoreMetadata;
    ed25519Restore: CurrentEd25519RestoreMetadata;
  };

export type BuildCurrentEcdsaSealedSessionRecordInput =
  BuildCurrentSealedSessionRecordCommonInput & {
    curve: 'ecdsa';
    thresholdSessionIds: EcdsaSealedRecordThresholdSessionIds;
    walletId: string;
    relayerUrl: string;
    ecdsaRestore: SealedSigningSessionEcdsaRestoreMetadata;
    ed25519Restore?: CurrentEd25519RestoreMetadata;
  };

export type BuildCurrentSealedSessionRecordInput =
  | BuildCurrentEd25519SealedSessionRecordInput
  | BuildCurrentEcdsaSealedSessionRecordInput;

export type UpdateExactSealedSessionPolicyInput = {
  thresholdSessionId: string;
  filter: SigningSessionSealedRecordFilter;
  expiresAtMs?: number;
  remainingUses?: number;
  updatedAtMs: number;
};

export type ResolvedIdentityDeleteReason =
  | 'durable_record_deleted'
  | 'invalid_persisted_record'
  | 'same_lane_replaced'
  | 'same_scope_replaced';

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
  return normalizeThresholdSessionIds(obj.thresholdSessionIds);
}

function hasRetiredAuthorizationIdentityField(value: unknown): boolean {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (!obj) return false;
  const camelCaseKey = ['signing', 'Grant', 'Id'].join('');
  const snakeCaseKey = ['signing', 'grant', 'id'].join('_');
  return (
    Object.prototype.hasOwnProperty.call(obj, camelCaseKey) ||
    Object.prototype.hasOwnProperty.call(obj, snakeCaseKey)
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

function durableLaneStorageRow(record: CurrentSealedSessionRecord): Record<string, unknown> {
  const ecdsaChainTarget = record.ecdsaRestore?.chainTarget;
  const ecdsaThresholdSessionId = optionalStringForIndex(record.thresholdSessionIds.ecdsa);
  const ed25519ThresholdSessionId = optionalStringForIndex(record.thresholdSessionIds.ed25519);
  return {
    store_key: record.storeKey,
    wallet_id: record.walletId,
    auth_method: record.authMethod,
    curve: record.curve,
    signing_root_id: optionalStringForIndex(
      'signingRootId' in record ? record.signingRootId : undefined,
    ),
    signing_root_version: optionalStringForIndex(
      'signingRootVersion' in record ? record.signingRootVersion : undefined,
    ),
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

function inactiveEcdsaMaterialStorageRow(
  record: EcdsaInactiveSealedMaterialRecord,
): Record<string, unknown> {
  return {
    store_key: record.storeKey,
    wallet_id: record.walletId,
    auth_method: record.authMethod,
    curve: record.curve,
    key_handle: record.ecdsaRestore.keyHandle,
    chain_target_key: thresholdEcdsaChainTargetKey(record.ecdsaRestore.chainTarget),
    updated_at: record.updatedAtMs,
    [SEALED_RECORD_PAYLOAD_FIELD]: record,
  };
}

function sealedRecordStorageRow(record: CurrentSealedSessionRecord): Record<string, unknown> {
  return durableLaneStorageRow(record);
}

function restoreLeaseStorageRow(lease: SigningSessionRestoreLease): Record<string, unknown> {
  return {
    lease_key: lease.leaseKey,
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

function parseSealedEcdsaRouterAbDerivationNormalSigningState(
  value: unknown,
): RouterAbEcdsaDerivationNormalSigningStateV1 | null {
  try {
    return parseRouterAbEcdsaDerivationNormalSigningStateV1(value);
  } catch {
    return null;
  }
}

function normalizeSealedEcdsaRestoreSource(
  value: unknown,
): SealedSigningSessionEcdsaRestoreSource | null {
  switch (value) {
    case 'login':
    case 'registration':
    case 'manual-bootstrap':
    case 'email_otp':
      return value;
    default:
      return null;
  }
}

function signingRootBindingFromStoredRuntimePolicyScope(
  value: unknown,
): { signingRootId: string; signingRootVersion: string } | null {
  try {
    const scope = signingRootScopeFromRuntimePolicyScope(normalizeRuntimePolicyScope(value));
    const signingRootId = normalizeOptionalNonEmptyString(scope.signingRootId);
    const signingRootVersion = normalizeOptionalNonEmptyString(scope.signingRootVersion);
    return signingRootId && signingRootVersion ? { signingRootId, signingRootVersion } : null;
  } catch {
    return null;
  }
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
  const source = normalizeSealedEcdsaRestoreSource(obj.source);
  const authorityRef = parseWalletAuthAuthorityRef(obj.authority);
  const rpId = normalizeOptionalNonEmptyString(obj.rpId);
  const runtimePolicyScope =
    obj.runtimePolicyScope && typeof obj.runtimePolicyScope === 'object'
      ? obj.runtimePolicyScope
      : undefined;
  const runtimeSigningRootBinding =
    signingRootBindingFromStoredRuntimePolicyScope(runtimePolicyScope);
  const explicitSigningRootId = normalizeOptionalNonEmptyString(obj.signingRootId);
  const explicitSigningRootVersion = normalizeOptionalNonEmptyString(obj.signingRootVersion);
  if (
    explicitSigningRootId &&
    runtimeSigningRootBinding?.signingRootId &&
    explicitSigningRootId !== runtimeSigningRootBinding.signingRootId
  ) {
    return undefined;
  }
  if (
    explicitSigningRootVersion &&
    runtimeSigningRootBinding?.signingRootVersion &&
    explicitSigningRootVersion !== runtimeSigningRootBinding.signingRootVersion
  ) {
    return undefined;
  }
  const signingRootId = explicitSigningRootId || runtimeSigningRootBinding?.signingRootId || '';
  const signingRootVersion =
    explicitSigningRootVersion || runtimeSigningRootBinding?.signingRootVersion || '';
  const credentialIdB64u = normalizeOptionalNonEmptyString(obj.credentialIdB64u);
  let roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef | null = null;
  try {
    roleLocalMaterialRef = parseEcdsaRoleLocalPersistedMaterialRef(obj.roleLocalMaterialRef);
  } catch {
    roleLocalMaterialRef = null;
  }
  const emailOtpAuthority = parseEmailOtpWalletAuthAuthority(obj.emailOtpAuthority);
  const provider = obj.provider === 'google' || obj.provider === 'email' ? obj.provider : null;
  const providerSubjectId = normalizeOptionalNonEmptyString(obj.providerSubjectId);
  const emailHashHex = normalizeOptionalNonEmptyString(obj.emailHashHex);
  const keyHandle = normalizeOptionalNonEmptyString(obj.keyHandle);
  const ecdsaThresholdKeyId = normalizeOptionalNonEmptyString(obj.ecdsaThresholdKeyId);
  const ethereumAddress = normalizeEthereumAddress(obj.ethereumAddress);
  const relayerKeyId = normalizeOptionalNonEmptyString(obj.relayerKeyId);
  const thresholdEcdsaPublicKeyB64u = normalizeOptionalNonEmptyString(
    obj.thresholdEcdsaPublicKeyB64u,
  );
  const routerAbEcdsaDerivationNormalSigning = parseSealedEcdsaRouterAbDerivationNormalSigningState(
    obj.routerAbEcdsaDerivationNormalSigning,
  );
  let publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1 | null = null;
  try {
    publicCapability = parseRouterAbEcdsaDerivationPublicCapabilityV1(obj.publicCapability);
  } catch {
    publicCapability = null;
  }
  const participantIds = Array.isArray(obj.participantIds)
    ? obj.participantIds
        .map((participantId) => Math.floor(Number(participantId)))
        .filter((participantId) => Number.isFinite(participantId) && participantId > 0)
    : [];
  if (
    !chainTarget ||
    !source ||
    !signingRootId ||
    !signingRootVersion ||
    !keyHandle ||
    !ethereumAddress ||
    !relayerKeyId ||
    !routerAbEcdsaDerivationNormalSigning ||
    !publicCapability ||
    !participantIds.length
  ) {
    return undefined;
  }
  const authBranch =
    credentialIdB64u && rpId && roleLocalMaterialRef && authorityRef && source !== 'email_otp'
      ? ({
          source,
          authority: authorityRef,
          roleLocalMaterialRef,
          rpId,
          credentialIdB64u,
        } as const)
      : providerSubjectId &&
          provider &&
          emailHashHex &&
          roleLocalMaterialRef &&
          authorityRef &&
          emailOtpAuthority &&
          source === 'email_otp'
        ? ({
            source,
            provider,
            providerSubjectId,
            emailHashHex,
            authority: authorityRef,
            emailOtpAuthority,
            roleLocalMaterialRef,
          } as const)
        : null;
  if (!authBranch) return undefined;
  const clientVerifyingShareB64u = normalizeOptionalNonEmptyString(obj.clientVerifyingShareB64u);
  return {
    chainTarget,
    signingRootId,
    signingRootVersion,
    ...authBranch,
    keyHandle,
    ...(ecdsaThresholdKeyId ? { ecdsaThresholdKeyId } : {}),
    ethereumAddress,
    relayerKeyId,
    ...(clientVerifyingShareB64u ? { clientVerifyingShareB64u } : {}),
    ...(thresholdEcdsaPublicKeyB64u ? { thresholdEcdsaPublicKeyB64u } : {}),
    participantIds,
    routerAbEcdsaDerivationNormalSigning,
    publicCapability,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
  };
}

function normalizeCurrentEd25519RestoreMetadata(
  value: unknown,
): CurrentEd25519RestoreMetadata | undefined {
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
  const provider = obj.provider === 'google' || obj.provider === 'email' ? obj.provider : null;
  const emailHashHex = normalizeOptionalNonEmptyString(obj.emailHashHex);
  const authSubjectId = normalizeOptionalNonEmptyString(obj.authSubjectId);
  const relayerKeyId = normalizeOptionalNonEmptyString(obj.relayerKeyId);
  const participantIds = Array.isArray(obj.participantIds)
    ? obj.participantIds
        .map((participantId) => Math.floor(Number(participantId)))
        .filter((participantId) => Number.isFinite(participantId) && participantId > 0)
    : [];
  const signerSlot = normalizeInteger(obj.signerSlot);
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(obj.routerAbNormalSigning);
  const materialActivation = parseMpcMaterialActivationRef(obj.materialActivation);
  const authBranch =
    credentialIdB64u && !providerSubjectId && materialActivation.ok
      ? ({ credentialIdB64u, materialActivation: materialActivation.value } as const)
      : provider && providerSubjectId && emailHashHex && !credentialIdB64u && materialActivation.ok
        ? ({
            provider,
            providerSubjectId,
            emailHashHex,
            materialActivation: materialActivation.value,
          } as const)
        : null;
  if (
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !rpId ||
    !relayerKeyId ||
    !participantIds.length ||
    signerSlot == null ||
    signerSlot <= 0 ||
    !routerAbNormalSigning ||
    !authBranch ||
    authSubjectId
  ) {
    return undefined;
  }
  return {
    nearAccountId,
    nearEd25519SigningKeyId,
    rpId,
    ...authBranch,
    relayerKeyId,
    participantIds,
    ...(obj.runtimePolicyScope && typeof obj.runtimePolicyScope === 'object'
      ? { runtimePolicyScope: obj.runtimePolicyScope }
      : {}),
    signerSlot,
    routerAbNormalSigning,
  };
}

type Ed25519SealedRecordStoreKeyInput = {
  walletId: string;
  authMethod: 'passkey' | 'email_otp';
  restore: CurrentEd25519RestoreMetadata;
};

function ed25519SealedRecordStoreKey(args: Ed25519SealedRecordStoreKeyInput): string {
  const materialActivation = args.restore.materialActivation;
  return [
    'ed25519-material-v2',
    args.walletId,
    args.authMethod,
    'ed25519',
    materialActivation.activationId,
    materialActivation.capability,
    materialActivation.materialOwner,
    materialActivation.keyBinding,
    materialActivation.lifecycleBinding,
    materialActivation.signingWorker,
  ]
    .map(sealedStoreKeyPart)
    .join(':');
}

function makeInactiveEcdsaMaterialStoreKey(args: {
  walletId: string;
  authMethod: 'passkey' | 'email_otp';
  restore: EcdsaInactiveMaterialPublicRestore;
}): string {
  const material = args.restore.roleLocalMaterialRef;
  return [
    'inactive-material',
    args.walletId,
    args.authMethod,
    'ecdsa',
    thresholdEcdsaChainTargetKey(args.restore.chainTarget),
    material.materialActivation.activationId,
  ]
    .map(sealedStoreKeyPart)
    .join(':');
}

function sealedStoreKeyPart(value: unknown): string {
  return encodeURIComponent(String(value || '').trim());
}

function normalizeAuthMethod(value: unknown): 'passkey' | 'email_otp' | undefined {
  const authMethod = String(value || '').trim();
  return authMethod === 'passkey' || authMethod === 'email_otp' ? authMethod : undefined;
}

function hasStaleSealedSessionWalletIdentityFields(value: unknown): boolean {
  const obj = asRawSealedSessionRecord(value);
  return Boolean(
    normalizeOptionalNonEmptyString(obj?.subjectId) || normalizeOptionalNonEmptyString(obj?.userId),
  );
}

function hasTopLevelSigningRootFields(value: unknown): boolean {
  const obj = asRawSealedSessionRecord(value);
  return Boolean(
    normalizeOptionalNonEmptyString(obj?.signingRootId) ||
    normalizeOptionalNonEmptyString(obj?.signingRootVersion),
  );
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
  if (left.curve === 'ed25519' && right.curve === 'ed25519') {
    return mpcMaterialActivationRefsEqual(
      left.ed25519Restore.materialActivation,
      right.ed25519Restore.materialActivation,
    );
  }
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

function buildSealedSessionSafeSummary(
  obj: RawSealedSessionRecord | null,
): Record<string, unknown> {
  return {
    authMethod: normalizeOptionalNonEmptyString(obj?.authMethod) || null,
    curve: normalizeOptionalNonEmptyString(obj?.curve) || null,
    storeKey: normalizeOptionalNonEmptyString(obj?.storeKey) || null,
    walletId: normalizeOptionalNonEmptyString(obj?.walletId) || null,
    thresholdSessionIds: normalizeThresholdSessionIdsFromStoredRecord(obj),
    hasEcdsaRestore: Boolean(asRawSealedSessionRecord(obj?.ecdsaRestore)),
    hasEd25519Restore: Boolean(asRawSealedSessionRecord(obj?.ed25519Restore)),
    issuedAtMs: normalizeInteger(obj?.issuedAtMs),
    expiresAtMs: normalizeInteger(obj?.expiresAtMs),
    remainingUses: normalizeInteger(obj?.remainingUses),
    updatedAtMs: normalizeInteger(obj?.updatedAtMs),
  };
}

function classifyNonCurrentRecord(
  kind: NonCurrentSealedSessionRecordClassificationKind,
  obj: RawSealedSessionRecord | null,
  reason: SealedSessionRecordClassificationReason,
): NonCurrentSealedSessionRecordClassification {
  return {
    kind,
    storeKey: normalizeOptionalNonEmptyString(obj?.storeKey) || null,
    walletId: normalizeOptionalNonEmptyString(obj?.walletId) || null,
    reason,
    safeSummary: buildSealedSessionSafeSummary(obj),
  };
}

export function classifyRawSealedSessionRecord(raw: unknown): SealedSessionRecordClassification {
  raw = storagePayloadFromSealedStoreRow(raw);
  const obj = asRawSealedSessionRecord(raw);
  if (!obj) return classifyNonCurrentRecord('malformed', null, 'invalid_payload');
  if (obj.kind === 'lane_sealed_holder_record_v1') {
    return classifyNonCurrentRecord('unrelated_record', obj, 'owned_by_lane_holder_store');
  }
  if (hasRetiredAuthorizationIdentityField(obj)) {
    return classifyNonCurrentRecord('delete_required', obj, 'invalid_identity');
  }
  if (obj.recordKind === 'ecdsa_reauth_anchor_v1') {
    return classifyNonCurrentRecord('delete_required', obj, 'invalid_header');
  }
  if (obj.recordKind === ECDSA_INACTIVE_SEALED_MATERIAL_RECORD_KIND) {
    const record = normalizeEcdsaInactiveSealedMaterialRecord(obj);
    return record
      ? { kind: 'ecdsa_inactive_material', record }
      : classifyNonCurrentRecord('malformed', obj, 'invalid_identity');
  }
  if (Number(obj.v) === 1) {
    return classifyNonCurrentRecord('delete_required', obj, 'invalid_header');
  }
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
  const thresholdSessionIds = normalizeThresholdSessionIdsFromStoredRecord(obj);
  const sealedSecretB64u = normalizeOptionalNonEmptyString(obj.sealedSecretB64u);
  const curve = normalizeCurve(obj.curve);
  const subjectId = normalizeOptionalNonEmptyString(obj.subjectId);
  const userId = normalizeOptionalNonEmptyString(obj.userId);
  const walletId = normalizeOptionalNonEmptyString(obj.walletId);
  const signingRootId = normalizeOptionalNonEmptyString(obj.signingRootId);
  const explicitSigningRootVersion = normalizeOptionalNonEmptyString(obj.signingRootVersion);
  const signingRootVersion = explicitSigningRootVersion || (signingRootId ? 'default' : null);
  const relayerUrl = normalizeOptionalNonEmptyString(obj.relayerUrl);
  const keyVersion = normalizeOptionalNonEmptyString(obj.keyVersion);
  const groupId = normalizeOptionalNonEmptyString(obj.groupId);
  const issuedAtMs = normalizeInteger(obj.issuedAtMs);
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  const remainingUses = normalizeInteger(obj.remainingUses);
  const updatedAtMs = normalizeInteger(obj.updatedAtMs);

  if (!sealedSecretB64u || !keyVersion || groupId !== SIGNING_SESSION_SEAL_GROUP_ID) {
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
  const ed25519Restore = normalizeCurrentEd25519RestoreMetadata(obj.ed25519Restore);

  if (recordCurve === 'ecdsa') {
    if (!thresholdSessionIds.ecdsa) {
      return classifyNonCurrentRecord('malformed', obj, 'invalid_identity');
    }
    if (subjectId || userId || signingRootId || explicitSigningRootVersion) {
      return classifyNonCurrentRecord('delete_required', obj, 'invalid_identity');
    }
    if (!ecdsaRestoreObj || !relayerUrl) {
      return classifyNonCurrentRecord('rebuild_required', obj, 'missing_restore_metadata');
    }
    if (!normalizeParticipantIds(ecdsaRestoreObj.participantIds).length) {
      return classifyNonCurrentRecord('delete_required', obj, 'missing_participant_ids');
    }
    if (!ecdsaRestore) {
      return classifyNonCurrentRecord('rebuild_required', obj, 'missing_restore_metadata');
    }
    const storeKey = ecdsaSealedRecordStoreKey({
      walletId,
      authMethod,
      chainTarget: ecdsaRestore.chainTarget,
      materialActivation: ecdsaRestore.roleLocalMaterialRef.materialActivation,
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
        thresholdSessionIds: {
          ...(thresholdSessionIds.ed25519 ? { ed25519: thresholdSessionIds.ed25519 } : {}),
          ecdsa: thresholdSessionIds.ecdsa,
        },
        sealedSecretB64u,
        curve: 'ecdsa',
        walletId,
        relayerUrl,
        keyVersion,
        groupId: SIGNING_SESSION_SEAL_GROUP_ID,
        ecdsaRestore,
        ...(ed25519Restore ? { ed25519Restore } : {}),
        issuedAtMs,
        expiresAtMs,
        remainingUses,
        updatedAtMs,
      },
    };
  }

  if (!thresholdSessionIds.ed25519) {
    return classifyNonCurrentRecord('malformed', obj, 'invalid_identity');
  }
  if (subjectId || userId)
    return classifyNonCurrentRecord('delete_required', obj, 'invalid_identity');
  if (!ed25519RestoreObj || !relayerUrl) {
    return classifyNonCurrentRecord('rebuild_required', obj, 'missing_restore_metadata');
  }
  if (!normalizeParticipantIds(ed25519RestoreObj.participantIds).length) {
    return classifyNonCurrentRecord('delete_required', obj, 'missing_participant_ids');
  }
  if (!ed25519Restore) {
    return classifyNonCurrentRecord('rebuild_required', obj, 'missing_restore_metadata');
  }
  const storeKey = ed25519SealedRecordStoreKey({
    walletId,
    authMethod,
    restore: ed25519Restore,
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
      thresholdSessionIds: {
        ed25519: thresholdSessionIds.ed25519,
        ...(thresholdSessionIds.ecdsa ? { ecdsa: thresholdSessionIds.ecdsa } : {}),
      },
      sealedSecretB64u,
      curve: 'ed25519',
      walletId,
      ...(signingRootId ? { signingRootId } : {}),
      ...(signingRootVersion ? { signingRootVersion } : {}),
      relayerUrl,
      keyVersion,
      groupId: SIGNING_SESSION_SEAL_GROUP_ID,
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

async function classifyPersistedSealedRecord(
  entry: StoredRawSealedRecordEntry,
): Promise<SealedSessionRecordClassification> {
  const payload = storagePayloadFromSealedStoreRow(entry.value);
  const classification = classifyRawSealedSessionRecord(payload);
  if (classification.kind !== 'current') {
    return classification;
  }
  const raw = asRawSealedSessionRecord(payload);
  const rawRow = asRawSealedSessionRecord(entry.value);
  if (
    hasRetiredAuthorizationIdentityField(rawRow) ||
    hasRetiredAuthorizationIdentityField(raw)
  ) {
    return classifyNonCurrentRecord('delete_required', raw, 'invalid_identity');
  }
  const persistedStoreKey = normalizeOptionalNonEmptyString(raw?.storeKey);
  if (!persistedStoreKey || persistedStoreKey === classification.record.storeKey) {
    return classification;
  }
  return classification;
}

function normalizeEcdsaInactiveMaterialPublicRestore(
  value: unknown,
): EcdsaInactiveMaterialPublicRestore | null {
  const obj = asRawSealedSessionRecord(value);
  if (!obj) return null;
  if (
    obj.clientVerifyingShareB64u != null
  ) {
    return null;
  }
  let chainTarget: ThresholdEcdsaChainTarget;
  let runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  let routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  let publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  try {
    chainTarget = thresholdEcdsaChainTargetFromRequest(
      obj.chainTarget && typeof obj.chainTarget === 'object'
        ? (obj.chainTarget as Record<string, unknown>)
        : {},
    );
    runtimePolicyScope = normalizeRuntimePolicyScope(obj.runtimePolicyScope);
    const parsedRouterAbState = parseRouterAbEcdsaDerivationNormalSigningStateV1(
      obj.routerAbEcdsaDerivationNormalSigning,
    );
    if (!parsedRouterAbState) return null;
    routerAbEcdsaDerivationNormalSigning = parsedRouterAbState;
    publicCapability = parseRouterAbEcdsaDerivationPublicCapabilityV1(obj.publicCapability);
  } catch {
    return null;
  }
  const signingRootId = normalizeOptionalNonEmptyString(obj.signingRootId);
  const signingRootVersion = normalizeOptionalNonEmptyString(obj.signingRootVersion);
  let roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef | null = null;
  try {
    roleLocalMaterialRef = parseEcdsaRoleLocalPersistedMaterialRef(obj.roleLocalMaterialRef);
  } catch {
    roleLocalMaterialRef = null;
  }
  const authorityRef = parseWalletAuthAuthorityRef(obj.authority);
  const emailOtpAuthority = parseEmailOtpWalletAuthAuthority(obj.emailOtpAuthority);
  const keyHandle = normalizeOptionalNonEmptyString(obj.keyHandle);
  const ecdsaThresholdKeyId = normalizeOptionalNonEmptyString(obj.ecdsaThresholdKeyId);
  const ethereumAddress = normalizeOptionalNonEmptyString(obj.ethereumAddress);
  const relayerKeyId = normalizeOptionalNonEmptyString(obj.relayerKeyId);
  const thresholdEcdsaPublicKeyB64u = normalizeOptionalNonEmptyString(
    obj.thresholdEcdsaPublicKeyB64u,
  );
  const participantIds = normalizeParticipantIds(obj.participantIds);
  if (
    !signingRootId ||
    !signingRootVersion ||
    !keyHandle ||
    !ecdsaThresholdKeyId ||
    !ethereumAddress ||
    !relayerKeyId ||
    !thresholdEcdsaPublicKeyB64u ||
    !participantIds.length
  ) {
    return null;
  }
  switch (obj.source) {
    case 'email_otp': {
      const provider = obj.provider === 'google' || obj.provider === 'email' ? obj.provider : null;
      const providerSubjectId = normalizeOptionalNonEmptyString(obj.providerSubjectId);
      const emailHashHex = normalizeOptionalNonEmptyString(obj.emailHashHex);
      if (
        !provider ||
        !providerSubjectId ||
        !emailHashHex ||
        !roleLocalMaterialRef ||
        !authorityRef ||
        !emailOtpAuthority ||
        obj.rpId != null ||
        obj.credentialIdB64u != null
      ) {
        return null;
      }
      return {
        chainTarget,
        signingRootId,
        signingRootVersion,
        keyHandle,
        ecdsaThresholdKeyId,
        ethereumAddress,
        relayerKeyId,
        thresholdEcdsaPublicKeyB64u,
        participantIds,
        runtimePolicyScope,
        routerAbEcdsaDerivationNormalSigning,
        publicCapability,
        source: 'email_otp',
        provider,
        providerSubjectId,
        emailHashHex,
        authority: authorityRef,
        emailOtpAuthority,
        roleLocalMaterialRef,
      };
    }
    case 'login':
    case 'registration':
    case 'manual-bootstrap': {
      const rpId = normalizeOptionalNonEmptyString(obj.rpId);
      const credentialIdB64u = normalizeOptionalNonEmptyString(obj.credentialIdB64u);
      if (
        !rpId ||
        !credentialIdB64u ||
        !roleLocalMaterialRef ||
        !authorityRef ||
        obj.providerSubjectId != null ||
        obj.emailHashHex != null
      ) {
        return null;
      }
      return {
        chainTarget,
        signingRootId,
        signingRootVersion,
        keyHandle,
        ecdsaThresholdKeyId,
        ethereumAddress,
        relayerKeyId,
        thresholdEcdsaPublicKeyB64u,
        participantIds,
        runtimePolicyScope,
        routerAbEcdsaDerivationNormalSigning,
        publicCapability,
        source: obj.source,
        authority: authorityRef,
        roleLocalMaterialRef,
        rpId,
        credentialIdB64u,
      };
    }
    default:
      return null;
  }
}

function normalizeEcdsaInactiveSealedMaterialRecord(
  value: unknown,
): EcdsaInactiveSealedMaterialRecord | null {
  const payload = storagePayloadFromSealedStoreRow(value);
  const obj = asRawSealedSessionRecord(payload);
  if (!obj || obj.recordKind !== ECDSA_INACTIVE_SEALED_MATERIAL_RECORD_KIND) return null;
  if (
    hasRetiredAuthorizationIdentityField(obj) ||
    obj.thresholdSessionIds != null ||
    obj.ed25519Restore != null
  ) {
    return null;
  }
  if (obj.curve !== 'ecdsa') return null;
  const authMethod = normalizeAuthMethod(obj.authMethod);
  const walletId = normalizeOptionalNonEmptyString(obj.walletId);
  const relayerUrl = normalizeOptionalNonEmptyString(obj.relayerUrl);
  const ecdsaRestore = normalizeEcdsaInactiveMaterialPublicRestore(obj.ecdsaRestore);
  const sealedSecretB64u = normalizeOptionalNonEmptyString(obj.sealedSecretB64u);
  const keyVersion = normalizeOptionalNonEmptyString(obj.keyVersion);
  const groupId = normalizeOptionalNonEmptyString(obj.groupId);
  const updatedAtMs = normalizeInteger(obj.updatedAtMs);
  const authorizationRetirementReason = obj.authorizationRetirementReason;
  if (
    !authMethod ||
    !walletId ||
    !relayerUrl ||
    !ecdsaRestore ||
    obj.alg !== SIGNING_SESSION_SEAL_ALG ||
    obj.storageScope !== SIGNING_SESSION_SEAL_STORAGE_SCOPE ||
    obj.secretKind !== SIGNING_SESSION_SECRET_KIND ||
    !sealedSecretB64u ||
    !keyVersion ||
    groupId !== SIGNING_SESSION_SEAL_GROUP_ID ||
    obj.issuedAtMs != null ||
    obj.expiresAtMs != null ||
    obj.remainingUses != null ||
    updatedAtMs == null ||
    updatedAtMs <= 0
  ) {
    return null;
  }
  if (
    authorizationRetirementReason !== 'expired' &&
    authorizationRetirementReason !== 'exhausted'
  ) {
    return null;
  }
  const storeKey = makeInactiveEcdsaMaterialStoreKey({
    walletId,
    authMethod,
    restore: ecdsaRestore,
  });
  if (normalizeOptionalNonEmptyString(obj.storeKey) !== storeKey) return null;
  const common = {
    recordKind: ECDSA_INACTIVE_SEALED_MATERIAL_RECORD_KIND,
    storeKey,
    curve: 'ecdsa',
    walletId,
    relayerUrl,
    alg: SIGNING_SESSION_SEAL_ALG,
    storageScope: SIGNING_SESSION_SEAL_STORAGE_SCOPE,
    secretKind: SIGNING_SESSION_SECRET_KIND,
    sealedSecretB64u,
    keyVersion,
    groupId: SIGNING_SESSION_SEAL_GROUP_ID,
    updatedAtMs,
    authorizationRetirementReason,
  } as const;
  if (authMethod === 'email_otp' && ecdsaRestore.source === 'email_otp') {
    return { ...common, authMethod, ecdsaRestore };
  }
  if (authMethod === 'passkey' && ecdsaRestore.source !== 'email_otp') {
    return { ...common, authMethod, ecdsaRestore };
  }
  return null;
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

function logSealedSessionClassification(args: {
  operation: string;
  classification: Exclude<
    SealedSessionRecordClassification,
    CurrentSealedSessionRecordClassification
  >;
}): void {
  if (args.classification.kind === 'ecdsa_inactive_material') return;
  if (args.classification.kind === 'rebuild_required') return;
  if (args.classification.kind === 'unrelated_record') return;
  const outcome = args.classification.kind === 'malformed' ? 'malformed' : 'rejected';
  const payload = {
    operation: args.operation,
    outcome,
    classificationKind: args.classification.kind,
    ...args.classification,
  };
  console.warn('[SigningSessionSealedStore] rejected sealed record', payload);
}

export function buildCurrentSealedSessionRecord(
  args: BuildCurrentSealedSessionRecordInput,
): CurrentSealedSessionRecord | null {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const curve = normalizeCurve(args.curve);
  const authMethod =
    args.authMethod === 'passkey' || args.authMethod === 'email_otp' ? args.authMethod : undefined;
  if (!curve || !authMethod) return null;
  const thresholdSessionIds = thresholdSessionIdsForWrite({
    thresholdSessionId,
    curve,
    thresholdSessionIds: args.thresholdSessionIds,
  });
  const walletId = normalizeOptionalNonEmptyString(args.walletId);
  const sealedSecretB64u = normalizeOptionalNonEmptyString(args.sealedSecretB64u);
  const expiresAtMs = normalizeInteger(args.expiresAtMs);
  const remainingUses = normalizeInteger(args.remainingUses);
  const issuedAtMs = normalizeInteger(args.issuedAtMs);
  const updatedAtMs = normalizeInteger(args.updatedAtMs);
  const keyVersion = normalizeOptionalNonEmptyString(args.keyVersion);
  if (
    !thresholdSessionId ||
    !sealedSecretB64u ||
    !keyVersion ||
    args.groupId !== SIGNING_SESSION_SEAL_GROUP_ID
  )
    return null;
  if (!thresholdSessionIds.ed25519 && !thresholdSessionIds.ecdsa) return null;
  if (issuedAtMs == null || issuedAtMs <= 0) return null;
  if (expiresAtMs == null || expiresAtMs <= 0) return null;
  if (remainingUses == null || remainingUses < 0) return null;
  if (updatedAtMs == null || updatedAtMs <= 0) return null;
  const ecdsaRestore = normalizeEcdsaRestoreMetadata(args.ecdsaRestore);
  const ed25519Restore = normalizeCurrentEd25519RestoreMetadata(args.ed25519Restore);
  if (hasStaleSealedSessionWalletIdentityFields(args)) return null;
  if (curve === 'ecdsa') {
    if (!ecdsaRestore?.chainTarget || !walletId) return null;
    if (hasTopLevelSigningRootFields(args)) return null;
  }
  let signingRootIdForWrite: string | undefined;
  let signingRootVersionForWrite: string | undefined;
  if (args.curve === 'ed25519') {
    signingRootIdForWrite = normalizeOptionalNonEmptyString(args.signingRootId);
    signingRootVersionForWrite = normalizeOptionalNonEmptyString(args.signingRootVersion);
  }

  const classification = classifyRawSealedSessionRecord({
    v: SIGNING_SESSION_SEALED_RECORD_VERSION,
    alg: SIGNING_SESSION_SEAL_ALG,
    storageScope: SIGNING_SESSION_SEAL_STORAGE_SCOPE,
    authMethod,
    secretKind: SIGNING_SESSION_SECRET_KIND,
    thresholdSessionIds,
    sealedSecretB64u,
    curve,
    ...(walletId ? { walletId } : {}),
    ...(signingRootIdForWrite ? { signingRootId: signingRootIdForWrite } : {}),
    ...(signingRootVersionForWrite ? { signingRootVersion: signingRootVersionForWrite } : {}),
    ...(normalizeOptionalNonEmptyString(args.relayerUrl)
      ? { relayerUrl: normalizeOptionalNonEmptyString(args.relayerUrl) }
      : {}),
    keyVersion,
    groupId: SIGNING_SESSION_SEAL_GROUP_ID,
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
  if (hasRetiredAuthorizationIdentityField(obj)) return null;
  const leaseKey = normalizeOptionalNonEmptyString(obj.leaseKey);
  const ownerId = normalizeOptionalNonEmptyString(obj.ownerId);
  const attemptId = normalizeOptionalNonEmptyString(obj.attemptId);
  const startedAtMs = normalizeInteger(obj.startedAtMs);
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  if (!leaseKey || !ownerId || !attemptId) return null;
  if (startedAtMs == null || startedAtMs <= 0) return null;
  if (expiresAtMs == null || expiresAtMs <= startedAtMs) return null;
  return {
    v: 1,
    leaseKey,
    ownerId,
    attemptId,
    startedAtMs,
    expiresAtMs,
  };
}

function makeSigningSessionRestoreLease(args: {
  leaseKey: string;
  ownerId: string;
  nowMs: number;
  ttlMs: number;
}): SigningSessionRestoreLease {
  return {
    v: 1,
    leaseKey: args.leaseKey,
    ownerId: args.ownerId,
    attemptId: createRandomId('restore-attempt'),
    startedAtMs: args.nowMs,
    expiresAtMs: args.nowMs + args.ttlMs,
  };
}

function thresholdSessionIdsForWrite(args: {
  thresholdSessionId: string;
  curve: 'ed25519' | 'ecdsa';
  thresholdSessionIds: {
    ed25519?: string;
    ecdsa?: string;
  };
}): { ed25519?: string; ecdsa?: string } {
  const explicit = normalizeThresholdSessionIds(args.thresholdSessionIds);
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return {};
  if (args.curve === 'ed25519' && explicit.ed25519 === thresholdSessionId) return explicit;
  if (args.curve === 'ecdsa' && explicit.ecdsa === thresholdSessionId) return explicit;
  return {};
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
    const rawThresholdSessionIds = rawThresholdSessionIdsFromSealedStoreRow(entry.value);
    return (
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
    const classification = await classifyPersistedSealedRecord(entry);
    if (classification.kind === 'current') {
      if (recordMatchesFilter(classification.record, thresholdSessionId, filter)) {
        selected = classification.record;
      }
      continue;
    }
    logSealedSessionClassification({ operation, classification });
    if (classification.kind === 'delete_required' || classification.kind === 'malformed') {
      deletePrimaryKeys.push(entry.primaryKey);
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
      const classification = await classifyPersistedSealedRecord(entry);
      const record = classification.kind === 'current' ? classification.record : null;
      if (record?.storeKey && recordMatchesFilter(record, thresholdSessionId, filter)) {
        deletePrimaryKeys.push(record.storeKey);
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
      const classification = await classifyPersistedSealedRecord(entry);
      const existing = classification.kind === 'current' ? classification.record : null;
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

function inactiveMaterialStoreKeyReplacedByCurrent(
  record: CurrentSealedSessionRecord,
): string | null {
  if (record.curve !== 'ecdsa') return null;
  const publicRestore = buildEcdsaInactiveMaterialPublicRestore(
    record.ecdsaRestore,
    record.relayerUrl,
  );
  if (!publicRestore) return null;
  return makeInactiveEcdsaMaterialStoreKey({
    walletId: record.walletId,
    authMethod: record.authMethod,
    restore: publicRestore,
  });
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

export async function readExactEd25519SealedSession(
  locator: Ed25519DurableMaterialLocator,
): Promise<CurrentEd25519SealedSessionRecord | null> {
  const entries = await signingSessionSealsRepository.collectAllRawSealedRecordEntries();
  const deletePrimaryKeys: unknown[] = [];
  const matches: CurrentEd25519SealedSessionRecord[] = [];
  for (const entry of entries) {
    const classification = await classifyPersistedSealedRecord(entry);
    if (classification.kind === 'current') {
      const record = classification.record;
      if (
        record.curve === 'ed25519' &&
        record.authMethod === locator.authMethod &&
        mpcMaterialActivationRefsEqual(
          record.ed25519Restore.materialActivation,
          locator.materialActivation,
        )
      ) {
        matches.push(record);
      }
      continue;
    }
    logSealedSessionClassification({
      operation: 'read exact Ed25519 material',
      classification,
    });
    if (classification.kind === 'delete_required' || classification.kind === 'malformed') {
      deletePrimaryKeys.push(entry.primaryKey);
    }
    if (classification.kind === 'user_action_required') {
      await signingSessionSealsRepository.deleteSealedRecords(deletePrimaryKeys);
      throw new SealedSessionRecordUserActionRequiredError(classification);
    }
  }
  await signingSessionSealsRepository.deleteSealedRecords(deletePrimaryKeys);
  if (matches.length > 1) {
    throw new Error(
      '[SigningSessionSealedStore] exact Ed25519 material activation is ambiguous',
    );
  }
  return matches[0] ?? null;
}

export async function listExactSealedSessionsForWallet(args: {
  walletId: string;
  filter: SigningSessionSealedRecordFilter;
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
      const classification = await classifyPersistedSealedRecord(value);
      if (classification.kind !== 'current') {
        logSealedSessionClassification({
          operation: 'list exact account records',
          classification,
        });
        if (classification.kind === 'delete_required' || classification.kind === 'malformed') {
          deletePrimaryKeys.push(value.primaryKey);
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
}): Promise<EcdsaDurableLaneRecord[]> {
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
    const records: EcdsaDurableLaneRecord[] = [];
    const seen = new Set<string>();
    for (const value of values) {
      const classification = await classifyPersistedSealedRecord(value);
      if (classification.kind === 'ecdsa_inactive_material') {
        const record = classification.record;
        if (record.walletId !== walletId) continue;
        if (args.filter.authMethod && record.authMethod !== args.filter.authMethod) continue;
        if (seen.has(record.storeKey)) continue;
        seen.add(record.storeKey);
        records.push(record);
        continue;
      }
      if (classification.kind !== 'current') {
        logSealedSessionClassification({
          operation: 'list wallet ecdsa records',
          classification,
        });
        if (classification.kind === 'delete_required' || classification.kind === 'malformed') {
          deletePrimaryKeys.push(value.primaryKey);
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

  const staleRecords = await listSameScopeRecords(currentRecord);
  const replacedInactiveMaterialStoreKey = inactiveMaterialStoreKeyReplacedByCurrent(currentRecord);
  await signingSessionSealsRepository.replaceSealedRecord({
    row: sealedRecordStorageRow(currentRecord),
    staleStoreKeys: [
      ...staleRecords.map((record) => record.storeKey),
      ...(replacedInactiveMaterialStoreKey ? [replacedInactiveMaterialStoreKey] : []),
    ],
  });
}

export function buildEcdsaInactiveMaterialPublicRestore(
  restore: SealedSigningSessionEcdsaRestoreMetadata,
  relayerUrlRaw: string,
): EcdsaInactiveMaterialPublicRestore | null {
  const relayerUrl = normalizeOptionalNonEmptyString(relayerUrlRaw);
  const ecdsaThresholdKeyId = normalizeOptionalNonEmptyString(restore.ecdsaThresholdKeyId);
  const thresholdEcdsaPublicKeyB64u = normalizeOptionalNonEmptyString(
    restore.thresholdEcdsaPublicKeyB64u,
  );
  if (!relayerUrl || !ecdsaThresholdKeyId || !thresholdEcdsaPublicKeyB64u) return null;
  let runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  try {
    runtimePolicyScope = normalizeRuntimePolicyScope(restore.runtimePolicyScope);
  } catch {
    return null;
  }
  switch (restore.source) {
    case 'email_otp':
      return {
        chainTarget: restore.chainTarget,
        signingRootId: restore.signingRootId,
        signingRootVersion: restore.signingRootVersion,
        keyHandle: restore.keyHandle,
        ecdsaThresholdKeyId,
        ethereumAddress: restore.ethereumAddress,
        relayerKeyId: restore.relayerKeyId,
        thresholdEcdsaPublicKeyB64u,
        participantIds: [...restore.participantIds],
        runtimePolicyScope,
        routerAbEcdsaDerivationNormalSigning: restore.routerAbEcdsaDerivationNormalSigning,
        publicCapability: restore.publicCapability,
        source: 'email_otp',
        provider: restore.provider,
        providerSubjectId: restore.providerSubjectId,
        emailHashHex: restore.emailHashHex,
        authority: restore.authority,
        emailOtpAuthority: restore.emailOtpAuthority,
        roleLocalMaterialRef: parseEcdsaRoleLocalPersistedMaterialRef(restore.roleLocalMaterialRef),
      };
    case 'login':
    case 'registration':
    case 'manual-bootstrap':
      return {
        chainTarget: restore.chainTarget,
        signingRootId: restore.signingRootId,
        signingRootVersion: restore.signingRootVersion,
        keyHandle: restore.keyHandle,
        ecdsaThresholdKeyId,
        ethereumAddress: restore.ethereumAddress,
        relayerKeyId: restore.relayerKeyId,
        thresholdEcdsaPublicKeyB64u,
        participantIds: [...restore.participantIds],
        runtimePolicyScope,
        routerAbEcdsaDerivationNormalSigning: restore.routerAbEcdsaDerivationNormalSigning,
        publicCapability: restore.publicCapability,
        source: restore.source,
        authority: restore.authority,
        roleLocalMaterialRef: parseEcdsaRoleLocalPersistedMaterialRef(restore.roleLocalMaterialRef),
        rpId: restore.rpId,
        credentialIdB64u: restore.credentialIdB64u,
      };
  }
}

function buildInactiveEcdsaSealedMaterial(args: {
  record: CurrentEcdsaSealedSessionRecord;
  retirement: 'expired' | 'exhausted';
  updatedAtMs: number;
}): EcdsaInactiveSealedMaterialRecord | null {
  const record = args.record;
  const publicRestore = buildEcdsaInactiveMaterialPublicRestore(
    record.ecdsaRestore,
    record.relayerUrl,
  );
  if (!publicRestore) return null;
  const base = {
    recordKind: ECDSA_INACTIVE_SEALED_MATERIAL_RECORD_KIND,
    storeKey: makeInactiveEcdsaMaterialStoreKey({
      walletId: record.walletId,
      authMethod: record.authMethod,
      restore: publicRestore,
    }),
    curve: 'ecdsa',
    walletId: record.walletId,
    relayerUrl: record.relayerUrl,
    alg: SIGNING_SESSION_SEAL_ALG,
    storageScope: SIGNING_SESSION_SEAL_STORAGE_SCOPE,
    secretKind: SIGNING_SESSION_SECRET_KIND,
    sealedSecretB64u: record.sealedSecretB64u,
    keyVersion: record.keyVersion,
    groupId: SIGNING_SESSION_SEAL_GROUP_ID,
    updatedAtMs: args.updatedAtMs,
    authorizationRetirementReason: args.retirement,
  } as const;
  if (record.authMethod === 'email_otp' && publicRestore.source === 'email_otp') {
    return {
      ...base,
      authMethod: 'email_otp',
      ecdsaRestore: publicRestore,
    };
  }
  if (record.authMethod === 'passkey' && publicRestore.source !== 'email_otp') {
    return {
      ...base,
      authMethod: 'passkey',
      ecdsaRestore: publicRestore,
    };
  }
  return null;
}

function requireInactiveEcdsaSealedMaterial(args: {
  record: CurrentEcdsaSealedSessionRecord;
  retirement: 'expired' | 'exhausted';
  updatedAtMs: number;
}): EcdsaInactiveSealedMaterialRecord {
  const inactiveMaterial = buildInactiveEcdsaSealedMaterial(args);
  if (!inactiveMaterial) {
    throw new Error(
      '[SigningSessionSealedStore] inactive ECDSA material requires exact public restore facts',
    );
  }
  return inactiveMaterial;
}

async function writeInactiveEcdsaSealedMaterial(args: {
  current: CurrentEcdsaSealedSessionRecord;
  inactive: EcdsaInactiveSealedMaterialRecord;
}): Promise<void> {
  await signingSessionSealsRepository.replaceSealedRecordAndDeleteRestoreLease({
    row: inactiveEcdsaMaterialStorageRow(args.inactive),
    staleStoreKeys: [args.current.storeKey],
    restoreLeaseKey: args.current.storeKey,
  });
}

export async function updateExactSealedSessionPolicy(
  args: UpdateExactSealedSessionPolicyInput,
): Promise<void> {
  const purpose = requireSealedRecordPurpose(args.filter, 'update policy');
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return;
  const existing = await readExactSealedSession(thresholdSessionId, purpose);
  if (!existing) return;
  await writeUpdatedSealedSessionPolicy(existing, args);
}

export async function updateExactEd25519SealedSessionPolicy(args: {
  locator: Ed25519DurableMaterialLocator;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs: number;
}): Promise<void> {
  const existing = await readExactEd25519SealedSession(args.locator);
  if (!existing) return;
  await writeUpdatedSealedSessionPolicy(existing, args);
}

async function writeUpdatedSealedSessionPolicy(
  existing: CurrentSealedSessionRecord,
  args: {
    expiresAtMs?: number;
    remainingUses?: number;
    updatedAtMs: number;
  },
): Promise<void> {
  const expiresAtMs = normalizeInteger(args.expiresAtMs ?? existing.expiresAtMs);
  const remainingUses = normalizeInteger(args.remainingUses ?? existing.remainingUses);
  const updatedAtMs = normalizeInteger(args.updatedAtMs);
  if (expiresAtMs == null || expiresAtMs <= 0) return;
  if (remainingUses == null || remainingUses < 0) return;
  if (updatedAtMs == null || updatedAtMs <= 0) return;
  const updatedRecord: CurrentSealedSessionRecord = {
    ...existing,
    expiresAtMs,
    remainingUses,
    updatedAtMs,
  };
  if (updatedRecord.curve === 'ecdsa' && expiresAtMs <= Date.now()) {
    await writeInactiveEcdsaSealedMaterial({
      current: updatedRecord,
      inactive: requireInactiveEcdsaSealedMaterial({
        record: updatedRecord,
        retirement: 'expired',
        updatedAtMs,
      }),
    });
    return;
  }
  if (updatedRecord.curve === 'ecdsa' && remainingUses === 0) {
    await writeInactiveEcdsaSealedMaterial({
      current: updatedRecord,
      inactive: requireInactiveEcdsaSealedMaterial({
        record: updatedRecord,
        retirement: 'exhausted',
        updatedAtMs,
      }),
    });
    return;
  }
  await writeExactSealedSession(updatedRecord);
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
  if (record && options.deleteResolvedIdentity) {
    await signingSessionSealsRepository.deleteRestoreLease(record.storeKey);
  }
}

export async function deleteExactEd25519SealedSession(
  locator: Ed25519DurableMaterialLocator,
  options: DeleteExactSealedSessionOptions,
): Promise<void> {
  const entries = await signingSessionSealsRepository.collectAllRawSealedRecordEntries();
  const deletePrimaryKeys: unknown[] = [];
  const restoreLeaseKeys: string[] = [];
  for (const entry of entries) {
    const classification = await classifyPersistedSealedRecord(entry);
    if (classification.kind !== 'current') {
      logSealedSessionClassification({
        operation: 'delete exact Ed25519 material',
        classification,
      });
      continue;
    }
    const record = classification.record;
    if (
      record.curve !== 'ed25519' ||
      record.authMethod !== locator.authMethod ||
      !mpcMaterialActivationRefsEqual(
        record.ed25519Restore.materialActivation,
        locator.materialActivation,
      )
    ) {
      continue;
    }
    deletePrimaryKeys.push(entry.primaryKey);
    if (options.deleteResolvedIdentity) restoreLeaseKeys.push(record.storeKey);
  }
  await signingSessionSealsRepository.deleteSealedRecords(deletePrimaryKeys);
  if (options.deleteResolvedIdentity) {
    for (const leaseKey of restoreLeaseKeys) {
      await signingSessionSealsRepository.deleteRestoreLease(leaseKey);
    }
  }
}

export async function deleteDurableSealedSessionRecord(
  command: DeleteDurableSealedSessionCommand,
): Promise<void> {
  const options: DeleteExactSealedSessionOptions = command.preserveResolvedIdentity
    ? { deleteResolvedIdentity: false }
    : { deleteResolvedIdentity: true, resolvedIdentityDeleteReason: 'durable_record_deleted' };
  if (command.durableRecord.curve === 'ed25519') {
    await deleteExactEd25519SealedSession(
      {
        kind: 'ed25519_durable_material',
        authMethod: command.durableRecord.authMethod,
        materialActivation: command.durableRecord.materialActivation,
      },
      options,
    );
    return;
  }
  const filter = exactSealedSessionFilterForIdentity(command.durableRecord);
  const existingRecord =
    await readExactSealedSessionOrNull(command.durableRecord.thresholdSessionId, filter);
  if (
    command.preserveResolvedIdentity &&
    command.durableRecord.curve === 'ecdsa' &&
    existingRecord?.curve === 'ecdsa' &&
    (command.deleteReason === 'expired' || command.deleteReason === 'exhausted')
  ) {
    await writeInactiveEcdsaSealedMaterial({
      current: existingRecord,
      inactive: requireInactiveEcdsaSealedMaterial({
        record: existingRecord,
        retirement: command.deleteReason,
        updatedAtMs: Date.now(),
      }),
    });
    return;
  }
  await deleteExactSealedSession(command.durableRecord.thresholdSessionId, filter, options);
}

async function readExactSealedSessionOrNull(
  thresholdSessionId: string,
  filter: SigningSessionSealedRecordFilter,
): Promise<CurrentSealedSessionRecord | null> {
  try {
    return await readExactSealedSession(thresholdSessionId, filter);
  } catch {
    return null;
  }
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
  const currentRecord = await readRecordByThresholdSessionId(
    thresholdSessionId,
    purpose,
    'acquire restore lease',
  );
  if (!currentRecord) return null;
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
  if (!lease?.leaseKey || !lease.ownerId || !lease.attemptId) return;
  await signingSessionSealsRepository.deleteRestoreLeaseIf({
    leaseKey: lease.leaseKey,
    shouldDelete: (rawLease) => {
      const existing = normalizeSigningSessionRestoreLease(rawLease);
      return existing?.ownerId === lease.ownerId && existing.attemptId === lease.attemptId;
    },
  });
}

export async function clearAllSealedSessions(): Promise<void> {
  await signingSessionSealsRepository.clearAll();
}
