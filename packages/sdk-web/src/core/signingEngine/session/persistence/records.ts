import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  normalizeInteger,
  normalizeOptionalNonEmptyString,
  normalizePositiveInteger,
} from '@shared/utils/normalize';
import { base64UrlDecode } from '@shared/utils/base64';
import {
  parseEmailOtpWalletAuthAuthority,
  parseWalletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  parseMpcMaterialActivationRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import type { SigningSessionSealAuthMethod } from '@shared/utils/signingSessionSeal';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { toAccountId, type AccountId, type StrictAccountId } from '@/core/types/accountIds';
import type {
  Ed25519LaneCandidate,
  LaneCandidateState,
  ThresholdEcdsaEmailOtpAuthContext,
  EmailOtpAuthUse,
  ThresholdEcdsaSessionStoreSource,
  ThresholdEd25519SessionStoreSource,
} from '../identity/laneIdentity';
import {
  buildEmailOtpAuthContext,
  emailOtpAuthContextProvider,
  emailOtpAuthContextProviderUserId,
  emailOtpAuthContextRetention,
  laneCandidateStateFromRuntimePolicy,
} from '../identity/laneIdentity';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import { THRESHOLD_ECDSA_SESSION_STORE_SOURCES } from '../identity/laneIdentity';
import type {
  ThresholdEcdsaCanonicalExportArtifact,
  ThresholdEcdsaSecp256k1KeyRef,
} from '../../interfaces/signing';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import {
  parseRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from '../../threshold/ed25519/routerAbNormalSigningState';
import {
  parseRouterAbEcdsaDerivationNormalSigningStateV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  formatSigningSessionSealKeyVersionForWire,
  parseEcdsaRoleLocalBindingDigest,
  type EcdsaRoleLocalPersistedMaterialRef,
  type EcdsaRoleLocalWorkerHandle,
  type SigningSessionSealKeyVersion,
} from '../keyMaterialBrands';
import {
  bindLiveEcdsaRoleLocalMaterial,
  buildPersistedEcdsaRoleLocalMaterial,
  clearEcdsaRoleLocalWorkerRuntimeState,
  requireMatchingLiveEcdsaRoleLocalMaterial,
  type PersistedEcdsaRoleLocalMaterial,
} from '../material/ecdsaRoleLocalMaterialResolver';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaLaneKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  nearEd25519SigningKeyIdFromString,
  parseNearEd25519SigningKeyId,
  type NearEd25519SigningKeyId,
} from '@shared/utils/registrationIntent';
import { parseSignerSlot, type SignerSlot } from '@shared/utils/signerSlot';
import {
  buildPasskeyEcdsaAuthBinding,
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  buildEvmFamilyEcdsaSessionLane,
  buildResolvedEvmFamilyEcdsaKey,
  buildVerifiedEcdsaPublicFacts,
  deriveBaseEcdsaSubjectIdFromWalletId,
  resolveThresholdEcdsaKeyIdFromRecord,
  resolveThresholdSigningRootBindingFromRecord,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
  type EvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyIdentity,
  type EvmFamilyEcdsaSessionLane,
  type ResolvedEvmFamilyEcdsaKey,
  type VerifiedEcdsaPublicFacts,
  type BuildEcdsaWalletSessionTransportAuthInput,
} from '../identity/evmFamilyEcdsaIdentity';
import { resolveRouterAbEcdsaWalletSessionAuthFromRecord } from '../warmCapabilities/routerAbEcdsaWalletSessionAuth';
import {
  type ExactEd25519SigningLaneIdentity,
} from '../identity/exactSigningLaneIdentity';
import {
  signingLaneAuthMethod,
  type SigningLaneAuthBinding,
} from '../identity/signingLaneAuthBinding';
import {
  SigningSessionIds,
  type ThresholdEcdsaSessionId,
  type ThresholdEd25519SessionId,
  type SigningGrantId,
} from '../operationState/types';
import {
  normalizeThresholdSessionKind,
  normalizeThresholdRuntimePolicyScope,
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
} from '../../threshold/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type {
  EcdsaRoleLocalAuthMethod,
  EcdsaRoleLocalPublicFacts,
} from '@/core/platform/types';
import {
  buildEcdsaRoleLocalPublicFacts,
  parseEcdsaRoleLocalAuthMethod,
} from './ecdsaRoleLocalRecords';
import {
  assertMatchingEvmFamilySigningKeySlotId,
  assertEvmFamilySigningKeySlotIdMatchesPlan,
  parseEvmFamilySigningKeySlotId,
  type EvmFamilySigningKeySlotId,
} from '@shared/signing-lanes';

export type ThresholdSessionCurve = 'ed25519' | 'ecdsa';

type CurrentSessionRetirementDiagnostic = {
  kind: 'retired_null_generation_legacy_fact';
  thresholdSessionId: string;
};

declare const operationUsableThresholdEd25519SessionRecord: unique symbol;

type ThresholdEcdsaSessionRecordCore = {
  walletId: WalletId;
  authority: WalletAuthAuthorityRef;
  materialActivation: MpcMaterialActivationRef;
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  chainTarget: ThresholdEcdsaChainTarget;
  relayerUrl: string;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion?: string;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  clientAdditiveShareHandle?: never;
  ecdsaRoleLocalAuthMethod: EcdsaRoleLocalAuthMethod;
  ecdsaRoleLocalPublicFacts: EcdsaRoleLocalPublicFacts;
  ecdsaRoleLocalReadyRecord?: never;
  participantIds: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbEcdsaDerivationNormalSigning?: RouterAbEcdsaDerivationNormalSigningStateV1;
  thresholdSessionKind: 'jwt' | 'cookie';
  thresholdSessionId: string;
  signingGrantId: string;
  walletSessionJwt?: string;
  signingSessionSealKeyVersion?: string;
  signingSessionSealShamirPrimeB64u?: string;
  expiresAtMs: number;
  remainingUses: number;
  thresholdEcdsaPublicKeyB64u?: string;
  verifiedPublicFacts?: VerifiedEcdsaPublicFacts;
  ethereumAddress: string;
  relayerVerifyingShareB64u?: string;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  updatedAtMs: number;
  source: ThresholdEcdsaSessionStoreSource;
};

export type RawThresholdEcdsaSessionRecord = Record<string, unknown>;

type NormalizedThresholdEcdsaSessionRecordShared = Omit<
  ThresholdEcdsaSessionRecordCore,
  | 'clientAdditiveShareHandle'
  | 'ecdsaRoleLocalAuthMethod'
  | 'ecdsaRoleLocalReadyRecord'
  | 'emailOtpAuthContext'
  | 'source'
  | 'verifiedPublicFacts'
  | 'thresholdEcdsaPublicKeyB64u'
> & {
  verifiedPublicFacts?: VerifiedEcdsaPublicFacts;
  thresholdEcdsaPublicKeyB64u?: string;
};

export type ReadyPasskeyEcdsaSessionRecord = NormalizedThresholdEcdsaSessionRecordShared & {
  source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  ecdsaRoleLocalAuthMethod: Extract<EcdsaRoleLocalAuthMethod, { kind: 'passkey' }>;
  ecdsaRoleLocalReadyRecord?: never;
  clientAdditiveShareHandle?: never;
  emailOtpAuthContext?: never;
};

type EmailOtpEcdsaSessionRecordShared = Omit<
  NormalizedThresholdEcdsaSessionRecordShared,
  'thresholdSessionKind' | 'walletSessionJwt'
> & {
  source: 'email_otp';
  thresholdSessionKind: 'jwt';
  walletSessionJwt: string;
  ecdsaRoleLocalAuthMethod: Extract<EcdsaRoleLocalAuthMethod, { kind: 'email_otp' }>;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
};

export type EmailOtpEcdsaSessionRecord = EmailOtpEcdsaSessionRecordShared & {
  ecdsaRoleLocalReadyRecord?: never;
  clientAdditiveShareHandle?: never;
};

export type NormalizedThresholdEcdsaSessionRecord =
  | ReadyPasskeyEcdsaSessionRecord
  | EmailOtpEcdsaSessionRecord;

export type ThresholdEcdsaSessionRecord = NormalizedThresholdEcdsaSessionRecord & {
  purpose: 'transaction_signing';
};

export type ThresholdEcdsaSessionCommitResult =
  | {
      kind: 'committed_current';
      current: ThresholdEcdsaSessionRecord;
      retired: readonly ThresholdEcdsaSessionRecord[];
      diagnostics: readonly CurrentSessionRetirementDiagnostic[];
    }
  | {
      kind: 'same_generation_distinct_session';
      incoming: ThresholdEcdsaSessionRecord;
      existing: ThresholdEcdsaSessionRecord;
    }
  | {
      kind: 'stale_commit_ignored';
      incoming: ThresholdEcdsaSessionRecord;
      current: ThresholdEcdsaSessionRecord;
    };

export function thresholdEcdsaEmailOtpAuthContext(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): ThresholdEcdsaEmailOtpAuthContext | null {
  return record?.source === 'email_otp' ? record.emailOtpAuthContext : null;
}

export type ThresholdEcdsaRuntimeLaneKey = string & {
  readonly __brand: 'ThresholdEcdsaRuntimeLaneKey';
};

// Raw persistence boundary shape. Core code uses ThresholdEd25519SessionRecord.
export type ThresholdEd25519SessionRow = {
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  rpId: string;
  passkeyCredentialIdB64u?: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  signingRootId?: string;
  signingRootVersion?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  signerSlot: number;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  thresholdSessionKind: 'jwt' | 'cookie';
  thresholdSessionId: string;
  signingGrantId?: string;
  walletSessionJwt?: string;
  expiresAtMs: number;
  remainingUses: number;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  updatedAtMs: number;
  source: ThresholdEd25519SessionStoreSource;
};

export type ThresholdEd25519SessionRecord = ThresholdEd25519SessionRow;

export type OperationUsableThresholdEd25519SessionRecord = ThresholdEd25519SessionRecord & {
  signingGrantId: string;
  walletSessionJwt: string;
  readonly [operationUsableThresholdEd25519SessionRecord]: true;
};

export type ThresholdEd25519SessionCommitResult =
  | {
      kind: 'committed_current';
      current: OperationUsableThresholdEd25519SessionRecord;
      retired: readonly ThresholdEd25519SessionRecord[];
      diagnostics: readonly CurrentSessionRetirementDiagnostic[];
    }
  | {
      kind: 'same_generation_distinct_session';
      incoming: OperationUsableThresholdEd25519SessionRecord;
      existing: OperationUsableThresholdEd25519SessionRecord;
    }
  | {
      kind: 'stale_commit_ignored';
      incoming: OperationUsableThresholdEd25519SessionRecord;
      current: OperationUsableThresholdEd25519SessionRecord;
    };

export type ThresholdSessionRecordByCurve = {
  ed25519: ThresholdEd25519SessionRecord;
  ecdsa: ThresholdEcdsaSessionRecord;
};

export type WalletSessionJwtAuthSource = 'ecdsa' | 'ed25519' | 'none';

export type ThresholdSessionSealTransportAuthMaterial =
  | {
      curve: 'ed25519';
      walletId?: string;
      relayerUrl: string;
      signingGrantId?: string;
      walletSessionJwt?: string;
      walletSessionJwtSource: WalletSessionJwtAuthSource;
      signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
      shamirPrimeB64u?: string;
    }
  | {
      curve: 'ecdsa';
      walletId?: string;
      chainTarget: ThresholdEcdsaChainTarget;
      relayerUrl: string;
      signingGrantId?: string;
      walletSessionJwt?: string;
      walletSessionJwtSource: WalletSessionJwtAuthSource;
      signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
      shamirPrimeB64u?: string;
    };

export type ThresholdEcdsaSessionStoreDeps = {
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>;
  exportArtifactsByLane?: Map<string, ThresholdEcdsaCanonicalExportArtifact>;
  now?: () => number;
};

export type ThresholdEcdsaSessionRecordReadModel = {
  record: ThresholdEcdsaSessionRecord;
  key: EvmFamilyEcdsaKeyIdentity;
  resolvedKey?: ResolvedEvmFamilyEcdsaKey;
  lane: EvmFamilyEcdsaSessionLane;
};

export function thresholdEcdsaRecordRpId(record: ThresholdEcdsaSessionRecord): string {
  if (record.ecdsaRoleLocalAuthMethod.kind !== 'passkey') {
    throw new Error(
      '[SigningEngine] threshold ECDSA session record does not carry passkey RP scope',
    );
  }
  return record.ecdsaRoleLocalAuthMethod.rpId;
}

function thresholdEcdsaAuthMethodForRecord(
  record: ThresholdEcdsaSessionRecord,
): SigningSessionSealAuthMethod {
  const source = record.source;
  switch (source) {
    case SIGNER_AUTH_METHODS.emailOtp:
      return SIGNER_AUTH_METHODS.emailOtp;
    case 'login':
    case 'registration':
    case 'manual-bootstrap':
      return SIGNER_AUTH_METHODS.passkey;
    default:
      source satisfies never;
      throw new Error(
        `[SigningEngine] unsupported threshold ECDSA session source: ${String(source)}`,
      );
  }
}

function thresholdEcdsaResolvedKeyFromRecord(
  record: ThresholdEcdsaSessionRecord,
): ResolvedEvmFamilyEcdsaKey | null {
  if (thresholdEcdsaAuthMethodForRecord(record) !== 'passkey') return null;
  if (!record.verifiedPublicFacts) return null;
  const authMethod = record.ecdsaRoleLocalAuthMethod;
  if (authMethod.kind !== 'passkey') return null;
  try {
    return buildResolvedEvmFamilyEcdsaKey({
      walletId: record.walletId,
      publicFacts: record.verifiedPublicFacts,
      authBinding: buildPasskeyEcdsaAuthBinding({
        rpId: authMethod.rpId,
        credentialIdB64u: authMethod.credentialIdB64u,
      }),
    });
  } catch {
    return null;
  }
}

function thresholdEcdsaWalletSessionAuthInputFromRecord(
  record: ThresholdEcdsaSessionRecord,
): BuildEcdsaWalletSessionTransportAuthInput {
  const authority = resolveRouterAbEcdsaWalletSessionAuthFromRecord(record);
  if (authority.kind !== 'ready') {
    throw new Error(
      `[threshold-ecdsa] persisted session record is missing Wallet Session authority: ${authority.reason}`,
    );
  }
  return {
    kind: 'wallet_session_jwt',
    walletSessionJwt: authority.walletSessionJwt,
  };
}

export function thresholdEcdsaSessionRecordReadModel(
  record: ThresholdEcdsaSessionRecord,
): ThresholdEcdsaSessionRecordReadModel {
  const key = buildEvmFamilyEcdsaKeyIdentityFromRecord({
    record,
  });
  const resolvedKey = thresholdEcdsaResolvedKeyFromRecord(record);
  const lane = buildEvmFamilyEcdsaSessionLane({
    key,
    materialActivation: record.materialActivation,
    chainTarget: record.chainTarget,
    authMethod: thresholdEcdsaAuthMethodForRecord(record),
    source: record.source,
    thresholdSessionId: record.thresholdSessionId,
    signingGrantId: record.signingGrantId,
    walletSessionAuth: thresholdEcdsaWalletSessionAuthInputFromRecord(record),
    remainingUses: record.remainingUses,
    expiresAtMs: record.expiresAtMs,
  });
  return {
    record,
    key,
    ...(resolvedKey ? { resolvedKey } : {}),
    lane,
  };
}

function evmFamilyEcdsaSharedContextKey(
  key: EvmFamilyEcdsaKeyIdentity,
  materialActivation: MpcMaterialActivationRef,
): string {
  return ecdsaIndexKey([
    key.walletId,
    deriveBaseEcdsaSubjectIdFromWalletId(key.walletId),
    materialActivation.activationId,
    materialActivation.capability,
    key.keyScope,
    key.signingRootId,
    key.signingRootVersion,
  ]);
}

function evmFamilyEcdsaIdentityValue(key: EvmFamilyEcdsaKeyIdentity): string {
  return ecdsaIndexKey([
    key.ecdsaThresholdKeyId,
    key.participantIds.map((id) => String(Number(id))).join(','),
    key.thresholdOwnerAddress,
  ]);
}

function assertUniqueEvmFamilyEcdsaIdentityForStore(args: {
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>;
  incomingLaneKey: string;
  incomingRecord: ThresholdEcdsaSessionRecord;
}): void {
  const incoming = thresholdEcdsaSessionRecordReadModel(args.incomingRecord).key;
  const incomingContextKey = evmFamilyEcdsaSharedContextKey(
    incoming,
    args.incomingRecord.materialActivation,
  );
  const incomingIdentityValue = evmFamilyEcdsaIdentityValue(incoming);

  for (const [storedLaneKey, storedRecord] of args.recordsByLane.entries()) {
    if (storedLaneKey === args.incomingLaneKey) continue;
    let stored: EvmFamilyEcdsaKeyIdentity;
    try {
      stored = thresholdEcdsaSessionRecordReadModel(storedRecord).key;
    } catch {
      continue;
    }
    if (evmFamilyEcdsaSharedContextKey(stored, storedRecord.materialActivation) !== incomingContextKey)
      continue;
    if (evmFamilyEcdsaIdentityValue(stored) === incomingIdentityValue) continue;
    throw new Error(
      '[SigningEngine] EVM-family ECDSA key identity already exists for wallet/key/signing root',
    );
  }
}

function nullableRecordInteger(value: unknown): number | null {
  const normalized = normalizeInteger(value);
  return normalized == null ? null : normalized;
}

function normalizeOptionalRuntimeChainTarget(value: unknown): ThresholdEcdsaChainTarget | null {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!obj) return null;
  try {
    return thresholdEcdsaChainTargetFromRequest({
      kind: obj.kind,
      chain: obj.chain,
      namespace: obj.namespace,
      chainId: obj.chainId,
      networkSlug: obj.networkSlug,
    });
  } catch {
    return null;
  }
}

export type ThresholdSessionStoreInvalidRecordReason =
  | 'invalid_json'
  | 'invalid_version'
  | 'invalid_shape';

export class ThresholdSessionStoreInvalidRecordError extends Error {
  readonly code = 'invalid_threshold_session_record';
  readonly curve: ThresholdSessionCurve;
  readonly recordKey: string;
  readonly reason: ThresholdSessionStoreInvalidRecordReason;
  readonly cause?: unknown;

  constructor(args: {
    curve: ThresholdSessionCurve;
    recordKey: string;
    reason: ThresholdSessionStoreInvalidRecordReason;
    cause?: unknown;
  }) {
    super(
      `[threshold-session-store] invalid ${args.curve} session record ${args.recordKey}: ${args.reason}`,
    );
    this.name = 'ThresholdSessionStoreInvalidRecordError';
    this.curve = args.curve;
    this.recordKey = args.recordKey;
    this.reason = args.reason;
    if ('cause' in args) {
      this.cause = args.cause;
    }
  }
}

const inMemoryEcdsaRecordsByLane = new Map<string, ThresholdEcdsaSessionRecord>();
const inMemoryEd25519RecordsByAccount = new Map<string, ThresholdEd25519SessionRecord>();
const inMemoryEd25519AccountBySessionId = new Map<string, string>();
const inMemoryEd25519RecordsByWallet = new Map<string, ThresholdEd25519SessionRecord>();
const inMemoryEd25519WalletBySessionId = new Map<string, string>();
const inMemoryEd25519RecordsByLane = new Map<string, ThresholdEd25519SessionRecord>();
const inMemoryEd25519LaneBySessionId = new Map<string, string>();

type ThresholdEcdsaRuntimeRecordIndex = {
  laneKeysByWallet: Map<string, Set<string>>;
  laneKeysByWalletTarget: Map<string, Set<string>>;
  laneKeysByWalletTargetSource: Map<string, Set<string>>;
  laneKeysByThresholdSessionId: Map<string, Set<string>>;
};

const inMemoryEcdsaRecordIndex: ThresholdEcdsaRuntimeRecordIndex =
  createThresholdEcdsaRuntimeRecordIndex();
const ecdsaRecordIndexesByMap = new WeakMap<
  Map<string, ThresholdEcdsaSessionRecord>,
  ThresholdEcdsaRuntimeRecordIndex
>();

function createThresholdEcdsaRuntimeRecordIndex(): ThresholdEcdsaRuntimeRecordIndex {
  return {
    laneKeysByWallet: new Map(),
    laneKeysByWalletTarget: new Map(),
    laneKeysByWalletTargetSource: new Map(),
    laneKeysByThresholdSessionId: new Map(),
  };
}

function clearThresholdEcdsaRuntimeRecordIndex(index: ThresholdEcdsaRuntimeRecordIndex): void {
  index.laneKeysByWallet.clear();
  index.laneKeysByWalletTarget.clear();
  index.laneKeysByWalletTargetSource.clear();
  index.laneKeysByThresholdSessionId.clear();
}

function getThresholdEcdsaRuntimeRecordIndex(
  deps: ThresholdEcdsaSessionStoreDeps,
): ThresholdEcdsaRuntimeRecordIndex {
  const existing = ecdsaRecordIndexesByMap.get(deps.recordsByLane);
  if (existing) return existing;
  const index = createThresholdEcdsaRuntimeRecordIndex();
  for (const [storedLaneKey, record] of deps.recordsByLane.entries()) {
    let canonicalRecord: ThresholdEcdsaSessionRecord;
    try {
      canonicalRecord = normalizeThresholdEcdsaSessionRecord(record, 'transaction_signing');
    } catch {
      deps.recordsByLane.delete(storedLaneKey);
      deps.exportArtifactsByLane?.delete(storedLaneKey);
      continue;
    }
    const canonicalLaneKey = getThresholdEcdsaSessionLaneKeyForRecord(canonicalRecord);
    if (!canonicalLaneKey || canonicalLaneKey !== storedLaneKey) {
      deps.recordsByLane.delete(storedLaneKey);
      deps.exportArtifactsByLane?.delete(storedLaneKey);
      continue;
    }
    if (canonicalRecord !== record) {
      deps.recordsByLane.set(storedLaneKey, canonicalRecord);
    }
    indexThresholdEcdsaRecord(index, canonicalLaneKey, canonicalRecord);
  }
  ecdsaRecordIndexesByMap.set(deps.recordsByLane, index);
  return index;
}

function ecdsaIndexPart(value: unknown): string {
  return encodeURIComponent(String(value ?? '').trim());
}

function ecdsaIndexKey(parts: readonly unknown[]): string {
  return parts.map(ecdsaIndexPart).join('|');
}

function addIndexedLaneKey(
  indexMap: Map<string, Set<string>>,
  indexKey: string | null,
  laneKey: string,
): void {
  if (!indexKey) return;
  const existing = indexMap.get(indexKey);
  if (existing) {
    existing.add(laneKey);
    return;
  }
  indexMap.set(indexKey, new Set([laneKey]));
}

function deleteIndexedLaneKey(
  indexMap: Map<string, Set<string>>,
  indexKey: string | null,
  laneKey: string,
): void {
  if (!indexKey) return;
  const existing = indexMap.get(indexKey);
  if (!existing) return;
  existing.delete(laneKey);
  if (!existing.size) indexMap.delete(indexKey);
}

function thresholdEcdsaWalletIndexKey(record: ThresholdEcdsaSessionRecord): string {
  return ecdsaIndexKey([String(record.walletId || '').trim()]);
}

function thresholdEcdsaThresholdSessionIndexKey(
  record: ThresholdEcdsaSessionRecord,
): string | null {
  const thresholdSessionId = normalizeOptionalNonEmptyString(record.thresholdSessionId);
  return thresholdSessionId ? ecdsaIndexKey([thresholdSessionId]) : null;
}

function thresholdEcdsaWalletTargetIndexKey(record: ThresholdEcdsaSessionRecord): string | null {
  return ecdsaIndexKey([record.walletId, thresholdEcdsaChainTargetKey(record.chainTarget)]);
}

function thresholdEcdsaWalletTargetSourceIndexKey(
  record: ThresholdEcdsaSessionRecord,
): string | null {
  return ecdsaIndexKey([
    record.walletId,
    thresholdEcdsaChainTargetKey(record.chainTarget),
    record.source,
  ]);
}

function indexThresholdEcdsaRecord(
  index: ThresholdEcdsaRuntimeRecordIndex,
  laneKey: string,
  record: ThresholdEcdsaSessionRecord,
): void {
  addIndexedLaneKey(index.laneKeysByWallet, thresholdEcdsaWalletIndexKey(record), laneKey);
  addIndexedLaneKey(
    index.laneKeysByThresholdSessionId,
    thresholdEcdsaThresholdSessionIndexKey(record),
    laneKey,
  );
  addIndexedLaneKey(
    index.laneKeysByWalletTarget,
    thresholdEcdsaWalletTargetIndexKey(record),
    laneKey,
  );
  addIndexedLaneKey(
    index.laneKeysByWalletTargetSource,
    thresholdEcdsaWalletTargetSourceIndexKey(record),
    laneKey,
  );
}

function deindexThresholdEcdsaRecord(
  index: ThresholdEcdsaRuntimeRecordIndex,
  laneKey: string,
  record: ThresholdEcdsaSessionRecord,
): void {
  deleteIndexedLaneKey(index.laneKeysByWallet, thresholdEcdsaWalletIndexKey(record), laneKey);
  deleteIndexedLaneKey(
    index.laneKeysByThresholdSessionId,
    thresholdEcdsaThresholdSessionIndexKey(record),
    laneKey,
  );
  deleteIndexedLaneKey(
    index.laneKeysByWalletTarget,
    thresholdEcdsaWalletTargetIndexKey(record),
    laneKey,
  );
  deleteIndexedLaneKey(
    index.laneKeysByWalletTargetSource,
    thresholdEcdsaWalletTargetSourceIndexKey(record),
    laneKey,
  );
}

function getIndexedThresholdEcdsaRecord(
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>,
  laneKey: string,
): ThresholdEcdsaSessionRecord | null {
  return recordsByLane.get(laneKey) || null;
}

function indexedThresholdEcdsaRecords(args: {
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>;
  laneKeys: Iterable<string> | undefined;
}): ThresholdEcdsaSessionRecord[] {
  if (!args.laneKeys) return [];
  const records: ThresholdEcdsaSessionRecord[] = [];
  const seen = new Set<string>();
  for (const laneKey of args.laneKeys) {
    if (!laneKey || seen.has(laneKey)) continue;
    seen.add(laneKey);
    const record = getIndexedThresholdEcdsaRecord(args.recordsByLane, laneKey);
    if (record) records.push(record);
  }
  return records;
}

function listAllThresholdEcdsaRecords(
  deps: ThresholdEcdsaSessionStoreDeps,
): ThresholdEcdsaSessionRecord[] {
  const recordsByCanonicalLane = new Map<string, ThresholdEcdsaSessionRecord>();
  for (const record of [...deps.recordsByLane.values(), ...inMemoryEcdsaRecordsByLane.values()]) {
    recordsByCanonicalLane.set(getThresholdEcdsaSessionLaneKeyForRecord(record), record);
  }
  return Array.from(recordsByCanonicalLane.values());
}

function normalizeThresholdEcdsaCanonicalExportArtifact(
  value: unknown,
): ThresholdEcdsaCanonicalExportArtifact | null {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!obj) return null;
  const artifactKind = String(obj.artifactKind || '').trim();
  const chainTargetRaw =
    obj.chainTarget && typeof obj.chainTarget === 'object' && !Array.isArray(obj.chainTarget)
      ? (obj.chainTarget as Record<string, unknown>)
      : null;
  const chainTarget = (() => {
    if (!chainTargetRaw) return null;
    try {
      return thresholdEcdsaChainTargetFromRequest(chainTargetRaw);
    } catch {
      return null;
    }
  })();
  const signingRootId = normalizeOptionalNonEmptyString(obj.signingRootId);
  const signingRootVersion = normalizeOptionalNonEmptyString(obj.signingRootVersion);
  const publicKeyHex = String(obj.publicKeyHex || '').trim();
  const privateKeyHex = String(obj.privateKeyHex || '').trim();
  const ethereumAddress = String(obj.ethereumAddress || '').trim();
  if (
    artifactKind !== 'ecdsa-derivation-secp256k1-export' ||
    !chainTarget ||
    !signingRootId ||
    !publicKeyHex ||
    !privateKeyHex ||
    !ethereumAddress
  ) {
    return null;
  }
  return {
    artifactKind: 'ecdsa-derivation-secp256k1-export',
    chainTarget,
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
    publicKeyHex,
    privateKeyHex,
    ethereumAddress,
  };
}

function normalizeStoredRuntimePolicyScope(
  obj: Record<string, unknown>,
  jwt?: string,
): ThresholdRuntimePolicyScope | undefined {
  if (Object.prototype.hasOwnProperty.call(obj, 'runtimeSnapshotScope')) {
    throw new Error('Invalid threshold session record: stale runtimeSnapshotScope');
  }
  if (Object.prototype.hasOwnProperty.call(obj, 'runtimePolicyScope')) {
    const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(obj.runtimePolicyScope);
    if (!runtimePolicyScope) {
      throw new Error('Invalid threshold session record: stale runtimePolicyScope');
    }
    return runtimePolicyScope;
  }
  return parseThresholdRuntimePolicyScopeFromJwt(jwt);
}

function getSigningRootBindingFromRuntimePolicyScope(
  runtimePolicyScope: ThresholdRuntimePolicyScope | undefined,
): { signingRootId: string; signingRootVersion?: string } | null {
  if (!runtimePolicyScope) return null;
  try {
    const scope = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
    const signingRootId = normalizeOptionalNonEmptyString(scope.signingRootId);
    const signingRootVersion = normalizeOptionalNonEmptyString(scope.signingRootVersion);
    if (!signingRootId) return null;
    return {
      signingRootId,
      ...(signingRootVersion ? { signingRootVersion } : {}),
    };
  } catch {
    return null;
  }
}

function normalizeStoredSigningRootBinding(
  obj: Record<string, unknown>,
  runtimePolicyScope: ThresholdRuntimePolicyScope | undefined,
): { signingRootId: string; signingRootVersion?: string } {
  const explicitSigningRootId = normalizeOptionalNonEmptyString(obj.signingRootId);
  const explicitSigningRootVersion = normalizeOptionalNonEmptyString(obj.signingRootVersion);
  const scopeBinding = getSigningRootBindingFromRuntimePolicyScope(runtimePolicyScope);
  if (
    explicitSigningRootId &&
    scopeBinding?.signingRootId &&
    explicitSigningRootId !== scopeBinding.signingRootId
  ) {
    throw new Error('Invalid threshold ECDSA canonical session record: signingRootId mismatch');
  }
  if (
    explicitSigningRootVersion &&
    scopeBinding?.signingRootVersion &&
    explicitSigningRootVersion !== scopeBinding.signingRootVersion
  ) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: signingRootVersion mismatch',
    );
  }

  const signingRootId = explicitSigningRootId || scopeBinding?.signingRootId || '';
  const signingRootVersion = explicitSigningRootVersion || scopeBinding?.signingRootVersion || '';
  if (!signingRootId) {
    throw new Error('Invalid threshold ECDSA canonical session record: missing signingRootId');
  }
  return {
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
  };
}

function normalizeEthereumAddress20B64u(value: string): string {
  const bytes = base64UrlDecode(value);
  if (bytes.length !== 20) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: Router A/B ethereum address must decode to 20 bytes',
    );
  }
  return `0x${Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`;
}

function normalizeStoredRouterAbEcdsaDerivationNormalSigningState(args: {
  raw: unknown;
  walletId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string | undefined;
  clientVerifyingShareB64u: string;
  thresholdEcdsaPublicKeyB64u: string | null | undefined;
  ethereumAddress: string;
  relayerVerifyingShareB64u: string | null | undefined;
}): RouterAbEcdsaDerivationNormalSigningStateV1 | undefined {
  const parsed = parseRouterAbEcdsaDerivationNormalSigningStateV1(args.raw);
  if (!parsed) return undefined;
  const publicIdentity = parsed.scope.public_identity;
  const expectedSigningRootVersion = args.signingRootVersion || 'default';
  const checks: Array<[string, string, string]> = [
    ['wallet_id', parsed.scope.wallet_id, args.walletId],
    ['ecdsa_threshold_key_id', parsed.scope.ecdsa_threshold_key_id, args.ecdsaThresholdKeyId],
    ['signing_root_id', parsed.scope.signing_root_id, args.signingRootId],
    ['signing_root_version', parsed.scope.signing_root_version, expectedSigningRootVersion],
    [
      'derivation_client_share_public_key33_b64u',
      publicIdentity.derivation_client_share_public_key33_b64u,
      args.clientVerifyingShareB64u,
    ],
    [
      'ethereum_address20_b64u',
      normalizeEthereumAddress20B64u(publicIdentity.ethereum_address20_b64u),
      args.ethereumAddress.toLowerCase(),
    ],
  ];
  if (args.thresholdEcdsaPublicKeyB64u) {
    checks.push([
      'threshold_public_key33_b64u',
      publicIdentity.threshold_public_key33_b64u,
      args.thresholdEcdsaPublicKeyB64u,
    ]);
  }
  if (args.relayerVerifyingShareB64u) {
    checks.push([
      'server_public_key33_b64u',
      publicIdentity.server_public_key33_b64u,
      args.relayerVerifyingShareB64u,
    ]);
  }
  for (const [field, actual, expected] of checks) {
    if (actual !== expected) {
      throw new Error(
        `Invalid threshold ECDSA canonical session record: Router A/B ECDSA derivation ${field} mismatch`,
      );
    }
  }
  return parsed;
}

function normalizeStoredVerifiedPublicFacts(args: {
  rawVerifiedPublicFacts: unknown;
}): VerifiedEcdsaPublicFacts | null {
  const raw =
    args.rawVerifiedPublicFacts &&
    typeof args.rawVerifiedPublicFacts === 'object' &&
    !Array.isArray(args.rawVerifiedPublicFacts)
      ? (args.rawVerifiedPublicFacts as Record<string, unknown>)
      : null;
  if (!raw) return null;
  const keyHandle = normalizeOptionalNonEmptyString(raw.keyHandle);
  const publicKeyB64u = normalizeOptionalNonEmptyString(raw.publicKeyB64u);
  const thresholdOwnerAddress = normalizeOptionalNonEmptyString(raw.thresholdOwnerAddress);
  const participantIds = raw.participantIds;

  if (!keyHandle || !publicKeyB64u || !thresholdOwnerAddress || !Array.isArray(participantIds)) {
    return null;
  }
  try {
    const verifiedPublicFacts = buildVerifiedEcdsaPublicFacts({
      keyHandle: toEvmFamilyEcdsaKeyHandle(keyHandle),
      publicKeyB64u,
      participantIds,
      thresholdOwnerAddress,
    });
    if (String(verifiedPublicFacts.keyHandle) !== keyHandle) return null;
    return verifiedPublicFacts;
  } catch {
    return null;
  }
}

function ecdsaParticipantIdsKey(participantIds: readonly number[]): string {
  const parts: string[] = [];
  for (const participantId of participantIds) {
    parts.push(String(Number(participantId)));
  }
  return parts.join(',');
}

function assertEcdsaRoleLocalPublicFactMatches(args: {
  field: string;
  actual: string;
  expected: string;
}): void {
  if (args.actual !== args.expected) {
    throw new Error(
      `Invalid threshold ECDSA canonical session record: role-local publicFacts ${args.field} mismatch`,
    );
  }
}

function assertEcdsaRoleLocalPublicFactsMatchSessionRecord(args: {
  publicFacts: EcdsaRoleLocalPublicFacts;
  walletId: WalletId;
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion?: string;
  clientVerifyingShareB64u: string;
  participantIds: readonly number[];
  thresholdEcdsaPublicKeyB64u?: string;
  ethereumAddress: string;
  relayerVerifyingShareB64u?: string;
}): void {
  const facts = args.publicFacts;
  const expectedSigningRootVersion = args.signingRootVersion || 'default';
  assertMatchingEvmFamilySigningKeySlotId({
    expected: args.evmFamilySigningKeySlotId,
    actual: facts.evmFamilySigningKeySlotId,
    actualLabel: 'role-local publicFacts evmFamilySigningKeySlotId',
    message:
      'Invalid threshold ECDSA canonical session record: role-local publicFacts evmFamilySigningKeySlotId mismatch',
  });
  const checks: Array<[string, string, string]> = [
    ['walletId', String(facts.walletId), String(args.walletId)],
    ['keyHandle', String(facts.keyHandle), args.keyHandle],
    ['ecdsaThresholdKeyId', String(facts.ecdsaThresholdKeyId), args.ecdsaThresholdKeyId],
    ['signingRootId', String(facts.signingRootId), args.signingRootId],
    ['signingRootVersion', String(facts.signingRootVersion), expectedSigningRootVersion],
    [
      'derivationClientSharePublicKey33B64u',
      String(facts.derivationClientSharePublicKey33B64u),
      args.clientVerifyingShareB64u,
    ],
    [
      'participantIds',
      ecdsaParticipantIdsKey(facts.participantIds),
      ecdsaParticipantIdsKey(args.participantIds),
    ],
    [
      'ethereumAddress',
      String(facts.ethereumAddress).toLowerCase(),
      args.ethereumAddress.toLowerCase(),
    ],
  ];
  if (args.thresholdEcdsaPublicKeyB64u) {
    checks.push([
      'groupPublicKey33B64u',
      String(facts.groupPublicKey33B64u),
      args.thresholdEcdsaPublicKeyB64u,
    ]);
  }
  if (args.relayerVerifyingShareB64u) {
    checks.push([
      'relayerPublicKey33B64u',
      String(facts.relayerPublicKey33B64u),
      args.relayerVerifyingShareB64u,
    ]);
  }
  for (const [field, actual, expected] of checks) {
    assertEcdsaRoleLocalPublicFactMatches({ field, actual, expected });
  }
  if (!thresholdEcdsaChainTargetsEqual(facts.chainTarget, args.chainTarget)) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: role-local publicFacts chainTarget mismatch',
    );
  }
}

function assertEcdsaRoleLocalPublicCapabilityMatchesFacts(args: {
  facts: EcdsaRoleLocalPublicFacts;
  walletId: WalletId;
}): void {
  const facts = args.facts;
  const capability = facts.publicCapability;
  const publicIdentity = capability.public_identity;
  const checks: Array<[string, string, string]> = [
    ['publicCapability.client_id', capability.client_id, String(args.walletId)],
    [
      'publicCapability.context.application_binding_digest_b64u',
      capability.context.application_binding_digest_b64u,
      facts.applicationBindingDigestB64u,
    ],
    [
      'publicCapability.public_identity.context_binding_b64u',
      publicIdentity.context_binding_b64u,
      facts.contextBinding32B64u,
    ],
    [
      'publicCapability.public_identity.derivation_client_share_public_key33_b64u',
      publicIdentity.derivation_client_share_public_key33_b64u,
      facts.derivationClientSharePublicKey33B64u,
    ],
    [
      'publicCapability.public_identity.server_public_key33_b64u',
      publicIdentity.server_public_key33_b64u,
      facts.relayerPublicKey33B64u,
    ],
    [
      'publicCapability.public_identity.threshold_public_key33_b64u',
      publicIdentity.threshold_public_key33_b64u,
      facts.groupPublicKey33B64u,
    ],
    [
      'publicCapability.public_identity.ethereum_address20_b64u',
      normalizeEthereumAddress20B64u(publicIdentity.ethereum_address20_b64u),
      facts.ethereumAddress.toLowerCase(),
    ],
  ];
  for (const [field, actual, expected] of checks) {
    assertEcdsaRoleLocalPublicFactMatches({ field, actual, expected });
  }
}

function assertEcdsaRoleLocalPublicFactsMatchNormalSigningState(args: {
  publicFacts: EcdsaRoleLocalPublicFacts;
  normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
}): void {
  const scope = args.normalSigning.scope;
  const facts = args.publicFacts;
  const publicCapability = facts.publicCapability;
  const publicIdentity = scope.public_identity;
  const checks: Array<[string, string, string]> = [
    ['normalSigning.activation_epoch', scope.activation_epoch, publicCapability.activation_epoch],
    [
      'normalSigning.context.application_binding_digest_b64u',
      scope.context.application_binding_digest_b64u,
      facts.applicationBindingDigestB64u,
    ],
    [
      'normalSigning.public_identity.context_binding_b64u',
      publicIdentity.context_binding_b64u,
      facts.contextBinding32B64u,
    ],
    [
      'normalSigning.public_identity.derivation_client_share_public_key33_b64u',
      publicIdentity.derivation_client_share_public_key33_b64u,
      facts.derivationClientSharePublicKey33B64u,
    ],
    [
      'normalSigning.public_identity.server_public_key33_b64u',
      publicIdentity.server_public_key33_b64u,
      facts.relayerPublicKey33B64u,
    ],
    [
      'normalSigning.public_identity.threshold_public_key33_b64u',
      publicIdentity.threshold_public_key33_b64u,
      facts.groupPublicKey33B64u,
    ],
    [
      'normalSigning.public_identity.ethereum_address20_b64u',
      normalizeEthereumAddress20B64u(publicIdentity.ethereum_address20_b64u),
      facts.ethereumAddress.toLowerCase(),
    ],
    [
      'normalSigning.public_identity.client_share_retry_counter',
      String(publicIdentity.client_share_retry_counter),
      String(publicCapability.public_identity.client_share_retry_counter),
    ],
    [
      'normalSigning.public_identity.server_share_retry_counter',
      String(publicIdentity.server_share_retry_counter),
      String(publicCapability.public_identity.server_share_retry_counter),
    ],
    [
      'normalSigning.signing_worker.server_id',
      scope.signing_worker.server_id,
      publicCapability.signer_set.selected_server.server_id,
    ],
    [
      'normalSigning.signing_worker.key_epoch',
      scope.signing_worker.key_epoch,
      publicCapability.signer_set.selected_server.key_epoch,
    ],
    [
      'normalSigning.signing_worker.recipient_encryption_key',
      scope.signing_worker.recipient_encryption_key,
      publicCapability.signer_set.selected_server.recipient_encryption_key,
    ],
  ];
  for (const [field, actual, expected] of checks) {
    assertEcdsaRoleLocalPublicFactMatches({ field, actual, expected });
  }
}

function normalizeThresholdEcdsaSessionRecord(
  value: unknown,
  purpose: 'transaction_signing',
): ThresholdEcdsaSessionRecord {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
  if (obj.purpose !== purpose) {
    throw new Error(`Invalid threshold ECDSA session record: expected ${purpose} purpose`);
  }
  const walletId = toWalletId(String(obj.walletId || '').trim());
  const authority = parseWalletAuthAuthorityRef(obj.authority);
  if (!authority || authority.walletId !== walletId) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: authority does not match wallet',
    );
  }
  const materialActivationResult = parseMpcMaterialActivationRef(obj.materialActivation);
  if (!materialActivationResult.ok) {
    throw new Error(
      `Invalid threshold ECDSA canonical session record: ${materialActivationResult.error.message}`,
    );
  }
  const materialActivation = materialActivationResult.value;
  if (obj.authMetadata !== undefined && obj.authMetadata !== null) {
    throw new Error('Invalid threshold ECDSA canonical session record: deleted authMetadata');
  }
  const evmFamilySigningKeySlotIdResult = parseEvmFamilySigningKeySlotId(
    obj.evmFamilySigningKeySlotId,
  );
  let evmFamilySigningKeySlotId = evmFamilySigningKeySlotIdResult.ok
    ? evmFamilySigningKeySlotIdResult.value
    : null;
  const relayerUrl = String(obj.relayerUrl || '').trim();
  const keyHandle = normalizeOptionalNonEmptyString(obj.keyHandle);
  const relayerKeyId = String(obj.relayerKeyId || '').trim();
  const clientVerifyingShareB64u = String(obj.clientVerifyingShareB64u || '').trim();
  if (obj.clientAdditiveShareHandle !== undefined && obj.clientAdditiveShareHandle !== null) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: deleted clientAdditiveShareHandle',
    );
  }
  if (obj.roleLocalMaterialRef !== undefined && obj.roleLocalMaterialRef !== null) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: deleted roleLocalMaterialRef',
    );
  }
  if (obj.roleLocalMaterialHandle !== undefined && obj.roleLocalMaterialHandle !== null) {
    throw new Error(
      'Invalid threshold ECDSA persisted session record: volatile worker handle is not durable state',
    );
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds(obj.participantIds);
  const thresholdSessionKind = normalizeThresholdSessionKind(obj.thresholdSessionKind);
  const thresholdSessionId = String(obj.thresholdSessionId || '').trim();
  const signingGrantId = normalizeOptionalNonEmptyString(obj.signingGrantId);
  const walletSessionJwt = normalizeOptionalNonEmptyString(obj.walletSessionJwt);
  const signingSessionSealKeyVersion = normalizeOptionalNonEmptyString(
    obj.signingSessionSealKeyVersion,
  );
  const signingSessionSealShamirPrimeB64u = normalizeOptionalNonEmptyString(
    obj.signingSessionSealShamirPrimeB64u,
  );
  const runtimePolicyScope = normalizeStoredRuntimePolicyScope(obj, walletSessionJwt);
  const ecdsaThresholdKeyId = String(obj.ecdsaThresholdKeyId || '').trim();
  if (!ecdsaThresholdKeyId) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: missing ecdsaThresholdKeyId',
    );
  }
  const signingRootBinding = normalizeStoredSigningRootBinding(obj, runtimePolicyScope);
  const chainTarget = normalizeOptionalRuntimeChainTarget(obj.chainTarget);
  if (!chainTarget) {
    throw new Error('Invalid threshold ECDSA canonical session record: missing chainTarget');
  }
  if (evmFamilySigningKeySlotId) {
    evmFamilySigningKeySlotId = assertEvmFamilySigningKeySlotIdMatchesPlan({
      evmFamilySigningKeySlotId,
      walletId,
      signingRootId: signingRootBinding.signingRootId,
      signingRootVersion: signingRootBinding.signingRootVersion,
      message:
        'Invalid threshold ECDSA canonical session record: evmFamilySigningKeySlotId signing-root mismatch',
    });
  }
  const sourceRaw = String(obj.source || '').trim();
  const source: ThresholdEcdsaSessionStoreSource =
    sourceRaw === 'login' ||
    sourceRaw === 'registration' ||
    sourceRaw === 'manual-bootstrap' ||
    sourceRaw === 'email_otp'
      ? sourceRaw
      : 'manual-bootstrap';
  const updatedAtMs = normalizeInteger(obj.updatedAtMs) || Date.now();
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  const remainingUses = normalizeInteger(obj.remainingUses);
  const thresholdEcdsaPublicKeyB64u = normalizeOptionalNonEmptyString(
    obj.thresholdEcdsaPublicKeyB64u,
  );
  const ethereumAddress = normalizeOptionalNonEmptyString(obj.ethereumAddress);
  const relayerVerifyingShareB64u = normalizeOptionalNonEmptyString(obj.relayerVerifyingShareB64u);
  const emailOtpAuthContext =
    source === 'email_otp'
      ? normalizeThresholdEcdsaEmailOtpAuthContext(obj.emailOtpAuthContext)
      : null;
  if (obj.ecdsaRoleLocalReadyRecord !== undefined && obj.ecdsaRoleLocalReadyRecord !== null) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: deleted ecdsaRoleLocalReadyRecord',
    );
  }
  const ecdsaRoleLocalAuthMethod = parseEcdsaRoleLocalAuthMethod(obj.ecdsaRoleLocalAuthMethod);
  const ecdsaRoleLocalPublicFacts = buildEcdsaRoleLocalPublicFacts(obj.ecdsaRoleLocalPublicFacts);

  if (
    !relayerUrl ||
    !evmFamilySigningKeySlotId ||
    !keyHandle ||
    !relayerKeyId ||
    !clientVerifyingShareB64u ||
    !participantIds ||
    !thresholdSessionId ||
    !signingGrantId ||
    !chainTarget ||
    !ethereumAddress
  ) {
    throw new Error(
      formatMissingThresholdEcdsaCanonicalRecordFields({
        relayerUrl,
        evmFamilySigningKeySlotId,
        keyHandle,
        relayerKeyId,
        clientVerifyingShareB64u,
        participantIds,
        thresholdSessionId,
        signingGrantId,
        chainTarget,
        ethereumAddress,
      }),
    );
  }
  if (normalizeOptionalNonEmptyString(obj.subjectId)) {
    throw new Error('Invalid threshold ECDSA canonical session record: unexpected subjectId');
  }
  if (
    obj.ecdsaDerivationRoleLocalClientState !== undefined &&
    obj.ecdsaDerivationRoleLocalClientState !== null
  ) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: deleted ecdsaDerivationRoleLocalClientState',
    );
  }
  assertEcdsaRoleLocalPublicFactsMatchSessionRecord({
    publicFacts: ecdsaRoleLocalPublicFacts,
    walletId,
    evmFamilySigningKeySlotId,
    chainTarget,
    keyHandle,
    ecdsaThresholdKeyId,
    signingRootId: signingRootBinding.signingRootId,
    signingRootVersion: signingRootBinding.signingRootVersion,
    clientVerifyingShareB64u,
    participantIds,
    thresholdEcdsaPublicKeyB64u: thresholdEcdsaPublicKeyB64u || undefined,
    ethereumAddress,
    relayerVerifyingShareB64u: relayerVerifyingShareB64u || undefined,
  });
  assertEcdsaRoleLocalPublicCapabilityMatchesFacts({
    facts: ecdsaRoleLocalPublicFacts,
    walletId,
  });
  if (thresholdSessionKind === 'jwt' && !walletSessionJwt) {
    throw new Error('Invalid threshold ECDSA canonical session record: missing walletSessionJwt');
  }
  if (expiresAtMs == null || expiresAtMs <= 0) {
    throw new Error('Invalid threshold ECDSA canonical session record: missing expiresAtMs');
  }
  if (remainingUses == null || remainingUses < 0) {
    throw new Error('Invalid threshold ECDSA canonical session record: missing remainingUses');
  }
  const routerAbEcdsaDerivationNormalSigning =
    normalizeStoredRouterAbEcdsaDerivationNormalSigningState({
      raw: obj.routerAbEcdsaDerivationNormalSigning,
      walletId,
      ecdsaThresholdKeyId,
      signingRootId: signingRootBinding.signingRootId,
      signingRootVersion: signingRootBinding.signingRootVersion,
      clientVerifyingShareB64u,
      thresholdEcdsaPublicKeyB64u,
      ethereumAddress,
      relayerVerifyingShareB64u,
    });
  if (routerAbEcdsaDerivationNormalSigning) {
    assertEcdsaRoleLocalPublicFactsMatchNormalSigningState({
      publicFacts: ecdsaRoleLocalPublicFacts,
      normalSigning: routerAbEcdsaDerivationNormalSigning,
    });
  }
  const verifiedPublicFacts = normalizeStoredVerifiedPublicFacts({
    rawVerifiedPublicFacts: obj.verifiedPublicFacts,
  });
  if (!verifiedPublicFacts) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: missing verifiedPublicFacts',
    );
  }
  const sharedRecord = {
    walletId,
    authority,
    materialActivation,
    evmFamilySigningKeySlotId,
    relayerUrl,
    keyHandle: toEvmFamilyEcdsaKeyHandle(keyHandle),
    ecdsaThresholdKeyId: resolveThresholdEcdsaKeyIdFromRecord({
      record: { ecdsaThresholdKeyId },
    }),
    signingRootId: signingRootBinding.signingRootId,
    ...(signingRootBinding.signingRootVersion
      ? { signingRootVersion: signingRootBinding.signingRootVersion }
      : {}),
    relayerKeyId,
    clientVerifyingShareB64u,
    ecdsaRoleLocalPublicFacts,
    participantIds,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(routerAbEcdsaDerivationNormalSigning ? { routerAbEcdsaDerivationNormalSigning } : {}),
    thresholdSessionKind,
    thresholdSessionId,
    signingGrantId,
    ...(walletSessionJwt ? { walletSessionJwt } : {}),
    ...(signingSessionSealKeyVersion ? { signingSessionSealKeyVersion } : {}),
    ...(signingSessionSealShamirPrimeB64u ? { signingSessionSealShamirPrimeB64u } : {}),
    expiresAtMs,
    remainingUses,
    ...(thresholdEcdsaPublicKeyB64u ? { thresholdEcdsaPublicKeyB64u } : {}),
    ...(verifiedPublicFacts ? { verifiedPublicFacts } : {}),
    ethereumAddress,
    ...(relayerVerifyingShareB64u ? { relayerVerifyingShareB64u } : {}),
    updatedAtMs,
    chainTarget,
  };
  if (source === 'email_otp') {
    if (ecdsaRoleLocalAuthMethod.kind !== 'email_otp') {
      throw new Error(
        'Invalid threshold ECDSA canonical session record: Email OTP source requires Email OTP auth',
      );
    }
    if (thresholdSessionKind !== 'jwt') {
      throw new Error(
        'Invalid threshold ECDSA canonical session record: Email OTP requires jwt session kind',
      );
    }
    if (!walletSessionJwt) {
      throw new Error(
        'Invalid threshold ECDSA canonical session record: Email OTP requires walletSessionJwt',
      );
    }
    if (!emailOtpAuthContext) {
      throw new Error(
        'Invalid threshold ECDSA canonical session record: missing Email OTP context',
      );
    }
    return {
      ...sharedRecord,
      purpose: 'transaction_signing',
      thresholdSessionKind: 'jwt',
      walletSessionJwt,
      ecdsaRoleLocalAuthMethod,
      emailOtpAuthContext,
      source,
    };
  }
  if (ecdsaRoleLocalAuthMethod.kind !== 'passkey') {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: passkey source requires passkey auth',
    );
  }
  return {
    ...sharedRecord,
    purpose: 'transaction_signing',
    ecdsaRoleLocalAuthMethod,
    source,
  };
}

function formatMissingThresholdEcdsaCanonicalRecordFields(args: {
  relayerUrl: string;
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId | null;
  keyHandle: string | null | undefined;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  participantIds: number[] | null;
  thresholdSessionId: string;
  signingGrantId: string | null | undefined;
  chainTarget: ThresholdEcdsaChainTarget | null;
  ethereumAddress: string | null | undefined;
}): string {
  const missing: string[] = [];
  if (!args.relayerUrl) missing.push('relayerUrl');
  if (!args.evmFamilySigningKeySlotId) missing.push('evmFamilySigningKeySlotId');
  if (!args.keyHandle) missing.push('keyHandle');
  if (!args.relayerKeyId) missing.push('relayerKeyId');
  if (!args.clientVerifyingShareB64u) missing.push('clientVerifyingShareB64u');
  if (!args.participantIds) missing.push('participantIds');
  if (!args.thresholdSessionId) missing.push('thresholdSessionId');
  if (!args.signingGrantId) missing.push('signingGrantId');
  if (!args.chainTarget) missing.push('chainTarget');
  if (!args.ethereumAddress) missing.push('ethereumAddress');
  return `Invalid threshold ECDSA canonical session record: missing ${missing.join(', ')}`;
}

export function parseRawThresholdEcdsaSessionRecord(
  value: RawThresholdEcdsaSessionRecord | unknown,
): ThresholdEcdsaSessionRecord {
  return normalizeThresholdEcdsaSessionRecord(value, 'transaction_signing');
}

function normalizeThresholdEcdsaEmailOtpAuthContext(
  value: unknown,
): ThresholdEcdsaEmailOtpAuthContext {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid Email OTP auth context: missing context');
  }
  const obj = value as Record<string, unknown>;
  const policyRaw = String(obj.policy || '')
    .trim()
    .toLowerCase();
  if (policyRaw !== 'session' && policyRaw !== 'per_operation') {
    throw new Error('Invalid Email OTP auth context: invalid policy');
  }
  const policy: EmailOtpAuthPolicy = policyRaw;
  const authMethodRaw = String(obj.authMethod || '')
    .trim()
    .toLowerCase();
  if (authMethodRaw !== 'email_otp') {
    throw new Error('Invalid Email OTP auth context: invalid authMethod');
  }
  if (Object.prototype.hasOwnProperty.call(obj, 'authSubjectId')) {
    throw new Error('Invalid Email OTP auth context: deleted authSubjectId');
  }
  if (Object.prototype.hasOwnProperty.call(obj, 'retention')) {
    throw new Error('Invalid Email OTP auth context: deleted retention');
  }
  if (Object.prototype.hasOwnProperty.call(obj, 'reason')) {
    throw new Error('Invalid Email OTP auth context: deleted reason');
  }
  if (Object.prototype.hasOwnProperty.call(obj, 'consumedAtMs')) {
    throw new Error('Invalid Email OTP auth context: deleted consumedAtMs');
  }
  const authority = parseEmailOtpWalletAuthAuthority(obj.authority);
  if (!authority) {
    throw new Error('Invalid Email OTP auth context: invalid wallet auth authority');
  }
  const use = normalizeEmailOtpAuthUse(obj.use);
  switch (use.kind) {
    case 'session':
      return buildEmailOtpAuthContext({
        policy,
        retention: 'session',
        reason: use.reason,
        authority,
      });
    case 'single_use_pending':
      return buildEmailOtpAuthContext({
        policy,
        retention: 'single_use',
        authority,
      });
    case 'single_use_consumed':
      return buildEmailOtpAuthContext({
        policy,
        retention: 'single_use',
        authority,
        consumedAtMs: use.consumedAtMs,
      });
  }
  use satisfies never;
  throw new Error('Invalid Email OTP auth context: unsupported use');
}

function normalizeEmailOtpAuthUse(value: unknown): EmailOtpAuthUse {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid Email OTP auth context: missing use');
  }
  const obj = value as Record<string, unknown>;
  const kind = String(obj.kind || '')
    .trim()
    .toLowerCase();
  const reason = String(obj.reason || '')
    .trim()
    .toLowerCase();
  switch (kind) {
    case 'session':
      if (reason !== 'login' && reason !== 'sign') {
        throw new Error('Invalid Email OTP auth context: invalid session use reason');
      }
      return { kind: 'session', reason };
    case 'single_use_pending':
      if (Object.prototype.hasOwnProperty.call(obj, 'reason')) {
        throw new Error('Invalid Email OTP auth context: pending single-use reason is deleted');
      }
      return { kind: 'single_use_pending' };
    case 'single_use_consumed': {
      if (Object.prototype.hasOwnProperty.call(obj, 'reason')) {
        throw new Error('Invalid Email OTP auth context: consumed single-use reason is deleted');
      }
      const consumedAtMs = normalizePositiveInteger(obj.consumedAtMs);
      if (!consumedAtMs) {
        throw new Error('Invalid Email OTP auth context: missing consumedAtMs');
      }
      return { kind: 'single_use_consumed', consumedAtMs };
    }
  }
  throw new Error('Invalid Email OTP auth context: invalid use kind');
}

function parseThresholdEd25519SessionIdentity(obj: Record<string, unknown>): {
  walletId: ReturnType<typeof toWalletId>;
  nearAccountId: ReturnType<typeof toAccountId>;
  nearEd25519SigningKeyId: ReturnType<typeof nearEd25519SigningKeyIdFromString>;
} {
  const nearAccountIdRaw = String(obj.nearAccountId || '').trim();
  const walletIdRaw = String(obj.walletId || '').trim();
  const nearEd25519SigningKeyIdRaw = String(obj.nearEd25519SigningKeyId || '').trim();
  if (!walletIdRaw || !nearAccountIdRaw || !nearEd25519SigningKeyIdRaw) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing identity binding');
  }
  return {
    walletId: toWalletId(walletIdRaw),
    nearAccountId: toAccountId(nearAccountIdRaw),
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(nearEd25519SigningKeyIdRaw),
  };
}

function normalizeThresholdEd25519SessionRecord(value: unknown): ThresholdEd25519SessionRecord {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
  const { walletId, nearAccountId, nearEd25519SigningKeyId } =
    parseThresholdEd25519SessionIdentity(obj);
  const rpId = String(obj.rpId || '').trim();
  const passkeyCredentialIdB64u = normalizeOptionalNonEmptyString(obj.passkeyCredentialIdB64u);
  const relayerUrl = String(obj.relayerUrl || '').trim();
  const relayerKeyId = String(obj.relayerKeyId || '').trim();
  const participantIds = normalizeThresholdEd25519ParticipantIds(obj.participantIds);
  const runtimePolicyScope = normalizeStoredRuntimePolicyScope(obj);
  const scopeBinding = runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope)
    : null;
  const explicitSigningRootId = normalizeOptionalNonEmptyString(obj.signingRootId);
  const explicitSigningRootVersion = normalizeOptionalNonEmptyString(obj.signingRootVersion);
  const scopeSigningRootId = normalizeOptionalNonEmptyString(scopeBinding?.signingRootId);
  const scopeSigningRootVersion = normalizeOptionalNonEmptyString(scopeBinding?.signingRootVersion);
  if (explicitSigningRootId && scopeSigningRootId && explicitSigningRootId !== scopeSigningRootId) {
    throw new Error('Invalid threshold Ed25519 canonical session record: signingRootId mismatch');
  }
  if (
    explicitSigningRootVersion &&
    scopeSigningRootVersion &&
    explicitSigningRootVersion !== scopeSigningRootVersion
  ) {
    throw new Error(
      'Invalid threshold Ed25519 canonical session record: signingRootVersion mismatch',
    );
  }
  const signingRootId = explicitSigningRootId || scopeSigningRootId || '';
  const signingRootVersion = explicitSigningRootVersion || scopeSigningRootVersion || '';
  const signerSlot = normalizeInteger(obj.signerSlot);
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(obj.routerAbNormalSigning);
  const thresholdSessionKindRaw = String(obj.thresholdSessionKind || 'jwt')
    .trim()
    .toLowerCase();
  const thresholdSessionKind: 'jwt' | 'cookie' =
    thresholdSessionKindRaw === 'cookie' ? 'cookie' : 'jwt';
  const thresholdSessionId = String(obj.thresholdSessionId || '').trim();
  const signingGrantId = normalizeOptionalNonEmptyString(obj.signingGrantId);
  const walletSessionJwt = normalizeOptionalNonEmptyString(obj.walletSessionJwt);
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  const remainingUses = normalizeInteger(obj.remainingUses);
  const updatedAtMs = normalizeInteger(obj.updatedAtMs) || Date.now();
  const sourceRaw = String(obj.source || '').trim();
  const source: ThresholdEd25519SessionStoreSource =
    sourceRaw === 'login' ||
    sourceRaw === 'registration' ||
    sourceRaw === 'add-signer' ||
    sourceRaw === 'manual-connect' ||
    sourceRaw === 'bootstrap' ||
    sourceRaw === 'email_otp'
      ? sourceRaw
      : 'manual-connect';
  const emailOtpAuthContext =
    source === 'email_otp'
      ? normalizeThresholdEcdsaEmailOtpAuthContext(obj.emailOtpAuthContext)
      : null;

  if (!rpId || !relayerUrl || !relayerKeyId || !participantIds || !thresholdSessionId) {
    throw new Error('Invalid threshold Ed25519 canonical session record');
  }
  if (thresholdSessionKind === 'jwt' && !walletSessionJwt) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing walletSessionJwt');
  }
  if (expiresAtMs == null || expiresAtMs <= 0) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing expiresAtMs');
  }
  if (remainingUses == null || remainingUses < 0) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing remainingUses');
  }
  if (signerSlot == null || signerSlot <= 0) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing signerSlot');
  }
  if (!routerAbNormalSigning) {
    throw new Error(
      'Invalid threshold Ed25519 canonical session record: missing routerAbNormalSigning',
    );
  }
  return {
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    rpId,
    ...(passkeyCredentialIdB64u ? { passkeyCredentialIdB64u } : {}),
    relayerUrl,
    relayerKeyId,
    participantIds,
    ...(signingRootId ? { signingRootId } : {}),
    ...(signingRootVersion ? { signingRootVersion } : {}),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    signerSlot,
    routerAbNormalSigning,
    thresholdSessionKind,
    thresholdSessionId,
    ...(signingGrantId ? { signingGrantId } : {}),
    ...(walletSessionJwt ? { walletSessionJwt } : {}),
    expiresAtMs,
    remainingUses,
    ...(emailOtpAuthContext ? { emailOtpAuthContext } : {}),
    updatedAtMs,
    source,
  };
}

function forgetStaleInMemoryThresholdEd25519LaneForSession(args: {
  thresholdSessionId: string;
  currentLaneKey: string | null;
}): void {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return;
  const currentLaneKey = String(args.currentLaneKey || '').trim();
  const indexedLaneKey = String(
    inMemoryEd25519LaneBySessionId.get(thresholdSessionId) || '',
  ).trim();
  if (!indexedLaneKey || indexedLaneKey === currentLaneKey) return;
  const indexedLaneRecord = inMemoryEd25519RecordsByLane.get(indexedLaneKey) || null;
  if (
    indexedLaneRecord &&
    String(indexedLaneRecord.thresholdSessionId || '').trim() === thresholdSessionId
  ) {
    inMemoryEd25519RecordsByLane.delete(indexedLaneKey);
  }
  inMemoryEd25519LaneBySessionId.delete(thresholdSessionId);
}

type Ed25519DefaultRecordPolicy = 'prefer_incoming' | 'prefer_current_generation';

function thresholdSessionRecordGeneration(record: {
  updatedAtMs?: number | null;
  expiresAtMs?: number | null;
}): number | null {
  const updatedAtGeneration = Math.floor(Number(record.updatedAtMs) || 0);
  if (Number.isFinite(updatedAtGeneration) && updatedAtGeneration > 0) {
    return updatedAtGeneration;
  }
  const generation = Math.floor(Number(record.expiresAtMs) || 0);
  return Number.isFinite(generation) && generation > 0 ? generation : null;
}

function shouldReplaceDefaultThresholdSessionRecord(args: {
  existing:
    | { thresholdSessionId?: string; updatedAtMs?: number | null; expiresAtMs?: number | null }
    | null
    | undefined;
  incoming: {
    thresholdSessionId?: string;
    updatedAtMs?: number | null;
    expiresAtMs?: number | null;
  };
  policy: Ed25519DefaultRecordPolicy;
}): boolean {
  if (args.policy === 'prefer_incoming') return true;
  const existing = args.existing;
  if (!existing) return true;
  const existingSessionId = String(existing.thresholdSessionId || '').trim();
  const incomingSessionId = String(args.incoming.thresholdSessionId || '').trim();
  if (existingSessionId && existingSessionId === incomingSessionId) return true;
  const existingGeneration = thresholdSessionRecordGeneration(existing);
  const incomingGeneration = thresholdSessionRecordGeneration(args.incoming);
  if (!existingGeneration && incomingGeneration) return true;
  if (existingGeneration && incomingGeneration) return incomingGeneration > existingGeneration;
  return !existingGeneration && !incomingGeneration;
}

function rememberInMemoryThresholdEd25519Record(
  record: ThresholdEd25519SessionRecord,
  defaultPolicy: Ed25519DefaultRecordPolicy = 'prefer_incoming',
): void {
  const accountKey = String(record.nearAccountId || '').trim();
  const walletKey = String(record.walletId || '').trim();
  const thresholdSessionId = String(record.thresholdSessionId || '').trim();
  if (!accountKey || !walletKey || !thresholdSessionId) return;
  const laneKey = getThresholdEd25519SessionLaneKeyForRecord(record);
  forgetStaleInMemoryThresholdEd25519LaneForSession({
    thresholdSessionId,
    currentLaneKey: laneKey,
  });

  // The account index tracks the default lane; the lane/session indexes retain
  // exact in-flight sessions so concurrent step-up operations cannot displace
  // each other's planned material.
  const previous = inMemoryEd25519RecordsByAccount.get(accountKey);
  if (
    shouldReplaceDefaultThresholdSessionRecord({
      existing: previous,
      incoming: record,
      policy: defaultPolicy,
    })
  ) {
    const previousSessionId = String(previous?.thresholdSessionId || '').trim();
    if (previousSessionId && previousSessionId !== thresholdSessionId) {
      inMemoryEd25519AccountBySessionId.delete(previousSessionId);
    }
    inMemoryEd25519RecordsByAccount.set(accountKey, record);
    inMemoryEd25519AccountBySessionId.set(thresholdSessionId, accountKey);
  }
  const previousWallet = inMemoryEd25519RecordsByWallet.get(walletKey);
  if (
    shouldReplaceDefaultThresholdSessionRecord({
      existing: previousWallet,
      incoming: record,
      policy: defaultPolicy,
    })
  ) {
    const previousWalletSessionId = String(previousWallet?.thresholdSessionId || '').trim();
    if (previousWalletSessionId && previousWalletSessionId !== thresholdSessionId) {
      inMemoryEd25519WalletBySessionId.delete(previousWalletSessionId);
    }
    inMemoryEd25519RecordsByWallet.set(walletKey, record);
    inMemoryEd25519WalletBySessionId.set(thresholdSessionId, walletKey);
  }

  if (!laneKey) return;
  const previousLaneRecord = inMemoryEd25519RecordsByLane.get(laneKey);
  const previousLaneSessionId = String(previousLaneRecord?.thresholdSessionId || '').trim();
  if (previousLaneSessionId && previousLaneSessionId !== thresholdSessionId) {
    inMemoryEd25519LaneBySessionId.delete(previousLaneSessionId);
  }
  inMemoryEd25519RecordsByLane.set(laneKey, record);
  inMemoryEd25519LaneBySessionId.set(thresholdSessionId, laneKey);
}

function getInMemoryThresholdEd25519SessionRecordForAccount(
  nearAccountIdRaw: AccountId | string,
): ThresholdEd25519SessionRecord | null {
  try {
    const accountKey = String(toAccountId(nearAccountIdRaw)).trim();
    return inMemoryEd25519RecordsByAccount.get(accountKey) || null;
  } catch {
    return null;
  }
}

function getInMemoryThresholdEd25519SessionRecordForWallet(
  walletIdRaw: WalletId | string,
): ThresholdEd25519SessionRecord | null {
  try {
    const walletKey = String(toWalletId(walletIdRaw)).trim();
    return inMemoryEd25519RecordsByWallet.get(walletKey) || null;
  } catch {
    return null;
  }
}

function getInMemoryThresholdEd25519SessionRecordByThresholdSessionId(
  thresholdSessionIdRaw: string,
): ThresholdEd25519SessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;

  const indexedLaneKey = String(
    inMemoryEd25519LaneBySessionId.get(thresholdSessionId) || '',
  ).trim();
  if (indexedLaneKey) {
    const indexedLaneRecord = inMemoryEd25519RecordsByLane.get(indexedLaneKey) || null;
    if (
      indexedLaneRecord &&
      String(indexedLaneRecord.thresholdSessionId || '').trim() === thresholdSessionId
    ) {
      return indexedLaneRecord;
    }
    inMemoryEd25519LaneBySessionId.delete(thresholdSessionId);
  }

  const indexedWalletKey = String(
    inMemoryEd25519WalletBySessionId.get(thresholdSessionId) || '',
  ).trim();
  if (indexedWalletKey) {
    const indexedWalletRecord = inMemoryEd25519RecordsByWallet.get(indexedWalletKey) || null;
    if (
      indexedWalletRecord &&
      String(indexedWalletRecord.thresholdSessionId || '').trim() === thresholdSessionId
    ) {
      return indexedWalletRecord;
    }
    inMemoryEd25519WalletBySessionId.delete(thresholdSessionId);
  }

  const indexedAccountKey = String(
    inMemoryEd25519AccountBySessionId.get(thresholdSessionId) || '',
  ).trim();
  if (indexedAccountKey) {
    const indexedRecord = inMemoryEd25519RecordsByAccount.get(indexedAccountKey) || null;
    if (
      indexedRecord &&
      String(indexedRecord.thresholdSessionId || '').trim() === thresholdSessionId
    ) {
      return indexedRecord;
    }
    inMemoryEd25519AccountBySessionId.delete(thresholdSessionId);
  }

  for (const [accountKey, record] of inMemoryEd25519RecordsByAccount.entries()) {
    if (String(record.thresholdSessionId || '').trim() !== thresholdSessionId) continue;
    inMemoryEd25519AccountBySessionId.set(thresholdSessionId, accountKey);
    return record;
  }

  for (const [walletKey, record] of inMemoryEd25519RecordsByWallet.entries()) {
    if (String(record.thresholdSessionId || '').trim() !== thresholdSessionId) continue;
    inMemoryEd25519WalletBySessionId.set(thresholdSessionId, walletKey);
    return record;
  }

  return null;
}

export type ThresholdEd25519SessionUpsertInput = {
  walletId: WalletId | string;
  nearAccountId: AccountId | string;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId | string;
  rpId: string;
  passkeyCredentialIdB64u?: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  signingRootId?: string;
  signingRootVersion?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  signerSlot: number;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  thresholdSessionKind?: 'jwt' | 'cookie';
  thresholdSessionId: string;
  signingGrantId?: string;
  walletSessionJwt?: string;
  expiresAtMs: number;
  remainingUses: number;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  updatedAtMs?: number;
  source?: ThresholdEd25519SessionStoreSource;
};

function forgetInMemoryThresholdEd25519Record(record: ThresholdEd25519SessionRecord): void {
  const accountKey = String(record.nearAccountId || '').trim();
  const walletKey = String(record.walletId || '').trim();
  const thresholdSessionId = normalizeOptionalNonEmptyString(record.thresholdSessionId);
  if (accountKey) {
    const currentAccountRecord = inMemoryEd25519RecordsByAccount.get(accountKey) || null;
    if (
      currentAccountRecord &&
      String(currentAccountRecord.thresholdSessionId || '').trim() === thresholdSessionId
    ) {
      inMemoryEd25519RecordsByAccount.delete(accountKey);
    }
  }
  if (
    thresholdSessionId &&
    inMemoryEd25519AccountBySessionId.get(thresholdSessionId) === accountKey
  ) {
    inMemoryEd25519AccountBySessionId.delete(thresholdSessionId);
  }
  if (walletKey) {
    const currentWalletRecord = inMemoryEd25519RecordsByWallet.get(walletKey) || null;
    if (
      currentWalletRecord &&
      String(currentWalletRecord.thresholdSessionId || '').trim() === thresholdSessionId
    ) {
      inMemoryEd25519RecordsByWallet.delete(walletKey);
    }
  }
  if (
    thresholdSessionId &&
    inMemoryEd25519WalletBySessionId.get(thresholdSessionId) === walletKey
  ) {
    inMemoryEd25519WalletBySessionId.delete(thresholdSessionId);
  }
  const laneKey = getThresholdEd25519SessionLaneKeyForRecord(record);
  if (laneKey) {
    const currentLaneRecord = inMemoryEd25519RecordsByLane.get(laneKey) || null;
    if (
      currentLaneRecord &&
      String(currentLaneRecord.thresholdSessionId || '').trim() === thresholdSessionId
    ) {
      inMemoryEd25519RecordsByLane.delete(laneKey);
    }
  }
  if (
    thresholdSessionId &&
    laneKey &&
    inMemoryEd25519LaneBySessionId.get(thresholdSessionId) === laneKey
  ) {
    inMemoryEd25519LaneBySessionId.delete(thresholdSessionId);
  }
}

type ThresholdEd25519SessionAuthMethod = SigningSessionSealAuthMethod;

export type ThresholdEd25519SessionRecordKey = {
  walletId: WalletId;
  nearAccountId: StrictAccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  authMethod: ThresholdEd25519SessionAuthMethod;
  signingGrantId: SigningGrantId;
  thresholdSessionId: ThresholdEd25519SessionId;
  signerSlot: SignerSlot;
};

export type ThresholdEd25519SessionRecordKeyInput = {
  walletId: unknown;
  nearAccountId: unknown;
  nearEd25519SigningKeyId: unknown;
  authMethod: ThresholdEd25519SessionAuthMethod;
  signingGrantId: unknown;
  thresholdSessionId: unknown;
  signerSlot: unknown;
};

function thresholdEd25519AuthMethodForRecord(
  record: ThresholdEd25519SessionRecord,
): ThresholdEd25519SessionAuthMethod {
  const source = record.source;
  switch (source) {
    case SIGNER_AUTH_METHODS.emailOtp:
      return SIGNER_AUTH_METHODS.emailOtp;
    case 'login':
    case 'registration':
    case 'add-signer':
    case 'manual-connect':
    case 'bootstrap':
      return SIGNER_AUTH_METHODS.passkey;
    default:
      source satisfies never;
      throw new Error(
        `[SigningEngine] unsupported threshold Ed25519 session source: ${String(source)}`,
      );
  }
}

function thresholdEd25519AuthBindingForRecord(
  record: ThresholdEd25519SessionRecord,
): SigningLaneAuthBinding {
  if (record.source === 'email_otp') {
    const providerSubjectId = record.emailOtpAuthContext
      ? emailOtpAuthContextProviderUserId(record.emailOtpAuthContext)
      : '';
    if (!providerSubjectId) {
      throw new Error('[SigningEngine] Email OTP Ed25519 record is missing auth subject');
    }
    return {
      kind: 'email_otp',
      providerSubjectId,
    };
  }
  const credentialIdB64u = normalizeOptionalNonEmptyString(record.passkeyCredentialIdB64u);
  if (!credentialIdB64u) {
    throw new Error('[SigningEngine] passkey Ed25519 record is missing credential id');
  }
  return {
    kind: 'passkey',
    rpId: toRpId(record.rpId),
    credentialIdB64u,
  };
}

export function thresholdEd25519LaneCandidateFromSessionRecord(args: {
  record: ThresholdEd25519SessionRecord;
  nowMs?: number;
}): Ed25519LaneCandidate | null {
  const signingGrantId = normalizeOptionalNonEmptyString(args.record.signingGrantId);
  if (!signingGrantId) return null;
  const signerSlot = normalizeInteger(args.record.signerSlot);
  if (signerSlot == null || signerSlot < 1) return null;
  return {
    kind: 'lane_candidate',
    walletId: args.record.walletId,
    nearAccountId: args.record.nearAccountId,
    nearEd25519SigningKeyId: args.record.nearEd25519SigningKeyId,
    signerSlot,
    auth: thresholdEd25519AuthBindingForRecord(args.record),
    curve: 'ed25519',
    chain: 'near',
    signingGrantId,
    thresholdSessionId: args.record.thresholdSessionId,
    state: laneCandidateStateFromRuntimePolicy({
      remainingUses: args.record.remainingUses,
      expiresAtMs: args.record.expiresAtMs,
      nowMs: args.nowMs,
    }),
    remainingUses: nullableRecordInteger(args.record.remainingUses),
    expiresAtMs: nullableRecordInteger(args.record.expiresAtMs),
    updatedAtMs: nullableRecordInteger(args.record.updatedAtMs),
    source: 'runtime_session_record',
  };
}

export function serializeThresholdEd25519SessionLaneKey(args: {
  walletId: WalletId;
  nearAccountId: StrictAccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  authMethod: ThresholdEd25519SessionAuthMethod;
  signingGrantId: SigningGrantId;
  thresholdSessionId: ThresholdEd25519SessionId;
  signerSlot: SignerSlot;
}): string {
  const walletId = String(args.walletId).trim();
  const nearAccountId = String(args.nearAccountId).trim();
  const nearEd25519SigningKeyId = String(args.nearEd25519SigningKeyId).trim();
  const authMethod = args.authMethod;
  const signingGrantId = String(args.signingGrantId).trim();
  const thresholdSessionId = String(args.thresholdSessionId).trim();
  const signerSlot = args.signerSlot;
  if (
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    (authMethod !== 'email_otp' && authMethod !== 'passkey') ||
    !signingGrantId ||
    !thresholdSessionId ||
    signerSlot == null ||
    signerSlot < 1
  ) {
    throw new Error('[SigningEngine] invalid threshold Ed25519 lane key input');
  }
  return [
    encodeLaneToken(walletId),
    encodeLaneToken(nearAccountId),
    encodeLaneToken(nearEd25519SigningKeyId),
    encodeLaneToken(authMethod),
    encodeLaneToken(signingGrantId),
    encodeLaneToken(thresholdSessionId),
    encodeLaneToken(String(signerSlot)),
  ].join('|');
}

export function buildThresholdEd25519SessionRecordKey(
  args: ThresholdEd25519SessionRecordKeyInput,
): ThresholdEd25519SessionRecordKey {
  const signerSlot = parseSignerSlot(args.signerSlot);
  if (!signerSlot) {
    throw new Error('[SigningEngine] invalid threshold Ed25519 lane signerSlot');
  }
  if (typeof args.nearAccountId !== 'string') {
    throw new Error('[SigningEngine] invalid threshold Ed25519 lane nearAccountId');
  }
  if (args.authMethod !== 'email_otp' && args.authMethod !== 'passkey') {
    throw new Error('[SigningEngine] invalid threshold Ed25519 lane authMethod');
  }
  return {
    walletId: toWalletId(args.walletId),
    nearAccountId: toAccountId(args.nearAccountId),
    nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(args.nearEd25519SigningKeyId),
    authMethod: args.authMethod,
    signingGrantId: SigningSessionIds.signingGrant(args.signingGrantId),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(args.thresholdSessionId),
    signerSlot,
  };
}

export function thresholdEd25519SessionRecordKeyFromRecord(
  record: ThresholdEd25519SessionRecord,
): ThresholdEd25519SessionRecordKey | null {
  try {
    return buildThresholdEd25519SessionRecordKey({
      walletId: record.walletId,
      nearAccountId: record.nearAccountId,
      nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
      authMethod: thresholdEd25519AuthMethodForRecord(record),
      signingGrantId: record.signingGrantId,
      thresholdSessionId: record.thresholdSessionId,
      signerSlot: record.signerSlot,
    });
  } catch {
    return null;
  }
}

export function thresholdEd25519SessionRecordKeyFromExactIdentity(
  identity: ExactEd25519SigningLaneIdentity,
): ThresholdEd25519SessionRecordKey {
  const signer = identity.signer;
  return buildThresholdEd25519SessionRecordKey({
    walletId: signer.account.wallet.walletId,
    nearAccountId: signer.account.nearAccountId,
    nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
    authMethod: signingLaneAuthMethod(identity.auth),
    signingGrantId: identity.signingGrantId,
    thresholdSessionId: identity.thresholdSessionId,
    signerSlot: signer.signerSlot,
  });
}

function getThresholdEd25519SessionLaneKeyForRecord(
  record: ThresholdEd25519SessionRecord,
): string | null {
  const key = thresholdEd25519SessionRecordKeyFromRecord(record);
  return key ? serializeThresholdEd25519SessionLaneKey(key) : null;
}

function thresholdEd25519AuthSupersessionKey(record: ThresholdEd25519SessionRecord): string | null {
  if (record.source === 'email_otp') {
    const providerSubjectId = record.emailOtpAuthContext
      ? emailOtpAuthContextProviderUserId(record.emailOtpAuthContext)
      : '';
    return providerSubjectId ? `email_otp:${providerSubjectId}` : null;
  }
  const rpId = String(record.rpId || '').trim();
  const credentialIdB64u = normalizeOptionalNonEmptyString(record.passkeyCredentialIdB64u);
  return rpId && credentialIdB64u ? `passkey:${rpId}:${credentialIdB64u}` : null;
}

function thresholdEd25519SupersessionGroupKey(
  record: ThresholdEd25519SessionRecord,
): string | null {
  const walletId = String(record.walletId || '').trim();
  const nearAccountId = String(record.nearAccountId || '').trim();
  const nearEd25519SigningKeyId = String(record.nearEd25519SigningKeyId || '').trim();
  const signerSlot = parseSignerSlot(record.signerSlot);
  const authKey = thresholdEd25519AuthSupersessionKey(record);
  if (!walletId || !nearAccountId || !nearEd25519SigningKeyId || !signerSlot || !authKey) {
    return null;
  }
  return [
    encodeLaneToken(walletId),
    encodeLaneToken(nearAccountId),
    encodeLaneToken(nearEd25519SigningKeyId),
    encodeLaneToken(authKey),
    encodeLaneToken(String(signerSlot)),
  ].join('|');
}

export function buildOperationUsableThresholdEd25519SessionRecord(
  record: ThresholdEd25519SessionRecord,
): OperationUsableThresholdEd25519SessionRecord | null {
  if (!String(record.thresholdSessionId || '').trim()) return null;
  if (!String(record.signingGrantId || '').trim()) return null;
  if (!String(record.walletSessionJwt || '').trim()) return null;
  if (Math.floor(Number(record.remainingUses) || 0) <= 0) return null;
  if (!thresholdSessionRecordGeneration(record)) return null;
  if (!thresholdEd25519SupersessionGroupKey(record)) return null;
  return record as OperationUsableThresholdEd25519SessionRecord;
}

export function describeOperationUsableThresholdEd25519SessionRecordRejection(
  record: ThresholdEd25519SessionRecord,
): readonly string[] {
  const reasons: string[] = [];
  if (!String(record.thresholdSessionId || '').trim()) {
    reasons.push('missing_threshold_session_id');
  }
  if (!String(record.signingGrantId || '').trim()) {
    reasons.push('missing_signing_grant_id');
  }
  if (!String(record.walletSessionJwt || '').trim()) {
    reasons.push('missing_wallet_session_jwt');
  }
  if (Math.floor(Number(record.remainingUses) || 0) <= 0) {
    reasons.push('non_positive_remaining_uses');
  }
  if (!thresholdSessionRecordGeneration(record)) {
    reasons.push('missing_session_generation');
  }
  if (!thresholdEd25519SupersessionGroupKey(record)) {
    reasons.push('missing_supersession_group');
  }
  return reasons;
}

function thresholdEd25519SessionId(record: ThresholdEd25519SessionRecord): string {
  return String(record.thresholdSessionId || '').trim();
}

function sameThresholdEd25519SupersessionGroup(args: {
  incoming: ThresholdEd25519SessionRecord;
  existing: ThresholdEd25519SessionRecord;
}): boolean {
  const incomingGroupKey = thresholdEd25519SupersessionGroupKey(args.incoming);
  return Boolean(
    incomingGroupKey && thresholdEd25519SupersessionGroupKey(args.existing) === incomingGroupKey,
  );
}

function thresholdEd25519SameGroupRecords(
  incomingRecord: ThresholdEd25519SessionRecord,
): ThresholdEd25519SessionRecord[] {
  return [...inMemoryEd25519RecordsByLane.values()].filter((existingRecord) =>
    sameThresholdEd25519SupersessionGroup({
      incoming: incomingRecord,
      existing: existingRecord,
    }),
  );
}

function storeThresholdEd25519SessionFact(args: {
  record: ThresholdEd25519SessionRecord;
  defaultPolicy: Ed25519DefaultRecordPolicy;
}): ThresholdEd25519SessionRecord {
  rememberInMemoryThresholdEd25519Record(args.record, args.defaultPolicy);
  return args.record;
}

export function commitCurrentThresholdEd25519Session(args: {
  record: OperationUsableThresholdEd25519SessionRecord;
}): ThresholdEd25519SessionCommitResult {
  const incomingRecord = args.record;
  const incomingGeneration = thresholdSessionRecordGeneration(incomingRecord);
  if (!incomingGeneration) {
    throw new Error('Current Ed25519 session commit requires server-issued generation');
  }
  const incomingSessionId = thresholdEd25519SessionId(incomingRecord);
  const existingRecords = thresholdEd25519SameGroupRecords(incomingRecord);
  for (const existingRecord of existingRecords) {
    const existingGeneration = thresholdSessionRecordGeneration(existingRecord);
    const existingSessionId = thresholdEd25519SessionId(existingRecord);
    if (existingSessionId === incomingSessionId) continue;
    const existingCurrent = buildOperationUsableThresholdEd25519SessionRecord(existingRecord);
    if (existingCurrent && existingGeneration && existingGeneration > incomingGeneration) {
      return {
        kind: 'stale_commit_ignored',
        incoming: incomingRecord,
        current: existingCurrent,
      };
    }
    if (existingCurrent && existingGeneration === incomingGeneration) {
      return {
        kind: 'same_generation_distinct_session',
        incoming: incomingRecord,
        existing: existingCurrent,
      };
    }
  }

  storeThresholdEd25519SessionFact({
    record: incomingRecord,
    defaultPolicy: 'prefer_incoming',
  });

  const incomingLaneKey = getThresholdEd25519SessionLaneKeyForRecord(incomingRecord);
  const retired: ThresholdEd25519SessionRecord[] = [];
  const diagnostics: CurrentSessionRetirementDiagnostic[] = [];
  for (const existingRecord of existingRecords) {
    const existingLaneKey = getThresholdEd25519SessionLaneKeyForRecord(existingRecord);
    if (incomingLaneKey && existingLaneKey === incomingLaneKey) continue;
    const existingSessionId = thresholdEd25519SessionId(existingRecord);
    const existingGeneration = thresholdSessionRecordGeneration(existingRecord);
    const shouldRetire =
      existingSessionId === incomingSessionId ||
      existingGeneration === null ||
      existingGeneration < incomingGeneration;
    if (!shouldRetire) continue;
    if (existingGeneration === null) {
      diagnostics.push({
        kind: 'retired_null_generation_legacy_fact',
        thresholdSessionId: existingSessionId,
      });
    }
    forgetInMemoryThresholdEd25519Record(existingRecord);
    retired.push(existingRecord);
  }

  return {
    kind: 'committed_current',
    current: incomingRecord,
    retired,
    diagnostics,
  };
}

export function requireCommittedThresholdEd25519Session(
  result: ThresholdEd25519SessionCommitResult,
): OperationUsableThresholdEd25519SessionRecord {
  switch (result.kind) {
    case 'committed_current':
      return result.current;
    case 'same_generation_distinct_session':
      throw new Error('Current Ed25519 session commit produced same-generation distinct sessions');
    case 'stale_commit_ignored':
      throw new Error('Current Ed25519 session commit was stale');
    default: {
      const exhaustive: never = result;
      throw new Error(String((exhaustive as { kind?: unknown })?.kind || 'unknown'));
    }
  }
}

function thresholdEd25519RecordMatchesLane(
  record: ThresholdEd25519SessionRecord,
  lane: ThresholdEd25519SessionRecordKey,
): boolean {
  return (
    String(record.walletId) === String(lane.walletId) &&
    String(record.nearAccountId) === String(lane.nearAccountId) &&
    String(record.nearEd25519SigningKeyId) === String(lane.nearEd25519SigningKeyId) &&
    thresholdEd25519AuthMethodForRecord(record) === lane.authMethod &&
    String(record.signingGrantId || '').trim() === String(lane.signingGrantId) &&
    String(record.thresholdSessionId || '').trim() === String(lane.thresholdSessionId) &&
    Number(record.signerSlot) === lane.signerSlot
  );
}

function rememberInMemoryThresholdEcdsaRecord(record: ThresholdEcdsaSessionRecord): void {
  const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
  const thresholdSessionId = String(record.thresholdSessionId || '').trim();
  if (!laneKey || !thresholdSessionId) return;
  assertUniqueEvmFamilyEcdsaIdentityForStore({
    recordsByLane: inMemoryEcdsaRecordsByLane,
    incomingLaneKey: laneKey,
    incomingRecord: record,
  });

  const previous = inMemoryEcdsaRecordsByLane.get(laneKey);
  if (previous) {
    deindexThresholdEcdsaRecord(inMemoryEcdsaRecordIndex, laneKey, previous);
  }

  inMemoryEcdsaRecordsByLane.set(laneKey, record);
  indexThresholdEcdsaRecord(inMemoryEcdsaRecordIndex, laneKey, record);
}

function forgetInMemoryThresholdEcdsaRecord(laneKey: string): void {
  const record = inMemoryEcdsaRecordsByLane.get(laneKey);
  if (record) {
    deindexThresholdEcdsaRecord(inMemoryEcdsaRecordIndex, laneKey, record);
  }
  inMemoryEcdsaRecordsByLane.delete(laneKey);
}

export { buildPersistedEcdsaRoleLocalMaterial };
export type { PersistedEcdsaRoleLocalMaterial };

export function requirePersistedEcdsaRoleLocalMaterial(
  record: ThresholdEcdsaSessionRecord,
): PersistedEcdsaRoleLocalMaterial {
  return buildPersistedEcdsaRoleLocalMaterial({
    authority: record.authority,
    materialActivation: record.materialActivation,
    publicFacts: record.ecdsaRoleLocalPublicFacts,
  });
}

function getInMemoryThresholdEcdsaSessionRecordByThresholdSessionId(
  thresholdSessionIdRaw: string,
): ThresholdEcdsaSessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  return selectUniqueThresholdEcdsaRecordByThresholdSessionId({
    thresholdSessionId,
    stores: [
      {
        recordsByLane: inMemoryEcdsaRecordsByLane,
        index: inMemoryEcdsaRecordIndex,
      },
    ],
  });
}

function normalizeThresholdEcdsaSessionStoreSource(
  sourceRaw: unknown,
): ThresholdEcdsaSessionStoreSource | null {
  const source = String(sourceRaw || '').trim();
  if (
    source === 'login' ||
    source === 'registration' ||
    source === 'manual-bootstrap' ||
    source === 'email_otp'
  ) {
    return source;
  }
  return null;
}

function isPasskeyThresholdEcdsaSessionSource(
  source: ThresholdEcdsaSessionStoreSource,
): source is Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'> {
  return source === 'login' || source === 'registration' || source === 'manual-bootstrap';
}

function encodeLaneToken(value: string): string {
  return encodeURIComponent(String(value || '').trim());
}

function decodeLaneToken(value: string): string | null {
  try {
    const decoded = decodeURIComponent(String(value || '').trim());
    return decoded || null;
  } catch {
    return null;
  }
}

function getThresholdEcdsaSessionLaneKeyForRecord(
  record: ThresholdEcdsaSessionRecord,
): ThresholdEcdsaRuntimeLaneKey {
  return thresholdEcdsaLaneKey({
    walletId: record.walletId,
    keyHandle: record.keyHandle,
    authMethod: thresholdEcdsaAuthMethodForRecord(record),
    curve: 'ecdsa',
    chainTarget: record.chainTarget,
    signingGrantId: record.signingGrantId,
    thresholdSessionId: record.thresholdSessionId,
  }) as ThresholdEcdsaRuntimeLaneKey;
}

function selectUniqueThresholdEcdsaRecordByThresholdSessionId(args: {
  thresholdSessionId: string;
  stores: readonly {
    recordsByLane: Map<string, ThresholdEcdsaSessionRecord>;
    index: ThresholdEcdsaRuntimeRecordIndex;
  }[];
}): ThresholdEcdsaSessionRecord | null {
  const unique = new Map<ThresholdEcdsaRuntimeLaneKey, ThresholdEcdsaSessionRecord>();
  const indexKey = ecdsaIndexKey([args.thresholdSessionId]);
  for (const store of args.stores) {
    const laneKeys = store.index.laneKeysByThresholdSessionId.get(indexKey);
    const candidates = indexedThresholdEcdsaRecords({
      recordsByLane: store.recordsByLane,
      laneKeys,
    });
    for (const candidate of candidates) {
      if (String(candidate.thresholdSessionId || '').trim() !== args.thresholdSessionId) continue;
      unique.set(getThresholdEcdsaSessionLaneKeyForRecord(candidate), candidate);
    }
  }

  switch (unique.size) {
    case 0:
      return null;
    case 1: {
      const selected = unique.values().next();
      return selected.done ? null : selected.value;
    }
    default:
      return null;
  }
}

export function deriveThresholdEcdsaRuntimeLaneKey(
  record: ThresholdEcdsaSessionRecord,
): ThresholdEcdsaRuntimeLaneKey {
  return getThresholdEcdsaSessionLaneKeyForRecord(record);
}

function pickPreferredThresholdEcdsaSessionRecord(
  a: ThresholdEcdsaSessionRecord | null,
  b: ThresholdEcdsaSessionRecord,
): ThresholdEcdsaSessionRecord {
  if (!a) return b;
  const aUpdatedAtMs = normalizeInteger(a.updatedAtMs) || 0;
  const bUpdatedAtMs = normalizeInteger(b.updatedAtMs) || 0;
  if (bUpdatedAtMs !== aUpdatedAtMs) {
    return bUpdatedAtMs > aUpdatedAtMs ? b : a;
  }
  const aExpiresAtMs = normalizeInteger(a.expiresAtMs) || 0;
  const bExpiresAtMs = normalizeInteger(b.expiresAtMs) || 0;
  if (bExpiresAtMs !== aExpiresAtMs) {
    return bExpiresAtMs > aExpiresAtMs ? b : a;
  }
  return String(b.thresholdSessionId || '').localeCompare(String(a.thresholdSessionId || '')) > 0
    ? b
    : a;
}

type EcdsaRecordFromBootstrapArgsBase = {
  walletId: WalletId | string;
  authority: WalletAuthAuthorityRef;
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  signingSessionSeal?: {
    signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
    shamirPrimeB64u?: string;
  };
};

type EcdsaRecordFromBootstrapArgs =
  | (EcdsaRecordFromBootstrapArgsBase & {
      purpose: 'transaction_signing';
      source: 'email_otp';
      emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    })
  | (EcdsaRecordFromBootstrapArgsBase & {
      purpose: 'transaction_signing';
      source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
    });

type BuildEcdsaRecordFromBootstrapArgs = EcdsaRecordFromBootstrapArgs & { nowMs: number };

function roleLocalMaterialRefFromBackendBinding(
  binding: ThresholdEcdsaSecp256k1KeyRef['backendBinding'],
): EcdsaRoleLocalPersistedMaterialRef | null {
  if (!binding) return null;
  switch (binding.materialKind) {
    case 'role_local_worker_handle':
      return binding.roleLocalMaterialRef;
    case 'role_local_durable_sealed_ref':
      return binding.roleLocalMaterialRef;
    case 'email_otp_worker_handle':
    case 'role_local_durable_public_anchor':
    case 'role_local_ready_state_blob':
    case 'metadata_only':
      return null;
  }
}

// Bootstrap persistence boundary: normalize raw route/worker output once, then
// store the exact session/grant/material identity used by strict lane readers.
function buildEcdsaRecordFromBootstrap(
  args: BuildEcdsaRecordFromBootstrapArgs,
): ThresholdEcdsaSessionRecord {
  const walletId = toWalletId(args.walletId);
  const authority = parseWalletAuthAuthorityRef(args.authority);
  if (!authority || authority.walletId !== walletId) {
    throw new Error('[SigningEngine] threshold ECDSA bootstrap authority does not match wallet');
  }
  const keyRef = args.bootstrap.thresholdEcdsaKeyRef;
  const keyHandle = String(keyRef.keyHandle || '').trim();
  if (!keyHandle) {
    throw new Error('[SigningEngine] threshold ECDSA bootstrap did not provide keyHandle');
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds(keyRef.participantIds);
  if (!participantIds) {
    throw new Error('[SigningEngine] threshold ECDSA bootstrap did not provide participantIds');
  }
  const thresholdSessionId = String(
    keyRef.thresholdSessionId || args.bootstrap.session.thresholdSessionId || '',
  ).trim();
  if (!thresholdSessionId) {
    throw new Error('[SigningEngine] threshold ECDSA bootstrap did not provide thresholdSessionId');
  }
  const thresholdSessionKind = normalizeThresholdSessionKind(keyRef.thresholdSessionKind || 'jwt');
  const signingGrantId = normalizeOptionalNonEmptyString(
    keyRef.signingGrantId ||
      (args.bootstrap.session as { signingGrantId?: unknown }).signingGrantId,
  );
  const walletSessionJwt = normalizeOptionalNonEmptyString(args.bootstrap.session.jwt);
  const runtimePolicyScope =
    normalizeThresholdRuntimePolicyScope(
      (args.bootstrap.session as { runtimePolicyScope?: unknown }).runtimePolicyScope,
    ) ||
    normalizeThresholdRuntimePolicyScope(parseThresholdRuntimePolicyScopeFromJwt(walletSessionJwt));
  const ecdsaThresholdKeyId = resolveThresholdEcdsaKeyIdFromRecord({
    record: {
      ecdsaThresholdKeyId: keyRef.ecdsaThresholdKeyId,
    },
  });
  const thresholdEcdsaPublicKeyB64u =
    normalizeOptionalNonEmptyString(keyRef.thresholdEcdsaPublicKeyB64u) ||
    normalizeOptionalNonEmptyString(args.bootstrap.keygen.thresholdEcdsaPublicKeyB64u);
  const ethereumAddress =
    normalizeOptionalNonEmptyString(keyRef.ethereumAddress) ||
    normalizeOptionalNonEmptyString(args.bootstrap.keygen.ethereumAddress);
  const roleLocalMaterialRef = roleLocalMaterialRefFromBackendBinding(keyRef.backendBinding);
  if (!roleLocalMaterialRef || keyRef.backendBinding?.materialKind !== 'role_local_worker_handle') {
    throw new Error(
      '[SigningEngine] threshold ECDSA bootstrap did not provide canonical durable role-local material',
    );
  }
  const ecdsaRoleLocalAuthMethod = parseEcdsaRoleLocalAuthMethod(
    keyRef.backendBinding.authMethod,
  );
  const ecdsaRoleLocalPublicFacts = buildEcdsaRoleLocalPublicFacts(
    keyRef.backendBinding.publicFacts,
  );
  const signingSessionSealKeyVersion = args.signingSessionSeal?.signingSessionSealKeyVersion
    ? formatSigningSessionSealKeyVersionForWire(
        args.signingSessionSeal.signingSessionSealKeyVersion,
      )
    : undefined;
  const signingSessionSealShamirPrimeB64u = normalizeOptionalNonEmptyString(
    args.signingSessionSeal?.shamirPrimeB64u,
  );
  if (thresholdSessionKind === 'jwt' && !walletSessionJwt) {
    throw new Error('[SigningEngine] threshold ECDSA bootstrap did not provide walletSessionJwt');
  }
  const signingRootBinding = resolveThresholdSigningRootBindingFromRecord({
    record: {
      signingRootId: ecdsaRoleLocalPublicFacts.signingRootId,
      signingRootVersion: ecdsaRoleLocalPublicFacts.signingRootVersion,
    },
  });
  if (!thresholdEcdsaPublicKeyB64u || !ethereumAddress) {
    throw new Error(
      '[SigningEngine] threshold ECDSA bootstrap did not provide verified public facts',
    );
  }
  const verifiedPublicFacts = buildVerifiedEcdsaPublicFacts({
    keyHandle: toEvmFamilyEcdsaKeyHandle(keyHandle),
    publicKeyB64u: thresholdEcdsaPublicKeyB64u,
    participantIds,
    thresholdOwnerAddress: ethereumAddress,
  });

  const rawRecord = {
    purpose: args.purpose,
    walletId,
    authority,
    materialActivation: roleLocalMaterialRef.materialActivation,
    evmFamilySigningKeySlotId: args.bootstrap.keygen.evmFamilySigningKeySlotId,
    chainTarget: args.chainTarget,
    relayerUrl: keyRef.relayerUrl,
    keyHandle,
    ecdsaThresholdKeyId,
    signingRootId: signingRootBinding.signingRootId,
    ...(signingRootBinding.signingRootVersion
      ? { signingRootVersion: signingRootBinding.signingRootVersion }
      : {}),
    relayerKeyId: keyRef.backendBinding?.relayerKeyId,
    clientVerifyingShareB64u: keyRef.backendBinding?.clientVerifyingShareB64u,
    ecdsaRoleLocalAuthMethod,
    ecdsaRoleLocalPublicFacts,
    participantIds,
    thresholdSessionKind,
    thresholdSessionId,
    ...(signingGrantId ? { signingGrantId } : {}),
    walletSessionJwt: walletSessionJwt,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(keyRef.routerAbEcdsaDerivationNormalSigning
      ? { routerAbEcdsaDerivationNormalSigning: keyRef.routerAbEcdsaDerivationNormalSigning }
      : {}),
    ...(signingSessionSealKeyVersion ? { signingSessionSealKeyVersion } : {}),
    ...(signingSessionSealShamirPrimeB64u ? { signingSessionSealShamirPrimeB64u } : {}),
    expiresAtMs: args.bootstrap.session.expiresAtMs,
    remainingUses: args.bootstrap.session.remainingUses,
    thresholdEcdsaPublicKeyB64u,
    verifiedPublicFacts,
    ethereumAddress,
    relayerVerifyingShareB64u: keyRef.relayerVerifyingShareB64u,
    ...(args.source === 'email_otp' ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
    updatedAtMs: args.nowMs,
    source: args.source,
  };
  return normalizeThresholdEcdsaSessionRecord(rawRecord, 'transaction_signing');
}

function setEcdsaExportArtifactForLane(args: {
  deps: ThresholdEcdsaSessionStoreDeps;
  laneKey: string;
  artifact?: ThresholdEcdsaCanonicalExportArtifact;
}): void {
  if (!args.deps.exportArtifactsByLane) return;
  if (args.artifact) {
    args.deps.exportArtifactsByLane.set(args.laneKey, args.artifact);
    return;
  }
  args.deps.exportArtifactsByLane.delete(args.laneKey);
}

function sameCurrentPasskeyWalletTarget(args: {
  incoming: ThresholdEcdsaSessionRecord;
  existing: ThresholdEcdsaSessionRecord;
}): boolean {
  return (
    isPasskeyThresholdEcdsaSessionSource(args.incoming.source) &&
    isPasskeyThresholdEcdsaSessionSource(args.existing.source) &&
    String(args.incoming.walletId) === String(args.existing.walletId) &&
    thresholdEcdsaChainTargetsEqual(args.incoming.chainTarget, args.existing.chainTarget)
  );
}

function sameEmailOtpAuthorityKey(args: {
  incoming: EmailOtpEcdsaSessionRecord;
  existing: EmailOtpEcdsaSessionRecord;
}): boolean {
  return (
    emailOtpAuthContextProvider(args.incoming.emailOtpAuthContext) ===
      emailOtpAuthContextProvider(args.existing.emailOtpAuthContext) &&
    emailOtpAuthContextProviderUserId(args.incoming.emailOtpAuthContext) ===
      emailOtpAuthContextProviderUserId(args.existing.emailOtpAuthContext)
  );
}

function sameEmailOtpEcdsaLaneGroup(args: {
  incoming: ThresholdEcdsaSessionRecord;
  existing: ThresholdEcdsaSessionRecord;
}): boolean {
  if (args.incoming.source !== 'email_otp' || args.existing.source !== 'email_otp') return false;
  return (
    String(args.incoming.walletId) === String(args.existing.walletId) &&
    String(args.incoming.evmFamilySigningKeySlotId) ===
      String(args.existing.evmFamilySigningKeySlotId) &&
    String(args.incoming.ecdsaThresholdKeyId) === String(args.existing.ecdsaThresholdKeyId) &&
    String(args.incoming.signingRootId) === String(args.existing.signingRootId) &&
    String(args.incoming.signingRootVersion || 'default') ===
      String(args.existing.signingRootVersion || 'default') &&
    sameEmailOtpAuthorityKey({
      incoming: args.incoming,
      existing: args.existing,
    })
  );
}

function sameEmailOtpEcdsaSupersessionTarget(args: {
  incoming: ThresholdEcdsaSessionRecord;
  existing: ThresholdEcdsaSessionRecord;
}): boolean {
  return (
    sameEmailOtpEcdsaLaneGroup(args) &&
    thresholdEcdsaChainTargetsEqual(args.incoming.chainTarget, args.existing.chainTarget)
  );
}

function clearStoredThresholdEcdsaLane(args: {
  deps: ThresholdEcdsaSessionStoreDeps;
  laneKey: string;
}): void {
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(args.deps);
  const persistedRecord = args.deps.recordsByLane.get(args.laneKey);
  if (persistedRecord) {
    deindexThresholdEcdsaRecord(depsIndex, args.laneKey, persistedRecord);
    args.deps.recordsByLane.delete(args.laneKey);
    args.deps.exportArtifactsByLane?.delete(args.laneKey);
  }
  forgetInMemoryThresholdEcdsaRecord(args.laneKey);
}

function thresholdEcdsaSessionId(record: ThresholdEcdsaSessionRecord): string {
  return String(record.thresholdSessionId || '').trim();
}

function sameThresholdEcdsaCurrentCommitTarget(args: {
  incoming: ThresholdEcdsaSessionRecord;
  existing: ThresholdEcdsaSessionRecord;
}): boolean {
  if (args.incoming.source === 'email_otp') {
    return sameEmailOtpEcdsaSupersessionTarget(args);
  }
  return sameCurrentPasskeyWalletTarget(args);
}

function thresholdEcdsaSameTargetRecords(args: {
  deps: ThresholdEcdsaSessionStoreDeps;
  incomingRecord: ThresholdEcdsaSessionRecord;
}): ThresholdEcdsaSessionRecord[] {
  return listAllThresholdEcdsaRecords(args.deps).filter((existingRecord) =>
    sameThresholdEcdsaCurrentCommitTarget({
      incoming: args.incomingRecord,
      existing: existingRecord,
    }),
  );
}

function storeThresholdEcdsaSessionFact(args: {
  deps: ThresholdEcdsaSessionStoreDeps;
  laneKey: string;
  record: ThresholdEcdsaSessionRecord;
}): ThresholdEcdsaSessionRecord {
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(args.deps);
  const previous = args.deps.recordsByLane.get(args.laneKey);
  if (previous) {
    deindexThresholdEcdsaRecord(depsIndex, args.laneKey, previous);
  }
  args.deps.recordsByLane.set(args.laneKey, args.record);
  indexThresholdEcdsaRecord(depsIndex, args.laneKey, args.record);
  rememberInMemoryThresholdEcdsaRecord(args.record);
  return args.record;
}

export function commitCurrentThresholdEcdsaSession(args: {
  deps: ThresholdEcdsaSessionStoreDeps;
  record: ThresholdEcdsaSessionRecord;
}): ThresholdEcdsaSessionCommitResult {
  const incomingRecord = args.record;
  const incomingGeneration = thresholdSessionRecordGeneration(incomingRecord);
  if (!incomingGeneration) {
    throw new Error('Current ECDSA session commit requires server-issued generation');
  }
  const incomingLaneKey = getThresholdEcdsaSessionLaneKeyForRecord(incomingRecord);
  const incomingSessionId = thresholdEcdsaSessionId(incomingRecord);
  const existingRecords = thresholdEcdsaSameTargetRecords({
    deps: args.deps,
    incomingRecord,
  });
  for (const existingRecord of existingRecords) {
    const existingGeneration = thresholdSessionRecordGeneration(existingRecord);
    const existingSessionId = thresholdEcdsaSessionId(existingRecord);
    if (existingSessionId === incomingSessionId) continue;
    if (existingGeneration && existingGeneration > incomingGeneration) {
      return {
        kind: 'stale_commit_ignored',
        incoming: incomingRecord,
        current: existingRecord,
      };
    }
    if (existingGeneration === incomingGeneration) {
      return {
        kind: 'same_generation_distinct_session',
        incoming: incomingRecord,
        existing: existingRecord,
      };
    }
  }

  storeThresholdEcdsaSessionFact({
    deps: args.deps,
    laneKey: incomingLaneKey,
    record: incomingRecord,
  });

  const retired: ThresholdEcdsaSessionRecord[] = [];
  const diagnostics: CurrentSessionRetirementDiagnostic[] = [];
  for (const existingRecord of existingRecords) {
    const existingLaneKey = getThresholdEcdsaSessionLaneKeyForRecord(existingRecord);
    if (existingLaneKey === incomingLaneKey) continue;
    const existingGeneration = thresholdSessionRecordGeneration(existingRecord);
    const shouldRetire =
      thresholdEcdsaSessionId(existingRecord) === incomingSessionId ||
      existingGeneration === null ||
      existingGeneration < incomingGeneration;
    if (!shouldRetire) continue;
    if (existingGeneration === null) {
      diagnostics.push({
        kind: 'retired_null_generation_legacy_fact',
        thresholdSessionId: thresholdEcdsaSessionId(existingRecord),
      });
    }
    clearStoredThresholdEcdsaLane({ deps: args.deps, laneKey: existingLaneKey });
    retired.push(existingRecord);
  }

  return {
    kind: 'committed_current',
    current: incomingRecord,
    retired,
    diagnostics,
  };
}

function requireCommittedThresholdEcdsaSession(
  result: ThresholdEcdsaSessionCommitResult,
): ThresholdEcdsaSessionRecord {
  switch (result.kind) {
    case 'committed_current':
      return result.current;
    case 'same_generation_distinct_session':
      throw new Error('Current ECDSA session commit produced same-generation distinct sessions');
    case 'stale_commit_ignored':
      throw new Error('Current ECDSA session commit was stale');
    default: {
      const exhaustive: never = result;
      throw new Error(String((exhaustive as { kind?: unknown })?.kind || 'unknown'));
    }
  }
}

export function upsertThresholdEcdsaSessionFromBootstrap(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: EcdsaRecordFromBootstrapArgs,
): ThresholdEcdsaSessionRecord {
  const nowMs = Math.max(0, Math.floor((deps.now || Date.now)()));
  const backendBinding = args.bootstrap.thresholdEcdsaKeyRef.backendBinding;
  const roleLocalMaterialHandle =
    backendBinding?.materialKind === 'role_local_worker_handle'
      ? backendBinding.roleLocalMaterialHandle
      : null;
  const roleLocalMaterialRef =
    backendBinding?.materialKind === 'role_local_worker_handle'
      ? backendBinding.roleLocalMaterialRef
      : null;
  const record =
    args.source === 'email_otp'
      ? buildEcdsaRecordFromBootstrap({
          purpose: 'transaction_signing',
          walletId: args.walletId,
          authority: args.authority,
          chainTarget: args.chainTarget,
          bootstrap: args.bootstrap,
          source: 'email_otp',
          emailOtpAuthContext: args.emailOtpAuthContext,
          nowMs,
          ...(args.signingSessionSeal ? { signingSessionSeal: args.signingSessionSeal } : {}),
        })
      : buildEcdsaRecordFromBootstrap({
          purpose: 'transaction_signing',
          walletId: args.walletId,
          authority: args.authority,
          chainTarget: args.chainTarget,
          bootstrap: args.bootstrap,
          source: args.source,
          nowMs,
          ...(args.signingSessionSeal ? { signingSessionSeal: args.signingSessionSeal } : {}),
        });
  const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
  assertUniqueEvmFamilyEcdsaIdentityForStore({
    recordsByLane: deps.recordsByLane,
    incomingLaneKey: laneKey,
    incomingRecord: record,
  });
  assertUniqueEvmFamilyEcdsaIdentityForStore({
    recordsByLane: inMemoryEcdsaRecordsByLane,
    incomingLaneKey: laneKey,
    incomingRecord: record,
  });
  const persistedRoleLocalMaterial = roleLocalMaterialHandle
    ? requirePersistedEcdsaRoleLocalMaterial(record)
    : null;
  if (roleLocalMaterialHandle && roleLocalMaterialRef && persistedRoleLocalMaterial) {
    requireMatchingLiveEcdsaRoleLocalMaterial({
      persistedMaterial: persistedRoleLocalMaterial,
      materialRef: roleLocalMaterialRef,
      liveHandle: roleLocalMaterialHandle,
    });
  }
  requireCommittedThresholdEcdsaSession(
    commitCurrentThresholdEcdsaSession({
      deps,
      record,
    }),
  );
  if (roleLocalMaterialHandle && roleLocalMaterialRef && persistedRoleLocalMaterial) {
    bindLiveEcdsaRoleLocalMaterial({
      persistedMaterial: persistedRoleLocalMaterial,
      materialRef: roleLocalMaterialRef,
      liveHandle: roleLocalMaterialHandle,
    });
  }
  setEcdsaExportArtifactForLane({
    deps,
    laneKey,
    artifact:
      normalizeThresholdEcdsaCanonicalExportArtifact(
        args.bootstrap.thresholdEcdsaKeyRef.ecdsaDerivationExportArtifact,
      ) || undefined,
  });
  return record;
}

export function upsertThresholdEcdsaSessionFact(
  deps: ThresholdEcdsaSessionStoreDeps,
  recordRaw: unknown,
): ThresholdEcdsaSessionRecord {
  const rawObject =
    recordRaw && typeof recordRaw === 'object' ? (recordRaw as Record<string, unknown>) : {};
  const record = normalizeThresholdEcdsaSessionRecord(
    {
      ...rawObject,
      updatedAtMs: Math.max(0, Math.floor((deps.now || Date.now)())),
    },
    'transaction_signing',
  );
  const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
  assertUniqueEvmFamilyEcdsaIdentityForStore({
    recordsByLane: deps.recordsByLane,
    incomingLaneKey: laneKey,
    incomingRecord: record,
  });
  assertUniqueEvmFamilyEcdsaIdentityForStore({
    recordsByLane: inMemoryEcdsaRecordsByLane,
    incomingLaneKey: laneKey,
    incomingRecord: record,
  });
  return storeThresholdEcdsaSessionFact({ deps, laneKey, record });
}

export function upsertRestoredThresholdEcdsaSessionRecord(
  recordRaw: unknown,
): ThresholdEcdsaSessionRecord {
  return upsertThresholdEcdsaSessionFact({ recordsByLane: inMemoryEcdsaRecordsByLane }, recordRaw);
}

export function listThresholdEcdsaSessionRecordsForWalletTarget(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    walletId: WalletId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): ThresholdEcdsaSessionRecord[] {
  const walletId = toWalletId(args.walletId);
  const targetKey = thresholdEcdsaChainTargetKey(args.chainTarget);
  const recordsByLane = new Map<string, ThresholdEcdsaSessionRecord>();
  for (const record of listAllThresholdEcdsaRecords(deps)) {
    if (String(record.walletId) !== String(walletId)) continue;
    if (thresholdEcdsaChainTargetKey(record.chainTarget) !== targetKey) continue;
    if (args.source && record.source !== args.source) continue;
    recordsByLane.set(getThresholdEcdsaSessionLaneKeyForRecord(record), record);
  }
  return Array.from(recordsByLane, ([, record]) => record).sort(
    (left, right) =>
      Math.floor(Number(right.updatedAtMs) || 0) - Math.floor(Number(left.updatedAtMs) || 0),
  );
}

export function getThresholdEcdsaSessionRecordForWalletTarget(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    walletId: WalletId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    source: ThresholdEcdsaSessionStoreSource;
  },
): ThresholdEcdsaSessionRecord {
  const walletId = toWalletId(args.walletId);
  const candidates = listThresholdEcdsaSessionRecordsForWalletTarget(deps, {
    ...args,
    walletId,
  });
  if (candidates.length === 1) return candidates[0]!;
  if (candidates.length > 1) {
    throw new Error(
      `[SigningEngine] ambiguous threshold ECDSA session for wallet ${String(walletId)} ${thresholdEcdsaChainTargetKey(args.chainTarget)}; exact lane identity is required`,
    );
  }

  throw new Error(
    `[SigningEngine] missing concrete threshold ECDSA session for wallet ${String(walletId)} ${thresholdEcdsaChainTargetKey(args.chainTarget)}; reconnect threshold session via bootstrapEcdsaSession`,
  );
}

export function clearThresholdEcdsaSessionRecordForWalletTarget(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    walletId: WalletId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): void {
  const walletId = toWalletId(args.walletId);
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(deps);
  for (const record of listAllThresholdEcdsaRecords(deps)) {
    if (String(record.walletId) !== String(walletId)) continue;
    if (!thresholdEcdsaChainTargetsEqual(record.chainTarget, args.chainTarget)) continue;
    if (args.source && record.source !== args.source) continue;
    const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
    const persistedRecord = deps.recordsByLane.get(laneKey);
    if (persistedRecord) deindexThresholdEcdsaRecord(depsIndex, laneKey, persistedRecord);
    deps.recordsByLane.delete(laneKey);
    deps.exportArtifactsByLane?.delete(laneKey);
    forgetInMemoryThresholdEcdsaRecord(laneKey);
  }
}

export function clearThresholdEcdsaSessionRecordsForWalletTargetKeyHandle(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    walletId: WalletId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    keyHandle: EvmFamilyEcdsaKeyHandle | string;
  },
): number {
  const walletId = toWalletId(args.walletId);
  const keyHandle = normalizeOptionalNonEmptyString(args.keyHandle);
  if (!keyHandle) return 0;
  let removed = 0;
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(deps);
  for (const record of listAllThresholdEcdsaRecords(deps)) {
    if (String(record.walletId) !== String(walletId)) continue;
    if (!thresholdEcdsaChainTargetsEqual(record.chainTarget, args.chainTarget)) continue;
    if (String(record.keyHandle || '').trim() !== keyHandle) continue;
    const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
    const persistedRecord = deps.recordsByLane.get(laneKey);
    if (persistedRecord) deindexThresholdEcdsaRecord(depsIndex, laneKey, persistedRecord);
    deps.recordsByLane.delete(laneKey);
    deps.exportArtifactsByLane?.delete(laneKey);
    forgetInMemoryThresholdEcdsaRecord(laneKey);
    removed += 1;
  }
  return removed;
}

export function clearStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget(args: {
  thresholdSessionId: string;
  chainTarget: ThresholdEcdsaChainTarget;
}): number {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return 0;
  const expectedTargetKey = thresholdEcdsaChainTargetKey(args.chainTarget);
  const laneKeys = inMemoryEcdsaRecordIndex.laneKeysByThresholdSessionId.get(
    ecdsaIndexKey([thresholdSessionId]),
  );
  if (!laneKeys?.size) return 0;
  let removed = 0;
  for (const record of indexedThresholdEcdsaRecords({
    recordsByLane: inMemoryEcdsaRecordsByLane,
    laneKeys,
  })) {
    if (String(record.thresholdSessionId || '').trim() !== thresholdSessionId) continue;
    if (thresholdEcdsaChainTargetKey(record.chainTarget) !== expectedTargetKey) continue;
    const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
    forgetInMemoryThresholdEcdsaRecord(laneKey);
    removed += 1;
  }
  return removed;
}

export function clearStoredThresholdEcdsaSessionRecordsForWalletKeyHandle(args: {
  walletId: WalletId | string;
  keyHandle: EvmFamilyEcdsaKeyHandle | string;
}): number {
  let walletId = '';
  try {
    walletId = String(toWalletId(args.walletId)).trim();
  } catch {
    return 0;
  }
  const keyHandle = normalizeOptionalNonEmptyString(args.keyHandle);
  if (!walletId || !keyHandle) return 0;
  const laneKeys = inMemoryEcdsaRecordIndex.laneKeysByWallet.get(ecdsaIndexKey([walletId]));
  if (!laneKeys?.size) return 0;
  let removed = 0;
  for (const record of indexedThresholdEcdsaRecords({
    recordsByLane: inMemoryEcdsaRecordsByLane,
    laneKeys,
  })) {
    if (String(record.walletId || '').trim() !== walletId) continue;
    if (String(record.keyHandle || '').trim() !== keyHandle) continue;
    const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
    forgetInMemoryThresholdEcdsaRecord(laneKey);
    removed += 1;
  }
  return removed;
}

export function clearAllThresholdEcdsaSessionRecords(deps: ThresholdEcdsaSessionStoreDeps): void {
  deps.recordsByLane.clear();
  deps.exportArtifactsByLane?.clear();
  clearThresholdEcdsaRuntimeRecordIndex(getThresholdEcdsaRuntimeRecordIndex(deps));
  inMemoryEcdsaRecordsByLane.clear();
  clearEcdsaRoleLocalWorkerRuntimeState();
  clearThresholdEcdsaRuntimeRecordIndex(inMemoryEcdsaRecordIndex);
}

export function getStoredThresholdEcdsaSessionRecordByThresholdSessionId(
  thresholdSessionIdRaw: string,
): ThresholdEcdsaSessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  return getInMemoryThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId);
}

export function getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget(args: {
  thresholdSessionId: string;
  chainTarget: ThresholdEcdsaChainTarget;
}): ThresholdEcdsaSessionRecord | null {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return null;
  const expectedTargetKey = thresholdEcdsaChainTargetKey(args.chainTarget);
  const laneKeys = inMemoryEcdsaRecordIndex.laneKeysByThresholdSessionId.get(
    ecdsaIndexKey([thresholdSessionId]),
  );
  const candidates = indexedThresholdEcdsaRecords({
    recordsByLane: inMemoryEcdsaRecordsByLane,
    laneKeys,
  }).filter(
    (record) =>
      String(record.thresholdSessionId || '').trim() === thresholdSessionId &&
      thresholdEcdsaChainTargetKey(record.chainTarget) === expectedTargetKey,
  );
  const unique = new Map<string, ThresholdEcdsaSessionRecord>();
  for (const candidate of candidates) {
    unique.set(getThresholdEcdsaSessionLaneKeyForRecord(candidate), candidate);
  }
  switch (unique.size) {
    case 0:
      return null;
    case 1: {
      const selected = unique.values().next();
      return selected.done ? null : selected.value;
    }
    default:
      return null;
  }
}

export function getThresholdEcdsaSessionRecordByThresholdSessionId(
  deps: ThresholdEcdsaSessionStoreDeps,
  thresholdSessionIdRaw: string,
): ThresholdEcdsaSessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  return selectUniqueThresholdEcdsaRecordByThresholdSessionId({
    thresholdSessionId,
    stores: [
      {
        recordsByLane: deps.recordsByLane,
        index: getThresholdEcdsaRuntimeRecordIndex(deps),
      },
      {
        recordsByLane: inMemoryEcdsaRecordsByLane,
        index: inMemoryEcdsaRecordIndex,
      },
    ],
  });
}

export function buildThresholdEd25519SessionFact(
  args: ThresholdEd25519SessionUpsertInput,
): ThresholdEd25519SessionRecord | null {
  const nearAccountId = toAccountId(args.nearAccountId);
  const rawWalletId = String(args.walletId || '').trim();
  const rawNearEd25519SigningKeyId = String(args.nearEd25519SigningKeyId || '').trim();
  if (!rawWalletId || !rawNearEd25519SigningKeyId) {
    throw new Error(
      'Threshold Ed25519 session persistence requires walletId and nearEd25519SigningKeyId',
    );
  }
  const walletId = toWalletId(rawWalletId);
  const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString(rawNearEd25519SigningKeyId);
  const signerSlot = Math.floor(Number(args.signerSlot) || 0);
  return normalizeThresholdEd25519SessionRecord({
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    rpId: String(args.rpId || '').trim(),
    ...(String(args.passkeyCredentialIdB64u || '').trim()
      ? { passkeyCredentialIdB64u: String(args.passkeyCredentialIdB64u || '').trim() }
      : {}),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    participantIds: args.participantIds,
    ...(String(args.signingRootId || '').trim()
      ? { signingRootId: String(args.signingRootId || '').trim() }
      : {}),
    ...(String(args.signingRootVersion || '').trim()
      ? { signingRootVersion: String(args.signingRootVersion || '').trim() }
      : {}),
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    signerSlot,
    routerAbNormalSigning: args.routerAbNormalSigning,
    thresholdSessionKind: String(args.thresholdSessionKind || 'jwt')
      .trim()
      .toLowerCase(),
    thresholdSessionId: String(args.thresholdSessionId || '').trim(),
    ...(String(args.signingGrantId || '').trim()
      ? { signingGrantId: String(args.signingGrantId || '').trim() }
      : {}),
    ...(String(args.walletSessionJwt || '').trim()
      ? { walletSessionJwt: String(args.walletSessionJwt || '').trim() }
      : {}),
    expiresAtMs: Math.floor(Number(args.expiresAtMs) || 0),
    remainingUses: Math.floor(Number(args.remainingUses) || 0),
    ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
    updatedAtMs: Math.floor(Number(args.updatedAtMs ?? Date.now()) || 0),
    source: args.source || 'manual-connect',
  });
}

export function upsertThresholdEd25519SessionFact(
  args: ThresholdEd25519SessionUpsertInput,
): ThresholdEd25519SessionRecord | null {
  const record = buildThresholdEd25519SessionFact(args);
  if (!record) return null;
  return storeThresholdEd25519SessionFact({
    record,
    defaultPolicy: 'prefer_current_generation',
  });
}

/**
 * Re-seeds the in-memory runtime cache from a persisted Ed25519 session record
 * (e.g. after a page/iframe refresh wipes runtime state) so account-, wallet-,
 * and session-keyed readers resolve it again. Uses the generation-monotonic
 * 'prefer_current_generation' policy so it never downgrades a fresher in-flight
 * record. Only identity/metadata is seeded — ephemeral auth material (wallet
 * session JWT / PRF claim) is not persisted, so a rehydrated record still
 * derives as auth_missing and forces step-up re-auth before any signing.
 */
export function rememberPersistedThresholdEd25519RuntimeRecord(
  record: ThresholdEd25519SessionRecord,
): ThresholdEd25519SessionRecord {
  return storeThresholdEd25519SessionFact({
    record,
    defaultPolicy: 'prefer_current_generation',
  });
}

// Broad Ed25519 wallet/account readers expose default/discovery records only.
// Authority-bearing mutations must use exact lane-key helpers.
export function getStoredThresholdEd25519SessionRecordForAccount(
  nearAccountIdRaw: AccountId | string,
): ThresholdEd25519SessionRecord | null {
  const inMemory = getInMemoryThresholdEd25519SessionRecordForAccount(nearAccountIdRaw);
  if (inMemory) return inMemory;
  return null;
}

export function getStoredThresholdEd25519SessionRecordForWallet(
  walletIdRaw: WalletId | string,
): ThresholdEd25519SessionRecord | null {
  const inMemory = getInMemoryThresholdEd25519SessionRecordForWallet(walletIdRaw);
  if (inMemory) return inMemory;
  return null;
}

export function listStoredThresholdEd25519SessionRecordsForAccount(
  nearAccountIdRaw: AccountId | string,
): ThresholdEd25519SessionRecord[] {
  try {
    const accountKey = String(toAccountId(nearAccountIdRaw)).trim();
    const record = accountKey ? inMemoryEd25519RecordsByAccount.get(accountKey) || null : null;
    return record ? [record] : [];
  } catch {
    return [];
  }
}

export function listStoredThresholdEd25519SessionRecordsForWallet(
  walletIdRaw: WalletId | string,
): ThresholdEd25519SessionRecord[] {
  try {
    const walletKey = String(toWalletId(walletIdRaw)).trim();
    const record = walletKey ? inMemoryEd25519RecordsByWallet.get(walletKey) || null : null;
    return record ? [record] : [];
  } catch {
    return [];
  }
}

export function listStoredThresholdEd25519SessionLaneRecordsForAccount(
  nearAccountIdRaw: AccountId | string,
): ThresholdEd25519SessionRecord[] {
  try {
    const accountKey = String(toAccountId(nearAccountIdRaw)).trim();
    if (!accountKey) return [];
    const recordsBySessionId = new Map<string, ThresholdEd25519SessionRecord>();
    const add = (record: ThresholdEd25519SessionRecord | null): void => {
      if (!record) return;
      if (String(record.nearAccountId || '').trim() !== accountKey) return;
      const thresholdSessionId = String(record.thresholdSessionId || '').trim();
      if (!thresholdSessionId) return;
      recordsBySessionId.set(thresholdSessionId, record);
    };
    add(inMemoryEd25519RecordsByAccount.get(accountKey) || null);
    for (const record of inMemoryEd25519RecordsByLane.values()) {
      add(record);
    }
    return [...recordsBySessionId.values()].sort(
      (left, right) =>
        Math.floor(Number(right.updatedAtMs) || 0) - Math.floor(Number(left.updatedAtMs) || 0),
    );
  } catch {
    return [];
  }
}

export function listStoredThresholdEd25519SessionLaneRecordsForWallet(
  walletIdRaw: WalletId | string,
): ThresholdEd25519SessionRecord[] {
  try {
    const walletKey = String(toWalletId(walletIdRaw)).trim();
    if (!walletKey) return [];
    const recordsBySessionId = new Map<string, ThresholdEd25519SessionRecord>();
    const add = (record: ThresholdEd25519SessionRecord | null): void => {
      if (!record) return;
      if (String(record.walletId || '').trim() !== walletKey) return;
      const thresholdSessionId = String(record.thresholdSessionId || '').trim();
      if (!thresholdSessionId) return;
      recordsBySessionId.set(thresholdSessionId, record);
    };
    add(inMemoryEd25519RecordsByWallet.get(walletKey) || null);
    for (const record of inMemoryEd25519RecordsByLane.values()) {
      add(record);
    }
    return [...recordsBySessionId.values()].sort(
      (left, right) =>
        Math.floor(Number(right.updatedAtMs) || 0) - Math.floor(Number(left.updatedAtMs) || 0),
    );
  } catch {
    return [];
  }
}

export function listStoredThresholdEcdsaSessionRecordsForWallet(
  walletIdRaw: WalletId | string,
  filter: {
    chainTarget?: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  } = {},
): ThresholdEcdsaSessionRecord[] {
  let walletKey = '';
  try {
    walletKey = String(toWalletId(walletIdRaw)).trim();
  } catch {
    return [];
  }
  if (!walletKey) return [];

  const records: ThresholdEcdsaSessionRecord[] = [];
  const seen = new Set<string>();
  const laneKeys = inMemoryEcdsaRecordIndex.laneKeysByWallet.get(ecdsaIndexKey([walletKey]));
  const filterTargetKey = filter.chainTarget
    ? thresholdEcdsaChainTargetKey(filter.chainTarget)
    : null;
  for (const record of indexedThresholdEcdsaRecords({
    recordsByLane: inMemoryEcdsaRecordsByLane,
    laneKeys,
  })) {
    if (filterTargetKey && thresholdEcdsaChainTargetKey(record.chainTarget) !== filterTargetKey) {
      continue;
    }
    if (filter.source && record.source !== filter.source) continue;
    const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
    if (!laneKey || seen.has(laneKey)) continue;
    seen.add(laneKey);
    records.push(record);
  }

  return records.sort(
    (left, right) =>
      Math.floor(Number(right.updatedAtMs) || 0) - Math.floor(Number(left.updatedAtMs) || 0),
  );
}

export function getStoredThresholdEd25519SessionRecordForLane(args: {
  walletId: WalletId | string;
  nearAccountId: AccountId | string;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId | string;
  authMethod: ThresholdEd25519SessionAuthMethod;
  signingGrantId: SigningGrantId | string;
  thresholdSessionId: ThresholdEd25519SessionId | string;
  signerSlot: unknown;
}): ThresholdEd25519SessionRecord | null {
  let lane: ThresholdEd25519SessionRecordKey;
  let laneKey: string;
  try {
    lane = buildThresholdEd25519SessionRecordKey(args);
    laneKey = serializeThresholdEd25519SessionLaneKey(lane);
  } catch {
    return null;
  }
  const record = inMemoryEd25519RecordsByLane.get(laneKey) || null;
  if (record && thresholdEd25519RecordMatchesLane(record, lane)) return record;
  if (record) {
    inMemoryEd25519RecordsByLane.delete(laneKey);
    const thresholdSessionId = String(record.thresholdSessionId || '').trim();
    if (thresholdSessionId && inMemoryEd25519LaneBySessionId.get(thresholdSessionId) === laneKey) {
      inMemoryEd25519LaneBySessionId.delete(thresholdSessionId);
    }
  }
  return null;
}

export type ClearStoredThresholdEd25519SessionRecordForLaneKeyResult =
  | { readonly ok: true; readonly cleared: boolean }
  | {
      readonly ok: false;
      readonly code: 'mismatched_record';
      readonly message: string;
    };

export function clearStoredThresholdEd25519SessionRecordForLaneKey(
  lane: ThresholdEd25519SessionRecordKey,
): ClearStoredThresholdEd25519SessionRecordForLaneKeyResult {
  const laneKey = serializeThresholdEd25519SessionLaneKey(lane);
  const record = inMemoryEd25519RecordsByLane.get(laneKey) || null;
  if (!record) return { ok: true, cleared: false };
  if (!thresholdEd25519RecordMatchesLane(record, lane)) {
    return {
      ok: false,
      code: 'mismatched_record',
      message: '[SigningEngine] threshold Ed25519 lane clear refused mismatched record',
    };
  }
  forgetInMemoryThresholdEd25519Record(record);
  return { ok: true, cleared: true };
}

export function clearStoredThresholdEd25519SessionRecordForExactIdentity(
  identity: ExactEd25519SigningLaneIdentity,
): ClearStoredThresholdEd25519SessionRecordForLaneKeyResult {
  return clearStoredThresholdEd25519SessionRecordForLaneKey(
    thresholdEd25519SessionRecordKeyFromExactIdentity(identity),
  );
}

export type RetireRecoveredPasskeyThresholdEd25519SessionsResult = {
  readonly retired: number;
};

export function retireRecoveredPasskeyThresholdEd25519Sessions(args: {
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: SignerSlot;
  retainedThresholdSessionId: ThresholdEd25519SessionId;
}): RetireRecoveredPasskeyThresholdEd25519SessionsResult {
  const walletId = String(args.walletId).trim();
  const nearAccountId = String(args.nearAccountId).trim();
  const nearEd25519SigningKeyId = String(args.nearEd25519SigningKeyId).trim();
  const signerSlot = parseSignerSlot(args.signerSlot);
  const retainedThresholdSessionId = String(args.retainedThresholdSessionId).trim();
  if (
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !signerSlot ||
    !retainedThresholdSessionId
  ) {
    throw new Error(
      '[SigningEngine] recovered Ed25519 session retirement requires exact lane identity',
    );
  }

  const retiredRecords = [...inMemoryEd25519RecordsByLane.values()].filter((record) => {
    if (record.source === 'email_otp') return false;
    if (String(record.walletId || '').trim() !== walletId) return false;
    if (String(record.nearAccountId || '').trim() !== nearAccountId) return false;
    if (String(record.nearEd25519SigningKeyId || '').trim() !== nearEd25519SigningKeyId) {
      return false;
    }
    if (parseSignerSlot(record.signerSlot) !== signerSlot) return false;
    if (String(record.thresholdSessionId || '').trim() === retainedThresholdSessionId) {
      return false;
    }
    return true;
  });

  for (const record of retiredRecords) {
    forgetInMemoryThresholdEd25519Record(record);
  }

  return { retired: retiredRecords.length };
}

export function markThresholdEd25519EmailOtpSessionConsumedForWallet(args: {
  walletId: WalletId;
  thresholdSessionId?: string;
  uses?: number;
  nowMs?: number;
}): ThresholdEd25519SessionRecord | null {
  const record = getStoredThresholdEd25519SessionRecordForWallet(args.walletId);
  if (!record || record.source !== 'email_otp' || !record.emailOtpAuthContext) return null;
  const expectedSessionId = String(args.thresholdSessionId || '').trim();
  const actualSessionId = String(record.thresholdSessionId || '').trim();
  if (expectedSessionId && actualSessionId && expectedSessionId !== actualSessionId) {
    return null;
  }
  const nowMs = Math.max(0, Math.floor(Number(args.nowMs ?? Date.now()) || 0));
  const uses = Math.max(1, Math.floor(Number(args.uses) || 1));
  const remainingUses = Math.max(0, Math.floor(Number(record.remainingUses) || 0) - uses);
  return upsertThresholdEd25519SessionFact({
    walletId: record.walletId,
    nearAccountId: record.nearAccountId,
    nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
    rpId: record.rpId,
    relayerUrl: record.relayerUrl,
    relayerKeyId: record.relayerKeyId,
    participantIds: record.participantIds,
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    signerSlot: record.signerSlot,
    routerAbNormalSigning: record.routerAbNormalSigning,
    thresholdSessionKind: record.thresholdSessionKind,
    thresholdSessionId: record.thresholdSessionId,
    ...(record.signingGrantId ? { signingGrantId: record.signingGrantId } : {}),
    ...(record.walletSessionJwt ? { walletSessionJwt: record.walletSessionJwt } : {}),
    expiresAtMs: record.expiresAtMs,
    remainingUses,
    emailOtpAuthContext: buildEmailOtpAuthContext({
      policy: record.emailOtpAuthContext.policy,
      retention: 'single_use',
      authority: record.emailOtpAuthContext.authority,
      consumedAtMs: nowMs,
    }),
    updatedAtMs: nowMs,
    source: 'email_otp',
  });
}

export function getStoredThresholdEd25519SessionRecordByThresholdSessionId(
  thresholdSessionIdRaw: string,
): ThresholdEd25519SessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  const inMemory = getInMemoryThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
  if (inMemory) return inMemory;
  return null;
}

export function clearAllStoredThresholdEd25519SessionRecords(): void {
  inMemoryEd25519RecordsByAccount.clear();
  inMemoryEd25519AccountBySessionId.clear();
  inMemoryEd25519RecordsByWallet.clear();
  inMemoryEd25519WalletBySessionId.clear();
  inMemoryEd25519RecordsByLane.clear();
  inMemoryEd25519LaneBySessionId.clear();
}

export function getStoredThresholdEcdsaSessionRecordForWalletChain(args: {
  walletId: WalletId | string;
  chain: ThresholdEcdsaChainTarget['kind'];
}): ThresholdEcdsaSessionRecord | null {
  const walletId = toWalletId(args.walletId);
  let selected: ThresholdEcdsaSessionRecord | null = null;
  for (const record of indexedThresholdEcdsaRecords({
    recordsByLane: inMemoryEcdsaRecordsByLane,
    laneKeys: inMemoryEcdsaRecordIndex.laneKeysByWallet.get(ecdsaIndexKey([String(walletId)])),
  })) {
    if (record.chainTarget.kind !== args.chain) continue;
    selected = pickPreferredThresholdEcdsaSessionRecord(selected, record);
  }
  return selected;
}

export function getStoredThresholdSessionRecordByThresholdSessionId<
  TCurve extends ThresholdSessionCurve,
>(args: {
  curve: TCurve;
  thresholdSessionId: string;
}): ThresholdSessionRecordByCurve[TCurve] | null {
  if (args.curve === 'ecdsa') {
    return getStoredThresholdEcdsaSessionRecordByThresholdSessionId(args.thresholdSessionId) as
      | ThresholdSessionRecordByCurve[TCurve]
      | null;
  }
  return getStoredThresholdEd25519SessionRecordByThresholdSessionId(args.thresholdSessionId) as
    | ThresholdSessionRecordByCurve[TCurve]
    | null;
}

export function clearAllStoredThresholdSessionRecords(curve?: ThresholdSessionCurve): void {
  if (!curve || curve === 'ed25519') {
    clearAllStoredThresholdEd25519SessionRecords();
  }
  if (!curve || curve === 'ecdsa') {
    inMemoryEcdsaRecordsByLane.clear();
    clearEcdsaRoleLocalWorkerRuntimeState();
    clearThresholdEcdsaRuntimeRecordIndex(inMemoryEcdsaRecordIndex);
  }
}
