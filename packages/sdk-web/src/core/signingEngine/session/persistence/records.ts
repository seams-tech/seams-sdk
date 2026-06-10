import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  normalizeInteger,
  normalizeOptionalNonEmptyString,
  normalizePositiveInteger,
} from '@shared/utils/normalize';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type {
  EcdsaLaneCandidate,
  Ed25519LaneCandidate,
  LaneCandidateState,
  SelectedEcdsaLane,
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
  ThresholdEd25519SessionStoreSource,
} from '../identity/laneIdentity';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import { THRESHOLD_ECDSA_SESSION_STORE_SOURCES } from '../identity/laneIdentity';
import type {
  ThresholdEcdsaClientAdditiveShareHandle,
  EcdsaThresholdKeyId,
  ThresholdEcdsaCanonicalExportArtifact,
  ThresholdEcdsaSecp256k1KeyRef,
} from '../../interfaces/signing';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaLaneKey,
  type ThresholdEcdsaSessionRecordKey,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
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
  type EvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyIdentity,
  type EvmFamilyEcdsaSessionLane,
  type ResolvedEvmFamilyEcdsaKey,
  type VerifiedEcdsaPublicFacts,
} from '../identity/evmFamilyEcdsaIdentity';
import { buildThresholdEcdsaSecp256k1KeyRefFromRecord } from '../identity/thresholdEcdsaSignerAdapter';
import {
  SigningSessionIds,
  type ThresholdEcdsaSessionId,
  type WalletSigningSessionId,
} from '../operationState/types';
import {
  normalizeThresholdSessionKind,
  normalizeThresholdRuntimePolicyScope,
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
} from '../../threshold/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { EcdsaRoleLocalReadyRecord } from '@/core/platform/types';
import { parseEcdsaRoleLocalReadyRecord } from './ecdsaRoleLocalRecords';

export type ThresholdSessionCurve = 'ed25519' | 'ecdsa';

export type ThresholdEcdsaSessionAuthMetadata = {
  rpId: string;
};

type ThresholdEcdsaSessionRecordCore = {
  walletId: AccountId;
  // Compatibility boundary only; current records persist rpId in authMetadata.
  rpId?: string;
  authMetadata: ThresholdEcdsaSessionAuthMetadata;
  chainTarget: ThresholdEcdsaChainTarget;
  relayerUrl: string;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: string;
  signingRootVersion?: string;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  clientAdditiveShareHandle?: ThresholdEcdsaClientAdditiveShareHandle;
  ecdsaRoleLocalReadyRecord: EcdsaRoleLocalReadyRecord;
  participantIds: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  thresholdSessionKind: 'jwt' | 'cookie';
  thresholdSessionId: string;
  walletSigningSessionId: string;
  thresholdSessionAuthToken?: string;
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
  clientAdditiveShareHandle?: ThresholdEcdsaClientAdditiveShareHandle;
};

export type ReadyEmailOtpEcdsaSessionRecord = NormalizedThresholdEcdsaSessionRecordShared & {
  source: 'email_otp';
  clientAdditiveShareHandle?: ThresholdEcdsaClientAdditiveShareHandle;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
};

export type NormalizedThresholdEcdsaSessionRecord =
  | ReadyPasskeyEcdsaSessionRecord
  | ReadyEmailOtpEcdsaSessionRecord;

export type ThresholdEcdsaSessionRecord = NormalizedThresholdEcdsaSessionRecord;

export function thresholdEcdsaEmailOtpAuthContext(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): ThresholdEcdsaEmailOtpAuthContext | null {
  return record?.source === 'email_otp' ? record.emailOtpAuthContext : null;
}

export type ThresholdEcdsaRuntimeLaneKey = string & {
  readonly __brand: 'ThresholdEcdsaRuntimeLaneKey';
};

export type PositiveRemainingUses = number & {
  readonly __brand: 'PositiveRemainingUses';
};

export type ExactEcdsaLaneIdentity = {
  kind: 'exact_ecdsa_lane_identity';
  walletId: AccountId;
  authMethod: 'email_otp' | 'passkey';
  chainTarget: ThresholdEcdsaChainTarget;
  key: EvmFamilyEcdsaKeyIdentity;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEcdsaSessionId;
};

export type ExactEcdsaRuntimeLaneRef = {
  kind: 'exact_ecdsa_runtime_lane_ref';
  laneKey: ThresholdEcdsaRuntimeLaneKey;
  exactIdentity: ExactEcdsaLaneIdentity;
  expectedUpdatedAtMs: number;
};

export type ConsumableEmailOtpEcdsaLane = {
  kind: 'consumable_email_otp_ecdsa_lane';
  laneRef: ExactEcdsaRuntimeLaneRef;
  remainingUses: 1;
  consumedAtMs: null;
};

export type SessionEmailOtpEcdsaLane = {
  kind: 'session_email_otp_ecdsa_lane';
  laneRef: ExactEcdsaRuntimeLaneRef;
  remainingUses: PositiveRemainingUses;
  consumedAtMs?: never;
};

export type EmailOtpEcdsaPostSignMaterial = ConsumableEmailOtpEcdsaLane | SessionEmailOtpEcdsaLane;

export type ConsumeSingleUseEmailOtpEcdsaLaneCommand = {
  kind: 'consume_single_use_email_otp_ecdsa_lane';
  lane: ConsumableEmailOtpEcdsaLane;
  uses: 1;
  subjectId?: never;
  chainTarget?: never;
  thresholdSessionId?: never;
  walletSigningSessionId?: never;
};

export type ConsumeSingleUseEmailOtpEcdsaLaneResult =
  | {
      kind: 'consumed';
      laneKey: ThresholdEcdsaRuntimeLaneKey;
      consumedAtMs: number;
    }
  | {
      kind: 'already_consumed';
      laneKey: ThresholdEcdsaRuntimeLaneKey;
      consumedAtMs: number;
    }
  | {
      kind: 'missing_lane';
      laneKey: ThresholdEcdsaRuntimeLaneKey;
    }
  | {
      kind: 'stale_record';
      laneKey: ThresholdEcdsaRuntimeLaneKey;
      reason:
        | 'lane_key_mismatch'
        | 'updated_at_mismatch'
        | 'remaining_uses_mismatch'
        | 'wallet_mismatch'
        | 'key_identity_mismatch'
        | 'auth_method_mismatch'
        | 'chain_target_mismatch'
        | 'session_identity_mismatch'
        | 'retention_mismatch';
    };

export type ThresholdEd25519SessionRecord = {
  nearAccountId: AccountId;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  xClientBaseB64u?: string;
  thresholdSessionKind: 'jwt' | 'cookie';
  thresholdSessionId: string;
  walletSigningSessionId?: string;
  thresholdSessionAuthToken?: string;
  expiresAtMs: number;
  remainingUses: number;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  updatedAtMs: number;
  source: ThresholdEd25519SessionStoreSource;
};

export type ThresholdSessionRecordByCurve = {
  ed25519: ThresholdEd25519SessionRecord;
  ecdsa: ThresholdEcdsaSessionRecord;
};

export type ThresholdEcdsaSessionAuthTokenSource = 'ecdsa' | 'ed25519' | 'none';

export type ThresholdSessionSealTransportAuthMaterial =
  | {
      curve: 'ed25519';
      walletId?: string;
      relayerUrl: string;
      walletSigningSessionId?: string;
      thresholdSessionAuthToken?: string;
      thresholdSessionAuthTokenSource: ThresholdEcdsaSessionAuthTokenSource;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    }
  | {
      curve: 'ecdsa';
      walletId?: string;
      chainTarget: ThresholdEcdsaChainTarget;
      relayerUrl: string;
      walletSigningSessionId?: string;
      thresholdSessionAuthToken?: string;
      thresholdSessionAuthTokenSource: ThresholdEcdsaSessionAuthTokenSource;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };

export type ThresholdEcdsaSessionStoreDeps = {
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>;
  exportArtifactsByLane?: Map<string, ThresholdEcdsaCanonicalExportArtifact>;
  now?: () => number;
};

export type ThresholdEcdsaKeyRefLookupResult = {
  source: ThresholdEcdsaSessionStoreSource;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
};

export type ThresholdEcdsaSessionRecordReadModel = {
  record: ThresholdEcdsaSessionRecord;
  key: EvmFamilyEcdsaKeyIdentity;
  resolvedKey?: ResolvedEvmFamilyEcdsaKey;
  lane: EvmFamilyEcdsaSessionLane;
};

export type ThresholdEcdsaRuntimeRecordCandidate = {
  source: 'runtime_session_record';
  walletId: AccountId;
  key: EvmFamilyEcdsaKeyIdentity;
  resolvedKey?: ResolvedEvmFamilyEcdsaKey;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  verifiedPublicFacts?: VerifiedEcdsaPublicFacts;
  thresholdEcdsaPublicKeyB64u: string;
  lane: EvmFamilyEcdsaSessionLane;
  authMethod: 'email_otp' | 'passkey';
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  walletSigningSessionId: string;
  thresholdSessionId: string;
  remainingUses?: number;
  expiresAtMs?: number;
  updatedAtMs?: number;
};

export type ThresholdEcdsaSessionRecordLookupKey =
  | ThresholdEcdsaSessionRecordKey
  | SelectedEcdsaLane;

function normalizeThresholdEcdsaSessionAuthMetadata(
  value: unknown,
): ThresholdEcdsaSessionAuthMetadata | null {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  const rpId = normalizeOptionalNonEmptyString(obj?.rpId);
  return rpId ? { rpId } : null;
}

export function thresholdEcdsaRecordRpId(record: {
  authMetadata?: {
    rpId?: unknown;
  } | null;
  rpId?: unknown;
}): string {
  const metadataRpId = normalizeOptionalNonEmptyString(record.authMetadata?.rpId);
  if (metadataRpId) return metadataRpId;
  const legacyRpId = normalizeOptionalNonEmptyString(record.rpId);
  if (legacyRpId) return legacyRpId;
  throw new Error('[SigningEngine] threshold ECDSA session record is missing auth rpId');
}

function thresholdEcdsaAuthMethodForRecord(
  record: ThresholdEcdsaSessionRecord,
): 'email_otp' | 'passkey' {
  return record.source === 'email_otp' ? 'email_otp' : 'passkey';
}

function thresholdEcdsaResolvedKeyFromRecord(
  record: ThresholdEcdsaSessionRecord,
): ResolvedEvmFamilyEcdsaKey | null {
  if (thresholdEcdsaAuthMethodForRecord(record) !== 'passkey') return null;
  if (!record.verifiedPublicFacts) return null;
  try {
    return buildResolvedEvmFamilyEcdsaKey({
      walletId: record.walletId,
      publicFacts: record.verifiedPublicFacts,
      authBinding: buildPasskeyEcdsaAuthBinding({
        rpId: thresholdEcdsaRecordRpId(record),
      }),
    });
  } catch {
    return null;
  }
}

export function thresholdEcdsaSessionRecordReadModel(
  record: ThresholdEcdsaSessionRecord,
): ThresholdEcdsaSessionRecordReadModel {
  const key = buildEvmFamilyEcdsaKeyIdentityFromRecord({
    record,
    rpId: thresholdEcdsaRecordRpId(record),
  });
  const resolvedKey = thresholdEcdsaResolvedKeyFromRecord(record);
  const lane = buildEvmFamilyEcdsaSessionLane({
    key,
    chainTarget: record.chainTarget,
    authMethod: thresholdEcdsaAuthMethodForRecord(record),
    source: record.source,
    thresholdSessionId: record.thresholdSessionId,
    walletSigningSessionId: record.walletSigningSessionId,
    thresholdSessionKind: record.thresholdSessionKind,
    thresholdSessionAuthToken: record.thresholdSessionAuthToken,
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

function evmFamilyEcdsaSharedContextKey(key: EvmFamilyEcdsaKeyIdentity): string {
  return ecdsaIndexKey([
    key.walletId,
    deriveBaseEcdsaSubjectIdFromWalletId(key.walletId),
    key.rpId,
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
  const incomingContextKey = evmFamilyEcdsaSharedContextKey(incoming);
  const incomingIdentityValue = evmFamilyEcdsaIdentityValue(incoming);

  for (const [storedLaneKey, storedRecord] of args.recordsByLane.entries()) {
    if (storedLaneKey === args.incomingLaneKey) continue;
    let stored: EvmFamilyEcdsaKeyIdentity;
    try {
      stored = thresholdEcdsaSessionRecordReadModel(storedRecord).key;
    } catch {
      continue;
    }
    if (evmFamilyEcdsaSharedContextKey(stored) !== incomingContextKey) continue;
    if (evmFamilyEcdsaIdentityValue(stored) === incomingIdentityValue) continue;
    throw new Error(
      '[SigningEngine] EVM-family ECDSA key identity already exists for wallet/subject/rp/signing root',
    );
  }
}

function thresholdEcdsaRecordMatchesLookupKey(args: {
  record: ThresholdEcdsaSessionRecord;
  identity: ThresholdEcdsaSessionRecordLookupKey;
}): boolean {
  let readModel: ThresholdEcdsaSessionRecordReadModel;
  try {
    readModel = thresholdEcdsaSessionRecordReadModel(args.record);
  } catch {
    return false;
  }
  const identity = args.identity;
  return (
    String(readModel.key.walletId) === String(identity.walletId) &&
    String(args.record.keyHandle) === String(identity.keyHandle) &&
    readModel.lane.authMethod === identity.authMethod &&
    identity.curve === 'ecdsa' &&
    thresholdEcdsaChainTargetsEqual(readModel.lane.chainTarget, identity.chainTarget) &&
    String(readModel.lane.walletSigningSessionId) === String(identity.walletSigningSessionId) &&
    String(readModel.lane.thresholdSessionId) === String(identity.thresholdSessionId)
  );
}

function thresholdEcdsaRuntimeRecordCandidateLaneKey(
  candidate: ThresholdEcdsaRuntimeRecordCandidate,
): string {
  return thresholdEcdsaLaneKey({
    walletId: candidate.walletId,
    keyHandle: candidate.keyHandle,
    authMethod: candidate.authMethod,
    curve: 'ecdsa',
    chainTarget: candidate.chainTarget,
    walletSigningSessionId: candidate.walletSigningSessionId,
    thresholdSessionId: candidate.thresholdSessionId,
  });
}

function laneCandidateStateFromRuntimePolicy(args: {
  remainingUses: number;
  expiresAtMs: number;
  nowMs?: number;
}): LaneCandidateState {
  if (args.remainingUses <= 0) return 'exhausted';
  const nowMs = Math.floor(Number(args.nowMs) || Date.now());
  if (args.expiresAtMs <= nowMs) return 'expired';
  return 'ready';
}

function nullableRecordInteger(value: unknown): number | null {
  const normalized = normalizeInteger(value);
  return normalized == null ? null : normalized;
}

export function thresholdEcdsaLaneCandidateFromSessionRecord(args: {
  record: ThresholdEcdsaSessionRecord;
  nowMs?: number;
}): EcdsaLaneCandidate {
  const resolvedKey = thresholdEcdsaResolvedKeyFromRecord(args.record);
  return {
    kind: 'lane_candidate',
    walletId: args.record.walletId,
    key: buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: args.record,
      rpId: thresholdEcdsaRecordRpId(args.record),
    }),
    ...(resolvedKey ? { resolvedKey } : {}),
    keyHandle: args.record.keyHandle,
    authMethod: thresholdEcdsaAuthMethodForRecord(args.record),
    curve: 'ecdsa',
    chain: args.record.chainTarget.kind,
    chainTarget: args.record.chainTarget,
    walletSigningSessionId: args.record.walletSigningSessionId,
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
      canonicalRecord = normalizeThresholdEcdsaSessionRecord(record);
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
    artifactKind !== 'ecdsa-hss-secp256k1-export' ||
    !chainTarget ||
    !signingRootId ||
    !publicKeyHex ||
    !privateKeyHex ||
    !ethereumAddress
  ) {
    return null;
  }
  return {
    artifactKind: 'ecdsa-hss-secp256k1-export',
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

function normalizeStoredVerifiedPublicFacts(args: {
  rawVerifiedPublicFacts: unknown;
  keyHandle: string;
  thresholdEcdsaPublicKeyB64u: string | null | undefined;
  participantIds: readonly number[];
  thresholdOwnerAddress: string;
}): VerifiedEcdsaPublicFacts | null {
  const raw =
    args.rawVerifiedPublicFacts &&
    typeof args.rawVerifiedPublicFacts === 'object' &&
    !Array.isArray(args.rawVerifiedPublicFacts)
      ? (args.rawVerifiedPublicFacts as Record<string, unknown>)
      : null;
  const keyHandle = normalizeOptionalNonEmptyString(raw?.keyHandle) || args.keyHandle;
  const publicKeyB64u =
    normalizeOptionalNonEmptyString(raw?.publicKeyB64u) || args.thresholdEcdsaPublicKeyB64u;
  const thresholdOwnerAddress =
    normalizeOptionalNonEmptyString(raw?.thresholdOwnerAddress) || args.thresholdOwnerAddress;
  const participantIds = raw?.participantIds ?? args.participantIds;

  if (!keyHandle || !publicKeyB64u || !thresholdOwnerAddress) return null;
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

function normalizeThresholdEcdsaSessionRecord(value: unknown): ThresholdEcdsaSessionRecord {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
  const walletId = toAccountId(String(obj.walletId || '').trim());
  const authMetadata = normalizeThresholdEcdsaSessionAuthMetadata(obj.authMetadata);
  const rpId = authMetadata?.rpId || normalizeOptionalNonEmptyString(obj.rpId) || '';
  const relayerUrl = String(obj.relayerUrl || '').trim();
  const keyHandle = normalizeOptionalNonEmptyString(obj.keyHandle);
  const relayerKeyId = String(obj.relayerKeyId || '').trim();
  const clientVerifyingShareB64u = String(obj.clientVerifyingShareB64u || '').trim();
  const clientAdditiveShareHandle = normalizeThresholdEcdsaClientAdditiveShareHandle(
    obj.clientAdditiveShareHandle,
  );
  const participantIds = normalizeThresholdEd25519ParticipantIds(obj.participantIds);
  const thresholdSessionKind = normalizeThresholdSessionKind(obj.thresholdSessionKind);
  const thresholdSessionId = String(obj.thresholdSessionId || '').trim();
  const walletSigningSessionId = normalizeOptionalNonEmptyString(obj.walletSigningSessionId);
  const thresholdSessionAuthToken = normalizeOptionalNonEmptyString(obj.thresholdSessionAuthToken);
  const signingSessionSealKeyVersion = normalizeOptionalNonEmptyString(
    obj.signingSessionSealKeyVersion,
  );
  const signingSessionSealShamirPrimeB64u = normalizeOptionalNonEmptyString(
    obj.signingSessionSealShamirPrimeB64u,
  );
  const runtimePolicyScope = normalizeStoredRuntimePolicyScope(obj, thresholdSessionAuthToken);
  const ecdsaThresholdKeyId = String(obj.ecdsaThresholdKeyId || '').trim();
  if (!ecdsaThresholdKeyId) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: missing ecdsaThresholdKeyId',
    );
  }
  const signingRootBinding = normalizeStoredSigningRootBinding(obj, runtimePolicyScope);
  const sourceRaw = String(obj.source || '').trim();
  const source: ThresholdEcdsaSessionStoreSource =
    sourceRaw === 'login' ||
    sourceRaw === 'registration' ||
    sourceRaw === 'manual-bootstrap' ||
    sourceRaw === 'email_otp'
      ? sourceRaw
      : 'manual-bootstrap';
  const chainTarget = normalizeOptionalRuntimeChainTarget(obj.chainTarget);
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
  const ecdsaRoleLocalReadyRecord = normalizeEcdsaRoleLocalReadyRecord(
    obj.ecdsaRoleLocalReadyRecord,
  );

  if (
    !relayerUrl ||
    !rpId ||
    !keyHandle ||
    !relayerKeyId ||
    !clientVerifyingShareB64u ||
    !participantIds ||
    !thresholdSessionId ||
    !walletSigningSessionId ||
    !chainTarget ||
    !ethereumAddress
  ) {
    throw new Error('Invalid threshold ECDSA canonical session record');
  }
  if (normalizeOptionalNonEmptyString(obj.subjectId)) {
    throw new Error('Invalid threshold ECDSA canonical session record: unexpected subjectId');
  }
  if (obj.ecdsaHssRoleLocalClientState !== undefined && obj.ecdsaHssRoleLocalClientState !== null) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: deleted ecdsaHssRoleLocalClientState',
    );
  }
  if (!ecdsaRoleLocalReadyRecord) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: missing role-local ready record (ecdsaRoleLocalReadyRecord)',
    );
  }
  if (thresholdSessionKind === 'jwt' && !thresholdSessionAuthToken) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: missing threshold session auth token',
    );
  }
  if (expiresAtMs == null || expiresAtMs <= 0) {
    throw new Error('Invalid threshold ECDSA canonical session record: missing expiresAtMs');
  }
  if (remainingUses == null || remainingUses < 0) {
    throw new Error('Invalid threshold ECDSA canonical session record: missing remainingUses');
  }
  const verifiedPublicFacts = normalizeStoredVerifiedPublicFacts({
    rawVerifiedPublicFacts: obj.verifiedPublicFacts,
    keyHandle,
    thresholdEcdsaPublicKeyB64u,
    participantIds,
    thresholdOwnerAddress: ethereumAddress,
  });
  if (!verifiedPublicFacts) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: missing verifiedPublicFacts',
    );
  }
  const sharedRecord = {
    walletId,
    authMetadata: { rpId },
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
    ecdsaRoleLocalReadyRecord,
    participantIds,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    thresholdSessionKind,
    thresholdSessionId,
    walletSigningSessionId,
    ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
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
    if (!emailOtpAuthContext) {
      throw new Error(
        'Invalid threshold ECDSA canonical session record: missing Email OTP context',
      );
    }
    return {
      ...sharedRecord,
      ...(clientAdditiveShareHandle ? { clientAdditiveShareHandle } : {}),
      emailOtpAuthContext,
      source,
    };
  }
  return {
    ...sharedRecord,
    source,
  };
}

export function parseRawThresholdEcdsaSessionRecord(
  value: RawThresholdEcdsaSessionRecord | unknown,
): ThresholdEcdsaSessionRecord {
  return normalizeThresholdEcdsaSessionRecord(value);
}

function normalizeEcdsaRoleLocalReadyRecord(value: unknown): EcdsaRoleLocalReadyRecord | null {
  if (value === undefined || value === null) return null;
  return parseEcdsaRoleLocalReadyRecord(value);
}

function normalizeThresholdEcdsaClientAdditiveShareHandle(
  value: unknown,
): ThresholdEcdsaClientAdditiveShareHandle | null {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
  const kind = String(obj.kind || '').trim();
  const sessionId = String(obj.sessionId || '').trim();
  if (kind !== 'email_otp_worker_session' || !sessionId) return null;
  return {
    kind: 'email_otp_worker_session',
    sessionId,
  };
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
  const retentionRaw = String(obj.retention || '')
    .trim()
    .toLowerCase();
  if (retentionRaw !== 'session' && retentionRaw !== 'single_use') {
    throw new Error('Invalid Email OTP auth context: invalid retention');
  }
  const retention: 'session' | 'single_use' = retentionRaw;
  if (policy === 'per_operation' && retention !== 'single_use') {
    throw new Error('Invalid Email OTP auth context: per-operation sessions must be single-use');
  }
  const reasonRaw = String(obj.reason || '')
    .trim()
    .toLowerCase();
  if (reasonRaw !== 'login' && reasonRaw !== 'sign') {
    throw new Error('Invalid Email OTP auth context: invalid reason');
  }
  const authMethodRaw = String(obj.authMethod || '')
    .trim()
    .toLowerCase();
  if (authMethodRaw !== 'email_otp') {
    throw new Error('Invalid Email OTP auth context: invalid authMethod');
  }
  const reason: 'login' | 'sign' = reasonRaw;
  const authSubjectId = normalizeOptionalNonEmptyString(obj.authSubjectId);
  const consumedAtMs = normalizePositiveInteger(obj.consumedAtMs);
  return {
    policy,
    retention,
    reason,
    authMethod: 'email_otp',
    ...(authSubjectId ? { authSubjectId } : {}),
    ...(consumedAtMs ? { consumedAtMs } : {}),
  };
}

function normalizeThresholdEd25519SessionRecord(value: unknown): ThresholdEd25519SessionRecord {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
  const nearAccountId = toAccountId(String(obj.nearAccountId || '').trim());
  const rpId = String(obj.rpId || '').trim();
  const relayerUrl = String(obj.relayerUrl || '').trim();
  const relayerKeyId = String(obj.relayerKeyId || '').trim();
  const participantIds = normalizeThresholdEd25519ParticipantIds(obj.participantIds);
  const runtimePolicyScope = normalizeStoredRuntimePolicyScope(obj);
  const xClientBaseB64u = normalizeOptionalNonEmptyString(obj.xClientBaseB64u);
  const thresholdSessionKindRaw = String(obj.thresholdSessionKind || 'jwt')
    .trim()
    .toLowerCase();
  const thresholdSessionKind: 'jwt' | 'cookie' =
    thresholdSessionKindRaw === 'cookie' ? 'cookie' : 'jwt';
  const thresholdSessionId = String(obj.thresholdSessionId || '').trim();
  const walletSigningSessionId = normalizeOptionalNonEmptyString(obj.walletSigningSessionId);
  const thresholdSessionAuthToken = normalizeOptionalNonEmptyString(obj.thresholdSessionAuthToken);
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  const remainingUses = normalizeInteger(obj.remainingUses);
  const updatedAtMs = normalizeInteger(obj.updatedAtMs) || Date.now();
  const sourceRaw = String(obj.source || '').trim();
  const source: ThresholdEd25519SessionStoreSource =
    sourceRaw === 'login' ||
    sourceRaw === 'registration' ||
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
  if (thresholdSessionKind === 'jwt' && !thresholdSessionAuthToken) {
    throw new Error(
      'Invalid threshold Ed25519 canonical session record: missing threshold session auth token',
    );
  }
  if (expiresAtMs == null || expiresAtMs <= 0) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing expiresAtMs');
  }
  if (remainingUses == null || remainingUses < 0) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing remainingUses');
  }

  return {
    nearAccountId,
    rpId,
    relayerUrl,
    relayerKeyId,
    participantIds,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(xClientBaseB64u ? { xClientBaseB64u } : {}),
    thresholdSessionKind,
    thresholdSessionId,
    ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
    ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
    expiresAtMs,
    remainingUses,
    ...(emailOtpAuthContext ? { emailOtpAuthContext } : {}),
    updatedAtMs,
    source,
  };
}

function rememberInMemoryThresholdEd25519Record(record: ThresholdEd25519SessionRecord): void {
  const accountKey = String(record.nearAccountId || '').trim();
  const thresholdSessionId = String(record.thresholdSessionId || '').trim();
  if (!accountKey || !thresholdSessionId) return;

  const previous = inMemoryEd25519RecordsByAccount.get(accountKey);
  const previousSessionId = String(previous?.thresholdSessionId || '').trim();
  if (previousSessionId && previousSessionId !== thresholdSessionId) {
    inMemoryEd25519AccountBySessionId.delete(previousSessionId);
  }

  // The account index tracks the default lane; the lane/session indexes retain
  // exact in-flight sessions so concurrent step-up operations cannot displace
  // each other's planned material.
  inMemoryEd25519RecordsByAccount.set(accountKey, record);
  inMemoryEd25519AccountBySessionId.set(thresholdSessionId, accountKey);

  const laneKey = getThresholdEd25519SessionLaneKeyForRecord(record);
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

  return null;
}

type ThresholdEd25519SessionAuthMethod = 'email_otp' | 'passkey';

export type ThresholdEd25519SessionRecordKey = {
  nearAccountId: AccountId;
  authMethod: ThresholdEd25519SessionAuthMethod;
  walletSigningSessionId: string;
  thresholdSessionId: string;
};

function thresholdEd25519AuthMethodForRecord(
  record: ThresholdEd25519SessionRecord,
): ThresholdEd25519SessionAuthMethod {
  return record.source === 'email_otp' ? 'email_otp' : 'passkey';
}

export function thresholdEd25519LaneCandidateFromSessionRecord(args: {
  record: ThresholdEd25519SessionRecord;
  nowMs?: number;
}): Ed25519LaneCandidate | null {
  const walletSigningSessionId = normalizeOptionalNonEmptyString(
    args.record.walletSigningSessionId,
  );
  if (!walletSigningSessionId) return null;
  return {
    kind: 'lane_candidate',
    accountId: args.record.nearAccountId,
    authMethod: thresholdEd25519AuthMethodForRecord(args.record),
    curve: 'ed25519',
    chain: 'near',
    walletSigningSessionId,
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
  nearAccountId: AccountId | string;
  authMethod: ThresholdEd25519SessionAuthMethod;
  walletSigningSessionId: string;
  thresholdSessionId: string;
}): string {
  const nearAccountId = String(toAccountId(args.nearAccountId)).trim();
  const authMethod = String(args.authMethod || '').trim();
  const walletSigningSessionId = normalizeOptionalNonEmptyString(args.walletSigningSessionId);
  const thresholdSessionId = normalizeOptionalNonEmptyString(args.thresholdSessionId);
  if (
    !nearAccountId ||
    (authMethod !== 'email_otp' && authMethod !== 'passkey') ||
    !walletSigningSessionId ||
    !thresholdSessionId
  ) {
    throw new Error('[SigningEngine] invalid threshold Ed25519 lane key input');
  }
  return [
    encodeLaneToken(nearAccountId),
    encodeLaneToken(authMethod),
    encodeLaneToken(walletSigningSessionId),
    encodeLaneToken(thresholdSessionId),
  ].join('|');
}

function getThresholdEd25519SessionLaneKeyForRecord(
  record: ThresholdEd25519SessionRecord,
): string | null {
  const walletSigningSessionId = normalizeOptionalNonEmptyString(record.walletSigningSessionId);
  const thresholdSessionId = normalizeOptionalNonEmptyString(record.thresholdSessionId);
  if (!walletSigningSessionId || !thresholdSessionId) return null;
  try {
    return serializeThresholdEd25519SessionLaneKey({
      nearAccountId: record.nearAccountId,
      authMethod: thresholdEd25519AuthMethodForRecord(record),
      walletSigningSessionId,
      thresholdSessionId,
    });
  } catch {
    return null;
  }
}

function thresholdEd25519RecordMatchesLane(
  record: ThresholdEd25519SessionRecord,
  lane: ThresholdEd25519SessionRecordKey,
): boolean {
  return (
    String(record.nearAccountId) === String(lane.nearAccountId) &&
    thresholdEd25519AuthMethodForRecord(record) === lane.authMethod &&
    String(record.walletSigningSessionId || '').trim() === lane.walletSigningSessionId &&
    String(record.thresholdSessionId || '').trim() === lane.thresholdSessionId
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

function getInMemoryThresholdEcdsaSessionRecordByThresholdSessionId(
  thresholdSessionIdRaw: string,
): ThresholdEcdsaSessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;

  const laneKeys = inMemoryEcdsaRecordIndex.laneKeysByThresholdSessionId.get(
    ecdsaIndexKey([thresholdSessionId]),
  );
  return (
    indexedThresholdEcdsaRecords({
      recordsByLane: inMemoryEcdsaRecordsByLane,
      laneKeys,
    })[0] || null
  );
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
    walletSigningSessionId: record.walletSigningSessionId,
    thresholdSessionId: record.thresholdSessionId,
  }) as ThresholdEcdsaRuntimeLaneKey;
}

export function deriveThresholdEcdsaRuntimeLaneKey(
  record: ThresholdEcdsaSessionRecord,
): ThresholdEcdsaRuntimeLaneKey {
  return getThresholdEcdsaSessionLaneKeyForRecord(record);
}

function positiveRemainingUses(value: number): PositiveRemainingUses | null {
  const remainingUses = Math.floor(Number(value) || 0);
  return remainingUses > 0 ? (remainingUses as PositiveRemainingUses) : null;
}

function normalizedConsumedAtMs(record: ThresholdEcdsaSessionRecord): number | null {
  const consumedAtMs = Math.floor(Number(thresholdEcdsaEmailOtpAuthContext(record)?.consumedAtMs));
  return Number.isFinite(consumedAtMs) && consumedAtMs > 0 ? consumedAtMs : null;
}

function normalizedUpdatedAtMs(record: ThresholdEcdsaSessionRecord): number {
  const updatedAtMs = Math.floor(Number(record.updatedAtMs) || 0);
  return Number.isFinite(updatedAtMs) && updatedAtMs > 0 ? updatedAtMs : 0;
}

function isSelectedEcdsaLane(
  input: ThresholdEcdsaSessionRecord | SelectedEcdsaLane,
): input is SelectedEcdsaLane {
  return (input as { kind?: unknown }).kind === 'selected_lane';
}

export function toExactEcdsaLaneIdentity(
  input: ThresholdEcdsaSessionRecord | SelectedEcdsaLane,
): ExactEcdsaLaneIdentity {
  if (isSelectedEcdsaLane(input)) {
    return {
      kind: 'exact_ecdsa_lane_identity',
      walletId: input.walletId,
      authMethod: input.authMethod,
      chainTarget: input.chainTarget,
      key: input.key,
      walletSigningSessionId: input.walletSigningSessionId,
      thresholdSessionId: input.thresholdSessionId,
    };
  }
  return {
    kind: 'exact_ecdsa_lane_identity',
    walletId: input.walletId,
    authMethod: thresholdEcdsaAuthMethodForRecord(input),
    chainTarget: input.chainTarget,
    key: buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: input,
      rpId: thresholdEcdsaRecordRpId(input),
    }),
    walletSigningSessionId: SigningSessionIds.walletSigningSession(input.walletSigningSessionId),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(input.thresholdSessionId),
  };
}

function toExactEcdsaRuntimeLaneRef(record: ThresholdEcdsaSessionRecord): ExactEcdsaRuntimeLaneRef {
  return {
    kind: 'exact_ecdsa_runtime_lane_ref',
    laneKey: deriveThresholdEcdsaRuntimeLaneKey(record),
    exactIdentity: toExactEcdsaLaneIdentity(record),
    expectedUpdatedAtMs: normalizedUpdatedAtMs(record),
  };
}

export function emailOtpEcdsaPostSignMaterialFromRecord(
  record: ThresholdEcdsaSessionRecord,
): EmailOtpEcdsaPostSignMaterial | null {
  if (record.source !== 'email_otp') return null;
  if (record.emailOtpAuthContext?.authMethod !== 'email_otp') return null;
  const remainingUses = Math.floor(Number(record.remainingUses) || 0);
  const laneRef = toExactEcdsaRuntimeLaneRef(record);
  if (record.emailOtpAuthContext.retention === 'single_use') {
    if (remainingUses !== 1 || normalizedConsumedAtMs(record) !== null) return null;
    return {
      kind: 'consumable_email_otp_ecdsa_lane',
      laneRef,
      remainingUses: 1,
      consumedAtMs: null,
    };
  }
  const sessionRemainingUses = positiveRemainingUses(remainingUses);
  return sessionRemainingUses
    ? {
        kind: 'session_email_otp_ecdsa_lane',
        laneRef,
        remainingUses: sessionRemainingUses,
      }
    : null;
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
  walletId: AccountId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  signingSessionSeal?: {
    keyVersion?: string;
    shamirPrimeB64u?: string;
  };
};

type EcdsaRecordFromBootstrapArgs =
  | (EcdsaRecordFromBootstrapArgsBase & {
      source: 'email_otp';
      emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    })
  | (EcdsaRecordFromBootstrapArgsBase & {
      source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
    });

type BuildEcdsaRecordFromBootstrapArgs = EcdsaRecordFromBootstrapArgs & {
  nowMs: number;
};

function buildEcdsaRecordFromBootstrap(
  args: BuildEcdsaRecordFromBootstrapArgs,
): ThresholdEcdsaSessionRecord {
  const accountId = toAccountId(args.walletId);
  const keyRef = args.bootstrap.thresholdEcdsaKeyRef;
  const keyHandle = String(keyRef.keyHandle || '').trim();
  if (!keyHandle) {
    throw new Error('[SigningEngine] threshold ECDSA bootstrap did not provide keyHandle');
  }
  const canonicalKeyHandle = toEvmFamilyEcdsaKeyHandle(keyHandle);
  const participantIds = normalizeThresholdEd25519ParticipantIds(keyRef.participantIds);
  if (!participantIds) {
    throw new Error('[SigningEngine] threshold ECDSA bootstrap did not provide participantIds');
  }
  const thresholdSessionId = String(
    keyRef.thresholdSessionId || args.bootstrap.session.sessionId || '',
  ).trim();
  if (!thresholdSessionId) {
    throw new Error('[SigningEngine] threshold ECDSA bootstrap did not provide thresholdSessionId');
  }
  const thresholdSessionKind = normalizeThresholdSessionKind(keyRef.thresholdSessionKind || 'jwt');
  const walletSigningSessionId = normalizeOptionalNonEmptyString(
    keyRef.walletSigningSessionId ||
      (args.bootstrap.session as { walletSigningSessionId?: unknown }).walletSigningSessionId,
  );
  const thresholdSessionAuthToken = normalizeOptionalNonEmptyString(
    keyRef.thresholdSessionAuthToken || args.bootstrap.session.jwt,
  );
  const runtimePolicyScope =
    normalizeThresholdRuntimePolicyScope(
      (args.bootstrap.session as { runtimePolicyScope?: unknown }).runtimePolicyScope,
    ) ||
    normalizeThresholdRuntimePolicyScope(
      parseThresholdRuntimePolicyScopeFromJwt(thresholdSessionAuthToken),
    );
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
  const signingRootBinding = resolveThresholdSigningRootBindingFromRecord({
    record: {
      keyHandle: canonicalKeyHandle,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      signingRootId: keyRef.signingRootId,
      signingRootVersion: keyRef.signingRootVersion,
    },
  });
  const clientAdditiveShareHandle = normalizeThresholdEcdsaClientAdditiveShareHandle(
    keyRef.backendBinding?.clientAdditiveShareHandle,
  );
  const ecdsaRoleLocalReadyRecord = normalizeEcdsaRoleLocalReadyRecord(
    keyRef.backendBinding?.ecdsaRoleLocalReadyRecord,
  );
  const signingSessionSealKeyVersion = normalizeOptionalNonEmptyString(
    args.signingSessionSeal?.keyVersion,
  );
  const signingSessionSealShamirPrimeB64u = normalizeOptionalNonEmptyString(
    args.signingSessionSeal?.shamirPrimeB64u,
  );
  if (thresholdSessionKind === 'jwt' && !thresholdSessionAuthToken) {
    throw new Error(
      '[SigningEngine] threshold ECDSA bootstrap did not provide thresholdSessionAuthToken',
    );
  }
  if (!ecdsaRoleLocalReadyRecord) {
    throw new Error(
      '[SigningEngine] threshold ECDSA bootstrap did not provide role-local ready record',
    );
  }

  return normalizeThresholdEcdsaSessionRecord({
    walletId: accountId,
    authMetadata: { rpId: args.bootstrap.keygen.rpId },
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
    ...(clientAdditiveShareHandle ? { clientAdditiveShareHandle } : {}),
    ecdsaRoleLocalReadyRecord,
    participantIds,
    thresholdSessionKind,
    thresholdSessionId,
    ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
    thresholdSessionAuthToken,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(signingSessionSealKeyVersion ? { signingSessionSealKeyVersion } : {}),
    ...(signingSessionSealShamirPrimeB64u ? { signingSessionSealShamirPrimeB64u } : {}),
    expiresAtMs: args.bootstrap.session.expiresAtMs,
    remainingUses: args.bootstrap.session.remainingUses,
    thresholdEcdsaPublicKeyB64u,
    ethereumAddress,
    relayerVerifyingShareB64u: keyRef.relayerVerifyingShareB64u,
    ...(args.source === 'email_otp' ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
    updatedAtMs: args.nowMs,
    source: args.source,
  });
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

function clearConflictingCurrentPasskeyThresholdEcdsaRecords(args: {
  deps: ThresholdEcdsaSessionStoreDeps;
  incomingLaneKey: string;
  incomingRecord: ThresholdEcdsaSessionRecord;
}): void {
  if (!isPasskeyThresholdEcdsaSessionSource(args.incomingRecord.source)) {
    return;
  }

  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(args.deps);
  for (const record of listAllThresholdEcdsaRecords(args.deps)) {
    const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
    if (laneKey === args.incomingLaneKey) continue;
    if (
      !sameCurrentPasskeyWalletTarget({
        incoming: args.incomingRecord,
        existing: record,
      })
    ) {
      continue;
    }

    const persistedRecord = args.deps.recordsByLane.get(laneKey);
    if (persistedRecord) {
      deindexThresholdEcdsaRecord(depsIndex, laneKey, persistedRecord);
      args.deps.recordsByLane.delete(laneKey);
      args.deps.exportArtifactsByLane?.delete(laneKey);
    }
    forgetInMemoryThresholdEcdsaRecord(laneKey);
  }
}

export function upsertThresholdEcdsaSessionFromBootstrap(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: EcdsaRecordFromBootstrapArgs,
): ThresholdEcdsaSessionRecord {
  const nowMs = Math.max(0, Math.floor((deps.now || Date.now)()));
  const record =
    args.source === 'email_otp'
      ? buildEcdsaRecordFromBootstrap({
          walletId: args.walletId,
          chainTarget: args.chainTarget,
          bootstrap: args.bootstrap,
          source: 'email_otp',
          emailOtpAuthContext: args.emailOtpAuthContext,
          nowMs,
          ...(args.signingSessionSeal ? { signingSessionSeal: args.signingSessionSeal } : {}),
        })
      : buildEcdsaRecordFromBootstrap({
          walletId: args.walletId,
          chainTarget: args.chainTarget,
          bootstrap: args.bootstrap,
          source: args.source,
          nowMs,
          ...(args.signingSessionSeal ? { signingSessionSeal: args.signingSessionSeal } : {}),
        });
  const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(deps);
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
  clearConflictingCurrentPasskeyThresholdEcdsaRecords({
    deps,
    incomingLaneKey: laneKey,
    incomingRecord: record,
  });
  const previous = deps.recordsByLane.get(laneKey);
  if (previous) {
    deindexThresholdEcdsaRecord(depsIndex, laneKey, previous);
  }
  deps.recordsByLane.set(laneKey, record);
  indexThresholdEcdsaRecord(depsIndex, laneKey, record);
  rememberInMemoryThresholdEcdsaRecord(record);
  setEcdsaExportArtifactForLane({
    deps,
    laneKey,
    artifact:
      normalizeThresholdEcdsaCanonicalExportArtifact(
        args.bootstrap.thresholdEcdsaKeyRef.ecdsaHssExportArtifact,
      ) || undefined,
  });
  return record;
}

export function upsertStoredThresholdEcdsaSessionRecord(
  deps: ThresholdEcdsaSessionStoreDeps,
  recordRaw: unknown,
): ThresholdEcdsaSessionRecord {
  const rawObject =
    recordRaw && typeof recordRaw === 'object' ? (recordRaw as Record<string, unknown>) : {};
  const record = normalizeThresholdEcdsaSessionRecord({
    ...rawObject,
    updatedAtMs: Math.max(0, Math.floor((deps.now || Date.now)())),
  });
  const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(deps);
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
  clearConflictingCurrentPasskeyThresholdEcdsaRecords({
    deps,
    incomingLaneKey: laneKey,
    incomingRecord: record,
  });
  const previous = deps.recordsByLane.get(laneKey);
  if (previous) {
    deindexThresholdEcdsaRecord(depsIndex, laneKey, previous);
  }
  deps.recordsByLane.set(laneKey, record);
  indexThresholdEcdsaRecord(depsIndex, laneKey, record);
  rememberInMemoryThresholdEcdsaRecord(record);
  return record;
}

export function listThresholdEcdsaSessionRecordsForWalletTarget(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    walletId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): ThresholdEcdsaSessionRecord[] {
  const walletId = toAccountId(args.walletId);
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
    walletId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    source: ThresholdEcdsaSessionStoreSource;
  },
): ThresholdEcdsaSessionRecord {
  const walletId = toAccountId(args.walletId);
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

export function getThresholdEcdsaSessionRecordByKey(
  deps: ThresholdEcdsaSessionStoreDeps,
  identity: ThresholdEcdsaSessionRecordLookupKey,
): ThresholdEcdsaSessionRecord | null {
  const laneKey = thresholdEcdsaLaneKey(identity);
  const record = deps.recordsByLane.get(laneKey) || inMemoryEcdsaRecordsByLane.get(laneKey) || null;
  if (!record) return null;
  return thresholdEcdsaRecordMatchesLookupKey({ record, identity }) ? record : null;
}

function thresholdEcdsaKeyRefFromRecord(
  deps: ThresholdEcdsaSessionStoreDeps,
  record: ThresholdEcdsaSessionRecord,
): ThresholdEcdsaSecp256k1KeyRef {
  const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
  const ecdsaHssExportArtifact = deps.exportArtifactsByLane?.get(laneKey);
  return buildThresholdEcdsaSecp256k1KeyRefFromRecord({
    record,
    ...(ecdsaHssExportArtifact ? { exportArtifact: ecdsaHssExportArtifact } : {}),
  });
}

export function listThresholdEcdsaKeyRefsForWalletTarget(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    walletId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): ThresholdEcdsaKeyRefLookupResult[] {
  return listThresholdEcdsaSessionRecordsForWalletTarget(deps, args).map((record) => ({
    source: record.source,
    keyRef: thresholdEcdsaKeyRefFromRecord(deps, record),
  }));
}

export function getThresholdEcdsaKeyRefByKey(
  deps: ThresholdEcdsaSessionStoreDeps,
  identity: ThresholdEcdsaSessionRecordLookupKey,
): ThresholdEcdsaKeyRefLookupResult | null {
  const record = getThresholdEcdsaSessionRecordByKey(deps, identity);
  return record
    ? {
        source: record.source,
        keyRef: thresholdEcdsaKeyRefFromRecord(deps, record),
      }
    : null;
}

export function getEmailOtpThresholdEcdsaSessionRecordForSigning(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
  },
): ThresholdEcdsaSessionRecord {
  return getThresholdEcdsaSessionRecordForWalletTarget(deps, {
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    source: 'email_otp',
  });
}

export function getEmailOtpThresholdEcdsaKeyRefForSigning(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
  },
): ThresholdEcdsaSecp256k1KeyRef {
  const record = getEmailOtpThresholdEcdsaSessionRecordForSigning(deps, args);
  return thresholdEcdsaKeyRefFromRecord(deps, record);
}

export function getPasskeyThresholdEcdsaSessionRecordForSigning(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  },
): ThresholdEcdsaSessionRecord {
  return getThresholdEcdsaSessionRecordForWalletTarget(deps, {
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    source: args.source,
  });
}

export function getPasskeyThresholdEcdsaKeyRefForSigning(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  },
): ThresholdEcdsaSecp256k1KeyRef {
  const record = getPasskeyThresholdEcdsaSessionRecordForSigning(deps, args);
  return thresholdEcdsaKeyRefFromRecord(deps, record);
}

export function clearThresholdEcdsaSessionRecordForWallet(
  deps: ThresholdEcdsaSessionStoreDeps,
  walletId: AccountId | string,
): void {
  const normalizedWalletId = toAccountId(walletId);
  const walletKey = String(normalizedWalletId);
  const indexKey = ecdsaIndexKey([walletKey]);
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(deps);
  for (const laneKey of [...(depsIndex.laneKeysByWallet.get(indexKey) || [])]) {
    const record = deps.recordsByLane.get(laneKey);
    if (record) deindexThresholdEcdsaRecord(depsIndex, laneKey, record);
    deps.recordsByLane.delete(laneKey);
    deps.exportArtifactsByLane?.delete(laneKey);
  }
  for (const laneKey of [...(inMemoryEcdsaRecordIndex.laneKeysByWallet.get(indexKey) || [])]) {
    forgetInMemoryThresholdEcdsaRecord(laneKey);
  }
}

export function clearThresholdEcdsaSessionRecordForWalletTarget(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    walletId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): void {
  const walletId = toAccountId(args.walletId);
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
    walletId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    keyHandle: EvmFamilyEcdsaKeyHandle | string;
  },
): number {
  const walletId = toAccountId(args.walletId);
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
  walletId: AccountId | string;
  keyHandle: EvmFamilyEcdsaKeyHandle | string;
}): number {
  let walletId = '';
  try {
    walletId = String(toAccountId(args.walletId)).trim();
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

function exactEcdsaLaneIdentityMismatchReason(args: {
  expected: ExactEcdsaLaneIdentity;
  actual: ExactEcdsaLaneIdentity;
}): Extract<ConsumeSingleUseEmailOtpEcdsaLaneResult, { kind: 'stale_record' }>['reason'] | null {
  if (String(args.actual.walletId) !== String(args.expected.walletId)) return 'wallet_mismatch';
  if (args.actual.authMethod !== args.expected.authMethod) return 'auth_method_mismatch';
  if (!thresholdEcdsaChainTargetsEqual(args.actual.chainTarget, args.expected.chainTarget)) {
    return 'chain_target_mismatch';
  }
  if (
    String(args.actual.walletSigningSessionId) !== String(args.expected.walletSigningSessionId) ||
    String(args.actual.thresholdSessionId) !== String(args.expected.thresholdSessionId)
  ) {
    return 'session_identity_mismatch';
  }
  if (!exactEcdsaKeyIdentityMatches(args.actual.key, args.expected.key)) {
    return 'key_identity_mismatch';
  }
  return null;
}

function exactEcdsaKeyIdentityMatches(
  left: EvmFamilyEcdsaKeyIdentity,
  right: EvmFamilyEcdsaKeyIdentity,
): boolean {
  if (String(left.walletId) !== String(right.walletId)) return false;
  if (String(left.rpId) !== String(right.rpId)) return false;
  if (String(left.keyScope) !== String(right.keyScope)) return false;
  if (String(left.ecdsaThresholdKeyId) !== String(right.ecdsaThresholdKeyId)) return false;
  if (String(left.signingRootId) !== String(right.signingRootId)) return false;
  if (String(left.signingRootVersion) !== String(right.signingRootVersion)) return false;
  if (String(left.thresholdOwnerAddress) !== String(right.thresholdOwnerAddress)) return false;
  const leftParticipants = left.participantIds.map((participantId) => Number(participantId));
  const rightParticipants = right.participantIds.map((participantId) => Number(participantId));
  if (leftParticipants.length !== rightParticipants.length) return false;
  return leftParticipants.every(
    (participantId, index) => participantId === rightParticipants[index],
  );
}

function staleSingleUseEmailOtpEcdsaLaneResult(args: {
  laneKey: ThresholdEcdsaRuntimeLaneKey;
  reason: Extract<ConsumeSingleUseEmailOtpEcdsaLaneResult, { kind: 'stale_record' }>['reason'];
}): ConsumeSingleUseEmailOtpEcdsaLaneResult {
  return {
    kind: 'stale_record',
    laneKey: args.laneKey,
    reason: args.reason,
  };
}

export function consumeSingleUseEmailOtpEcdsaLane(
  deps: ThresholdEcdsaSessionStoreDeps,
  command: ConsumeSingleUseEmailOtpEcdsaLaneCommand,
): ConsumeSingleUseEmailOtpEcdsaLaneResult {
  const laneKey = command.lane.laneRef.laneKey;
  if (
    command.kind !== 'consume_single_use_email_otp_ecdsa_lane' ||
    command.uses !== 1 ||
    command.lane.kind !== 'consumable_email_otp_ecdsa_lane' ||
    command.lane.remainingUses !== 1 ||
    command.lane.consumedAtMs !== null ||
    command.lane.laneRef.exactIdentity.authMethod !== 'email_otp'
  ) {
    return staleSingleUseEmailOtpEcdsaLaneResult({ laneKey, reason: 'auth_method_mismatch' });
  }

  const record = deps.recordsByLane.get(laneKey);
  if (!record) return { kind: 'missing_lane', laneKey };
  const storedLaneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
  if (storedLaneKey !== laneKey) {
    return staleSingleUseEmailOtpEcdsaLaneResult({ laneKey, reason: 'lane_key_mismatch' });
  }
  let storedIdentity: ExactEcdsaLaneIdentity;
  try {
    storedIdentity = toExactEcdsaLaneIdentity(record);
  } catch {
    return staleSingleUseEmailOtpEcdsaLaneResult({ laneKey, reason: 'key_identity_mismatch' });
  }
  const identityMismatch = exactEcdsaLaneIdentityMismatchReason({
    expected: command.lane.laneRef.exactIdentity,
    actual: storedIdentity,
  });
  if (identityMismatch) {
    return staleSingleUseEmailOtpEcdsaLaneResult({ laneKey, reason: identityMismatch });
  }
  const emailOtpAuthContext = thresholdEcdsaEmailOtpAuthContext(record);
  if (
    record.source !== 'email_otp' ||
    !emailOtpAuthContext ||
    emailOtpAuthContext.authMethod !== 'email_otp' ||
    emailOtpAuthContext.retention !== 'single_use'
  ) {
    return staleSingleUseEmailOtpEcdsaLaneResult({ laneKey, reason: 'retention_mismatch' });
  }

  const consumedAtMs = normalizedConsumedAtMs(record);
  const remainingUses = Math.floor(Number(record.remainingUses) || 0);
  if (consumedAtMs !== null || remainingUses <= 0) {
    return {
      kind: 'already_consumed',
      laneKey,
      consumedAtMs: consumedAtMs || normalizedUpdatedAtMs(record),
    };
  }
  if (remainingUses !== 1) {
    return staleSingleUseEmailOtpEcdsaLaneResult({ laneKey, reason: 'remaining_uses_mismatch' });
  }
  if (normalizedUpdatedAtMs(record) !== command.lane.laneRef.expectedUpdatedAtMs) {
    return staleSingleUseEmailOtpEcdsaLaneResult({ laneKey, reason: 'updated_at_mismatch' });
  }

  const nowMs = Math.max(0, Math.floor((deps.now || Date.now)()));
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(deps);
  const nextRecord: ThresholdEcdsaSessionRecord = {
    ...record,
    remainingUses: Math.max(0, remainingUses - 1),
    emailOtpAuthContext: {
      ...emailOtpAuthContext,
      consumedAtMs: nowMs,
    },
    updatedAtMs: nowMs,
  };
  deindexThresholdEcdsaRecord(depsIndex, laneKey, record);
  deps.recordsByLane.set(laneKey, nextRecord);
  indexThresholdEcdsaRecord(depsIndex, laneKey, nextRecord);
  rememberInMemoryThresholdEcdsaRecord(nextRecord);

  return { kind: 'consumed', laneKey, consumedAtMs: nowMs };
}

export function clearAllThresholdEcdsaSessionRecords(deps: ThresholdEcdsaSessionStoreDeps): void {
  deps.recordsByLane.clear();
  deps.exportArtifactsByLane?.clear();
  clearThresholdEcdsaRuntimeRecordIndex(getThresholdEcdsaRuntimeRecordIndex(deps));
  inMemoryEcdsaRecordsByLane.clear();
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
  return unique.size === 1 ? [...unique.values()][0] : null;
}

export function getThresholdEcdsaSessionRecordByThresholdSessionId(
  deps: ThresholdEcdsaSessionStoreDeps,
  thresholdSessionIdRaw: string,
): ThresholdEcdsaSessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  const indexKey = ecdsaIndexKey([thresholdSessionId]);
  const depsRecord =
    indexedThresholdEcdsaRecords({
      recordsByLane: deps.recordsByLane,
      laneKeys:
        getThresholdEcdsaRuntimeRecordIndex(deps).laneKeysByThresholdSessionId.get(indexKey),
    })[0] || null;
  if (depsRecord) return depsRecord;
  return getInMemoryThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId);
}

export function upsertStoredThresholdEd25519SessionRecord(args: {
  nearAccountId: AccountId | string;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  xClientBaseB64u?: string;
  thresholdSessionKind?: 'jwt' | 'cookie';
  thresholdSessionId: string;
  walletSigningSessionId?: string;
  thresholdSessionAuthToken?: string;
  expiresAtMs: number;
  remainingUses: number;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  updatedAtMs?: number;
  source?: ThresholdEd25519SessionStoreSource;
}): ThresholdEd25519SessionRecord | null {
  const record = normalizeThresholdEd25519SessionRecord({
    nearAccountId: toAccountId(args.nearAccountId),
    rpId: String(args.rpId || '').trim(),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    participantIds: args.participantIds,
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    ...(String(args.xClientBaseB64u || '').trim()
      ? { xClientBaseB64u: String(args.xClientBaseB64u || '').trim() }
      : {}),
    thresholdSessionKind: String(args.thresholdSessionKind || 'jwt')
      .trim()
      .toLowerCase(),
    thresholdSessionId: String(args.thresholdSessionId || '').trim(),
    ...(String(args.walletSigningSessionId || '').trim()
      ? { walletSigningSessionId: String(args.walletSigningSessionId || '').trim() }
      : {}),
    ...(String(args.thresholdSessionAuthToken || '').trim()
      ? { thresholdSessionAuthToken: String(args.thresholdSessionAuthToken || '').trim() }
      : {}),
    expiresAtMs: Math.floor(Number(args.expiresAtMs) || 0),
    remainingUses: Math.floor(Number(args.remainingUses) || 0),
    ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
    updatedAtMs: Math.floor(Number(args.updatedAtMs ?? Date.now()) || 0),
    source: args.source || 'manual-connect',
  });
  rememberInMemoryThresholdEd25519Record(record);
  return record;
}

export function persistStoredThresholdEd25519SessionClientBase(args: {
  thresholdSessionId: string;
  xClientBaseB64u: string;
  updatedAtMs?: number;
}): ThresholdEd25519SessionRecord | null {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const xClientBaseB64u = String(args.xClientBaseB64u || '').trim();
  if (!thresholdSessionId || !xClientBaseB64u) return null;
  const existing = getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
  if (!existing) return null;
  return upsertStoredThresholdEd25519SessionRecord({
    nearAccountId: existing.nearAccountId,
    rpId: existing.rpId,
    relayerUrl: existing.relayerUrl,
    relayerKeyId: existing.relayerKeyId,
    participantIds: existing.participantIds,
    ...(existing.runtimePolicyScope ? { runtimePolicyScope: existing.runtimePolicyScope } : {}),
    xClientBaseB64u,
    thresholdSessionKind: existing.thresholdSessionKind,
    thresholdSessionId: existing.thresholdSessionId,
    ...(existing.walletSigningSessionId
      ? { walletSigningSessionId: existing.walletSigningSessionId }
      : {}),
    thresholdSessionAuthToken: existing.thresholdSessionAuthToken,
    expiresAtMs: existing.expiresAtMs,
    remainingUses: existing.remainingUses,
    ...(existing.emailOtpAuthContext ? { emailOtpAuthContext: existing.emailOtpAuthContext } : {}),
    updatedAtMs: args.updatedAtMs ?? Date.now(),
    source: existing.source,
  });
}

export function getStoredThresholdEd25519SessionRecordForAccount(
  nearAccountIdRaw: AccountId | string,
): ThresholdEd25519SessionRecord | null {
  const inMemory = getInMemoryThresholdEd25519SessionRecordForAccount(nearAccountIdRaw);
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

export function listStoredThresholdEcdsaSessionRecordsForWallet(
  walletIdRaw: AccountId | string,
  filter: {
    chainTarget?: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  } = {},
): ThresholdEcdsaSessionRecord[] {
  let walletKey = '';
  try {
    walletKey = String(toAccountId(walletIdRaw)).trim();
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

function ecdsaRuntimeLaneFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
}): ThresholdEcdsaRuntimeRecordCandidate | null {
  const readModel = thresholdEcdsaSessionRecordReadModel(args.record);
  const candidate = thresholdEcdsaLaneCandidateFromSessionRecord({
    record: args.record,
  });
  const verifiedPublicFacts = args.record.verifiedPublicFacts;
  if (!verifiedPublicFacts) return null;
  const thresholdEcdsaPublicKeyB64u = String(verifiedPublicFacts.publicKeyB64u || '').trim();
  if (!thresholdEcdsaPublicKeyB64u) return null;
  if (String(candidate.keyHandle) !== String(verifiedPublicFacts.keyHandle)) return null;
  return {
    key: readModel.key,
    ...(readModel.resolvedKey ? { resolvedKey: readModel.resolvedKey } : {}),
    keyHandle: verifiedPublicFacts.keyHandle,
    verifiedPublicFacts,
    thresholdEcdsaPublicKeyB64u,
    lane: readModel.lane,
    authMethod: candidate.authMethod,
    curve: 'ecdsa',
    walletId: candidate.walletId,
    chainTarget: candidate.chainTarget,
    walletSigningSessionId: candidate.walletSigningSessionId,
    thresholdSessionId: candidate.thresholdSessionId,
    source: 'runtime_session_record',
    ...(candidate.remainingUses == null ? {} : { remainingUses: candidate.remainingUses }),
    ...(candidate.expiresAtMs == null ? {} : { expiresAtMs: candidate.expiresAtMs }),
    ...(candidate.updatedAtMs == null ? {} : { updatedAtMs: candidate.updatedAtMs }),
  };
}

export function listThresholdEcdsaRuntimeLanesForWallet(
  deps: ThresholdEcdsaSessionStoreDeps,
  walletIdRaw: AccountId | string,
): ThresholdEcdsaRuntimeRecordCandidate[] {
  const walletId = toAccountId(walletIdRaw);
  const lanes: ThresholdEcdsaRuntimeRecordCandidate[] = [];
  const seen = new Set<string>();
  const indexKey = ecdsaIndexKey([String(walletId)]);
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(deps);
  for (const record of [
    ...indexedThresholdEcdsaRecords({
      recordsByLane: deps.recordsByLane,
      laneKeys: depsIndex.laneKeysByWallet.get(indexKey),
    }),
    ...indexedThresholdEcdsaRecords({
      recordsByLane: inMemoryEcdsaRecordsByLane,
      laneKeys: inMemoryEcdsaRecordIndex.laneKeysByWallet.get(indexKey),
    }),
  ]) {
    const lane = ecdsaRuntimeLaneFromRecord({ record });
    if (!lane) continue;
    const laneKey = thresholdEcdsaRuntimeRecordCandidateLaneKey(lane);
    if (seen.has(laneKey)) continue;
    seen.add(laneKey);
    lanes.push(lane);
  }
  return lanes.sort(
    (left, right) =>
      Math.floor(Number(right.updatedAtMs) || 0) - Math.floor(Number(left.updatedAtMs) || 0),
  );
}

export function getThresholdEcdsaRuntimeRecordCandidateByKey(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: { identity: ThresholdEcdsaSessionRecordKey },
): ThresholdEcdsaRuntimeRecordCandidate | null {
  const expectedKey = thresholdEcdsaLaneKey(args.identity);
  const record =
    deps.recordsByLane.get(expectedKey) || inMemoryEcdsaRecordsByLane.get(expectedKey) || null;
  if (!record) return null;
  const lane = ecdsaRuntimeLaneFromRecord({ record });
  return lane && thresholdEcdsaRuntimeRecordCandidateLaneKey(lane) === expectedKey ? lane : null;
}

export function getStoredThresholdEd25519SessionRecordForLane(args: {
  nearAccountId: AccountId | string;
  authMethod: ThresholdEd25519SessionAuthMethod;
  walletSigningSessionId: string;
  thresholdSessionId: string;
}): ThresholdEd25519SessionRecord | null {
  let lane: ThresholdEd25519SessionRecordKey;
  let laneKey: string;
  try {
    lane = {
      nearAccountId: toAccountId(args.nearAccountId),
      authMethod: args.authMethod,
      walletSigningSessionId: String(args.walletSigningSessionId || '').trim(),
      thresholdSessionId: String(args.thresholdSessionId || '').trim(),
    };
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

export function markThresholdEd25519EmailOtpSessionConsumedForAccount(args: {
  nearAccountId: AccountId;
  thresholdSessionId?: string;
  uses?: number;
  nowMs?: number;
}): ThresholdEd25519SessionRecord | null {
  const record = getStoredThresholdEd25519SessionRecordForAccount(args.nearAccountId);
  if (!record || record.source !== 'email_otp' || !record.emailOtpAuthContext) return null;
  const expectedSessionId = String(args.thresholdSessionId || '').trim();
  const actualSessionId = String(record.thresholdSessionId || '').trim();
  if (expectedSessionId && actualSessionId && expectedSessionId !== actualSessionId) {
    return null;
  }
  const nowMs = Math.max(0, Math.floor(Number(args.nowMs ?? Date.now()) || 0));
  const uses = Math.max(1, Math.floor(Number(args.uses) || 1));
  const remainingUses = Math.max(0, Math.floor(Number(record.remainingUses) || 0) - uses);
  const clearClientBase = record.emailOtpAuthContext.retention === 'single_use';
  return upsertStoredThresholdEd25519SessionRecord({
    nearAccountId: record.nearAccountId,
    rpId: record.rpId,
    relayerUrl: record.relayerUrl,
    relayerKeyId: record.relayerKeyId,
    participantIds: record.participantIds,
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    ...(record.xClientBaseB64u && !clearClientBase
      ? { xClientBaseB64u: record.xClientBaseB64u }
      : {}),
    thresholdSessionKind: record.thresholdSessionKind,
    thresholdSessionId: record.thresholdSessionId,
    ...(record.walletSigningSessionId
      ? { walletSigningSessionId: record.walletSigningSessionId }
      : {}),
    ...(record.thresholdSessionAuthToken
      ? { thresholdSessionAuthToken: record.thresholdSessionAuthToken }
      : {}),
    expiresAtMs: record.expiresAtMs,
    remainingUses,
    emailOtpAuthContext: {
      ...record.emailOtpAuthContext,
      consumedAtMs: nowMs,
    },
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

export function clearStoredThresholdEd25519SessionRecordForAccount(
  nearAccountIdRaw: AccountId | string,
): void {
  const inMemory = getInMemoryThresholdEd25519SessionRecordForAccount(nearAccountIdRaw);
  const inMemorySessionId = String(inMemory?.thresholdSessionId || '').trim();
  if (inMemorySessionId) {
    inMemoryEd25519AccountBySessionId.delete(inMemorySessionId);
  }
  try {
    const nearAccountId = toAccountId(nearAccountIdRaw);
    const accountKey = String(nearAccountId);
    inMemoryEd25519RecordsByAccount.delete(accountKey);
    for (const [laneKey, record] of inMemoryEd25519RecordsByLane.entries()) {
      if (String(record.nearAccountId || '').trim() !== accountKey) continue;
      const thresholdSessionId = String(record.thresholdSessionId || '').trim();
      inMemoryEd25519RecordsByLane.delete(laneKey);
      if (
        thresholdSessionId &&
        inMemoryEd25519LaneBySessionId.get(thresholdSessionId) === laneKey
      ) {
        inMemoryEd25519LaneBySessionId.delete(thresholdSessionId);
      }
    }
  } catch {}
}

export function clearAllStoredThresholdEd25519SessionRecords(): void {
  inMemoryEd25519RecordsByAccount.clear();
  inMemoryEd25519AccountBySessionId.clear();
  inMemoryEd25519RecordsByLane.clear();
  inMemoryEd25519LaneBySessionId.clear();
}

export function getStoredThresholdEcdsaSessionRecordForWalletChain(args: {
  walletId: AccountId | string;
  chain: ThresholdEcdsaChainTarget['kind'];
}): ThresholdEcdsaSessionRecord | null {
  const walletId = toAccountId(args.walletId);
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
    clearThresholdEcdsaRuntimeRecordIndex(inMemoryEcdsaRecordIndex);
  }
}
