import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import {
  nearEd25519SigningKeyIdFromString,
  type NearEd25519SigningKeyId,
} from '@shared/utils/registrationIntent';
import { parseSignerSlot } from '@shared/utils/signerSlot';
import {
  decodeJwtPayloadRecord,
  ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
} from '@shared/utils/sessionTokens';
import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type { RouterAbEcdsaHssNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaHss';
import type { SigningSessionSealedStoreRecord } from '../persistence/sealedSessionStore';
import {
  ed25519SealedRecoveryMaterialIdentity,
  normalizeSealedRecoveryRecord,
  sealedRecoveryWalletSessionJwt,
} from '../sealedRecovery/recoveryRecord';
import type {
  EmailOtpEcdsaCompanionEd25519Recovery,
  EmailOtpEcdsaSealedRecoveryRecord,
  PasskeyEcdsaSealedRecoveryRecord,
  SealedRecoveryRecord,
} from '../sealedRecovery/recoveryRecord';
import type {
  EcdsaLaneCandidate,
  Ed25519LaneCandidate,
  LaneCandidateSource,
  LaneCandidateState,
} from '../identity/laneIdentity';
import {
  buildPasskeyEcdsaAuthBinding,
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildResolvedEvmFamilyEcdsaKey,
  buildVerifiedEcdsaPublicFacts,
  deriveEvmFamilyKeyFingerprintFromPublicFacts,
  resolveThresholdEcdsaKeyIdFromRecord,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
  toVerifiedEcdsaPublicFactsFromDurableRecord,
  type EvmFamilyKeyFingerprint,
  type EvmFamilyEcdsaAuthMethod,
  type EvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyIdentity,
  type PasskeyEcdsaAuthBinding,
  type ResolvedEvmFamilyEcdsaKey,
  type VerifiedEcdsaPublicFacts,
} from '../identity/evmFamilyEcdsaIdentity';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  selectedEcdsaLane,
  selectedEd25519Lane,
  type SelectedLane,
} from '../identity/laneIdentity';
import { exactSigningLaneIdentityFromSelectedLane } from '../identity/exactSigningLaneIdentity';
import {
  signingLaneAuthMethod,
  type SigningLaneAuthBinding,
} from '../identity/signingLaneAuthBinding';
import {
  buildFreshStepUpRequired,
  buildStepUpFreshnessFromRestoredSealedRecord,
  type FreshStepUpRequired,
  type StepUpExpiryState,
} from '../operationState/stepUpFreshness';
import {
  buildReauthAnchorIdentity,
  type ReauthAnchorIdentity,
  type ReauthAnchorSourceState,
} from '../operationState/transactionState';
import type { SigningOperationFingerprint, SigningOperationId } from '../operationState/types';
import {
  parseEd25519WorkerMaterialBindingDigest,
  parseEd25519WorkerMaterialKeyId,
  type Ed25519WorkerMaterialBindingDigest,
  type Ed25519WorkerMaterialKeyId,
} from '../keyMaterialBrands';
import {
  canonicalizeLaneFacts,
  serverIssuedGenerationFromNumber,
  type CanonicalFactSupersession,
  type CanonicalLaneInventoryAdapter,
  type CanonicalTieBreakOrder,
  type ServerIssuedGeneration,
} from './canonicalLaneInventory';

export type AvailableSigningLaneState =
  | 'ready'
  | 'restorable'
  | 'deferred'
  | 'expired'
  | 'exhausted';

export type AvailableSigningLanePolicyHint = {
  remainingUses?: number;
  expiresAtMs?: number;
};

export type MissingAvailableEcdsaSigningLane = {
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  state: 'missing';
  key?: never;
  publicFacts?: never;
  authMethod?: never;
  resolvedKey?: never;
  signingGrantId?: never;
  thresholdSessionId?: never;
  remainingUses?: never;
  expiresAtMs?: never;
  policyHint?: never;
  updatedAtMs?: never;
  source?: never;
  sourceChainTarget?: never;
};

export type ResolvedPasskeyAvailableEcdsaKey = ResolvedEvmFamilyEcdsaKey<PasskeyEcdsaAuthBinding>;

type ConcreteAvailableEcdsaSigningLaneAuth =
  | {
      auth: Extract<SigningLaneAuthBinding, { kind: 'passkey' }>;
      resolvedKey: ResolvedPasskeyAvailableEcdsaKey;
    }
  | {
      auth: Extract<SigningLaneAuthBinding, { kind: 'email_otp' }>;
      resolvedKey?: never;
    };

function isPasskeyResolvedEcdsaKey(
  value: ResolvedEvmFamilyEcdsaKey,
): value is ResolvedPasskeyAvailableEcdsaKey {
  return value.authBinding.kind === 'passkey_ecdsa_auth_binding';
}

type ConcreteAvailableEcdsaSigningLaneSource =
  | {
      source?: 'durable_sealed_record' | 'runtime_session_record';
      sourceChainTarget?: never;
    }
  | {
      source: 'evm_family_shared_key';
      sourceChainTarget: ThresholdEcdsaChainTarget;
    };

export type ConcreteAvailableEcdsaSigningLane = {
  key: EvmFamilyEcdsaKeyIdentity;
  publicFacts: VerifiedEcdsaPublicFacts;
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  state: AvailableSigningLaneState;
  signingGrantId: string;
  thresholdSessionId: string;
  remainingUses?: number;
  expiresAtMs?: number;
  policyHint?: AvailableSigningLanePolicyHint;
  updatedAtMs?: number;
} & ConcreteAvailableEcdsaSigningLaneSource &
  ConcreteAvailableEcdsaSigningLaneAuth;

export type AvailableEcdsaSigningLane =
  | MissingAvailableEcdsaSigningLane
  | ConcreteAvailableEcdsaSigningLane;

export type EcdsaLaneRecordFactSource =
  | 'runtime_session_record'
  | 'sealed_restore_record'
  | 'evm_family_shared_projection';

export type EcdsaLaneGroupKey = {
  walletId: string;
  authKey: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
};

export type EcdsaLaneRecordFact = {
  source: EcdsaLaneRecordFactSource;
  groupKey: EcdsaLaneGroupKey;
  chainTargetKey: string;
  lane: ConcreteAvailableEcdsaSigningLane;
};

export type EcdsaLaneGroup = {
  key: EcdsaLaneGroupKey;
  facts: readonly EcdsaLaneRecordFact[];
};

export type EcdsaLaneConflict = {
  groupKey: EcdsaLaneGroupKey;
  field:
    | 'ecdsaThresholdKeyId'
    | 'thresholdOwnerAddress'
    | 'keyHandle'
    | 'publicKeyB64u'
    | 'participantIds';
  values: readonly string[];
};

export type EcdsaCanonicalLaneSelection =
  | {
      kind: 'selected';
      selectedFact: EcdsaLaneRecordFact;
      supersededFacts: readonly EcdsaLaneRecordFact[];
    }
  | { kind: 'no_current_lane'; unusableFacts: readonly EcdsaLaneRecordFact[] }
  | { kind: 'conflicting_key_material'; conflicts: readonly EcdsaLaneConflict[] }
  | {
      kind: 'ambiguous_material';
      candidates: readonly EcdsaLaneGroupKey[];
      candidateFacts: readonly EcdsaLaneRecordFact[];
    };

export function availableEcdsaSigningLaneAuthMethod(
  lane: Pick<ConcreteAvailableEcdsaSigningLane, 'auth'>,
): EvmFamilyEcdsaAuthMethod {
  return signingLaneAuthMethod(lane.auth);
}

export type MissingAvailableEd25519SigningLane = {
  curve: 'ed25519';
  chain: 'near';
  state: 'missing';
  walletId?: never;
  nearAccountId?: never;
  nearEd25519SigningKeyId?: never;
  signerSlot?: never;
  authMethod?: never;
  signingGrantId?: never;
  thresholdSessionId?: never;
  remainingUses?: never;
  expiresAtMs?: never;
  policyHint?: never;
  updatedAtMs?: never;
  source?: never;
  material?: never;
};

export type Ed25519AvailableWorkerMaterialIdentity = {
  bindingDigest: Ed25519WorkerMaterialBindingDigest;
  materialKeyId: Ed25519WorkerMaterialKeyId;
};

export type Ed25519AvailableWorkerMaterialState =
  | {
      kind: 'material_pending';
      identity?: never;
    }
  | {
      kind: 'loaded_worker_material';
      identity: Ed25519AvailableWorkerMaterialIdentity;
    }
  | {
      kind: 'sealed_worker_material';
      identity: Ed25519AvailableWorkerMaterialIdentity;
    };

export type ConcreteAvailableEd25519SigningLane = {
  auth: SigningLaneAuthBinding;
  curve: 'ed25519';
  chain: 'near';
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
  state: AvailableSigningLaneState;
  signingGrantId: string;
  thresholdSessionId: string;
  remainingUses?: number;
  expiresAtMs?: number;
  policyHint?: AvailableSigningLanePolicyHint;
  updatedAtMs?: number;
  material: Ed25519AvailableWorkerMaterialState;
  source?: 'durable_sealed_record' | 'runtime_session_record';
};

export type AvailableEd25519SigningLane =
  | MissingAvailableEd25519SigningLane
  | ConcreteAvailableEd25519SigningLane;

function isConcreteEd25519AvailableLane(
  lane: AvailableEd25519SigningLane | null | undefined,
): lane is ConcreteAvailableEd25519SigningLane {
  return Boolean(lane) && lane!.curve === 'ed25519' && lane!.state !== 'missing';
}

export function availableEd25519SigningLaneAuthMethod(
  lane: Pick<ConcreteAvailableEd25519SigningLane, 'auth'>,
): 'email_otp' | 'passkey' {
  return signingLaneAuthMethod(lane.auth);
}

export type AvailableLaneStateAdvisory =
  | {
      kind: 'warm_status';
      status: 'active';
      thresholdSessionId: string;
      remainingUses: number;
      expiresAtMs: number;
      code?: never;
    }
  | {
      kind: 'durable_policy';
      thresholdSessionId: string;
      remainingUses: number;
      expiresAtMs: number;
      state: AvailableSigningLaneState;
      code?: never;
    }
  | {
      kind: 'warm_status';
      status: 'exhausted';
      thresholdSessionId: string;
      remainingUses: 0;
      expiresAtMs?: never;
      code?: never;
    }
  | {
      kind: 'warm_status';
      status: 'expired';
      thresholdSessionId: string;
      remainingUses?: never;
      expiresAtMs?: never;
      code?: never;
    }
  | {
      kind: 'warm_status';
      status: 'cache_miss';
      thresholdSessionId: string;
      remainingUses?: never;
      expiresAtMs?: never;
      code?: string;
    }
  | {
      kind: 'warm_status';
      status: 'unavailable';
      thresholdSessionId: string;
      remainingUses?: never;
      expiresAtMs?: never;
      code: string;
    };

export function durableRecordPolicyAdvisory(args: {
  thresholdSessionId: string;
  remainingUses: unknown;
  expiresAtMs: unknown;
  state: 'ready' | 'restorable' | 'deferred';
}): AvailableLaneStateAdvisory | null {
  const remainingUses = Math.floor(Number(args.remainingUses));
  const expiresAtMs = Math.floor(Number(args.expiresAtMs));
  if (!Number.isFinite(remainingUses) || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    return null;
  }
  if (remainingUses <= 0) {
    return {
      kind: 'durable_policy',
      thresholdSessionId: args.thresholdSessionId,
      remainingUses: 0,
      expiresAtMs,
      state: 'exhausted',
    };
  }
  if (expiresAtMs <= Date.now()) {
    return {
      kind: 'durable_policy',
      thresholdSessionId: args.thresholdSessionId,
      remainingUses,
      expiresAtMs,
      state: 'expired',
    };
  }
  return {
    kind: 'durable_policy',
    thresholdSessionId: args.thresholdSessionId,
    remainingUses,
    expiresAtMs,
    state: args.state,
  };
}

export function runtimeEcdsaRecordAdvisoryKey(
  record: AvailableSigningLanesRuntimeEcdsaRecord,
): string | null {
  const walletId = String(record.key.walletId || '').trim();
  const keyHandle = String(record.keyHandle || '').trim();
  const thresholdSessionId = String(record.thresholdSessionId || '').trim();
  const signingGrantId = String(record.signingGrantId || '').trim();
  if (!walletId || !keyHandle || !thresholdSessionId || !signingGrantId) return null;
  return [
    encodeURIComponent(walletId),
    encodeURIComponent(keyHandle),
    encodeURIComponent(signingLaneAuthMethod(record.auth)),
    'ecdsa',
    encodeURIComponent(thresholdEcdsaChainTargetKey(record.chainTarget)),
    encodeURIComponent(signingGrantId),
    encodeURIComponent(thresholdSessionId),
  ].join(':');
}

type AvailableSigningLanesRuntimeEcdsaAuthRecord =
  | {
      auth: Extract<SigningLaneAuthBinding, { kind: 'passkey' }>;
      resolvedKey?: ResolvedEvmFamilyEcdsaKey;
    }
  | {
      auth: Extract<SigningLaneAuthBinding, { kind: 'email_otp' }>;
      resolvedKey?: never;
    };

type AvailableSigningLanesRuntimeEcdsaPublicFactsRecord = {
  verifiedPublicFacts?: VerifiedEcdsaPublicFacts;
  keyHandle: EvmFamilyEcdsaKeyHandle;
};

export type AvailableSigningLanesRuntimeEcdsaRecord = {
  key: EvmFamilyEcdsaKeyIdentity;
  routerAbEcdsaHssNormalSigning: RouterAbEcdsaHssNormalSigningStateV1;
  thresholdEcdsaPublicKeyB64u: string;
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  signingGrantId: string;
  remainingUses?: number;
  expiresAtMs?: number;
  updatedAtMs?: number;
} & AvailableSigningLanesRuntimeEcdsaAuthRecord &
  AvailableSigningLanesRuntimeEcdsaPublicFactsRecord;

export type AvailableSigningLanesRuntimeEd25519Record = {
  auth: SigningLaneAuthBinding;
  curve: 'ed25519';
  chain: 'near';
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  thresholdSessionId: string;
  signingGrantId: string;
  remainingUses?: number;
  expiresAtMs?: number;
  updatedAtMs?: number;
  material: Ed25519AvailableWorkerMaterialState;
};

export type InvalidAvailableSigningLaneDiagnostic =
  | {
      curve: 'ed25519';
      source: 'runtime_session_record' | 'canonical_lane_inventory';
      reason:
        | 'missing_router_ab_state'
        | 'missing_threshold_session_id'
        | 'missing_signing_grant_id'
        | 'ambiguous_material'
        | 'conflicting_key_material';
      authMethod?: 'email_otp' | 'passkey';
      thresholdSessionId?: string;
      signingGrantId?: string;
      message?: string;
    }
  | {
      curve: 'ecdsa';
      source: 'runtime_session_record' | 'canonical_lane_inventory';
      reason:
        | 'missing_router_ab_state'
        | 'missing_threshold_session_id'
        | 'unsupported_ecdsa_chain_target'
        | 'invalid_runtime_public_facts'
        | 'conflicting_key_material'
        | 'ambiguous_material';
      authMethod?: 'email_otp' | 'passkey';
      thresholdSessionId?: string;
      signingGrantId?: string;
      targetKey?: string;
      message?: string;
      groupKey?: EcdsaLaneGroupKey;
      conflicts?: readonly EcdsaLaneConflict[];
    };

export type AvailableSigningLaneDiagnostics = {
  invalidLanes: InvalidAvailableSigningLaneDiagnostic[];
};

export type AvailableSigningLanes = {
  walletId: WalletId;
  generation: number;
  ecdsa: {
    targets: ThresholdEcdsaChainTarget[];
    lanesByTarget: Record<string, AvailableEcdsaSigningLane>;
    candidatesByTarget: Record<string, AvailableEcdsaSigningLane[]>;
  };
  lanes: {
    ed25519: {
      near: AvailableEd25519SigningLane;
    };
  };
  candidates: {
    ed25519: {
      near: AvailableEd25519SigningLane[];
    };
  };
  diagnostics?: AvailableSigningLaneDiagnostics;
};

export type ConcreteAvailableSigningLane =
  | ConcreteAvailableEcdsaSigningLane
  | ConcreteAvailableEd25519SigningLane;

export type ReadAvailableSigningLanesInput = {
  walletId: WalletId | string;
  subjectId?: never;
  ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
  authMethod?: 'email_otp' | 'passkey';
  nowMs?: number;
};

export type ReadAvailableSigningLanesForSigningInput =
  | {
      walletId: WalletId | string;
      subjectId?: never;
      curve: 'ed25519';
      authMethod?: 'email_otp' | 'passkey';
    }
  | {
      walletId: WalletId;
      subjectId?: never;
      curve: 'ecdsa';
      ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
      authMethod?: 'email_otp' | 'passkey';
    };

export type ReadAvailableSigningLanesPorts = {
  listSealedRecordsForWallet: (args: {
    walletId: string;
    filter:
      | {
          authMethod?: 'email_otp' | 'passkey';
          curve: 'ed25519';
        }
      | {
          authMethod?: 'email_otp' | 'passkey';
          curve: 'ecdsa';
          chainTarget: ThresholdEcdsaChainTarget;
        };
  }) => Promise<SigningSessionSealedStoreRecord[]>;
  listEcdsaSealedRecordsForWallet?: (args: {
    walletId: string;
    filter: {
      authMethod?: 'email_otp' | 'passkey';
      curve: 'ecdsa';
    };
  }) => Promise<SigningSessionSealedStoreRecord[]>;
  listRuntimeEcdsaLanesForWallet?: (args: {
    walletId: string;
  }) => Promise<AvailableSigningLanesRuntimeEcdsaRecord[]>;
  readEcdsaWarmStatusAdvisoriesForRecords?: (
    records: AvailableSigningLanesRuntimeEcdsaRecord[],
  ) => Promise<Map<string, AvailableLaneStateAdvisory | null>>;
  listRuntimeEd25519RecordsForWallet?: (args: {
    walletId: string;
  }) => Promise<AvailableSigningLanesRuntimeEd25519Record[]>;
  readWarmStatusAdvisoriesForSessions?: (
    sessionIds: string[],
  ) => Promise<Map<string, AvailableLaneStateAdvisory | null>>;
};

export function isConcreteAvailableSigningLane(
  lane: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
): lane is ConcreteAvailableSigningLane {
  if (lane.state === 'missing') return false;
  const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
  const signingGrantId = String(lane.signingGrantId || '').trim();
  if (lane.thresholdSessionId !== thresholdSessionId) return false;
  if (lane.signingGrantId !== signingGrantId) return false;
  if (!thresholdSessionId || !signingGrantId) return false;
  if (lane.curve !== 'ecdsa') {
    return (
      (lane.auth.kind === 'email_otp' || lane.auth.kind === 'passkey') &&
      isEd25519AvailableWorkerMaterialState(lane.material)
    );
  }
  if (lane.auth.kind !== 'email_otp' && lane.auth.kind !== 'passkey') return false;
  const hasEcdsaFields = Boolean(
    lane.key &&
    String(lane.key.walletId || '').trim() &&
    String(lane.key.ecdsaThresholdKeyId || '').trim() &&
    String(lane.key.signingRootId || '').trim() &&
    String(lane.key.signingRootVersion || '').trim() &&
    Array.isArray(lane.key.participantIds) &&
    lane.key.participantIds.length > 0 &&
    String(lane.key.thresholdOwnerAddress || '').trim() &&
    Boolean(
      'publicFacts' in lane &&
      lane.publicFacts &&
      lane.publicFacts.keyHandle &&
      String(lane.publicFacts.publicKeyB64u || '').trim() &&
      Array.isArray(lane.publicFacts.participantIds) &&
      lane.publicFacts.participantIds.length > 0 &&
      String(lane.publicFacts.thresholdOwnerAddress || '').trim(),
    ),
  );
  if (!hasEcdsaFields) return false;
  if (signingLaneAuthMethod(lane.auth) === 'passkey') {
    return (
      lane.resolvedKey?.kind === 'resolved_evm_family_ecdsa_key' &&
      lane.resolvedKey.authBinding.kind === 'passkey_ecdsa_auth_binding' &&
      String(lane.resolvedKey.walletId) === String(lane.key.walletId) &&
      lane.resolvedKey.publicFacts === lane.publicFacts
    );
  }
  return !('resolvedKey' in lane);
}

function laneCandidateStateFromAvailableLaneState(
  state: AvailableSigningLaneState | 'missing',
): LaneCandidateState | null {
  return state === 'missing' ? null : state;
}

function laneCandidateSourceFromAvailableLaneSource(
  source: ConcreteAvailableSigningLane['source'],
): LaneCandidateSource {
  return source || 'unknown';
}

function nonSharedLaneCandidateSourceFromAvailableLaneSource(
  source: Exclude<ConcreteAvailableSigningLane['source'], 'evm_family_shared_key'>,
): Exclude<LaneCandidateSource, 'evm_family_shared_key'> {
  return source || 'unknown';
}

function nullablePositiveInteger(value: unknown): number | null {
  const normalized = Math.floor(Number(value));
  return Number.isFinite(normalized) && normalized > 0 ? normalized : null;
}

function nullableNonNegativeInteger(value: unknown): number | null {
  const normalized = Math.max(0, Math.floor(Number(value)));
  return Number.isFinite(normalized) ? normalized : null;
}

export function ed25519AvailableMaterialStateFromBoundaryFields(args: {
  bindingDigest: unknown;
  materialKeyId: unknown;
  kind: 'loaded_worker_material' | 'sealed_worker_material';
}): Ed25519AvailableWorkerMaterialState | null {
  const bindingDigest = String(args.bindingDigest || '').trim();
  const materialKeyId = String(args.materialKeyId || '').trim();
  if (!bindingDigest && !materialKeyId) return { kind: 'material_pending' };
  if (!bindingDigest || !materialKeyId) return null;
  return {
    kind: args.kind,
    identity: {
      bindingDigest: parseEd25519WorkerMaterialBindingDigest(bindingDigest),
      materialKeyId: parseEd25519WorkerMaterialKeyId(materialKeyId),
    },
  };
}

function isEd25519AvailableWorkerMaterialState(
  value: unknown,
): value is Ed25519AvailableWorkerMaterialState {
  if (!value || typeof value !== 'object') return false;
  const material = value as Partial<Ed25519AvailableWorkerMaterialState>;
  switch (material.kind) {
    case 'material_pending':
      return !('identity' in material);
    case 'loaded_worker_material':
    case 'sealed_worker_material':
      return Boolean(
        material.identity &&
        String(material.identity.bindingDigest || '').trim() &&
        String(material.identity.materialKeyId || '').trim(),
      );
    default:
      return false;
  }
}

function resolveEd25519RuntimeAvailableMaterial(args: {
  material: Ed25519AvailableWorkerMaterialState;
  matchingDurableLane: ConcreteAvailableEd25519SigningLane | null;
}): Ed25519AvailableWorkerMaterialState | null {
  const runtimeMaterial = args.material;
  if (!isEd25519AvailableWorkerMaterialState(runtimeMaterial)) return null;
  if (runtimeMaterial.kind !== 'material_pending') return runtimeMaterial;
  const durableMaterial = args.matchingDurableLane?.material;
  return durableMaterial && durableMaterial.kind !== 'material_pending'
    ? durableMaterial
    : runtimeMaterial;
}

export function ed25519LaneCandidateFromAvailableLane(args: {
  lane: AvailableEd25519SigningLane;
}): Ed25519LaneCandidate | null {
  if (!isConcreteAvailableSigningLane(args.lane) || args.lane.curve !== 'ed25519') {
    return null;
  }
  const state = laneCandidateStateFromAvailableLaneState(args.lane.state);
  if (!state) return null;
  return {
    kind: 'lane_candidate',
    walletId: args.lane.walletId,
    nearAccountId: args.lane.nearAccountId,
    nearEd25519SigningKeyId: args.lane.nearEd25519SigningKeyId,
    signerSlot: args.lane.signerSlot,
    auth: args.lane.auth,
    curve: 'ed25519',
    chain: 'near',
    signingGrantId: args.lane.signingGrantId,
    thresholdSessionId: args.lane.thresholdSessionId,
    state,
    remainingUses: nullableNonNegativeInteger(args.lane.remainingUses),
    expiresAtMs: nullablePositiveInteger(args.lane.expiresAtMs),
    updatedAtMs: nullablePositiveInteger(args.lane.updatedAtMs),
    source: laneCandidateSourceFromAvailableLaneSource(args.lane.source),
  };
}

export function ecdsaLaneCandidateFromAvailableLane(args: {
  walletId: WalletId | string;
  lane: AvailableEcdsaSigningLane;
}): EcdsaLaneCandidate | null {
  if (!isConcreteAvailableSigningLane(args.lane) || args.lane.curve !== 'ecdsa') {
    return null;
  }
  const state = laneCandidateStateFromAvailableLaneState(args.lane.state);
  if (!state) return null;
  const authMethod = signingLaneAuthMethod(args.lane.auth);
  const base = {
    kind: 'lane_candidate',
    walletId: toWalletId(args.walletId),
    auth: args.lane.auth,
    authMethod,
    curve: 'ecdsa',
    chain: args.lane.chainTarget.kind,
    key: args.lane.key,
    ...(authMethod === 'passkey' ? { resolvedKey: args.lane.resolvedKey } : {}),
    keyHandle: args.lane.publicFacts.keyHandle,
    chainTarget: args.lane.chainTarget,
    signingGrantId: args.lane.signingGrantId,
    thresholdSessionId: args.lane.thresholdSessionId,
    state,
    remainingUses: nullableNonNegativeInteger(args.lane.remainingUses),
    expiresAtMs: nullablePositiveInteger(args.lane.expiresAtMs),
    updatedAtMs: nullablePositiveInteger(args.lane.updatedAtMs),
  } as const;
  if (args.lane.source === 'evm_family_shared_key') {
    return {
      ...base,
      source: 'evm_family_shared_key',
      sourceChainTarget: args.lane.sourceChainTarget,
    };
  }
  return {
    ...base,
    source: nonSharedLaneCandidateSourceFromAvailableLaneSource(args.lane.source),
  };
}

function runtimePasskeyResolvedKeyFromRecord(args: {
  record: AvailableSigningLanesRuntimeEcdsaRecord;
  publicFacts: VerifiedEcdsaPublicFacts;
}): ResolvedPasskeyAvailableEcdsaKey | null {
  const candidate = args.record.resolvedKey;
  if (!candidate) return null;
  if (candidate.kind !== 'resolved_evm_family_ecdsa_key') return null;
  if (!isPasskeyResolvedEcdsaKey(candidate)) return null;
  if (String(candidate.walletId) !== String(args.record.key.walletId)) return null;
  if (String(candidate.publicFacts.keyHandle) !== String(args.publicFacts.keyHandle)) return null;
  if (
    String(candidate.publicFacts.thresholdOwnerAddress) !==
    String(args.publicFacts.thresholdOwnerAddress)
  ) {
    return null;
  }
  return candidate;
}

function passkeyAuthFromResolvedEcdsaKey(
  resolvedKey: ResolvedPasskeyAvailableEcdsaKey,
): Extract<SigningLaneAuthBinding, { kind: 'passkey' }> {
  return {
    kind: 'passkey',
    rpId: toRpId(resolvedKey.authBinding.rpId),
    credentialIdB64u: resolvedKey.authBinding.credentialIdB64u,
  };
}

function ecdsaRecoveryRecordAuthBinding(
  record: EmailOtpEcdsaSealedRecoveryRecord | PasskeyEcdsaSealedRecoveryRecord,
): SigningLaneAuthBinding | null {
  if (record.authMethod === 'passkey') {
    return {
      kind: 'passkey',
      rpId: toRpId(record.authority.verifier.rpId),
      credentialIdB64u: record.authority.factor.credentialIdB64u,
    };
  }
  return {
    kind: 'email_otp',
    providerSubjectId: record.authority.factor.providerUserId,
  };
}

type EcdsaAvailableLaneIdentityBase = Pick<
  ConcreteAvailableEcdsaSigningLane,
  'curve' | 'chainTarget' | 'key' | 'publicFacts' | 'signingGrantId' | 'thresholdSessionId'
>;

export type EcdsaAvailableLaneIdentityInput = EcdsaAvailableLaneIdentityBase &
  ConcreteAvailableEcdsaSigningLaneAuth;

export function ecdsaAvailableLaneIdentityKey(
  lane: EcdsaAvailableLaneIdentityInput | MissingAvailableEcdsaSigningLane | null | undefined,
): string | null {
  if (!lane || lane.curve !== 'ecdsa') return null;
  if (!lane.chainTarget) return null;
  if (!('key' in lane) || !lane.key) return null;
  if (!('auth' in lane) || !lane.auth) return null;
  const authMethod = signingLaneAuthMethod(lane.auth);
  const signingGrantId = String(lane.signingGrantId || '').trim();
  const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
  const authKey = ecdsaAvailableLaneAuthKey(lane.auth);
  if (!authMethod || !signingGrantId || !thresholdSessionId || !authKey) return null;
  try {
    return [
      authMethod,
      'ecdsa',
      thresholdEcdsaChainTargetKey(lane.chainTarget),
      authKey,
      deriveAvailableEcdsaLaneFingerprint(lane),
      signingGrantId,
      thresholdSessionId,
    ].join(':');
  } catch {
    return null;
  }
}

export function ecdsaAvailableLaneAuthKey(auth: SigningLaneAuthBinding): string | null {
  return signingLaneAuthBindingKey(auth);
}

function signingLaneAuthBindingKey(auth: SigningLaneAuthBinding): string | null {
  if (auth.kind === 'passkey') {
    const rpId = String(auth.rpId || '').trim();
    const credentialIdB64u = String(auth.credentialIdB64u || '').trim();
    return rpId && credentialIdB64u ? ['passkey', rpId, credentialIdB64u].join(':') : null;
  }
  const providerSubjectId = String(auth.providerSubjectId || '').trim();
  return providerSubjectId ? ['email_otp', providerSubjectId].join(':') : null;
}

function deriveAvailableEcdsaLaneFingerprint(args: {
  key: EvmFamilyEcdsaKeyIdentity;
  publicFacts: VerifiedEcdsaPublicFacts;
}): EvmFamilyKeyFingerprint {
  return deriveEvmFamilyKeyFingerprintFromPublicFacts({
    walletId: args.key.walletId,
    publicFacts: args.publicFacts,
  });
}

type Ed25519AvailableLaneIdentityInput = {
  auth?: SigningLaneAuthBinding;
  curve: 'ed25519';
  chain: 'near';
  walletId?: unknown;
  nearAccountId?: unknown;
  nearEd25519SigningKeyId?: unknown;
  signerSlot?: unknown;
  signingGrantId?: unknown;
  thresholdSessionId?: unknown;
  state?: AvailableSigningLaneState | 'missing';
};

export function ed25519AvailableLaneIdentityKey(
  lane: Ed25519AvailableLaneIdentityInput | null | undefined,
): string | null {
  if (!lane || lane.curve !== 'ed25519' || lane.chain !== 'near') return null;
  if (lane.state === 'missing') return null;
  if (!lane.auth) return null;
  const authMethod = signingLaneAuthMethod(lane.auth);
  const walletId = String(lane.walletId || '').trim();
  const nearAccountId = String(lane.nearAccountId || '').trim();
  const nearEd25519SigningKeyId = String(lane.nearEd25519SigningKeyId || '').trim();
  const signerSlot = String(lane.signerSlot || '').trim();
  const signingGrantId = String(lane.signingGrantId || '').trim();
  const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
  if (
    !authMethod ||
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !signerSlot ||
    !signingGrantId ||
    !thresholdSessionId
  ) {
    return null;
  }
  return [
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    signerSlot,
    authMethod,
    'ed25519',
    'near',
    signingGrantId,
    thresholdSessionId,
  ].join(':');
}

function emptyEcdsaLane(args: {
  chainTarget: ThresholdEcdsaChainTarget;
}): MissingAvailableEcdsaSigningLane {
  return {
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    state: 'missing',
  };
}

export function ecdsaAvailableLaneForTarget(
  availableLanes: AvailableSigningLanes,
  chainTarget: ThresholdEcdsaChainTarget,
): AvailableEcdsaSigningLane {
  const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
  return availableLanes.ecdsa.lanesByTarget[targetKey] || emptyEcdsaLane({ chainTarget });
}

export function ecdsaAvailableLaneTargets(
  availableLanes: AvailableSigningLanes,
): ThresholdEcdsaChainTarget[] {
  return availableLanes.ecdsa.targets;
}

export function ecdsaAvailableLaneCandidatesForTarget(
  availableLanes: AvailableSigningLanes,
  chainTarget: ThresholdEcdsaChainTarget,
): AvailableEcdsaSigningLane[] {
  const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
  return availableLanes.ecdsa.candidatesByTarget[targetKey] || [];
}

export function buildReauthAnchorIdentityFromAvailableLane(args: {
  walletId: WalletId | string;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  lane: AvailableEcdsaSigningLane | AvailableEd25519SigningLane;
  nowMs?: number;
}): ReauthAnchorIdentity | null {
  if (!isConcreteAvailableSigningLane(args.lane)) return null;
  if (args.lane.state !== 'expired' && args.lane.state !== 'exhausted') return null;
  const selectedLane = selectedLaneFromConcreteAvailableLane({
    walletId: args.walletId,
    lane: args.lane,
  });
  const freshness = buildStepUpFreshnessFromRestoredSealedRecord({
    walletId: toWalletId(args.walletId),
    operationId: args.operationId,
    operationFingerprint: args.operationFingerprint,
    laneIdentity: exactSigningLaneIdentityFromSelectedLane(selectedLane),
    recordVersion: availableLaneRecordVersion(args.lane),
    updatedAtMs: availableLaneUpdatedAtMs(args.lane),
    remainingUses: args.lane.remainingUses ?? null,
    expiresAtMs: args.lane.expiresAtMs ?? null,
    ...(args.nowMs ? { nowMs: args.nowMs } : {}),
  });
  if (freshness.kind !== 'fresh_step_up_required') return null;
  return buildReauthAnchorIdentity({
    freshness,
    sourceState: sourceStateFromAvailableLane(args.lane, freshness),
  });
}

export function buildReauthAnchorIdentityFromEcdsaLaneCandidate(args: {
  walletId: WalletId | string;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  candidate: EcdsaLaneCandidate;
}): ReauthAnchorIdentity | null {
  if (args.candidate.state !== 'expired' && args.candidate.state !== 'exhausted') return null;
  const walletId = toWalletId(args.walletId);
  if (String(args.candidate.walletId) !== String(walletId)) {
    throw new Error('[SigningEngine][ecdsa] reauth candidate wallet mismatch');
  }
  const selectedLane = selectedEcdsaLane({
    key: args.candidate.key,
    keyHandle: args.candidate.keyHandle,
    walletId,
    auth: args.candidate.auth,
    signingGrantId: args.candidate.signingGrantId,
    thresholdSessionId: args.candidate.thresholdSessionId,
    chainTarget: args.candidate.chainTarget,
  });
  const freshness = buildFreshStepUpRequired({
    walletId,
    operationId: args.operationId,
    operationFingerprint: args.operationFingerprint,
    laneIdentity: exactSigningLaneIdentityFromSelectedLane(selectedLane),
    projection: { kind: 'unavailable', reason: 'restored_record_has_no_projection' },
    expiry: laneCandidateExpiry(args.candidate),
    provenance: {
      kind: 'restored_sealed_record_status',
      recordVersion: ecdsaCandidateRecordVersion(args.candidate),
      updatedAtMs: laneCandidateUpdatedAtMs(args.candidate),
    },
    reason: laneCandidateStepUpReason(args.candidate),
  });
  return buildReauthAnchorIdentity({
    freshness,
    sourceState: sourceStateFromEcdsaLaneCandidate(args.candidate, freshness),
  });
}

function emptyEd25519Lane(): AvailableEd25519SigningLane {
  return {
    curve: 'ed25519',
    chain: 'near',
    state: 'missing',
  };
}

function selectedLaneFromConcreteAvailableLane(args: {
  walletId: WalletId | string;
  lane: ConcreteAvailableSigningLane;
}): SelectedLane {
  if (args.lane.curve === 'ed25519') {
    return selectedEd25519Lane({
      walletId: args.lane.walletId,
      nearAccountId: args.lane.nearAccountId,
      nearEd25519SigningKeyId: args.lane.nearEd25519SigningKeyId,
      signerSlot: args.lane.signerSlot,
      auth: args.lane.auth,
      signingGrantId: args.lane.signingGrantId,
      thresholdSessionId: args.lane.thresholdSessionId,
    });
  }
  return selectedEcdsaLane({
    key: args.lane.key,
    keyHandle: args.lane.publicFacts.keyHandle,
    walletId: toWalletId(String(args.lane.key.walletId)),
    auth: args.lane.auth,
    signingGrantId: args.lane.signingGrantId,
    thresholdSessionId: args.lane.thresholdSessionId,
    chainTarget: args.lane.chainTarget,
  });
}

function availableLaneRecordVersion(lane: ConcreteAvailableSigningLane): string {
  return [
    lane.curve,
    'source' in lane ? lane.source || 'unknown' : 'unknown',
    String(lane.signingGrantId),
    String(lane.thresholdSessionId),
    String(availableLaneUpdatedAtMs(lane)),
  ].join(':');
}

function ecdsaCandidateRecordVersion(candidate: EcdsaLaneCandidate): string {
  return [
    candidate.curve,
    candidate.source || 'unknown',
    String(candidate.signingGrantId),
    String(candidate.thresholdSessionId),
    String(laneCandidateUpdatedAtMs(candidate)),
  ].join(':');
}

function sourceStateFromAvailableLane(
  lane: ConcreteAvailableSigningLane,
  freshness: FreshStepUpRequired,
): ReauthAnchorSourceState {
  const authMethod = signingLaneAuthMethod(lane.auth);
  return {
    kind: 'reauth_anchor_source_state',
    availabilitySource: 'source' in lane && lane.source ? lane.source : 'runtime_session_record',
    storeSource: authMethod === 'email_otp' ? 'email_otp' : 'login',
    retention: authMethod === 'email_otp' ? 'single_use' : 'session',
    remainingUses: nullableNonNegativeInteger(lane.remainingUses),
    expiry: freshness.expiry,
    projection: freshness.projection,
  };
}

function sourceStateFromEcdsaLaneCandidate(
  candidate: EcdsaLaneCandidate,
  freshness: FreshStepUpRequired,
): ReauthAnchorSourceState {
  const authMethod = signingLaneAuthMethod(candidate.auth);
  const remainingUses =
    candidate.state === 'exhausted' ? 0 : nullableNonNegativeInteger(candidate.remainingUses);
  return {
    kind: 'reauth_anchor_source_state',
    availabilitySource:
      candidate.source === 'unknown' ? 'runtime_session_record' : candidate.source,
    storeSource: authMethod === 'email_otp' ? 'email_otp' : 'login',
    retention: authMethod === 'email_otp' ? 'single_use' : 'session',
    remainingUses,
    expiry: freshness.expiry,
    projection: freshness.projection,
  };
}

function durablePolicyHint(
  record: SigningSessionSealedStoreRecord,
): AvailableSigningLanePolicyHint | undefined {
  const remainingUses = Math.floor(Number(record.remainingUses));
  const expiresAtMs = Math.floor(Number(record.expiresAtMs));
  const hint: AvailableSigningLanePolicyHint = {};
  if (Number.isFinite(remainingUses) && remainingUses >= 0) {
    hint.remainingUses = remainingUses;
  }
  if (Number.isFinite(expiresAtMs) && expiresAtMs > 0) {
    hint.expiresAtMs = expiresAtMs;
  }
  return Object.keys(hint).length ? hint : undefined;
}

function ecdsaRecoveryRecordForDurableLane(
  record: SealedRecoveryRecord,
): EmailOtpEcdsaSealedRecoveryRecord | PasskeyEcdsaSealedRecoveryRecord | undefined {
  if (record.curve === 'ecdsa') return record;
  if (record.authMethod === 'email_otp') return record.companionEcdsaRecovery;
  return undefined;
}

type DurableEcdsaWalletSessionJwtClaims = {
  walletId: string;
  keyHandle: string;
  thresholdSessionId: string;
  signingGrantId: string;
};

function parseDurableEcdsaWalletSessionJwtClaims(
  jwt: string,
): DurableEcdsaWalletSessionJwtClaims | null {
  const payload = decodeJwtPayloadRecord(jwt);
  if (!payload || payload.kind !== ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND) {
    return null;
  }
  if (String(payload.keyScope || '').trim() !== 'evm-family') return null;
  const thresholdSessionId = String(payload.thresholdSessionId || '').trim();
  const signingGrantId = String(payload.signingGrantId || '').trim();
  const walletId = String(payload.walletId || '').trim();
  const keyHandle = String(payload.keyHandle || '').trim();
  if (!thresholdSessionId || !signingGrantId || !walletId || !keyHandle) return null;
  return {
    walletId,
    keyHandle,
    thresholdSessionId,
    signingGrantId,
  };
}

function durableEcdsaJwtMatchesRecord(args: {
  recoveryRecord: EmailOtpEcdsaSealedRecoveryRecord | PasskeyEcdsaSealedRecoveryRecord;
  thresholdSessionId: string;
  signingGrantId: string;
  expectedWalletId: string;
  expectedKeyHandle: string;
}): boolean {
  const jwt = String(
    sealedRecoveryWalletSessionJwt(args.recoveryRecord.walletSessionAuth) || '',
  ).trim();
  if (!jwt) return true;
  const claims = parseDurableEcdsaWalletSessionJwtClaims(jwt);
  if (!claims) return false;
  if (claims.walletId !== args.expectedWalletId) return false;
  if (claims.keyHandle !== args.expectedKeyHandle) return false;

  return (
    claims.thresholdSessionId === args.thresholdSessionId &&
    claims.signingGrantId === args.signingGrantId
  );
}

async function publicFactsFromAvailableEcdsaKey(args: {
  key: EvmFamilyEcdsaKeyIdentity;
  keyHandle?: EvmFamilyEcdsaKeyHandle;
  verifiedPublicFacts?: VerifiedEcdsaPublicFacts;
  thresholdEcdsaPublicKeyB64u: unknown;
}): Promise<VerifiedEcdsaPublicFacts> {
  if (args.verifiedPublicFacts) return args.verifiedPublicFacts;
  const keyHandle = String(args.keyHandle || '').trim();
  if (!keyHandle) {
    throw new Error('missing runtime ECDSA keyHandle');
  }
  return buildVerifiedEcdsaPublicFacts({
    keyHandle: args.keyHandle!,
    publicKeyB64u: args.thresholdEcdsaPublicKeyB64u,
    participantIds: args.key.participantIds,
    thresholdOwnerAddress: args.key.thresholdOwnerAddress,
  });
}

function concreteAvailableEcdsaAuthFields(args: {
  key: EvmFamilyEcdsaKeyIdentity;
  auth?: SigningLaneAuthBinding;
  publicFacts: VerifiedEcdsaPublicFacts;
}): ConcreteAvailableEcdsaSigningLaneAuth | null {
  if (args.auth?.kind === 'passkey') {
    if (!args.auth || args.auth.kind !== 'passkey') return null;
    return {
      auth: args.auth,
      resolvedKey: buildResolvedEvmFamilyEcdsaKey({
        walletId: args.key.walletId,
        publicFacts: args.publicFacts,
        authBinding: buildPasskeyEcdsaAuthBinding({
          rpId: args.auth.rpId,
          credentialIdB64u: args.auth.credentialIdB64u,
        }),
      }),
    };
  }
  if (!args.auth || args.auth.kind !== 'email_otp') return null;
  return { auth: args.auth };
}

export function buildRuntimeEcdsaAvailableLaneIdentityInput(args: {
  record: AvailableSigningLanesRuntimeEcdsaRecord;
  publicFacts: VerifiedEcdsaPublicFacts;
}): EcdsaAvailableLaneIdentityInput {
  if (args.record.auth.kind === 'passkey') {
    const resolvedKey =
      runtimePasskeyResolvedKeyFromRecord(args) ||
      buildResolvedEvmFamilyEcdsaKey({
        walletId: args.record.key.walletId,
        publicFacts: args.publicFacts,
        authBinding: buildPasskeyEcdsaAuthBinding({
          rpId: args.record.auth.rpId,
          credentialIdB64u: args.record.auth.credentialIdB64u,
        }),
      });
    return {
      key: args.record.key,
      publicFacts: args.publicFacts,
      auth: passkeyAuthFromResolvedEcdsaKey(resolvedKey),
      resolvedKey,
      curve: 'ecdsa',
      chainTarget: args.record.chainTarget,
      signingGrantId: args.record.signingGrantId,
      thresholdSessionId: args.record.thresholdSessionId,
    };
  }
  return {
    key: args.record.key,
    publicFacts: args.publicFacts,
    auth: args.record.auth,
    curve: 'ecdsa',
    chainTarget: args.record.chainTarget,
    signingGrantId: args.record.signingGrantId,
    thresholdSessionId: args.record.thresholdSessionId,
  };
}

export async function runtimeEcdsaAvailableLaneIdentityKey(
  record: AvailableSigningLanesRuntimeEcdsaRecord,
): Promise<string | null> {
  const publicFacts = await publicFactsFromAvailableEcdsaKey({
    key: record.key,
    keyHandle: record.keyHandle,
    verifiedPublicFacts: record.verifiedPublicFacts,
    thresholdEcdsaPublicKeyB64u: record.thresholdEcdsaPublicKeyB64u,
  });
  return ecdsaAvailableLaneIdentityKey(
    buildRuntimeEcdsaAvailableLaneIdentityInput({ record, publicFacts }),
  );
}

async function recordToEcdsaLane(args: {
  chainTarget: ThresholdEcdsaChainTarget;
  record: SigningSessionSealedStoreRecord;
}): Promise<AvailableEcdsaSigningLane | null> {
  const normalized = normalizeSealedRecoveryRecord(args.record, {
    allowExpired: true,
    allowExhausted: true,
  });
  if (normalized.kind !== 'accepted') return null;
  const recoveryRecord = ecdsaRecoveryRecordForDurableLane(normalized.record);
  if (!recoveryRecord) return null;
  let recordTargetKey: string;
  try {
    recordTargetKey = thresholdEcdsaChainTargetKey(recoveryRecord.chainTarget);
  } catch {
    return null;
  }
  if (recordTargetKey !== thresholdEcdsaChainTargetKey(args.chainTarget)) {
    return null;
  }

  const thresholdSessionId = String(recoveryRecord.thresholdSessionId || '').trim();
  const signingGrantId = String(recoveryRecord.signingGrantId || '').trim();
  let ecdsaThresholdKeyId = '';
  try {
    ecdsaThresholdKeyId = String(
      resolveThresholdEcdsaKeyIdFromRecord({
        record: {
          ecdsaThresholdKeyId: recoveryRecord.ecdsaThresholdKeyId,
        },
      }),
    ).trim();
  } catch {
    ecdsaThresholdKeyId = '';
  }
  const policyHint = durablePolicyHint(args.record);
  const walletId = String(args.record.walletId || '').trim();
  if (
    !thresholdSessionId ||
    !signingGrantId ||
    !walletId ||
    !recoveryRecord.keyHandle ||
    !ecdsaThresholdKeyId
  ) {
    return null;
  }
  if (
    !durableEcdsaJwtMatchesRecord({
      recoveryRecord,
      thresholdSessionId,
      signingGrantId,
      expectedWalletId: walletId,
      expectedKeyHandle: String(recoveryRecord.keyHandle || '').trim(),
    })
  ) {
    return null;
  }
  let keyIdentity: ReturnType<typeof buildBaseEvmFamilyEcdsaKeyIdentity>;
  try {
    keyIdentity = buildBaseEvmFamilyEcdsaKeyIdentity({
      walletId,
      evmFamilySigningKeySlotId: recoveryRecord.evmFamilySigningKeySlotId,
      ecdsaThresholdKeyId,
      signingRootId: recoveryRecord.signingRootId,
      signingRootVersion: recoveryRecord.signingRootVersion,
      participantIds: recoveryRecord.participantIds,
      thresholdOwnerAddress: recoveryRecord.ethereumAddress,
    });
  } catch {
    return null;
  }
  let publicFacts: VerifiedEcdsaPublicFacts;
  try {
    publicFacts = await toVerifiedEcdsaPublicFactsFromDurableRecord({
      record: {
        ecdsaRestore: {
          keyHandle: recoveryRecord.keyHandle,
          thresholdEcdsaPublicKeyB64u: recoveryRecord.thresholdEcdsaPublicKeyB64u,
          participantIds: recoveryRecord.participantIds,
          ethereumAddress: recoveryRecord.ethereumAddress,
        },
      },
    });
  } catch {
    return null;
  }
  const expiresAtMs = Math.floor(Number(args.record.expiresAtMs) || 0);
  const remainingUses = Math.floor(Number(args.record.remainingUses) || 0);
  const state: AvailableSigningLaneState =
    expiresAtMs > 0 && expiresAtMs <= Date.now()
      ? 'expired'
      : args.record.authMethod === 'email_otp' && remainingUses <= 0
        ? 'exhausted'
        : 'restorable';
  const authFields = concreteAvailableEcdsaAuthFields({
    key: keyIdentity,
    auth: ecdsaRecoveryRecordAuthBinding(recoveryRecord) || undefined,
    publicFacts,
  });
  if (!authFields) return null;

  return {
    key: keyIdentity,
    publicFacts,
    ...authFields,
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    state,
    source: 'durable_sealed_record',
    signingGrantId,
    thresholdSessionId,
    updatedAtMs: Math.floor(Number(args.record.updatedAtMs) || 0),
    ...(policyHint ? { policyHint } : {}),
    ...(state === 'exhausted' ? { remainingUses: 0 } : {}),
    ...(state === 'expired' && expiresAtMs > 0 ? { expiresAtMs } : {}),
  };
}

function ed25519RecoveryRecordForDurableLane(
  record: SealedRecoveryRecord,
):
  | Extract<SealedRecoveryRecord, { curve: 'ed25519' }>
  | EmailOtpEcdsaCompanionEd25519Recovery
  | null {
  if (record.curve === 'ed25519') return record;
  if (record.authMethod === 'email_otp') return record.companionEd25519Recovery || null;
  return null;
}

function ed25519RecoveryRecordAuthBinding(
  record:
    | Extract<SealedRecoveryRecord, { curve: 'ed25519' }>
    | EmailOtpEcdsaCompanionEd25519Recovery,
): SigningLaneAuthBinding | null {
  if (record.authMethod === 'passkey') {
    return {
      kind: 'passkey',
      rpId: toRpId(record.authority.verifier.rpId),
      credentialIdB64u: record.authority.factor.credentialIdB64u,
    };
  }
  return {
    kind: 'email_otp',
    providerSubjectId: record.authority.factor.providerUserId,
  };
}

function recordToEd25519Lane(args: {
  record: SigningSessionSealedStoreRecord;
}): AvailableEd25519SigningLane | null {
  const normalized = normalizeSealedRecoveryRecord(args.record, {
    allowExpired: true,
    allowExhausted: true,
  });
  if (normalized.kind !== 'accepted') return null;
  const recoveryRecord = ed25519RecoveryRecordForDurableLane(normalized.record);
  if (!recoveryRecord) return null;
  const thresholdSessionId = String(recoveryRecord.thresholdSessionId || '').trim();
  const signingGrantId = String(recoveryRecord.signingGrantId || '').trim();
  if (!thresholdSessionId || !signingGrantId) return null;
  const policyHint = durablePolicyHint(args.record);
  const expiresAtMs = Math.floor(Number(recoveryRecord.expiresAtMs) || 0);
  const remainingUses = Math.max(0, Math.floor(Number(recoveryRecord.remainingUses) || 0));
  const state: AvailableSigningLaneState =
    expiresAtMs > 0 && expiresAtMs <= Date.now()
      ? 'expired'
      : remainingUses <= 0
        ? 'exhausted'
        : 'restorable';
  const auth = ed25519RecoveryRecordAuthBinding(recoveryRecord);
  if (!auth) return null;
  const signerSlot = parseSignerSlot(recoveryRecord.signerSlot);
  if (signerSlot == null) return null;
  const materialIdentity = ed25519SealedRecoveryMaterialIdentity(recoveryRecord);
  const material = ed25519AvailableMaterialStateFromBoundaryFields({
    bindingDigest: materialIdentity.bindingDigest,
    materialKeyId: materialIdentity.materialKeyId,
    kind: 'sealed_worker_material',
  });
  if (!material) return null;

  return {
    auth,
    curve: 'ed25519',
    chain: 'near',
    walletId: toWalletId(recoveryRecord.walletId),
    nearAccountId: toAccountId(recoveryRecord.nearAccountId),
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
      recoveryRecord.nearEd25519SigningKeyId,
    ),
    signerSlot,
    state,
    source: 'durable_sealed_record',
    signingGrantId,
    updatedAtMs: Math.floor(Number(args.record.updatedAtMs) || 0),
    thresholdSessionId,
    material,
    ...(remainingUses >= 0 ? { remainingUses } : {}),
    ...(expiresAtMs > 0 ? { expiresAtMs } : {}),
    ...(policyHint ? { policyHint } : {}),
  };
}

export function warmStatusToAvailableLaneStateAdvisory(args: {
  thresholdSessionId: string;
  status: { ok: true; remainingUses: number; expiresAtMs: number } | { ok: false; code: string };
}): AvailableLaneStateAdvisory {
  if (args.status.ok) {
    return {
      kind: 'warm_status',
      status: 'active',
      thresholdSessionId: args.thresholdSessionId,
      remainingUses: args.status.remainingUses,
      expiresAtMs: args.status.expiresAtMs,
    };
  }
  if (args.status.code === 'expired') {
    return { kind: 'warm_status', status: 'expired', thresholdSessionId: args.thresholdSessionId };
  }
  if (args.status.code === 'exhausted') {
    return {
      kind: 'warm_status',
      status: 'exhausted',
      thresholdSessionId: args.thresholdSessionId,
      remainingUses: 0,
    };
  }
  if (args.status.code === 'not_found') {
    return {
      kind: 'warm_status',
      status: 'cache_miss',
      thresholdSessionId: args.thresholdSessionId,
    };
  }
  return {
    kind: 'warm_status',
    status: 'unavailable',
    thresholdSessionId: args.thresholdSessionId,
    code: args.status.code,
  };
}

function advisoryRemainingUses(advisory: AvailableLaneStateAdvisory | null): number | undefined {
  if (!advisory) return undefined;
  return 'remainingUses' in advisory ? advisory.remainingUses : undefined;
}

function advisoryExpiresAtMs(advisory: AvailableLaneStateAdvisory | null): number | undefined {
  if (!advisory) return undefined;
  return 'expiresAtMs' in advisory ? advisory.expiresAtMs : undefined;
}

function advisoryToLaneState(
  advisory: AvailableLaneStateAdvisory | null,
  durableLane?: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
  recordPolicyState?: 'expired' | 'exhausted' | null,
): AvailableSigningLaneState {
  const durableConcreteState =
    durableLane && durableLane.state !== 'missing' ? durableLane.state : undefined;
  if (!advisory) return recordPolicyState || durableConcreteState || 'deferred';
  switch (advisory.kind) {
    case 'durable_policy':
      return recordPolicyState || advisory.state;
    case 'warm_status': {
      const warmStatus = advisory.status;
      switch (warmStatus) {
        case 'active':
          return 'ready';
        case 'expired':
          return 'expired';
        case 'exhausted':
          return 'exhausted';
        case 'cache_miss':
        case 'unavailable':
          return recordPolicyState || durableConcreteState || 'deferred';
        default: {
          const exhaustive: never = warmStatus;
          return exhaustive;
        }
      }
    }
    default: {
      const exhaustive: never = advisory;
      return exhaustive;
    }
  }
}

function runtimeRecordPolicyState(args: {
  remainingUses: number | null;
  expiresAtMs: number | null;
}): 'expired' | 'exhausted' | null {
  if (args.remainingUses === 0) return 'exhausted';
  if (args.expiresAtMs !== null && args.expiresAtMs <= Date.now()) return 'expired';
  return null;
}

async function runtimeRecordToEcdsaLane(args: {
  record: AvailableSigningLanesRuntimeEcdsaRecord;
  publicFacts: VerifiedEcdsaPublicFacts;
  advisory: AvailableLaneStateAdvisory | null;
  durableLane: AvailableEcdsaSigningLane;
}): Promise<ConcreteAvailableEcdsaSigningLane> {
  const thresholdSessionId = String(args.record.thresholdSessionId || '').trim();
  const advisory = args.advisory;
  const runtimeLaneIdentity = buildRuntimeEcdsaAvailableLaneIdentityInput({
    record: args.record,
    publicFacts: args.publicFacts,
  });
  const runtimeLaneKey = ecdsaAvailableLaneIdentityKey(runtimeLaneIdentity);
  const durableLaneKey = ecdsaAvailableLaneIdentityKey(args.durableLane);
  const hasMatchingDurableLane =
    isConcreteAvailableSigningLane(args.durableLane) &&
    args.durableLane.source === 'durable_sealed_record' &&
    Boolean(runtimeLaneKey) &&
    durableLaneKey === runtimeLaneKey;
  const remainingUses = nullableNonNegativeInteger(
    advisoryRemainingUses(advisory) ?? args.record.remainingUses,
  );
  const expiresAtMs = nullablePositiveInteger(
    advisoryExpiresAtMs(advisory) ?? args.record.expiresAtMs,
  );
  const recordPolicyState = runtimeRecordPolicyState({ remainingUses, expiresAtMs });
  const runtimeUpdatedAtMs = nullablePositiveInteger(args.record.updatedAtMs) || 0;
  const durableUpdatedAtMs =
    hasMatchingDurableLane && isConcreteAvailableSigningLane(args.durableLane)
      ? nullablePositiveInteger(args.durableLane.updatedAtMs) || 0
      : 0;
  const updatedAtMs = Math.max(runtimeUpdatedAtMs, durableUpdatedAtMs);
  const base = {
    key: args.record.key,
    publicFacts: args.publicFacts,
    curve: 'ecdsa',
    chainTarget: args.record.chainTarget,
    state: advisoryToLaneState(
      advisory,
      hasMatchingDurableLane ? args.durableLane : undefined,
      recordPolicyState,
    ),
    source: 'runtime_session_record',
    signingGrantId: args.record.signingGrantId,
    thresholdSessionId,
    ...(remainingUses == null ? {} : { remainingUses }),
    ...(expiresAtMs == null ? {} : { expiresAtMs }),
    ...(updatedAtMs > 0 ? { updatedAtMs } : {}),
  } as const;
  if (runtimeLaneIdentity.auth.kind === 'passkey') {
    const resolvedKey = runtimeLaneIdentity.resolvedKey;
    if (!resolvedKey) {
      throw new Error('[SigningSession] passkey ECDSA runtime lane is missing resolved key');
    }
    return {
      ...base,
      auth: runtimeLaneIdentity.auth,
      resolvedKey,
    };
  }
  return {
    ...base,
    auth: runtimeLaneIdentity.auth,
  };
}

function runtimeRecordToEd25519Lane(args: {
  record: AvailableSigningLanesRuntimeEd25519Record;
  advisory: AvailableLaneStateAdvisory | null;
  durableLane: AvailableEd25519SigningLane;
}): ConcreteAvailableEd25519SigningLane | null {
  const thresholdSessionId = String(args.record.thresholdSessionId || '').trim();
  const signingGrantId = String(args.record.signingGrantId || '').trim();
  if (!thresholdSessionId || !signingGrantId) return null;
  const durableSigningGrantId = String(args.durableLane.signingGrantId || '').trim();
  const advisory = args.advisory;
  const hasMatchingDurableLane =
    args.durableLane.source === 'durable_sealed_record' &&
    isConcreteAvailableSigningLane(args.durableLane) &&
    args.durableLane.curve === 'ed25519' &&
    availableEd25519SigningLaneAuthMethod(args.durableLane) ===
      signingLaneAuthMethod(args.record.auth) &&
    durableSigningGrantId === signingGrantId &&
    String(args.durableLane.thresholdSessionId || '').trim() === thresholdSessionId;
  const matchingDurableLane =
    hasMatchingDurableLane && isConcreteEd25519AvailableLane(args.durableLane)
      ? args.durableLane
      : null;
  const remainingUses = nullableNonNegativeInteger(
    advisoryRemainingUses(advisory) ?? args.record.remainingUses,
  );
  const expiresAtMs = nullablePositiveInteger(
    advisoryExpiresAtMs(advisory) ?? args.record.expiresAtMs,
  );
  const recordPolicyState = runtimeRecordPolicyState({ remainingUses, expiresAtMs });
  const runtimeUpdatedAtMs = nullablePositiveInteger(args.record.updatedAtMs) || 0;
  const durableUpdatedAtMs = hasMatchingDurableLane
    ? nullablePositiveInteger(args.durableLane.updatedAtMs) || 0
    : 0;
  const updatedAtMs = Math.max(runtimeUpdatedAtMs, durableUpdatedAtMs);
  const signerSlot = parseSignerSlot(args.record.signerSlot);
  if (signerSlot == null) return null;
  const material = resolveEd25519RuntimeAvailableMaterial({
    material: args.record.material,
    matchingDurableLane,
  });
  if (!material) return null;

  return {
    auth: args.record.auth,
    curve: 'ed25519',
    chain: 'near',
    walletId: args.record.walletId,
    nearAccountId: args.record.nearAccountId,
    nearEd25519SigningKeyId: args.record.nearEd25519SigningKeyId,
    signerSlot,
    state: advisoryToLaneState(
      advisory,
      hasMatchingDurableLane ? args.durableLane : undefined,
      recordPolicyState,
    ),
    source: 'runtime_session_record',
    signingGrantId,
    thresholdSessionId,
    ...(remainingUses == null ? {} : { remainingUses }),
    ...(expiresAtMs == null ? {} : { expiresAtMs }),
    ...(updatedAtMs > 0 ? { updatedAtMs } : {}),
    material,
  };
}

function availableLaneUpdatedAtMs(
  lane: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
): number {
  return Math.floor(Number('updatedAtMs' in lane ? lane.updatedAtMs : 0) || 0);
}

function laneCandidateUpdatedAtMs(candidate: EcdsaLaneCandidate | Ed25519LaneCandidate): number {
  return Math.floor(Number(candidate.updatedAtMs) || 0);
}

function laneCandidateExpiry(
  candidate: EcdsaLaneCandidate | Ed25519LaneCandidate,
): StepUpExpiryState {
  const expiresAtMs = nullablePositiveInteger(candidate.expiresAtMs);
  return expiresAtMs
    ? { kind: 'known', expiresAtMs }
    : { kind: 'unavailable', reason: 'restored_record_has_no_expiry' };
}

function laneCandidateStepUpReason(
  candidate: EcdsaLaneCandidate | Ed25519LaneCandidate,
): FreshStepUpRequired['reason'] {
  switch (candidate.state) {
    case 'expired':
      return 'threshold_session_expired';
    case 'exhausted':
      return 'threshold_session_exhausted';
    case 'ready':
    case 'restorable':
    case 'deferred':
      throw new Error('[SigningEngine] lane candidate does not require fresh auth');
    default: {
      const exhaustive: never = candidate.state;
      return exhaustive;
    }
  }
}

function availableLaneServerIssuedGeneration(
  lane: ConcreteAvailableEcdsaSigningLane | ConcreteAvailableEd25519SigningLane,
): ServerIssuedGeneration | null {
  return serverIssuedGenerationFromNumber(lane.expiresAtMs ?? lane.policyHint?.expiresAtMs);
}

function availableLaneStatePriority(
  lane: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
): number {
  switch (lane.state) {
    case 'ready':
      return 5;
    case 'restorable':
      return 4;
    case 'deferred':
      return 3;
    case 'expired':
    case 'exhausted':
      return 2;
    case 'missing':
      return 1;
  }
}

function availableLaneSourcePriority(
  lane: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
): number {
  if (!isConcreteAvailableSigningLane(lane)) return 0;
  switch (lane.source) {
    case 'runtime_session_record':
      return 4;
    case 'evm_family_shared_key':
      return 2;
    case 'durable_sealed_record':
      return 1;
    default:
      return 0;
  }
}

function compareAvailableLanePriority(
  left: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
  right: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
): number {
  const stateDelta = availableLaneStatePriority(left) - availableLaneStatePriority(right);
  if (stateDelta) return stateDelta;
  const sourceDelta = availableLaneSourcePriority(left) - availableLaneSourcePriority(right);
  if (sourceDelta) return sourceDelta;
  return availableLaneUpdatedAtMs(left) - availableLaneUpdatedAtMs(right);
}

function ed25519AvailableLaneMaterialPriority(lane: AvailableEd25519SigningLane): number {
  if (!isConcreteAvailableSigningLane(lane) || lane.curve !== 'ed25519') return 0;
  switch (lane.material.kind) {
    case 'loaded_worker_material':
      return 3;
    case 'sealed_worker_material':
      return 2;
    case 'material_pending':
      return 0;
  }
}

function compareEd25519AvailableLanePriority(
  left: AvailableEd25519SigningLane,
  right: AvailableEd25519SigningLane,
): number {
  const materialDelta =
    ed25519AvailableLaneMaterialPriority(left) - ed25519AvailableLaneMaterialPriority(right);
  if (materialDelta) return materialDelta;
  return compareAvailableLanePriority(left, right);
}

type Ed25519LaneGroupKey = {
  walletId: string;
  authKey: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: string;
};

type Ed25519LaneRecordFact = {
  groupKey: Ed25519LaneGroupKey;
  lane: ConcreteAvailableEd25519SigningLane;
};

function ed25519LaneGroupKey(
  lane: ConcreteAvailableEd25519SigningLane,
): Ed25519LaneGroupKey | null {
  const authKey = signingLaneAuthBindingKey(lane.auth);
  const walletId = String(lane.walletId || '').trim();
  const nearAccountId = String(lane.nearAccountId || '').trim();
  const nearEd25519SigningKeyId = String(lane.nearEd25519SigningKeyId || '').trim();
  const signerSlot = String(lane.signerSlot || '').trim();
  if (!authKey || !walletId || !nearAccountId || !nearEd25519SigningKeyId || !signerSlot) {
    return null;
  }
  return {
    walletId,
    authKey,
    nearAccountId,
    nearEd25519SigningKeyId,
    signerSlot,
  };
}

function ed25519LaneGroupKeyString(key: Ed25519LaneGroupKey): string {
  return [
    key.walletId,
    key.authKey,
    key.nearAccountId,
    key.nearEd25519SigningKeyId,
    key.signerSlot,
  ]
    .map((part) => encodeURIComponent(part))
    .join('|');
}

function ed25519LaneRecordFact(
  lane: AvailableEd25519SigningLane,
): Ed25519LaneRecordFact | null {
  if (!isConcreteAvailableSigningLane(lane) || lane.curve !== 'ed25519') return null;
  const groupKey = ed25519LaneGroupKey(lane);
  if (!groupKey) return null;
  return { groupKey, lane };
}

function compareEd25519AvailableLanePriorityDescending(
  left: AvailableEd25519SigningLane,
  right: AvailableEd25519SigningLane,
): number {
  return compareEd25519AvailableLanePriority(right, left);
}

function canonicalTieBreakFromNumber(left: number, right: number): CanonicalTieBreakOrder {
  if (left > right) return 1;
  if (right > left) return -1;
  return 0;
}

function canonicalTieBreakFromString(left: string, right: string): CanonicalTieBreakOrder {
  const comparison = left.localeCompare(right);
  if (comparison > 0) return 1;
  if (comparison < 0) return -1;
  return 0;
}

function firstCanonicalTieBreakResult(
  results: readonly CanonicalTieBreakOrder[],
): CanonicalTieBreakOrder {
  for (const result of results) {
    if (result !== 0) return result;
  }
  return 0;
}

type Ed25519LaneConflict = never;

function ed25519LaneGroupConflicts(
  _facts: readonly Ed25519LaneRecordFact[],
): readonly Ed25519LaneConflict[] {
  return [];
}

function isEd25519CanonicalFactOperationUsable(fact: Ed25519LaneRecordFact): boolean {
  return fact.lane.state !== 'deferred' && fact.lane.material.kind !== 'material_pending';
}

function ed25519CanonicalFactGeneration(
  fact: Ed25519LaneRecordFact,
): ServerIssuedGeneration | null {
  return availableLaneServerIssuedGeneration(fact.lane);
}

function ed25519CanonicalFactExactness(): 'exact_target' {
  return 'exact_target';
}

function ed25519CanonicalTieBreak(
  left: Ed25519LaneRecordFact,
  right: Ed25519LaneRecordFact,
): CanonicalTieBreakOrder {
  return firstCanonicalTieBreakResult([
    canonicalTieBreakFromNumber(
      availableLaneStatePriority(left.lane),
      availableLaneStatePriority(right.lane),
    ),
    canonicalTieBreakFromNumber(
      availableLaneSourcePriority(left.lane),
      availableLaneSourcePriority(right.lane),
    ),
    canonicalTieBreakFromNumber(
      ed25519AvailableLaneMaterialPriority(left.lane),
      ed25519AvailableLaneMaterialPriority(right.lane),
    ),
    canonicalTieBreakFromString(
      ed25519CanonicalStableTieBreakKey(left.lane),
      ed25519CanonicalStableTieBreakKey(right.lane),
    ),
  ]);
}

function ed25519CanonicalStableTieBreakKey(lane: ConcreteAvailableEd25519SigningLane): string {
  return [lane.thresholdSessionId, lane.signingGrantId, lane.source || 'runtime_session_record']
    .map((part) => String(part))
    .join('|');
}

const ed25519CanonicalSupersession: CanonicalFactSupersession<Ed25519LaneRecordFact> = {
  isOperationUsable: isEd25519CanonicalFactOperationUsable,
  generation: ed25519CanonicalFactGeneration,
  exactness: ed25519CanonicalFactExactness,
  tieBreak: ed25519CanonicalTieBreak,
};

const ed25519CanonicalLaneInventoryAdapter: CanonicalLaneInventoryAdapter<
  Ed25519LaneRecordFact,
  Ed25519LaneGroupKey,
  Ed25519LaneConflict
> = {
  groupKey: ed25519RecordFactGroupKey,
  groupKeyString: ed25519LaneGroupKeyString,
  groupConflicts: ed25519LaneGroupConflicts,
  supersession: ed25519CanonicalSupersession,
};

function ed25519RecordFactGroupKey(fact: Ed25519LaneRecordFact): Ed25519LaneGroupKey {
  return fact.groupKey;
}

function ed25519FactsByGroup(
  facts: readonly Ed25519LaneRecordFact[],
): Map<string, Ed25519LaneRecordFact[]> {
  const groups = new Map<string, Ed25519LaneRecordFact[]>();
  for (const fact of facts) {
    const groupKey = ed25519LaneGroupKeyString(fact.groupKey);
    groups.set(groupKey, [...(groups.get(groupKey) || []), fact]);
  }
  return groups;
}

function canonicalizeEd25519FactGroup(
  facts: readonly Ed25519LaneRecordFact[],
  invalidLanes: InvalidAvailableSigningLaneDiagnostic[],
): AvailableEd25519SigningLane[] {
  const selection = canonicalizeLaneFacts(facts, ed25519CanonicalLaneInventoryAdapter);
  switch (selection.kind) {
    case 'selected':
      return [selection.selectedFact.lane];
    case 'no_current_lane':
      return [];
    case 'conflicting_key_material':
      invalidLanes.push({
        curve: 'ed25519',
        source: 'canonical_lane_inventory',
        reason: 'conflicting_key_material',
        message: 'Ed25519 canonical lane inventory has conflicting material facts',
      });
      return [];
    case 'ambiguous_material':
      invalidLanes.push({
        curve: 'ed25519',
        source: 'canonical_lane_inventory',
        reason: 'ambiguous_material',
        message: 'Ed25519 canonical lane inventory has incomparable usable records',
      });
      return [];
    default: {
      const exhaustive: never = selection;
      return exhaustive;
    }
  }
}

function canonicalizeEd25519AvailableLanes(
  candidates: readonly AvailableEd25519SigningLane[],
  invalidLanes: InvalidAvailableSigningLaneDiagnostic[],
): AvailableEd25519SigningLane[] {
  const facts = candidates
    .map(ed25519LaneRecordFact)
    .filter((fact): fact is Ed25519LaneRecordFact => fact !== null);
  const canonicalLanes: AvailableEd25519SigningLane[] = [];
  for (const factGroup of ed25519FactsByGroup(facts).values()) {
    canonicalLanes.push(...canonicalizeEd25519FactGroup(factGroup, invalidLanes));
  }
  return canonicalLanes.sort(compareEd25519AvailableLanePriorityDescending);
}

function ed25519CompanionIdentityKey(lane: AvailableEd25519SigningLane): string | null {
  if (!isConcreteAvailableSigningLane(lane) || lane.curve !== 'ed25519') return null;
  const signingGrantId = String(lane.signingGrantId || '').trim();
  const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
  if (!signingGrantId || !thresholdSessionId) return null;
  return `${signingGrantId}:${thresholdSessionId}`;
}

function emailOtpPreferredEd25519PrimaryLane(args: {
  primaryLane: AvailableEd25519SigningLane;
  candidates: AvailableEd25519SigningLane[];
}): AvailableEd25519SigningLane {
  if (
    !isConcreteAvailableSigningLane(args.primaryLane) ||
    args.primaryLane.curve !== 'ed25519' ||
    availableEd25519SigningLaneAuthMethod(args.primaryLane) !== 'passkey'
  ) {
    return args.primaryLane;
  }
  const primaryKey = ed25519CompanionIdentityKey(args.primaryLane);
  if (!primaryKey) return args.primaryLane;
  const emailOtpLane = args.candidates.find(
    (candidate) =>
      isConcreteAvailableSigningLane(candidate) &&
      candidate.curve === 'ed25519' &&
      availableEd25519SigningLaneAuthMethod(candidate) === 'email_otp' &&
      ed25519CompanionIdentityKey(candidate) === primaryKey,
  );
  return emailOtpLane || args.primaryLane;
}

function primaryEd25519LaneFromNormalizedCandidates(args: {
  primaryLane: AvailableEd25519SigningLane;
  candidates: AvailableEd25519SigningLane[];
}): AvailableEd25519SigningLane {
  const primaryKey = ed25519AvailableLaneIdentityKey(args.primaryLane);
  if (!primaryKey) return args.primaryLane;
  return (
    args.candidates.find(
      (candidate) => ed25519AvailableLaneIdentityKey(candidate) === primaryKey,
    ) ||
    args.candidates[0] ||
    args.primaryLane
  );
}

function isAvailableSigningLaneDiagnosticsEnabled(): boolean {
  try {
    const storage = (globalThis as { localStorage?: Storage }).localStorage;
    return storage?.getItem('seams:debug:signing-session') === '1';
  } catch {
    return false;
  }
}

function summarizeEcdsaLaneForDiagnostics(
  lane: AvailableEcdsaSigningLane | null | undefined,
): Record<string, unknown> {
  if (!lane) return { present: false };
  if (!isConcreteAvailableSigningLane(lane)) {
    return {
      present: true,
      curve: lane.curve,
      chainTarget: lane.chainTarget,
      state: lane.state,
    };
  }
  return {
    present: true,
    authMethod: signingLaneAuthMethod(lane.auth),
    curve: lane.curve,
    keyHandle: lane.publicFacts.keyHandle,
    walletId: lane.key.walletId,
    chainTarget: lane.chainTarget,
    targetKey: thresholdEcdsaChainTargetKey(lane.chainTarget),
    state: lane.state,
    source: lane.source,
    ...(lane.source === 'evm_family_shared_key'
      ? { sourceChainTarget: lane.sourceChainTarget }
      : {}),
    signingGrantId: lane.signingGrantId,
    thresholdSessionId: lane.thresholdSessionId,
    evmFamilyKeyFingerprint: deriveAvailableEcdsaLaneFingerprint(lane),
    ecdsaThresholdKeyId: lane.key.ecdsaThresholdKeyId,
    participantIds: lane.publicFacts.participantIds,
    thresholdOwnerAddress: lane.publicFacts.thresholdOwnerAddress,
    remainingUses: lane.remainingUses,
    expiresAtMs: lane.expiresAtMs,
    updatedAtMs: lane.updatedAtMs,
  };
}

function ecdsaLaneRecordFactSource(
  lane: ConcreteAvailableEcdsaSigningLane,
): EcdsaLaneRecordFactSource {
  if (lane.source === 'evm_family_shared_key') return 'evm_family_shared_projection';
  if (lane.source === 'durable_sealed_record') return 'sealed_restore_record';
  return 'runtime_session_record';
}

function ecdsaLaneGroupKey(lane: ConcreteAvailableEcdsaSigningLane): EcdsaLaneGroupKey | null {
  const authKey = ecdsaAvailableLaneAuthKey(lane.auth);
  if (!authKey) return null;
  return {
    walletId: String(lane.key.walletId),
    authKey,
    evmFamilySigningKeySlotId: String(lane.key.evmFamilySigningKeySlotId),
    ecdsaThresholdKeyId: String(lane.key.ecdsaThresholdKeyId),
    signingRootId: String(lane.key.signingRootId),
    signingRootVersion: String(lane.key.signingRootVersion || 'default'),
  };
}

function ecdsaLaneGroupKeyString(key: EcdsaLaneGroupKey): string {
  return [
    key.walletId,
    key.authKey,
    key.evmFamilySigningKeySlotId,
    key.ecdsaThresholdKeyId,
    key.signingRootId,
    key.signingRootVersion,
  ]
    .map((part) => encodeURIComponent(part))
    .join('|');
}

function ecdsaLaneRecordFact(lane: ConcreteAvailableEcdsaSigningLane): EcdsaLaneRecordFact | null {
  const groupKey = ecdsaLaneGroupKey(lane);
  if (!groupKey) return null;
  return {
    source: ecdsaLaneRecordFactSource(lane),
    groupKey,
    chainTargetKey: thresholdEcdsaChainTargetKey(lane.chainTarget),
    lane,
  };
}

function ecdsaLaneFamilyGroupKeyString(lane: ConcreteAvailableEcdsaSigningLane): string | null {
  const authKey = ecdsaAvailableLaneAuthKey(lane.auth);
  if (!authKey) return null;
  return [
    String(lane.key.walletId),
    authKey,
    String(lane.key.evmFamilySigningKeySlotId),
    String(lane.key.signingRootId),
    String(lane.key.signingRootVersion || 'default'),
  ]
    .map((part) => encodeURIComponent(part))
    .join('|');
}

function ecdsaCanonicalPublicFactValues(
  facts: readonly EcdsaLaneRecordFact[],
  read: (lane: ConcreteAvailableEcdsaSigningLane) => string,
): string[] {
  return [...new Set(facts.map((fact) => read(fact.lane)).filter(Boolean))].sort();
}

function ecdsaLaneGroupConflicts(group: EcdsaLaneGroup): EcdsaLaneConflict[] {
  const fields = [
    {
      field: 'ecdsaThresholdKeyId' as const,
      values: ecdsaCanonicalPublicFactValues(group.facts, (lane) =>
        String(lane.key.ecdsaThresholdKeyId || ''),
      ),
    },
    {
      field: 'thresholdOwnerAddress' as const,
      values: ecdsaCanonicalPublicFactValues(group.facts, (lane) =>
        String(lane.publicFacts.thresholdOwnerAddress || '').toLowerCase(),
      ),
    },
    {
      field: 'keyHandle' as const,
      values: ecdsaCanonicalPublicFactValues(group.facts, (lane) =>
        String(lane.publicFacts.keyHandle || ''),
      ),
    },
    {
      field: 'publicKeyB64u' as const,
      values: ecdsaCanonicalPublicFactValues(group.facts, (lane) =>
        String(lane.publicFacts.publicKeyB64u || ''),
      ),
    },
    {
      field: 'participantIds' as const,
      values: ecdsaCanonicalPublicFactValues(group.facts, (lane) =>
        lane.publicFacts.participantIds.map((participantId) => Number(participantId)).join(','),
      ),
    },
  ];
  return fields
    .filter((entry) => entry.values.length > 1)
    .map((entry) => ({
      groupKey: group.key,
      field: entry.field,
      values: entry.values,
    }));
}

function ecdsaFamilyGroupConflicts(
  facts: readonly EcdsaLaneRecordFact[],
): Map<string, EcdsaLaneConflict[]> {
  const factsByFamilyGroup = new Map<string, EcdsaLaneRecordFact[]>();
  for (const fact of facts) {
    const familyGroupKey = ecdsaLaneFamilyGroupKeyString(fact.lane);
    if (!familyGroupKey) continue;
    factsByFamilyGroup.set(familyGroupKey, [
      ...(factsByFamilyGroup.get(familyGroupKey) || []),
      fact,
    ]);
  }
  const conflictsByFamilyGroup = new Map<string, EcdsaLaneConflict[]>();
  for (const [familyGroupKey, groupFacts] of factsByFamilyGroup) {
    const firstFact = groupFacts[0];
    if (!firstFact) continue;
    const conflicts = ecdsaLaneGroupConflicts({
      key: firstFact.groupKey,
      facts: groupFacts,
    });
    if (conflicts.length) {
      conflictsByFamilyGroup.set(familyGroupKey, conflicts);
    }
  }
  return conflictsByFamilyGroup;
}

function ecdsaFactFamilyConflicts(args: {
  fact: EcdsaLaneRecordFact;
  conflictsByFamilyGroup: Map<string, EcdsaLaneConflict[]>;
}): readonly EcdsaLaneConflict[] {
  const familyGroupKey = ecdsaLaneFamilyGroupKeyString(args.fact.lane);
  if (!familyGroupKey) return [];
  return args.conflictsByFamilyGroup.get(familyGroupKey) || [];
}

function ecdsaRecordFactsForCandidates(
  candidates: readonly AvailableEcdsaSigningLane[],
): EcdsaLaneRecordFact[] {
  return candidates
    .filter(
      (candidate): candidate is ConcreteAvailableEcdsaSigningLane =>
        isConcreteAvailableSigningLane(candidate) && candidate.curve === 'ecdsa',
    )
    .map(ecdsaLaneRecordFact)
    .filter((fact): fact is EcdsaLaneRecordFact => fact !== null);
}

function ecdsaCanonicalSourcePriority(lane: ConcreteAvailableEcdsaSigningLane): number {
  if (lane.source === 'evm_family_shared_key') return 1;
  if (lane.source === 'durable_sealed_record') return 2;
  return 3;
}

function ecdsaCanonicalFactGroupKey(fact: EcdsaLaneRecordFact): EcdsaLaneGroupKey {
  return fact.groupKey;
}

function ecdsaCanonicalGroupConflicts(
  facts: readonly EcdsaLaneRecordFact[],
): readonly EcdsaLaneConflict[] {
  const firstFact = facts[0];
  if (!firstFact) return [];
  return ecdsaLaneGroupConflicts({ key: firstFact.groupKey, facts });
}

function isEcdsaCanonicalFactOperationUsable(fact: EcdsaLaneRecordFact): boolean {
  return fact.lane.state !== 'deferred';
}

function ecdsaCanonicalFactGeneration(fact: EcdsaLaneRecordFact): ServerIssuedGeneration | null {
  return availableLaneServerIssuedGeneration(fact.lane);
}

function ecdsaCanonicalFactExactness(
  fact: EcdsaLaneRecordFact,
): 'exact_target' | 'shared_projection' {
  return fact.lane.source === 'evm_family_shared_key' ? 'shared_projection' : 'exact_target';
}

function ecdsaCanonicalStableTieBreakKey(lane: ConcreteAvailableEcdsaSigningLane): string {
  return [
    lane.thresholdSessionId,
    lane.signingGrantId,
    lane.source || 'runtime_session_record',
    thresholdEcdsaChainTargetKey(lane.chainTarget),
  ]
    .map((part) => String(part))
    .join('|');
}

function ecdsaCanonicalTieBreak(
  left: EcdsaLaneRecordFact,
  right: EcdsaLaneRecordFact,
): CanonicalTieBreakOrder {
  return firstCanonicalTieBreakResult([
    canonicalTieBreakFromNumber(
      availableLaneStatePriority(left.lane),
      availableLaneStatePriority(right.lane),
    ),
    canonicalTieBreakFromNumber(
      ecdsaCanonicalSourcePriority(left.lane),
      ecdsaCanonicalSourcePriority(right.lane),
    ),
    canonicalTieBreakFromString(
      ecdsaCanonicalStableTieBreakKey(left.lane),
      ecdsaCanonicalStableTieBreakKey(right.lane),
    ),
  ]);
}

const ecdsaCanonicalSupersession: CanonicalFactSupersession<EcdsaLaneRecordFact> = {
  isOperationUsable: isEcdsaCanonicalFactOperationUsable,
  generation: ecdsaCanonicalFactGeneration,
  exactness: ecdsaCanonicalFactExactness,
  tieBreak: ecdsaCanonicalTieBreak,
};

const ecdsaCanonicalLaneInventoryAdapter: CanonicalLaneInventoryAdapter<
  EcdsaLaneRecordFact,
  EcdsaLaneGroupKey,
  EcdsaLaneConflict
> = {
  groupKey: ecdsaCanonicalFactGroupKey,
  groupKeyString: ecdsaLaneGroupKeyString,
  groupConflicts: ecdsaCanonicalGroupConflicts,
  supersession: ecdsaCanonicalSupersession,
};

function ecdsaGroupKeysForFacts(facts: readonly EcdsaLaneRecordFact[]): EcdsaLaneGroupKey[] {
  const groupKeysByEncodedKey = new Map<string, EcdsaLaneGroupKey>();
  for (const fact of facts) {
    groupKeysByEncodedKey.set(ecdsaLaneGroupKeyString(fact.groupKey), fact.groupKey);
  }
  return [...groupKeysByEncodedKey.values()];
}

function canonicalEcdsaLaneSelectionForFacts(
  facts: readonly EcdsaLaneRecordFact[],
): EcdsaCanonicalLaneSelection {
  const selection = canonicalizeLaneFacts(facts, ecdsaCanonicalLaneInventoryAdapter);
  switch (selection.kind) {
    case 'selected':
      return {
        kind: 'selected',
        selectedFact: selection.selectedFact,
        supersededFacts: selection.supersededFacts,
      };
    case 'no_current_lane':
      return {
        kind: 'no_current_lane',
        unusableFacts: selection.unusableFacts,
      };
    case 'conflicting_key_material':
      return { kind: 'conflicting_key_material', conflicts: selection.conflicts };
    case 'ambiguous_material':
      return {
        kind: 'ambiguous_material',
        candidates: ecdsaGroupKeysForFacts(selection.candidates),
        candidateFacts: selection.candidates,
      };
    default: {
      const exhaustive: never = selection;
      return exhaustive;
    }
  }
}

function canonicalizeEcdsaAvailableLanes(args: {
  targets: readonly ThresholdEcdsaChainTarget[];
  candidatesByTarget: Record<string, AvailableEcdsaSigningLane[]>;
  invalidLanes: InvalidAvailableSigningLaneDiagnostic[];
}): {
  lanesByTarget: Record<string, AvailableEcdsaSigningLane>;
  candidatesByTarget: Record<string, AvailableEcdsaSigningLane[]>;
} {
  const canonicalCandidatesByTarget: Record<string, AvailableEcdsaSigningLane[]> = {};
  const canonicalLanesByTarget: Record<string, AvailableEcdsaSigningLane> = {};
  const allConcreteFacts = Object.values(args.candidatesByTarget).flatMap(
    ecdsaRecordFactsForCandidates,
  );
  const conflictsByFamilyGroup = ecdsaFamilyGroupConflicts(allConcreteFacts);
  for (const chainTarget of args.targets) {
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    const concreteFacts = ecdsaRecordFactsForCandidates(args.candidatesByTarget[targetKey] || []);
    const targetConflicts = concreteFacts.flatMap((fact) =>
      ecdsaFactFamilyConflicts({ fact, conflictsByFamilyGroup }),
    );
    if (targetConflicts.length) {
      args.invalidLanes.push({
        curve: 'ecdsa',
        source: 'canonical_lane_inventory',
        reason: 'conflicting_key_material',
        targetKey,
        groupKey: targetConflicts[0]?.groupKey,
        conflicts: targetConflicts,
      });
      canonicalCandidatesByTarget[targetKey] = [];
      canonicalLanesByTarget[targetKey] = emptyEcdsaLane({ chainTarget });
      continue;
    }
    const selection = canonicalEcdsaLaneSelectionForFacts(concreteFacts);
    switch (selection.kind) {
      case 'selected':
        canonicalCandidatesByTarget[targetKey] = [selection.selectedFact.lane];
        canonicalLanesByTarget[targetKey] = selection.selectedFact.lane;
        break;
      case 'no_current_lane':
        canonicalCandidatesByTarget[targetKey] = [];
        canonicalLanesByTarget[targetKey] = emptyEcdsaLane({ chainTarget });
        break;
      case 'conflicting_key_material':
        args.invalidLanes.push({
          curve: 'ecdsa',
          source: 'canonical_lane_inventory',
          reason: 'conflicting_key_material',
          targetKey,
          groupKey: selection.conflicts[0]?.groupKey,
          conflicts: selection.conflicts,
        });
        canonicalCandidatesByTarget[targetKey] = [];
        canonicalLanesByTarget[targetKey] = emptyEcdsaLane({ chainTarget });
        break;
      case 'ambiguous_material':
        args.invalidLanes.push({
          curve: 'ecdsa',
          source: 'canonical_lane_inventory',
          reason: 'ambiguous_material',
          targetKey,
        });
        canonicalCandidatesByTarget[targetKey] = [];
        canonicalLanesByTarget[targetKey] = emptyEcdsaLane({ chainTarget });
        break;
    }
  }
  return {
    lanesByTarget: canonicalLanesByTarget,
    candidatesByTarget: canonicalCandidatesByTarget,
  };
}

function ecdsaSharedKeyCompletionGroup(lane: ConcreteAvailableEcdsaSigningLane): string {
  return [
    lane.key.walletId,
    ecdsaAvailableLaneAuthKey(lane.auth),
    lane.key.keyScope,
    lane.publicFacts.keyHandle,
    lane.publicFacts.publicKeyB64u,
    lane.publicFacts.thresholdOwnerAddress,
    lane.publicFacts.participantIds.map((participantId) => Number(participantId)).join(','),
    signingLaneAuthMethod(lane.auth),
  ]
    .map((part) => String(part))
    .join('|');
}

function sharedEvmFamilyLaneForTarget(args: {
  sourceLane: ConcreteAvailableEcdsaSigningLane;
  chainTarget: ThresholdEcdsaChainTarget;
}): ConcreteAvailableEcdsaSigningLane {
  const sourceLane = args.sourceLane;
  const sharedState: AvailableSigningLaneState =
    sourceLane.state === 'ready' ||
    sourceLane.state === 'expired' ||
    sourceLane.state === 'exhausted'
      ? sourceLane.state
      : 'deferred';
  const base = {
    key: sourceLane.key,
    publicFacts: sourceLane.publicFacts,
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    state: sharedState,
    source: 'evm_family_shared_key',
    sourceChainTarget: sourceLane.chainTarget,
    signingGrantId: sourceLane.signingGrantId,
    thresholdSessionId: sourceLane.thresholdSessionId,
    ...(sourceLane.remainingUses == null ? {} : { remainingUses: sourceLane.remainingUses }),
    ...(sourceLane.expiresAtMs == null ? {} : { expiresAtMs: sourceLane.expiresAtMs }),
    updatedAtMs: sourceLane.updatedAtMs,
  } as const;
  if (sourceLane.auth.kind === 'passkey') {
    const resolvedKey = sourceLane.resolvedKey;
    if (!resolvedKey) {
      throw new Error('[SigningSession] passkey ECDSA shared lane is missing resolved key');
    }
    return {
      ...base,
      auth: sourceLane.auth,
      resolvedKey,
    };
  }
  return {
    ...base,
    auth: sourceLane.auth,
  };
}

function completeMissingEvmFamilyTargetsFromSharedKey(args: {
  targets: readonly ThresholdEcdsaChainTarget[];
  lanesByTarget: Record<string, AvailableEcdsaSigningLane>;
  candidatesByTarget: Record<string, AvailableEcdsaSigningLane[]>;
  laneUpdatedAtMsByTarget: Record<string, number>;
}): void {
  const sourceLanesByGroup = new Map<string, ConcreteAvailableEcdsaSigningLane[]>();
  for (const candidates of Object.values(args.candidatesByTarget)) {
    for (const candidate of candidates) {
      if (!isConcreteAvailableSigningLane(candidate) || candidate.curve !== 'ecdsa') continue;
      if (candidate.source === 'evm_family_shared_key') continue;
      const groupKey = ecdsaSharedKeyCompletionGroup(candidate);
      sourceLanesByGroup.set(groupKey, [...(sourceLanesByGroup.get(groupKey) || []), candidate]);
    }
  }

  const uniqueSourceLanes = [...sourceLanesByGroup.values()]
    .filter((group) => group.length > 0)
    .map(
      (group) => [...group].sort((left, right) => compareAvailableLanePriority(right, left))[0]!,
    );
  if (uniqueSourceLanes.length !== 1) return;
  const sourceLane = uniqueSourceLanes[0]!;

  for (const chainTarget of args.targets) {
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    const concreteCandidates = (args.candidatesByTarget[targetKey] || []).filter(
      (candidate): candidate is ConcreteAvailableEcdsaSigningLane =>
        isConcreteAvailableSigningLane(candidate) && candidate.curve === 'ecdsa',
    );
    if (thresholdEcdsaChainTargetKey(sourceLane.chainTarget) === targetKey) continue;
    const sharedLane = sharedEvmFamilyLaneForTarget({ sourceLane, chainTarget });
    const bestTargetCandidate = [...concreteCandidates].sort((left, right) =>
      compareAvailableLanePriority(right, left),
    )[0];
    if (bestTargetCandidate && compareAvailableLanePriority(bestTargetCandidate, sharedLane) >= 0) {
      continue;
    }
    const existingSharedLane = concreteCandidates.find(
      (candidate) =>
        candidate.source === 'evm_family_shared_key' &&
        thresholdEcdsaChainTargetKey(candidate.sourceChainTarget) ===
          thresholdEcdsaChainTargetKey(sourceLane.chainTarget) &&
        ecdsaSharedKeyCompletionGroup(candidate) === ecdsaSharedKeyCompletionGroup(sourceLane),
    );
    if (existingSharedLane) continue;
    args.candidatesByTarget[targetKey] = [
      ...(args.candidatesByTarget[targetKey] || []),
      sharedLane,
    ];
    args.lanesByTarget[targetKey] = sharedLane;
    args.laneUpdatedAtMsByTarget[targetKey] = availableLaneUpdatedAtMs(sharedLane);
  }
}

function summarizeSealedEcdsaRecordForDiagnostics(
  record: SigningSessionSealedStoreRecord,
): Record<string, unknown> {
  const restore = record.ecdsaRestore;
  const normalized = normalizeSealedRecoveryRecord(record, {
    allowExpired: true,
    allowExhausted: true,
  });
  const recoveryRecord =
    normalized.kind === 'accepted' ? ecdsaRecoveryRecordForDurableLane(normalized.record) : null;
  return {
    storeKey: record.storeKey,
    walletId: String(record.walletId || '').trim() || null,
    authMethod: record.authMethod,
    curve: record.curve,
    signingGrantId: String(record.signingGrantId || '').trim() || null,
    thresholdSessionId: String(record.thresholdSessionIds?.ecdsa || '').trim() || null,
    restoreThresholdSessionId: String(recoveryRecord?.thresholdSessionId || '').trim() || null,
    restoreChainTarget: restore?.chainTarget || null,
    restoreTargetKey: restore?.chainTarget
      ? thresholdEcdsaChainTargetKey(restore.chainTarget)
      : null,
    keyHandle: String(restore?.keyHandle || '').trim() || null,
    ecdsaThresholdKeyId: String(recoveryRecord?.ecdsaThresholdKeyId || '').trim() || null,
    normalizedRecoveryKind: normalized.kind,
    updatedAtMs: Math.floor(Number(record.updatedAtMs) || 0),
  };
}

function collapseExactDuplicateAvailableLanes<
  TLane extends AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
>(
  lanes: TLane[],
  laneIdentityKey: (lane: TLane) => string | null,
  comparePriority: (left: TLane, right: TLane) => number = compareAvailableLanePriority,
): TLane[] {
  const keyedGroups = new Map<string, TLane[]>();
  const unkeyed: TLane[] = [];
  for (const lane of lanes) {
    const key = laneIdentityKey(lane);
    if (!key) {
      unkeyed.push(lane);
      continue;
    }
    keyedGroups.set(key, [...(keyedGroups.get(key) || []), lane]);
  }
  const normalized = [...keyedGroups.values()].map(
    (group) => [...group].sort((left, right) => comparePriority(right, left))[0]!,
  );
  return [...normalized, ...unkeyed];
}

export async function readAvailableSigningLanes(
  input: ReadAvailableSigningLanesInput,
  ports: ReadAvailableSigningLanesPorts,
): Promise<AvailableSigningLanes> {
  const walletId = toWalletId(input.walletId);
  const ecdsaTargetsByKey = new Map<string, ThresholdEcdsaChainTarget>();
  for (const chainTarget of input.ecdsaChainTargets) {
    ecdsaTargetsByKey.set(thresholdEcdsaChainTargetKey(chainTarget), chainTarget);
  }
  const ecdsaChainTargets = [...ecdsaTargetsByKey.values()];
  const ecdsaRecordsByTarget = await Promise.all(
    ecdsaChainTargets.map((chainTarget) =>
      ports.listSealedRecordsForWallet({
        walletId,
        filter: {
          ...(input.authMethod ? { authMethod: input.authMethod } : {}),
          curve: 'ecdsa',
          chainTarget,
        },
      }),
    ),
  );
  const walletScopedEcdsaRecords = ports.listEcdsaSealedRecordsForWallet
    ? await ports.listEcdsaSealedRecordsForWallet({
        walletId,
        filter: {
          ...(input.authMethod ? { authMethod: input.authMethod } : {}),
          curve: 'ecdsa',
        },
      })
    : [];
  const ecdsaRecordsByStoreKey = new Map<string, SigningSessionSealedStoreRecord>();
  for (const record of [...ecdsaRecordsByTarget.flat(), ...walletScopedEcdsaRecords]) {
    ecdsaRecordsByStoreKey.set(record.storeKey, record);
  }
  const ecdsaRecords = [...ecdsaRecordsByStoreKey.values()];
  const ed25519Records = await ports.listSealedRecordsForWallet({
    walletId,
    filter: {
      ...(input.authMethod ? { authMethod: input.authMethod } : {}),
      curve: 'ed25519',
    },
  });

  const ecdsaTargets = [...ecdsaChainTargets];
  const ecdsaLanesByTarget: Record<string, AvailableEcdsaSigningLane> = {};
  const ecdsaCandidatesByTarget: Record<string, AvailableEcdsaSigningLane[]> = {};
  const ecdsaLaneUpdatedAtMsByTarget: Record<string, number> = {};
  for (const chainTarget of ecdsaTargets) {
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    ecdsaLanesByTarget[targetKey] = emptyEcdsaLane({ chainTarget });
    ecdsaCandidatesByTarget[targetKey] = [];
    ecdsaLaneUpdatedAtMsByTarget[targetKey] = 0;
  }
  const ed25519Candidates: AvailableEd25519SigningLane[] = [];
  let ed25519Lane = emptyEd25519Lane();
  let ed25519LaneUpdatedAtMs = 0;
  let generation = 0;
  const collectDiagnostics = isAvailableSigningLaneDiagnosticsEnabled();
  const durableEcdsaDiscovery: Record<string, unknown>[] = [];
  const runtimeEcdsaDiscovery: Record<string, unknown>[] = [];
  const invalidLanes: InvalidAvailableSigningLaneDiagnostic[] = [];
  const recordDurableEcdsaDiscovery = (
    record: SigningSessionSealedStoreRecord,
    result: Record<string, unknown>,
  ): void => {
    durableEcdsaDiscovery.push({
      ...summarizeSealedEcdsaRecordForDiagnostics(record),
      ...result,
    });
  };

  for (const record of ecdsaRecords) {
    if (!record.thresholdSessionIds.ecdsa) {
      recordDurableEcdsaDiscovery(record, {
        result: 'rejected',
        reason: 'missing_ecdsa_threshold_session_id',
      });
      continue;
    }
    const chainTarget = record.ecdsaRestore?.chainTarget;
    if (!chainTarget) {
      recordDurableEcdsaDiscovery(record, {
        result: 'rejected',
        reason: 'missing_ecdsa_restore_chain_target',
      });
      continue;
    }
    const chain = chainTarget.kind;
    if (chain !== 'tempo' && chain !== 'evm') {
      recordDurableEcdsaDiscovery(record, {
        result: 'rejected',
        reason: 'unsupported_ecdsa_chain_target',
        chainTarget,
      });
      continue;
    }
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    const updatedAtMs = Math.floor(Number(record.updatedAtMs) || 0);
    generation = Math.max(generation, updatedAtMs);
    const lane = await recordToEcdsaLane({
      chainTarget,
      record,
    });
    if (!lane) {
      recordDurableEcdsaDiscovery(record, {
        result: 'rejected',
        reason: 'record_to_ecdsa_lane_rejected',
        requestedTargetKeys: [...ecdsaTargetsByKey.keys()],
        recordTargetKey: targetKey,
      });
      continue;
    }
    recordDurableEcdsaDiscovery(record, {
      result: 'accepted',
      targetKey,
      lane: summarizeEcdsaLaneForDiagnostics(lane),
    });
    ecdsaCandidatesByTarget[targetKey] ||= [];
    ecdsaCandidatesByTarget[targetKey].push(lane);
    if (updatedAtMs < (ecdsaLaneUpdatedAtMsByTarget[targetKey] || 0)) continue;
    ecdsaLaneUpdatedAtMsByTarget[targetKey] = updatedAtMs;
    ecdsaLanesByTarget[targetKey] = lane;
  }

  for (const record of ed25519Records) {
    if (!record.thresholdSessionIds.ed25519) continue;
    const updatedAtMs = Math.floor(Number(record.updatedAtMs) || 0);
    generation = Math.max(generation, updatedAtMs);
    const lane = recordToEd25519Lane({ record });
    if (!lane) continue;
    ed25519Candidates.push(lane);
    if (updatedAtMs < ed25519LaneUpdatedAtMs) continue;
    ed25519Lane = lane;
    ed25519LaneUpdatedAtMs = updatedAtMs;
  }

  const rawRuntimeEcdsaRecords = ports.listRuntimeEcdsaLanesForWallet
    ? await ports.listRuntimeEcdsaLanesForWallet({ walletId })
    : [];
  const runtimeEcdsaRecords: AvailableSigningLanesRuntimeEcdsaRecord[] = [];
  for (const record of rawRuntimeEcdsaRecords) {
    const recordAuthMethod = signingLaneAuthMethod(record.auth);
    if (input.authMethod && recordAuthMethod !== input.authMethod) continue;
    const thresholdSessionId = String(record.thresholdSessionId || '').trim();
    if (!record.routerAbEcdsaHssNormalSigning) {
      invalidLanes.push({
        curve: 'ecdsa',
        source: 'runtime_session_record',
        reason: 'missing_router_ab_state',
        authMethod: recordAuthMethod,
        ...(thresholdSessionId ? { thresholdSessionId } : {}),
        ...(record.signingGrantId ? { signingGrantId: String(record.signingGrantId) } : {}),
      });
      continue;
    }
    runtimeEcdsaRecords.push(record);
  }
  const rawRuntimeEd25519Records = ports.listRuntimeEd25519RecordsForWallet
    ? await ports.listRuntimeEd25519RecordsForWallet({ walletId })
    : [];
  const runtimeEd25519Records: AvailableSigningLanesRuntimeEd25519Record[] = [];
  for (const record of rawRuntimeEd25519Records) {
    const recordAuthMethod = signingLaneAuthMethod(record.auth);
    if (input.authMethod && recordAuthMethod !== input.authMethod) continue;
    const thresholdSessionId = String(record.thresholdSessionId || '').trim();
    const signingGrantId = String(record.signingGrantId || '').trim();
    runtimeEd25519Records.push(record);
  }
  const advisoriesByEcdsaRecordKey =
    runtimeEcdsaRecords.length && ports.readEcdsaWarmStatusAdvisoriesForRecords
      ? await ports.readEcdsaWarmStatusAdvisoriesForRecords(runtimeEcdsaRecords)
      : new Map<string, AvailableLaneStateAdvisory | null>();
  const runtimeEd25519SessionIds = runtimeEd25519Records
    .map((record) => String(record.thresholdSessionId || '').trim())
    .filter(Boolean);
  const advisoriesBySessionId =
    runtimeEd25519SessionIds.length && ports.readWarmStatusAdvisoriesForSessions
      ? await ports.readWarmStatusAdvisoriesForSessions(runtimeEd25519SessionIds)
      : new Map<string, AvailableLaneStateAdvisory | null>();

  for (const runtimeRecord of runtimeEcdsaRecords) {
    const runtimeAuthMethod = signingLaneAuthMethod(runtimeRecord.auth);
    const chain = runtimeRecord.chainTarget.kind;
    if (chain !== 'tempo' && chain !== 'evm') {
      invalidLanes.push({
        curve: 'ecdsa',
        source: 'runtime_session_record',
        reason: 'unsupported_ecdsa_chain_target',
        authMethod: runtimeAuthMethod,
        thresholdSessionId: String(runtimeRecord.thresholdSessionId || '').trim(),
        signingGrantId: String(runtimeRecord.signingGrantId || '').trim(),
      });
      runtimeEcdsaDiscovery.push({
        result: 'rejected',
        reason: 'unsupported_ecdsa_chain_target',
        record: runtimeRecord,
      });
      continue;
    }
    const thresholdSessionId = String(runtimeRecord.thresholdSessionId || '').trim();
    if (!thresholdSessionId) {
      invalidLanes.push({
        curve: 'ecdsa',
        source: 'runtime_session_record',
        reason: 'missing_threshold_session_id',
        authMethod: runtimeAuthMethod,
        signingGrantId: String(runtimeRecord.signingGrantId || '').trim(),
      });
      runtimeEcdsaDiscovery.push({
        result: 'rejected',
        reason: 'missing_runtime_threshold_session_id',
        record: runtimeRecord,
      });
      continue;
    }
    let runtimePublicFacts: VerifiedEcdsaPublicFacts;
    try {
      runtimePublicFacts = await publicFactsFromAvailableEcdsaKey({
        key: runtimeRecord.key,
        keyHandle: runtimeRecord.keyHandle,
        verifiedPublicFacts: runtimeRecord.verifiedPublicFacts,
        thresholdEcdsaPublicKeyB64u: runtimeRecord.thresholdEcdsaPublicKeyB64u,
      });
    } catch (error) {
      invalidLanes.push({
        curve: 'ecdsa',
        source: 'runtime_session_record',
        reason: 'invalid_runtime_public_facts',
        authMethod: runtimeAuthMethod,
        thresholdSessionId,
        signingGrantId: String(runtimeRecord.signingGrantId || '').trim(),
        message: error instanceof Error ? error.message : String(error),
      });
      runtimeEcdsaDiscovery.push({
        result: 'rejected',
        reason: 'invalid_runtime_public_facts',
        message: error instanceof Error ? error.message : String(error),
        record: runtimeRecord,
      });
      continue;
    }
    const runtimeLaneKey = ecdsaAvailableLaneIdentityKey(
      buildRuntimeEcdsaAvailableLaneIdentityInput({
        record: runtimeRecord,
        publicFacts: runtimePublicFacts,
      }),
    );
    const targetKey = thresholdEcdsaChainTargetKey(runtimeRecord.chainTarget);
    const targetCandidates = ecdsaCandidatesByTarget[targetKey] || [];
    const targetLane =
      ecdsaLanesByTarget[targetKey] || emptyEcdsaLane({ chainTarget: runtimeRecord.chainTarget });
    const durableLane =
      (runtimeLaneKey
        ? targetCandidates.find((lane) => ecdsaAvailableLaneIdentityKey(lane) === runtimeLaneKey)
        : undefined) || targetLane;
    const advisoryKey = runtimeEcdsaRecordAdvisoryKey(runtimeRecord);
    const runtimeAdvisory = advisoryKey
      ? advisoriesByEcdsaRecordKey.get(advisoryKey) || null
      : null;
    let runtimeLane: ConcreteAvailableEcdsaSigningLane;
    try {
      runtimeLane = await runtimeRecordToEcdsaLane({
        record: runtimeRecord,
        publicFacts: runtimePublicFacts,
        advisory: runtimeAdvisory,
        durableLane,
      });
    } catch (error) {
      invalidLanes.push({
        curve: 'ecdsa',
        source: 'runtime_session_record',
        reason: 'invalid_runtime_public_facts',
        authMethod: runtimeAuthMethod,
        thresholdSessionId,
        signingGrantId: String(runtimeRecord.signingGrantId || '').trim(),
        message: error instanceof Error ? error.message : String(error),
      });
      runtimeEcdsaDiscovery.push({
        result: 'rejected',
        reason: 'invalid_runtime_public_facts',
        message: error instanceof Error ? error.message : String(error),
        record: runtimeRecord,
      });
      continue;
    }
    runtimeEcdsaDiscovery.push({
      result: 'accepted',
      targetKey,
      runtimeLaneKey,
      advisory: runtimeAdvisory,
      lane: summarizeEcdsaLaneForDiagnostics(runtimeLane),
    });
    const candidateIndex = runtimeLaneKey
      ? targetCandidates.findIndex((lane) => ecdsaAvailableLaneIdentityKey(lane) === runtimeLaneKey)
      : -1;
    if (candidateIndex >= 0) {
      targetCandidates[candidateIndex] = runtimeLane;
    } else {
      targetCandidates.push(runtimeLane);
    }
    ecdsaCandidatesByTarget[targetKey] = targetCandidates;
    const runtimeUpdatedAtMs = availableLaneUpdatedAtMs(runtimeLane);
    if (runtimeUpdatedAtMs >= (ecdsaLaneUpdatedAtMsByTarget[targetKey] || 0)) {
      ecdsaLaneUpdatedAtMsByTarget[targetKey] = runtimeUpdatedAtMs;
      ecdsaLanesByTarget[targetKey] = runtimeLane;
    }
  }

  for (const runtimeRecord of runtimeEd25519Records) {
    const runtimeAuthMethod = signingLaneAuthMethod(runtimeRecord.auth);
    const thresholdSessionId = String(runtimeRecord.thresholdSessionId || '').trim();
    if (!thresholdSessionId) {
      invalidLanes.push({
        curve: 'ed25519',
        source: 'runtime_session_record',
        reason: 'missing_threshold_session_id',
        authMethod: runtimeAuthMethod,
        signingGrantId: String(runtimeRecord.signingGrantId || '').trim(),
      });
      continue;
    }
    const signingGrantId = String(runtimeRecord.signingGrantId || '').trim();
    if (!signingGrantId) {
      invalidLanes.push({
        curve: 'ed25519',
        source: 'runtime_session_record',
        reason: 'missing_signing_grant_id',
        authMethod: runtimeAuthMethod,
        thresholdSessionId,
      });
      continue;
    }
    const runtimeLaneKey = ed25519AvailableLaneIdentityKey(runtimeRecord);
    const durableLane =
      (runtimeLaneKey
        ? ed25519Candidates.find((lane) => ed25519AvailableLaneIdentityKey(lane) === runtimeLaneKey)
        : undefined) || ed25519Lane;
    const runtimeLane = runtimeRecordToEd25519Lane({
      record: runtimeRecord,
      advisory: advisoriesBySessionId.get(thresholdSessionId) || null,
      durableLane,
    });
    if (!runtimeLane) continue;
    const candidateIndex = runtimeLaneKey
      ? ed25519Candidates.findIndex(
          (lane) => ed25519AvailableLaneIdentityKey(lane) === runtimeLaneKey,
        )
      : -1;
    if (candidateIndex >= 0) {
      ed25519Candidates[candidateIndex] = runtimeLane;
    } else {
      ed25519Candidates.push(runtimeLane);
    }
    const runtimeUpdatedAtMs = availableLaneUpdatedAtMs(runtimeLane);
    if (runtimeUpdatedAtMs >= ed25519LaneUpdatedAtMs) {
      ed25519LaneUpdatedAtMs = runtimeUpdatedAtMs;
      ed25519Lane = runtimeLane;
    }
  }

  completeMissingEvmFamilyTargetsFromSharedKey({
    targets: ecdsaTargets,
    lanesByTarget: ecdsaLanesByTarget,
    candidatesByTarget: ecdsaCandidatesByTarget,
    laneUpdatedAtMsByTarget: ecdsaLaneUpdatedAtMsByTarget,
  });

  const normalizedEd25519Candidates = collapseExactDuplicateAvailableLanes(
    ed25519Candidates,
    ed25519AvailableLaneIdentityKey,
    compareEd25519AvailableLanePriority,
  ).sort(compareEd25519AvailableLanePriorityDescending);
  const activeEd25519Candidates = canonicalizeEd25519AvailableLanes(
    normalizedEd25519Candidates,
    invalidLanes,
  );
  const primaryEd25519Lane = activeEd25519Candidates.length
    ? primaryEd25519LaneFromNormalizedCandidates({
        primaryLane: ed25519Lane,
        candidates: activeEd25519Candidates,
      })
    : emptyEd25519Lane();
  const preferredEd25519Lane = emailOtpPreferredEd25519PrimaryLane({
    primaryLane: primaryEd25519Lane,
    candidates: activeEd25519Candidates,
  });
  const canonicalEcdsaAvailableLanes = canonicalizeEcdsaAvailableLanes({
    targets: ecdsaTargets,
    candidatesByTarget: ecdsaCandidatesByTarget,
    invalidLanes,
  });

  const availableLanes: AvailableSigningLanes = {
    walletId,
    generation,
    ecdsa: {
      targets: ecdsaTargets,
      lanesByTarget: canonicalEcdsaAvailableLanes.lanesByTarget,
      candidatesByTarget: canonicalEcdsaAvailableLanes.candidatesByTarget,
    },
    lanes: {
      ed25519: {
        near: preferredEd25519Lane,
      },
    },
    candidates: {
      ed25519: {
        near: activeEd25519Candidates,
      },
    },
    diagnostics: {
      invalidLanes,
    },
  };
  const missingEcdsaTargets = ecdsaTargets
    .map((target) => {
      const targetKey = thresholdEcdsaChainTargetKey(target);
      const candidates = availableLanes.ecdsa.candidatesByTarget[targetKey] || [];
      const selectedLane = availableLanes.ecdsa.lanesByTarget[targetKey];
      const selectedLaneState = selectedLane?.state || 'missing';
      if (candidates.length > 0 && selectedLaneState !== 'missing') return null;
      return {
        chainTarget: target,
        targetKey,
        candidateCount: candidates.length,
        selectedLane: summarizeEcdsaLaneForDiagnostics(selectedLane),
      };
    })
    .filter((entry): entry is NonNullable<typeof entry> => Boolean(entry));
  const laneDiagnosticPayload = {
    walletId,
    authMethod: input.authMethod || 'any',
    requestedTargets: ecdsaTargets.map((target) => ({
      chainTarget: target,
      targetKey: thresholdEcdsaChainTargetKey(target),
    })),
    sealedRecordCount: ecdsaRecords.length,
    runtimeRecordCount: runtimeEcdsaRecords.length,
    durableDiscovery: durableEcdsaDiscovery,
    runtimeDiscovery: runtimeEcdsaDiscovery,
    resultSelectedLanesByTarget: Object.fromEntries(
      Object.entries(availableLanes.ecdsa.lanesByTarget).map(([targetKey, lane]) => [
        targetKey,
        summarizeEcdsaLaneForDiagnostics(lane),
      ]),
    ),
    resultCandidatesByTarget: Object.fromEntries(
      Object.entries(availableLanes.ecdsa.candidatesByTarget).map(([targetKey, lanes]) => [
        targetKey,
        lanes.map((lane) => summarizeEcdsaLaneForDiagnostics(lane)),
      ]),
    ),
  };
  if (collectDiagnostics && missingEcdsaTargets.length > 0) {
    try {
      console.warn('[SigningLanes][available][ecdsa][missing-candidates]', {
        ...laneDiagnosticPayload,
        missingEcdsaTargets,
      });
    } catch {}
  }
  if (collectDiagnostics) {
    try {
      console.info('[SigningLanes][available][ecdsa]', laneDiagnosticPayload);
    } catch {}
  }
  return availableLanes;
}
