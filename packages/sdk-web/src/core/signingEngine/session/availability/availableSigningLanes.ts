import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import {
  nearEd25519SigningKeyIdFromString,
  type NearEd25519SigningKeyId,
} from '@shared/utils/registrationIntent';
import { parseSignerSlot } from '@shared/utils/signerSlot';
import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type { SigningSessionSealedStoreRecord } from '../persistence/sealedSessionStore';
import type {
  EcdsaLaneCandidate,
  Ed25519LaneCandidate,
  LaneCandidateSource,
  LaneCandidateState,
} from '../identity/laneIdentity';
import {
  deriveEvmFamilyKeyFingerprintFromPublicFacts,
  toRpId,
  type EvmFamilyKeyFingerprint,
  type EvmFamilyEcdsaKeyIdentity,
  type PasskeyEcdsaAuthBinding,
  type ResolvedEvmFamilyEcdsaKey,
  type VerifiedEcdsaPublicFacts,
} from '../identity/evmFamilyEcdsaIdentity';
import type { WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  signingLaneAuthBindingKey,
  signingLaneAuthMethod,
  type SigningLaneAuthBinding,
} from '../identity/signingLaneAuthBinding';
import { type FreshStepUpRequired, type StepUpExpiryState } from '../operationState/stepUpFreshness';
import {
  canonicalizeLaneFacts,
  serverIssuedGenerationFromNumber,
  type CanonicalFactSupersession,
  type CanonicalLaneInventoryAdapter,
  type CanonicalTieBreakOrder,
  type ServerIssuedGeneration,
} from './canonicalLaneInventory';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../material/ecdsaSigningCapability';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { SigningSessionIds } from '../operationState/types';

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
  publicReauthAuthority?: never;
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

type ConcreteAvailableEcdsaSigningLaneBase = {
  key: EvmFamilyEcdsaKeyIdentity;
  materialActivation: MpcMaterialActivationRef;
  publicFacts: VerifiedEcdsaPublicFacts;
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  state: Exclude<AvailableSigningLaneState, 'restorable'>;
  policyHint?: AvailableSigningLanePolicyHint;
  updatedAtMs?: number;
} & ConcreteAvailableEcdsaSigningLaneAuth;

export type ConcreteAvailableEcdsaSigningLane = ConcreteAvailableEcdsaSigningLaneBase & {
  source: 'canonical_capability';
  sourceChainTarget?: never;
  publicReauthAuthority?: never;
  signingGrantId?: never;
  thresholdSessionId?: never;
} & (
    | {
        authorization: ActiveEvmFamilyWalletSessionAuthorization;
        remainingUses: number;
        expiresAtMs: number;
      }
    | {
        authorization?: never;
        state: 'deferred';
        remainingUses?: never;
        expiresAtMs?: never;
      }
  );

export type AvailableEcdsaSigningLane =
  | MissingAvailableEcdsaSigningLane
  | ConcreteAvailableEcdsaSigningLane;

function materialActivationKey(activation: MpcMaterialActivationRef): string {
  return [
    activation.activationId,
    activation.capability,
    activation.materialOwner,
    activation.keyBinding,
    activation.lifecycleBinding,
    activation.signingWorker,
  ]
    .map((part) => encodeURIComponent(String(part)))
    .join(':');
}

export type EcdsaLaneRecordFactSource = 'canonical_capability';

export type EcdsaLaneGroupKey = {
  walletId: string;
  authKey: string;
  materialActivationKey: string;
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
): WalletAuthAuthority['factor']['kind'] {
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
};

type ConcreteAvailableEd25519SigningLaneBase = {
  auth: SigningLaneAuthBinding;
  curve: 'ed25519';
  chain: 'near';
  materialActivation: MpcMaterialActivationRef;
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
  thresholdSessionId: string;
  remainingUses?: number;
  expiresAtMs?: number;
  policyHint?: AvailableSigningLanePolicyHint;
  updatedAtMs?: number;
  source?: 'durable_sealed_record' | 'runtime_session_record';
};

export type ConcreteAvailableEd25519SigningLane =
  ConcreteAvailableEd25519SigningLaneBase &
    (
      | {
          authorizationState: 'authorized';
          authorization: ActiveWalletSessionAuthorizationProjection;
          signingGrantId: string;
          state: Exclude<AvailableSigningLaneState, 'deferred'>;
        }
      | {
          authorizationState: 'authorization_required';
          authorization?: never;
          signingGrantId?: never;
          state: 'deferred';
        }
    );

export type AvailableEd25519SigningLane =
  | MissingAvailableEd25519SigningLane
  | ConcreteAvailableEd25519SigningLane;

export function availableEd25519SigningLaneAuthMethod(
  lane: Pick<ConcreteAvailableEd25519SigningLane, 'auth'>,
): 'email_otp' | 'passkey' {
  return signingLaneAuthMethod(lane.auth);
}

export type AvailableLaneStateAdvisory =
  | {
      kind: 'runtime_material';
      remainingUses: number;
      expiresAtMs: number;
      code?: never;
    }
  | {
      kind: 'warm_status';
      status: 'active';
      remainingUses: number;
      expiresAtMs: number;
      code?: never;
    }
  | {
      kind: 'durable_policy';
      remainingUses: number;
      expiresAtMs: number;
      state: AvailableSigningLaneState;
      code?: never;
    }
  | {
      kind: 'warm_status';
      status: 'exhausted';
      remainingUses: 0;
      expiresAtMs?: never;
      code?: never;
    }
  | {
      kind: 'warm_status';
      status: 'expired';
      remainingUses?: never;
      expiresAtMs?: never;
      code?: never;
    }
  | {
      kind: 'warm_status';
      status: 'cache_miss';
      remainingUses?: never;
      expiresAtMs?: never;
      code?: string;
    }
  | {
      kind: 'warm_status';
      status: 'unavailable';
      remainingUses?: never;
      expiresAtMs?: never;
      code: string;
    };

export function durableRecordPolicyAdvisory(args: {
  remainingUses: unknown;
  expiresAtMs: unknown;
  state: 'ready' | 'restorable' | 'deferred';
}): AvailableLaneStateAdvisory | null {
  const remainingUses = Math.floor(Number(args.remainingUses));
  const expiresAtMs = Math.floor(Number(args.expiresAtMs));
  if (!Number.isFinite(remainingUses) || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    return null;
  }
  if (expiresAtMs <= Date.now()) {
    return {
      kind: 'durable_policy',
      remainingUses,
      expiresAtMs,
      state: 'expired',
    };
  }
  if (remainingUses <= 0) {
    return {
      kind: 'durable_policy',
      remainingUses: 0,
      expiresAtMs,
      state: 'exhausted',
    };
  }
  return {
    kind: 'durable_policy',
    remainingUses,
    expiresAtMs,
    state: args.state,
  };
}

type AvailableSigningLanesRuntimeEd25519RecordBase = {
  auth: SigningLaneAuthBinding;
  curve: 'ed25519';
  chain: 'near';
  materialActivation: MpcMaterialActivationRef;
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  thresholdSessionId: string;
  source: 'durable_sealed_record' | 'runtime_session_record';
  remainingUses?: number;
  expiresAtMs?: number;
  updatedAtMs?: number;
};

export type AvailableSigningLanesRuntimeEd25519Record =
  AvailableSigningLanesRuntimeEd25519RecordBase &
    (
      | {
          authorizationState: 'authorized';
          authorization: ActiveWalletSessionAuthorizationProjection;
          signingGrantId: string;
        }
      | {
          authorizationState: 'authorization_required';
          authorization?: never;
          signingGrantId?: never;
        }
    );

function durableEd25519AuthBinding(
  record: Extract<SigningSessionSealedStoreRecord, { curve: 'ed25519' }>,
): SigningLaneAuthBinding | null {
  const restore = record.ed25519Restore;
  if (record.authMethod === 'passkey') {
    if (!restore.credentialIdB64u) return null;
    try {
      return {
        kind: 'passkey',
        rpId: toRpId(restore.rpId),
        credentialIdB64u: restore.credentialIdB64u,
      };
    } catch {
      return null;
    }
  }
  if (!restore.providerSubjectId) return null;
  return {
    kind: 'email_otp',
    providerSubjectId: restore.providerSubjectId,
  };
}

function recordToEd25519Lane(
  record: SigningSessionSealedStoreRecord,
): ConcreteAvailableEd25519SigningLane | null {
  if (record.curve !== 'ed25519') return null;
  const thresholdSessionId = String(record.thresholdSessionIds.ed25519 || '').trim();
  const walletId = String(record.walletId || '').trim();
  const restore = record.ed25519Restore;
  const signerSlot = parseSignerSlot(restore.signerSlot);
  const auth = durableEd25519AuthBinding(record);
  if (!thresholdSessionId || !walletId || signerSlot === null || !auth) {
    return null;
  }
  const expiresAtMs = Math.floor(Number(record.expiresAtMs) || 0);
  const remainingUses = Math.max(0, Math.floor(Number(record.remainingUses) || 0));
  const state: AvailableSigningLaneState =
    expiresAtMs > 0 && expiresAtMs <= Date.now()
      ? 'expired'
      : remainingUses === 0
        ? 'exhausted'
        : 'restorable';
  try {
    return {
      auth,
      curve: 'ed25519',
      chain: 'near',
      materialActivation: restore.materialActivation,
      walletId: toWalletId(walletId),
      nearAccountId: toAccountId(restore.nearAccountId),
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(restore.nearEd25519SigningKeyId),
      signerSlot,
      state: 'deferred',
      source: 'durable_sealed_record',
      authorizationState: 'authorization_required',
      thresholdSessionId,
      remainingUses,
      ...(expiresAtMs > 0 ? { expiresAtMs } : {}),
      updatedAtMs: Math.floor(Number(record.updatedAtMs) || 0),
      ...(durablePolicyHint(record) ? { policyHint: durablePolicyHint(record) } : {}),
    };
  } catch {
    return null;
  }
}

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
    filter: {
      authMethod?: 'email_otp' | 'passkey';
      curve: 'ed25519';
    };
  }) => Promise<SigningSessionSealedStoreRecord[]>;
  listCanonicalEcdsaLanesForWallet?: (args: {
    walletId: string;
  }) => Promise<ConcreteAvailableEcdsaSigningLane[]>;
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
  if (lane.curve !== 'ecdsa') {
    const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
    if (lane.thresholdSessionId !== thresholdSessionId) return false;
    if (!thresholdSessionId) return false;
    if (lane.authorizationState === 'authorization_required') {
      return lane.state === 'deferred' && lane.signingGrantId === undefined;
    }
    const signingGrantId = String(lane.signingGrantId || '').trim();
    if (lane.signingGrantId !== signingGrantId || !signingGrantId) return false;
    return lane.auth.kind === 'email_otp' || lane.auth.kind === 'passkey';
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

function nullablePositiveInteger(value: unknown): number | null {
  const normalized = Math.floor(Number(value));
  return Number.isFinite(normalized) && normalized > 0 ? normalized : null;
}

function nullableNonNegativeInteger(value: unknown): number | null {
  const normalized = Math.max(0, Math.floor(Number(value)));
  return Number.isFinite(normalized) ? normalized : null;
}

export function ed25519LaneCandidateFromAvailableLane(args: {
  lane: AvailableEd25519SigningLane;
}): Ed25519LaneCandidate | null {
  if (!isConcreteAvailableSigningLane(args.lane) || args.lane.curve !== 'ed25519') {
    return null;
  }
  const state = laneCandidateStateFromAvailableLaneState(args.lane.state);
  if (!state) return null;
  const base = {
    kind: 'lane_candidate',
    walletId: args.lane.walletId,
    nearAccountId: args.lane.nearAccountId,
    nearEd25519SigningKeyId: args.lane.nearEd25519SigningKeyId,
    signerSlot: args.lane.signerSlot,
    auth: args.lane.auth,
    curve: 'ed25519',
    chain: 'near',
    thresholdSessionId: args.lane.thresholdSessionId,
    state,
    remainingUses: nullableNonNegativeInteger(args.lane.remainingUses),
    expiresAtMs: nullablePositiveInteger(args.lane.expiresAtMs),
    updatedAtMs: nullablePositiveInteger(args.lane.updatedAtMs),
    source: laneCandidateSourceFromAvailableLaneSource(args.lane.source),
  } as const;
  if (args.lane.authorizationState === 'authorization_required') {
    return {
      ...base,
      authorizationState: 'authorization_required',
      state: 'deferred',
    };
  }
  return {
    ...base,
    authorizationState: 'authorized',
    authorization: args.lane.authorization,
    signingGrantId: SigningSessionIds.signingGrant(args.lane.signingGrantId),
  };
}

export function ecdsaLaneCandidateFromAvailableLane(args: {
  walletId: WalletId | string;
  lane: AvailableEcdsaSigningLane;
}): EcdsaLaneCandidate | null {
  if (!isConcreteAvailableSigningLane(args.lane) || args.lane.curve !== 'ecdsa') {
    return null;
  }
  if (args.lane.source !== 'canonical_capability') return null;
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
    materialActivation: args.lane.materialActivation,
    ...(authMethod === 'passkey' ? { resolvedKey: args.lane.resolvedKey } : {}),
    keyHandle: args.lane.publicFacts.keyHandle,
    chainTarget: args.lane.chainTarget,
  } as const;
  if (!args.lane.authorization) {
    return {
      ...base,
      source: 'canonical_capability',
      authorizationState: 'authorization_required',
      state: 'deferred',
    };
  }
  return {
    ...base,
    source: 'canonical_capability',
    authorizationState: 'authorized',
    authorization: args.lane.authorization,
    state,
  };
}

type EcdsaAvailableLaneIdentityBase = Pick<
  ConcreteAvailableEcdsaSigningLane,
  'curve' | 'chainTarget' | 'key' | 'materialActivation' | 'publicFacts' | 'authorization'
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
  try {
    const authKey = signingLaneAuthBindingKey(lane.auth);
    return [
      authMethod,
      'ecdsa',
      thresholdEcdsaChainTargetKey(lane.chainTarget),
      authKey,
      deriveAvailableEcdsaLaneFingerprint(lane),
      materialActivationKey(lane.materialActivation),
    ].join(':');
  } catch {
    return null;
  }
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
  materialActivation?: MpcMaterialActivationRef;
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
  const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
  const activationKey = lane.materialActivation ? materialActivationKey(lane.materialActivation) : '';
  if (
    !authMethod ||
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !signerSlot ||
    !thresholdSessionId ||
    !activationKey
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
    thresholdSessionId,
    activationKey,
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

function emptyEd25519Lane(): AvailableEd25519SigningLane {
  return {
    curve: 'ed25519',
    chain: 'near',
    state: 'missing',
  };
}

function durablePolicyHint(record: {
  remainingUses: number;
  expiresAtMs: number;
}): AvailableSigningLanePolicyHint | undefined {
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

export function warmStatusToAvailableLaneStateAdvisory(args: {
  status: { ok: true; remainingUses: number; expiresAtMs: number } | { ok: false; code: string };
}): AvailableLaneStateAdvisory {
  if (args.status.ok) {
    return {
      kind: 'warm_status',
      status: 'active',
      remainingUses: args.status.remainingUses,
      expiresAtMs: args.status.expiresAtMs,
    };
  }
  if (args.status.code === 'expired') {
    return { kind: 'warm_status', status: 'expired' };
  }
  if (args.status.code === 'exhausted') {
    return {
      kind: 'warm_status',
      status: 'exhausted',
      remainingUses: 0,
    };
  }
  if (args.status.code === 'not_found') {
    return {
      kind: 'warm_status',
      status: 'cache_miss',
    };
  }
  return {
    kind: 'warm_status',
    status: 'unavailable',
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
    case 'runtime_material':
      return recordPolicyState || 'ready';
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
  if (args.expiresAtMs !== null && args.expiresAtMs <= Date.now()) return 'expired';
  if (args.remainingUses === 0) return 'exhausted';
  return null;
}

function runtimeRecordToEd25519Lane(args: {
  record: AvailableSigningLanesRuntimeEd25519Record;
  advisory: AvailableLaneStateAdvisory | null;
}): ConcreteAvailableEd25519SigningLane | null {
  const thresholdSessionId = String(args.record.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return null;
  const advisory = args.advisory;
  const remainingUses = nullableNonNegativeInteger(
    advisoryRemainingUses(advisory) ?? args.record.remainingUses,
  );
  const expiresAtMs = nullablePositiveInteger(
    advisoryExpiresAtMs(advisory) ?? args.record.expiresAtMs,
  );
  const recordPolicyState = runtimeRecordPolicyState({ remainingUses, expiresAtMs });
  const runtimeUpdatedAtMs = nullablePositiveInteger(args.record.updatedAtMs) || 0;
  const updatedAtMs = runtimeUpdatedAtMs;
  const signerSlot = parseSignerSlot(args.record.signerSlot);
  if (signerSlot == null) return null;

  const base = {
    auth: args.record.auth,
    curve: 'ed25519',
    chain: 'near',
    materialActivation: args.record.materialActivation,
    walletId: args.record.walletId,
    nearAccountId: args.record.nearAccountId,
    nearEd25519SigningKeyId: args.record.nearEd25519SigningKeyId,
    signerSlot,
    source: args.record.source,
    thresholdSessionId,
    ...(remainingUses == null ? {} : { remainingUses }),
    ...(expiresAtMs == null ? {} : { expiresAtMs }),
    ...(updatedAtMs > 0 ? { updatedAtMs } : {}),
  } as const;
  if (args.record.authorizationState === 'authorization_required') {
    return {
      ...base,
      authorizationState: 'authorization_required',
      state: 'deferred',
    };
  }
  const state = advisoryToLaneState(advisory, undefined, recordPolicyState);
  return {
    ...base,
    authorizationState: 'authorized',
    authorization: args.record.authorization,
    signingGrantId: args.record.signingGrantId,
    state: state === 'deferred' ? 'restorable' : state,
  };
}

function availableLaneUpdatedAtMs(
  lane: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
): number {
  return Math.floor(Number('updatedAtMs' in lane ? lane.updatedAtMs : 0) || 0);
}

function laneCandidateUpdatedAtMs(candidate: EcdsaLaneCandidate | Ed25519LaneCandidate): number {
  return candidate.curve === 'ecdsa' ? 0 : Math.floor(Number(candidate.updatedAtMs) || 0);
}

function laneCandidateExpiry(
  candidate: EcdsaLaneCandidate | Ed25519LaneCandidate,
): StepUpExpiryState {
  if (candidate.curve === 'ecdsa' && candidate.authorizationState !== 'authorized') {
    return { kind: 'unavailable', reason: 'restored_record_has_no_expiry' };
  }
  const expiresAtMs =
    candidate.curve === 'ecdsa'
      ? candidate.authorization.status.expiresAtMs
      : nullablePositiveInteger(candidate.expiresAtMs);
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
  if (lane.curve === 'ecdsa') return 0;
  switch (lane.source) {
    case 'runtime_session_record':
      return 4;
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

function compareEd25519AvailableLanePriority(
  left: AvailableEd25519SigningLane,
  right: AvailableEd25519SigningLane,
): number {
  return compareAvailableLanePriority(left, right);
}

type Ed25519LaneGroupKey = {
  walletId: string;
  authKey: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: string;
  materialActivationKey: string;
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
  const materialActivationKeyValue = materialActivationKey(lane.materialActivation);
  if (
    !authKey ||
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !signerSlot ||
    !materialActivationKeyValue
  ) {
    return null;
  }
  return {
    walletId,
    authKey,
    nearAccountId,
    nearEd25519SigningKeyId,
    signerSlot,
    materialActivationKey: materialActivationKeyValue,
  };
}

function ed25519LaneGroupKeyString(key: Ed25519LaneGroupKey): string {
  return [
    key.walletId,
    key.authKey,
    key.nearAccountId,
    key.nearEd25519SigningKeyId,
    key.signerSlot,
    key.materialActivationKey,
  ]
    .map((part) => encodeURIComponent(part))
    .join('|');
}

function ed25519LaneRecordFact(lane: AvailableEd25519SigningLane): Ed25519LaneRecordFact | null {
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
  return fact.lane.state !== 'deferred';
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
  _lane: ConcreteAvailableEcdsaSigningLane,
): EcdsaLaneRecordFactSource {
  return 'canonical_capability';
}

function ecdsaLaneGroupKey(lane: ConcreteAvailableEcdsaSigningLane): EcdsaLaneGroupKey | null {
  const authKey = signingLaneAuthBindingKey(lane.auth);
  return {
    walletId: String(lane.key.walletId),
    authKey,
    materialActivationKey: materialActivationKey(lane.materialActivation),
    ecdsaThresholdKeyId: String(lane.key.ecdsaThresholdKeyId),
    signingRootId: String(lane.key.signingRootId),
    signingRootVersion: String(lane.key.signingRootVersion || 'default'),
  };
}

function ecdsaLaneGroupKeyString(key: EcdsaLaneGroupKey): string {
  return [
    key.walletId,
    key.authKey,
    key.materialActivationKey,
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
  const authKey = signingLaneAuthBindingKey(lane.auth);
  return [
    String(lane.key.walletId),
    authKey,
    materialActivationKey(lane.materialActivation),
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

function ecdsaCanonicalSourcePriority(_lane: ConcreteAvailableEcdsaSigningLane): number {
  return 1;
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
  return (
    fact.lane.state !== 'deferred' ||
    (fact.lane.source === 'canonical_capability' && !fact.lane.authorization)
  );
}

function ecdsaCanonicalFactGeneration(fact: EcdsaLaneRecordFact): ServerIssuedGeneration | null {
  return availableLaneServerIssuedGeneration(fact.lane);
}

function ecdsaCanonicalFactExactness(_fact: EcdsaLaneRecordFact): 'exact_target' {
  return 'exact_target';
}

function ecdsaCanonicalStableTieBreakKey(lane: ConcreteAvailableEcdsaSigningLane): string {
  return [
    materialActivationKey(lane.materialActivation),
    lane.source,
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
  let generation = 0;
  const collectDiagnostics = isAvailableSigningLaneDiagnosticsEnabled();
  const runtimeEcdsaDiscovery: Record<string, unknown>[] = [];
  const invalidLanes: InvalidAvailableSigningLaneDiagnostic[] = [];

  for (const record of ed25519Records) {
    const lane = recordToEd25519Lane(record);
    if (!lane) continue;
    ed25519Candidates.push(lane);
    const updatedAtMs = availableLaneUpdatedAtMs(lane);
    generation = Math.max(generation, updatedAtMs);
  }

  const canonicalEcdsaLanes = ports.listCanonicalEcdsaLanesForWallet
    ? await ports.listCanonicalEcdsaLanesForWallet({ walletId })
    : [];
  const rawRuntimeEd25519Records = ports.listRuntimeEd25519RecordsForWallet
    ? await ports.listRuntimeEd25519RecordsForWallet({ walletId })
    : [];
  const runtimeEd25519Records: AvailableSigningLanesRuntimeEd25519Record[] = [];
  for (const record of rawRuntimeEd25519Records) {
    const recordAuthMethod = signingLaneAuthMethod(record.auth);
    if (input.authMethod && recordAuthMethod !== input.authMethod) continue;
    runtimeEd25519Records.push(record);
  }
  const runtimeEd25519SessionIds = runtimeEd25519Records
    .map((record) => String(record.thresholdSessionId || '').trim())
    .filter(Boolean);
  const advisoriesBySessionId =
    runtimeEd25519SessionIds.length && ports.readWarmStatusAdvisoriesForSessions
      ? await ports.readWarmStatusAdvisoriesForSessions(runtimeEd25519SessionIds)
      : new Map<string, AvailableLaneStateAdvisory | null>();

  for (const lane of canonicalEcdsaLanes) {
    const authMethod = signingLaneAuthMethod(lane.auth);
    if (input.authMethod && authMethod !== input.authMethod) continue;
    if (String(lane.key.walletId) !== String(walletId)) continue;
    const targetKey = thresholdEcdsaChainTargetKey(lane.chainTarget);
    if (!ecdsaTargetsByKey.has(targetKey)) continue;
    ecdsaCandidatesByTarget[targetKey] ||= [];
    ecdsaCandidatesByTarget[targetKey].push(lane);
    const updatedAtMs = availableLaneUpdatedAtMs(lane);
    generation = Math.max(generation, updatedAtMs);
    runtimeEcdsaDiscovery.push({
      result: 'accepted',
      targetKey,
      lane: summarizeEcdsaLaneForDiagnostics(lane),
    });
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
    if (
      runtimeRecord.authorizationState === 'authorized' &&
      !String(runtimeRecord.signingGrantId || '').trim()
    ) {
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
    const runtimeLane = runtimeRecordToEd25519Lane({
      record: runtimeRecord,
      advisory: advisoriesBySessionId.get(thresholdSessionId) || null,
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
  }

  const normalizedEd25519Candidates = collapseExactDuplicateAvailableLanes(
    ed25519Candidates,
    ed25519AvailableLaneIdentityKey,
    compareEd25519AvailableLanePriority,
  ).sort(compareEd25519AvailableLanePriorityDescending);
  const activeEd25519Candidates = canonicalizeEd25519AvailableLanes(
    normalizedEd25519Candidates,
    invalidLanes,
  );
  const primaryEd25519Lane = activeEd25519Candidates[0] || emptyEd25519Lane();
  const preferredEd25519Lane = emailOtpPreferredEd25519PrimaryLane({
    primaryLane: primaryEd25519Lane,
    candidates: activeEd25519Candidates,
  });
  const canonicalEcdsaSources = canonicalizeEcdsaAvailableLanes({
    targets: ecdsaTargets,
    candidatesByTarget: ecdsaCandidatesByTarget,
    invalidLanes,
  });
  const canonicalEcdsaAvailableLanes = canonicalizeEcdsaAvailableLanes({
    targets: ecdsaTargets,
    candidatesByTarget: canonicalEcdsaSources.candidatesByTarget,
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
    sealedRecordCount: 0,
    runtimeRecordCount: canonicalEcdsaLanes.length,
    durableDiscovery: [],
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
      console.warn(
        '[SigningLanes][available][ecdsa][missing-candidates]',
        JSON.stringify({
          ...laneDiagnosticPayload,
          missingEcdsaTargets,
        }),
      );
    } catch {}
  }
  if (collectDiagnostics) {
    try {
      console.info('[SigningLanes][available][ecdsa]', JSON.stringify(laneDiagnosticPayload));
    } catch {}
  }
  return availableLanes;
}
