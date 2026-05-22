import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type {
  EcdsaLaneCandidate,
  ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import {
  buildEcdsaSessionIdentity,
  type EcdsaSessionIdentity,
  type EcdsaSigningKeyContext,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import {
  assertMatchingVerifiedEcdsaPublicFacts,
  buildReadyEcdsaSignerSessionFromReadyMaterial,
  buildVerifiedEcdsaPublicFacts,
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  deriveEvmFamilyKeyFingerprintFromRecordPublicFacts,
  resolveReadyEvmFamilyEcdsaMaterial,
  toEvmFamilyEcdsaKeyHandle,
  type ReadyEcdsaSignerSession,
  type ReadyEvmFamilyEcdsaMaterial,
  type VerifiedEcdsaPublicFacts,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  thresholdEcdsaRecordRpId,
  type ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  type EvmFamilyEcdsaAuthMethod,
  type ResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaKeyRef,
  summarizeEvmFamilyEcdsaSessionRecord,
} from './ecdsaLanes';

type EcdsaMaterialBase = {
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  chainTarget: ThresholdEcdsaChainTarget;
  identity: EcdsaSessionIdentity;
};

export type MissingEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'public_identity_unavailable';
  hasRecord: boolean;
  hasKeyRef: boolean;
  record?: never;
  keyRef?: never;
  publicFacts?: never;
  signerSession?: never;
};

export type PublicIdentityAvailableEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'public_identity_available';
  publicFacts: VerifiedEcdsaPublicFacts;
  record: ThresholdEcdsaSessionRecord;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  signerSession?: never;
};

export type ReauthRequiredEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'reauth_required';
  publicFacts: VerifiedEcdsaPublicFacts;
  record: ThresholdEcdsaSessionRecord;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  reason: 'missing_worker_share' | 'missing_inline_share' | 'expired' | 'exhausted';
  signerSession?: never;
};

export type ReadyEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'ready_to_sign';
  publicFacts: VerifiedEcdsaPublicFacts;
  signingKeyContext: EcdsaSigningKeyContext;
  readyMaterial: ReadyEvmFamilyEcdsaMaterial;
  signerSession: ReadyEcdsaSignerSession;
  record: ThresholdEcdsaSessionRecord;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
};

export type EcdsaMaterialState =
  | MissingEcdsaMaterial
  | PublicIdentityAvailableEcdsaMaterial
  | ReauthRequiredEcdsaMaterial
  | ReadyEcdsaMaterial;

export type EcdsaMaterialSummary = {
  present: boolean;
  kind: EcdsaMaterialState['kind'];
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  walletSigningSessionId: string;
  evmFamilyKeyFingerprint?: string;
  hasRecord: boolean;
  hasKeyRef: boolean;
  publicIdentityPresent: boolean;
  signerMaterialPresent: boolean;
};

export type BuildEcdsaMaterialStateForCandidateArgs = {
  candidate: EcdsaLaneCandidate;
  record: ThresholdEcdsaSessionRecord | undefined;
  keyRef: ThresholdEcdsaSecp256k1KeyRef | undefined;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  chainTarget: ThresholdEcdsaChainTarget;
  materialChainTarget: ThresholdEcdsaChainTarget;
};

export type ResolvedEcdsaMaterialInput =
  | {
      kind: 'resolved_ecdsa_material_pair';
      record: ThresholdEcdsaSessionRecord;
      keyRef: ThresholdEcdsaSecp256k1KeyRef;
    }
  | {
      kind: 'resolved_ecdsa_material_missing';
      record?: never;
      keyRef?: never;
    };

export function buildEcdsaMaterialStateForCandidate(
  args: BuildEcdsaMaterialStateForCandidateArgs,
): EcdsaMaterialState {
  if (!thresholdEcdsaChainTargetsEqual(args.chainTarget, args.candidate.chainTarget)) {
    throw new Error(
      '[SigningEngine][ecdsa] material-state builder chain target must match candidate chain target',
    );
  }
  const identity = buildEcdsaSessionIdentity({
    thresholdSessionId: args.candidate.thresholdSessionId,
    walletSigningSessionId: args.candidate.walletSigningSessionId,
  });
  const base = {
    authMethod: args.authMethod,
    source: args.source,
    chainTarget: args.chainTarget,
    identity,
  } as const;
  const publicFacts =
    args.record && args.keyRef
      ? tryBuildVerifiedPublicFactsForPair({
          record: args.record,
          keyRef: args.keyRef,
        })
      : null;

  const readyResolution = resolveReadyEvmFamilyEcdsaMaterial({
    record: args.record || null,
    keyRef: args.keyRef || null,
    rpId: args.candidate.key.rpId,
    expected: {
      walletId: args.candidate.walletId,
      chainTarget: args.materialChainTarget,
      authMethod: args.authMethod,
      source: args.source,
      thresholdSessionId: identity.thresholdSessionId,
      walletSigningSessionId: identity.walletSigningSessionId,
    },
  });
  if (readyResolution.kind === 'ready') {
    if (!publicFacts) {
      return {
        ...base,
        kind: 'public_identity_unavailable',
        hasRecord: Boolean(args.record),
        hasKeyRef: Boolean(args.keyRef),
      };
    }
    const signerSession = buildReadyEcdsaSignerSessionFromReadyMaterial({
      material: readyResolution.material,
      publicFacts,
    });
    return {
      ...base,
      kind: 'ready_to_sign',
      publicFacts,
      signingKeyContext: readyResolution.material.signingKeyContext,
      readyMaterial: readyResolution.material,
      signerSession,
      record: readyResolution.material.record,
      keyRef: readyResolution.material.keyRef,
    };
  }
  if (args.record && args.keyRef && publicFacts) {
    const reauthReason = reauthReasonFromMaterialResolution({
      reason: readyResolution.reason,
      record: args.record,
      keyRef: args.keyRef,
    });
    if (reauthReason) {
      return {
        ...base,
        kind: 'reauth_required',
        publicFacts,
        record: args.record,
        keyRef: args.keyRef,
        reason: reauthReason,
      };
    }
    return {
      ...base,
      kind: 'public_identity_available',
      publicFacts,
      record: args.record,
      keyRef: args.keyRef,
    };
  }
  return {
    ...base,
    kind: 'public_identity_unavailable',
    hasRecord: Boolean(args.record),
    hasKeyRef: Boolean(args.keyRef),
  };
}

export function buildEcdsaMaterialStateForResolvedLane(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  material: ResolvedEcdsaMaterialInput;
}): EcdsaMaterialState {
  const record = args.material.kind === 'resolved_ecdsa_material_pair' ? args.material.record : undefined;
  const keyRef = args.material.kind === 'resolved_ecdsa_material_pair' ? args.material.keyRef : undefined;
  return buildEcdsaMaterialStateForCandidate({
    candidate: {
      kind: 'lane_candidate',
      walletId: args.lane.walletId,
      key: args.lane.key,
      keyHandle: args.lane.keyHandle,
      authMethod: args.authMethod,
      curve: 'ecdsa',
      chain: args.lane.chainFamily,
      walletSigningSessionId: String(args.lane.walletSigningSessionId),
      thresholdSessionId: String(args.lane.thresholdSessionId),
      state: 'ready',
      remainingUses: null,
      expiresAtMs: null,
      updatedAtMs: null,
      source: 'runtime_session_record',
      chainTarget: args.lane.chainTarget,
    },
    record,
    keyRef,
    authMethod: args.authMethod,
    source: args.source,
    chainTarget: args.lane.chainTarget,
    materialChainTarget: args.lane.chainTarget,
  });
}

export function resolvedEcdsaMaterialInputFromOptionalPair(args: {
  record: ThresholdEcdsaSessionRecord | undefined;
  keyRef: ThresholdEcdsaSecp256k1KeyRef | undefined;
  context: string;
}): ResolvedEcdsaMaterialInput {
  if (args.record && args.keyRef) {
    return {
      kind: 'resolved_ecdsa_material_pair',
      record: args.record,
      keyRef: args.keyRef,
    };
  }
  if (!args.record && !args.keyRef) {
    return { kind: 'resolved_ecdsa_material_missing' };
  }
  throw new Error(
    `[SigningEngine][ecdsa] ${args.context} resolved material requires paired record and keyRef`,
  );
}

export function requireReadyEcdsaMaterial(
  state: EcdsaMaterialState,
  context: string,
): ReadyEcdsaMaterial {
  if (state.kind === 'ready_to_sign') return state;
  throw new Error(
    `[SigningEngine][ecdsa] ${context} requires ready ECDSA material, got ${state.kind}`,
  );
}

export function requireReadyEcdsaMaterialForResolvedLane(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  record: ThresholdEcdsaSessionRecord;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  context: string;
}): ReadyEcdsaMaterial {
  return requireReadyEcdsaMaterial(
    buildEcdsaMaterialStateForResolvedLane({
      lane: args.lane,
      authMethod: args.authMethod,
      source: args.source,
      material: {
        kind: 'resolved_ecdsa_material_pair',
        record: args.record,
        keyRef: args.keyRef,
      },
    }),
    args.context,
  );
}

export function summarizeEcdsaMaterialState(state: EcdsaMaterialState): EcdsaMaterialSummary {
  const evmFamilyKeyFingerprint =
    state.kind === 'ready_to_sign'
      ? safeDeriveRecordPublicFactsFingerprint({
          walletId: state.readyMaterial.key.walletId,
          record: state.readyMaterial.record,
        })
      : state.kind === 'public_identity_available' || state.kind === 'reauth_required'
        ? safeDeriveRecordPublicFactsFingerprint({
            walletId: state.record.walletId,
            record: state.record,
          })
      : undefined;
  const publicIdentityPresent = state.kind !== 'public_identity_unavailable';
  const signerMaterialPresent = state.kind === 'ready_to_sign';
  return {
    present: publicIdentityPresent,
    kind: state.kind,
    authMethod: state.authMethod,
    source: state.source,
    chainTarget: state.chainTarget,
    thresholdSessionId: state.identity.thresholdSessionId,
    walletSigningSessionId: state.identity.walletSigningSessionId,
    ...(evmFamilyKeyFingerprint ? { evmFamilyKeyFingerprint } : {}),
    hasRecord: state.kind === 'public_identity_unavailable' ? state.hasRecord : true,
    hasKeyRef: state.kind === 'public_identity_unavailable' ? state.hasKeyRef : true,
    publicIdentityPresent,
    signerMaterialPresent,
  };
}

export function summarizeVisibleEcdsaMaterial(args: {
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  chainTarget: ThresholdEcdsaChainTarget;
  materialChainTarget: ThresholdEcdsaChainTarget;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): EcdsaMaterialSummary | { present: false } {
  const record = args.record;
  const keyRef = args.keyRef;
  if (!record || !keyRef) return { present: false };
  const identity = buildEcdsaSessionIdentity({
    thresholdSessionId: record.thresholdSessionId,
    walletSigningSessionId: record.walletSigningSessionId,
  });
  const readyResolution = resolveReadyEvmFamilyEcdsaMaterial({
    record,
    keyRef,
    rpId: thresholdEcdsaRecordRpId(record),
    expected: {
      walletId: record.walletId,
      chainTarget: args.materialChainTarget,
      authMethod: args.authMethod,
      source: args.source,
      thresholdSessionId: identity.thresholdSessionId,
      walletSigningSessionId: identity.walletSigningSessionId,
    },
  });
  return summarizeEcdsaMaterialState(
    buildEcdsaMaterialStateForCandidate({
      candidate: {
        kind: 'lane_candidate',
        walletId: record.walletId,
        key:
          readyResolution.kind === 'ready'
            ? readyResolution.material.key
            : buildEvmFamilyEcdsaKeyIdentityFromRecord({
                record,
                rpId: thresholdEcdsaRecordRpId(record),
              }),
        keyHandle: record.keyHandle,
        authMethod: args.authMethod,
        curve: 'ecdsa',
        chain: args.chainTarget.kind,
        walletSigningSessionId: record.walletSigningSessionId,
        thresholdSessionId: record.thresholdSessionId,
        state: 'ready',
        remainingUses: record.remainingUses,
        expiresAtMs: record.expiresAtMs,
        updatedAtMs: record.updatedAtMs,
        source: 'runtime_session_record',
        chainTarget: args.chainTarget,
      },
      record,
      keyRef,
      authMethod: args.authMethod,
      source: args.source,
      chainTarget: args.chainTarget,
      materialChainTarget: args.materialChainTarget,
    }),
  );
}

function tryBuildVerifiedPublicFactsForPair(args: {
  record: ThresholdEcdsaSessionRecord;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
}): VerifiedEcdsaPublicFacts | null {
  try {
    if (!args.keyRef.keyHandle) return null;
    const recordFacts = buildVerifiedEcdsaPublicFacts({
      keyHandle: args.record.keyHandle,
      publicKeyB64u: args.record.thresholdEcdsaPublicKeyB64u,
      participantIds: args.record.participantIds,
      thresholdOwnerAddress: args.record.ethereumAddress,
    });
    const keyRefFacts = buildVerifiedEcdsaPublicFacts({
      keyHandle: toEvmFamilyEcdsaKeyHandle(args.keyRef.keyHandle),
      publicKeyB64u: args.keyRef.thresholdEcdsaPublicKeyB64u,
      participantIds: args.keyRef.participantIds,
      thresholdOwnerAddress: args.keyRef.ethereumAddress,
    });
    assertMatchingVerifiedEcdsaPublicFacts({
      expected: recordFacts,
      actual: keyRefFacts,
      context: 'ECDSA signing lane material',
    });
    return recordFacts;
  } catch {
    return null;
  }
}

function reauthReasonFromMaterialResolution(args: {
  reason?: { kind: string; reason?: string };
  record: ThresholdEcdsaSessionRecord;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
}): ReauthRequiredEcdsaMaterial['reason'] | null {
  if (args.reason?.kind !== 'stale_or_unrestorable_material') return null;
  switch (args.reason.reason) {
    case 'expired':
      return 'expired';
    case 'exhausted':
      return 'exhausted';
    case 'auth_missing':
      return missingShareReasonForKeyRef(args.keyRef, args.record);
    case 'invalid_identity':
    default:
      return null;
  }
}

function missingShareReasonForKeyRef(
  keyRef: ThresholdEcdsaSecp256k1KeyRef,
  record: ThresholdEcdsaSessionRecord,
): Extract<ReauthRequiredEcdsaMaterial['reason'], 'missing_worker_share' | 'missing_inline_share'> {
  const handle = keyRef.backendBinding?.clientAdditiveShareHandle;
  if (record.source === 'email_otp' || handle?.kind === 'email_otp_worker_session') {
    return 'missing_worker_share';
  }
  return 'missing_inline_share';
}

function safeDeriveRecordPublicFactsFingerprint(args: {
  walletId: string;
  record: ThresholdEcdsaSessionRecord;
}): string | undefined {
  try {
    return deriveEvmFamilyKeyFingerprintFromRecordPublicFacts({
      walletId: args.walletId,
      record: args.record,
    });
  } catch {
    return undefined;
  }
}

export function getEcdsaMaterialRecord(
  state: EcdsaMaterialState,
): ThresholdEcdsaSessionRecord | undefined {
  switch (state.kind) {
    case 'public_identity_unavailable':
      return undefined;
    case 'public_identity_available':
    case 'reauth_required':
    case 'ready_to_sign':
      return state.record;
  }
}

export function getEcdsaMaterialKeyRef(
  state: EcdsaMaterialState,
): ThresholdEcdsaSecp256k1KeyRef | undefined {
  switch (state.kind) {
    case 'public_identity_unavailable':
      return undefined;
    case 'public_identity_available':
    case 'reauth_required':
    case 'ready_to_sign':
      return state.keyRef;
  }
}

export function summarizeReadyEcdsaMaterialForDiagnostics(
  state: ReadyEcdsaMaterial | undefined,
): Record<string, unknown> {
  if (!state) return { present: false };
  return {
    material: summarizeEcdsaMaterialState(state),
    record: summarizeEvmFamilyEcdsaSessionRecord(state.record),
    keyRef: summarizeEvmFamilyEcdsaKeyRef(state.keyRef),
  };
}

export function materialIdentityMatchesResolvedLane(args: {
  state: ReadyEcdsaMaterial;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
}): boolean {
  const materialKeyHandle =
    String(args.state.record.keyHandle || '').trim() ||
    String(args.state.keyRef.keyHandle || '').trim();
  const laneKeyHandle = String(args.lane.keyHandle || '').trim();
  return (
    String(args.lane.thresholdSessionId) === args.state.identity.thresholdSessionId &&
    String(args.lane.walletSigningSessionId) === args.state.identity.walletSigningSessionId &&
    materialKeyHandle === laneKeyHandle &&
    String(args.state.record.keyHandle || '').trim() === laneKeyHandle &&
    thresholdEcdsaChainTargetsEqual(args.lane.chainTarget, args.state.chainTarget)
  );
}
