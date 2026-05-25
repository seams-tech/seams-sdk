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
  buildReadyEcdsaSignerSessionFromReadyMaterial,
  buildVerifiedEcdsaPublicFacts,
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  deriveEvmFamilyKeyFingerprintFromRecordPublicFacts,
  resolveReadyEvmFamilyEcdsaMaterial,
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
  record?: never;
  keyRef?: never;
  publicFacts?: never;
  signerSession?: never;
};

export type PublicIdentityAvailableEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'public_identity_available';
  publicFacts: VerifiedEcdsaPublicFacts;
  record: ThresholdEcdsaSessionRecord;
  keyRef?: never;
  signerSession?: never;
};

export type ReauthRequiredEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'reauth_required';
  publicFacts: VerifiedEcdsaPublicFacts;
  record: ThresholdEcdsaSessionRecord;
  keyRef?: never;
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
  keyRef?: never;
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
  publicIdentityPresent: boolean;
  signerMaterialPresent: boolean;
};

export type BuildEcdsaMaterialStateForCandidateArgs = {
  candidate: EcdsaLaneCandidate;
  record: ThresholdEcdsaSessionRecord | undefined;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  chainTarget: ThresholdEcdsaChainTarget;
  materialChainTarget: ThresholdEcdsaChainTarget;
};

export type ResolvedEcdsaMaterialInput =
  | {
      kind: 'resolved_ecdsa_session_record';
      record: ThresholdEcdsaSessionRecord;
    }
  | {
      kind: 'resolved_ecdsa_material_missing';
      record?: never;
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
  const publicFacts = args.record
    ? tryBuildVerifiedPublicFactsFromRecord({
        record: args.record,
      })
    : null;

  const readyResolution = resolveReadyEvmFamilyEcdsaMaterial({
    record: args.record || null,
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
    };
  }
  if (args.record && publicFacts) {
    const reauthReason = reauthReasonFromMaterialResolution({
      reason: readyResolution.reason,
      record: args.record,
    });
    if (reauthReason) {
      return {
        ...base,
        kind: 'reauth_required',
        publicFacts,
        record: args.record,
        reason: reauthReason,
      };
    }
    return {
      ...base,
      kind: 'public_identity_available',
      publicFacts,
      record: args.record,
    };
  }
  return {
    ...base,
    kind: 'public_identity_unavailable',
    hasRecord: Boolean(args.record),
  };
}

export function buildEcdsaMaterialStateForResolvedLane(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  material: ResolvedEcdsaMaterialInput;
}): EcdsaMaterialState {
  const record =
    args.material.kind === 'resolved_ecdsa_session_record' ? args.material.record : undefined;
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
    authMethod: args.authMethod,
    source: args.source,
    chainTarget: args.lane.chainTarget,
    materialChainTarget: args.lane.chainTarget,
  });
}

export function resolvedEcdsaMaterialInputFromOptionalRecord(args: {
  record: ThresholdEcdsaSessionRecord | undefined;
  context: string;
}): ResolvedEcdsaMaterialInput {
  if (args.record) {
    return {
      kind: 'resolved_ecdsa_session_record',
      record: args.record,
    };
  }
  return { kind: 'resolved_ecdsa_material_missing' };
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
  context: string;
}): ReadyEcdsaMaterial {
  return requireReadyEcdsaMaterial(
    buildEcdsaMaterialStateForResolvedLane({
      lane: args.lane,
      authMethod: args.authMethod,
      source: args.source,
      material: {
        kind: 'resolved_ecdsa_session_record',
        record: args.record,
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
}): EcdsaMaterialSummary | { present: false } {
  const record = args.record;
  if (!record) return { present: false };
  const identity = buildEcdsaSessionIdentity({
    thresholdSessionId: record.thresholdSessionId,
    walletSigningSessionId: record.walletSigningSessionId,
  });
  const readyResolution = resolveReadyEvmFamilyEcdsaMaterial({
    record,
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
      authMethod: args.authMethod,
      source: args.source,
      chainTarget: args.chainTarget,
      materialChainTarget: args.materialChainTarget,
    }),
  );
}

function tryBuildVerifiedPublicFactsFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
}): VerifiedEcdsaPublicFacts | null {
  try {
    return buildVerifiedEcdsaPublicFacts({
      keyHandle: args.record.keyHandle,
      publicKeyB64u: args.record.thresholdEcdsaPublicKeyB64u,
      participantIds: args.record.participantIds,
      thresholdOwnerAddress: args.record.ethereumAddress,
    });
  } catch {
    return null;
  }
}

function reauthReasonFromMaterialResolution(args: {
  reason?: { kind: string; reason?: string };
  record: ThresholdEcdsaSessionRecord;
}): ReauthRequiredEcdsaMaterial['reason'] | null {
  if (args.reason?.kind !== 'stale_or_unrestorable_material') return null;
  switch (args.reason.reason) {
    case 'expired':
      return 'expired';
    case 'exhausted':
      return 'exhausted';
    case 'auth_missing':
      return missingShareReasonForRecord(args.record);
    case 'invalid_identity':
    default:
      return null;
  }
}

function missingShareReasonForRecord(
  record: ThresholdEcdsaSessionRecord,
): Extract<ReauthRequiredEcdsaMaterial['reason'], 'missing_worker_share' | 'missing_inline_share'> {
  const handle = record.clientAdditiveShareHandle;
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

export function summarizeReadyEcdsaMaterialForDiagnostics(
  state: ReadyEcdsaMaterial | undefined,
): Record<string, unknown> {
  if (!state) return { present: false };
  return {
    material: summarizeEcdsaMaterialState(state),
    record: summarizeEvmFamilyEcdsaSessionRecord(state.record),
  };
}

export function materialIdentityMatchesResolvedLane(args: {
  state: ReadyEcdsaMaterial;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
}): boolean {
  const materialKeyHandle = String(args.state.record.keyHandle || '').trim();
  const laneKeyHandle = String(args.lane.keyHandle || '').trim();
  return (
    String(args.lane.thresholdSessionId) === args.state.identity.thresholdSessionId &&
    String(args.lane.walletSigningSessionId) === args.state.identity.walletSigningSessionId &&
    materialKeyHandle === laneKeyHandle &&
    String(args.state.record.keyHandle || '').trim() === laneKeyHandle &&
    thresholdEcdsaChainTargetsEqual(args.lane.chainTarget, args.state.chainTarget)
  );
}
