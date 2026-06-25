import type { NearEd25519SignerBinding } from '@shared/utils/walletCapabilityBindings';
import type { NearAccountId } from '@shared/utils/near';
import {
  availableEd25519SigningLaneAuthMethod,
  availableEcdsaSigningLaneAuthMethod,
  ecdsaAvailableLaneCandidatesForTarget,
  ed25519AvailableLaneIdentityKey,
  type ReadAvailableSigningLanesInput,
  type AvailableSigningLanes,
  type ConcreteAvailableEcdsaSigningLane,
  type AvailableEd25519SigningLane,
} from '../../session/availability/availableSigningLanes';
import { emitSigningSessionFlowFailure, emitSigningSessionFlowTrace } from '../../session/operationState/trace';
import { SigningSessionIds } from '../../session/operationState/types';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { deriveEvmFamilyKeyFingerprintFromPublicFacts } from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
  exactEd25519SigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
  exactSigningLaneIdentityKey,
  type ExactEcdsaSigningLaneIdentity,
  type ExactEd25519SigningLaneIdentity,
} from '../../session/identity/exactSigningLaneIdentity';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/uiConfirm.types';
import type { EvmFamilySigningTarget } from '../signEvmFamily/types';
import {
  isConcreteEcdsaExportLane,
  type ExactEcdsaExportLane,
} from './ecdsaExportMaterial';
import type {
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionForSigningResult,
} from '../../session/sealedRecovery/sealedRecovery.types';
import {
  parseEd25519WorkerMaterialBindingDigest,
  parseEd25519WorkerMaterialKeyId,
} from '../../session/keyMaterialBrands';

export type ExactNearEd25519ExportLane = {
  curve: 'ed25519';
  chain: 'near';
  signer: NearEd25519SignerBinding;
  nearAccountId: NearAccountId;
  authMethod: 'email_otp' | 'passkey';
  signingGrantId: string;
  thresholdSessionId: string;
  state: AvailableSigningLanes['lanes']['ed25519']['near']['state'];
  source: AvailableSigningLanes['lanes']['ed25519']['near']['source'];
  laneIdentity: ExactEd25519SigningLaneIdentity;
  material: {
    ed25519WorkerMaterialBindingDigest: string;
    materialKeyId: string;
  };
};

type ConcreteEd25519ExportAvailableLane = AvailableEd25519SigningLane & {
  authMethod: 'email_otp' | 'passkey';
  signingGrantId: string;
  thresholdSessionId: string;
};

type ConcreteEcdsaExportAvailableLane = ConcreteAvailableEcdsaSigningLane;

type ConcreteExportAvailableLane =
  | ConcreteEd25519ExportAvailableLane
  | ConcreteEcdsaExportAvailableLane;

type EcdsaExportSelectionKeyContext = {
  walletId: string;
};

type EcdsaExportMaterialLaneResolution =
  | {
      kind: 'resolved';
      lane: ConcreteEcdsaExportAvailableLane;
    }
  | {
      kind: 'duplicate_shared_key_targets';
      targetLane: ConcreteEcdsaExportAvailableLane;
      sourceCandidates: ConcreteEcdsaExportAvailableLane[];
    };

type RestorePasskeyPersistedSessionForSigningInput =
  RestorePersistedSessionForSigningInput & { authMethod: 'passkey' };
type RestoreEmailOtpPersistedSessionForSigningInput =
  RestorePersistedSessionForSigningInput & { authMethod: 'email_otp' };

export type ExportLaneSelectionDeps = {
  readPersistedAvailableSigningLanes: (
    args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
  ) => Promise<AvailableSigningLanes>;
  readPersistedAvailableSigningLanesForTargets: (
    args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'> & {
      ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
    },
  ) => Promise<AvailableSigningLanes>;
  restorePasskeyPersistedSessionForSigning: (
    args: RestorePasskeyPersistedSessionForSigningInput,
  ) => Promise<RestorePersistedSessionForSigningResult>;
  restoreEmailOtpPersistedSessionForSigning: (
    args: RestoreEmailOtpPersistedSessionForSigningInput,
  ) => Promise<RestorePersistedSessionForSigningResult>;
};

function isConcreteEd25519ExportLane(
  lane: AvailableEd25519SigningLane | null | undefined,
): lane is ConcreteEd25519ExportAvailableLane {
  return (
    Boolean(lane) &&
    lane!.curve === 'ed25519' &&
    lane!.chain === 'near' &&
    lane!.state !== 'missing' &&
    (lane!.auth.kind === 'email_otp' || lane!.auth.kind === 'passkey') &&
    Boolean(String(lane!.signingGrantId || '').trim()) &&
    Boolean(String(lane!.thresholdSessionId || '').trim())
  );
}

function summarizeExportAvailableLane(lane: ConcreteExportAvailableLane): Record<string, unknown> {
  const authMethod =
    lane.curve === 'ecdsa'
      ? availableEcdsaSigningLaneAuthMethod(lane)
      : availableEd25519SigningLaneAuthMethod(lane);
  return {
    authMethod,
    curve: lane.curve,
    chain: lane.curve === 'ecdsa' ? lane.chainTarget.kind : lane.chain,
    ...(lane.curve === 'ecdsa' ? { chainTarget: lane.chainTarget } : {}),
    state: lane.state,
    source: lane.source,
    signingGrantId: lane.signingGrantId,
    thresholdSessionId: lane.thresholdSessionId,
    remainingUses: lane.remainingUses,
    expiresAtMs: lane.expiresAtMs,
    updatedAtMs: lane.updatedAtMs,
    ...(lane.curve === 'ecdsa'
      ? {
          evmFamilyKeyFingerprint: deriveEvmFamilyKeyFingerprintFromPublicFacts({
            walletId: lane.key.walletId,
            publicFacts: lane.publicFacts,
          }),
        }
      : {}),
  };
}

function exportAvailableLaneSelectionKey(
  lane: ConcreteExportAvailableLane,
  ecdsaContext?: EcdsaExportSelectionKeyContext,
): string {
  if (lane.curve === 'ed25519') return ed25519AvailableLaneIdentityKey(lane) || '';
  if (!ecdsaContext) return '';
  if (String(lane.key.walletId) !== ecdsaContext.walletId) return '';
  return String(
    deriveEvmFamilyKeyFingerprintFromPublicFacts({
      walletId: lane.key.walletId,
      publicFacts: lane.publicFacts,
    }),
  );
}

function selectExactExportAvailableLane<TLane extends ConcreteExportAvailableLane>(args: {
  context: string;
  candidates: TLane[];
  ecdsaContext?: EcdsaExportSelectionKeyContext;
}): TLane {
  const traceScope = args.context.includes('ed25519') ? 'near' : 'evm-family';
  const failDuplicateRecords = (): never => {
    emitSigningSessionFlowFailure(traceScope, {
      stage: 'key_export.exact_lane_duplicate_records',
      context: args.context,
      candidateCount: args.candidates.length,
      candidates: args.candidates.map(summarizeExportAvailableLane),
    });
    throw new Error(
      `[SigningEngine][${args.context}] exact lane selection failed: duplicate_records`,
    );
  };
  if (!args.candidates.length) {
    emitSigningSessionFlowFailure(traceScope, {
      stage: 'key_export.exact_lane_no_candidate',
      context: args.context,
      candidateCount: args.candidates.length,
      candidates: args.candidates.map(summarizeExportAvailableLane),
    });
    throw new Error(`[SigningEngine][${args.context}] exact lane selection failed: no_candidate`);
  }
  for (const candidate of args.candidates) {
    if (!exportAvailableLaneSelectionKey(candidate, args.ecdsaContext)) {
      return failDuplicateRecords();
    }
  }
  if (args.candidates.length !== 1) {
    return failDuplicateRecords();
  }

  const [selectedLane] = args.candidates;
  emitSigningSessionFlowTrace(traceScope, {
    stage: 'key_export.exact_lane_selected',
    context: args.context,
    reason: 'single_exact_candidate',
    selectedLane: summarizeExportAvailableLane(selectedLane),
    candidateCount: args.candidates.length,
  });
  return selectedLane;
}

function exactEd25519IdentityForExportLane(
  lane: ConcreteEd25519ExportAvailableLane,
): ExactEd25519SigningLaneIdentity {
  return exactEd25519SigningLaneIdentity({
    signer: nearEd25519SignerBindingFromBoundaryFields({
      walletId: lane.walletId,
      nearAccountId: lane.nearAccountId,
      nearEd25519SigningKeyId: lane.nearEd25519SigningKeyId,
      signerSlot: lane.signerSlot,
    }),
    auth: lane.auth,
    signingGrantId: lane.signingGrantId,
    thresholdSessionId: lane.thresholdSessionId,
  });
}

function ed25519MaterialRestoreIdentityForExportLane(lane: ExactNearEd25519ExportLane) {
  return {
    kind: 'ed25519_worker_material_restore' as const,
    lane: lane.laneIdentity,
    materialBindingDigest: parseEd25519WorkerMaterialBindingDigest(
      lane.material.ed25519WorkerMaterialBindingDigest,
    ),
    materialKeyId: parseEd25519WorkerMaterialKeyId(lane.material.materialKeyId),
  };
}

function exactEcdsaIdentityForExportLane(args: {
  lane: ConcreteEcdsaExportAvailableLane;
  chainTarget?: ThresholdEcdsaChainTarget;
}): ExactEcdsaSigningLaneIdentity {
  return exactEcdsaSigningLaneIdentity({
    signer: buildEvmFamilyEcdsaSignerBinding({
      walletId: args.lane.key.walletId,
      chainTarget: args.chainTarget || args.lane.chainTarget,
      keyHandle: args.lane.publicFacts.keyHandle,
      key: args.lane.key,
    }),
    auth: args.lane.auth,
    signingGrantId: args.lane.signingGrantId,
    thresholdSessionId: args.lane.thresholdSessionId,
  });
}

function ed25519ExportLaneMatchesIdentity(args: {
  lane: ConcreteEd25519ExportAvailableLane;
  identity: ExactEd25519SigningLaneIdentity;
}): boolean {
  return (
    exactSigningLaneIdentityKey(exactEd25519IdentityForExportLane(args.lane)) ===
    exactSigningLaneIdentityKey(args.identity)
  );
}

function ecdsaExportLaneMatchesIdentity(args: {
  lane: ConcreteEcdsaExportAvailableLane;
  identity: ExactEcdsaSigningLaneIdentity;
}): boolean {
  return (
    exactSigningLaneIdentityKey(exactEcdsaIdentityForExportLane({ lane: args.lane })) ===
    exactSigningLaneIdentityKey(args.identity)
  );
}

function sameEcdsaExportSession(
  left: ConcreteEcdsaExportAvailableLane,
  right: ConcreteEcdsaExportAvailableLane,
): boolean {
  return (
    availableEcdsaSigningLaneAuthMethod(left) === availableEcdsaSigningLaneAuthMethod(right) &&
    left.signingGrantId === right.signingGrantId &&
    left.thresholdSessionId === right.thresholdSessionId
  );
}

function resolveEcdsaExportMaterialLane(args: {
  targetLane: ConcreteEcdsaExportAvailableLane;
  allCandidates: ConcreteEcdsaExportAvailableLane[];
  ecdsaContext: EcdsaExportSelectionKeyContext;
}): EcdsaExportMaterialLaneResolution {
  if (args.targetLane.source !== 'evm_family_shared_key') {
    return { kind: 'resolved', lane: args.targetLane };
  }
  const targetIdentityKey = exportAvailableLaneSelectionKey(args.targetLane, args.ecdsaContext);
  if (!targetIdentityKey) {
    return { kind: 'resolved', lane: args.targetLane };
  }
  const sourceChainTarget = args.targetLane.sourceChainTarget;
  const sourceCandidates = args.allCandidates.filter(
    (candidate): candidate is ConcreteEcdsaExportAvailableLane =>
      candidate.source !== 'evm_family_shared_key' &&
      thresholdEcdsaChainTargetsEqual(candidate.chainTarget, sourceChainTarget) &&
      sameEcdsaExportSession(candidate, args.targetLane) &&
      exportAvailableLaneSelectionKey(candidate, args.ecdsaContext) === targetIdentityKey,
  );
  if (sourceCandidates.length === 0) {
    return { kind: 'resolved', lane: args.targetLane };
  }
  if (sourceCandidates.length > 1) {
    return {
      kind: 'duplicate_shared_key_targets',
      targetLane: args.targetLane,
      sourceCandidates,
    };
  }
  const [selectedSource] = sourceCandidates;
  return { kind: 'resolved', lane: selectedSource };
}

function resolveEcdsaExportMaterialLanesForTarget(args: {
  targetCandidates: ConcreteEcdsaExportAvailableLane[];
  allCandidates: ConcreteEcdsaExportAvailableLane[];
  ecdsaContext: EcdsaExportSelectionKeyContext;
}): ConcreteEcdsaExportAvailableLane[] {
  const materialLanes: ConcreteEcdsaExportAvailableLane[] = [];
  for (const targetLane of args.targetCandidates) {
    const resolution = resolveEcdsaExportMaterialLane({
      targetLane,
      allCandidates: args.allCandidates,
      ecdsaContext: args.ecdsaContext,
    });
    if (resolution.kind === 'duplicate_shared_key_targets') {
      emitSigningSessionFlowFailure('evm-family', {
        stage: 'key_export.duplicate_shared_key_targets',
        context: 'ecdsa-export',
        targetLane: summarizeExportAvailableLane(resolution.targetLane),
        candidateCount: resolution.sourceCandidates.length,
        candidates: resolution.sourceCandidates.map(summarizeExportAvailableLane),
      });
      throw new Error(
        '[SigningEngine][ecdsa-export] shared-key source lane selection failed: duplicate_shared_key_targets',
      );
    }
    materialLanes.push(resolution.lane);
  }
  return materialLanes;
}

async function resolveNearEd25519ExportLane(
  deps: Pick<ExportLaneSelectionDeps, 'readPersistedAvailableSigningLanes'>,
  args: {
    signer: NearEd25519SignerBinding;
    laneIdentity: ExactEd25519SigningLaneIdentity;
  },
): Promise<ExactNearEd25519ExportLane> {
  const walletId = String(args.signer.account.wallet.walletId);
  const nearAccountId = args.signer.account.nearAccountId;
  const availableLanes = await deps.readPersistedAvailableSigningLanes({
    walletId,
  });
  const concreteCandidates = availableLanes.candidates.ed25519.near
    .filter(isConcreteEd25519ExportLane)
    .filter((lane) => String(lane.walletId) === walletId)
    .filter((lane) => String(lane.nearAccountId) === String(nearAccountId))
    .filter(
      (lane) =>
        String(lane.nearEd25519SigningKeyId) === String(args.signer.nearEd25519SigningKeyId),
    );
  const exactCandidates = concreteCandidates.filter((lane) =>
    ed25519ExportLaneMatchesIdentity({ lane, identity: args.laneIdentity }),
  );

  const selected = selectExactExportAvailableLane({
    context: 'ed25519-export',
    candidates: exactCandidates,
  });
  const laneIdentity = exactEd25519IdentityForExportLane(selected);
  return {
    curve: 'ed25519',
    chain: 'near',
    signer: args.signer,
    nearAccountId,
    authMethod: availableEd25519SigningLaneAuthMethod(selected),
    signingGrantId: selected.signingGrantId,
    thresholdSessionId: selected.thresholdSessionId,
    state: selected.state,
    source: selected.source,
    laneIdentity,
    material: {
      ed25519WorkerMaterialBindingDigest: String(
        selected.ed25519WorkerMaterialBindingDigest || '',
      ).trim(),
      materialKeyId: String(selected.materialKeyId || '').trim(),
    },
  };
}

async function resolveEcdsaExportLane(
  deps: Pick<ExportLaneSelectionDeps, 'readPersistedAvailableSigningLanesForTargets'>,
  args: {
    walletId: string;
    signingTarget: EvmFamilySigningTarget;
    laneIdentity: ExactEcdsaSigningLaneIdentity;
  },
): Promise<ExactEcdsaExportLane> {
  const targetAvailableLanes = await deps.readPersistedAvailableSigningLanesForTargets({
    walletId: args.walletId,
    ecdsaChainTargets: [args.signingTarget],
  });
  const targetCandidates = ecdsaAvailableLaneCandidatesForTarget(
    targetAvailableLanes,
    args.signingTarget,
  ).filter(isConcreteEcdsaExportLane);
  const exactTargetCandidates = targetCandidates.filter((lane) =>
    ecdsaExportLaneMatchesIdentity({ lane, identity: args.laneIdentity }),
  );
  const allConcreteCandidates = Object.values(targetAvailableLanes.ecdsa.candidatesByTarget)
    .flat()
    .filter(isConcreteEcdsaExportLane);
  const ecdsaContext = {
    walletId: args.walletId,
  };
  const materialCandidates = resolveEcdsaExportMaterialLanesForTarget({
    targetCandidates: exactTargetCandidates,
    allCandidates: allConcreteCandidates,
    ecdsaContext,
  });
  const selected = selectExactExportAvailableLane({
    context: 'ecdsa-export',
    candidates: materialCandidates,
    ecdsaContext,
  });
  const sessionChainTarget =
    selected.source === 'evm_family_shared_key' ? selected.sourceChainTarget : selected.chainTarget;
  const laneIdentity = exactEcdsaIdentityForExportLane({
    lane: selected,
    chainTarget: sessionChainTarget,
  });
  return {
    curve: 'ecdsa',
    laneIdentity,
    key: selected.key,
    publicFacts: selected.publicFacts,
    session: {
      chainTarget: sessionChainTarget,
      authMethod: availableEcdsaSigningLaneAuthMethod(selected),
      signingGrantId: SigningSessionIds.signingGrant(
        selected.signingGrantId,
      ),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(selected.thresholdSessionId),
      state: selected.state,
      source: selected.source,
    },
  };
}

export async function restoreNearEd25519SessionForExport(
  deps: ExportLaneSelectionDeps,
  args: {
    signer: NearEd25519SignerBinding;
    laneIdentity: ExactEd25519SigningLaneIdentity;
  },
): Promise<ExactNearEd25519ExportLane> {
  const restoreLane = await resolveNearEd25519ExportLane(deps, {
    signer: args.signer,
    laneIdentity: args.laneIdentity,
  });
  const walletId = String(args.signer.account.wallet.walletId);
  if (
    restoreLane.state === 'ready' ||
    restoreLane.source === 'runtime_session_record' ||
    restoreLane.source === 'runtime_and_durable'
  ) {
    return restoreLane;
  }
  if (restoreLane.authMethod === 'passkey') {
    await deps.restorePasskeyPersistedSessionForSigning({
      walletId,
      authMethod: 'passkey',
      curve: 'ed25519',
      chain: 'near',
      signingGrantId: restoreLane.signingGrantId,
      thresholdSessionId: restoreLane.thresholdSessionId,
      reason: 'export',
      materialRestoreIdentity: ed25519MaterialRestoreIdentityForExportLane(restoreLane),
    });
    return restoreLane;
  }
  await deps.restoreEmailOtpPersistedSessionForSigning({
    walletId,
    authMethod: 'email_otp',
    curve: 'ed25519',
    chain: 'near',
    signingGrantId: restoreLane.signingGrantId,
    thresholdSessionId: restoreLane.thresholdSessionId,
    reason: 'export',
    materialRestoreIdentity: ed25519MaterialRestoreIdentityForExportLane(restoreLane),
  });
  return restoreLane;
}

export async function restoreEcdsaSessionForExport(
  deps: ExportLaneSelectionDeps,
  args: {
    walletId: string;
    signingTarget: EvmFamilySigningTarget;
    laneIdentity: ExactEcdsaSigningLaneIdentity;
  },
): Promise<ExactEcdsaExportLane> {
  const restoreLane = await resolveEcdsaExportLane(deps, {
    ...args,
  });
  if (
    restoreLane.session.state === 'ready' ||
    restoreLane.session.source === 'runtime_session_record' ||
    restoreLane.session.source === 'runtime_and_durable'
  ) {
    return restoreLane;
  }
  if (restoreLane.session.authMethod === 'email_otp') {
    return restoreLane;
  }
  if (restoreLane.session.authMethod === 'passkey') {
    await deps.restorePasskeyPersistedSessionForSigning({
      walletId: args.walletId,
      authMethod: 'passkey',
      curve: 'ecdsa',
      chainTarget: restoreLane.session.chainTarget,
      signingGrantId: String(restoreLane.session.signingGrantId),
      thresholdSessionId: String(restoreLane.session.thresholdSessionId),
      reason: 'export',
      materialRestoreIdentity: {
        kind: 'ecdsa_role_local_restore',
        lane: restoreLane.laneIdentity,
        ecdsaThresholdKeyId: restoreLane.key.ecdsaThresholdKeyId,
      },
    });
    return restoreLane;
  }
  throw new Error('[SigningEngine][ecdsa-export] unsupported export auth method');
}
