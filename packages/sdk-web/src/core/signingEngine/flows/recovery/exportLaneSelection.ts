import {
  availableEcdsaSigningLaneAuthMethod,
  ecdsaAvailableLaneCandidatesForTarget,
  isConcreteAvailableSigningLane,
  type ReadAvailableSigningLanesInput,
  type AvailableSigningLanes,
  type ConcreteAvailableEd25519SigningLane,
  type ConcreteAvailableEcdsaSigningLane,
} from '../../session/availability/availableSigningLanes';
import {
  emitSigningSessionFlowFailure,
  emitSigningSessionFlowTrace,
} from '../../session/operationState/trace';
import { SigningSessionIds } from '../../session/operationState/types';
import {
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { deriveEvmFamilyKeyFingerprintFromPublicFacts } from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEd25519SigningLaneIdentity,
  exactEcdsaSigningLaneIdentity,
  exactSigningLaneIdentityKey,
  nearEd25519SignerBindingFromBoundaryFields,
  type ExactEcdsaSigningLaneIdentity,
  type ExactEd25519SigningLaneIdentity,
} from '../../session/identity/exactSigningLaneIdentity';
import type { EvmFamilySigningTarget } from '../signEvmFamily/types';
import {
  isConcreteEcdsaExportLane,
  type ExactEcdsaExportLane,
  type ExactEcdsaExportSession,
} from './ecdsaExportMaterial';
import type {
  SigningEngineResolveExactKeyExportLaneInput,
  SigningEngineResolveExactKeyExportLaneResult,
} from './keyExportFlow';

type ConcreteEcdsaExportAvailableLane = ConcreteAvailableEcdsaSigningLane;

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

export type ExportLaneSelectionDeps = {
  readPersistedAvailableSigningLanesForTargets: (
    args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'> & {
      ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
    },
  ) => Promise<AvailableSigningLanes>;
};

function summarizeExportAvailableLane(
  lane: ConcreteEcdsaExportAvailableLane,
): Record<string, unknown> {
  return {
    authMethod: availableEcdsaSigningLaneAuthMethod(lane),
    curve: lane.curve,
    chain: lane.chainTarget.kind,
    chainTarget: lane.chainTarget,
    state: lane.state,
    source: lane.source,
    signingGrantId: lane.signingGrantId,
    thresholdSessionId: lane.thresholdSessionId,
    remainingUses: lane.remainingUses,
    expiresAtMs: lane.expiresAtMs,
    updatedAtMs: lane.updatedAtMs,
    evmFamilyKeyFingerprint: deriveEvmFamilyKeyFingerprintFromPublicFacts({
      walletId: lane.key.walletId,
      publicFacts: lane.publicFacts,
    }),
  };
}

function exportAvailableLaneSelectionKey(
  lane: ConcreteEcdsaExportAvailableLane,
  ecdsaContext: EcdsaExportSelectionKeyContext,
): string {
  if (String(lane.key.walletId) !== ecdsaContext.walletId) return '';
  return String(
    deriveEvmFamilyKeyFingerprintFromPublicFacts({
      walletId: lane.key.walletId,
      publicFacts: lane.publicFacts,
    }),
  );
}

function selectExactExportAvailableLane<TLane extends ConcreteEcdsaExportAvailableLane>(args: {
  context: string;
  candidates: TLane[];
  ecdsaContext: EcdsaExportSelectionKeyContext;
}): TLane {
  if (!args.candidates.length) {
    emitSigningSessionFlowFailure('evm-family', {
      stage: 'key_export.exact_lane_no_candidate',
      context: args.context,
      candidateCount: args.candidates.length,
      candidates: args.candidates.map(summarizeExportAvailableLane),
    });
    throw new Error(`[SigningEngine][${args.context}] exact lane selection failed: no_candidate`);
  }
  for (const candidate of args.candidates) {
    if (!exportAvailableLaneSelectionKey(candidate, args.ecdsaContext)) {
      return failAmbiguousExportAvailableLanes(args);
    }
  }
  if (args.candidates.length !== 1) {
    return failAmbiguousExportAvailableLanes(args);
  }

  const [selectedLane] = args.candidates;
  emitSigningSessionFlowTrace('evm-family', {
    stage: 'key_export.exact_lane_selected',
    context: args.context,
    reason: 'single_exact_candidate',
    selectedLane: summarizeExportAvailableLane(selectedLane),
    candidateCount: args.candidates.length,
  });
  return selectedLane;
}

function failAmbiguousExportAvailableLanes<TLane extends ConcreteEcdsaExportAvailableLane>(args: {
  context: string;
  candidates: TLane[];
}): never {
  emitSigningSessionFlowFailure('evm-family', {
    stage: 'key_export.exact_lane_ambiguous_material',
    context: args.context,
    candidateCount: args.candidates.length,
    candidates: args.candidates.map(summarizeExportAvailableLane),
  });
  throw new Error(
    `[SigningEngine][${args.context}] exact lane selection failed: ambiguous_material`,
  );
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

function ecdsaExportMaterialAvailabilityForLane(lane: ConcreteEcdsaExportAvailableLane) {
  if (lane.state === 'ready') return { kind: 'loaded_worker_material' as const };
  if (availableEcdsaSigningLaneAuthMethod(lane) === 'email_otp') {
    return { kind: 'material_pending' as const, reason: 'email_otp_route_auth' as const };
  }
  return { kind: 'sealed_worker_material' as const };
}

function exactEcdsaExportSessionFromAvailableLane(args: {
  lane: ConcreteEcdsaExportAvailableLane;
  chainTarget: ThresholdEcdsaChainTarget;
}): ExactEcdsaExportSession {
  const authMethod = availableEcdsaSigningLaneAuthMethod(args.lane);
  const signingGrantId = SigningSessionIds.signingGrant(args.lane.signingGrantId);
  const thresholdSessionId = SigningSessionIds.thresholdEcdsaSession(args.lane.thresholdSessionId);
  const material = ecdsaExportMaterialAvailabilityForLane(args.lane);
  if (args.lane.source === 'durable_sealed_record') {
    return {
      chainTarget: args.chainTarget,
      authMethod,
      signingGrantId,
      thresholdSessionId,
      material,
      state: args.lane.state,
      source: 'durable_sealed_record',
      publicReauthAuthority: args.lane.publicReauthAuthority,
    };
  }
  switch (args.lane.state) {
    case 'expired':
    case 'exhausted':
      throw new Error(
        '[SigningEngine][ecdsa-export] expired export lane requires durable public reauth authority',
      );
    case 'ready':
    case 'restorable':
    case 'deferred':
      return {
        chainTarget: args.chainTarget,
        authMethod,
        signingGrantId,
        thresholdSessionId,
        material,
        state: args.lane.state,
        source: args.lane.source,
      };
  }
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

function targetEcdsaExportCandidates(args: {
  availableLanes: AvailableSigningLanes;
  chainTarget: ThresholdEcdsaChainTarget;
}): ConcreteEcdsaExportAvailableLane[] {
  return ecdsaAvailableLaneCandidatesForTarget(args.availableLanes, args.chainTarget).filter(
    isConcreteEcdsaExportLane,
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
    session: exactEcdsaExportSessionFromAvailableLane({
      lane: selected,
      chainTarget: sessionChainTarget,
    }),
  };
}

export async function resolveExactKeyExportLane(
  deps: Pick<ExportLaneSelectionDeps, 'readPersistedAvailableSigningLanesForTargets'>,
  input: SigningEngineResolveExactKeyExportLaneInput,
): Promise<SigningEngineResolveExactKeyExportLaneResult> {
  switch (input.kind) {
    case 'ecdsa':
      return await resolveExactEcdsaKeyExportLane(deps, input);
    case 'ed25519':
      return await resolveExactEd25519KeyExportLane(deps, input);
  }
}

async function resolveExactEcdsaKeyExportLane(
  deps: Pick<ExportLaneSelectionDeps, 'readPersistedAvailableSigningLanesForTargets'>,
  input: Extract<SigningEngineResolveExactKeyExportLaneInput, { kind: 'ecdsa' }>,
): Promise<Extract<SigningEngineResolveExactKeyExportLaneResult, { kind: 'ecdsa' }>> {
  const walletId = String(toWalletId(input.walletSession.walletId));
  const targetAvailableLanes = await deps.readPersistedAvailableSigningLanesForTargets({
    walletId,
    ecdsaChainTargets: [input.chainTarget],
  });
  const targetCandidates = targetEcdsaExportCandidates({
    availableLanes: targetAvailableLanes,
    chainTarget: input.chainTarget,
  });
  const selected = selectExactExportAvailableLane({
    context: 'ecdsa-export-resolve',
    candidates: targetCandidates,
    ecdsaContext: { walletId },
  });
  return {
    kind: 'ecdsa',
    laneIdentity: exactEcdsaIdentityForExportLane({ lane: selected }),
  };
}

function isUsableEd25519ExportLane(args: {
  lane: ConcreteAvailableEd25519SigningLane;
  walletId: string;
  nearAccountId: string;
}): boolean {
  const hasRecoverableSource =
    args.lane.source === 'runtime_session_record' || args.lane.source === 'durable_sealed_record';
  return (
    String(args.lane.walletId) === args.walletId &&
    String(args.lane.nearAccountId) === args.nearAccountId &&
    hasRecoverableSource &&
    args.lane.state !== 'deferred'
  );
}

function exactEd25519IdentityForExportLane(
  lane: ConcreteAvailableEd25519SigningLane,
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

async function resolveExactEd25519KeyExportLane(
  deps: Pick<ExportLaneSelectionDeps, 'readPersistedAvailableSigningLanesForTargets'>,
  input: Extract<SigningEngineResolveExactKeyExportLaneInput, { kind: 'ed25519' }>,
): Promise<Extract<SigningEngineResolveExactKeyExportLaneResult, { kind: 'ed25519' }>> {
  const walletId = String(toWalletId(input.walletSession.walletId));
  const nearAccountId = String(input.nearAccount.accountId);
  const available = await deps.readPersistedAvailableSigningLanesForTargets({
    walletId,
    ecdsaChainTargets: [],
  });
  const candidates = available.candidates.ed25519.near.filter(
    (lane): lane is ConcreteAvailableEd25519SigningLane =>
      isConcreteAvailableSigningLane(lane) &&
      lane.curve === 'ed25519' &&
      isUsableEd25519ExportLane({ lane, walletId, nearAccountId }),
  );
  if (candidates.length === 0) {
    throw new Error(
      '[SigningEngine][ed25519-export-resolve] exact Yao lane selection failed: no_candidate',
    );
  }
  if (candidates.length !== 1) {
    throw new Error(
      '[SigningEngine][ed25519-export-resolve] exact Yao lane selection failed: ambiguous_material',
    );
  }
  const [selectedLane] = candidates;
  return {
    kind: 'ed25519',
    laneIdentity: exactEd25519IdentityForExportLane(selectedLane),
  };
}

export async function resolveEcdsaSessionForExport(
  deps: ExportLaneSelectionDeps,
  args: {
    walletId: string;
    signingTarget: EvmFamilySigningTarget;
    laneIdentity: ExactEcdsaSigningLaneIdentity;
  },
): Promise<ExactEcdsaExportLane> {
  const restoreLane = await resolveEcdsaExportLane(deps, {
    walletId: args.walletId,
    signingTarget: args.signingTarget,
    laneIdentity: args.laneIdentity,
  });
  switch (restoreLane.session.material.kind) {
    case 'loaded_worker_material':
    case 'material_pending':
    case 'sealed_worker_material':
      return restoreLane;
  }
  restoreLane.session.material satisfies never;
  throw new Error('[SigningEngine][ecdsa-export] unsupported material availability');
}
