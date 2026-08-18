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
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { deriveEvmFamilyKeyFingerprintFromPublicFacts } from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEd25519ExportMaterialIdentity,
  exactEcdsaSigningLaneIdentity,
  exactSigningLaneIdentityKey,
  nearEd25519SignerBindingFromBoundaryFields,
  type ExactEcdsaSigningLaneIdentity,
  type ExactEd25519ExportMaterialIdentity,
} from '../../session/identity/exactSigningLaneIdentity';
import type { EvmFamilySigningTarget } from '../signEvmFamily/types';
import {
  isConcreteEcdsaExportLane,
  type ExactEcdsaExportLane,
} from './ecdsaExportMaterial';
import type {
  SigningEngineResolveExactKeyExportLaneInput,
  SigningEngineResolveExactKeyExportLaneResult,
} from './keyExportFlow';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import { signingLaneAuthBindingKey } from '../../session/identity/signingLaneAuthBinding';

type ConcreteEcdsaExportAvailableLane = ConcreteAvailableEcdsaSigningLane & {
  source: 'canonical_capability';
} & (
  | {
      authorization: NonNullable<ConcreteAvailableEcdsaSigningLane['authorization']>;
    }
  | {
      authorization?: never;
      auth: ConcreteAvailableEcdsaSigningLane['auth'];
    }
);

type EcdsaExportSelectionKeyContext = {
  walletId: string;
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
  const authorization = lane.authorization;
  return {
    authMethod: availableEcdsaSigningLaneAuthMethod(lane),
    curve: lane.curve,
    chain: lane.chainTarget.kind,
    chainTarget: lane.chainTarget,
    state: lane.state,
    source: lane.source,
    ...(authorization
      ? {
          remainingUses: lane.remainingUses,
          expiresAtMs: lane.expiresAtMs,
        }
      : {}),
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
      materialActivation: args.lane.materialActivation,
    }),
    auth: args.lane.auth,
  });
}

function ecdsaExportMaterialAvailabilityForLane(lane: ConcreteEcdsaExportAvailableLane) {
  if (lane.state === 'ready') return { kind: 'loaded_worker_material' as const };
  if (availableEcdsaSigningLaneAuthMethod(lane) === 'email_otp') {
    return { kind: 'material_pending' as const, reason: 'email_otp_route_auth' as const };
  }
  return { kind: 'sealed_worker_material' as const };
}

function exactEcdsaExportLaneStateFromAvailableLane(args: {
  lane: ConcreteEcdsaExportAvailableLane;
  chainTarget: ThresholdEcdsaChainTarget;
}): Pick<ExactEcdsaExportLane, 'authMethod' | 'chainTarget' | 'material' | 'source' | 'state'> {
  const authMethod = availableEcdsaSigningLaneAuthMethod(args.lane);
  const material = ecdsaExportMaterialAvailabilityForLane(args.lane);
  switch (args.lane.state) {
    case 'expired':
    case 'exhausted':
      throw new Error(
        '[SigningEngine][ecdsa-export] expired export lane requires durable public reauth authority',
      );
    case 'ready':
    case 'deferred':
      return {
        chainTarget: args.chainTarget,
        authMethod,
        material,
        state: args.lane.state,
        source: 'canonical_capability',
      };
  }
}

function exactEcdsaExportLaneFromAvailableLane(args: {
  lane: ConcreteEcdsaExportAvailableLane;
  chainTarget: ThresholdEcdsaChainTarget;
}): ExactEcdsaExportLane {
  const laneIdentity = exactEcdsaIdentityForExportLane({ lane: args.lane });
  const state = exactEcdsaExportLaneStateFromAvailableLane(args);
  if (args.lane.authorization) {
    return {
      curve: 'ecdsa',
      laneIdentity,
      authorizationState: 'authorized',
      authorization: args.lane.authorization,
      capability: args.lane.capability,
      key: args.lane.key,
      publicFacts: args.lane.publicFacts,
      ...state,
    };
  }
  return {
    curve: 'ecdsa',
    laneIdentity,
    authorizationState: 'authorization_required',
    capability: args.lane.capability,
    key: args.lane.key,
    publicFacts: args.lane.publicFacts,
    ...state,
  };
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
  const ecdsaContext = {
    walletId: args.walletId,
  };
  const selected = selectExactExportAvailableLane({
    context: 'ecdsa-export',
    candidates: exactTargetCandidates,
    ecdsaContext,
  });
  return exactEcdsaExportLaneFromAvailableLane({
      lane: selected,
      chainTarget: selected.chainTarget,
  });
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
    args.lane.source === 'durable_sealed_record' ||
    args.lane.source === 'public_capability_reference';
  return (
    String(args.lane.walletId) === args.walletId &&
    String(args.lane.nearAccountId) === args.nearAccountId &&
    args.lane.authorizationState === 'authorized' &&
    hasRecoverableSource
  );
}

function exactEd25519MaterialIdentityForExportLane(
  lane: ConcreteAvailableEd25519SigningLane,
): ExactEd25519ExportMaterialIdentity {
  return exactEd25519ExportMaterialIdentity({
    signer: nearEd25519SignerBindingFromBoundaryFields({
      walletId: lane.walletId,
      nearAccountId: lane.nearAccountId,
      nearEd25519SigningKeyId: lane.nearEd25519SigningKeyId,
      signerSlot: lane.signerSlot,
    }),
    auth: lane.auth,
    thresholdSessionId: lane.thresholdSessionId,
  });
}

function ed25519ExportOwnerIdentityKey(lane: ConcreteAvailableEd25519SigningLane): string {
  return [
    lane.walletId,
    lane.nearAccountId,
    lane.nearEd25519SigningKeyId,
    lane.signerSlot,
    signingLaneAuthBindingKey(lane.auth),
  ]
    .map((part) => String(part))
    .join('|');
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
  const canonicalLane = available.lanes.ed25519.near;
  if (
    !isConcreteAvailableSigningLane(canonicalLane) ||
    canonicalLane.curve !== 'ed25519' ||
    !isUsableEd25519ExportLane({ lane: canonicalLane, walletId, nearAccountId })
  ) {
    throw new Error(
      '[SigningEngine][ed25519-export-resolve] exact Yao lane selection failed: no_candidate',
    );
  }
  const candidates = available.candidates.ed25519.near.filter(
    (lane): lane is ConcreteAvailableEd25519SigningLane =>
      isConcreteAvailableSigningLane(lane) &&
      lane.curve === 'ed25519' &&
      isUsableEd25519ExportLane({ lane, walletId, nearAccountId }),
  );
  const canonicalOwnerIdentityKey = ed25519ExportOwnerIdentityKey(canonicalLane);
  if (
    candidates.some(
      (candidate) => ed25519ExportOwnerIdentityKey(candidate) !== canonicalOwnerIdentityKey,
    )
  ) {
    throw new Error(
      '[SigningEngine][ed25519-export-resolve] exact Yao lane selection failed: ambiguous_material',
    );
  }
  return {
    kind: 'ed25519',
    laneIdentity: exactEd25519MaterialIdentityForExportLane(canonicalLane),
    materialActivation: canonicalLane.materialActivation,
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
  switch (restoreLane.material.kind) {
    case 'loaded_worker_material':
    case 'material_pending':
    case 'sealed_worker_material':
      return restoreLane;
  }
  restoreLane.material satisfies never;
  throw new Error('[SigningEngine][ecdsa-export] unsupported material availability');
}
