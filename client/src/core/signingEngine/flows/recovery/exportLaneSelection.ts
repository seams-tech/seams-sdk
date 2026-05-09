import type { AccountId } from '@/core/types/accountIds';
import {
  ecdsaAvailableLaneCandidatesForTarget,
  ecdsaAvailableLaneIdentityKey,
  ed25519AvailableLaneIdentityKey,
  type ReadAvailableSigningLanesInput,
  type AvailableSigningLanes,
  type ConcreteAvailableEcdsaSigningLane,
  type AvailableEd25519SigningLane,
} from '../../session/availability/availableSigningLanes';
import { emitSigningSessionFlowFailure, emitSigningSessionFlowTrace } from '../../session/operationState/trace';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  toWalletSubjectId,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/types';
import type { EvmFamilySigningTarget } from '../signEvmFamily/types';
import {
  isConcreteEcdsaExportLane,
  type ExactEcdsaExportLane,
} from './ecdsaExportMaterial';
import type {
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionForSigningResult,
} from '../../session/sealedRecovery/types';

export type ExactNearEd25519ExportLane = {
  curve: 'ed25519';
  chain: 'near';
  nearAccountId: AccountId;
  authMethod: 'email_otp' | 'passkey';
  walletSigningSessionId: string;
  thresholdSessionId: string;
  state: AvailableSigningLanes['lanes']['ed25519']['near']['state'];
  source: AvailableSigningLanes['lanes']['ed25519']['near']['source'];
};

type ConcreteEd25519ExportAvailableLane = AvailableEd25519SigningLane & {
  authMethod: 'email_otp' | 'passkey';
  walletSigningSessionId: string;
  thresholdSessionId: string;
};

type ConcreteEcdsaExportAvailableLane = ConcreteAvailableEcdsaSigningLane;

type ConcreteExportAvailableLane =
  | ConcreteEd25519ExportAvailableLane
  | ConcreteEcdsaExportAvailableLane;

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
    (lane!.authMethod === 'email_otp' || lane!.authMethod === 'passkey') &&
    Boolean(String(lane!.walletSigningSessionId || '').trim()) &&
    Boolean(String(lane!.thresholdSessionId || '').trim())
  );
}

function summarizeExportAvailableLane(lane: ConcreteExportAvailableLane): Record<string, unknown> {
  return {
    authMethod: lane.authMethod,
    curve: lane.curve,
    chain: lane.curve === 'ecdsa' ? lane.chainTarget.kind : lane.chain,
    ...(lane.curve === 'ecdsa' ? { chainTarget: lane.chainTarget } : {}),
    state: lane.state,
    source: lane.source,
    walletSigningSessionId: lane.walletSigningSessionId,
    thresholdSessionId: lane.thresholdSessionId,
    remainingUses: lane.remainingUses,
    expiresAtMs: lane.expiresAtMs,
    updatedAtMs: lane.updatedAtMs,
  };
}

function exportAvailableLaneExactKey(lane: ConcreteExportAvailableLane): string {
  if (lane.curve === 'ed25519') return ed25519AvailableLaneIdentityKey(lane) || '';
  return ecdsaAvailableLaneIdentityKey(lane) || '';
}

function isRuntimeExportLane(lane: ConcreteExportAvailableLane): boolean {
  return (
    lane.state === 'ready' ||
    lane.source === 'runtime_and_durable' ||
    lane.source === 'runtime_session_record'
  );
}

function selectCanonicalLaneFromExactGroup<TLane extends ConcreteExportAvailableLane>(
  candidates: TLane[],
): TLane | null {
  const runtimeCandidates = candidates.filter(isRuntimeExportLane);
  if (runtimeCandidates.length === 1) return runtimeCandidates[0]!;
  if (!runtimeCandidates.length && candidates.length === 1) return candidates[0]!;
  return null;
}

function selectCanonicalExactExportCandidates<TLane extends ConcreteExportAvailableLane>(
  candidates: TLane[],
): { kind: 'ok'; candidates: TLane[] } | { kind: 'ambiguous' } {
  const groups = new Map<string, TLane[]>();
  for (const candidate of candidates) {
    const key = exportAvailableLaneExactKey(candidate);
    if (!key) return { kind: 'ambiguous' };
    groups.set(key, [...(groups.get(key) || []), candidate]);
  }
  const collapsed: TLane[] = [];
  for (const groupCandidates of groups.values()) {
    const selected = selectCanonicalLaneFromExactGroup(groupCandidates);
    if (!selected) return { kind: 'ambiguous' };
    collapsed.push(selected);
  }
  return { kind: 'ok', candidates: collapsed };
}

function selectExactExportAvailableLane<TLane extends ConcreteExportAvailableLane>(args: {
  context: string;
  candidates: TLane[];
}): TLane {
  const traceScope = args.context.includes('ed25519') ? 'near' : 'evm-family';
  const failAmbiguous = (): never => {
    emitSigningSessionFlowFailure(traceScope, {
      stage: 'key_export.exact_lane_ambiguous',
      context: args.context,
      candidateCount: args.candidates.length,
      candidates: args.candidates.map(summarizeExportAvailableLane),
    });
    throw new Error(
      `[SigningEngine][${args.context}] exact lane selection failed: ambiguous_candidates`,
    );
  };
  const selectableCandidates = args.candidates.filter((candidate) => candidate.state !== 'missing');
  if (!selectableCandidates.length) {
    emitSigningSessionFlowFailure(traceScope, {
      stage: 'key_export.exact_lane_no_candidate',
      context: args.context,
      candidateCount: args.candidates.length,
      candidates: args.candidates.map(summarizeExportAvailableLane),
    });
    throw new Error(`[SigningEngine][${args.context}] exact lane selection failed: no_candidate`);
  }
  const collapsed = selectCanonicalExactExportCandidates(selectableCandidates);
  if (collapsed.kind === 'ambiguous') {
    return failAmbiguous();
  }
  const collapsedCandidates = collapsed.candidates;
  const runtimeCandidates = collapsedCandidates.filter(isRuntimeExportLane);
  if (runtimeCandidates.length > 1) {
    return failAmbiguous();
  }
  if (runtimeCandidates.length === 1) {
    const selectedLane = runtimeCandidates[0]!;
    emitSigningSessionFlowTrace(traceScope, {
      stage: 'key_export.exact_lane_selected',
      context: args.context,
      reason: 'single_runtime_candidate',
      selectedLane: summarizeExportAvailableLane(selectedLane),
      candidateCount: args.candidates.length,
    });
    return selectedLane;
  }
  if (collapsedCandidates.length > 1) {
    return failAmbiguous();
  }

  const selectedLane = collapsedCandidates[0]!;
  emitSigningSessionFlowTrace(traceScope, {
    stage: 'key_export.exact_lane_selected',
    context: args.context,
    reason: 'single_exact_candidate',
    selectedLane: summarizeExportAvailableLane(selectedLane),
    candidateCount: args.candidates.length,
  });
  return selectedLane;
}

async function resolveNearEd25519ExportLane(
  deps: Pick<ExportLaneSelectionDeps, 'readPersistedAvailableSigningLanes'>,
  args: { nearAccountId: AccountId },
): Promise<ExactNearEd25519ExportLane> {
  const availableLanes = await deps.readPersistedAvailableSigningLanes({
    walletId: args.nearAccountId,
    subjectId: toWalletSubjectId(args.nearAccountId),
  });
  const concreteCandidates = availableLanes.candidates.ed25519.near.filter(isConcreteEd25519ExportLane);

  const selected = selectExactExportAvailableLane({
    context: 'ed25519-export',
    candidates: concreteCandidates,
  });
  return {
    curve: 'ed25519',
    chain: 'near',
    nearAccountId: args.nearAccountId,
    authMethod: selected.authMethod,
    walletSigningSessionId: selected.walletSigningSessionId,
    thresholdSessionId: selected.thresholdSessionId,
    state: selected.state,
    source: selected.source,
  };
}

async function resolveEcdsaExportLane(
  deps: Pick<ExportLaneSelectionDeps, 'readPersistedAvailableSigningLanesForTargets'>,
  args: {
    nearAccountId: AccountId;
    subjectId: WalletSubjectId;
    signingTarget: EvmFamilySigningTarget;
  },
): Promise<ExactEcdsaExportLane> {
  const targetAvailableLanes = await deps.readPersistedAvailableSigningLanesForTargets({
    walletId: args.nearAccountId,
    subjectId: args.subjectId,
    ecdsaChainTargets: [args.signingTarget],
  });
  const targetCandidates = ecdsaAvailableLaneCandidatesForTarget(
    targetAvailableLanes,
    args.signingTarget,
  ).filter(isConcreteEcdsaExportLane);
  const selected = selectExactExportAvailableLane({
    context: 'ecdsa-export',
    candidates: targetCandidates,
  });
  if (String(selected.subjectId) !== String(args.subjectId)) {
    throw new Error('[SigningEngine][ecdsa-export] selected export lane subject drifted');
  }
  if (!thresholdEcdsaChainTargetsEqual(selected.chainTarget, args.signingTarget)) {
    throw new Error('[SigningEngine][ecdsa-export] selected export lane target drifted');
  }
  return {
    curve: 'ecdsa',
    subjectId: selected.subjectId,
    chainTarget: selected.chainTarget,
    ecdsaThresholdKeyId: selected.ecdsaThresholdKeyId,
    signingRootId: selected.signingRootId,
    signingRootVersion: selected.signingRootVersion,
    nearAccountId: args.nearAccountId,
    authMethod: selected.authMethod,
    walletSigningSessionId: selected.walletSigningSessionId,
    thresholdSessionId: selected.thresholdSessionId,
    state: selected.state,
    source: selected.source,
  };
}

export async function restoreNearEd25519SessionForExport(
  deps: ExportLaneSelectionDeps,
  args: { nearAccountId: AccountId },
): Promise<ExactNearEd25519ExportLane> {
  const restoreLane = await resolveNearEd25519ExportLane(deps, {
    nearAccountId: args.nearAccountId,
  });
  if (
    restoreLane.state === 'ready' ||
    restoreLane.source === 'runtime_session_record' ||
    restoreLane.source === 'runtime_and_durable'
  ) {
    return restoreLane;
  }
  if (restoreLane.authMethod === 'passkey') {
    await deps.restorePasskeyPersistedSessionForSigning({
      walletId: args.nearAccountId,
      authMethod: 'passkey',
      curve: 'ed25519',
      chain: 'near',
      walletSigningSessionId: restoreLane.walletSigningSessionId,
      thresholdSessionId: restoreLane.thresholdSessionId,
      reason: 'export',
    });
    return restoreLane;
  }
  await deps.restoreEmailOtpPersistedSessionForSigning({
    walletId: args.nearAccountId,
    authMethod: 'email_otp',
    curve: 'ed25519',
    chain: 'near',
    walletSigningSessionId: restoreLane.walletSigningSessionId,
    thresholdSessionId: restoreLane.thresholdSessionId,
    reason: 'export',
  });
  return restoreLane;
}

export async function restoreEcdsaSessionForExport(
  deps: ExportLaneSelectionDeps,
  args: {
    nearAccountId: AccountId;
    subjectId: WalletSubjectId;
    signingTarget: EvmFamilySigningTarget;
  },
): Promise<ExactEcdsaExportLane> {
  const restoreLane = await resolveEcdsaExportLane(deps, {
    ...args,
  });
  if (
    restoreLane.state === 'ready' ||
    restoreLane.source === 'runtime_session_record' ||
    restoreLane.source === 'runtime_and_durable'
  ) {
    return restoreLane;
  }
  if (restoreLane.authMethod === 'email_otp') {
    return restoreLane;
  }
  if (restoreLane.authMethod === 'passkey') {
    await deps.restorePasskeyPersistedSessionForSigning({
      walletId: args.nearAccountId,
      authMethod: 'passkey',
      curve: 'ecdsa',
      chainTarget: args.signingTarget,
      walletSigningSessionId: restoreLane.walletSigningSessionId,
      thresholdSessionId: restoreLane.thresholdSessionId,
      reason: 'export',
    });
    return restoreLane;
  }
  throw new Error('[SigningEngine][ecdsa-export] unsupported export auth method');
}
