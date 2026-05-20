import type { AccountId } from '@/core/types/accountIds';
import {
  ecdsaAvailableLaneCandidatesForTarget,
  ecdsaAvailableLaneAuthRpId,
  ed25519AvailableLaneIdentityKey,
  isConcreteAvailableSigningLane,
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

type EcdsaExportSelectionKeyContext = {
  walletId: string;
  rpId: string;
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
  if (ecdsaAvailableLaneAuthRpId(lane) !== ecdsaContext.rpId) return '';
  return String(
    deriveEvmFamilyKeyFingerprintFromPublicFacts({
      walletId: lane.key.walletId,
      publicFacts: lane.publicFacts,
    }),
  );
}

function isRuntimeExportLane(lane: ConcreteExportAvailableLane): boolean {
  return (
    lane.state === 'ready' ||
    lane.source === 'runtime_and_durable' ||
    lane.source === 'runtime_session_record'
  );
}

function exportLaneStatePriority(lane: ConcreteExportAvailableLane): number {
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

function exportLaneSourcePriority(lane: ConcreteExportAvailableLane): number {
  switch (lane.source) {
    case 'runtime_and_durable':
      return 3;
    case 'runtime_session_record':
      return 2;
    case 'durable_sealed_record':
      return 1;
    case 'evm_family_shared_key':
    default:
      return 0;
  }
}

function candidatesWithBestPriority<TLane extends ConcreteExportAvailableLane>(
  candidates: readonly TLane[],
  priority: (candidate: TLane) => number,
): TLane[] {
  let bestPriority = -Infinity;
  let bestCandidates: TLane[] = [];
  for (const candidate of candidates) {
    const value = priority(candidate);
    if (value > bestPriority) {
      bestPriority = value;
      bestCandidates = [candidate];
      continue;
    }
    if (value === bestPriority) {
      bestCandidates.push(candidate);
    }
  }
  return bestCandidates;
}

function selectNewestExportLaneWhenUnambiguous<TLane extends ConcreteExportAvailableLane>(
  candidates: readonly TLane[],
): TLane | null {
  let selected: TLane | null = null;
  let selectedUpdatedAtMs = -Infinity;
  let ambiguous = false;
  for (const candidate of candidates) {
    const updatedAtMs = Math.floor(Number(candidate.updatedAtMs));
    if (!Number.isFinite(updatedAtMs)) return null;
    if (updatedAtMs > selectedUpdatedAtMs) {
      selected = candidate;
      selectedUpdatedAtMs = updatedAtMs;
      ambiguous = false;
      continue;
    }
    if (updatedAtMs === selectedUpdatedAtMs) {
      ambiguous = true;
    }
  }
  return ambiguous ? null : selected;
}

function selectCanonicalLaneFromSelectionGroup<TLane extends ConcreteExportAvailableLane>(
  candidates: TLane[],
): TLane | null {
  const stateCandidates = candidatesWithBestPriority(candidates, exportLaneStatePriority);
  if (stateCandidates.length <= 1) return stateCandidates[0] || null;
  const sourceCandidates = candidatesWithBestPriority(stateCandidates, exportLaneSourcePriority);
  if (sourceCandidates.length <= 1) return sourceCandidates[0] || null;
  return selectNewestExportLaneWhenUnambiguous(sourceCandidates);
}

function selectCanonicalExportCandidates<TLane extends ConcreteExportAvailableLane>(args: {
  candidates: TLane[];
  ecdsaContext?: EcdsaExportSelectionKeyContext;
}): { kind: 'ok'; candidates: TLane[] } | { kind: 'ambiguous' } {
  const groups = new Map<string, TLane[]>();
  for (const candidate of args.candidates) {
    const key = exportAvailableLaneSelectionKey(candidate, args.ecdsaContext);
    if (!key) return { kind: 'ambiguous' };
    groups.set(key, [...(groups.get(key) || []), candidate]);
  }
  const collapsed: TLane[] = [];
  for (const groupCandidates of groups.values()) {
    const selected = selectCanonicalLaneFromSelectionGroup(groupCandidates);
    if (!selected) return { kind: 'ambiguous' };
    collapsed.push(selected);
  }
  return { kind: 'ok', candidates: collapsed };
}

function selectExactExportAvailableLane<TLane extends ConcreteExportAvailableLane>(args: {
  context: string;
  candidates: TLane[];
  ecdsaContext?: EcdsaExportSelectionKeyContext;
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
  const collapsed = selectCanonicalExportCandidates({
    candidates: selectableCandidates,
    ecdsaContext: args.ecdsaContext,
  });
  if (collapsed.kind === 'ambiguous') {
    return failAmbiguous();
  }
  const collapsedCandidates = collapsed.candidates;
  const runtimeCandidates = collapsedCandidates.filter(isRuntimeExportLane);
  if (runtimeCandidates.length > 1) {
    const selectedLane = selectNewestExportLaneWhenUnambiguous(runtimeCandidates);
    if (!selectedLane) return failAmbiguous();
    emitSigningSessionFlowTrace(traceScope, {
      stage: 'key_export.exact_lane_selected',
      context: args.context,
      reason: 'newest_runtime_candidate',
      selectedLane: summarizeExportAvailableLane(selectedLane),
      candidateCount: args.candidates.length,
    });
    return selectedLane;
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
  });
  const concreteCandidates = availableLanes.candidates.ed25519.near.filter(isConcreteEd25519ExportLane);
  const emailOtpCandidates = concreteCandidates.filter(
    (candidate) => candidate.authMethod === 'email_otp',
  );
  const selectionCandidates = emailOtpCandidates.some((candidate) => candidate.state !== 'missing')
    ? emailOtpCandidates
    : concreteCandidates;

  const selected = selectExactExportAvailableLane({
    context: 'ed25519-export',
    candidates: selectionCandidates,
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
    walletId: string;
    rpId: string;
    signingTarget: EvmFamilySigningTarget;
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
  const exactTargetCandidates = targetCandidates.filter(
    (candidate) => candidate.source !== 'evm_family_shared_key',
  );
  const familyCandidates =
    exactTargetCandidates.length > 0
      ? exactTargetCandidates
      : Object.values(targetAvailableLanes.ecdsa.candidatesByTarget)
          .flat()
          .filter(
            (candidate): candidate is ConcreteAvailableEcdsaSigningLane =>
              isConcreteAvailableSigningLane(candidate) &&
              candidate.curve === 'ecdsa' &&
              candidate.source !== 'evm_family_shared_key',
          );
  const emailOtpTargetCandidates = familyCandidates.filter(
    (candidate) => candidate.authMethod === 'email_otp',
  );
  const selectionCandidates = emailOtpTargetCandidates.some(
    (candidate) => candidate.state !== 'missing',
  )
    ? emailOtpTargetCandidates
    : familyCandidates;
  const selected = selectExactExportAvailableLane({
    context: 'ecdsa-export',
    candidates: selectionCandidates,
    ecdsaContext: {
      walletId: args.walletId,
      rpId: args.rpId,
    },
  });
  if (
    exactTargetCandidates.length > 0 &&
    !thresholdEcdsaChainTargetsEqual(selected.chainTarget, args.signingTarget)
  ) {
    throw new Error('[SigningEngine][ecdsa-export] selected export lane target drifted');
  }
  return {
    curve: 'ecdsa',
    key: selected.key,
    publicFacts: selected.publicFacts,
    session: {
      chainTarget: selected.chainTarget,
      authMethod: selected.authMethod,
      walletSigningSessionId: SigningSessionIds.walletSigningSession(
        selected.walletSigningSessionId,
      ),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(selected.thresholdSessionId),
      state: selected.state,
      source: selected.source,
    },
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
    walletId: string;
    rpId: string;
    signingTarget: EvmFamilySigningTarget;
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
      walletSigningSessionId: String(restoreLane.session.walletSigningSessionId),
      thresholdSessionId: String(restoreLane.session.thresholdSessionId),
      reason: 'export',
    });
    return restoreLane;
  }
  throw new Error('[SigningEngine][ecdsa-export] unsupported export auth method');
}
