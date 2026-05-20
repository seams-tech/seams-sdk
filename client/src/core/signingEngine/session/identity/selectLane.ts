import type { AccountId } from '@/core/types/accountIds';
import type {
  ConcreteAvailableSigningLane,
  AvailableSigningLanes,
  ConcreteAvailableEcdsaSigningLane,
  AvailableEcdsaSigningLane,
  AvailableEd25519SigningLane,
} from '../availability/availableSigningLanes';
import {
  ecdsaLaneCandidateFromAvailableLane,
  ecdsaAvailableLaneCandidatesForTarget,
  ed25519LaneCandidateFromAvailableLane,
  isConcreteAvailableSigningLane,
} from '../availability/availableSigningLanes';
import {
  selectedEcdsaLane,
  selectedEd25519Lane,
  type EcdsaLaneCandidate,
  type Ed25519LaneCandidate,
  type LaneCandidate,
  type SelectedEcdsaLane,
  type SelectedEd25519Lane,
  type SelectedLane,
} from './laneIdentity';
import type { SigningAuthMethod } from '../operationState/types';
import type {
  EvmFamilyEcdsaTransactionSigningIntent,
  TransactionLane,
  TransactionSigningIntent,
} from '../operationState/transactionState';
import { thresholdEcdsaChainTargetsEqual } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type TransactionLaneSelectionFailure =
  | { kind: 'unsupported_intent'; curve: string; chain: string }
  | { kind: 'no_candidate'; authMethod?: SigningAuthMethod }
  | { kind: 'ambiguous_candidates'; allowedAuthMethods: readonly SigningAuthMethod[] }
  | { kind: 'incomplete_candidate'; missing: readonly string[] }
  | { kind: 'policy_blocked'; reason: string };

export type NearEd25519AvailableLane = AvailableEd25519SigningLane &
  ConcreteAvailableSigningLane & {
    curve: 'ed25519';
    chain: 'near';
  };

export type EvmFamilyEcdsaAvailableLane = ConcreteAvailableEcdsaSigningLane;

export type TransactionConcreteAvailableLane =
  | NearEd25519AvailableLane
  | EvmFamilyEcdsaAvailableLane;

export type TransactionLaneSelectionResult =
  | {
      ok: true;
      lane: TransactionLane;
      candidate: LaneCandidate;
      availableLane: TransactionConcreteAvailableLane;
    }
  | { ok: false; failure: TransactionLaneSelectionFailure };

type TransactionCandidatePair<TCandidate extends LaneCandidate, TAvailableLane> = {
  candidate: TCandidate;
  availableLane: TAvailableLane;
};

type NearEd25519TransactionCandidate = TransactionCandidatePair<
  Ed25519LaneCandidate,
  NearEd25519AvailableLane
>;

type EvmFamilyEcdsaTransactionCandidate = TransactionCandidatePair<
  EcdsaLaneCandidate,
  EvmFamilyEcdsaAvailableLane
>;

type ConcreteTransactionCandidate =
  | NearEd25519TransactionCandidate
  | EvmFamilyEcdsaTransactionCandidate;

export type TransactionIntentReceivedState = {
  tag: 'IntentReceived';
  intent: TransactionSigningIntent;
};

export type TransactionAvailableLanesReadState = {
  tag: 'AvailableLanesRead';
  intent: TransactionSigningIntent;
  availableLanes: AvailableSigningLanes | null;
  currentRuntimeLane?: AvailableEd25519SigningLane | AvailableEcdsaSigningLane | null;
};

export type TransactionLaneSelectedState<
  TLane extends TransactionLane = TransactionLane,
  TAvailableLane extends TransactionConcreteAvailableLane = TransactionConcreteAvailableLane,
  TCandidate extends LaneCandidate = LaneCandidate,
> = {
  tag: 'LaneSelected';
  intent: TransactionSigningIntent;
  lane: TLane;
  candidate: TCandidate;
  availableLane: TAvailableLane;
};

export type TransactionLaneSelectionFailedState = {
  tag: 'LaneSelectionFailed';
  intent: TransactionSigningIntent;
  failure: TransactionLaneSelectionFailure;
};

export type SelectTransactionLaneInput = {
  intent: TransactionSigningIntent;
  availableLanes: AvailableSigningLanes | null;
  currentRuntimeLane?: AvailableEd25519SigningLane | AvailableEcdsaSigningLane | null;
};

export function receiveTransactionIntent(
  intent: TransactionSigningIntent,
): TransactionIntentReceivedState {
  return { tag: 'IntentReceived', intent };
}

export function recordAvailableSigningLanesRead(
  state: TransactionIntentReceivedState,
  args: {
    availableLanes: AvailableSigningLanes | null;
    currentRuntimeLane?: AvailableEd25519SigningLane | AvailableEcdsaSigningLane | null;
  },
): TransactionAvailableLanesReadState {
  return {
    tag: 'AvailableLanesRead',
    intent: state.intent,
    availableLanes: args.availableLanes,
    ...(args.currentRuntimeLane !== undefined
      ? { currentRuntimeLane: args.currentRuntimeLane }
      : {}),
  };
}

function isConcreteNearEd25519Lane(
  lane: AvailableEd25519SigningLane | null | undefined,
): lane is NearEd25519AvailableLane {
  return (
    Boolean(lane) &&
    lane!.curve === 'ed25519' &&
    lane!.chain === 'near' &&
    isConcreteAvailableSigningLane(lane!)
  );
}

function isConcreteEvmFamilyEcdsaLane(
  lane: AvailableEcdsaSigningLane | null | undefined,
): lane is EvmFamilyEcdsaAvailableLane {
  return (
    Boolean(lane) &&
    lane!.curve === 'ecdsa' &&
    Boolean(lane!.chainTarget) &&
    isConcreteAvailableSigningLane(lane!)
  );
}

function missingConcreteFields(
  lane: AvailableEd25519SigningLane | AvailableEcdsaSigningLane | null | undefined,
): string[] {
  if (!lane) return ['lane'];
  const missing: string[] = [];
  if (
    !('authMethod' in lane) ||
    (lane.authMethod !== 'email_otp' && lane.authMethod !== 'passkey')
  ) {
    missing.push('authMethod');
  }
  if (!('walletSigningSessionId' in lane) || !String(lane.walletSigningSessionId || '').trim()) {
    missing.push('walletSigningSessionId');
  }
  if (!('thresholdSessionId' in lane) || !String(lane.thresholdSessionId || '').trim()) {
    missing.push('thresholdSessionId');
  }
  return missing;
}

function selectedLaneFromCandidate(candidate: LaneCandidate): SelectedLane {
  if (candidate.curve === 'ed25519') {
    return selectedEd25519Lane({
      accountId: candidate.accountId,
      authMethod: candidate.authMethod,
      walletSigningSessionId: candidate.walletSigningSessionId,
      thresholdSessionId: candidate.thresholdSessionId,
    });
  }
  return selectedEcdsaLane({
    key: candidate.key,
    keyHandle: candidate.keyHandle,
    walletId: candidate.walletId,
    authMethod: candidate.authMethod,
    walletSigningSessionId: candidate.walletSigningSessionId,
    thresholdSessionId: candidate.thresholdSessionId,
    chainTarget: candidate.chainTarget,
  });
}

function allowedAuthMethods(
  candidates: readonly ConcreteTransactionCandidate[],
): SigningAuthMethod[] {
  return [...new Set(candidates.map((candidate) => candidate.candidate.authMethod))].sort();
}

function candidateStatePriority(candidate: ConcreteTransactionCandidate): number {
  switch (candidate.candidate.state) {
    case 'ready':
      return 5;
    case 'restorable':
      return 4;
    case 'deferred':
      return 3;
    case 'expired':
    case 'exhausted':
      return 2;
    default:
      return 1;
  }
}

function candidateSourcePriority(candidate: ConcreteTransactionCandidate): number {
  switch (candidate.candidate.source) {
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

function candidateUpdatedAtMs(candidate: ConcreteTransactionCandidate): number | null {
  return candidate.candidate.updatedAtMs;
}

function candidatesWithBestPriority<TCandidate extends ConcreteTransactionCandidate>(
  candidates: readonly TCandidate[],
  priority: (candidate: TCandidate) => number,
): TCandidate[] {
  let bestPriority = -Infinity;
  let bestCandidates: TCandidate[] = [];
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

function selectNewestCandidateWhenUnambiguous<TCandidate extends ConcreteTransactionCandidate>(
  candidates: readonly TCandidate[],
): TCandidate | null {
  let selected: TCandidate | null = null;
  let selectedUpdatedAtMs = -Infinity;
  let ambiguous = false;
  for (const candidate of candidates) {
    const updatedAtMs = candidateUpdatedAtMs(candidate);
    if (updatedAtMs === null) return null;
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

function selectBestConcreteTransactionCandidate<TCandidate extends ConcreteTransactionCandidate>(
  candidates: readonly TCandidate[],
): TCandidate | null {
  const bestStateCandidates = candidatesWithBestPriority(candidates, candidateStatePriority);
  if (bestStateCandidates.length <= 1) return bestStateCandidates[0] || null;

  const bestSourceCandidates = candidatesWithBestPriority(
    bestStateCandidates,
    candidateSourcePriority,
  );
  if (bestSourceCandidates.length <= 1) return bestSourceCandidates[0] || null;

  return selectNewestCandidateWhenUnambiguous(bestSourceCandidates);
}

export function selectTransactionLane(
  input: SelectTransactionLaneInput,
): TransactionLaneSelectionResult {
  const intent = input.intent;
  if (intent.curve === 'ed25519' && intent.chain === 'near') {
    return selectSelectedEd25519Lane(input);
  }
  if (intent.curve === 'ecdsa') {
    return selectEvmFamilyEcdsaTransactionLane({ ...input, intent });
  }
  return {
    ok: false,
    failure: {
      kind: 'unsupported_intent',
      curve: (intent as { curve?: string }).curve || 'unknown',
      chain: (intent as { chain?: string }).chain || 'unknown',
    },
  };
}

function selectSelectedEd25519Lane(
  input: SelectTransactionLaneInput,
): TransactionLaneSelectionResult {
  const intent = input.intent;
  const runtimeLane = input.currentRuntimeLane || null;
  if (runtimeLane && !isConcreteNearEd25519Lane(runtimeLane as AvailableEd25519SigningLane)) {
    return {
      ok: false,
      failure: {
        kind: 'incomplete_candidate',
        missing: missingConcreteFields(runtimeLane),
      },
    };
  }

  const nearRuntimeLane = runtimeLane as NearEd25519AvailableLane | null;

  // Runtime lanes are accepted only after availability assembly has produced a
  // concrete candidate. Account metadata cannot create or override this anchor.
  if (nearRuntimeLane) {
    const candidate = ed25519LaneCandidateFromAvailableLane({
      walletId: intent.walletId,
      lane: nearRuntimeLane,
    });
    if (!candidate) {
      return {
        ok: false,
        failure: {
          kind: 'incomplete_candidate',
          missing: missingConcreteFields(nearRuntimeLane),
        },
      };
    }
    if (
      intent.authSelectionPolicy.kind === 'explicit' &&
      candidate.authMethod !== intent.authSelectionPolicy.authMethod
    ) {
      return {
        ok: false,
        failure: {
          kind: 'policy_blocked',
          reason: 'explicit auth method does not match current runtime lane',
        },
      };
    }
    return {
      ok: true,
      lane: selectedLaneFromCandidate(candidate) as SelectedEd25519Lane,
      candidate,
      availableLane: nearRuntimeLane,
    };
  }

  const concreteCandidates =
    input.availableLanes?.candidates?.ed25519?.near
      ?.filter(isConcreteNearEd25519Lane)
      .map((availableLane) => ({
        availableLane,
        candidate: ed25519LaneCandidateFromAvailableLane({
          walletId: intent.walletId,
          lane: availableLane,
        }),
      }))
      .filter((entry): entry is NearEd25519TransactionCandidate => entry.candidate !== null) || [];
  return selectConcreteTransactionCandidate({
    intent,
    candidates: concreteCandidates,
    buildLane: (entry) =>
      selectedLaneFromCandidate(entry.candidate) as SelectedEd25519Lane,
  });
}

function selectEvmFamilyEcdsaTransactionLane(
  input: SelectTransactionLaneInput & { intent: EvmFamilyEcdsaTransactionSigningIntent },
): TransactionLaneSelectionResult {
  const intent = input.intent;
  const runtimeLane = input.currentRuntimeLane || null;
  if (
    runtimeLane &&
    !isConcreteEvmFamilyEcdsaLane(runtimeLane as AvailableEcdsaSigningLane)
  ) {
    return {
      ok: false,
      failure: {
        kind: 'incomplete_candidate',
        missing: missingConcreteFields(runtimeLane),
      },
    };
  }

  const ecdsaRuntimeLane = runtimeLane as EvmFamilyEcdsaAvailableLane | null;
  if (ecdsaRuntimeLane) {
    const candidate = ecdsaLaneCandidateFromAvailableLane({
      walletId: intent.walletId,
      lane: ecdsaRuntimeLane,
    });
    if (!candidate) {
      return {
        ok: false,
        failure: {
          kind: 'incomplete_candidate',
          missing: missingConcreteFields(ecdsaRuntimeLane),
        },
      };
    }
    if (!thresholdEcdsaChainTargetsEqual(ecdsaRuntimeLane.chainTarget, intent.chainTarget)) {
      return {
        ok: false,
        failure: {
          kind: 'policy_blocked',
          reason: 'current runtime lane chain does not match requested chain target',
        },
      };
    }
    if (
      intent.authSelectionPolicy.kind === 'explicit' &&
      candidate.authMethod !== intent.authSelectionPolicy.authMethod
    ) {
      return {
        ok: false,
        failure: {
          kind: 'policy_blocked',
          reason: 'explicit auth method does not match current runtime lane',
        },
      };
    }
    return {
      ok: true,
      lane: selectedEvmFamilyLaneFromCandidate({ intent, candidate }),
      candidate,
      availableLane: ecdsaRuntimeLane,
    };
  }

  const concreteCandidates = input.availableLanes
    ? ecdsaAvailableLaneCandidatesForTarget(input.availableLanes, intent.chainTarget)
        .filter(isConcreteEvmFamilyEcdsaLane)
        .map((availableLane) => ({
          availableLane,
          candidate: ecdsaLaneCandidateFromAvailableLane({
            walletId: intent.walletId,
            lane: availableLane,
          }),
        }))
        .filter((entry): entry is EvmFamilyEcdsaTransactionCandidate => entry.candidate !== null)
    : [];
  return selectConcreteTransactionCandidate({
    intent,
    candidates: concreteCandidates,
    buildLane: (entry) =>
      selectedEvmFamilyLaneFromCandidate({ intent, candidate: entry.candidate }),
  });
}

function selectedEvmFamilyLaneFromCandidate(args: {
  intent: EvmFamilyEcdsaTransactionSigningIntent;
  candidate: EcdsaLaneCandidate;
}): SelectedEcdsaLane {
  if (!thresholdEcdsaChainTargetsEqual(args.candidate.chainTarget, args.intent.chainTarget)) {
    throw new Error('[SigningSessionSelectLane] ECDSA available lane target mismatch');
  }
  return selectedLaneFromCandidate(args.candidate) as SelectedEcdsaLane;
}

function selectConcreteTransactionCandidate<
  TCandidate extends ConcreteTransactionCandidate,
  TLane extends TransactionLane,
>(args: {
  intent: TransactionSigningIntent;
  candidates: readonly TCandidate[];
  buildLane: (candidate: TCandidate) => TLane;
}): TransactionLaneSelectionResult {
  const { intent } = args;
  const policyAuthMethod = intent.authSelectionPolicy.authMethod;
  const candidates = args.candidates.filter(
    (candidate) => candidate.candidate.authMethod === policyAuthMethod,
  );

  if (!candidates.length) {
    return {
      ok: false,
      failure: { kind: 'no_candidate', authMethod: policyAuthMethod },
    };
  }

  const selected = selectBestConcreteTransactionCandidate(candidates);
  if (!selected) {
    return {
      ok: false,
      failure: {
        kind: 'ambiguous_candidates',
        allowedAuthMethods: allowedAuthMethods(candidates),
      },
    };
  }

  return {
    ok: true,
    lane: args.buildLane(selected),
    candidate: selected.candidate,
    availableLane: selected.availableLane,
  };
}

export function selectTransactionLaneFromAvailableLanes(
  state: TransactionAvailableLanesReadState,
): TransactionLaneSelectedState | TransactionLaneSelectionFailedState {
  const selection = selectTransactionLane({
    intent: state.intent,
    availableLanes: state.availableLanes,
    currentRuntimeLane: state.currentRuntimeLane,
  });
  if (!selection.ok) {
    return {
      tag: 'LaneSelectionFailed',
      intent: state.intent,
      failure: selection.failure,
    };
  }
  return {
    tag: 'LaneSelected',
    intent: state.intent,
    lane: selection.lane,
    candidate: selection.candidate,
    availableLane: selection.availableLane,
  };
}
