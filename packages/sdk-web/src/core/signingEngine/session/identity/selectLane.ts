import type { AccountId } from '@/core/types/accountIds';
import type {
  ConcreteAvailableSigningLane,
  AvailableSigningLanes,
  ConcreteAvailableEcdsaSigningLane,
  AvailableEcdsaSigningLane,
  AvailableEd25519SigningLane,
  Ed25519AvailableWorkerMaterialIdentity,
} from '../availability/availableSigningLanes';
import {
  ecdsaLaneCandidateFromAvailableLane,
  ecdsaAvailableLaneCandidatesForTarget,
  ed25519AvailableLaneIdentityKey,
  ed25519LaneCandidateFromAvailableLane,
  isConcreteAvailableSigningLane,
} from '../availability/availableSigningLanes';
import {
  selectedEcdsaLane,
  selectedEd25519Lane,
  laneCandidateAuthMethod,
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
  | { kind: 'ambiguous_material'; allowedAuthMethods: readonly SigningAuthMethod[] }
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

export type Ed25519LaneAuthorityKey = string & { readonly __brand: 'Ed25519LaneAuthorityKey' };

export type NearEd25519TransactionReadyAvailableLane = Omit<NearEd25519AvailableLane, 'source'> & {
  state: 'ready' | 'restorable';
};

export type NearEd25519TransactionReauthAvailableLane = Omit<
  NearEd25519AvailableLane,
  'source'
> & {
  state: 'expired' | 'exhausted';
};

export type NearEd25519TransactionSelectableAvailableLane =
  | NearEd25519TransactionReadyAvailableLane
  | NearEd25519TransactionReauthAvailableLane;

export type Ed25519TransactionMaterialIdentity = Ed25519AvailableWorkerMaterialIdentity;

export type Ed25519TransactionMaterialAvailability =
  | {
      kind: 'loaded_worker_material';
      identity: Ed25519TransactionMaterialIdentity;
    }
  | {
      kind: 'sealed_worker_material';
      identity: Ed25519TransactionMaterialIdentity;
    };

export type NearEd25519TransactionMaterial = Ed25519TransactionMaterialAvailability;

export type NearEd25519TransactionReadyLane = TransactionCandidatePair<
  Ed25519LaneCandidate,
  NearEd25519TransactionReadyAvailableLane
> & {
  kind: 'near_ed25519_transaction_ready_lane';
  selectedLane: SelectedEd25519Lane;
  authorityKey: Ed25519LaneAuthorityKey;
  material: NearEd25519TransactionMaterial;
};

export type NearEd25519TransactionReauthLane = TransactionCandidatePair<
  Ed25519LaneCandidate,
  NearEd25519TransactionReauthAvailableLane
> & {
  kind: 'near_ed25519_transaction_reauth_lane';
  selectedLane: SelectedEd25519Lane;
  authorityKey: Ed25519LaneAuthorityKey;
  material: NearEd25519TransactionMaterial;
};

export type NearEd25519TransactionSelectableLane =
  | NearEd25519TransactionReadyLane
  | NearEd25519TransactionReauthLane;

export type TransactionLaneSelectionResult =
  | {
      ok: true;
      lane: TransactionLane;
      candidate: LaneCandidate;
      availableLane: TransactionConcreteAvailableLane;
      selectionCandidate: ConcreteTransactionCandidate;
    }
  | { ok: false; failure: TransactionLaneSelectionFailure };

type TransactionCandidatePair<TCandidate extends LaneCandidate, TAvailableLane> = {
  candidate: TCandidate;
  availableLane: TAvailableLane;
};

type EvmFamilyEcdsaTransactionCandidate = TransactionCandidatePair<
  EcdsaLaneCandidate,
  EvmFamilyEcdsaAvailableLane
>;

export type ConcreteTransactionCandidate =
  | NearEd25519TransactionSelectableLane
  | EvmFamilyEcdsaTransactionCandidate;

export type TransactionIntentReceivedState = {
  tag: 'IntentReceived';
  intent: TransactionSigningIntent;
};

export type TransactionAvailableLanesReadState = {
  tag: 'AvailableLanesRead';
  intent: TransactionSigningIntent;
  availableLanes: AvailableSigningLanes | null;
};

export type TransactionLaneSelectedState<
  TLane extends TransactionLane = TransactionLane,
  TAvailableLane extends TransactionConcreteAvailableLane = TransactionConcreteAvailableLane,
  TCandidate extends LaneCandidate = LaneCandidate,
  TSelectionCandidate extends ConcreteTransactionCandidate = ConcreteTransactionCandidate,
> = {
  tag: 'LaneSelected';
  intent: TransactionSigningIntent;
  lane: TLane;
  candidate: TCandidate;
  availableLane: TAvailableLane;
  selectionCandidate: TSelectionCandidate;
};

export type TransactionLaneSelectionFailedState = {
  tag: 'LaneSelectionFailed';
  intent: TransactionSigningIntent;
  failure: TransactionLaneSelectionFailure;
};

export type SelectTransactionLaneInput = {
  intent: TransactionSigningIntent;
  availableLanes: AvailableSigningLanes | null;
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
  },
): TransactionAvailableLanesReadState {
  return {
    tag: 'AvailableLanesRead',
    intent: state.intent,
    availableLanes: args.availableLanes,
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

function toEd25519LaneAuthorityKey(lane: NearEd25519AvailableLane): Ed25519LaneAuthorityKey | null {
  const key = ed25519AvailableLaneIdentityKey(lane);
  return key ? (key as Ed25519LaneAuthorityKey) : null;
}

function nearEd25519TransactionReadyState(
  lane: NearEd25519AvailableLane,
): NearEd25519TransactionReadyAvailableLane['state'] | null {
  if (lane.state === 'ready') return 'ready';
  if (lane.state === 'restorable') return 'restorable';
  return null;
}

function nearEd25519TransactionReauthState(
  lane: NearEd25519AvailableLane,
): NearEd25519TransactionReauthAvailableLane['state'] | null {
  if (lane.state === 'expired') return 'expired';
  if (lane.state === 'exhausted') return 'exhausted';
  return null;
}

function nearEd25519TransactionSelectableState(
  lane: NearEd25519AvailableLane,
): NearEd25519TransactionSelectableAvailableLane['state'] | null {
  return nearEd25519TransactionReadyState(lane) || nearEd25519TransactionReauthState(lane);
}

function nearEd25519TransactionReadyAvailableLaneProjection(
  lane: NearEd25519AvailableLane,
): NearEd25519TransactionReadyAvailableLane {
  const state = nearEd25519TransactionReadyState(lane);
  if (!state) {
    throw new Error('[SigningSessionSelectLane] Ed25519 lane is not transaction-ready');
  }
  return {
    auth: lane.auth,
    curve: 'ed25519',
    chain: 'near',
    walletId: lane.walletId,
    nearAccountId: lane.nearAccountId,
    nearEd25519SigningKeyId: lane.nearEd25519SigningKeyId,
    signerSlot: lane.signerSlot,
    state,
    signingGrantId: lane.signingGrantId,
    thresholdSessionId: lane.thresholdSessionId,
    material: lane.material,
    ...(lane.remainingUses == null ? {} : { remainingUses: lane.remainingUses }),
    ...(lane.expiresAtMs == null ? {} : { expiresAtMs: lane.expiresAtMs }),
    ...(lane.policyHint ? { policyHint: lane.policyHint } : {}),
    ...(lane.updatedAtMs == null ? {} : { updatedAtMs: lane.updatedAtMs }),
  };
}

function nearEd25519TransactionReauthAvailableLaneProjection(
  lane: NearEd25519AvailableLane,
): NearEd25519TransactionReauthAvailableLane {
  const state = nearEd25519TransactionReauthState(lane);
  if (!state) {
    throw new Error('[SigningSessionSelectLane] Ed25519 lane is not transaction-reauthable');
  }
  return {
    auth: lane.auth,
    curve: 'ed25519',
    chain: 'near',
    walletId: lane.walletId,
    nearAccountId: lane.nearAccountId,
    nearEd25519SigningKeyId: lane.nearEd25519SigningKeyId,
    signerSlot: lane.signerSlot,
    state,
    signingGrantId: lane.signingGrantId,
    thresholdSessionId: lane.thresholdSessionId,
    material: lane.material,
    ...(lane.remainingUses == null ? {} : { remainingUses: lane.remainingUses }),
    ...(lane.expiresAtMs == null ? {} : { expiresAtMs: lane.expiresAtMs }),
    ...(lane.policyHint ? { policyHint: lane.policyHint } : {}),
    ...(lane.updatedAtMs == null ? {} : { updatedAtMs: lane.updatedAtMs }),
  };
}

export function ed25519TransactionMaterialAvailabilityFromLane(
  lane: AvailableEd25519SigningLane | null | undefined,
): NearEd25519TransactionMaterial | null {
  if (!isConcreteNearEd25519Lane(lane)) return null;
  const state = nearEd25519TransactionSelectableState(lane);
  if (!state) return null;
  switch (lane.material.kind) {
    case 'loaded_worker_material':
      if (state !== 'ready') return null;
      return {
        kind: 'loaded_worker_material',
        identity: lane.material.identity,
      };
    case 'sealed_worker_material':
      return {
        kind: 'sealed_worker_material',
        identity: lane.material.identity,
      };
    case 'material_pending':
      return null;
  }
}

function selectedEd25519LaneForTransactionCandidate(
  candidate: Ed25519LaneCandidate,
): SelectedEd25519Lane {
  return selectedEd25519Lane({
    walletId: candidate.walletId,
    nearAccountId: candidate.nearAccountId,
    nearEd25519SigningKeyId: candidate.nearEd25519SigningKeyId,
    signerSlot: candidate.signerSlot,
    auth: candidate.auth,
    signingGrantId: candidate.signingGrantId,
    thresholdSessionId: candidate.thresholdSessionId,
  });
}

function buildNearEd25519TransactionReadyLane(args: {
  lane: NearEd25519AvailableLane;
  candidate: Ed25519LaneCandidate;
  authorityKey: Ed25519LaneAuthorityKey;
  material: NearEd25519TransactionMaterial;
}): NearEd25519TransactionReadyLane {
  return {
    kind: 'near_ed25519_transaction_ready_lane',
    candidate: args.candidate,
    availableLane: nearEd25519TransactionReadyAvailableLaneProjection(args.lane),
    selectedLane: selectedEd25519LaneForTransactionCandidate(args.candidate),
    authorityKey: args.authorityKey,
    material: args.material,
  };
}

function buildNearEd25519TransactionReauthLane(args: {
  lane: NearEd25519AvailableLane;
  candidate: Ed25519LaneCandidate;
  authorityKey: Ed25519LaneAuthorityKey;
  material: NearEd25519TransactionMaterial;
}): NearEd25519TransactionReauthLane {
  return {
    kind: 'near_ed25519_transaction_reauth_lane',
    candidate: args.candidate,
    availableLane: nearEd25519TransactionReauthAvailableLaneProjection(args.lane),
    selectedLane: selectedEd25519LaneForTransactionCandidate(args.candidate),
    authorityKey: args.authorityKey,
    material: args.material,
  };
}

export function toNearEd25519TransactionReadyLane(
  lane: AvailableEd25519SigningLane | null | undefined,
): NearEd25519TransactionReadyLane | null {
  if (!isConcreteNearEd25519Lane(lane)) return null;
  if (!nearEd25519TransactionReadyState(lane)) return null;
  const material = ed25519TransactionMaterialAvailabilityFromLane(lane);
  if (!material) return null;
  const authorityKey = toEd25519LaneAuthorityKey(lane);
  if (!authorityKey) return null;
  const candidate = ed25519LaneCandidateFromAvailableLane({ lane });
  if (!candidate) return null;
  return buildNearEd25519TransactionReadyLane({ lane, candidate, authorityKey, material });
}

export function listNearEd25519TransactionReadyLanes(
  lanes: readonly AvailableEd25519SigningLane[] | null | undefined,
): NearEd25519TransactionReadyLane[] {
  return (lanes || [])
    .map(toNearEd25519TransactionReadyLane)
    .filter((lane): lane is NearEd25519TransactionReadyLane => lane !== null);
}

export function toNearEd25519TransactionSelectableLane(
  lane: AvailableEd25519SigningLane | null | undefined,
): NearEd25519TransactionSelectableLane | null {
  if (!isConcreteNearEd25519Lane(lane)) return null;
  const readyState = nearEd25519TransactionReadyState(lane);
  const reauthState = nearEd25519TransactionReauthState(lane);
  if (!readyState && !reauthState) return null;
  const material = ed25519TransactionMaterialAvailabilityFromLane(lane);
  if (!material) return null;
  const authorityKey = toEd25519LaneAuthorityKey(lane);
  if (!authorityKey) return null;
  const candidate = ed25519LaneCandidateFromAvailableLane({ lane });
  if (!candidate) return null;
  if (readyState) {
    return buildNearEd25519TransactionReadyLane({ lane, candidate, authorityKey, material });
  }
  return buildNearEd25519TransactionReauthLane({ lane, candidate, authorityKey, material });
}

export function listNearEd25519TransactionSelectableLanes(
  lanes: readonly AvailableEd25519SigningLane[] | null | undefined,
): NearEd25519TransactionSelectableLane[] {
  return (lanes || [])
    .map(toNearEd25519TransactionSelectableLane)
    .filter((lane): lane is NearEd25519TransactionSelectableLane => lane !== null);
}

function selectedLaneFromCandidate(candidate: LaneCandidate): SelectedLane {
  if (candidate.curve === 'ed25519') {
    return selectedEd25519Lane({
      walletId: candidate.walletId,
      nearAccountId: candidate.nearAccountId,
      nearEd25519SigningKeyId: candidate.nearEd25519SigningKeyId,
      signerSlot: candidate.signerSlot,
      auth: candidate.auth,
      signingGrantId: candidate.signingGrantId,
      thresholdSessionId: candidate.thresholdSessionId,
    });
  }
  return selectedEcdsaLane({
    key: candidate.key,
    keyHandle: candidate.keyHandle,
    walletId: candidate.walletId,
    auth: candidate.auth,
    signingGrantId: candidate.signingGrantId,
    thresholdSessionId: candidate.thresholdSessionId,
    chainTarget: candidate.chainTarget,
  });
}

function allowedAuthMethods(
  candidates: readonly ConcreteTransactionCandidate[],
): SigningAuthMethod[] {
  return [
    ...new Set(candidates.map((candidate) => laneCandidateAuthMethod(candidate.candidate))),
  ].sort();
}

function selectOnlyConcreteTransactionCandidate<TCandidate extends ConcreteTransactionCandidate>(
  candidates: readonly TCandidate[],
): TCandidate | null {
  switch (candidates.length) {
    case 0:
      return null;
    case 1: {
      const [candidate] = candidates;
      return candidate || null;
    }
    default:
      return null;
  }
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
  const concreteCandidates = input.availableLanes?.candidates?.ed25519?.near
    ? listNearEd25519TransactionSelectableLanes(input.availableLanes.candidates.ed25519.near)
    : [];
  return selectConcreteTransactionCandidate({
    intent,
    candidates: concreteCandidates,
    buildLane: (entry) => entry.selectedLane,
  });
}

function selectEvmFamilyEcdsaTransactionLane(
  input: SelectTransactionLaneInput & { intent: EvmFamilyEcdsaTransactionSigningIntent },
): TransactionLaneSelectionResult {
  const intent = input.intent;
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

function transactionCandidatesAllowedByAuthPolicy<TCandidate extends ConcreteTransactionCandidate>(
  intent: TransactionSigningIntent,
  candidates: readonly TCandidate[],
): readonly TCandidate[] {
  if (intent.authSelectionPolicy.kind === 'any') return candidates;
  const policyAuthMethod = intent.authSelectionPolicy.authMethod;
  return candidates.filter(
    (candidate) => laneCandidateAuthMethod(candidate.candidate) === policyAuthMethod,
  );
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
  const candidates = transactionCandidatesAllowedByAuthPolicy(intent, args.candidates);

  if (!candidates.length) {
    return {
      ok: false,
      failure:
        intent.authSelectionPolicy.kind === 'any'
          ? { kind: 'no_candidate' }
          : { kind: 'no_candidate', authMethod: intent.authSelectionPolicy.authMethod },
    };
  }

  const selected = selectOnlyConcreteTransactionCandidate(candidates);
  if (!selected) {
    return {
      ok: false,
      failure: {
        kind: 'ambiguous_material',
        allowedAuthMethods: allowedAuthMethods(candidates),
      },
    };
  }

  return {
    ok: true,
    lane: args.buildLane(selected),
    candidate: selected.candidate,
    availableLane: selected.availableLane,
    selectionCandidate: selected,
  };
}

export function selectTransactionLaneFromAvailableLanes(
  state: TransactionAvailableLanesReadState,
): TransactionLaneSelectedState | TransactionLaneSelectionFailedState {
  const selection = selectTransactionLane({
    intent: state.intent,
    availableLanes: state.availableLanes,
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
    selectionCandidate: selection.selectionCandidate,
  };
}
