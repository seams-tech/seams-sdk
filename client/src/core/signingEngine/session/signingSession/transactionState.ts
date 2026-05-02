import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type {
  ConcreteSigningSessionSnapshotLane,
  SigningSessionSnapshot,
  SigningSessionSnapshotEcdsaLane,
  SigningSessionSnapshotEd25519Lane,
} from '../snapshotReader';
import {
  compareSnapshotCandidates,
  isConcreteSigningSessionSnapshotLane,
} from '../snapshotReader';
import {
  SigningSessionIds,
  type SigningAuthMethod,
  type SigningOperationId,
  type ThresholdEcdsaSessionId,
  type ThresholdEd25519SessionId,
  type WalletSigningSessionId,
} from './types';
import type { SigningSessionPreparedBudgetIdentity } from './budget';

export type TransactionSigningIntent = {
  operationId?: SigningOperationId;
  walletId: AccountId | string;
  curve: 'ed25519' | 'ecdsa';
  chain: 'near' | 'tempo' | 'evm';
  authSelectionPolicy: TransactionAuthSelectionPolicy;
  operationUsesNeeded: number;
};

export type TransactionAuthSelectionPolicy =
  | { kind: 'explicit'; authMethod: SigningAuthMethod }
  | { kind: 'account_class'; authMethod: SigningAuthMethod }
  | { kind: 'current_lane'; authMethod: SigningAuthMethod };

export type NearEd25519TransactionLane = {
  accountId: AccountId;
  authMethod: SigningAuthMethod;
  curve: 'ed25519';
  chain: 'near';
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEd25519SessionId;
};

export type EvmFamilyEcdsaTransactionLane = {
  accountId: AccountId;
  authMethod: SigningAuthMethod;
  curve: 'ecdsa';
  chain: 'tempo' | 'evm';
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEcdsaSessionId;
};

export type TransactionLane = NearEd25519TransactionLane | EvmFamilyEcdsaTransactionLane;

export type TransactionReadiness =
  | { status: 'ready'; remainingUses: number; expiresAtMs: number }
  | { status: 'missing_hot_material' }
  | { status: 'expired' }
  | { status: 'exhausted' }
  | { status: 'restore_failed'; reason: string }
  | { status: 'auth_unavailable'; reason: string }
  | { status: 'status_unavailable'; reason: string }
  | { status: 'budget_unknown'; reason: string }
  | { status: 'policy_blocked'; reason: string };

export type PreparedTransactionOperation<TLane extends TransactionLane = TransactionLane> = {
  intent: TransactionSigningIntent;
  lane: TLane;
  readiness: TransactionReadiness;
};

export type TransactionBudgetAdmission = {
  budgetIdentity: SigningSessionPreparedBudgetIdentity;
};

export type BudgetAdmittedOperation<TLane extends TransactionLane = TransactionLane> =
  PreparedTransactionOperation<TLane> & {
    budgetAdmission: TransactionBudgetAdmission;
  };

export type SignedTransactionOperation<TLane extends TransactionLane = TransactionLane> =
  BudgetAdmittedOperation<TLane> & {
    result: unknown;
  };

export type TransactionLaneSelectionFailure =
  | { kind: 'unsupported_intent'; curve: string; chain: string }
  | { kind: 'no_candidate'; authMethod?: SigningAuthMethod }
  | { kind: 'ambiguous_candidates'; allowedAuthMethods: readonly SigningAuthMethod[] }
  | { kind: 'incomplete_candidate'; missing: readonly string[] }
  | { kind: 'policy_blocked'; reason: string };

export type NearEd25519ConcreteSnapshotLane = SigningSessionSnapshotEd25519Lane &
  ConcreteSigningSessionSnapshotLane & {
    curve: 'ed25519';
    chain: 'near';
  };

export type EvmFamilyEcdsaConcreteSnapshotLane = SigningSessionSnapshotEcdsaLane &
  ConcreteSigningSessionSnapshotLane & {
    curve: 'ecdsa';
    chain: 'tempo' | 'evm';
  };

export type TransactionConcreteSnapshotLane =
  | NearEd25519ConcreteSnapshotLane
  | EvmFamilyEcdsaConcreteSnapshotLane;

export type TransactionLaneSelectionResult =
  | {
      ok: true;
      lane: TransactionLane;
      snapshotLane: TransactionConcreteSnapshotLane;
    }
  | { ok: false; failure: TransactionLaneSelectionFailure };

export type TransactionIntentReceivedState = {
  tag: 'IntentReceived';
  intent: TransactionSigningIntent;
};

export type TransactionSnapshotReadState = {
  tag: 'SnapshotRead';
  intent: TransactionSigningIntent;
  snapshot: SigningSessionSnapshot | null;
  currentRuntimeLane?: SigningSessionSnapshotEd25519Lane | SigningSessionSnapshotEcdsaLane | null;
};

export type TransactionLaneSelectedState<
  TLane extends TransactionLane = TransactionLane,
  TSnapshotLane extends TransactionConcreteSnapshotLane = TransactionConcreteSnapshotLane,
> = {
  tag: 'LaneSelected';
  intent: TransactionSigningIntent;
  lane: TLane;
  snapshotLane: TSnapshotLane;
};

export type TransactionLaneSelectionFailedState = {
  tag: 'LaneSelectionFailed';
  intent: TransactionSigningIntent;
  failure: TransactionLaneSelectionFailure;
};

export type TransactionExactRestoreAttemptedState<
  TLane extends TransactionLane = TransactionLane,
  TSnapshotLane extends TransactionConcreteSnapshotLane = TransactionConcreteSnapshotLane,
> = {
  tag: 'ExactRestoreAttempted';
  intent: TransactionSigningIntent;
  lane: TLane;
  snapshotLane: TSnapshotLane;
  restored: boolean;
  failureReason?: string;
};

export type TransactionReadinessClassifiedState<
  TLane extends TransactionLane = TransactionLane,
> = {
  tag: 'ReadinessClassified';
  intent: TransactionSigningIntent;
  lane: TLane;
  snapshotLane: TransactionConcreteSnapshotLane;
  readiness: TransactionReadiness;
};

export type TransactionAuthPlannedState<TLane extends TransactionLane = TransactionLane> = {
  tag: 'AuthPlanned';
  operation: PreparedTransactionOperation<TLane>;
  authPlan: unknown;
};

export type TransactionBudgetAdmittedState<TLane extends TransactionLane = TransactionLane> = {
  tag: 'BudgetAdmitted';
  operation: BudgetAdmittedOperation<TLane>;
};

export type TransactionSignedState<TLane extends TransactionLane = TransactionLane> = {
  tag: 'Signed';
  operation: SignedTransactionOperation<TLane>;
};

export type TransactionSigningState =
  | TransactionIntentReceivedState
  | TransactionSnapshotReadState
  | TransactionLaneSelectedState
  | TransactionLaneSelectionFailedState
  | TransactionExactRestoreAttemptedState
  | TransactionReadinessClassifiedState
  | TransactionAuthPlannedState
  | TransactionBudgetAdmittedState
  | TransactionSignedState;

export type SelectTransactionLaneInput = {
  intent: TransactionSigningIntent;
  snapshot: SigningSessionSnapshot | null;
  currentRuntimeLane?: SigningSessionSnapshotEd25519Lane | SigningSessionSnapshotEcdsaLane | null;
};

export function receiveTransactionIntent(
  intent: TransactionSigningIntent,
): TransactionIntentReceivedState {
  return { tag: 'IntentReceived', intent };
}

export function recordTransactionSnapshot(
  state: TransactionIntentReceivedState,
  args: {
    snapshot: SigningSessionSnapshot | null;
    currentRuntimeLane?: SigningSessionSnapshotEd25519Lane | SigningSessionSnapshotEcdsaLane | null;
  },
): TransactionSnapshotReadState {
  return {
    tag: 'SnapshotRead',
    intent: state.intent,
    snapshot: args.snapshot,
    ...(args.currentRuntimeLane !== undefined
      ? { currentRuntimeLane: args.currentRuntimeLane }
      : {}),
  };
}

function isConcreteNearEd25519Lane(
  lane: SigningSessionSnapshotEd25519Lane | null | undefined,
): lane is NearEd25519ConcreteSnapshotLane {
  return (
    Boolean(lane) &&
    lane!.curve === 'ed25519' &&
    lane!.chain === 'near' &&
    isConcreteSigningSessionSnapshotLane(lane!)
  );
}

function isConcreteEvmFamilyEcdsaLane(
  lane: SigningSessionSnapshotEcdsaLane | null | undefined,
): lane is EvmFamilyEcdsaConcreteSnapshotLane {
  return (
    Boolean(lane) &&
    lane!.curve === 'ecdsa' &&
    (lane!.chain === 'tempo' || lane!.chain === 'evm') &&
    isConcreteSigningSessionSnapshotLane(lane!)
  );
}

function missingConcreteFields(
  lane: SigningSessionSnapshotEd25519Lane | SigningSessionSnapshotEcdsaLane | null | undefined,
): string[] {
  if (!lane) return ['lane'];
  const missing: string[] = [];
  if (lane.authMethod !== 'email_otp' && lane.authMethod !== 'passkey') {
    missing.push('authMethod');
  }
  if (!String(lane.walletSigningSessionId || '').trim()) {
    missing.push('walletSigningSessionId');
  }
  if (!String(lane.thresholdSessionId || '').trim()) {
    missing.push('thresholdSessionId');
  }
  return missing;
}

function buildNearEd25519TransactionLane(args: {
  walletId: AccountId | string;
  lane: NearEd25519ConcreteSnapshotLane;
}): NearEd25519TransactionLane {
  return {
    accountId: toAccountId(args.walletId),
    authMethod: args.lane.authMethod,
    curve: 'ed25519',
    chain: 'near',
    walletSigningSessionId: SigningSessionIds.walletSigningSession(
      args.lane.walletSigningSessionId,
    ),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
      args.lane.thresholdSessionId,
    ),
  };
}

function buildEvmFamilyEcdsaTransactionLane(args: {
  walletId: AccountId | string;
  lane: EvmFamilyEcdsaConcreteSnapshotLane;
}): EvmFamilyEcdsaTransactionLane {
  return {
    accountId: toAccountId(args.walletId),
    authMethod: args.lane.authMethod,
    curve: 'ecdsa',
    chain: args.lane.chain,
    walletSigningSessionId: SigningSessionIds.walletSigningSession(
      args.lane.walletSigningSessionId,
    ),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(
      args.lane.thresholdSessionId,
    ),
  };
}

function allowedAuthMethods(
  candidates: readonly TransactionConcreteSnapshotLane[],
): SigningAuthMethod[] {
  return [...new Set(candidates.map((candidate) => candidate.authMethod))].sort();
}

export function selectTransactionLane(
  input: SelectTransactionLaneInput,
): TransactionLaneSelectionResult {
  const intent = input.intent;
  if (intent.curve === 'ed25519' && intent.chain === 'near') {
    return selectNearEd25519TransactionLane(input);
  }
  if (
    intent.curve === 'ecdsa' &&
    (intent.chain === 'tempo' || intent.chain === 'evm')
  ) {
    return selectEvmFamilyEcdsaTransactionLane(input);
  }
  return {
    ok: false,
    failure: {
      kind: 'unsupported_intent',
      curve: intent.curve,
      chain: intent.chain,
    },
  };
}

function selectNearEd25519TransactionLane(
  input: SelectTransactionLaneInput,
): TransactionLaneSelectionResult {
  const intent = input.intent;
  const runtimeLane = input.currentRuntimeLane || null;
  if (runtimeLane && !isConcreteNearEd25519Lane(runtimeLane as SigningSessionSnapshotEd25519Lane)) {
    return {
      ok: false,
      failure: {
        kind: 'incomplete_candidate',
        missing: missingConcreteFields(runtimeLane),
      },
    };
  }

  const nearRuntimeLane = runtimeLane as NearEd25519ConcreteSnapshotLane | null;

  // Current-lane and account-class policy are hints below a verified runtime
  // lane. Only an explicit user choice may reject a different hot lane.
  if (nearRuntimeLane) {
    if (
      intent.authSelectionPolicy.kind === 'explicit' &&
      nearRuntimeLane.authMethod !== intent.authSelectionPolicy.authMethod
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
      lane: buildNearEd25519TransactionLane({
        walletId: intent.walletId,
        lane: nearRuntimeLane,
      }),
      snapshotLane: nearRuntimeLane,
    };
  }

  const concreteCandidates =
    input.snapshot?.candidates?.ed25519?.near?.filter(isConcreteNearEd25519Lane) || [];
  return selectConcreteTransactionCandidate({
    intent,
    candidates: concreteCandidates,
    buildLane: (lane) =>
      buildNearEd25519TransactionLane({
        walletId: intent.walletId,
        lane,
      }),
  });
}

function selectEvmFamilyEcdsaTransactionLane(
  input: SelectTransactionLaneInput,
): TransactionLaneSelectionResult {
  const intent = input.intent;
  const runtimeLane = input.currentRuntimeLane || null;
  if (runtimeLane && !isConcreteEvmFamilyEcdsaLane(runtimeLane as SigningSessionSnapshotEcdsaLane)) {
    return {
      ok: false,
      failure: {
        kind: 'incomplete_candidate',
        missing: missingConcreteFields(runtimeLane),
      },
    };
  }

  const ecdsaRuntimeLane = runtimeLane as EvmFamilyEcdsaConcreteSnapshotLane | null;
  if (ecdsaRuntimeLane) {
    if (
      intent.authSelectionPolicy.kind === 'explicit' &&
      ecdsaRuntimeLane.authMethod !== intent.authSelectionPolicy.authMethod
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
      lane: buildEvmFamilyEcdsaTransactionLane({
        walletId: intent.walletId,
        lane: ecdsaRuntimeLane,
      }),
      snapshotLane: ecdsaRuntimeLane,
    };
  }

  const chain = intent.chain === 'tempo' || intent.chain === 'evm' ? intent.chain : 'evm';
  const concreteCandidates =
    input.snapshot?.candidates?.ecdsa?.[chain]?.filter(isConcreteEvmFamilyEcdsaLane) || [];
  return selectConcreteTransactionCandidate({
    intent,
    candidates: concreteCandidates,
    buildLane: (lane) =>
      buildEvmFamilyEcdsaTransactionLane({
        walletId: intent.walletId,
        lane,
      }),
  });
}

function selectConcreteTransactionCandidate<
  TSnapshotLane extends TransactionConcreteSnapshotLane,
  TLane extends TransactionLane,
>(args: {
  intent: TransactionSigningIntent;
  candidates: readonly TSnapshotLane[];
  buildLane: (lane: TSnapshotLane) => TLane;
}): TransactionLaneSelectionResult {
  const { intent } = args;
  const policyAuthMethod = intent.authSelectionPolicy.authMethod;
  const candidates = args.candidates
    .filter((candidate) => candidate.authMethod === policyAuthMethod)
    .sort((left, right) => compareSnapshotCandidates(left, right, policyAuthMethod));

  if (!candidates.length) {
    return {
      ok: false,
      failure: { kind: 'no_candidate', authMethod: policyAuthMethod },
    };
  }
  const authMethods = allowedAuthMethods(candidates);
  if (authMethods.length > 1) {
    return {
      ok: false,
      failure: { kind: 'ambiguous_candidates', allowedAuthMethods: authMethods },
    };
  }

  const selected = candidates[0];
  if (!selected) {
    return {
      ok: false,
      failure: { kind: 'no_candidate', authMethod: policyAuthMethod },
    };
  }
  return {
    ok: true,
    lane: args.buildLane(selected),
    snapshotLane: selected,
  };
}

export function selectTransactionLaneFromSnapshot(
  state: TransactionSnapshotReadState,
): TransactionLaneSelectedState | TransactionLaneSelectionFailedState {
  const selection = selectTransactionLane({
    intent: state.intent,
    snapshot: state.snapshot,
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
    snapshotLane: selection.snapshotLane,
  };
}

export function recordExactRestoreAttempt<
  TLane extends TransactionLane,
  TSnapshotLane extends TransactionConcreteSnapshotLane,
>(
  state: TransactionLaneSelectedState<TLane, TSnapshotLane>,
  result: { restored: boolean; failureReason?: string },
): TransactionExactRestoreAttemptedState<TLane, TSnapshotLane> {
  return {
    tag: 'ExactRestoreAttempted',
    intent: state.intent,
    lane: state.lane,
    snapshotLane: state.snapshotLane,
    restored: result.restored,
    ...(result.failureReason ? { failureReason: result.failureReason } : {}),
  };
}

export function classifyTransactionReadiness<TLane extends TransactionLane>(
  state:
    | TransactionLaneSelectedState<TLane>
    | TransactionExactRestoreAttemptedState<TLane>,
  readiness: TransactionReadiness,
): TransactionReadinessClassifiedState<TLane> {
  return {
    tag: 'ReadinessClassified',
    intent: state.intent,
    lane: state.lane,
    snapshotLane: state.snapshotLane,
    readiness,
  };
}

export function prepareTransactionOperationFromReadiness<TLane extends TransactionLane>(
  state: TransactionReadinessClassifiedState<TLane>,
): PreparedTransactionOperation<TLane> {
  return {
    intent: state.intent,
    lane: state.lane,
    readiness: state.readiness,
  };
}

export function replacePreparedTransactionLane<TLane extends TransactionLane>(
  operation: PreparedTransactionOperation<TLane>,
  args: {
    lane: TLane;
    readiness: TransactionReadiness;
  },
): PreparedTransactionOperation<TLane> {
  return {
    intent: operation.intent,
    lane: args.lane,
    readiness: args.readiness,
  };
}

export function admitTransactionBudget<TLane extends TransactionLane>(
  operation: PreparedTransactionOperation<TLane>,
  budgetAdmission: TransactionBudgetAdmission,
): BudgetAdmittedOperation<TLane> {
  return {
    ...operation,
    budgetAdmission,
  };
}

export function recordTransactionBudgetAdmission<TLane extends TransactionLane>(
  operation: BudgetAdmittedOperation<TLane>,
): TransactionBudgetAdmittedState<TLane> {
  return {
    tag: 'BudgetAdmitted',
    operation,
  };
}

export function recordTransactionSigned<TLane extends TransactionLane>(
  operation: BudgetAdmittedOperation<TLane>,
  result: unknown,
): SignedTransactionOperation<TLane> {
  return {
    ...operation,
    result,
  };
}
