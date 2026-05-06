import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type {
  ConcreteSigningSessionSnapshotLane,
  SigningSessionSnapshot,
  SigningSessionSnapshotConcreteEcdsaLane,
  SigningSessionSnapshotEcdsaLane,
  SigningSessionSnapshotEd25519Lane,
} from '../snapshotReader';
import {
  ecdsaSnapshotCandidatesForTarget,
  isConcreteSigningSessionSnapshotLane,
} from '../snapshotReader';
import {
  SigningSessionIds,
  type SigningAuthMethod,
  type SigningChainFamily,
  type SigningCurve,
  type SigningLaneContext,
  type SigningOperationContext,
  type SigningOperationId,
  type SelectedSigningLaneContext,
  SigningSessionPlanKind,
  type ThresholdEcdsaSessionId,
  type ThresholdEd25519SessionId,
  type WalletSigningSessionId,
} from './types';
import type { SigningSessionPreparedBudgetIdentity } from './budget';
import type { SigningPlannerDecisionTraceEvent } from './planner';
import {
  prepareThresholdSigningOperation,
  type PreparedThresholdSigningOperation,
  type ThresholdSigningLifecycleAdapter,
  type ThresholdSigningOperationCoordinator,
  type ThresholdSigningReadinessInput,
} from './preparedOperation';
import {
  buildEvmTransactionSigningLane,
  buildNearTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from './lanes';
import type {
  EvmEip155ChainTarget,
  TempoChainTarget,
  ThresholdEcdsaChainTarget,
  WalletSubjectId,
} from './ecdsaChainTarget';
import { thresholdEcdsaChainTargetsEqual } from './ecdsaChainTarget';

type TransactionSigningIntentBase = {
  operationId?: SigningOperationId;
  walletId: AccountId | string;
  authSelectionPolicy: TransactionAuthSelectionPolicy;
  operationUsesNeeded: number;
};

export type NearEd25519TransactionSigningIntent = TransactionSigningIntentBase & {
  curve: 'ed25519';
  chain: 'near';
};

export type EvmFamilyEcdsaTransactionSigningIntent =
  | (TransactionSigningIntentBase & {
      curve: 'ecdsa';
      chain: 'tempo';
      chainTarget: TempoChainTarget;
    })
  | (TransactionSigningIntentBase & {
      curve: 'ecdsa';
      chain: 'evm';
      chainTarget: EvmEip155ChainTarget;
    });

export type TransactionSigningIntent =
  | NearEd25519TransactionSigningIntent
  | EvmFamilyEcdsaTransactionSigningIntent;

export type TransactionAuthSelectionPolicy =
  | { kind: 'explicit'; authMethod: SigningAuthMethod }
  | { kind: 'account_class'; authMethod: SigningAuthMethod };

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
  subjectId: WalletSubjectId;
  authMethod: SigningAuthMethod;
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
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

export type BudgetAdmittedTransactionOperation<
  TLane extends TransactionLane = TransactionLane,
  TAuthPlan = unknown,
> = BudgetAdmittedOperation<TLane> & {
  authPlan: TAuthPlan;
};

export type SignedTransactionOperation<
  TLane extends TransactionLane = TransactionLane,
  TResult = unknown,
> =
  BudgetAdmittedOperation<TLane> & {
    result: TResult;
  };

export type PreparedTransactionBudgetState<TLane extends TransactionLane = TransactionLane> =
  | {
      kind: 'admitted';
      operation: BudgetAdmittedOperation<TLane>;
      state: TransactionBudgetAdmittedState<TLane>;
    }
  | {
      kind: 'not_admitted';
      reason: 'budget_identity_not_prepared';
    };

export type TransactionSigningExecutor<TLane extends TransactionLane, TPayload, TResult> = {
  sign(operation: BudgetAdmittedOperation<TLane>, payload: TPayload): Promise<TResult>;
};

export type SignedTransactionFinalizer<TLane extends TransactionLane, TResult> = {
  recordSuccess?: (
    operation: SignedTransactionOperation<TLane, TResult>,
  ) => Promise<void> | void;
  cleanup?: (operation: SignedTransactionOperation<TLane, TResult>) => Promise<void> | void;
};

export type TransactionSigningLifecycleAdapter<
  TLane extends TransactionLane,
  TSigningLane extends SigningLaneContext,
  TMetadata extends object = Record<string, never>,
> = {
  prepare(input: {
    intent: TransactionSigningIntent;
    operation?: SigningOperationContext;
  }): Promise<{
    lane: TSigningLane;
    transactionLane: TLane;
    transactionIntent?: TransactionSigningIntent;
    readiness: ThresholdSigningReadinessInput;
    snapshotGeneration?: number;
    forceFreshAuth?: boolean;
    metadata?: TMetadata;
  }>;
};

export type TransactionPreparedThresholdMetadata<
  TLane extends TransactionLane,
  TMetadata extends object = Record<string, never>,
> = TMetadata & {
  transactionLane: TLane;
  transactionOperation: PreparedTransactionOperation<TLane>;
};

export type PreparedTransactionSigningOperation<
  TLane extends TransactionLane,
  TSigningLane extends SigningLaneContext,
  TMetadata extends object = Record<string, never>,
> = {
  thresholdOperation: PreparedThresholdSigningOperation<
    TSigningLane,
    TransactionPreparedThresholdMetadata<TLane, TMetadata>
  >;
  transactionOperation: PreparedTransactionOperation<TLane>;
  budget: PreparedTransactionBudgetState<TLane>;
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

export type EvmFamilyEcdsaConcreteSnapshotLane = SigningSessionSnapshotConcreteEcdsaLane;

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
    Boolean(lane!.chainTarget) &&
    isConcreteSigningSessionSnapshotLane(lane!)
  );
}

function missingConcreteFields(
  lane: SigningSessionSnapshotEd25519Lane | SigningSessionSnapshotEcdsaLane | null | undefined,
): string[] {
  if (!lane) return ['lane'];
  const missing: string[] = [];
  if (!('authMethod' in lane) || (lane.authMethod !== 'email_otp' && lane.authMethod !== 'passkey')) {
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
  intent: EvmFamilyEcdsaTransactionSigningIntent;
  lane: EvmFamilyEcdsaConcreteSnapshotLane;
}): EvmFamilyEcdsaTransactionLane {
  if (!thresholdEcdsaChainTargetsEqual(args.lane.chainTarget, args.intent.chainTarget)) {
    throw new Error('[SigningSessionTransactionState] ECDSA snapshot lane target mismatch');
  }
  return {
    accountId: toAccountId(args.walletId),
    subjectId: args.lane.subjectId,
    authMethod: args.lane.authMethod,
    curve: 'ecdsa',
    chainTarget: args.intent.chainTarget,
    ecdsaThresholdKeyId: args.lane.ecdsaThresholdKeyId,
    signingRootId: args.lane.signingRootId,
    signingRootVersion: args.lane.signingRootVersion,
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

function candidateStatePriority(candidate: TransactionConcreteSnapshotLane): number {
  switch (candidate.state) {
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
    default:
      return 1;
  }
}

function candidateSourcePriority(candidate: TransactionConcreteSnapshotLane): number {
  switch (candidate.source) {
    case 'runtime_and_durable':
      return 3;
    case 'runtime_session_record':
      return 2;
    case 'durable_sealed_record':
      return 1;
    default:
      return 0;
  }
}

function candidateUpdatedAtMs(candidate: TransactionConcreteSnapshotLane): number | null {
  const value = Math.floor(Number(candidate.updatedAtMs));
  return Number.isFinite(value) && value > 0 ? value : null;
}

function candidatesWithBestPriority<TSnapshotLane extends TransactionConcreteSnapshotLane>(
  candidates: readonly TSnapshotLane[],
  priority: (candidate: TSnapshotLane) => number,
): TSnapshotLane[] {
  let bestPriority = -Infinity;
  let bestCandidates: TSnapshotLane[] = [];
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

function selectNewestCandidateWhenUnambiguous<
  TSnapshotLane extends TransactionConcreteSnapshotLane,
>(candidates: readonly TSnapshotLane[]): TSnapshotLane | null {
  let selected: TSnapshotLane | null = null;
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

function selectBestConcreteTransactionCandidate<
  TSnapshotLane extends TransactionConcreteSnapshotLane,
>(candidates: readonly TSnapshotLane[]): TSnapshotLane | null {
  const bestStateCandidates = candidatesWithBestPriority(candidates, candidateStatePriority);
  if (bestStateCandidates.length <= 1) return bestStateCandidates[0] || null;

  const bestSourceCandidates = candidatesWithBestPriority(
    bestStateCandidates,
    candidateSourcePriority,
  );
  if (bestSourceCandidates.length <= 1) return bestSourceCandidates[0] || null;

  // When multiple same-auth lanes remain, updatedAtMs is the only ordering
  // policy with meaning. Without a unique newest lane the caller must surface
  // ambiguity instead of picking by opaque session ids.
  return selectNewestCandidateWhenUnambiguous(bestSourceCandidates);
}

export function selectTransactionLane(
  input: SelectTransactionLaneInput,
): TransactionLaneSelectionResult {
  const intent = input.intent;
  if (intent.curve === 'ed25519' && intent.chain === 'near') {
    return selectNearEd25519TransactionLane(input);
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

  // Runtime lanes are accepted only after snapshot construction has produced a
  // concrete candidate. Account metadata cannot create or override this anchor.
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
  input: SelectTransactionLaneInput & { intent: EvmFamilyEcdsaTransactionSigningIntent },
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
        intent,
        lane: ecdsaRuntimeLane,
      }),
      snapshotLane: ecdsaRuntimeLane,
    };
  }

  const concreteCandidates =
    input.snapshot
      ? ecdsaSnapshotCandidatesForTarget(input.snapshot, intent.chainTarget).filter(
          isConcreteEvmFamilyEcdsaLane,
        )
      : [];
  return selectConcreteTransactionCandidate({
    intent,
    candidates: concreteCandidates,
    buildLane: (lane) =>
      buildEvmFamilyEcdsaTransactionLane({
        walletId: intent.walletId,
        intent,
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
  const candidates = args.candidates.filter(
    (candidate) => candidate.authMethod === policyAuthMethod,
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

export function recordPreparedTransactionBudgetAdmission<TLane extends TransactionLane>(
  operation: BudgetAdmittedOperation<TLane>,
): PreparedTransactionBudgetState<TLane> {
  return {
    kind: 'admitted',
    operation,
    state: recordTransactionBudgetAdmission(operation),
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

export async function signPreparedTransactionOperation<
  TLane extends TransactionLane,
  TPayload,
  TResult,
>(
  operation: BudgetAdmittedOperation<TLane>,
  payload: TPayload,
  executor: TransactionSigningExecutor<TLane, TPayload, TResult>,
): Promise<SignedTransactionOperation<TLane, TResult>> {
  return recordTransactionSigned(
    operation,
    await executor.sign(operation, payload),
  ) as SignedTransactionOperation<TLane, TResult>;
}

export async function finalizeSignedTransactionOperation<
  TLane extends TransactionLane,
  TResult,
>(
  operation: SignedTransactionOperation<TLane, TResult>,
  finalizer: SignedTransactionFinalizer<TLane, TResult>,
): Promise<void> {
  if (
    typeof finalizer.recordSuccess !== 'function' &&
    typeof finalizer.cleanup !== 'function'
  ) {
    throw new Error('[SigningSession] signed transaction finalization requires a real finalizer');
  }
  await finalizer.recordSuccess?.(operation);
  await finalizer.cleanup?.(operation);
}

export async function prepareTransactionSigningOperation<
  TLane extends TransactionLane,
  TSigningLane extends SigningLaneContext,
  TMetadata extends object = Record<string, never>,
>(args: {
  intent: TransactionSigningIntent;
  lifecycleAdapter: TransactionSigningLifecycleAdapter<TLane, TSigningLane, TMetadata>;
  coordinator: ThresholdSigningOperationCoordinator;
  operation?: SigningOperationContext;
  forceFreshAuth?: boolean;
  sensitiveOperationPolicy?: SensitiveOperationPolicy | null;
  missingWhenExpiresAtMissing?: boolean;
  prepareBudgetIdentity?: boolean;
  onPlannerTrace?: (event: SigningPlannerDecisionTraceEvent) => void;
}): Promise<PreparedTransactionSigningOperation<TLane, TSigningLane, TMetadata>> {
  let transactionLane: TLane | null = null;
  let transactionIntent: TransactionSigningIntent | null = null;
  let transactionOperation: PreparedTransactionOperation<TLane> | null = null;

  const thresholdLifecycleAdapter: ThresholdSigningLifecycleAdapter<
    TSigningLane,
    TransactionPreparedThresholdMetadata<TLane, TMetadata>
  > = {
    prepare: async (input) => {
      const lifecycle = await args.lifecycleAdapter.prepare({
        intent: args.intent,
        ...(input.operation ? { operation: input.operation } : {}),
      });
      transactionLane = lifecycle.transactionLane;
      transactionIntent = lifecycle.transactionIntent || args.intent;
      return {
        lane: lifecycle.lane,
        readiness: lifecycle.readiness,
        snapshotGeneration: lifecycle.snapshotGeneration,
        forceFreshAuth: lifecycle.forceFreshAuth,
        metadata: {
          ...(lifecycle.metadata || ({} as TMetadata)),
          transactionLane: lifecycle.transactionLane,
          // Filled after the threshold planner has normalized readiness below.
          transactionOperation: null as unknown as PreparedTransactionOperation<TLane>,
        },
      };
    },
  };

  const thresholdOperation = await prepareThresholdSigningOperation({
    intent: thresholdIntentFromTransactionIntent(args.intent),
    lifecycleAdapter: thresholdLifecycleAdapter,
    coordinator: args.coordinator,
    ...(args.operation ? { operation: args.operation } : {}),
    forceFreshAuth: args.forceFreshAuth,
    sensitiveOperationPolicy: args.sensitiveOperationPolicy,
    missingWhenExpiresAtMissing: args.missingWhenExpiresAtMissing,
    onPlannerTrace: args.onPlannerTrace,
  });

  if (!transactionLane) {
    throw new Error('[SigningSession] transaction prepare did not return a transaction lane');
  }
  transactionOperation = {
    intent: transactionIntent || args.intent,
    lane: transactionLane,
    readiness: transactionReadinessFromThresholdOperation(thresholdOperation),
  };
  thresholdOperation.metadata.transactionOperation = transactionOperation;

  const budgetIdentity =
    args.prepareBudgetIdentity &&
    thresholdOperation.signingSessionPlan.kind === SigningSessionPlanKind.WarmSession
      ? await args.coordinator.prepareBudgetIdentity({
          nearAccountId: String(args.intent.walletId),
          lane: thresholdOperation.lane,
          operationUsesNeeded: args.intent.operationUsesNeeded,
        })
      : undefined;

  const budget = budgetIdentity
    ? recordPreparedTransactionBudgetAdmission(
        admitTransactionBudget(transactionOperation, {
          budgetIdentity,
        }),
      )
    : ({
        kind: 'not_admitted',
        reason: 'budget_identity_not_prepared',
      } satisfies PreparedTransactionBudgetState<TLane>);

  return {
    thresholdOperation,
    transactionOperation,
    budget,
  };
}

function thresholdIntentFromTransactionIntent(intent: TransactionSigningIntent): {
  kind: 'transaction_sign';
  chain: SigningChainFamily;
  curve: SigningCurve;
  walletId: string;
  reason: 'transaction';
} {
  return {
    kind: 'transaction_sign',
    chain: intent.chain,
    curve: intent.curve,
    walletId: String(intent.walletId),
    reason: 'transaction',
  };
}

export function transactionReadinessFromThresholdOperation(
  operation: PreparedThresholdSigningOperation<SigningLaneContext, object>,
): TransactionReadiness {
  const status = operation.readiness.status;
  if (status === 'ready') {
    return {
      status: 'ready',
      remainingUses: Math.max(0, Math.floor(Number(operation.remainingUses) || 0)),
      expiresAtMs: Math.max(0, Math.floor(Number(operation.expiresAtMs) || 0)),
    };
  }
  if (status === 'missing_session') return { status: 'missing_hot_material' };
  if (status === 'expired') return { status: 'expired' };
  if (status === 'exhausted') return { status: 'exhausted' };
  if (status === 'auth_unavailable') {
    return { status: 'auth_unavailable', reason: 'auth_unavailable' };
  }
  if (status === 'status_unavailable') {
    return { status: 'status_unavailable', reason: 'status_unavailable' };
  }
  if (status === 'budget_unknown') {
    return { status: 'budget_unknown', reason: 'budget_unknown' };
  }
  return { status: 'policy_blocked', reason: status };
}

export function selectedSigningLaneContextFromTransactionLane(
  lane: TransactionLane,
): SelectedSigningLaneContext {
  // Transaction lanes intentionally carry only exact signing identity. Budget
  // tracing still expects the older lane shape, so the adapter fills stable
  // non-authoritative metadata without changing wallet/threshold identity.
  if (lane.curve === 'ed25519') {
    const signingLane = buildNearTransactionSigningLane(
      lane.authMethod === 'email_otp'
        ? {
            accountId: lane.accountId,
            authMethod: 'email_otp',
            walletSigningSessionId: lane.walletSigningSessionId,
            thresholdSessionId: lane.thresholdSessionId,
            retention: 'session',
            sessionOrigin: 'per_operation',
          }
        : {
            accountId: lane.accountId,
            authMethod: 'passkey',
            walletSigningSessionId: lane.walletSigningSessionId,
            thresholdSessionId: lane.thresholdSessionId,
            storageSource: 'bootstrap',
            retention: 'session',
            sessionOrigin: 'per_operation',
          },
    );
    return signingLane as SelectedSigningLaneContext;
  }

  const buildLane =
    lane.chainTarget.kind === 'tempo'
      ? buildTempoTransactionSigningLane
      : buildEvmTransactionSigningLane;
  const signingLane = buildLane(
    lane.authMethod === 'email_otp'
      ? {
          accountId: lane.accountId,
          authMethod: 'email_otp',
          chainTarget: lane.chainTarget,
          subjectId: lane.subjectId,
          ecdsaThresholdKeyId: lane.ecdsaThresholdKeyId,
          signingRootId: lane.signingRootId,
          signingRootVersion: lane.signingRootVersion,
          walletSigningSessionId: lane.walletSigningSessionId,
          thresholdSessionId: lane.thresholdSessionId,
          retention: 'session',
          sessionOrigin: 'per_operation',
        }
      : {
          accountId: lane.accountId,
          authMethod: 'passkey',
          chainTarget: lane.chainTarget,
          subjectId: lane.subjectId,
          ecdsaThresholdKeyId: lane.ecdsaThresholdKeyId,
          signingRootId: lane.signingRootId,
          signingRootVersion: lane.signingRootVersion,
          walletSigningSessionId: lane.walletSigningSessionId,
          thresholdSessionId: lane.thresholdSessionId,
          storageSource: 'manual-bootstrap',
          retention: 'session',
          sessionOrigin: 'per_operation',
        },
  );
  return {
    ...signingLane,
    chainTarget: lane.chainTarget,
    subjectId: lane.subjectId,
    ecdsaThresholdKeyId: lane.ecdsaThresholdKeyId,
    signingRootId: lane.signingRootId,
    signingRootVersion: lane.signingRootVersion,
  } as SelectedSigningLaneContext;
}
