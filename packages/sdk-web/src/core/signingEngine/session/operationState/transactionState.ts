import type { AccountId } from '@/core/types/accountIds';
import type { SignerSlot } from '@shared/utils/signerSlot';
import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  LaneCandidate,
  SelectedLane,
  ThresholdEcdsaSessionStoreSource,
  ThresholdEd25519SessionStoreSource,
} from '../identity/laneIdentity';
import type {
  TransactionConcreteAvailableLane,
  TransactionIntentReceivedState,
  TransactionLaneSelectedState,
  TransactionLaneSelectionFailedState,
  TransactionAvailableLanesReadState,
} from '../identity/selectLane';
import {
  type SigningAuthMethod,
  type SigningChainFamily,
  type SigningCurve,
  type SelectedSigningSessionPlanningLane,
  type SigningOperationContext,
  type SigningOperationId,
  SigningSessionPlanKind,
} from './types';
import type { SigningSessionPreparedBudgetIdentity } from '../budget/budget';
import type {
  ExactSigningLaneIdentity,
  ExactSigningLaneIdentityKey,
} from '../identity/exactSigningLaneIdentity';
import type {
  FreshStepUpSatisfiedForAdmission,
  FreshStepUpRequired,
  StepUpExpiryState,
  StepUpProjectionState,
} from './stepUpFreshness';
import { assertFreshnessMatchesLane } from './stepUpFreshness';
import { exactSigningLaneIdentityFromSelectedLane } from '../identity/exactSigningLaneIdentity';
import type { SigningPlannerDecisionTraceEvent } from '../planning/planner';
import {
  prepareThresholdSigningOperation,
  type PreparedThresholdSigningOperation,
  type ThresholdSigningLifecycleAdapter,
  type ThresholdSigningOperationCoordinator,
  type ThresholdSigningReadinessInput,
} from './preparedOperation';
import type {
  EvmEip155ChainTarget,
  TempoChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

type TransactionSigningIntentBase = {
  operationId?: SigningOperationId;
  authSelectionPolicy: TransactionAuthSelectionPolicy;
  operationUsesNeeded: number;
};

type NearEd25519TransactionSigningIntentBase = TransactionSigningIntentBase & {
  walletId: WalletId;
  signerSelection: NearEd25519TransactionSignerSelection;
};

type EvmFamilyEcdsaTransactionSigningIntentBase = TransactionSigningIntentBase & {
  walletId: WalletId;
};

export type NearEd25519TransactionSigningIntent = NearEd25519TransactionSigningIntentBase & {
  curve: 'ed25519';
  chain: 'near';
};

export type NearEd25519TransactionSignerSelection =
  | {
      kind: 'near_account';
      nearAccountId: AccountId;
      signerSlot?: never;
    }
  | {
      kind: 'signer_slot';
      nearAccountId: AccountId;
      signerSlot: SignerSlot;
    };

export type EvmFamilyEcdsaTransactionSigningIntent =
  | (EvmFamilyEcdsaTransactionSigningIntentBase & {
      curve: 'ecdsa';
      chain: 'tempo';
      chainTarget: TempoChainTarget;
    })
  | (EvmFamilyEcdsaTransactionSigningIntentBase & {
      curve: 'ecdsa';
      chain: 'evm';
      chainTarget: EvmEip155ChainTarget;
    });

export type TransactionSigningIntent =
  | NearEd25519TransactionSigningIntent
  | EvmFamilyEcdsaTransactionSigningIntent;

export type TransactionAuthSelectionPolicy =
  | { kind: 'any' }
  | { kind: 'explicit'; authMethod: SigningAuthMethod }
  | { kind: 'account_class'; authMethod: SigningAuthMethod };

export type TransactionLane = SelectedLane;

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
> = BudgetAdmittedOperation<TLane> & {
  result: TResult;
};

export type PreparedNoBudgetLifecycle<TLane extends TransactionLane = TransactionLane> = {
  kind: 'PreparedNoBudget';
  operation: PreparedTransactionOperation<TLane>;
  reason: 'budget_identity_not_prepared';
  state?: never;
  authPlan?: never;
  result?: never;
  finalizedAtMs?: never;
};

export type BudgetAdmittedLifecycle<TLane extends TransactionLane = TransactionLane> = {
  kind: 'BudgetAdmitted';
  operation: BudgetAdmittedOperation<TLane>;
  state: TransactionBudgetAdmittedState<TLane>;
  reason?: never;
  authPlan?: never;
  result?: never;
  finalizedAtMs?: never;
};

export type StepUpConfirmedLifecycle<
  TLane extends TransactionLane = TransactionLane,
  TAuthPlan = unknown,
> = {
  kind: 'StepUpConfirmed';
  operation: BudgetAdmittedTransactionOperation<TLane, TAuthPlan>;
  authPlan: TAuthPlan;
  reason?: never;
  state?: never;
  result?: never;
  finalizedAtMs?: never;
};

export type ReauthAdmittedLifecycle<
  TLane extends TransactionLane = TransactionLane,
  TAuthPlan = unknown,
> = {
  kind: 'ReauthAdmitted';
  reauthAnchor: ReauthAnchorIdentity;
  previousOperation: BudgetAdmittedOperation<TLane>;
  operation: BudgetAdmittedTransactionOperation<TLane, TAuthPlan>;
  authPlan: TAuthPlan;
  reason?: never;
  state?: never;
  result?: never;
  finalizedAtMs?: never;
};

export type ReauthAnchorSourceState = {
  kind: 'reauth_anchor_source_state';
  availabilitySource:
    | 'durable_sealed_record'
    | 'runtime_session_record'
    | 'evm_family_shared_key';
  storeSource: ThresholdEcdsaSessionStoreSource | ThresholdEd25519SessionStoreSource;
  retention: 'session' | 'single_use' | 'unknown';
  remainingUses: number | null;
  expiry: StepUpExpiryState;
  projection: StepUpProjectionState;
};

export type ReauthAnchorIdentity = {
  kind: 'reauth_anchor_identity';
  laneIdentity: ExactSigningLaneIdentity;
  laneIdentityKey: ExactSigningLaneIdentityKey;
  sourceState: ReauthAnchorSourceState;
  freshness: FreshStepUpRequired;
  readyLane?: never;
  budget?: never;
};

export type SignedWalletSigningBudgetLifecycle<
  TLane extends TransactionLane = TransactionLane,
  TResult = unknown,
> = {
  kind: 'Signed';
  operation: SignedTransactionOperation<TLane, TResult>;
  result: TResult;
  reason?: never;
  state?: never;
  authPlan?: never;
  finalizedAtMs?: never;
};

export type FinalizedWalletSigningBudgetLifecycle<
  TLane extends TransactionLane = TransactionLane,
  TResult = unknown,
> = {
  kind: 'Finalized';
  operation: SignedTransactionOperation<TLane, TResult>;
  result: TResult;
  finalizedAtMs: number;
  reason?: never;
  state?: never;
  authPlan?: never;
};

export type WalletSigningBudgetLifecycle<
  TLane extends TransactionLane = TransactionLane,
  TAuthPlan = unknown,
  TResult = unknown,
> =
  | PreparedNoBudgetLifecycle<TLane>
  | BudgetAdmittedLifecycle<TLane>
  | StepUpConfirmedLifecycle<TLane, TAuthPlan>
  | ReauthAdmittedLifecycle<TLane, TAuthPlan>
  | SignedWalletSigningBudgetLifecycle<TLane, TResult>
  | FinalizedWalletSigningBudgetLifecycle<TLane, TResult>;

export type PreparedTransactionBudgetState<TLane extends TransactionLane = TransactionLane> =
  | BudgetAdmittedLifecycle<TLane>
  | PreparedNoBudgetLifecycle<TLane>;

export type TransactionSigningExecutor<TLane extends TransactionLane, TPayload, TResult> = {
  sign(operation: BudgetAdmittedOperation<TLane>, payload: TPayload): Promise<TResult>;
};

export type SignedTransactionFinalizer<TLane extends TransactionLane, TResult> = {
  recordSuccess?: (operation: SignedTransactionOperation<TLane, TResult>) => Promise<void> | void;
  cleanup?: (operation: SignedTransactionOperation<TLane, TResult>) => Promise<void> | void;
};

export type TransactionSigningLifecycleAdapter<
  TLane extends TransactionLane,
  TSigningLane extends SelectedSigningSessionPlanningLane,
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
    availableLanesGeneration?: number;
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
  TSigningLane extends SelectedSigningSessionPlanningLane,
  TMetadata extends object = Record<string, never>,
> = {
  thresholdOperation: PreparedThresholdSigningOperation<
    TSigningLane,
    TransactionPreparedThresholdMetadata<TLane, TMetadata>
  >;
  transactionOperation: PreparedTransactionOperation<TLane>;
  budget: PreparedTransactionBudgetState<TLane>;
};

export type TransactionExactRestoreAttemptedState<
  TLane extends TransactionLane = TransactionLane,
  TAvailableLane extends TransactionConcreteAvailableLane = TransactionConcreteAvailableLane,
  TCandidate extends LaneCandidate = LaneCandidate,
> = {
  tag: 'ExactRestoreAttempted';
  intent: TransactionSigningIntent;
  lane: TLane;
  candidate: TCandidate;
  availableLane: TAvailableLane;
  restored: boolean;
  failureReason?: string;
};

export type TransactionReadinessClassifiedState<
  TLane extends TransactionLane = TransactionLane,
  TCandidate extends LaneCandidate = LaneCandidate,
> = {
  tag: 'ReadinessClassified';
  intent: TransactionSigningIntent;
  lane: TLane;
  candidate: TCandidate;
  availableLane: TransactionConcreteAvailableLane;
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
  | TransactionAvailableLanesReadState
  | TransactionLaneSelectedState
  | TransactionLaneSelectionFailedState
  | TransactionExactRestoreAttemptedState
  | TransactionReadinessClassifiedState
  | TransactionAuthPlannedState
  | TransactionBudgetAdmittedState
  | TransactionSignedState;

export function recordExactRestoreAttempt<
  TLane extends TransactionLane,
  TAvailableLane extends TransactionConcreteAvailableLane,
  TCandidate extends LaneCandidate,
>(
  state: TransactionLaneSelectedState<TLane, TAvailableLane, TCandidate>,
  result: { restored: boolean; failureReason?: string },
): TransactionExactRestoreAttemptedState<TLane, TAvailableLane, TCandidate> {
  return {
    tag: 'ExactRestoreAttempted',
    intent: state.intent,
    lane: state.lane,
    candidate: state.candidate,
    availableLane: state.availableLane,
    restored: result.restored,
    ...(result.failureReason ? { failureReason: result.failureReason } : {}),
  };
}

export function classifyTransactionReadiness<
  TLane extends TransactionLane,
  TAvailableLane extends TransactionConcreteAvailableLane,
  TCandidate extends LaneCandidate,
>(
  state:
    | TransactionLaneSelectedState<TLane, TAvailableLane, TCandidate>
    | TransactionExactRestoreAttemptedState<TLane, TAvailableLane, TCandidate>,
  readiness: TransactionReadiness,
): TransactionReadinessClassifiedState<TLane, TCandidate> {
  return {
    tag: 'ReadinessClassified',
    intent: state.intent,
    lane: state.lane,
    candidate: state.candidate,
    availableLane: state.availableLane,
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
    kind: 'BudgetAdmitted',
    operation,
    state: recordTransactionBudgetAdmission(operation),
  };
}

export function recordPreparedTransactionBudgetAdmissionFromFreshness<
  TLane extends TransactionLane,
>(
  operation: PreparedTransactionOperation<TLane>,
  budgetAdmission: TransactionBudgetAdmission,
  freshness: FreshStepUpSatisfiedForAdmission,
): BudgetAdmittedLifecycle<TLane> {
  assertFreshnessMatchesLane({
    freshness,
    laneIdentity: exactSigningLaneIdentityFromSelectedLane(operation.lane),
  });
  if (freshness.projection.version !== budgetAdmission.budgetIdentity.projectionVersion) {
    throw new Error('[SigningSession] admission freshness projection does not match budget');
  }
  const admittedOperation = admitTransactionBudget(operation, budgetAdmission);
  return {
    kind: 'BudgetAdmitted',
    operation: admittedOperation,
    state: recordTransactionBudgetAdmission(admittedOperation),
  };
}

export function recordPreparedTransactionNoBudget<TLane extends TransactionLane>(
  operation: PreparedTransactionOperation<TLane>,
  reason: PreparedNoBudgetLifecycle<TLane>['reason'],
): PreparedNoBudgetLifecycle<TLane> {
  return {
    kind: 'PreparedNoBudget',
    operation,
    reason,
  };
}

export function isPreparedTransactionBudgetAdmitted<TLane extends TransactionLane>(
  budget: PreparedTransactionBudgetState<TLane>,
): budget is BudgetAdmittedLifecycle<TLane> {
  return budget.kind === 'BudgetAdmitted';
}

export function recordTransactionStepUpConfirmed<TLane extends TransactionLane, TAuthPlan>(
  operation: BudgetAdmittedOperation<TLane>,
  authPlan: TAuthPlan,
): StepUpConfirmedLifecycle<TLane, TAuthPlan> {
  return {
    kind: 'StepUpConfirmed',
    operation: {
      ...operation,
      authPlan,
    },
    authPlan,
  };
}

export function recordTransactionReauthAdmitted<TLane extends TransactionLane, TAuthPlan>(
  reauthAnchor: ReauthAnchorIdentity,
  previousOperation: BudgetAdmittedOperation<TLane>,
  operation: BudgetAdmittedOperation<TLane>,
  authPlan: TAuthPlan,
): ReauthAdmittedLifecycle<TLane, TAuthPlan> {
  return {
    kind: 'ReauthAdmitted',
    reauthAnchor,
    previousOperation,
    operation: {
      ...operation,
      authPlan,
    },
    authPlan,
  };
}

export function buildReauthAnchorIdentity(args: {
  freshness: FreshStepUpRequired;
  sourceState: ReauthAnchorSourceState;
}): ReauthAnchorIdentity {
  if (args.freshness.kind !== 'fresh_step_up_required') {
    throw new Error('[SigningSession] reauth anchors require fresh-step-up-required state');
  }
  return {
    kind: 'reauth_anchor_identity',
    laneIdentity: args.freshness.laneIdentity,
    laneIdentityKey: args.freshness.laneIdentityKey,
    sourceState: args.sourceState,
    freshness: args.freshness,
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

export function recordSignedWalletSigningBudgetLifecycle<TLane extends TransactionLane, TResult>(
  operation: BudgetAdmittedOperation<TLane>,
  result: TResult,
): SignedWalletSigningBudgetLifecycle<TLane, TResult> {
  return {
    kind: 'Signed',
    operation: recordTransactionSigned(operation, result) as SignedTransactionOperation<
      TLane,
      TResult
    >,
    result,
  };
}

export function recordFinalizedWalletSigningBudgetLifecycle<TLane extends TransactionLane, TResult>(
  operation: SignedTransactionOperation<TLane, TResult>,
  finalizedAtMs: number,
): FinalizedWalletSigningBudgetLifecycle<TLane, TResult> {
  return {
    kind: 'Finalized',
    operation,
    result: operation.result,
    finalizedAtMs,
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

export async function finalizeSignedTransactionOperation<TLane extends TransactionLane, TResult>(
  operation: SignedTransactionOperation<TLane, TResult>,
  finalizer: SignedTransactionFinalizer<TLane, TResult>,
): Promise<void> {
  if (typeof finalizer.recordSuccess !== 'function' && typeof finalizer.cleanup !== 'function') {
    throw new Error('[SigningSession] signed transaction finalization requires a real finalizer');
  }
  await finalizer.recordSuccess?.(operation);
  await finalizer.cleanup?.(operation);
}

export async function prepareTransactionSigningOperation<
  TLane extends TransactionLane,
  TSigningLane extends SelectedSigningSessionPlanningLane,
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
        availableLanesGeneration: lifecycle.availableLanesGeneration,
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
          lane: thresholdOperation.lane,
          operationUsesNeeded: args.intent.operationUsesNeeded,
          ...(thresholdOperation.trustedStatusAuth
            ? { trustedStatusAuth: thresholdOperation.trustedStatusAuth }
            : {}),
        })
      : undefined;

  const budget = budgetIdentity
    ? recordPreparedTransactionBudgetAdmission(
        admitTransactionBudget(transactionOperation, {
          budgetIdentity,
        }),
      )
    : recordPreparedTransactionNoBudget(transactionOperation, 'budget_identity_not_prepared');

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
  operation: PreparedThresholdSigningOperation<SelectedSigningSessionPlanningLane, object>,
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
