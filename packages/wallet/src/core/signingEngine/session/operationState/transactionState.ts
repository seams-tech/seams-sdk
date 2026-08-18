import type { AccountId } from '@/core/types/accountIds';
import type { SignerSlot } from '@shared/utils/signerSlot';
import type { SensitiveOperationPolicy, SignerAuthMethod } from '@shared/utils/signerDomain';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  LaneCandidate,
  SelectedLane,
} from '../identity/laneIdentity';
import type {
  TransactionConcreteAvailableLane,
  TransactionIntentReceivedState,
  TransactionLaneSelectedState,
  TransactionLaneSelectionFailedState,
  TransactionAvailableLanesReadState,
} from '../identity/selectLane';
import {
  type SigningChainFamily,
  type SigningCurve,
  type SelectedSigningSessionPlanningLane,
  type SigningOperationContext,
  type SigningOperationId,
} from './types';
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
  | { kind: 'explicit'; authMethod: SignerAuthMethod }
  | { kind: 'account_class'; authMethod: SignerAuthMethod };

export type TransactionLane = SelectedLane;

export type TransactionReadiness =
  | { status: 'ready'; remainingUses: number; expiresAtMs: number }
  | { status: 'expired' }
  | { status: 'exhausted' }
  | { status: 'restore_failed'; reason: string }
  | { status: 'auth_unavailable'; reason: string }
  | { status: 'status_unavailable'; reason: string }
  | { status: 'status_unknown'; reason: string }
  | { status: 'policy_blocked'; reason: string };

export type PreparedTransactionOperation<TLane extends TransactionLane = TransactionLane> = {
  intent: TransactionSigningIntent;
  lane: TLane;
  readiness: TransactionReadiness;
};

export type SignedTransactionOperation<
  TLane extends TransactionLane = TransactionLane,
  TResult = unknown,
> = PreparedTransactionOperation<TLane> & {
  result: TResult;
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

  return {
    thresholdOperation,
    transactionOperation,
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

// Module-internal: the only caller is `prepareTransactionSigningOperation`
// above. Exporting it invited callers to derive transaction readiness outside
// the one place that owns the threshold operation it reads from.
function transactionReadinessFromThresholdOperation(
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
  if (status === 'missing_session') {
    return { status: 'status_unavailable', reason: 'missing_session' };
  }
  if (status === 'expired') return { status: 'expired' };
  if (status === 'exhausted') return { status: 'exhausted' };
  if (status === 'auth_unavailable') {
    return { status: 'auth_unavailable', reason: 'auth_unavailable' };
  }
  if (status === 'status_unavailable') {
    return { status: 'status_unavailable', reason: 'status_unavailable' };
  }
  if (status === 'status_unknown') {
    return { status: 'status_unknown', reason: 'status_unknown' };
  }
  return { status: 'policy_blocked', reason: status };
}
