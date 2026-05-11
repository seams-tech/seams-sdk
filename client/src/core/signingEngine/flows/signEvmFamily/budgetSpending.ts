import { createSigningSessionBudgetFinalizer } from '../../session/budget/budgetFinalizer';
import type {
  BudgetFinalizationSpend,
  SigningSessionBudgetReservation,
  SigningSessionBudgetStatusAuth,
  WalletBudgetSpend,
} from '../../session/budget/budget';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import {
  type SigningOperationFingerprint,
  type SigningOperationContext,
} from '../../session/operationState/types';
import type { BudgetAdmittedOperation } from '../../session/operationState/transactionState';
import type { SelectedEcdsaLane } from '../../session/identity/laneIdentity';
import type { ResolvedEvmFamilyEcdsaSigningLane } from './ecdsaLanes';
import { buildEcdsaSessionIdentity } from '../../session/warmCapabilities/ecdsaProvisionPlan';

export type EvmFamilyTransactionSigningOperationContext = SigningOperationContext & {
  operationFingerprint: SigningOperationFingerprint;
};

type EvmFamilyWalletSigningSessionBudgetArgs = {
  signingSessionCoordinator: SigningSessionCoordinator;
  nearAccountId: string;
  operation: EvmFamilyTransactionSigningOperationContext;
  admittedTransaction: BudgetAdmittedOperation<SelectedEcdsaLane>;
  finalizedSigningLane: ResolvedEvmFamilyEcdsaSigningLane;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  reserved?: boolean;
  error?: unknown;
};

function buildEvmFamilyBudgetFinalization(
  args: EvmFamilyWalletSigningSessionBudgetArgs,
): BudgetFinalizationSpend {
  const selectedTransactionLane = args.admittedTransaction.lane;
  const resolvedIdentity = buildEcdsaSessionIdentity(selectedTransactionLane);
  if (!resolvedIdentity.thresholdSessionId || !resolvedIdentity.walletSigningSessionId) {
    throw new Error(
      '[SigningEngine][ecdsa] budget finalizer requires an exact selected transaction lane',
    );
  }
  if (typeof args.error !== 'undefined') {
    return {
      kind: 'zero_spend',
      operationId: args.operation.operationId,
      lane: args.finalizedSigningLane,
      reason: 'signing_failed',
      error: args.error,
    };
  }
  const spend: WalletBudgetSpend = {
    operationId: args.operation.operationId,
    ...(args.operation.operationFingerprint
      ? { operationFingerprint: args.operation.operationFingerprint }
      : {}),
    nearAccountId: args.finalizedSigningLane.accountId,
    walletSigningSessionId: args.finalizedSigningLane.walletSigningSessionId,
    lane: args.finalizedSigningLane,
    thresholdSessionIds: [args.finalizedSigningLane.thresholdSessionId],
    backingMaterialSessionIds: [],
    uses: 1,
    reason: args.operation.intent,
  };
  if (args.reserved) {
    return {
      kind: 'reserved_success',
      spend,
      expectedBudgetProjectionVersion: args.admittedTransaction.budgetAdmission.budgetIdentity.projectionVersion,
      ...(args.trustedStatusAuth ? { trustedStatusAuth: args.trustedStatusAuth } : {}),
    };
  }
  return {
    kind: 'externally_consumed_success',
    spend,
    ...(args.trustedStatusAuth ? { trustedStatusAuth: args.trustedStatusAuth } : {}),
    alreadyConsumedThresholdSessionIds: [args.finalizedSigningLane.thresholdSessionId],
  };
}

function createEvmFamilyTransactionBudgetFinalizer(args: EvmFamilyWalletSigningSessionBudgetArgs) {
  const selectedTransactionLane = args.admittedTransaction.lane;
  const resolvedIdentity = buildEcdsaSessionIdentity(selectedTransactionLane);
  return {
    finalizer: createSigningSessionBudgetFinalizer({
      signingSessionBudget: args.signingSessionCoordinator,
      budgetIdentity: args.admittedTransaction.budgetAdmission.budgetIdentity,
      finalization: buildEvmFamilyBudgetFinalization(args),
      onRecordSuccessError: (error) => {
        console.warn('[SigningEngine][ecdsa] failed to update wallet signing-session budget', {
          nearAccountId: args.nearAccountId,
          chainTarget: selectedTransactionLane.chainTarget,
          walletSigningSessionId: resolvedIdentity.walletSigningSessionId,
          thresholdSessionId: resolvedIdentity.thresholdSessionId,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      },
      onRecordZeroSpendError: (error) => {
        console.warn('[SigningEngine][ecdsa] failed to record wallet signing-session zero spend', {
          nearAccountId: args.nearAccountId,
          chainTarget: selectedTransactionLane.chainTarget,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      },
    }),
    thresholdSessionId: resolvedIdentity.thresholdSessionId,
  };
}

export async function recordSuccessfulEvmFamilyWalletSigningSessionSpend(
  args: EvmFamilyWalletSigningSessionBudgetArgs,
): Promise<void> {
  const result = createEvmFamilyTransactionBudgetFinalizer(args);
  await result.finalizer.recordSuccess();
}

export async function reserveEvmFamilyWalletSigningSessionBudget(
  args: EvmFamilyWalletSigningSessionBudgetArgs,
): Promise<SigningSessionBudgetReservation | null> {
  const result = createEvmFamilyTransactionBudgetFinalizer(args);
  return await result.finalizer.reserve();
}

export function recordFailedEvmFamilyWalletSigningSessionSpend(
  args: EvmFamilyWalletSigningSessionBudgetArgs & { error: unknown },
): void {
  const result = createEvmFamilyTransactionBudgetFinalizer(args);
  result.finalizer.recordZeroSpend(args.error);
}
