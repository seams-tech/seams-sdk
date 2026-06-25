import { createSigningSessionBudgetFinalizer } from '../../session/budget/budgetFinalizer';
import type {
  BudgetFinalizationSpend,
  SigningSessionBudgetReserveResult,
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
import { toWalletId, type WalletSessionRef } from '../../interfaces/ecdsaChainTarget';
import { requireEvmFamilyEcdsaSigner } from '../../session/identity/exactSigningLaneIdentity';

export type EvmFamilyTransactionSigningOperationContext = SigningOperationContext & {
  operationFingerprint: SigningOperationFingerprint;
};

type EvmFamilySigningGrantBudgetArgs = {
  signingSessionCoordinator: SigningSessionCoordinator;
  walletSession: WalletSessionRef;
  operation: EvmFamilyTransactionSigningOperationContext;
  admittedTransaction: BudgetAdmittedOperation<SelectedEcdsaLane>;
  finalizedSigningLane: ResolvedEvmFamilyEcdsaSigningLane;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  error?: unknown;
};

function buildEvmFamilyBudgetFinalization(
  args: EvmFamilySigningGrantBudgetArgs,
): BudgetFinalizationSpend {
  const selectedTransactionLane = args.admittedTransaction.lane;
  const resolvedIdentity = buildEcdsaSessionIdentity(selectedTransactionLane);
  if (!resolvedIdentity.thresholdSessionId || !resolvedIdentity.signingGrantId) {
    throw new Error(
      '[SigningEngine][ecdsa] budget finalizer requires an exact selected transaction lane',
    );
  }
  if (typeof args.error !== 'undefined') {
    return {
      kind: 'zero_spend',
      operationId: args.operation.operationId,
      operationFingerprint: args.operation.operationFingerprint,
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
    lane: args.finalizedSigningLane,
    backingMaterialSessionIds: [],
    uses: 1,
    reason: args.operation.intent,
  };
  return {
    kind: 'externally_consumed_success',
    spend,
    ...(args.trustedStatusAuth ? { trustedStatusAuth: args.trustedStatusAuth } : {}),
    alreadyConsumedThresholdSessionIds: [args.finalizedSigningLane.thresholdSessionId],
  };
}

function createEvmFamilyTransactionBudgetFinalizer(args: EvmFamilySigningGrantBudgetArgs) {
  const selectedTransactionLane = args.admittedTransaction.lane;
  const selectedTransactionSigner = requireEvmFamilyEcdsaSigner(
    selectedTransactionLane.identity,
    'ECDSA budget finalizer',
  );
  const resolvedIdentity = buildEcdsaSessionIdentity(selectedTransactionLane);
  return {
    finalizer: createSigningSessionBudgetFinalizer({
      budgetMode: 'with_budget',
      signingSessionBudget: args.signingSessionCoordinator,
      budgetIdentity: args.admittedTransaction.budgetAdmission.budgetIdentity,
      finalization: buildEvmFamilyBudgetFinalization(args),
      onRecordSuccessError: (error) => {
        console.warn('[SigningEngine][ecdsa] failed to update signing grant budget', {
          walletId: toWalletId(args.walletSession.walletId),
          chainTarget: selectedTransactionSigner.chainTarget,
          signingGrantId: resolvedIdentity.signingGrantId,
          thresholdSessionId: resolvedIdentity.thresholdSessionId,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      },
      onRecordZeroSpendError: (error) => {
        console.warn('[SigningEngine][ecdsa] failed to record signing grant zero spend', {
          walletId: toWalletId(args.walletSession.walletId),
          chainTarget: selectedTransactionSigner.chainTarget,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      },
    }),
    thresholdSessionId: resolvedIdentity.thresholdSessionId,
  };
}

export async function recordSuccessfulEvmFamilySigningGrantSpend(
  args: EvmFamilySigningGrantBudgetArgs,
): Promise<void> {
  const result = createEvmFamilyTransactionBudgetFinalizer(args);
  await result.finalizer.recordSuccess();
}

export async function reserveEvmFamilySigningGrantBudget(
  args: EvmFamilySigningGrantBudgetArgs,
): Promise<SigningSessionBudgetReserveResult> {
  const result = createEvmFamilyTransactionBudgetFinalizer(args);
  return await result.finalizer.reserve();
}

export function recordFailedEvmFamilySigningGrantSpend(
  args: EvmFamilySigningGrantBudgetArgs & { error: unknown },
): void {
  const result = createEvmFamilyTransactionBudgetFinalizer(args);
  result.finalizer.recordZeroSpend(args.error);
}
