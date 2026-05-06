import { createSigningSessionBudgetFinalizer } from '../../session/signingSession/budgetFinalizer';
import type {
  SigningSessionBudgetReservation,
  SigningSessionPreparedBudgetIdentity,
  SigningSessionBudgetStatusAuth,
} from '../../session/signingSession/budget';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import {
  type SigningOperationFingerprint,
  type SigningOperationContext,
} from '../../session/signingSession/types';
import {
  selectedSigningLaneContextFromTransactionLane,
  type EvmFamilyEcdsaTransactionLane,
} from '../../session/signingSession/transactionState';

export type EvmFamilyTransactionSigningOperationContext = SigningOperationContext & {
  operationFingerprint: SigningOperationFingerprint;
};

type EvmFamilyWalletSigningSessionBudgetArgs = {
  signingSessionCoordinator: SigningSessionCoordinator;
  nearAccountId: string;
  operation: EvmFamilyTransactionSigningOperationContext;
  transactionLane: EvmFamilyEcdsaTransactionLane;
  budgetIdentity: SigningSessionPreparedBudgetIdentity;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
};

function createEvmFamilyTransactionBudgetFinalizer(args: EvmFamilyWalletSigningSessionBudgetArgs) {
  const transactionLane = args.transactionLane;
  const resolvedThresholdSessionId = String(transactionLane?.thresholdSessionId || '').trim();
  if (
    !transactionLane ||
    !resolvedThresholdSessionId ||
    !String(transactionLane.walletSigningSessionId).trim()
  ) {
    throw new Error('[SigningEngine][ecdsa] budget finalizer requires an exact transaction lane');
  }

  return {
    finalizer: createSigningSessionBudgetFinalizer({
      signingSessionBudget: args.signingSessionCoordinator,
      budgetIdentity: args.budgetIdentity,
      ...(args.trustedStatusAuth ? { trustedStatusAuth: args.trustedStatusAuth } : {}),
      operation: args.operation,
      // Passkey reauth can replace the ECDSA threshold session after the
      // confirmation. Budget finalization must follow the refreshed keyRef,
      // not the exhausted lane that was selected during pre-confirm planning.
      lane: transactionLane,
      onRecordSuccessError: (error) => {
        console.warn('[SigningEngine][ecdsa] failed to update wallet signing-session budget', {
          nearAccountId: args.nearAccountId,
          chainTarget: transactionLane.chainTarget,
          walletSigningSessionId: String(transactionLane.walletSigningSessionId),
          thresholdSessionId: resolvedThresholdSessionId,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      },
      onRecordZeroSpendError: (error) => {
        console.warn('[SigningEngine][ecdsa] failed to record wallet signing-session zero spend', {
          nearAccountId: args.nearAccountId,
          chainTarget: transactionLane.chainTarget,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      },
    }),
    thresholdSessionId: resolvedThresholdSessionId,
    selectedSigningLane: selectedSigningLaneContextFromTransactionLane(transactionLane),
  };
}

export async function recordSuccessfulEvmFamilyWalletSigningSessionSpend(
  args: EvmFamilyWalletSigningSessionBudgetArgs,
): Promise<void> {
  const result = createEvmFamilyTransactionBudgetFinalizer(args);
  await result.finalizer.recordSuccess({
    // ECDSA threshold authorization is the server-side budget spend boundary
    // for both Email OTP and passkey lanes. Finalization should sync the
    // resulting status, not spend the same threshold session a second time.
    ...(result.thresholdSessionId
      ? { alreadyConsumedThresholdSessionIds: [result.thresholdSessionId] }
      : {}),
  });
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
