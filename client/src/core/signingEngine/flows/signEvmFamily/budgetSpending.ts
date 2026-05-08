import { createSigningSessionBudgetFinalizer } from '../../session/budget/budgetFinalizer';
import type {
  SigningSessionBudgetReservation,
  SigningSessionPreparedBudgetIdentity,
  SigningSessionBudgetStatusAuth,
} from '../../session/budget/budget';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import {
  type SigningOperationFingerprint,
  type SigningOperationContext,
} from '../../session/signingSession/types';
import type { SelectedEcdsaLane } from '../../session/identity/laneIdentity';
import type { ResolvedEvmFamilyEcdsaSigningLane } from './ecdsaLanes';

export type EvmFamilyTransactionSigningOperationContext = SigningOperationContext & {
  operationFingerprint: SigningOperationFingerprint;
};

type EvmFamilyWalletSigningSessionBudgetArgs = {
  signingSessionCoordinator: SigningSessionCoordinator;
  nearAccountId: string;
  operation: EvmFamilyTransactionSigningOperationContext;
  selectedTransactionLane: SelectedEcdsaLane;
  selectedSigningLane: ResolvedEvmFamilyEcdsaSigningLane;
  budgetIdentity: SigningSessionPreparedBudgetIdentity;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
};

function createEvmFamilyTransactionBudgetFinalizer(args: EvmFamilyWalletSigningSessionBudgetArgs) {
  const selectedTransactionLane = args.selectedTransactionLane;
  const resolvedThresholdSessionId = String(
    selectedTransactionLane?.thresholdSessionId || '',
  ).trim();
  if (
    !selectedTransactionLane ||
    !resolvedThresholdSessionId ||
    !String(selectedTransactionLane.walletSigningSessionId).trim()
  ) {
    throw new Error(
      '[SigningEngine][ecdsa] budget finalizer requires an exact selected transaction lane',
    );
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
      lane: args.selectedSigningLane,
      onRecordSuccessError: (error) => {
        console.warn('[SigningEngine][ecdsa] failed to update wallet signing-session budget', {
          nearAccountId: args.nearAccountId,
          chainTarget: selectedTransactionLane.chainTarget,
          walletSigningSessionId: String(selectedTransactionLane.walletSigningSessionId),
          thresholdSessionId: resolvedThresholdSessionId,
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
    thresholdSessionId: resolvedThresholdSessionId,
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
