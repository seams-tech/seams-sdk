import { createSigningSessionBudgetFinalizer } from '../../session/signingSession/budgetFinalizer';
import type { SigningSessionBudgetReservation } from '../../session/signingSession/budget';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import {
  type SigningOperationFingerprint,
  type SigningOperationContext,
} from '../../session/signingSession/types';
import {
  requireResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaLane,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import type { EvmFamilyChain } from './types';

export type EvmFamilyTransactionSigningOperationContext = SigningOperationContext & {
  operationFingerprint: SigningOperationFingerprint;
};

type EvmFamilyWalletSigningSessionBudgetArgs = {
  signingSessionCoordinator?: SigningSessionCoordinator;
  nearAccountId: string;
  chain: EvmFamilyChain;
  operation: EvmFamilyTransactionSigningOperationContext;
  ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane;
};

function createEvmFamilyTransactionBudgetFinalizer(args: EvmFamilyWalletSigningSessionBudgetArgs) {
  const budgetLane = requireResolvedEvmFamilyEcdsaSigningLane({
    lane: args.ecdsaSigningLane,
    chain: args.chain,
    context: 'budget finalizer',
    diagnostics: {
      nearAccountId: args.nearAccountId,
      operationId: String(args.operation.operationId || ''),
      selectedLane: summarizeEvmFamilyEcdsaLane(args.ecdsaSigningLane),
    },
  });
  const resolvedThresholdSessionId = String(budgetLane.thresholdSessionId).trim();

  return {
    finalizer: createSigningSessionBudgetFinalizer({
      signingSessionBudget: args.signingSessionCoordinator,
      operation: args.operation,
      // Passkey reauth can replace the ECDSA threshold session after the
      // confirmation. Budget finalization must follow the refreshed keyRef,
      // not the exhausted lane that was selected during pre-confirm planning.
      lane: budgetLane,
      onRecordSuccessError: (error) => {
        console.warn('[SigningEngine][ecdsa] failed to update wallet signing-session budget', {
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          walletSigningSessionId: String(budgetLane.walletSigningSessionId),
          thresholdSessionId: resolvedThresholdSessionId,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      },
      onRecordZeroSpendError: (error) => {
        console.warn('[SigningEngine][ecdsa] failed to record wallet signing-session zero spend', {
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      },
    }),
    thresholdSessionId: resolvedThresholdSessionId,
    selectedSigningLane: budgetLane,
  };
}

export async function recordSuccessfulEvmFamilyWalletSigningSessionSpend(
  args: EvmFamilyWalletSigningSessionBudgetArgs,
): Promise<void> {
  const result = createEvmFamilyTransactionBudgetFinalizer(args);
  await result.finalizer.recordSuccess({
    ...(result.selectedSigningLane.authMethod === 'email_otp' && result.thresholdSessionId
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
