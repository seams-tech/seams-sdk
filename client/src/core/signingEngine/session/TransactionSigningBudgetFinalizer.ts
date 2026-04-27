import { buildWalletSigningSpendPlan } from './SigningBudgetSpendPlan';
import { inferWalletSigningBudgetZeroSpendReason } from './WalletSigningBudgetFailureReason';
import type {
  WalletSigningBudgetLedger,
  WalletSigningBudgetLedgerRecordSuccessInput,
  WalletSigningBudgetReservation,
} from './signingSession/budget';
import type {
  BackingMaterialSessionId,
  SigningLaneContext,
  SigningOperationContext,
  ThresholdSessionId,
  WalletSigningSpendPlan,
} from './signingSessionTypes';

export type TransactionSigningBudgetFinalizer = {
  spend?: WalletSigningSpendPlan;
  reserve(): Promise<WalletSigningBudgetReservation | null>;
  recordSuccess(input?: Omit<WalletSigningBudgetLedgerRecordSuccessInput, 'spend'>): Promise<void>;
  recordZeroSpend(error: unknown): void;
};

export function createTransactionSigningBudgetFinalizer(args: {
  walletSigningBudgetLedger?: WalletSigningBudgetLedger;
  operation: SigningOperationContext;
  lane: SigningLaneContext;
  thresholdSessionId?: ThresholdSessionId;
  backingMaterialSessionId?: BackingMaterialSessionId;
  onRecordSuccessError?: (error: unknown, spend: WalletSigningSpendPlan) => void;
  onRecordZeroSpendError?: (error: unknown) => void;
}): TransactionSigningBudgetFinalizer {
  const spend = buildWalletSigningSpendPlan(args.operation, args.lane, {
    ...(args.thresholdSessionId ? { thresholdSessionId: args.thresholdSessionId } : {}),
    ...(args.backingMaterialSessionId
      ? { backingMaterialSessionId: args.backingMaterialSessionId }
      : {}),
  });
  const ledger = args.walletSigningBudgetLedger;

  return {
    spend,
    async reserve() {
      if (!ledger) return null;
      return await ledger.reserve({ spend });
    },
    async recordSuccess(input = {}) {
      if (!ledger) return;
      await ledger.recordSuccess({ ...input, spend }).catch((error) => {
        args.onRecordSuccessError?.(error, spend);
        // Do not fail open here. A previous regression logged spend failures and
        // still reported signing success, leaving the next operation to hit
        // wallet signing-session not_found/exhausted errors unpredictably.
        throw error;
      });
    },
    recordZeroSpend(error) {
      if (!ledger) return;
      try {
        ledger.recordZeroSpend({
          spend,
          reason: inferWalletSigningBudgetZeroSpendReason({
            error,
            authMethod: spend.lane.authMethod,
          }),
          error,
        });
      } catch (recordError) {
        args.onRecordZeroSpendError?.(recordError);
      }
    },
  };
}
