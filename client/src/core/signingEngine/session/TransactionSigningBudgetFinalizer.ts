import { buildWalletSigningSpendPlan } from './SigningBudgetSpendPlan';
import {
  inferWalletSigningBudgetZeroSpendReason,
} from './WalletSigningBudgetFailureReason';
import type {
  WalletSigningBudgetLedger,
  WalletSigningBudgetLedgerRecordSuccessInput,
} from './WalletSigningBudgetLedger';
import type {
  BackingMaterialSessionId,
  SigningLaneContext,
  SigningOperationContext,
  ThresholdSessionId,
  WalletSigningSpendPlan,
} from './signingSessionTypes';

export type TransactionSigningBudgetFinalizer = {
  spend?: WalletSigningSpendPlan;
  reserve(): Promise<void>;
  recordSuccess(
    input?: Omit<WalletSigningBudgetLedgerRecordSuccessInput, 'spend'>,
  ): Promise<void>;
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
      if (!ledger) return;
      await ledger.reserve({ spend });
    },
    async recordSuccess(input = {}) {
      if (!ledger) return;
      await ledger.recordSuccess({ ...input, spend }).catch((error) => {
        args.onRecordSuccessError?.(error, spend);
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
