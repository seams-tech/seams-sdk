import type {
  WalletSigningBudgetLedger,
  WalletSigningBudgetLedgerRecordSuccessInput,
  WalletSigningBudgetReservation,
  WalletSigningBudgetLedgerZeroSpendReason,
} from './budget';
import { buildWalletSigningSpendPlan } from './budget';
import type {
  BackingMaterialSessionId,
  SigningAuthMethod,
  SigningLaneContext,
  SigningOperationContext,
  ThresholdSessionId,
  WalletSigningSpendPlan,
} from './types';

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

export function inferWalletSigningBudgetZeroSpendReason(args: {
  error: unknown;
  authMethod?: SigningAuthMethod;
}): WalletSigningBudgetLedgerZeroSpendReason {
  const code = extractErrorCode(args.error);
  const message = extractErrorMessage(args.error).toLowerCase();
  const haystack = `${code} ${message}`;

  if (
    haystack.includes('nonce_conflict') ||
    haystack.includes('nonce_lane_blocked') ||
    haystack.includes('nonce too low') ||
    haystack.includes('nonce too high') ||
    haystack.includes('replacement transaction underpriced') ||
    haystack.includes('already known') ||
    haystack.includes('invalid nonce')
  ) {
    return 'nonce_preparation_failed';
  }

  if (
    code === 'cancelled' ||
    code === 'user_cancelled' ||
    haystack.includes('request cancelled') ||
    haystack.includes('user rejected') ||
    haystack.includes('cancelled by user')
  ) {
    return 'confirmation_cancelled';
  }

  if (
    haystack.includes('fresh_email_otp_required') ||
    haystack.includes('email otp') ||
    haystack.includes('otp')
  ) {
    return 'email_otp_failed';
  }

  if (
    args.authMethod === 'passkey' ||
    haystack.includes('passkey') ||
    haystack.includes('webauthn') ||
    haystack.includes('notallowederror') ||
    haystack.includes('not allowed')
  ) {
    return 'passkey_failed';
  }

  if (args.authMethod === 'email_otp') {
    return 'email_otp_failed';
  }

  return 'signing_failed';
}

function extractErrorCode(error: unknown): string {
  if (!error || typeof error !== 'object' || !('code' in error)) return '';
  return normalizeToken((error as { code?: unknown }).code);
}

function extractErrorMessage(error: unknown): string {
  if (!error) return '';
  if (typeof error === 'string') return error.trim();
  if (error instanceof Error) return String(error.message || '').trim();
  if (typeof error === 'object' && 'message' in error) {
    return String((error as { message?: unknown }).message || '').trim();
  }
  return String(error).trim();
}

function normalizeToken(value: unknown): string {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
}
