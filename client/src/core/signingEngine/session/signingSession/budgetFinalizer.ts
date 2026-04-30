import type {
  SigningSessionBudget,
  SigningSessionBudgetRecordSuccessInput,
  SigningSessionBudgetReservation,
  SigningSessionPreparedBudgetIdentity,
  SigningSessionBudgetStatusAuth,
  SigningSessionBudgetZeroSpendReason,
} from './budget';
import { buildWalletSigningSpendPlan } from './budget';
import type {
  BackingMaterialSessionId,
  SigningAuthMethod,
  SigningOperationContext,
  SelectedSigningLaneContext,
  WalletSigningSpendPlan,
} from './types';

export type SigningSessionBudgetFinalizer = {
  spend?: WalletSigningSpendPlan;
  reserve(): Promise<SigningSessionBudgetReservation | null>;
  recordSuccess(input?: Omit<SigningSessionBudgetRecordSuccessInput, 'spend'>): Promise<void>;
  recordZeroSpend(error: unknown): void;
};

export function createSigningSessionBudgetFinalizer(args: {
  signingSessionBudget?: SigningSessionBudget;
  budgetIdentity: SigningSessionPreparedBudgetIdentity;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  operation: SigningOperationContext;
  lane: SelectedSigningLaneContext;
  backingMaterialSessionId?: BackingMaterialSessionId;
  onRecordSuccessError?: (error: unknown, spend: WalletSigningSpendPlan) => void;
  onRecordZeroSpendError?: (error: unknown) => void;
}): SigningSessionBudgetFinalizer {
  const spend = buildWalletSigningSpendPlan(args.operation, args.lane, {
    ...(args.backingMaterialSessionId
      ? { backingMaterialSessionId: args.backingMaterialSessionId }
      : {}),
  });
  const budget = args.signingSessionBudget;
  if (args.budgetIdentity.walletSigningSessionId !== String(spend.walletSigningSessionId)) {
    throw new Error('[SigningSessionBudget] prepared budget identity does not match spend lane');
  }

  return {
    spend,
    async reserve() {
      if (!budget) return null;
      return await budget.reserve({
        spend,
        expectedBudgetProjectionVersion: args.budgetIdentity.projectionVersion,
        ...(args.trustedStatusAuth ? { trustedStatusAuth: args.trustedStatusAuth } : {}),
      });
    },
    async recordSuccess(input = {}) {
      if (!budget) return;
      await budget.recordSuccess({
        ...input,
        spend,
        expectedBudgetProjectionVersion: args.budgetIdentity.projectionVersion,
        ...(args.trustedStatusAuth ? { trustedStatusAuth: args.trustedStatusAuth } : {}),
      }).catch((error) => {
        args.onRecordSuccessError?.(error, spend);
        // Do not fail open here. A previous regression logged spend failures and
        // still reported signing success, leaving the next operation to hit
        // wallet signing-session not_found/exhausted errors unpredictably.
        throw error;
      });
    },
    recordZeroSpend(error) {
      if (!budget) return;
      try {
        budget.recordZeroSpend({
          spend,
          reason: inferSigningSessionBudgetZeroSpendReason({
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

export function inferSigningSessionBudgetZeroSpendReason(args: {
  error: unknown;
  authMethod?: SigningAuthMethod;
}): SigningSessionBudgetZeroSpendReason {
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
