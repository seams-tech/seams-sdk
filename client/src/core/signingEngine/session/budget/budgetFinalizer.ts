import type {
  BudgetFinalizationSpend,
  ExternallyConsumedBudgetFinalizationSpend,
  ReservedBudgetFinalizationSpend,
  SigningSessionBudget,
  SigningSessionBudgetReservation,
  SigningSessionPreparedBudgetIdentity,
  SigningSessionBudgetZeroSpendReason,
  UnreservedBudgetFinalizationSpend,
  ZeroBudgetFinalizationSpend,
} from './budget';
import { isSigningSessionBudgetInFlightError } from './budget';
import type {
  SigningAuthMethod,
  WalletSigningSpendPlan,
} from '../operationState/types';

export type SigningSessionBudgetFinalizer = {
  spend?: WalletSigningSpendPlan;
  reserve(): Promise<SigningSessionBudgetReservation | null>;
  recordSuccess(): Promise<void>;
  recordZeroSpend(error: unknown): void;
};

type BudgetFinalizationSpendWithSpend =
  | ReservedBudgetFinalizationSpend
  | UnreservedBudgetFinalizationSpend
  | ExternallyConsumedBudgetFinalizationSpend;

export function createSigningSessionBudgetFinalizer(args: {
  signingSessionBudget?: SigningSessionBudget;
  budgetIdentity: SigningSessionPreparedBudgetIdentity;
  finalization: BudgetFinalizationSpend;
  onRecordSuccessError?: (error: unknown, spend: WalletSigningSpendPlan) => void;
  onRecordZeroSpendError?: (error: unknown) => void;
}): SigningSessionBudgetFinalizer {
  const spend = getFinalizationSpend(args.finalization);
  const budget = args.signingSessionBudget;
  if (
    spend &&
    args.budgetIdentity.walletSigningSessionId !== String(spend.walletSigningSessionId)
  ) {
    throw new Error('[SigningSessionBudget] prepared budget identity does not match spend lane');
  }

  return {
    spend,
    async reserve() {
      if (!budget) return null;
      if (!spend) return null;
      const successFinalization = requireSuccessFinalization(args.finalization, 'reserve');
      return await reserveWithLocalContentionRetry(
        async () =>
          await budget.reserve({
            spend,
            expectedBudgetProjectionVersion: args.budgetIdentity.projectionVersion,
            ...(successFinalization.trustedStatusAuth
              ? { trustedStatusAuth: successFinalization.trustedStatusAuth }
              : {}),
          }),
      );
    },
    async recordSuccess() {
      if (!budget) return;
      if (args.finalization.kind === 'zero_spend') return;
      await budget
        .recordSuccess(args.finalization)
        .catch((error) => {
          if (!spend) return;
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
        budget.recordZeroSpend(
          args.finalization.kind === 'zero_spend'
            ? {
                ...args.finalization,
                reason: inferSigningSessionBudgetZeroSpendReason({
                  error,
                  authMethod: args.finalization.lane.authMethod,
                }),
                error,
              }
            : {
                kind: 'zero_spend',
                operationId: args.finalization.spend.operationId,
                lane: args.finalization.spend.lane,
                reason: inferSigningSessionBudgetZeroSpendReason({
                  error,
                  authMethod: args.finalization.spend.lane.authMethod,
                }),
                error,
              },
        );
      } catch (recordError) {
        args.onRecordZeroSpendError?.(recordError);
      }
    },
  };
}

function getFinalizationSpend(
  finalization: BudgetFinalizationSpend,
): WalletSigningSpendPlan | undefined {
  switch (finalization.kind) {
    case 'reserved_success':
    case 'unreserved_success':
    case 'externally_consumed_success':
      return finalization.spend;
    case 'zero_spend':
      return undefined;
  }
}

function requireSuccessFinalization(
  finalization: BudgetFinalizationSpend,
  context: string,
): BudgetFinalizationSpendWithSpend {
  switch (finalization.kind) {
    case 'reserved_success':
    case 'unreserved_success':
    case 'externally_consumed_success':
      return finalization;
    case 'zero_spend':
      throw new Error(`[SigningSessionBudget] ${context} requires a success finalization branch`);
  }
}

async function reserveWithLocalContentionRetry(
  reserve: () => Promise<SigningSessionBudgetReservation | null>,
): Promise<SigningSessionBudgetReservation | null> {
  const delaysMs = [20, 50, 100];
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await reserve();
    } catch (error) {
      if (!isSigningSessionBudgetInFlightError(error) || attempt >= delaysMs.length) {
        throw error;
      }
      // Same-projection holds are local admission control, not auth failure.
      // Give the signer finalizer a short window to release completed holds.
      await new Promise((resolve) => setTimeout(resolve, delaysMs[attempt]));
    }
  }
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
