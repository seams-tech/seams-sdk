import type {
  BudgetReservationFinalizationCommand,
  BudgetFinalizationSpend,
  ExternallyConsumedBudgetFinalizationSpend,
  ReservedBudgetFinalizationSpend,
  SigningBudgetFinalizationResult,
  SigningSessionBudget,
  SigningSessionBudgetReserveResult,
  SigningSessionPreparedBudgetIdentity,
  SigningSessionBudgetSuccessInput,
  SigningSessionBudgetZeroSpendReason,
  UnreservedBudgetFinalizationSpend,
  ZeroBudgetFinalizationSpend,
  ZeroWalletBudgetSpend,
} from './budget';
import {
  buildSigningBudgetReservationIdentity,
  buildWalletSigningSpendPlan,
  isSigningSessionBudgetInFlightError,
  resolveWalletSigningOperationFingerprint,
} from './budget';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type SigningAuthMethod,
  type WalletSigningSpendPlan,
} from '../operationState/types';

export type SigningSessionBudgetFinalizer = {
  spend?: WalletSigningSpendPlan;
  reserve(): Promise<SigningSessionBudgetReserveResult>;
  recordSuccess(): Promise<SigningBudgetFinalizationResult | null>;
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
      if (!budget) return null;
      if (args.finalization.kind === 'zero_spend') return null;
      const successInput = withSuccessFinalizationCommand({
        finalization: args.finalization,
        budgetIdentity: args.budgetIdentity,
      });
      return await budget.recordSuccess(successInput).catch((error) => {
        if (!spend) return null;
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
        budget.recordZeroSpend(buildZeroSpendRecord(args, error));
      } catch (recordError) {
        args.onRecordZeroSpendError?.(recordError);
      }
    },
  };
}

function buildZeroSpendRecord(
  args: {
    budgetIdentity: SigningSessionPreparedBudgetIdentity;
    finalization: BudgetFinalizationSpend;
  },
  error: unknown,
): ZeroWalletBudgetSpend {
  if (args.finalization.kind === 'zero_spend') {
    const zeroSpend = {
      ...args.finalization,
      reason: inferSigningSessionBudgetZeroSpendReason({
        error,
        authMethod: args.finalization.lane.authMethod,
      }),
      error,
    };
    return withFinalizationCommand({
      zeroSpend,
      budgetIdentity: args.budgetIdentity,
    });
  }
  const spend = args.finalization.spend;
  return withFinalizationCommand({
    zeroSpend: {
      kind: 'zero_spend',
      operationId: spend.operationId,
      operationFingerprint: SigningSessionIds.signingOperationFingerprint(
        resolveWalletSigningOperationFingerprint(spend),
      ),
      lane: spend.lane,
      reason: inferSigningSessionBudgetZeroSpendReason({
        error,
        authMethod: spend.lane.authMethod,
      }),
      error,
    },
    budgetIdentity: args.budgetIdentity,
  });
}

function withFinalizationCommand(args: {
  zeroSpend: ZeroBudgetFinalizationSpend;
  budgetIdentity: SigningSessionPreparedBudgetIdentity;
}): ZeroWalletBudgetSpend {
  const spend = buildWalletSigningSpendPlan(
    {
      operationId: args.zeroSpend.operationId,
      operationFingerprint: args.zeroSpend.operationFingerprint,
      intent: SigningOperationIntent.TransactionSign,
    },
    args.zeroSpend.lane,
    args.zeroSpend.lane.curve === 'ecdsa' ? { ecdsaKey: args.zeroSpend.lane.key } : undefined,
  );
  const finalizationCommand: BudgetReservationFinalizationCommand = {
    kind: 'budget_reservation_finalization_command',
    reservation: buildSigningBudgetReservationIdentity({
      spend,
      projectionVersion: args.budgetIdentity.projectionVersion,
    }),
    outcome: 'failed_before_sign',
  };
  return {
    ...args.zeroSpend,
    finalizationCommand,
  };
}

function withSuccessFinalizationCommand(args: {
  finalization: BudgetFinalizationSpendWithSpend;
  budgetIdentity: SigningSessionPreparedBudgetIdentity;
}): SigningSessionBudgetSuccessInput {
  const finalizationCommand: BudgetReservationFinalizationCommand = {
    kind: 'budget_reservation_finalization_command',
    reservation: buildSigningBudgetReservationIdentity({
      spend: args.finalization.spend,
      projectionVersion: args.budgetIdentity.projectionVersion,
    }),
    outcome: 'signed',
  };
  return {
    ...args.finalization,
    finalizationCommand,
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
  reserve: () => Promise<SigningSessionBudgetReserveResult>,
): Promise<SigningSessionBudgetReserveResult> {
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
