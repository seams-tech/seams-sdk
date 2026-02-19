import { toAccountId, type AccountId } from '@/core/types/accountIds';

export type ThresholdEcdsaSignInFlightError = Error & { code: 'signing_in_progress' };

export function createThresholdEcdsaSignInFlightError(
  nearAccountId: AccountId | string,
): ThresholdEcdsaSignInFlightError {
  const accountId = String(toAccountId(nearAccountId));
  const err = new Error(
    `[WebAuthnManager] threshold ECDSA signing already in progress for ${accountId}`,
  ) as ThresholdEcdsaSignInFlightError;
  err.code = 'signing_in_progress';
  return err;
}

export async function withThresholdEcdsaSignInFlightGate<T>(args: {
  inFlightByAccount: Set<string>;
  nearAccountId: AccountId | string;
  enabled: boolean;
  task: () => Promise<T>;
}): Promise<T> {
  if (!args.enabled) return await args.task();

  const accountKey = String(toAccountId(args.nearAccountId));
  if (args.inFlightByAccount.has(accountKey)) {
    throw createThresholdEcdsaSignInFlightError(accountKey);
  }

  args.inFlightByAccount.add(accountKey);
  try {
    return await args.task();
  } finally {
    args.inFlightByAccount.delete(accountKey);
  }
}
