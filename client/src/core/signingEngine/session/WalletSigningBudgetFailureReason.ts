import type { SigningAuthMethod } from './signingSessionTypes';
import type { WalletSigningBudgetLedgerZeroSpendReason } from './WalletSigningBudgetLedger';

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
