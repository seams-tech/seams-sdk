export const WALLET_SESSION_FAILURE_CODES = {
  missing: 'wallet_session_missing',
  signatureInvalid: 'wallet_session_signature_invalid',
  claimsInvalid: 'wallet_session_claims_invalid',
  expired: 'wallet_session_expired',
  scopeMismatch: 'wallet_session_scope_mismatch',
  unavailable: 'wallet_session_unavailable',
  budgetExhausted: 'wallet_budget_exhausted',
} as const;

export type WalletSessionFailureCode =
  (typeof WALLET_SESSION_FAILURE_CODES)[keyof typeof WALLET_SESSION_FAILURE_CODES];

export function isWalletSessionFailureCode(value: unknown): value is WalletSessionFailureCode {
  switch (value) {
    case WALLET_SESSION_FAILURE_CODES.missing:
    case WALLET_SESSION_FAILURE_CODES.signatureInvalid:
    case WALLET_SESSION_FAILURE_CODES.claimsInvalid:
    case WALLET_SESSION_FAILURE_CODES.expired:
    case WALLET_SESSION_FAILURE_CODES.scopeMismatch:
    case WALLET_SESSION_FAILURE_CODES.unavailable:
    case WALLET_SESSION_FAILURE_CODES.budgetExhausted:
      return true;
    default:
      return false;
  }
}
