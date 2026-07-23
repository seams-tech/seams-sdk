import type { SessionParseFailureReason } from '../core/sessionValidation';
import {
  WALLET_SESSION_FAILURE_CODES,
  type WalletSessionFailureCode,
} from '@shared/utils/walletSessionFailure';

export type { WalletSessionFailureCode } from '@shared/utils/walletSessionFailure';

export type WalletSessionBoundaryFailure = {
  readonly ok: false;
  readonly code: WalletSessionFailureCode;
  readonly message: string;
};

export function walletSessionFailureCodeFromParseReason(
  reason: SessionParseFailureReason,
): Exclude<
  WalletSessionFailureCode,
  | typeof WALLET_SESSION_FAILURE_CODES.scopeMismatch
  | typeof WALLET_SESSION_FAILURE_CODES.unavailable
  | typeof WALLET_SESSION_FAILURE_CODES.budgetExhausted
> {
  switch (reason) {
    case 'missing':
      return WALLET_SESSION_FAILURE_CODES.missing;
    case 'signature_invalid':
      return WALLET_SESSION_FAILURE_CODES.signatureInvalid;
    case 'claims_invalid':
    case 'not_active':
      return WALLET_SESSION_FAILURE_CODES.claimsInvalid;
    case 'expired':
      return WALLET_SESSION_FAILURE_CODES.expired;
  }
}

export function walletSessionFailureMessage(code: WalletSessionFailureCode): string {
  switch (code) {
    case 'wallet_session_missing':
      return 'Wallet Session is missing';
    case 'wallet_session_signature_invalid':
      return 'Wallet Session signature is invalid';
    case 'wallet_session_claims_invalid':
      return 'Wallet Session claims are invalid';
    case 'wallet_session_expired':
      return 'Wallet Session expired';
    case 'wallet_session_scope_mismatch':
      return 'Wallet Session scope does not match the request';
    case 'wallet_session_unavailable':
      return 'Wallet Session status is unavailable';
    case 'wallet_budget_exhausted':
      return 'Wallet Session signing budget is exhausted';
  }
}

export function walletSessionFailureStatus(code: WalletSessionFailureCode): 401 | 403 | 409 | 503 {
  switch (code) {
    case 'wallet_session_missing':
    case 'wallet_session_signature_invalid':
    case 'wallet_session_claims_invalid':
    case 'wallet_session_expired':
      return 401;
    case 'wallet_session_scope_mismatch':
      return 403;
    case 'wallet_budget_exhausted':
      return 409;
    case 'wallet_session_unavailable':
      return 503;
  }
}

export function walletSessionParseFailure(
  reason: SessionParseFailureReason,
): WalletSessionBoundaryFailure {
  const code = walletSessionFailureCodeFromParseReason(reason);
  return walletSessionFailure(code);
}

export function walletSessionFailure(
  code: WalletSessionFailureCode,
): WalletSessionBoundaryFailure {
  return {
    ok: false,
    code,
    message: walletSessionFailureMessage(code),
  };
}
