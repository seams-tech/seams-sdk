import {
  isWalletSessionFailureCode,
  WALLET_SESSION_FAILURE_CODES,
  type WalletSessionFailureCode,
} from '@shared/utils/walletSessionFailure';

export type WalletSessionFailure =
  | {
      readonly kind: 'expired';
      readonly code: typeof WALLET_SESSION_FAILURE_CODES.expired;
    }
  | {
      readonly kind: 'missing';
      readonly code: typeof WALLET_SESSION_FAILURE_CODES.missing;
    }
  | {
      readonly kind: 'invalid';
      readonly code:
        | typeof WALLET_SESSION_FAILURE_CODES.signatureInvalid
        | typeof WALLET_SESSION_FAILURE_CODES.claimsInvalid
        | typeof WALLET_SESSION_FAILURE_CODES.scopeMismatch;
      readonly reason: 'signature_invalid' | 'claims_invalid' | 'scope_mismatch';
    }
  | {
      readonly kind: 'unavailable';
      readonly code: typeof WALLET_SESSION_FAILURE_CODES.unavailable;
    }
  | {
      readonly kind: 'exhausted';
      readonly code: typeof WALLET_SESSION_FAILURE_CODES.budgetExhausted;
    };

export class WalletSessionFailureError extends Error {
  readonly failure: WalletSessionFailure;

  constructor(args: { readonly failure: WalletSessionFailure; readonly message: string }) {
    super(args.message);
    this.name = 'WalletSessionFailureError';
    this.failure = args.failure;
  }
}

export function walletSessionFailureFromCode(code: WalletSessionFailureCode): WalletSessionFailure {
  switch (code) {
    case WALLET_SESSION_FAILURE_CODES.expired:
      return { kind: 'expired', code };
    case WALLET_SESSION_FAILURE_CODES.missing:
      return { kind: 'missing', code };
    case WALLET_SESSION_FAILURE_CODES.signatureInvalid:
      return { kind: 'invalid', code, reason: 'signature_invalid' };
    case WALLET_SESSION_FAILURE_CODES.claimsInvalid:
      return { kind: 'invalid', code, reason: 'claims_invalid' };
    case WALLET_SESSION_FAILURE_CODES.scopeMismatch:
      return { kind: 'invalid', code, reason: 'scope_mismatch' };
    case WALLET_SESSION_FAILURE_CODES.unavailable:
      return { kind: 'unavailable', code };
    case WALLET_SESSION_FAILURE_CODES.budgetExhausted:
      return { kind: 'exhausted', code };
  }
}

export function walletSessionFailureErrorFromPayload(args: {
  readonly code: unknown;
  readonly message: string;
}): WalletSessionFailureError | null {
  if (!isWalletSessionFailureCode(args.code)) return null;
  return new WalletSessionFailureError({
    failure: walletSessionFailureFromCode(args.code),
    message: args.message,
  });
}

export function walletSessionFailureFromError(error: unknown): WalletSessionFailure | null {
  if (error instanceof WalletSessionFailureError) return error.failure;
  if (!error || typeof error !== 'object') return null;
  const record = error as { readonly code?: unknown; readonly coreCode?: unknown };
  if (isWalletSessionFailureCode(record.coreCode)) {
    return walletSessionFailureFromCode(record.coreCode);
  }
  if (isWalletSessionFailureCode(record.code)) {
    return walletSessionFailureFromCode(record.code);
  }
  return null;
}
