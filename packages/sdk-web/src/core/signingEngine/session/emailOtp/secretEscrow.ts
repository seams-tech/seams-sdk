export const EMAIL_OTP_ESCROW_SECRET_LENGTH = 32 as const;

export type EmailOtpEscrowSecret32 = {
  readonly kind: 'secret32';
  readonly secret32: Uint8Array;
};

export type EmailOtpCorruptLocalCustodyFailure = {
  readonly kind: 'corrupt_local_custody';
  readonly ok: false;
  readonly code: 'corrupt_local_custody';
  readonly reason: 'invalid_escrow_plaintext_length';
  readonly expectedLength: typeof EMAIL_OTP_ESCROW_SECRET_LENGTH;
  readonly actualLength: number;
  readonly message: string;
};

export type EmailOtpEscrowSecret32DecodeResult =
  | EmailOtpEscrowSecret32
  | EmailOtpCorruptLocalCustodyFailure;

export class EmailOtpCorruptLocalCustodyError extends Error {
  readonly code = 'corrupt_local_custody' as const;
  readonly reason: EmailOtpCorruptLocalCustodyFailure['reason'];
  readonly expectedLength: typeof EMAIL_OTP_ESCROW_SECRET_LENGTH;
  readonly actualLength: number;

  constructor(failure: EmailOtpCorruptLocalCustodyFailure) {
    super(failure.message);
    this.name = 'EmailOtpCorruptLocalCustodyError';
    this.reason = failure.reason;
    this.expectedLength = failure.expectedLength;
    this.actualLength = failure.actualLength;
  }
}

function corruptPlaintextLength(actualLength: number): EmailOtpCorruptLocalCustodyFailure {
  return {
    kind: 'corrupt_local_custody',
    ok: false,
    code: 'corrupt_local_custody',
    reason: 'invalid_escrow_plaintext_length',
    expectedLength: EMAIL_OTP_ESCROW_SECRET_LENGTH,
    actualLength,
    message: `Email OTP local custody plaintext has invalid length: expected at most 32 bytes, received ${actualLength}`,
  };
}

export function decodeEmailOtpEscrowSecret32(
  plaintext: Uint8Array,
): EmailOtpEscrowSecret32DecodeResult {
  const actualLength = plaintext.length;
  if (actualLength < 1 || actualLength > EMAIL_OTP_ESCROW_SECRET_LENGTH) {
    return corruptPlaintextLength(actualLength);
  }

  // Shamir represents plaintext as an integer, so its big-endian output omits leading zeroes.
  const secret32 = new Uint8Array(EMAIL_OTP_ESCROW_SECRET_LENGTH);
  secret32.set(plaintext, EMAIL_OTP_ESCROW_SECRET_LENGTH - actualLength);
  return { kind: 'secret32', secret32 };
}

export function emailOtpCorruptLocalCustodyError(
  failure: EmailOtpCorruptLocalCustodyFailure,
): EmailOtpCorruptLocalCustodyError {
  return new EmailOtpCorruptLocalCustodyError(failure);
}
