import {
  encodeEmailOtpRecoveryKeyBytes as encodeWalletRecoveryCodeBytes,
  formatEmailOtpRecoveryKey as formatWalletRecoveryCode,
  EMAIL_OTP_RECOVERY_KEY_BYTE_LENGTH as WALLET_RECOVERY_CODE_BYTE_LENGTH,
  EMAIL_OTP_RECOVERY_KEY_COUNT as WALLET_RECOVERY_CODE_COUNT,
  type EmailOtpRecoveryCode as WalletRecoveryCode,
} from '../utils/emailOtpRecoveryKey';

/**
 * Issues the ten recovery codes that establishing custody requires.
 *
 * **This is Phase 2 work, not Phase 4's.** A ceremony that establishes custody
 * must issue its recovery set in the same act — the ceremony refuses to seal a
 * seed without ten codes, because an envelope with no recovery set is a working
 * wallet whose owner believes they hold codes that were never stored. Phase 4
 * owns what happens to codes afterwards: backup acknowledgement, rotation,
 * status, and the recovery UX.
 *
 * The codes are the only copy. Nothing here persists them, and the wraps the
 * ceremony seals are one-way — so a caller that discards this result without
 * showing it to the user has issued ten codes nobody can ever produce.
 */

export type IssuedWalletRecoveryCodes = {
  /** Formatted for display, in issue order. Show these once. */
  readonly codes: readonly WalletRecoveryCode[];
  /**
   * The same codes as bytes, in the same order, for the ceremony to wrap.
   *
   * Held separately rather than re-decoded at the seal site so the two can
   * never disagree about which code a wrap belongs to.
   */
  readonly codeBytes: readonly Uint8Array[];
};

/**
 * Mints ten codes from the platform CSPRNG.
 *
 * No id is derived here. The ceremony derives each code's id from the wallet
 * and the code bytes as it seals the wrap, so there is exactly one definition
 * of what an id is and a caller cannot supply one that names the wrong wrap.
 */
export function issueWalletRecoveryCodes(): IssuedWalletRecoveryCodes {
  const codes: WalletRecoveryCode[] = [];
  const codeBytes: Uint8Array[] = [];
  for (let index = 0; index < WALLET_RECOVERY_CODE_COUNT; index += 1) {
    const bytes = randomCodeBytes();
    codeBytes.push(bytes);
    codes.push(formatWalletRecoveryCode(encodeWalletRecoveryCodeBytes(bytes)));
  }
  return { codes, codeBytes };
}

/** Zeroizes the issued byte copies once the ceremony has wrapped them. */
export function zeroizeIssuedWalletRecoveryCodes(issued: IssuedWalletRecoveryCodes): void {
  for (const bytes of issued.codeBytes) bytes.fill(0);
}

function randomCodeBytes(): Uint8Array {
  const crypto = globalThis.crypto;
  if (!crypto?.getRandomValues) {
    // Never fall back to Math.random: these bytes are the wallet's last way
    // back in, and a predictable code is no code at all.
    throw new Error('a secure random source is required to issue wallet recovery codes');
  }
  return crypto.getRandomValues(new Uint8Array(WALLET_RECOVERY_CODE_BYTE_LENGTH));
}
