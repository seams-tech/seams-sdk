import { sha256Bytes } from '../utils/digests';
import { base64UrlEncode } from '../utils/encoders';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import {
  decodeEmailOtpRecoveryKey,
  normalizeEmailOtpRecoveryKey,
  EMAIL_OTP_RECOVERY_KEY_BYTE_LENGTH,
} from '../utils/emailOtpRecoveryKey';
import type { DerivedWalletRecoveryKeyId } from './recoveryKeyId';

/** The code-only digest used to locate a wallet recovery set. */
export type RecoveryCodeLocatorV1 = DigestB64u;

export type WalletRecoveryCodeLocatorRecordV1 = {
  readonly locatorB64u: RecoveryCodeLocatorV1;
  readonly recoveryKeyId: DerivedWalletRecoveryKeyId;
};

const RECOVERY_CODE_LOCATOR_CONTEXT_V1 = 'seams/wallet-recovery/code-locator/v1';

export function parseRecoveryCodeLocatorV1(
  value: unknown,
  label = 'recoveryCodeLocator',
): RecoveryCodeLocatorV1 {
  try {
    return parseDigestB64u(value);
  } catch (error: unknown) {
    throw new Error(
      `${label} ${error instanceof Error ? error.message : 'must be a canonical digest'}`,
    );
  }
}

/**
 * Derives the code-only locator from the normalized recovery code.
 *
 * The locator identifies a set for lookup. It never replaces the existing
 * wallet-bound recovery-key derivation that authenticates a wrap.
 */
export async function deriveRecoveryCodeLocatorV1(
  recoveryCode: string,
): Promise<RecoveryCodeLocatorV1> {
  const codeBytes = decodeEmailOtpRecoveryKey(normalizeEmailOtpRecoveryKey(recoveryCode));
  try {
    return await deriveRecoveryCodeLocatorV1FromBytes(codeBytes);
  } finally {
    codeBytes.fill(0);
  }
}

export async function deriveRecoveryCodeLocatorV1FromBytes(
  codeBytes: Uint8Array,
): Promise<RecoveryCodeLocatorV1> {
  if (
    !(codeBytes instanceof Uint8Array) ||
    codeBytes.length !== EMAIL_OTP_RECOVERY_KEY_BYTE_LENGTH
  ) {
    throw new Error(
      `recovery code bytes must be exactly ${EMAIL_OTP_RECOVERY_KEY_BYTE_LENGTH} bytes`,
    );
  }
  let tuple: Uint8Array | null = null;
  try {
    const contextBytes = new TextEncoder().encode(RECOVERY_CODE_LOCATOR_CONTEXT_V1);
    tuple = new Uint8Array(8 + contextBytes.length + codeBytes.length);
    const view = new DataView(tuple.buffer);
    view.setUint32(0, contextBytes.length, false);
    tuple.set(contextBytes, 4);
    view.setUint32(4 + contextBytes.length, codeBytes.length, false);
    tuple.set(codeBytes, 8 + contextBytes.length);
    return parseRecoveryCodeLocatorV1(base64UrlEncode(await sha256Bytes(tuple)));
  } finally {
    tuple?.fill(0);
  }
}

export async function deriveRecoveryCodeLocatorRecordsV1(
  inputs: readonly {
    readonly codeBytes: Uint8Array;
    readonly recoveryKeyId: DerivedWalletRecoveryKeyId;
  }[],
): Promise<readonly WalletRecoveryCodeLocatorRecordV1[]> {
  return await Promise.all(
    inputs.map(async (input) => ({
      locatorB64u: await deriveRecoveryCodeLocatorV1FromBytes(input.codeBytes),
      recoveryKeyId: input.recoveryKeyId,
    })),
  );
}
