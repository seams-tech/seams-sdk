import { encodeSigningSessionHkdfTuple } from '../utils/signingSessionSeal';
import { base64UrlEncode } from '../utils/encoders';
import {
  decodeEmailOtpRecoveryKey as decodeWalletRecoveryCode,
  normalizeEmailOtpRecoveryKey as normalizeWalletRecoveryCode,
} from '../utils/emailOtpRecoveryKey';

/**
 * The identity of one recovery code inside a wallet's custody set.
 *
 * **Wallet-scoped, and factor-neutral on purpose.** The Email OTP id it
 * replaces (`deriveEmailOtpRecoveryKeyId`) puts `enrollmentVersion` and
 * `enrollmentSealKeyVersion` in its tuple, so it cannot mint an id for a
 * passkey wallet — which has no enrollment at all. A wallet custody recovery
 * set belongs to the wallet, not to whichever factor happened to establish it,
 * exactly as the seed and the continuity cache do.
 *
 * The code-wrap crypto around it is already wallet-scoped and unchanged:
 * `WalletRecoveryCodeScopeV1` is `{ wallet_id, recovery_key_id }`, and
 * `encode_recovery_manifest_aad_v1` binds a wrap to the set version, wrap
 * algorithm, wallet id, this id, and the manifest-KEK purpose. This module adds
 * only the id those bindings name.
 *
 * The id is a *label*, not key material. It exists so a stored wrap can be
 * found by the code the user typed without revealing which code it is: the
 * digest is one-way, so a stored id identifies a wrap while telling a reader
 * with the record nothing about the code that opens it.
 */

declare const walletRecoveryKeyIdBrand: unique symbol;

export type DerivedWalletRecoveryKeyId = string & {
  readonly [walletRecoveryKeyIdBrand]: 'DerivedWalletRecoveryKeyId';
};

export const WALLET_RECOVERY_KEY_ID_PREFIX_V1 = 'wallet-rkid-v1-' as const;

const WALLET_RECOVERY_KEY_ID_CONTEXT_V1 = 'seams/wallet-recovery/recovery-key-id/v1';
const WALLET_RECOVERY_ENVELOPE_SET_VERSION_V1 = 'wallet_recovery_envelope_set_v1';

/** The prefix plus unpadded base64url over one SHA-256 digest. */
const DERIVED_WALLET_RECOVERY_KEY_ID_PATTERN = /^wallet-rkid-v1-[A-Za-z0-9_-]{43}$/;

export function parseDerivedWalletRecoveryKeyId(
  value: unknown,
  label = 'recoveryKeyId',
): DerivedWalletRecoveryKeyId {
  if (typeof value !== 'string' || !DERIVED_WALLET_RECOVERY_KEY_ID_PATTERN.test(value)) {
    throw new Error(`${label} must be a derived wallet recovery key id`);
  }
  return value as DerivedWalletRecoveryKeyId;
}

export function isDerivedWalletRecoveryKeyId(value: unknown): value is DerivedWalletRecoveryKeyId {
  return typeof value === 'string' && DERIVED_WALLET_RECOVERY_KEY_ID_PATTERN.test(value);
}

/**
 * Derives one code's id within a wallet's recovery set.
 *
 * Bound to the wallet and the set version, so the same code typed against a
 * different wallet produces a different id and finds no wrap. Length-delimited
 * fields under a fixed context, so no two inputs encode alike.
 *
 * The decoded code bytes are zeroized before returning, including on failure —
 * the code is the factor that opens the seed, and it must not outlive this
 * call in a buffer the caller cannot see.
 */
export async function deriveWalletRecoveryKeyId(args: {
  readonly recoveryCode: string;
  readonly walletId: string;
  readonly setVersion?: string;
}): Promise<DerivedWalletRecoveryKeyId> {
  const codeBytes = decodeWalletRecoveryCode(normalizeWalletRecoveryCode(args.recoveryCode));
  try {
    return await deriveWalletRecoveryKeyIdFromBytes({
      codeBytes,
      walletId: args.walletId,
      ...(args.setVersion === undefined ? {} : { setVersion: args.setVersion }),
    });
  } finally {
    zeroize(codeBytes);
  }
}

/**
 * The same derivation from decoded bytes.
 *
 * Separate entry point because the ceremony seals wraps from bytes it already
 * holds, while a user typing a code arrives as a string. Both must reach one
 * id, so both go through this.
 */
export async function deriveWalletRecoveryKeyIdFromBytes(args: {
  readonly codeBytes: Uint8Array;
  readonly walletId: string;
  readonly setVersion?: string;
}): Promise<DerivedWalletRecoveryKeyId> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required to derive a wallet recovery key id');
  const codeBytes = args.codeBytes;
  if (!codeBytes?.length) {
    throw new Error('recovery code bytes are required to derive a wallet recovery key id');
  }

  let tuple: Uint8Array | null = null;
  try {
    /* The frozen tuple, in this exact order. `derive_wallet_recovery_key_id_v1`
       in signer-core hashes the same four length-prefixed values, so the id a
       recovery lookup computes here equals the one the ceremony sealed. The
       cross-boundary vector test is what holds the two together. */
    tuple = encodeSigningSessionHkdfTuple([
      WALLET_RECOVERY_KEY_ID_CONTEXT_V1,
      base64UrlEncode(codeBytes),
      walletId,
      args.setVersion ?? WALLET_RECOVERY_ENVELOPE_SET_VERSION_V1,
    ]);
    const digest = await sha256Bytes(tuple);
    return `${WALLET_RECOVERY_KEY_ID_PREFIX_V1}${base64UrlEncode(digest)}` as DerivedWalletRecoveryKeyId;
  } finally {
    // The caller owns `codeBytes` here; only the tuple this built is ours.
    zeroize(tuple);
  }
}

async function sha256Bytes(input: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('WebCrypto is unavailable for wallet recovery key id derivation');
  const buffer = new ArrayBuffer(input.byteLength);
  new Uint8Array(buffer).set(input);
  return new Uint8Array(await subtle.digest('SHA-256', buffer));
}

function zeroize(value: Uint8Array | null): void {
  if (value) value.fill(0);
}
