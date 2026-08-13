import { base64UrlDecode, base64UrlEncode } from '../utils/base64';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';

type PasskeyCustodyBrand<TName extends string> = {
  readonly __passkeyCustodyBrand: TName;
};

// Unpadded canonical base64url over the AEAD nonce for one sealed envelope.
export type EnvelopeNonceB64u = string & PasskeyCustodyBrand<'EnvelopeNonceB64u'>;

// Unpadded canonical base64url over AEAD ciphertext. It never holds plaintext
// custody material, PRF output, a KEK, or a recovery code.
export type EnvelopeCiphertextB64u = string & PasskeyCustodyBrand<'EnvelopeCiphertextB64u'>;

// 32-byte Ed25519 public key. This is public identity, not custody material.
export type Ed25519PublicKeyB64u = string & PasskeyCustodyBrand<'Ed25519PublicKeyB64u'>;

// 33-byte compressed secp256k1 point. This is public identity, not custody
// material.
export type Secp256k1CompressedPublicKeyB64u = string &
  PasskeyCustodyBrand<'Secp256k1CompressedPublicKeyB64u'>;

// Yao key-creation signer slot. Router A/B encodes this as a positive u32 and
// binds it into the Ed25519 application binding.
export type KeyCreationSignerSlot = number & PasskeyCustodyBrand<'KeyCreationSignerSlot'>;

// Monotonic compare-and-set revision for one envelope row. A browser cache is
// usable only at the exact server revision.
export type EnvelopeRevision = number & PasskeyCustodyBrand<'EnvelopeRevision'>;

const UNPADDED_BASE64URL = /^[A-Za-z0-9_-]+$/;

function requireCanonicalBase64Url(value: unknown, label: string): Uint8Array {
  if (typeof value !== 'string' || !UNPADDED_BASE64URL.test(value)) {
    throw new Error(`${label} must be unpadded base64url`);
  }
  let decoded: Uint8Array;
  try {
    decoded = base64UrlDecode(value);
  } catch {
    throw new Error(`${label} must be valid base64url`);
  }
  if (base64UrlEncode(decoded) !== value) {
    throw new Error(`${label} must be canonical base64url`);
  }
  return decoded;
}

// Wraps the canonical 32-byte digest parser so a failure names the field that
// carried the bad digest.
export function parseDigestField(value: unknown, label: string): DigestB64u {
  try {
    return parseDigestB64u(value);
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is not a digest'}`);
  }
}

// Frozen AEAD for every passkey custody wrap: ChaCha20Poly1305 (IETF) under an
// HKDF-SHA256-derived key, matching EMAIL_OTP_RECOVERY_WRAP_ALG and the
// Rust/WASM activated-Client seal.
export const PASSKEY_CUSTODY_WRAP_ALG_V1 = 'chacha20poly1305-hkdf-sha256-v1' as const;
export const PASSKEY_CUSTODY_WRAP_NONCE_LENGTH = 12 as const;
export const PASSKEY_CUSTODY_WRAP_TAG_LENGTH = 16 as const;

export function parseEnvelopeNonceB64u(value: unknown, label = 'nonceB64u'): EnvelopeNonceB64u {
  const decoded = requireCanonicalBase64Url(value, label);
  if (decoded.length !== PASSKEY_CUSTODY_WRAP_NONCE_LENGTH) {
    throw new Error(`${label} must decode to a 12-byte ChaCha20Poly1305 nonce`);
  }
  return value as EnvelopeNonceB64u;
}

export function parseEnvelopeCiphertextB64u(
  value: unknown,
  label = 'ciphertextB64u',
): EnvelopeCiphertextB64u {
  const decoded = requireCanonicalBase64Url(value, label);
  if (decoded.length < PASSKEY_CUSTODY_WRAP_TAG_LENGTH + 1) {
    throw new Error(`${label} must decode to sealed ciphertext with an authentication tag`);
  }
  return value as EnvelopeCiphertextB64u;
}

export function parseEd25519PublicKeyB64u(
  value: unknown,
  label = 'registeredPublicKeyB64u',
): Ed25519PublicKeyB64u {
  const decoded = requireCanonicalBase64Url(value, label);
  if (decoded.length !== 32) {
    throw new Error(`${label} must decode to a 32-byte Ed25519 public key`);
  }
  return value as Ed25519PublicKeyB64u;
}

export function parseSecp256k1CompressedPublicKeyB64u(
  value: unknown,
  label = 'publicKey33B64u',
): Secp256k1CompressedPublicKeyB64u {
  const decoded = requireCanonicalBase64Url(value, label);
  if (decoded.length !== 33) {
    throw new Error(`${label} must decode to a 33-byte compressed secp256k1 point`);
  }
  if (decoded[0] !== 0x02 && decoded[0] !== 0x03) {
    throw new Error(`${label} must be a compressed secp256k1 public key`);
  }
  return value as Secp256k1CompressedPublicKeyB64u;
}

export function parseKeyCreationSignerSlot(
  value: unknown,
  label = 'keyCreationSignerSlot',
): KeyCreationSignerSlot {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value <= 0 ||
    value > 0xffffffff
  ) {
    throw new Error(`${label} must be a positive u32`);
  }
  return value as KeyCreationSignerSlot;
}

export function parseEnvelopeRevision(
  value: unknown,
  label = 'envelopeRevision',
): EnvelopeRevision {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer revision`);
  }
  return value as EnvelopeRevision;
}

export function parseUnixMs(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive unix-millisecond timestamp`);
  }
  return value;
}

export function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

// Substrings that mean an unexpected field is carrying plaintext custody
// material rather than a public binding. Allowed fields are matched first, so
// this only classifies fields that are already being rejected — it exists to
// report a leak as a leak instead of a generic schema mismatch.
const SECRET_BEARING_FIELD_SUBSTRINGS = [
  'prf',
  'kek',
  'seed',
  'scalar',
  'secretkey',
  'privatekey',
  'plaintext',
  'recoverycode',
  'clientroot',
  'holdershare',
] as const;

/**
 * Rejects every field outside this record's exact shape.
 *
 * `knownOnOtherBranches` names fields that are legitimate public bindings
 * somewhere else in the same union. Those are reported as the branch mismatch
 * they are; only genuinely unknown fields are classified as leaks, so a public
 * key like `clientRootPublicKey33B64u` on the wrong branch is never mistaken
 * for plaintext custody material.
 */
export function rejectUnknownFields(
  record: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
  knownOnOtherBranches: readonly string[] = [],
): void {
  const allowedSet = new Set(allowed);
  const knownSet = new Set(knownOnOtherBranches);
  for (const field of Object.keys(record)) {
    if (allowedSet.has(field)) continue;
    if (knownSet.has(field)) {
      throw new Error(`${label}.${field} is not part of ${label}`);
    }
    const normalized = field.toLowerCase().replace(/_/g, '');
    // A field that names itself a public key is not plaintext custody
    // material, whatever else its name contains. `clientRootPublicKey33B64u`
    // matches `clientroot` but is a published point; reporting it as a leak
    // would send a reader hunting a secret that was never there.
    const namesAPublicKey = normalized.includes('publickey');
    if (
      !namesAPublicKey &&
      SECRET_BEARING_FIELD_SUBSTRINGS.some((substring) => normalized.includes(substring))
    ) {
      throw new Error(`${label}.${field} must never carry plaintext custody material`);
    }
    throw new Error(`${label}.${field} is not part of ${label}`);
  }
}
