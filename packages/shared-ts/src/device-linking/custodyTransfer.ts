/**
 * Refactor 103 Phase 8 — the wire contract for carrying a wallet custody seed
 * from the approving owner device to a newly linked one.
 *
 * The crypto lives in `signer_core::linked_device_custody_transfer`; this is
 * the boundary the relay, the server, and both browsers agree on. Two shapes
 * cross it, and neither carries a secret:
 *
 *   Device 2 -> server -> Device 1 : the recipient public key to seal to
 *   Device 1 -> server -> Device 2 : the sealed package
 *
 * The binding is reconstructed independently on both devices and authenticated
 * as AEAD additional data, so it is not merely a description of the package —
 * substituting any field makes the package fail to open. That is why the same
 * type is used to *build* the transfer on Device 1 and to *verify* it on
 * Device 2 rather than trusting a server-supplied copy.
 */
import type { PasskeyCustodySecretBinding } from '../passkey-custody/custodySecretBinding';
import { parsePasskeyCustodySecretBinding } from '../passkey-custody/custodySecretBinding';
import {
  parseDigestField,
  parseEnvelopeCiphertextB64u,
  parseEnvelopeNonceB64u,
  rejectUnknownFields,
  requireRecord,
  type EnvelopeCiphertextB64u,
  type EnvelopeNonceB64u,
} from '../passkey-custody/primitives';
import { base64UrlDecode, base64UrlEncode } from '../utils/base64';
import type { DigestB64u } from '../utils/canonicalPrimitives';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  type LinkedDeviceEnrollmentId,
  type LinkedDeviceId,
} from '../signing-lanes/ids';
import { parseWalletId, type WalletId } from '../utils/domainIds';

/** Frozen wrap for the cross-device transfer. Mirrors the Rust constant. */
export const LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1 =
  'x25519-hkdf-sha256-chacha20poly1305-v1' as const;

const X25519_PUBLIC_KEY_LENGTH = 32 as const;
const UNPADDED_BASE64URL = /^[A-Za-z0-9_-]+$/;

/**
 * A 32-byte X25519 public key used by exactly one linked-device transfer.
 *
 * Distinct from `LinkDevicePublicKeyB64u`, which brands the QR's link key.
 * They are different keys held by different workers on purpose: the QR key
 * lives in the device-linking key worker as a non-extractable `CryptoKey`,
 * and the custody transfer must decapsulate inside the custody module so the
 * seed never reaches JavaScript. Separate brands stop one being passed where
 * the other is meant.
 */
export type LinkedDeviceCustodyTransferPublicKeyB64u = string & {
  readonly __linkedDeviceCustodyTransferPublicKeyB64uBrand: 'LinkedDeviceCustodyTransferPublicKeyB64u';
};

/** The transfer carries the wallet custody seed and nothing else. */
export type LinkedDeviceCustodyTransferSecretBindingV1 = Extract<
  PasskeyCustodySecretBinding,
  { readonly kind: 'wallet_custody_seed_v1' }
>;

/**
 * The public facts one transfer is bound to.
 *
 * Field names and order match the Rust struct's serde representation exactly;
 * that struct is `deny_unknown_fields`, so an extra field here is a hard
 * failure at the wasm boundary rather than a silently ignored value.
 */
export type LinkedDeviceCustodyTransferBindingV1 = {
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly recipientPublicKeyB64u: LinkedDeviceCustodyTransferPublicKeyB64u;
  readonly binding: LinkedDeviceCustodyTransferSecretBindingV1;
};

/**
 * Device 2's published recipient key.
 *
 * Registered with the claimed session so Device 1 learns where to seal. The
 * private half is generated inside Device 2's custody module and never leaves
 * it, so this is a public routing fact and not custody material.
 */
export type LinkedDeviceCustodyTransferRecipientV1 = {
  readonly kind: 'linked_device_custody_transfer_recipient_v1';
  readonly linkSessionId: string;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly transferAlg: typeof LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1;
  readonly recipientPublicKeyB64u: LinkedDeviceCustodyTransferPublicKeyB64u;
  readonly registeredAtMs: number;
};

/**
 * The sealed package Device 1 produces.
 *
 * Everything here is opaque or public: ciphertext, the ephemeral public key,
 * the nonce, and the two digests both sides compare before use. The seed, the
 * owner PRF, and the derived transfer key stay inside their workers.
 */
export type LinkedDeviceCustodyTransferPackageV1 = {
  readonly kind: 'linked_device_custody_transfer_package_v1';
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly transferAlg: typeof LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1;
  readonly recipientPublicKeyB64u: LinkedDeviceCustodyTransferPublicKeyB64u;
  readonly ephemeralPublicKeyB64u: LinkedDeviceCustodyTransferPublicKeyB64u;
  readonly nonceB64u: EnvelopeNonceB64u;
  readonly sealedCustodySecretB64u: EnvelopeCiphertextB64u;
  readonly aadHashB64u: DigestB64u;
  readonly ciphertextDigestB64u: DigestB64u;
  readonly sealedAtMs: number;
};

/** Device 1's authenticated submission of a prepared transfer. */
export type LinkedDeviceCustodyTransferSubmissionV1 = {
  readonly kind: 'linked_device_custody_transfer_submission_v1';
  readonly linkSessionId: string;
  readonly package: LinkedDeviceCustodyTransferPackageV1;
};

const RECIPIENT_FIELDS = [
  'kind',
  'linkSessionId',
  'walletId',
  'enrollmentId',
  'deviceId',
  'transferAlg',
  'recipientPublicKeyB64u',
  'registeredAtMs',
] as const;

const PACKAGE_FIELDS = [
  'kind',
  'walletId',
  'enrollmentId',
  'deviceId',
  'transferAlg',
  'recipientPublicKeyB64u',
  'ephemeralPublicKeyB64u',
  'nonceB64u',
  'sealedCustodySecretB64u',
  'aadHashB64u',
  'ciphertextDigestB64u',
  'sealedAtMs',
] as const;

const SUBMISSION_FIELDS = ['kind', 'linkSessionId', 'package'] as const;

export function parseLinkedDeviceCustodyTransferPublicKeyB64u(
  value: unknown,
  label = 'recipientPublicKeyB64u',
): LinkedDeviceCustodyTransferPublicKeyB64u {
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
  if (decoded.length !== X25519_PUBLIC_KEY_LENGTH) {
    throw new Error(`${label} must decode to a 32-byte X25519 public key`);
  }
  return value as LinkedDeviceCustodyTransferPublicKeyB64u;
}

export function parseLinkedDeviceCustodyTransferSecretBindingV1(
  value: unknown,
  label = 'LinkedDeviceCustodyTransferBindingV1.binding',
): LinkedDeviceCustodyTransferSecretBindingV1 {
  const binding = parsePasskeyCustodySecretBinding(value, label);
  if (binding.kind !== 'wallet_custody_seed_v1') {
    throw new Error(`${label} must be the wallet custody seed binding`);
  }
  return binding;
}

/**
 * Builds the exact object handed to the wasm boundary.
 *
 * Constructed field by field rather than spread from a wider record: the Rust
 * struct rejects unknown fields, and an accidental extra key would surface as
 * an opaque deserialization error at the point where a seed is about to be
 * sealed.
 */
export function buildLinkedDeviceCustodyTransferBindingV1(input: {
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly recipientPublicKeyB64u: LinkedDeviceCustodyTransferPublicKeyB64u;
  readonly binding: LinkedDeviceCustodyTransferSecretBindingV1;
}): LinkedDeviceCustodyTransferBindingV1 {
  return {
    walletId: input.walletId,
    enrollmentId: input.enrollmentId,
    deviceId: input.deviceId,
    recipientPublicKeyB64u: input.recipientPublicKeyB64u,
    binding: input.binding,
  };
}

/** Serializes the binding for the wasm boundary with no extra fields. */
export function serializeLinkedDeviceCustodyTransferBindingV1(
  binding: LinkedDeviceCustodyTransferBindingV1,
): string {
  return JSON.stringify({
    walletId: String(binding.walletId),
    enrollmentId: String(binding.enrollmentId),
    deviceId: String(binding.deviceId),
    recipientPublicKeyB64u: String(binding.recipientPublicKeyB64u),
    binding: {
      kind: binding.binding.kind,
      derivationScheme: binding.binding.derivationScheme,
    },
  });
}

export function parseLinkedDeviceCustodyTransferRecipientV1(
  raw: unknown,
): LinkedDeviceCustodyTransferRecipientV1 {
  const record = exactRecord(
    raw,
    RECIPIENT_FIELDS,
    'LinkedDeviceCustodyTransferRecipientV1',
  );
  if (record.kind !== 'linked_device_custody_transfer_recipient_v1') {
    throw new Error('LinkedDeviceCustodyTransferRecipientV1.kind is invalid');
  }
  requireTransferAlg(record.transferAlg, 'LinkedDeviceCustodyTransferRecipientV1.transferAlg');
  return {
    kind: 'linked_device_custody_transfer_recipient_v1',
    linkSessionId: requireCanonicalToken(
      record.linkSessionId,
      'LinkedDeviceCustodyTransferRecipientV1.linkSessionId',
    ),
    walletId: requireParsed(
      parseWalletId(record.walletId),
      'LinkedDeviceCustodyTransferRecipientV1.walletId',
    ),
    enrollmentId: requireParsed(
      parseLinkedDeviceEnrollmentId(record.enrollmentId),
      'LinkedDeviceCustodyTransferRecipientV1.enrollmentId',
    ),
    deviceId: requireParsed(
      parseLinkedDeviceId(record.deviceId),
      'LinkedDeviceCustodyTransferRecipientV1.deviceId',
    ),
    transferAlg: LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1,
    recipientPublicKeyB64u: parseLinkedDeviceCustodyTransferPublicKeyB64u(
      record.recipientPublicKeyB64u,
      'LinkedDeviceCustodyTransferRecipientV1.recipientPublicKeyB64u',
    ),
    registeredAtMs: requireUnixMs(
      record.registeredAtMs,
      'LinkedDeviceCustodyTransferRecipientV1.registeredAtMs',
    ),
  };
}

export function parseLinkedDeviceCustodyTransferPackageV1(
  raw: unknown,
): LinkedDeviceCustodyTransferPackageV1 {
  const record = exactRecord(raw, PACKAGE_FIELDS, 'LinkedDeviceCustodyTransferPackageV1');
  if (record.kind !== 'linked_device_custody_transfer_package_v1') {
    throw new Error('LinkedDeviceCustodyTransferPackageV1.kind is invalid');
  }
  requireTransferAlg(record.transferAlg, 'LinkedDeviceCustodyTransferPackageV1.transferAlg');
  const recipientPublicKeyB64u = parseLinkedDeviceCustodyTransferPublicKeyB64u(
    record.recipientPublicKeyB64u,
    'LinkedDeviceCustodyTransferPackageV1.recipientPublicKeyB64u',
  );
  const ephemeralPublicKeyB64u = parseLinkedDeviceCustodyTransferPublicKeyB64u(
    record.ephemeralPublicKeyB64u,
    'LinkedDeviceCustodyTransferPackageV1.ephemeralPublicKeyB64u',
  );
  // An ephemeral key equal to the recipient's would mean the sender reused the
  // published key rather than generating one, which is never a valid seal.
  if (ephemeralPublicKeyB64u === recipientPublicKeyB64u) {
    throw new Error(
      'LinkedDeviceCustodyTransferPackageV1.ephemeralPublicKeyB64u repeats the recipient key',
    );
  }
  return {
    kind: 'linked_device_custody_transfer_package_v1',
    walletId: requireParsed(
      parseWalletId(record.walletId),
      'LinkedDeviceCustodyTransferPackageV1.walletId',
    ),
    enrollmentId: requireParsed(
      parseLinkedDeviceEnrollmentId(record.enrollmentId),
      'LinkedDeviceCustodyTransferPackageV1.enrollmentId',
    ),
    deviceId: requireParsed(
      parseLinkedDeviceId(record.deviceId),
      'LinkedDeviceCustodyTransferPackageV1.deviceId',
    ),
    transferAlg: LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1,
    recipientPublicKeyB64u,
    ephemeralPublicKeyB64u,
    nonceB64u: parseEnvelopeNonceB64u(
      record.nonceB64u,
      'LinkedDeviceCustodyTransferPackageV1.nonceB64u',
    ),
    sealedCustodySecretB64u: parseEnvelopeCiphertextB64u(
      record.sealedCustodySecretB64u,
      'LinkedDeviceCustodyTransferPackageV1.sealedCustodySecretB64u',
    ),
    aadHashB64u: parseDigestField(
      record.aadHashB64u,
      'LinkedDeviceCustodyTransferPackageV1.aadHashB64u',
    ),
    ciphertextDigestB64u: parseDigestField(
      record.ciphertextDigestB64u,
      'LinkedDeviceCustodyTransferPackageV1.ciphertextDigestB64u',
    ),
    sealedAtMs: requireUnixMs(
      record.sealedAtMs,
      'LinkedDeviceCustodyTransferPackageV1.sealedAtMs',
    ),
  };
}

export function parseLinkedDeviceCustodyTransferSubmissionV1(
  raw: unknown,
): LinkedDeviceCustodyTransferSubmissionV1 {
  const record = exactRecord(
    raw,
    SUBMISSION_FIELDS,
    'LinkedDeviceCustodyTransferSubmissionV1',
  );
  if (record.kind !== 'linked_device_custody_transfer_submission_v1') {
    throw new Error('LinkedDeviceCustodyTransferSubmissionV1.kind is invalid');
  }
  return {
    kind: 'linked_device_custody_transfer_submission_v1',
    linkSessionId: requireCanonicalToken(
      record.linkSessionId,
      'LinkedDeviceCustodyTransferSubmissionV1.linkSessionId',
    ),
    package: parseLinkedDeviceCustodyTransferPackageV1(record.package),
  };
}

/**
 * True when a package was sealed for exactly this recipient registration.
 *
 * The AEAD would reject a mismatch anyway; checking here means Device 2 fails
 * with a routing error naming the wrong field instead of an opaque decrypt
 * failure.
 */
export function linkedDeviceCustodyTransferMatchesRecipientV1(
  transferPackage: LinkedDeviceCustodyTransferPackageV1,
  recipient: LinkedDeviceCustodyTransferRecipientV1,
): boolean {
  return (
    transferPackage.walletId === recipient.walletId &&
    transferPackage.enrollmentId === recipient.enrollmentId &&
    transferPackage.deviceId === recipient.deviceId &&
    transferPackage.recipientPublicKeyB64u === recipient.recipientPublicKeyB64u
  );
}

function exactRecord(
  raw: unknown,
  fields: readonly string[],
  label: string,
): Record<string, unknown> {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, fields, label);
  for (const field of fields) {
    if (record[field] === undefined) throw new Error(`${label}.${field} is required`);
  }
  return record;
}

function requireTransferAlg(value: unknown, label: string): void {
  if (value !== LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1) {
    throw new Error(`${label} must be ${LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1}`);
  }
}

function requireCanonicalToken(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value || value.trim() !== value) {
    throw new Error(`${label} must be a non-empty canonical string`);
  }
  return value;
}

function requireUnixMs(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive unix-millisecond timestamp`);
  }
  return value;
}

function requireParsed<T>(
  parsed:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (!parsed.ok) throw new Error(`${label} ${parsed.error.message}`);
  return parsed.value;
}
