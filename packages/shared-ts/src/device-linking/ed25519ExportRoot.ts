/**
 * Authenticated relay records for the cross-device Ed25519 Yao Client export
 * root. The relay sees only public routing facts and an encrypted root.
 * Wallet-custody seed bindings deliberately have no representation here.
 */
import {
  parseDigestField,
  parseEd25519PublicKeyB64u,
  parseEnvelopeCiphertextB64u,
  parseEnvelopeNonceB64u,
  rejectUnknownFields,
  requireRecord,
  type Ed25519PublicKeyB64u,
  type EnvelopeCiphertextB64u,
  type EnvelopeNonceB64u,
} from '../passkey-custody/primitives';
import type { DigestB64u } from '../utils/canonicalPrimitives';
import { base64UrlDecode, base64UrlEncode } from '../utils/base64';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseLinkDeviceSessionId,
  parseWalletKeyId,
  type LinkedDeviceEnrollmentId,
  type LinkedDeviceId,
  type LinkDeviceSessionId,
  type WalletKeyId,
} from '../signing-lanes/ids';
import {
  parseWalletId,
  type WalletId,
} from '../utils/domainIds';
import type { LinkedDeviceTargetFactorV1 } from './contracts';

/** Frozen by signer-core's Ed25519 Yao Client-root transfer module. */
export const LINKED_DEVICE_ED25519_EXPORT_ROOT_TRANSFER_ALG_V1 =
  'x25519-hkdf-sha256-chacha20poly1305-v1' as const;

const X25519_PUBLIC_KEY_LENGTH = 32 as const;
const UNPADDED_BASE64URL = /^[A-Za-z0-9_-]+$/;

/** One-use X25519 public key generated and retained by Device 2's worker. */
export type LinkedDeviceEd25519ExportRootRecipientPublicKeyB64u = string & {
  readonly __linkedDeviceEd25519ExportRootRecipientPublicKeyB64uBrand: 'LinkedDeviceEd25519ExportRootRecipientPublicKeyB64u';
};

/** Exact public facts authenticated by signer-core as transfer AAD. */
export type LinkedDeviceEd25519ExportRootTransferBindingV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly targetFactor: LinkedDeviceTargetFactorV1;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly revocationEpoch: number;
  readonly applicationBindingDigestB64u: DigestB64u;
  readonly registeredPublicKeyB64u: Ed25519PublicKeyB64u;
  readonly recipientPublicKeyB64u: LinkedDeviceEd25519ExportRootRecipientPublicKeyB64u;
};

/** Device 2's authenticated recipient registration. */
export type LinkedDeviceEd25519ExportRootRecipientV1 = {
  readonly kind: 'linked_device_ed25519_export_root_recipient_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly transferAlg: typeof LINKED_DEVICE_ED25519_EXPORT_ROOT_TRANSFER_ALG_V1;
  readonly applicationBindingDigestB64u: DigestB64u;
  readonly registeredPublicKeyB64u: Ed25519PublicKeyB64u;
  readonly targetFactor: LinkedDeviceTargetFactorV1;
  readonly revocationEpoch: number;
  readonly recipientPublicKeyB64u: LinkedDeviceEd25519ExportRootRecipientPublicKeyB64u;
  readonly registeredAtMs: number;
};

/** Device 1's encrypted export-root package. */
export type LinkedDeviceEd25519ExportRootPackageV1 = {
  readonly kind: 'linked_device_ed25519_export_root_package_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly transferAlg: typeof LINKED_DEVICE_ED25519_EXPORT_ROOT_TRANSFER_ALG_V1;
  readonly applicationBindingDigestB64u: DigestB64u;
  readonly registeredPublicKeyB64u: Ed25519PublicKeyB64u;
  readonly targetFactor: LinkedDeviceTargetFactorV1;
  readonly revocationEpoch: number;
  readonly recipientPublicKeyB64u: LinkedDeviceEd25519ExportRootRecipientPublicKeyB64u;
  readonly ephemeralPublicKeyB64u: LinkedDeviceEd25519ExportRootRecipientPublicKeyB64u;
  readonly nonceB64u: EnvelopeNonceB64u;
  readonly sealedExportRootB64u: EnvelopeCiphertextB64u;
  readonly bindingDigestB64u: DigestB64u;
  readonly ciphertextDigestB64u: DigestB64u;
  readonly sealedAtMs: number;
};

/** Device 1's authenticated submission of one package. */
export type LinkedDeviceEd25519ExportRootSubmissionV1 = {
  readonly kind: 'linked_device_ed25519_export_root_submission_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly package: LinkedDeviceEd25519ExportRootPackageV1;
};

const RECIPIENT_FIELDS = [
  'kind',
  'linkSessionId',
  'walletId',
  'walletKeyId',
  'enrollmentId',
  'deviceId',
  'transferAlg',
  'applicationBindingDigestB64u',
  'registeredPublicKeyB64u',
  'targetFactor',
  'revocationEpoch',
  'recipientPublicKeyB64u',
  'registeredAtMs',
] as const;

const PACKAGE_FIELDS = [
  'kind',
  'linkSessionId',
  'walletId',
  'walletKeyId',
  'enrollmentId',
  'deviceId',
  'transferAlg',
  'applicationBindingDigestB64u',
  'registeredPublicKeyB64u',
  'targetFactor',
  'revocationEpoch',
  'recipientPublicKeyB64u',
  'ephemeralPublicKeyB64u',
  'nonceB64u',
  'sealedExportRootB64u',
  'bindingDigestB64u',
  'ciphertextDigestB64u',
  'sealedAtMs',
] as const;

const SUBMISSION_FIELDS = ['kind', 'linkSessionId', 'package'] as const;

export function parseLinkedDeviceEd25519ExportRootRecipientPublicKeyB64u(
  value: unknown,
  label = 'recipientPublicKeyB64u',
): LinkedDeviceEd25519ExportRootRecipientPublicKeyB64u {
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
  return value as LinkedDeviceEd25519ExportRootRecipientPublicKeyB64u;
}

export function buildLinkedDeviceEd25519ExportRootTransferBindingV1(input: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly targetFactor: LinkedDeviceTargetFactorV1;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly revocationEpoch: number;
  readonly applicationBindingDigestB64u: DigestB64u;
  readonly registeredPublicKeyB64u: Ed25519PublicKeyB64u;
  readonly recipientPublicKeyB64u: LinkedDeviceEd25519ExportRootRecipientPublicKeyB64u;
}): LinkedDeviceEd25519ExportRootTransferBindingV1 {
  return {
    linkSessionId: input.linkSessionId,
    walletId: input.walletId,
    walletKeyId: input.walletKeyId,
    targetFactor: input.targetFactor,
    enrollmentId: input.enrollmentId,
    deviceId: input.deviceId,
    revocationEpoch: input.revocationEpoch,
    applicationBindingDigestB64u: input.applicationBindingDigestB64u,
    registeredPublicKeyB64u: input.registeredPublicKeyB64u,
    recipientPublicKeyB64u: input.recipientPublicKeyB64u,
  };
}

/** Serializes exactly the six fields accepted by signer-core's AAD binding. */
export function serializeLinkedDeviceEd25519ExportRootTransferBindingV1(
  binding: LinkedDeviceEd25519ExportRootTransferBindingV1,
): string {
  return JSON.stringify({
    linkSessionId: String(binding.linkSessionId),
    walletId: String(binding.walletId),
    walletKeyId: String(binding.walletKeyId),
    targetFactor: binding.targetFactor,
    enrollmentId: String(binding.enrollmentId),
    deviceId: String(binding.deviceId),
    revocationEpoch: binding.revocationEpoch,
    applicationBindingDigestB64u: String(binding.applicationBindingDigestB64u),
    registeredPublicKeyB64u: String(binding.registeredPublicKeyB64u),
    recipientPublicKeyB64u: String(binding.recipientPublicKeyB64u),
  });
}

export function parseLinkedDeviceEd25519ExportRootRecipientV1(
  raw: unknown,
): LinkedDeviceEd25519ExportRootRecipientV1 {
  const record = exactRecord(raw, RECIPIENT_FIELDS, 'LinkedDeviceEd25519ExportRootRecipientV1');
  if (record.kind !== 'linked_device_ed25519_export_root_recipient_v1') {
    throw new Error('LinkedDeviceEd25519ExportRootRecipientV1.kind is invalid');
  }
  requireTransferAlg(record.transferAlg, 'LinkedDeviceEd25519ExportRootRecipientV1.transferAlg');
  return {
    kind: 'linked_device_ed25519_export_root_recipient_v1',
    linkSessionId: parseRequired(
      parseLinkDeviceSessionId(record.linkSessionId),
      'LinkedDeviceEd25519ExportRootRecipientV1.linkSessionId',
    ),
    walletId: parseRequired(parseWalletId(record.walletId), 'walletId'),
    walletKeyId: parseRequired(parseWalletKeyId(record.walletKeyId), 'walletKeyId'),
    enrollmentId: parseRequired(parseLinkedDeviceEnrollmentId(record.enrollmentId), 'enrollmentId'),
    deviceId: parseRequired(parseLinkedDeviceId(record.deviceId), 'deviceId'),
    transferAlg: LINKED_DEVICE_ED25519_EXPORT_ROOT_TRANSFER_ALG_V1,
    applicationBindingDigestB64u: parseDigestField(
      record.applicationBindingDigestB64u,
      'applicationBindingDigestB64u',
    ),
    registeredPublicKeyB64u: parseEd25519PublicKeyB64u(
      record.registeredPublicKeyB64u,
      'registeredPublicKeyB64u',
    ),
    targetFactor: parseTargetFactor(record.targetFactor),
    revocationEpoch: parseRevocationEpoch(record.revocationEpoch, 'revocationEpoch'),
    recipientPublicKeyB64u: parseLinkedDeviceEd25519ExportRootRecipientPublicKeyB64u(
      record.recipientPublicKeyB64u,
      'recipientPublicKeyB64u',
    ),
    registeredAtMs: parseUnixMs(record.registeredAtMs, 'registeredAtMs'),
  };
}

export function parseLinkedDeviceEd25519ExportRootPackageV1(
  raw: unknown,
): LinkedDeviceEd25519ExportRootPackageV1 {
  const record = exactRecord(raw, PACKAGE_FIELDS, 'LinkedDeviceEd25519ExportRootPackageV1');
  if (record.kind !== 'linked_device_ed25519_export_root_package_v1') {
    throw new Error('LinkedDeviceEd25519ExportRootPackageV1.kind is invalid');
  }
  requireTransferAlg(record.transferAlg, 'LinkedDeviceEd25519ExportRootPackageV1.transferAlg');
  const recipientPublicKeyB64u = parseLinkedDeviceEd25519ExportRootRecipientPublicKeyB64u(
    record.recipientPublicKeyB64u,
    'recipientPublicKeyB64u',
  );
  const ephemeralPublicKeyB64u = parseLinkedDeviceEd25519ExportRootRecipientPublicKeyB64u(
    record.ephemeralPublicKeyB64u,
    'ephemeralPublicKeyB64u',
  );
  if (recipientPublicKeyB64u === ephemeralPublicKeyB64u) {
    throw new Error('ephemeralPublicKeyB64u repeats the recipient key');
  }
  return {
    kind: 'linked_device_ed25519_export_root_package_v1',
    linkSessionId: parseRequired(parseLinkDeviceSessionId(record.linkSessionId), 'linkSessionId'),
    walletId: parseRequired(parseWalletId(record.walletId), 'walletId'),
    walletKeyId: parseRequired(parseWalletKeyId(record.walletKeyId), 'walletKeyId'),
    enrollmentId: parseRequired(parseLinkedDeviceEnrollmentId(record.enrollmentId), 'enrollmentId'),
    deviceId: parseRequired(parseLinkedDeviceId(record.deviceId), 'deviceId'),
    transferAlg: LINKED_DEVICE_ED25519_EXPORT_ROOT_TRANSFER_ALG_V1,
    applicationBindingDigestB64u: parseDigestField(
      record.applicationBindingDigestB64u,
      'applicationBindingDigestB64u',
    ),
    registeredPublicKeyB64u: parseEd25519PublicKeyB64u(
      record.registeredPublicKeyB64u,
      'registeredPublicKeyB64u',
    ),
    targetFactor: parseTargetFactor(record.targetFactor),
    revocationEpoch: parseRevocationEpoch(record.revocationEpoch, 'revocationEpoch'),
    recipientPublicKeyB64u,
    ephemeralPublicKeyB64u,
    nonceB64u: parseEnvelopeNonceB64u(record.nonceB64u, 'nonceB64u'),
    sealedExportRootB64u: parseEnvelopeCiphertextB64u(
      record.sealedExportRootB64u,
      'sealedExportRootB64u',
    ),
    bindingDigestB64u: parseDigestField(record.bindingDigestB64u, 'bindingDigestB64u'),
    ciphertextDigestB64u: parseDigestField(record.ciphertextDigestB64u, 'ciphertextDigestB64u'),
    sealedAtMs: parseUnixMs(record.sealedAtMs, 'sealedAtMs'),
  };
}

export function parseLinkedDeviceEd25519ExportRootSubmissionV1(
  raw: unknown,
): LinkedDeviceEd25519ExportRootSubmissionV1 {
  const record = exactRecord(raw, SUBMISSION_FIELDS, 'LinkedDeviceEd25519ExportRootSubmissionV1');
  if (record.kind !== 'linked_device_ed25519_export_root_submission_v1') {
    throw new Error('LinkedDeviceEd25519ExportRootSubmissionV1.kind is invalid');
  }
  return {
    kind: 'linked_device_ed25519_export_root_submission_v1',
    linkSessionId: parseRequired(parseLinkDeviceSessionId(record.linkSessionId), 'linkSessionId'),
    package: parseLinkedDeviceEd25519ExportRootPackageV1(record.package),
  };
}

/** Ensures relay persistence cannot join two different root bindings. */
export function linkedDeviceEd25519ExportRootMatchesRecipientV1(
  transferPackage: LinkedDeviceEd25519ExportRootPackageV1,
  recipient: LinkedDeviceEd25519ExportRootRecipientV1,
): boolean {
  return (
    transferPackage.linkSessionId === recipient.linkSessionId &&
    transferPackage.walletId === recipient.walletId &&
    transferPackage.walletKeyId === recipient.walletKeyId &&
    transferPackage.enrollmentId === recipient.enrollmentId &&
    transferPackage.deviceId === recipient.deviceId &&
    transferPackage.transferAlg === recipient.transferAlg &&
    transferPackage.applicationBindingDigestB64u === recipient.applicationBindingDigestB64u &&
    transferPackage.registeredPublicKeyB64u === recipient.registeredPublicKeyB64u &&
    transferPackage.targetFactor.kind === recipient.targetFactor.kind &&
    transferPackage.revocationEpoch === recipient.revocationEpoch &&
    transferPackage.recipientPublicKeyB64u === recipient.recipientPublicKeyB64u
  );
}

function parseTargetFactor(raw: unknown): LinkedDeviceTargetFactorV1 {
  const record = exactRecord(raw, ['kind'], 'targetFactor');
  switch (record.kind) {
    case 'passkey_prf':
      return { kind: 'passkey_prf' };
    case 'email_otp':
      return { kind: 'email_otp' };
    default:
      throw new Error('targetFactor.kind is unsupported');
  }
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
  if (value !== LINKED_DEVICE_ED25519_EXPORT_ROOT_TRANSFER_ALG_V1) {
    throw new Error(`${label} must be ${LINKED_DEVICE_ED25519_EXPORT_ROOT_TRANSFER_ALG_V1}`);
  }
}

function parseRevocationEpoch(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return value;
}

function parseUnixMs(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive unix-millisecond timestamp`);
  }
  return value;
}

function parseRequired<T>(
  parsed:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (!parsed.ok) throw new Error(`${label} ${parsed.error.message}`);
  return parsed.value;
}
