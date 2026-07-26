import { base64UrlDecode, base64UrlEncode } from './base64';
import { alphabetizeStringify } from './digests';

type EcdsaCapabilityBrand<TName extends string> = {
  readonly __ecdsaCapabilityBrand: TName;
};

export type EvmFamilyEcdsaSignerId = string & EcdsaCapabilityBrand<'EvmFamilyEcdsaSignerId'>;
export type EcdsaServerGeneration = string & EcdsaCapabilityBrand<'EcdsaServerGeneration'>;
export type EcdsaCapabilityManifestId = string & EcdsaCapabilityBrand<'EcdsaCapabilityManifestId'>;
export type EcdsaCapabilityManifestRevision = number &
  EcdsaCapabilityBrand<'EcdsaCapabilityManifestRevision'>;
export type EcdsaCiphertextDigest = string & EcdsaCapabilityBrand<'EcdsaCiphertextDigest'>;
export type EcdsaPendingCiphertextDigest = string &
  EcdsaCapabilityBrand<'EcdsaPendingCiphertextDigest'>;
export type EcdsaActivationDigest = string & EcdsaCapabilityBrand<'EcdsaActivationDigest'>;
export type EcdsaLifecycleId = string & EcdsaCapabilityBrand<'EcdsaLifecycleId'>;
export type EcdsaMaterialSealingKeyId = string & EcdsaCapabilityBrand<'EcdsaMaterialSealingKeyId'>;
export type EcdsaIv12B64u = string & EcdsaCapabilityBrand<'EcdsaIv12B64u'>;
export type EcdsaCiphertextB64u = string & EcdsaCapabilityBrand<'EcdsaCiphertextB64u'>;
export type CanonicalEcdsaServerActivationRequest = string &
  EcdsaCapabilityBrand<'CanonicalEcdsaServerActivationRequest'>;

function parseNonEmptyString<TName extends string>(
  value: unknown,
  label: string,
): string & EcdsaCapabilityBrand<TName> {
  if (typeof value !== 'string' || value.trim() !== value || value.length === 0) {
    throw new Error(`${label} must be a non-empty canonical string`);
  }
  return value as string & EcdsaCapabilityBrand<TName>;
}

function parseCanonicalBase64Url<TName extends string>(
  value: unknown,
  label: string,
  byteLength: number | null,
): string & EcdsaCapabilityBrand<TName> {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${label} must be unpadded base64url`);
  }
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(value);
  } catch {
    throw new Error(`${label} must be valid base64url`);
  }
  if (
    bytes.length === 0 ||
    (byteLength !== null && bytes.length !== byteLength) ||
    base64UrlEncode(bytes) !== value
  ) {
    throw new Error(`${label} has an invalid canonical byte length`);
  }
  return value as string & EcdsaCapabilityBrand<TName>;
}

export function parseEvmFamilyEcdsaSignerId(value: unknown): EvmFamilyEcdsaSignerId {
  return parseNonEmptyString<'EvmFamilyEcdsaSignerId'>(value, 'ECDSA signer id');
}

export function parseEcdsaServerGeneration(value: unknown): EcdsaServerGeneration {
  return parseNonEmptyString<'EcdsaServerGeneration'>(value, 'ECDSA server generation');
}

export function parseEcdsaCapabilityManifestId(value: unknown): EcdsaCapabilityManifestId {
  return parseNonEmptyString<'EcdsaCapabilityManifestId'>(value, 'ECDSA manifest id');
}

export function parseEcdsaCapabilityManifestRevision(
  value: unknown,
): EcdsaCapabilityManifestRevision {
  if (!Number.isSafeInteger(value) || Number(value) < 1) {
    throw new Error('ECDSA manifest revision must be a positive safe integer');
  }
  return value as EcdsaCapabilityManifestRevision;
}

export function parseEcdsaCiphertextDigest(value: unknown): EcdsaCiphertextDigest {
  return parseCanonicalBase64Url<'EcdsaCiphertextDigest'>(value, 'ECDSA ciphertext digest', 32);
}

export function parseEcdsaPendingCiphertextDigest(value: unknown): EcdsaPendingCiphertextDigest {
  return parseCanonicalBase64Url<'EcdsaPendingCiphertextDigest'>(
    value,
    'ECDSA pending ciphertext digest',
    32,
  );
}

export function parseEcdsaActivationDigest(value: unknown): EcdsaActivationDigest {
  return parseCanonicalBase64Url<'EcdsaActivationDigest'>(value, 'ECDSA activation digest', 32);
}

export function parseEcdsaLifecycleId(value: unknown): EcdsaLifecycleId {
  return parseNonEmptyString<'EcdsaLifecycleId'>(value, 'ECDSA lifecycle id');
}

export function parseEcdsaMaterialSealingKeyId(value: unknown): EcdsaMaterialSealingKeyId {
  return parseNonEmptyString<'EcdsaMaterialSealingKeyId'>(value, 'ECDSA material sealing key id');
}

export function parseEcdsaIv12B64u(value: unknown): EcdsaIv12B64u {
  return parseCanonicalBase64Url<'EcdsaIv12B64u'>(value, 'ECDSA AES-GCM IV', 12);
}

export function parseEcdsaCiphertextB64u(value: unknown): EcdsaCiphertextB64u {
  return parseCanonicalBase64Url<'EcdsaCiphertextB64u'>(value, 'ECDSA ciphertext', null);
}

export function parseCanonicalEcdsaServerActivationRequest(
  value: unknown,
): CanonicalEcdsaServerActivationRequest {
  if (typeof value !== 'string' || value.trim() !== value) {
    throw new Error('ECDSA server activation request must be canonical JSON');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error('ECDSA server activation request must be canonical JSON');
  }
  if (
    parsed === null ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed) ||
    alphabetizeStringify(parsed) !== value
  ) {
    throw new Error('ECDSA server activation request must be a canonical JSON object');
  }
  return value as CanonicalEcdsaServerActivationRequest;
}
