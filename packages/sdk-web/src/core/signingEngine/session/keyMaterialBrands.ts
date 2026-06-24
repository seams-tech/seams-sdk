import {
  parseSdkEcdsaHssThresholdKeyId,
  type EcdsaThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';

export type { EcdsaThresholdKeyId };

export type Brand<T, Name extends string> = T & { readonly __brand: Name };

export type Ed25519HssKeyVersion = Brand<string, 'Ed25519HssKeyVersion'>;
export type EcdsaHssKeyVersion = Brand<string, 'EcdsaHssKeyVersion'>;
export type SigningSessionSealKeyVersion = Brand<string, 'SigningSessionSealKeyVersion'>;
export type Ed25519WorkerMaterialHandle = Brand<string, 'Ed25519WorkerMaterialHandle'>;
export type Ed25519SealedWorkerMaterialRef = Brand<string, 'Ed25519SealedWorkerMaterialRef'>;
export type Ed25519WorkerMaterialKeyId = Brand<string, 'Ed25519WorkerMaterialKeyId'>;
export type Ed25519WorkerMaterialBindingDigest = Brand<
  string,
  'Ed25519WorkerMaterialBindingDigest'
>;
export type Ed25519ClientVerifyingShareB64u = Brand<
  string,
  'Ed25519ClientVerifyingShareB64u'
>;
export type EcdsaClientVerifyingShareB64u = Brand<
  string,
  'EcdsaClientVerifyingShareB64u'
>;
export type Ed25519RelayerKeyId = Brand<string, 'Ed25519RelayerKeyId'>;
export type EcdsaRelayerKeyId = Brand<string, 'EcdsaRelayerKeyId'>;
export type EcdsaKeyHandle = Brand<string, 'EcdsaKeyHandle'>;
export type EcdsaClientAdditiveShareHandle = Brand<
  string,
  'EcdsaClientAdditiveShareHandle'
>;
export type SigningSessionSealShamirPrimeB64u = Brand<
  string,
  'SigningSessionSealShamirPrimeB64u'
>;

function parseNonEmptyBrand<T extends string>(value: unknown, label: string): Brand<string, T> {
  const normalized = String(value ?? '').trim();
  if (!normalized) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return normalized as Brand<string, T>;
}

export function parseEd25519HssKeyVersion(value: unknown): Ed25519HssKeyVersion {
  return parseNonEmptyBrand<'Ed25519HssKeyVersion'>(value, 'Ed25519 HSS key version');
}

export function parseEcdsaHssKeyVersion(value: unknown): EcdsaHssKeyVersion {
  return parseNonEmptyBrand<'EcdsaHssKeyVersion'>(value, 'ECDSA HSS key version');
}

export function parseSigningSessionSealKeyVersion(
  value: unknown,
): SigningSessionSealKeyVersion {
  return parseNonEmptyBrand<'SigningSessionSealKeyVersion'>(
    value,
    'signing-session seal key version',
  );
}

export function parseEd25519WorkerMaterialHandle(
  value: unknown,
): Ed25519WorkerMaterialHandle {
  return parseNonEmptyBrand<'Ed25519WorkerMaterialHandle'>(
    value,
    'Ed25519 worker material handle',
  );
}

export function parseEd25519SealedWorkerMaterialRef(
  value: unknown,
): Ed25519SealedWorkerMaterialRef {
  return parseNonEmptyBrand<'Ed25519SealedWorkerMaterialRef'>(
    value,
    'Ed25519 sealed worker material ref',
  );
}

export function parseEd25519WorkerMaterialKeyId(value: unknown): Ed25519WorkerMaterialKeyId {
  return parseNonEmptyBrand<'Ed25519WorkerMaterialKeyId'>(
    value,
    'Ed25519 worker material key id',
  );
}

export function parseEd25519WorkerMaterialBindingDigest(
  value: unknown,
): Ed25519WorkerMaterialBindingDigest {
  return parseNonEmptyBrand<'Ed25519WorkerMaterialBindingDigest'>(
    value,
    'Ed25519 worker material binding digest',
  );
}

export function parseEd25519ClientVerifyingShareB64u(
  value: unknown,
): Ed25519ClientVerifyingShareB64u {
  return parseNonEmptyBrand<'Ed25519ClientVerifyingShareB64u'>(
    value,
    'Ed25519 client verifying share',
  );
}

export function parseEcdsaClientVerifyingShareB64u(
  value: unknown,
): EcdsaClientVerifyingShareB64u {
  return parseNonEmptyBrand<'EcdsaClientVerifyingShareB64u'>(
    value,
    'ECDSA client verifying share',
  );
}

export function parseEd25519RelayerKeyId(value: unknown): Ed25519RelayerKeyId {
  return parseNonEmptyBrand<'Ed25519RelayerKeyId'>(value, 'Ed25519 relayer key id');
}

export function parseEcdsaRelayerKeyId(value: unknown): EcdsaRelayerKeyId {
  return parseNonEmptyBrand<'EcdsaRelayerKeyId'>(value, 'ECDSA relayer key id');
}

export function parseEcdsaThresholdKeyId(value: unknown): EcdsaThresholdKeyId {
  return parseSdkEcdsaHssThresholdKeyId(value);
}

export function parseEcdsaKeyHandle(value: unknown): EcdsaKeyHandle {
  return parseNonEmptyBrand<'EcdsaKeyHandle'>(value, 'ECDSA key handle');
}

export function parseEcdsaClientAdditiveShareHandle(
  value: unknown,
): EcdsaClientAdditiveShareHandle {
  return parseNonEmptyBrand<'EcdsaClientAdditiveShareHandle'>(
    value,
    'ECDSA client additive share handle',
  );
}

export function parseSigningSessionSealShamirPrimeB64u(
  value: unknown,
): SigningSessionSealShamirPrimeB64u {
  return parseNonEmptyBrand<'SigningSessionSealShamirPrimeB64u'>(
    value,
    'signing-session seal Shamir prime',
  );
}

export function formatEd25519HssKeyVersionForWire(value: Ed25519HssKeyVersion): string {
  return value;
}

export function formatEcdsaHssKeyVersionForWire(value: EcdsaHssKeyVersion): string {
  return value;
}

export function formatSigningSessionSealKeyVersionForWire(
  value: SigningSessionSealKeyVersion,
): string {
  return value;
}

export function formatEd25519WorkerMaterialHandleForWire(
  value: Ed25519WorkerMaterialHandle,
): string {
  return value;
}

export function formatEd25519SealedWorkerMaterialRefForWire(
  value: Ed25519SealedWorkerMaterialRef,
): string {
  return value;
}

export function formatEd25519WorkerMaterialKeyIdForWire(
  value: Ed25519WorkerMaterialKeyId,
): string {
  return value;
}

export function formatEd25519WorkerMaterialBindingDigestForWire(
  value: Ed25519WorkerMaterialBindingDigest,
): string {
  return value;
}

export function formatEd25519ClientVerifyingShareB64uForWire(
  value: Ed25519ClientVerifyingShareB64u,
): string {
  return value;
}

export function formatEcdsaClientVerifyingShareB64uForWire(
  value: EcdsaClientVerifyingShareB64u,
): string {
  return value;
}

export function formatEd25519RelayerKeyIdForWire(value: Ed25519RelayerKeyId): string {
  return value;
}

export function formatEcdsaRelayerKeyIdForWire(value: EcdsaRelayerKeyId): string {
  return value;
}

export function formatEcdsaThresholdKeyIdForWire(value: EcdsaThresholdKeyId): string {
  return value;
}

export function formatEcdsaKeyHandleForWire(value: EcdsaKeyHandle): string {
  return value;
}

export function formatEcdsaClientAdditiveShareHandleForWire(
  value: EcdsaClientAdditiveShareHandle,
): string {
  return value;
}

export function formatSigningSessionSealShamirPrimeB64uForWire(
  value: SigningSessionSealShamirPrimeB64u,
): string {
  return value;
}
