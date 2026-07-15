import {
  parseSdkEcdsaHssThresholdKeyId,
  type EcdsaThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';

export type { EcdsaThresholdKeyId };

export type Brand<T, Name extends string> = T & { readonly __brand: Name };

export type Ed25519KeyVersion = Brand<string, 'Ed25519KeyVersion'>;
export type EcdsaHssKeyVersion = Brand<string, 'EcdsaHssKeyVersion'>;
export type SigningSessionSealKeyVersion = Brand<string, 'SigningSessionSealKeyVersion'>;
export type EcdsaClientVerifyingShareB64u = Brand<
  string,
  'EcdsaClientVerifyingShareB64u'
>;
export type Ed25519RelayerKeyId = Brand<string, 'Ed25519RelayerKeyId'>;
export type EcdsaRelayerKeyId = Brand<string, 'EcdsaRelayerKeyId'>;
export type EcdsaKeyHandle = Brand<string, 'EcdsaKeyHandle'>;
export type EcdsaRoleLocalMaterialHandle = Brand<string, 'EcdsaRoleLocalMaterialHandle'>;
export type EcdsaRoleLocalBindingDigest = Brand<string, 'EcdsaRoleLocalBindingDigest'>;
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

export function parseEd25519KeyVersion(value: unknown): Ed25519KeyVersion {
  return parseNonEmptyBrand<'Ed25519KeyVersion'>(value, 'Ed25519 key version');
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

export function parseEcdsaRoleLocalMaterialHandle(
  value: unknown,
): EcdsaRoleLocalMaterialHandle {
  return parseNonEmptyBrand<'EcdsaRoleLocalMaterialHandle'>(
    value,
    'ECDSA role-local material handle',
  );
}

export function parseEcdsaRoleLocalBindingDigest(
  value: unknown,
): EcdsaRoleLocalBindingDigest {
  return parseNonEmptyBrand<'EcdsaRoleLocalBindingDigest'>(
    value,
    'ECDSA role-local binding digest',
  );
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

export function formatEd25519KeyVersionForWire(value: Ed25519KeyVersion): string {
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
