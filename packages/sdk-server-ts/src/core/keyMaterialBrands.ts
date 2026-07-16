export type Brand<T, Name extends string> = T & { readonly __brand: Name };

export type EcdsaDerivationKeyVersion = Brand<string, 'EcdsaDerivationKeyVersion'>;
export type SigningSessionSealKeyVersion = Brand<string, 'SigningSessionSealKeyVersion'>;
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
export type EcdsaThresholdKeyId = Brand<string, 'EcdsaThresholdKeyId'>;
export type EcdsaKeyHandle = Brand<string, 'EcdsaKeyHandle'>;
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

export function parseEcdsaDerivationKeyVersion(value: unknown): EcdsaDerivationKeyVersion {
  return parseNonEmptyBrand<'EcdsaDerivationKeyVersion'>(value, 'ECDSA DERIVATION key version');
}

export function parseSigningSessionSealKeyVersion(
  value: unknown,
): SigningSessionSealKeyVersion {
  return parseNonEmptyBrand<'SigningSessionSealKeyVersion'>(
    value,
    'signing-session seal key version',
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
  return parseNonEmptyBrand<'EcdsaThresholdKeyId'>(value, 'ECDSA threshold key id');
}

export function parseEcdsaKeyHandle(value: unknown): EcdsaKeyHandle {
  return parseNonEmptyBrand<'EcdsaKeyHandle'>(value, 'ECDSA key handle');
}

export function parseSigningSessionSealShamirPrimeB64u(
  value: unknown,
): SigningSessionSealShamirPrimeB64u {
  return parseNonEmptyBrand<'SigningSessionSealShamirPrimeB64u'>(
    value,
    'signing-session seal Shamir prime',
  );
}

export function formatEcdsaDerivationKeyVersionForWire(value: EcdsaDerivationKeyVersion): string {
  return value;
}

export function formatSigningSessionSealKeyVersionForWire(
  value: SigningSessionSealKeyVersion,
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

export function formatSigningSessionSealShamirPrimeB64uForWire(
  value: SigningSessionSealShamirPrimeB64u,
): string {
  return value;
}
