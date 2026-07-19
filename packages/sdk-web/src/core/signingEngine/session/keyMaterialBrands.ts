import {
  parseSdkEcdsaDerivationThresholdKeyId,
  type EcdsaThresholdKeyId,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';

export type { EcdsaThresholdKeyId };

export type Brand<T, Name extends string> = T & { readonly __brand: Name };

export type Ed25519KeyVersion = Brand<string, 'Ed25519KeyVersion'>;
export type EcdsaDerivationKeyVersion = Brand<string, 'EcdsaDerivationKeyVersion'>;
export type SigningSessionSealKeyVersion = Brand<string, 'SigningSessionSealKeyVersion'>;
export type EcdsaClientVerifyingShareB64u = Brand<string, 'EcdsaClientVerifyingShareB64u'>;
export type Ed25519RelayerKeyId = Brand<string, 'Ed25519RelayerKeyId'>;
export type EcdsaRelayerKeyId = Brand<string, 'EcdsaRelayerKeyId'>;
export type EcdsaKeyHandle = Brand<string, 'EcdsaKeyHandle'>;
export type EcdsaRoleLocalMaterialHandle = Brand<string, 'EcdsaRoleLocalMaterialHandle'>;
export type EcdsaRoleLocalBindingDigest = Brand<string, 'EcdsaRoleLocalBindingDigest'>;
export type EcdsaRoleLocalDurableMaterialRef = Brand<string, 'EcdsaRoleLocalDurableMaterialRef'>;
export type EcdsaRoleLocalPersistedMaterialRef = {
  readonly kind: 'ecdsa_role_local_persisted_material_ref_v1';
  readonly durableMaterialRef: EcdsaRoleLocalDurableMaterialRef;
  readonly bindingDigest: EcdsaRoleLocalBindingDigest;
};
export type EcdsaRoleLocalWorkerHandle = {
  readonly kind: 'ecdsa_role_local_worker_handle_v1';
  readonly materialHandle: EcdsaRoleLocalMaterialHandle;
  readonly bindingDigest: EcdsaRoleLocalBindingDigest;
  readonly durableMaterialRef: EcdsaRoleLocalDurableMaterialRef;
};
export type EcdsaClientAdditiveShareHandle = Brand<string, 'EcdsaClientAdditiveShareHandle'>;
export type SigningSessionSealShamirPrimeB64u = Brand<string, 'SigningSessionSealShamirPrimeB64u'>;

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

export function parseEcdsaDerivationKeyVersion(value: unknown): EcdsaDerivationKeyVersion {
  return parseNonEmptyBrand<'EcdsaDerivationKeyVersion'>(value, 'ECDSA DERIVATION key version');
}

export function parseSigningSessionSealKeyVersion(value: unknown): SigningSessionSealKeyVersion {
  return parseNonEmptyBrand<'SigningSessionSealKeyVersion'>(
    value,
    'signing-session seal key version',
  );
}

export function parseEcdsaClientVerifyingShareB64u(value: unknown): EcdsaClientVerifyingShareB64u {
  return parseNonEmptyBrand<'EcdsaClientVerifyingShareB64u'>(value, 'ECDSA client verifying share');
}

export function parseEd25519RelayerKeyId(value: unknown): Ed25519RelayerKeyId {
  return parseNonEmptyBrand<'Ed25519RelayerKeyId'>(value, 'Ed25519 relayer key id');
}

export function parseEcdsaRelayerKeyId(value: unknown): EcdsaRelayerKeyId {
  return parseNonEmptyBrand<'EcdsaRelayerKeyId'>(value, 'ECDSA relayer key id');
}

export function parseEcdsaThresholdKeyId(value: unknown): EcdsaThresholdKeyId {
  return parseSdkEcdsaDerivationThresholdKeyId(value);
}

export function parseEcdsaKeyHandle(value: unknown): EcdsaKeyHandle {
  return parseNonEmptyBrand<'EcdsaKeyHandle'>(value, 'ECDSA key handle');
}

export function parseEcdsaRoleLocalMaterialHandle(value: unknown): EcdsaRoleLocalMaterialHandle {
  return parseNonEmptyBrand<'EcdsaRoleLocalMaterialHandle'>(
    value,
    'ECDSA role-local material handle',
  );
}

export function parseEcdsaRoleLocalBindingDigest(value: unknown): EcdsaRoleLocalBindingDigest {
  return parseNonEmptyBrand<'EcdsaRoleLocalBindingDigest'>(
    value,
    'ECDSA role-local binding digest',
  );
}

export function parseEcdsaRoleLocalDurableMaterialRef(
  value: unknown,
): EcdsaRoleLocalDurableMaterialRef {
  return parseNonEmptyBrand<'EcdsaRoleLocalDurableMaterialRef'>(
    value,
    'ECDSA role-local durable material reference',
  );
}

export function parseEcdsaRoleLocalPersistedMaterialRef(
  value: unknown,
): EcdsaRoleLocalPersistedMaterialRef {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('ECDSA role-local persisted material reference must be an object');
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const expectedKeys = ['bindingDigest', 'durableMaterialRef', 'kind'];
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new Error('ECDSA role-local persisted material reference has unexpected fields');
  }
  if (record.kind !== 'ecdsa_role_local_persisted_material_ref_v1') {
    throw new Error('ECDSA role-local persisted material reference kind is invalid');
  }
  return {
    kind: 'ecdsa_role_local_persisted_material_ref_v1',
    durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(record.durableMaterialRef),
    bindingDigest: parseEcdsaRoleLocalBindingDigest(record.bindingDigest),
  };
}

export function parseEcdsaRoleLocalWorkerHandle(value: unknown): EcdsaRoleLocalWorkerHandle {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('ECDSA role-local worker handle must be an object');
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const expectedKeys = ['bindingDigest', 'durableMaterialRef', 'kind', 'materialHandle'];
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new Error('ECDSA role-local worker handle has unexpected fields');
  }
  if (record.kind !== 'ecdsa_role_local_worker_handle_v1') {
    throw new Error('ECDSA role-local worker handle kind is invalid');
  }
  return {
    kind: 'ecdsa_role_local_worker_handle_v1',
    materialHandle: parseEcdsaRoleLocalMaterialHandle(record.materialHandle),
    bindingDigest: parseEcdsaRoleLocalBindingDigest(record.bindingDigest),
    durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(record.durableMaterialRef),
  };
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

export function formatEcdsaDerivationKeyVersionForWire(value: EcdsaDerivationKeyVersion): string {
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
