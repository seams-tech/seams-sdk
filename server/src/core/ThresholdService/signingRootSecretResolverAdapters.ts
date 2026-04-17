import type {
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssServerInputs,
} from '../types';
import {
  deriveEcdsaHssYRelayerFromSigningRootSecretShares,
  deriveEd25519HssServerInputsFromSigningRootSecretShares,
  type EcdsaHssSigningRootContext,
} from './thresholdPrfWasm';
import {
  resolveSigningRootSecretShareWirePair,
  zeroizeSigningRootSecretShareWireV1,
  type SigningRootSecretShareId,
  type SigningRootSecretShareWirePair,
  type SigningRootSecretShareWireResult,
  type SealedSigningRootSecretShare,
  type SigningRootSecretShareDecryptor,
} from './signingRootSecretShareWires';

export type ResolveSigningRootSecretSharesInput = {
  readonly signingRootId: string;
  readonly signingRootVersion?: string;
};

export type SigningRootSecretResolver = {
  readonly listSealedSigningRootSecretShares: (
    input: ResolveSigningRootSecretSharesInput,
  ) => Promise<readonly SealedSigningRootSecretShare[]>;
  readonly decryptSigningRootSecretShare: SigningRootSecretShareDecryptor;
};

export type SigningRootSecretStorageAdapterKind =
  | 'cloudflare-durable-object'
  | 'in-memory'
  | 'postgres'
  | 'aws-secrets-manager'
  | 'gcp-secret-manager'
  | 'custom';

export type SigningRootSecretDecryptAdapterKind =
  | 'local-aes-gcm-kek'
  | 'aws-secrets-manager-kek'
  | 'gcp-secret-manager-kek'
  | 'aws-kms'
  | 'gcp-kms'
  | 'tee'
  | 'custom';

export type SigningRootSecretShareSource = {
  readonly listSealedSigningRootSecretShares: SigningRootSecretResolver['listSealedSigningRootSecretShares'];
  readonly adapterKind?: SigningRootSecretStorageAdapterKind | string;
};

export type SigningRootSecretDecryptAdapter = {
  readonly decryptSigningRootSecretShare: SigningRootSecretShareDecryptor;
  readonly adapterKind?: SigningRootSecretDecryptAdapterKind | string;
};

export type SigningRootSecretResolverAdapters = {
  /**
   * Durable sealed-share storage adapter.
   *
   * Built-ins currently include PostgresSigningRootSecretStore and
   * CloudflareDurableObjectSigningRootSecretStore. AWS/GCP Secret Manager can
   * implement this interface when the sealed share records live there.
   */
  readonly storageAdapter: SigningRootSecretShareSource;
  /**
   * Decrypt/unwrap adapter.
   *
   * Use createSigningRootSecretAesGcmDecryptAdapter for local AES-GCM with a
   * KEK resolver. AWS KMS, GCP KMS, or TEE-backed unwrap flows should implement
   * this interface directly so the SDK never needs the raw KEK.
   */
  readonly decryptAdapter: SigningRootSecretDecryptAdapter;
};

export function createSigningRootSecretResolverFromAdapters(
  input: SigningRootSecretResolverAdapters,
): SigningRootSecretResolver {
  return {
    listSealedSigningRootSecretShares: (request) =>
      input.storageAdapter.listSealedSigningRootSecretShares(request),
    decryptSigningRootSecretShare: (record) => input.decryptAdapter.decryptSigningRootSecretShare(record),
  };
}

export function createSigningRootSecretResolver(input: {
  readonly store: SigningRootSecretShareSource;
  readonly decryptAdapter: SigningRootSecretDecryptAdapter;
}): SigningRootSecretResolver {
  return createSigningRootSecretResolverFromAdapters({
    storageAdapter: input.store,
    decryptAdapter: input.decryptAdapter,
  });
}

export type ResolveSigningRootSecretShareWirePairFromResolverInput = ResolveSigningRootSecretSharesInput & {
  readonly resolver: SigningRootSecretResolver;
  readonly preferredShareIds?: readonly SigningRootSecretShareId[];
};

export type DeriveEcdsaHssYRelayerFromSigningRootSecretResolverInput =
  ResolveSigningRootSecretShareWirePairFromResolverInput & {
    readonly context: EcdsaHssSigningRootContext;
  };

export type DeriveEd25519HssServerInputsFromSigningRootSecretResolverInput =
  ResolveSigningRootSecretShareWirePairFromResolverInput & {
    readonly context: ThresholdEd25519HssCanonicalContext;
  };

function resolverErr<T>(message: string): SigningRootSecretShareWireResult<T> {
  return { ok: false, code: 'resolver_failed', message };
}

function deriveErr<T>(message: string): SigningRootSecretShareWireResult<T> {
  return { ok: false, code: 'derive_failed', message };
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

function zeroizeShareWirePair(shareWires: SigningRootSecretShareWirePair): void {
  zeroizeSigningRootSecretShareWireV1(shareWires[0]);
  zeroizeSigningRootSecretShareWireV1(shareWires[1]);
}

export async function resolveSigningRootSecretShareWirePairFromResolver(
  input: ResolveSigningRootSecretShareWirePairFromResolverInput,
): Promise<SigningRootSecretShareWireResult<SigningRootSecretShareWirePair>> {
  let records: readonly SealedSigningRootSecretShare[];
  try {
    records = await input.resolver.listSealedSigningRootSecretShares({
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
    });
  } catch (error) {
    return resolverErr(errorMessage(error, 'failed to list sealed signing-root shares'));
  }

  return resolveSigningRootSecretShareWirePair({
    signingRootId: input.signingRootId,
    records,
    decryptShare: input.resolver.decryptSigningRootSecretShare,
    preferredShareIds: input.preferredShareIds,
  });
}

export async function deriveEcdsaHssYRelayerFromSigningRootSecretResolver(
  input: DeriveEcdsaHssYRelayerFromSigningRootSecretResolverInput,
): Promise<SigningRootSecretShareWireResult<Uint8Array>> {
  const resolved = await resolveSigningRootSecretShareWirePairFromResolver(input);
  if (!resolved.ok) return resolved;

  try {
    const yRelayer = await deriveEcdsaHssYRelayerFromSigningRootSecretShares({
      shareWires: resolved.value,
      context: input.context,
    });
    return { ok: true, value: yRelayer };
  } catch (error) {
    return deriveErr(errorMessage(error, 'failed to derive ecdsa-hss y_relayer'));
  } finally {
    zeroizeShareWirePair(resolved.value);
  }
}

export async function deriveEd25519HssServerInputsFromSigningRootSecretResolver(
  input: DeriveEd25519HssServerInputsFromSigningRootSecretResolverInput,
): Promise<
  SigningRootSecretShareWireResult<
    ThresholdEd25519HssCanonicalContext &
      ThresholdEd25519HssServerInputs & { contextBindingB64u: string }
  >
> {
  const resolved = await resolveSigningRootSecretShareWirePairFromResolver(input);
  if (!resolved.ok) return resolved;

  try {
    const serverInputs = await deriveEd25519HssServerInputsFromSigningRootSecretShares({
      shareWires: resolved.value,
      context: input.context,
    });
    return { ok: true, value: serverInputs };
  } catch (error) {
    return deriveErr(errorMessage(error, 'failed to derive ed25519-hss server inputs'));
  } finally {
    zeroizeShareWirePair(resolved.value);
  }
}
