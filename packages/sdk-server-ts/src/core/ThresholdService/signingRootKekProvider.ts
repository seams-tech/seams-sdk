import { base64Decode, base64UrlDecode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { MISSING_SIGNING_ROOT_KEK_CODE } from './signingRootSecretShareWires';
import type {
  SigningRootSecretShareKekResolutionInput,
  SigningRootSecretShareKekResolver,
} from './signingRootSecretSealing';

export type SigningRootEncodedKekMaterialEncoding = 'base64url' | 'base64' | 'hex';

export type CloudflareSecretsStoreSecretBinding = {
  get(): Promise<string | null>;
};

export class MissingSigningRootKekError extends Error {
  readonly code = MISSING_SIGNING_ROOT_KEK_CODE;

  constructor(kekId: string, source: string) {
    super(`${source} missing signing-root KEK for kekId=${kekId}`);
    this.name = 'MissingSigningRootKekError';
  }
}

export function isMissingSigningRootKekError(error: unknown): error is MissingSigningRootKekError {
  if (error instanceof MissingSigningRootKekError) return true;
  if (!error || typeof error !== 'object' || !('code' in error)) return false;
  return error.code === MISSING_SIGNING_ROOT_KEK_CODE;
}

export type SigningRootExternalKmsKekResolutionResult =
  | {
      kind: 'raw_key_bytes';
      keyBytes: Uint8Array;
      key?: never;
      encodedKey?: never;
      encoding?: never;
    }
  | {
      kind: 'crypto_key';
      key: CryptoKey;
      keyBytes?: never;
      encodedKey?: never;
      encoding?: never;
    }
  | {
      kind: 'encoded_key';
      encodedKey: string;
      encoding: SigningRootEncodedKekMaterialEncoding;
      keyBytes?: never;
      key?: never;
    };

export type SigningRootExternalKmsKekClient = {
  resolveSigningRootAesGcmKek(
    input: SigningRootSecretShareKekResolutionInput,
  ): Promise<SigningRootExternalKmsKekResolutionResult>;
};

export type SigningRootKekProvider =
  | {
      kind: 'cloudflare_secrets_store';
      secretsByKekId: Readonly<Record<string, CloudflareSecretsStoreSecretBinding>>;
      encoding: SigningRootEncodedKekMaterialEncoding;
      workerSecretsByKekId?: never;
      externalKmsClient?: never;
    }
  | {
      kind: 'worker_secret';
      workerSecretsByKekId: Readonly<Record<string, string>>;
      encoding: SigningRootEncodedKekMaterialEncoding;
      secretsByKekId?: never;
      externalKmsClient?: never;
    }
  | {
      kind: 'external_kms';
      externalKmsClient: SigningRootExternalKmsKekClient;
      secretsByKekId?: never;
      workerSecretsByKekId?: never;
      encoding?: never;
    };

class SigningRootKekProviderResolver {
  private readonly provider: SigningRootKekProvider;

  constructor(provider: SigningRootKekProvider) {
    this.provider = provider;
  }

  async resolve(
    input: SigningRootSecretShareKekResolutionInput,
  ): Promise<CryptoKey | Uint8Array> {
    return resolveSigningRootKekFromProvider(this.provider, input);
  }
}

export function createSigningRootSecretShareKekResolver(
  provider: SigningRootKekProvider,
): SigningRootSecretShareKekResolver {
  const resolver = new SigningRootKekProviderResolver(provider);
  return resolver.resolve.bind(resolver);
}

async function resolveSigningRootKekFromProvider(
  provider: SigningRootKekProvider,
  input: SigningRootSecretShareKekResolutionInput,
): Promise<CryptoKey | Uint8Array> {
  switch (provider.kind) {
    case 'cloudflare_secrets_store':
      return resolveCloudflareSecretsStoreKek(provider, input);
    case 'worker_secret':
      return resolveWorkerSecretKek(provider, input);
    case 'external_kms':
      return resolveExternalKmsKek(provider, input);
    default:
      return assertNever(provider);
  }
}

async function resolveCloudflareSecretsStoreKek(
  provider: Extract<SigningRootKekProvider, { kind: 'cloudflare_secrets_store' }>,
  input: SigningRootSecretShareKekResolutionInput,
): Promise<Uint8Array> {
  const kekId = requireKekId(input.kekId);
  const binding = provider.secretsByKekId[kekId];
  if (!binding) {
    throw new MissingSigningRootKekError(kekId, 'Cloudflare Secrets Store binding');
  }
  const encoded = toOptionalTrimmedString(await binding.get());
  if (!encoded) {
    throw new MissingSigningRootKekError(kekId, 'Cloudflare Secrets Store secret');
  }
  return decodeEncodedKekMaterial(encoded, provider.encoding);
}

function resolveWorkerSecretKek(
  provider: Extract<SigningRootKekProvider, { kind: 'worker_secret' }>,
  input: SigningRootSecretShareKekResolutionInput,
): Uint8Array {
  const kekId = requireKekId(input.kekId);
  const encoded = toOptionalTrimmedString(provider.workerSecretsByKekId[kekId]);
  if (!encoded) throw new MissingSigningRootKekError(kekId, 'Worker secret');
  return decodeEncodedKekMaterial(encoded, provider.encoding);
}

async function resolveExternalKmsKek(
  provider: Extract<SigningRootKekProvider, { kind: 'external_kms' }>,
  input: SigningRootSecretShareKekResolutionInput,
): Promise<CryptoKey | Uint8Array> {
  const result = await provider.externalKmsClient.resolveSigningRootAesGcmKek(input);
  switch (result.kind) {
    case 'raw_key_bytes':
      return copyNonEmptyKeyBytes(result.keyBytes, 'external KMS raw_key_bytes');
    case 'crypto_key':
      return result.key;
    case 'encoded_key':
      return decodeEncodedKekMaterial(result.encodedKey, result.encoding);
    default:
      return assertNever(result);
  }
}

function decodeEncodedKekMaterial(
  encoded: string,
  encoding: SigningRootEncodedKekMaterialEncoding,
): Uint8Array {
  switch (encoding) {
    case 'base64url':
      return copyNonEmptyKeyBytes(base64UrlDecode(encoded), 'base64url KEK');
    case 'base64':
      return copyNonEmptyKeyBytes(base64Decode(encoded), 'base64 KEK');
    case 'hex':
      return copyNonEmptyKeyBytes(hexToBytes(encoded), 'hex KEK');
    default:
      return assertNever(encoding);
  }
}

function hexToBytes(input: string): Uint8Array {
  const normalized = input.trim();
  if (!/^[0-9a-fA-F]+$/.test(normalized) || normalized.length % 2 !== 0) {
    throw new Error('hex KEK must be an even-length hexadecimal string');
  }
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function copyNonEmptyKeyBytes(input: Uint8Array, label: string): Uint8Array {
  if (!(input instanceof Uint8Array) || input.byteLength === 0) {
    throw new Error(`${label} must decode to non-empty key bytes`);
  }
  return new Uint8Array(input);
}

function requireKekId(input: unknown): string {
  const kekId = toOptionalTrimmedString(input);
  if (!kekId) throw new Error('kekId is required');
  return kekId;
}

function assertNever(value: never): never {
  throw new Error(`Unexpected signing-root KEK provider branch: ${String(value)}`);
}
