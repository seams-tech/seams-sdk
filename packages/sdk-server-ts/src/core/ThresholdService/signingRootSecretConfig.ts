import { isObject } from './validation';
import {
  createSigningRootSecretResolver,
  createSigningRootSecretResolverFromAdapters,
  type SigningRootSecretResolver,
  type SigningRootSecretResolverAdapters,
  type SigningRootSecretDecryptAdapter,
  type SigningRootSecretShareSource,
} from './signingRootSecretResolverAdapters';
import {
  createSigningRootSecretAesGcmDecryptAdapter,
  type SigningRootSecretShareKekResolver,
} from './signingRootSecretSealing';
import {
  createHostedSigningRootShareResolver,
  type SigningRootShareResolver,
} from './signingRootShareResolver';

function isSigningRootSecretResolver(input: unknown): input is SigningRootSecretResolver {
  return (
    isObject(input) &&
    typeof input.listSealedSigningRootSecretShares === 'function' &&
    typeof input.decryptSigningRootSecretShare === 'function'
  );
}

function isSigningRootSecretShareSource(input: unknown): input is SigningRootSecretShareSource {
  return isObject(input) && typeof input.listSealedSigningRootSecretShares === 'function';
}

function isSigningRootSecretShareKekResolver(input: unknown): input is SigningRootSecretShareKekResolver {
  return typeof input === 'function';
}

function isSigningRootSecretDecryptAdapter(
  input: unknown,
): input is SigningRootSecretDecryptAdapter {
  return isObject(input) && typeof input.decryptSigningRootSecretShare === 'function';
}

function isSigningRootSecretShareAdapters(input: unknown): input is SigningRootSecretResolverAdapters {
  return (
    isObject(input) &&
    isSigningRootSecretShareSource(input.storageAdapter) &&
    isSigningRootSecretDecryptAdapter(input.decryptAdapter)
  );
}

function isSigningRootShareResolver(input: unknown): input is SigningRootShareResolver {
  return isObject(input) && typeof input.resolveSigningRootSharePair === 'function';
}

export function createConfiguredSigningRootShareResolver(
  config: unknown,
): SigningRootShareResolver | null {
  if (!isObject(config)) return null;

  if (isSigningRootShareResolver(config.signingRootShareResolver)) {
    return config.signingRootShareResolver;
  }

  if (isSigningRootSecretShareAdapters(config.signingRootSecretResolverAdapters)) {
    return createHostedSigningRootShareResolver(config.signingRootSecretResolverAdapters);
  }

  if (
    isSigningRootSecretShareSource(config.signingRootSecretStore) &&
    isSigningRootSecretDecryptAdapter(config.signingRootSecretDecryptAdapter)
  ) {
    return createHostedSigningRootShareResolver({
      storageAdapter: config.signingRootSecretStore,
      decryptAdapter: config.signingRootSecretDecryptAdapter,
    });
  }

  if (
    isSigningRootSecretShareSource(config.signingRootSecretStore) &&
    isSigningRootSecretShareKekResolver(config.signingRootSecretShareKekResolver)
  ) {
    return createHostedSigningRootShareResolver({
      storageAdapter: config.signingRootSecretStore,
      decryptAdapter: createSigningRootSecretAesGcmDecryptAdapter({
        resolveKek: config.signingRootSecretShareKekResolver,
      }),
    });
  }

  return null;
}

export function createConfiguredSigningRootSecretResolver(
  config: unknown,
): SigningRootSecretResolver | null {
  if (!isObject(config)) return null;

  if (isSigningRootSecretResolver(config.signingRootSecretResolver)) {
    return config.signingRootSecretResolver;
  }

  if (isSigningRootSecretShareAdapters(config.signingRootSecretResolverAdapters)) {
    return createSigningRootSecretResolverFromAdapters(config.signingRootSecretResolverAdapters);
  }

  if (
    isSigningRootSecretShareSource(config.signingRootSecretShareStore) &&
    isSigningRootSecretDecryptAdapter(config.signingRootSecretShareDecryptAdapter)
  ) {
    return createSigningRootSecretResolverFromAdapters({
      storageAdapter: config.signingRootSecretShareStore,
      decryptAdapter: config.signingRootSecretShareDecryptAdapter,
    });
  }

  if (
    isSigningRootSecretShareSource(config.signingRootSecretShareStore) &&
    isSigningRootSecretShareKekResolver(config.signingRootSecretShareKekResolver)
  ) {
    return createSigningRootSecretResolver({
      store: config.signingRootSecretShareStore,
      decryptAdapter: createSigningRootSecretAesGcmDecryptAdapter({
        resolveKek: config.signingRootSecretShareKekResolver,
      }),
    });
  }

  return null;
}
