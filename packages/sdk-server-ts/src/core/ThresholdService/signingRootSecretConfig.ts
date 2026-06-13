import { isObject } from './validation';
import {
  createHostedSigningRootShareResolver,
  type CreateHostedSigningRootShareResolverInput,
  type SigningRootShareDecryptAdapter,
  type SigningRootShareResolver,
  type SigningRootShareSource,
} from './signingRootShareResolver';
import type { ThresholdPrfPolicy } from './thresholdPrfWasm';

function isSigningRootShareResolver(input: unknown): input is SigningRootShareResolver {
  return (
    isObject(input) &&
    isThresholdPrfPolicy(input.policy) &&
    typeof input.resolveSigningRootShareSet === 'function'
  );
}

function isThresholdPrfPolicy(input: unknown): input is ThresholdPrfPolicy {
  return (
    isObject(input) &&
    input.protocol === 'threshold-prf' &&
    typeof input.threshold === 'number' &&
    typeof input.shareCount === 'number'
  );
}

function isSigningRootShareSource(input: unknown): input is SigningRootShareSource {
  return isObject(input) && typeof input.listSealedSigningRootShares === 'function';
}

function isSigningRootShareDecryptAdapter(
  input: unknown,
): input is SigningRootShareDecryptAdapter {
  return isObject(input) && typeof input.decryptSigningRootShare === 'function';
}

function isSigningRootShareAdapters(
  input: unknown,
): input is CreateHostedSigningRootShareResolverInput {
  return (
    isObject(input) &&
    isThresholdPrfPolicy(input.policy) &&
    isSigningRootShareSource(input.storageAdapter) &&
    isSigningRootShareDecryptAdapter(input.decryptAdapter)
  );
}

export function createConfiguredSigningRootShareResolver(
  config: unknown,
): SigningRootShareResolver | null {
  if (!isObject(config)) return null;

  if (isSigningRootShareResolver(config.signingRootShareResolver)) {
    return config.signingRootShareResolver;
  }

  if (isSigningRootShareAdapters(config.signingRootShareResolverAdapters)) {
    return createHostedSigningRootShareResolver(config.signingRootShareResolverAdapters);
  }

  if (
    isThresholdPrfPolicy(config.signingRootSharePolicy) &&
    isSigningRootShareSource(config.signingRootShareStore) &&
    isSigningRootShareDecryptAdapter(config.signingRootShareDecryptAdapter)
  ) {
    return createHostedSigningRootShareResolver({
      policy: config.signingRootSharePolicy,
      storageAdapter: config.signingRootShareStore,
      decryptAdapter: config.signingRootShareDecryptAdapter,
    });
  }

  return null;
}
