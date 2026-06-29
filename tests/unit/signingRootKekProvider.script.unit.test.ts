import { expect, test } from '@playwright/test';
import {
  createSigningRootSecretShareKekResolver,
  isMissingSigningRootKekError,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootKekProvider';
import type {
  CloudflareSecretsStoreSecretBinding,
  SigningRootKekProvider,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootKekProvider';
import type { SigningRootSecretShareKekResolutionInput } from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootSecretSealing';

const KEK_ID = 'kek-share-1';
const MISSING_KEK_REQUEST: SigningRootSecretShareKekResolutionInput = {
  signingRootId: 'project-alpha',
  signingRootVersion: 'root-v1',
  shareId: 1,
  kekId: KEK_ID,
};

async function emptySecret(): Promise<string | null> {
  return '';
}

function emptyCloudflareSecretsStoreBinding(): CloudflareSecretsStoreSecretBinding {
  return { get: emptySecret };
}

function workerSecretProvider(): SigningRootKekProvider {
  return {
    kind: 'worker_secret',
    workerSecretsByKekId: {},
    encoding: 'base64url',
  };
}

function emptyCloudflareSecretsStoreProvider(): SigningRootKekProvider {
  return {
    kind: 'cloudflare_secrets_store',
    secretsByKekId: {
      [KEK_ID]: emptyCloudflareSecretsStoreBinding(),
    },
    encoding: 'base64url',
  };
}

test('signing-root KEK providers raise typed missing-KEK errors', async () => {
  const workerResolver = createSigningRootSecretShareKekResolver(workerSecretProvider());
  const cloudflareResolver = createSigningRootSecretShareKekResolver(
    emptyCloudflareSecretsStoreProvider(),
  );

  await expect(workerResolver(MISSING_KEK_REQUEST)).rejects.toMatchObject({
    code: 'missing_signing_root_kek',
  });
  await expect(cloudflareResolver(MISSING_KEK_REQUEST)).rejects.toMatchObject({
    code: 'missing_signing_root_kek',
  });

  try {
    await workerResolver(MISSING_KEK_REQUEST);
  } catch (error) {
    expect(isMissingSigningRootKekError(error)).toBe(true);
    return;
  }
  throw new Error('worker resolver unexpectedly found a KEK');
});
