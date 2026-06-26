import type {
  CloudflareSecretsStoreSecretBinding,
  SigningRootExternalKmsKekClient,
  SigningRootKekProvider,
} from './signingRootKekProvider';

const secretBinding: CloudflareSecretsStoreSecretBinding = {
  async get(): Promise<string | null> {
    return null;
  },
};

const kmsClient: SigningRootExternalKmsKekClient = {
  async resolveSigningRootAesGcmKek() {
    return {
      kind: 'encoded_key',
      encodedKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      encoding: 'base64url',
    };
  },
};

const cloudflareProvider: SigningRootKekProvider = {
  kind: 'cloudflare_secrets_store',
  secretsByKekId: { 'signing-root-kek-test-r1': secretBinding },
  encoding: 'base64url',
};

const workerSecretProvider: SigningRootKekProvider = {
  kind: 'worker_secret',
  workerSecretsByKekId: { 'signing-root-kek-test-r1': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
  encoding: 'base64url',
};

const externalKmsProvider: SigningRootKekProvider = {
  kind: 'external_kms',
  externalKmsClient: kmsClient,
};

void cloudflareProvider;
void workerSecretProvider;
void externalKmsProvider;

// @ts-expect-error Cloudflare Secrets Store providers cannot carry Worker secret maps.
const invalidCloudflareProvider: SigningRootKekProvider = {
  kind: 'cloudflare_secrets_store',
  secretsByKekId: { 'signing-root-kek-test-r1': secretBinding },
  workerSecretsByKekId: { 'signing-root-kek-test-r1': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
  encoding: 'base64url',
};

// @ts-expect-error Worker secret providers require an explicit encoded material encoding.
const invalidWorkerSecretProvider: SigningRootKekProvider = {
  kind: 'worker_secret',
  workerSecretsByKekId: { 'signing-root-kek-test-r1': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
};

// @ts-expect-error External KMS providers cannot carry direct Worker secret material.
const invalidExternalKmsProvider: SigningRootKekProvider = {
  kind: 'external_kms',
  externalKmsClient: kmsClient,
  workerSecretsByKekId: { 'signing-root-kek-test-r1': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
};

void invalidCloudflareProvider;
void invalidWorkerSecretProvider;
void invalidExternalKmsProvider;
