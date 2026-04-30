import {
  AuthService,
  CloudflareDurableObjectSigningRootSecretStore,
  createSigningRootSecretAesGcmDecryptAdapter,
  type SigningRootSecretShareKekResolutionInput,
  type ThresholdStoreConfigInput,
} from '@seams/sdk/server';
import { createSelfHostedCloudflareSigningWorker } from '@seams/sdk/server/router/cloudflare';
import signerWasmModule from '@seams/sdk/server/wasm/signer';

export { ThresholdStoreDurableObject } from '@seams/sdk/server/router/cloudflare';

type DurableObjectNamespace = {
  idFromName(name: string): unknown;
  get(id: unknown): { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };
};

type Env = {
  RELAYER_ACCOUNT_ID: string;
  RELAYER_PRIVATE_KEY: string;
  NEAR_RPC_URL?: string;
  NETWORK_ID?: string;
  EXPECTED_ORIGIN?: string;
  EXPECTED_WALLET_ORIGIN?: string;
  SESSION_COOKIE_NAME?: string;
  THRESHOLD_PREFIX?: string;
  THRESHOLD_STORE: DurableObjectNamespace;
  THRESHOLD_SIGNING_ROOT_OBJECT_NAME?: string;
  SIGNING_ROOT_SECRET_SHARE_CACHE_TTL_MS?: string;
  SIGNING_ROOT_SECRET_SHARE_KEK_B64U?: string;
  SELF_HOST_ADMIN_TOKEN?: string;
};

function base64UrlDecodeBytes(input: string): Uint8Array {
  const normalized = input.trim().replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), '=');
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

function cacheTtlMs(env: Env): number {
  const value = Number(env.SIGNING_ROOT_SECRET_SHARE_CACHE_TTL_MS || '30000');
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : 0;
}

function createThresholdStoreConfig(env: Env): ThresholdStoreConfigInput {
  const signingRootSecretStore = new CloudflareDurableObjectSigningRootSecretStore({
    namespace: env.THRESHOLD_STORE,
    objectName: env.THRESHOLD_SIGNING_ROOT_OBJECT_NAME || 'threshold-signing-root-secrets',
    cacheTtlMs: cacheTtlMs(env),
  });

  return {
    kind: 'cloudflare-do',
    namespace: env.THRESHOLD_STORE,
    name: 'threshold-store',
    THRESHOLD_PREFIX: env.THRESHOLD_PREFIX,
    signingRootSecretResolverAdapters: {
      storageAdapter: signingRootSecretStore,
      decryptAdapter: createSigningRootSecretAesGcmDecryptAdapter({
        resolveKek: (_input: SigningRootSecretShareKekResolutionInput) => {
          if (!env.SIGNING_ROOT_SECRET_SHARE_KEK_B64U) {
            throw new Error(
              'SIGNING_ROOT_SECRET_SHARE_KEK_B64U is required to decrypt imported signing-root shares',
            );
          }
          return base64UrlDecodeBytes(env.SIGNING_ROOT_SECRET_SHARE_KEK_B64U);
        },
      }),
    },
  };
}

function createAuthService(env: Env): AuthService {
  return new AuthService({
    relayerAccount: env.RELAYER_ACCOUNT_ID,
    relayerPrivateKey: env.RELAYER_PRIVATE_KEY,
    nearRpcUrl: env.NEAR_RPC_URL,
    networkId: env.NETWORK_ID,
    thresholdStore: createThresholdStoreConfig(env),
    signerWasm: {
      moduleOrPath: signerWasmModule,
    },
  });
}

export default createSelfHostedCloudflareSigningWorker<Env>({
  createAuthService: ({ env }) => createAuthService(env),
  signingRootAdmin: ({ env }) => ({
    namespace: env.THRESHOLD_STORE,
    objectName: env.THRESHOLD_SIGNING_ROOT_OBJECT_NAME || 'threshold-signing-root-secrets',
    authenticate: ({ request }) => {
      const expected = env.SELF_HOST_ADMIN_TOKEN;
      const actual = request.headers.get('authorization') || '';
      return Boolean(expected && actual === `Bearer ${expected}`);
    },
  }),
  routerOptions: ({ env }) => ({
    healthz: true,
    readyz: true,
    logger: console,
    corsOrigins: [env.EXPECTED_ORIGIN, env.EXPECTED_WALLET_ORIGIN],
    sessionCookieName: env.SESSION_COOKIE_NAME,
  }),
});
