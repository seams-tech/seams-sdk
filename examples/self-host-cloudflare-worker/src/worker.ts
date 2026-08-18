import {
  AuthService,
  type ThresholdStoreConfigInput,
} from '@seams/wallet-server';
import { createSelfHostedCloudflareSigningWorker } from '@seams/wallet-server/router/cloudflare';
import signerWasmModule from '@seams/wallet-server/wasm/signer';

export { ThresholdStoreDurableObject } from '@seams/wallet-server/router/cloudflare';

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
};

function createThresholdStoreConfig(env: Env): ThresholdStoreConfigInput {
  return {
    kind: 'cloudflare-do',
    namespace: env.THRESHOLD_STORE,
    name: 'threshold-store',
    THRESHOLD_PREFIX: env.THRESHOLD_PREFIX,
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
  routerOptions: ({ env }) => ({
    healthz: true,
    readyz: true,
    logger: console,
    corsOrigins: [env.EXPECTED_ORIGIN, env.EXPECTED_WALLET_ORIGIN],
    sessionCookieName: env.SESSION_COOKIE_NAME,
  }),
});
