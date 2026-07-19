import { isObject } from '@shared/utils/validation';
import type { AuthService } from '../AuthService';
import { coerceLogger, type Logger } from '../logger';
import type { ThresholdStoreConfigInput } from '../types';
import { createThresholdEcdsaSigningStores } from '../ThresholdService/stores/EcdsaSigningStore';
import {
  createThresholdEd25519KeyStore,
} from '../ThresholdService/stores/KeyStore';
import {
  createEcdsaWalletSessionStore,
  createEd25519WalletSessionStore,
  createWalletSigningBudgetSessionStore,
} from '../ThresholdService/stores/WalletSessionStore';
import {
  parseRouterAbEcdsaPresignRuntimeConfig,
  RouterAbEcdsaPresignRuntime,
} from './RouterAbEcdsaPresignRuntime';
import { RouterAbLocalSigningSeedRuntime } from './RouterAbLocalSigningSeedRuntime';
import {
  parseRouterAbNormalSigningRuntimeConfig,
  requireRouterAbConfiguredSigningWorkerPrivateTransport,
  RouterAbNormalSigningRuntime,
} from './RouterAbNormalSigningRuntime';

export type RouterAbSigningRuntimeBundle = {
  readonly normalSigning: RouterAbNormalSigningRuntime;
  readonly localSigningSeed: RouterAbLocalSigningSeedRuntime;
  readonly ecdsaPresign: RouterAbEcdsaPresignRuntime;
};

type RouterAbSigningReadyAuthPort = Pick<AuthService, 'getRelayerAccount'>;

async function ensureRouterAbSigningRuntimeReady(
  this: RouterAbSigningReadyAuthPort,
): Promise<void> {
  await this.getRelayerAccount();
}

function isNodeEnvironment(): boolean {
  const processObject = (globalThis as unknown as { process?: { versions?: { node?: string } } })
    .process;
  const isNode = Boolean(processObject?.versions?.node);
  const webSocketPair = (globalThis as unknown as { WebSocketPair?: unknown }).WebSocketPair;
  const isCloudflareWorker =
    typeof webSocketPair !== 'undefined' ||
    (typeof navigator !== 'undefined' &&
      String(navigator.userAgent || '').includes('Cloudflare-Workers'));
  return isNode && !isCloudflareWorker;
}

function thresholdStoreConfigFromEnvironment(
  environment: Record<string, string | undefined> | undefined,
): ThresholdStoreConfigInput | null {
  if (!environment) return null;
  return {
    UPSTASH_REDIS_REST_URL: environment.UPSTASH_REDIS_REST_URL,
    UPSTASH_REDIS_REST_TOKEN: environment.UPSTASH_REDIS_REST_TOKEN,
    REDIS_URL: environment.REDIS_URL,
    THRESHOLD_PREFIX: environment.THRESHOLD_PREFIX,
    THRESHOLD_ED25519_KEYSTORE_PREFIX: environment.THRESHOLD_ED25519_KEYSTORE_PREFIX,
    THRESHOLD_ED25519_WALLET_SESSION_PREFIX: environment.THRESHOLD_ED25519_WALLET_SESSION_PREFIX,
    THRESHOLD_WALLET_SIGNING_BUDGET_SESSION_PREFIX:
      environment.THRESHOLD_WALLET_SIGNING_BUDGET_SESSION_PREFIX,
    THRESHOLD_ECDSA_KEYSTORE_PREFIX: environment.THRESHOLD_ECDSA_KEYSTORE_PREFIX,
    THRESHOLD_ECDSA_SESSION_PREFIX: environment.THRESHOLD_ECDSA_SESSION_PREFIX,
    THRESHOLD_ECDSA_WALLET_SESSION_PREFIX: environment.THRESHOLD_ECDSA_WALLET_SESSION_PREFIX,
    THRESHOLD_ECDSA_PRESIGN_PREFIX: environment.THRESHOLD_ECDSA_PRESIGN_PREFIX,
    THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID:
      environment.THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID,
    THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID:
      environment.THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID,
    THRESHOLD_NODE_ROLE: environment.THRESHOLD_NODE_ROLE,
    THRESHOLD_COORDINATOR_INSTANCE_ID: environment.THRESHOLD_COORDINATOR_INSTANCE_ID,
    THRESHOLD_COORDINATOR_PEERS: environment.THRESHOLD_COORDINATOR_PEERS,
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: environment.ROUTER_AB_NORMAL_SIGNING_WORKER_ID,
    ROUTER_AB_SIGNING_WORKER_URL: environment.ROUTER_AB_SIGNING_WORKER_URL,
    ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: environment.ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET,
  };
}

function resolveThresholdStoreConfig(input: {
  readonly explicitConfig: ThresholdStoreConfigInput | null | undefined;
  readonly environmentConfig: ThresholdStoreConfigInput | null;
}): ThresholdStoreConfigInput | null {
  if (isObject(input.environmentConfig) && isObject(input.explicitConfig)) {
    return { ...input.environmentConfig, ...input.explicitConfig };
  }
  return input.explicitConfig ?? input.environmentConfig;
}

export function createRouterAbSigningRuntimes(input: {
  readonly authService: Pick<AuthService, 'getRelayerAccount'>;
  readonly thresholdStore?: ThresholdStoreConfigInput | null;
  readonly logger?: Logger | null;
  readonly isNode?: boolean;
}): RouterAbSigningRuntimeBundle {
  const logger = coerceLogger(input.logger);
  const isNode = input.isNode ?? isNodeEnvironment();
  const environment = isNode
    ? (globalThis as unknown as { process?: { env?: Record<string, string | undefined> } }).process
        ?.env
    : undefined;
  const config = resolveThresholdStoreConfig({
    explicitConfig: input.thresholdStore,
    environmentConfig: thresholdStoreConfigFromEnvironment(environment),
  });
  const configRecord = isObject(config) ? config : {};

  const ed25519KeyStore = createThresholdEd25519KeyStore({ config, logger, isNode });
  const ed25519WalletSessionStore = createEd25519WalletSessionStore({ config, logger, isNode });
  const walletBudgetSessionStore = createWalletSigningBudgetSessionStore({
    config,
    logger,
    isNode,
  });
  const ecdsaWalletSessionStore = createEcdsaWalletSessionStore({ config, logger, isNode });
  const ecdsaSigningStores = createThresholdEcdsaSigningStores({ config, logger, isNode });
  const ensureReady = ensureRouterAbSigningRuntimeReady.bind(input.authService);
  const normalSigningConfig = parseRouterAbNormalSigningRuntimeConfig(configRecord);
  const signingWorkerTransport = requireRouterAbConfiguredSigningWorkerPrivateTransport(
    normalSigningConfig.signingWorkerTransport,
  );

  const normalSigning = new RouterAbNormalSigningRuntime({
    walletSessionStore: ed25519WalletSessionStore,
    ecdsaWalletSessionStore,
    walletBudgetSessionStore,
    config: normalSigningConfig,
  });
  const localSigningSeed = new RouterAbLocalSigningSeedRuntime({
    ed25519KeyStore,
    ed25519WalletSessionStore,
    ecdsaWalletSessionStore,
    normalSigningRuntime: normalSigning,
  });
  const ecdsaPresign = new RouterAbEcdsaPresignRuntime({
    logger,
    config: parseRouterAbEcdsaPresignRuntimeConfig(configRecord),
    ecdsaPoolFillSessionStore: ecdsaSigningStores.poolFillSessionStore,
    signingWorkerTransport,
    ensureReady,
  });

  return { normalSigning, localSigningSeed, ecdsaPresign };
}
