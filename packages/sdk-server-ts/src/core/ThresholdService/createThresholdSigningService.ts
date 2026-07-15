import type { AuthService } from '../AuthService';
import type { ThresholdStoreConfigInput } from '../types';
import type { Logger } from '../logger';
import { coerceLogger } from '../logger';
import { ThresholdSigningService } from './ThresholdSigningService';
import {
  createEcdsaWalletSessionStore,
  createEd25519WalletSessionStore,
  createWalletSigningBudgetSessionStore,
} from './stores/WalletSessionStore';
import { createThresholdEcdsaSigningStores } from './stores/EcdsaSigningStore';
import { createThresholdEcdsaKeyStore, createThresholdEd25519KeyStore } from './stores/KeyStore';
import {
  createThresholdEcdsaSessionStore,
  createThresholdEd25519SessionStore,
} from './stores/SessionStore';
import { isObject } from '@shared/utils/validation';
import { createConfiguredSigningRootShareResolver } from './signingRootSecretConfig';
import type { SigningRootShareResolver } from './signingRootShareResolver';
import {
  parseRouterAbNormalSigningRuntimeConfig,
  RouterAbNormalSigningRuntime,
} from '../routerAbSigning/RouterAbNormalSigningRuntime';
import { RouterAbLocalSigningSeedRuntime } from '../routerAbSigning/RouterAbLocalSigningSeedRuntime';
import {
  RouterAbEcdsaBootstrapExportRuntime,
  type RouterAbEcdsaBootstrapExportRuntimeState,
} from '../routerAbSigning/RouterAbEcdsaBootstrapExportRuntime';
import { parseThresholdEd25519ParticipantIds2p } from './config';

export type ThresholdSigningRuntimeBundle = {
  readonly thresholdSigningService: ThresholdSigningService;
  readonly routerAbNormalSigningRuntime: RouterAbNormalSigningRuntime;
  readonly routerAbLocalSigningSeedRuntime: RouterAbLocalSigningSeedRuntime;
  readonly routerAbEcdsaBootstrapExportRuntime: RouterAbEcdsaBootstrapExportRuntimeState;
};

export function createRouterAbEcdsaBootstrapExportRuntimeState(input: {
  readonly runtimeInput: Omit<
    ConstructorParameters<typeof RouterAbEcdsaBootstrapExportRuntime>[0],
    'signingRootShareResolver'
  >;
  readonly signingRootShareResolver: SigningRootShareResolver | null;
}): RouterAbEcdsaBootstrapExportRuntimeState {
  if (!input.signingRootShareResolver) return { kind: 'unconfigured' };
  return {
    kind: 'configured',
    runtime: new RouterAbEcdsaBootstrapExportRuntime({
      ...input.runtimeInput,
      signingRootShareResolver: input.signingRootShareResolver,
    }),
  };
}

function isNodeEnvironment(): boolean {
  const processObj = (globalThis as unknown as { process?: { versions?: { node?: string } } })
    .process;
  const isNode = Boolean(processObj?.versions?.node);
  const webSocketPair = (globalThis as unknown as { WebSocketPair?: unknown }).WebSocketPair;
  const isCloudflareWorker =
    typeof webSocketPair !== 'undefined' ||
    (typeof navigator !== 'undefined' &&
      String(navigator.userAgent || '').includes('Cloudflare-Workers'));
  return isNode && !isCloudflareWorker;
}

export function createThresholdSigningService(input: {
  authService: AuthService;
  thresholdStore?: ThresholdStoreConfigInput | null;
  signingRootShareResolver?: SigningRootShareResolver | null;
  logger?: Logger | null;
  isNode?: boolean;
}): ThresholdSigningRuntimeBundle {
  const logger = coerceLogger(input.logger);
  const isNode = input.isNode ?? isNodeEnvironment();
  const env = isNode
    ? (globalThis as unknown as { process?: { env?: Record<string, string | undefined> } }).process
        ?.env
    : undefined;
  const envFallback: ThresholdStoreConfigInput | null = env
    ? {
        UPSTASH_REDIS_REST_URL: env.UPSTASH_REDIS_REST_URL,
        UPSTASH_REDIS_REST_TOKEN: env.UPSTASH_REDIS_REST_TOKEN,
        REDIS_URL: env.REDIS_URL,
        THRESHOLD_PREFIX: env.THRESHOLD_PREFIX,
        THRESHOLD_ED25519_KEYSTORE_PREFIX: env.THRESHOLD_ED25519_KEYSTORE_PREFIX,
        THRESHOLD_ED25519_SESSION_PREFIX: env.THRESHOLD_ED25519_SESSION_PREFIX,
        THRESHOLD_ED25519_WALLET_SESSION_PREFIX: env.THRESHOLD_ED25519_WALLET_SESSION_PREFIX,
        THRESHOLD_WALLET_SIGNING_BUDGET_SESSION_PREFIX:
          env.THRESHOLD_WALLET_SIGNING_BUDGET_SESSION_PREFIX,
        THRESHOLD_ECDSA_KEYSTORE_PREFIX: env.THRESHOLD_ECDSA_KEYSTORE_PREFIX,
        THRESHOLD_ECDSA_SESSION_PREFIX: env.THRESHOLD_ECDSA_SESSION_PREFIX,
        THRESHOLD_ECDSA_WALLET_SESSION_PREFIX: env.THRESHOLD_ECDSA_WALLET_SESSION_PREFIX,
        THRESHOLD_ECDSA_PRESIGN_PREFIX: env.THRESHOLD_ECDSA_PRESIGN_PREFIX,
        THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID: env.THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID,
        THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID: env.THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID,
        THRESHOLD_NODE_ROLE: env.THRESHOLD_NODE_ROLE,
        THRESHOLD_COORDINATOR_SHARED_SECRET_B64U: env.THRESHOLD_COORDINATOR_SHARED_SECRET_B64U,
        THRESHOLD_COORDINATOR_INSTANCE_ID: env.THRESHOLD_COORDINATOR_INSTANCE_ID,
        THRESHOLD_COORDINATOR_PEERS: env.THRESHOLD_COORDINATOR_PEERS,
        THRESHOLD_ED25519_RELAYER_COSIGNERS: env.THRESHOLD_ED25519_RELAYER_COSIGNERS,
        THRESHOLD_ED25519_RELAYER_COSIGNER_ID: env.THRESHOLD_ED25519_RELAYER_COSIGNER_ID,
        THRESHOLD_ED25519_RELAYER_COSIGNER_T: env.THRESHOLD_ED25519_RELAYER_COSIGNER_T,
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: env.ROUTER_AB_NORMAL_SIGNING_WORKER_ID,
        ROUTER_AB_SIGNING_WORKER_URL: env.ROUTER_AB_SIGNING_WORKER_URL,
        ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: env.ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET,
      }
    : null;

  // Merge explicit config over env-derived defaults so callers can set
  // `kind: 'in-memory'` (etc) while still using env vars like THRESHOLD_NODE_ROLE.
  const config =
    isObject(envFallback) && isObject(input.thresholdStore)
      ? ({
          ...envFallback,
          ...input.thresholdStore,
        } as ThresholdStoreConfigInput)
      : (input.thresholdStore ?? envFallback);

  // Emit a single, non-sensitive config summary to help hosts confirm that threshold signing is wired up.
  try {
    const cosignersRaw = (config as { THRESHOLD_ED25519_RELAYER_COSIGNERS?: unknown })
      ?.THRESHOLD_ED25519_RELAYER_COSIGNERS;
    const cosignerCount = (() => {
      if (typeof cosignersRaw !== 'string') return null;
      const parsed = JSON.parse(cosignersRaw);
      return Array.isArray(parsed) ? parsed.length : null;
    })();
    const nodeRole = (config as { THRESHOLD_NODE_ROLE?: unknown })?.THRESHOLD_NODE_ROLE;
    const cosignerId = (config as { THRESHOLD_ED25519_RELAYER_COSIGNER_ID?: unknown })
      ?.THRESHOLD_ED25519_RELAYER_COSIGNER_ID;
    const cosignerT = (config as { THRESHOLD_ED25519_RELAYER_COSIGNER_T?: unknown })
      ?.THRESHOLD_ED25519_RELAYER_COSIGNER_T;
    logger.info('[threshold-ed25519] init', {
      isNode,
      nodeRole: typeof nodeRole === 'string' ? nodeRole : null,
      cosignerId: typeof cosignerId === 'string' ? cosignerId : null,
      cosignerT: typeof cosignerT === 'string' ? cosignerT : null,
      cosignerCount,
    });
  } catch {
    // Ignore logging issues; never block service creation.
  }

  const keyStore = createThresholdEd25519KeyStore({ config, logger, isNode });
  const sessionStore = createThresholdEd25519SessionStore({ config, logger, isNode });
  const walletSessionStore = createEd25519WalletSessionStore({ config, logger, isNode });
  const walletBudgetSessionStore = createWalletSigningBudgetSessionStore({
    config,
    logger,
    isNode,
  });

  const ecdsaKeyStore = createThresholdEcdsaKeyStore({ config, logger, isNode });
  const ecdsaSessionStore = createThresholdEcdsaSessionStore({ config, logger, isNode });
  const ecdsaWalletSessionStore = createEcdsaWalletSessionStore({ config, logger, isNode });
  const ecdsaSigningStores = createThresholdEcdsaSigningStores({ config, logger, isNode });
  const signingRootShareResolver =
    input.signingRootShareResolver ?? createConfiguredSigningRootShareResolver(config);

  const ensureReady = async (): Promise<void> => {
    await input.authService.getRelayerAccount();
  };

  const routerAbNormalSigningRuntime = new RouterAbNormalSigningRuntime({
    walletSessionStore,
    ecdsaWalletSessionStore,
    walletBudgetSessionStore,
    config: parseRouterAbNormalSigningRuntimeConfig(isObject(config) ? config : {}),
  });
  const routerAbLocalSigningSeedRuntime = new RouterAbLocalSigningSeedRuntime({
    ed25519KeyStore: keyStore,
    ed25519WalletSessionStore: walletSessionStore,
    ecdsaWalletSessionStore,
    normalSigningRuntime: routerAbNormalSigningRuntime,
  });
  const participantIds = parseThresholdEd25519ParticipantIds2p(
    isObject(config) ? config : {},
  );
  const routerAbEcdsaBootstrapExportRuntime =
    createRouterAbEcdsaBootstrapExportRuntimeState({
      signingRootShareResolver,
      runtimeInput: {
        ecdsaKeyStore,
        ecdsaWalletSessionStore,
        routerAbNormalSigningRuntime,
        participantIds: [
          participantIds.clientParticipantId,
          participantIds.relayerParticipantId,
        ],
      },
    });
  const thresholdSigningService = new ThresholdSigningService({
    logger,
    keyStore,
    sessionStore,
    walletSessionStore,
    routerAbNormalSigningRuntime,
    ecdsaKeyStore,
    ecdsaSessionStore,
    ecdsaWalletSessionStore,
    ecdsaPoolFillSessionStore: ecdsaSigningStores.poolFillSessionStore,
    ecdsaPresignaturePool: ecdsaSigningStores.presignaturePool,
    signingRootShareResolver,
    config,
    ensureReady,
    ensureSignerWasm: ensureReady,
    verifyWebAuthnAuthenticationLite: (req) =>
      input.authService.verifyWebAuthnAuthenticationLite(req),
    dispatchNearTransaction: (request) =>
      input.authService.dispatchNearSignedTransactionBorsh(request),
  });
  return {
    thresholdSigningService,
    routerAbNormalSigningRuntime,
    routerAbLocalSigningSeedRuntime,
    routerAbEcdsaBootstrapExportRuntime,
  };
}
