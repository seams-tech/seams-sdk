import type { WebAuthnRpId } from '@shared/utils/domainIds';
import { coerceLogger, type Logger } from '../logger';
import type {
  ThresholdStoreConfigInput,
  VerifyAuthenticationResponse,
  WebAuthnAuthenticationCredential,
} from '../types';
import {
  createCloudflareDurableObjectThresholdEcdsaStores,
  createCloudflareDurableObjectThresholdEd25519Stores,
  createCloudflareDurableObjectWalletSigningBudgetStores,
} from '../ThresholdService/stores/CloudflareDurableObjectStore';
import type { RouterAbSigningRuntimeBundle } from './createRouterAbSigningRuntimes';
import {
  parseRouterAbEcdsaPresignRuntimeConfig,
  RouterAbEcdsaPresignRuntime,
} from './RouterAbEcdsaPresignRuntime';
import { RouterAbLocalSigningSeedRuntime } from './RouterAbLocalSigningSeedRuntime';
import {
  parseRouterAbNormalSigningRuntimeConfig,
  RouterAbNormalSigningRuntime,
} from './RouterAbNormalSigningRuntime';

type RouterAbNearTransactionDispatchResult = {
  readonly rpcResult: unknown;
};

type RouterAbNearTransactionDispatcher = (input: {
  readonly signedTransactionBorshB64u: string;
}) => Promise<RouterAbNearTransactionDispatchResult>;

export type CloudflareDurableObjectRouterAbSigningAuthPort = {
  readonly getRelayerAccount: () => Promise<unknown>;
  readonly verifyWebAuthnAuthenticationLite: (request: {
    readonly userId: string;
    readonly rpId: WebAuthnRpId;
    readonly expectedChallenge: string;
    readonly expected_origin: string;
    readonly webauthn_authentication: WebAuthnAuthenticationCredential;
  }) => Promise<VerifyAuthenticationResponse>;
  readonly dispatchNearSignedTransactionBorsh: RouterAbNearTransactionDispatcher;
};

async function ensureCloudflareRouterAbSigningRuntimeReady(
  this: Pick<CloudflareDurableObjectRouterAbSigningAuthPort, 'getRelayerAccount'>,
): Promise<void> {
  await this.getRelayerAccount();
}

export function createCloudflareDurableObjectRouterAbSigningRuntimes(input: {
  readonly auth: CloudflareDurableObjectRouterAbSigningAuthPort;
  readonly thresholdStore: ThresholdStoreConfigInput;
  readonly logger?: Logger | null;
}): RouterAbSigningRuntimeBundle {
  const logger = coerceLogger(input.logger);
  const ed25519Stores = createCloudflareDurableObjectThresholdEd25519Stores({
    config: input.thresholdStore,
    logger,
  });
  const walletBudgetStores = createCloudflareDurableObjectWalletSigningBudgetStores({
    config: input.thresholdStore,
    logger,
  });
  const ecdsaStores = createCloudflareDurableObjectThresholdEcdsaStores({
    config: input.thresholdStore,
    logger,
  });
  if (!ed25519Stores || !walletBudgetStores || !ecdsaStores) {
    throw new Error('Cloudflare D1 Router API thresholdStore must use kind: "cloudflare-do"');
  }
  const ensureReady = ensureCloudflareRouterAbSigningRuntimeReady.bind(input.auth);
  const normalSigning = new RouterAbNormalSigningRuntime({
    walletSessionStore: ed25519Stores.walletSessionStore,
    ecdsaWalletSessionStore: ecdsaStores.walletSessionStore,
    walletBudgetSessionStore: walletBudgetStores.walletSessionStore,
    config: parseRouterAbNormalSigningRuntimeConfig(input.thresholdStore),
  });
  const localSigningSeed = new RouterAbLocalSigningSeedRuntime({
    ed25519KeyStore: ed25519Stores.keyStore,
    ed25519WalletSessionStore: ed25519Stores.walletSessionStore,
    ecdsaWalletSessionStore: ecdsaStores.walletSessionStore,
    normalSigningRuntime: normalSigning,
  });
  const ecdsaPresign = new RouterAbEcdsaPresignRuntime({
    logger,
    config: parseRouterAbEcdsaPresignRuntimeConfig(input.thresholdStore),
    ecdsaSessionStore: ecdsaStores.sessionStore,
    ecdsaPoolFillSessionStore: ecdsaStores.poolFillSessionStore,
    ecdsaKeyStore: ecdsaStores.keyStore,
    normalSigningRuntime: normalSigning,
    ensureReady,
    liveSessionOwner: ecdsaStores.poolFillLiveSessionOwner,
  });

  return { normalSigning, localSigningSeed, ecdsaPresign };
}
