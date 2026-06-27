import type { AccessKeyList } from '../rpcClients/near/NearClient';
import type {
  ThresholdStoreConfigInput,
  VerifyAuthenticationResponse,
  WebAuthnAuthenticationCredential,
} from '../types';
import type { WebAuthnRpId } from '@shared/utils/domainIds';
import type { Logger } from '../logger';
import { coerceLogger } from '../logger';
import { ThresholdSigningService } from './ThresholdSigningService';
import { createConfiguredSigningRootShareResolver } from './signingRootSecretConfig';
import {
  createCloudflareDurableObjectThresholdEcdsaStores,
  createCloudflareDurableObjectThresholdEd25519Stores,
  createCloudflareDurableObjectWalletSigningBudgetStores,
} from './stores/CloudflareDurableObjectStore';

type ThresholdNearTransactionDispatchResult = {
  readonly rpcResult: unknown;
};

type ThresholdNearTransactionDispatcher = (input: {
  readonly signedTransactionBorshB64u: string;
}) => Promise<ThresholdNearTransactionDispatchResult>;

export type CloudflareDurableObjectThresholdSigningAuthPort = {
  readonly getRelayerAccount: () => Promise<unknown>;
  readonly verifyWebAuthnAuthenticationLite: (request: {
    readonly userId: string;
    readonly rpId: WebAuthnRpId;
    readonly expectedChallenge: string;
    readonly expected_origin: string;
    readonly webauthn_authentication: WebAuthnAuthenticationCredential;
  }) => Promise<VerifyAuthenticationResponse>;
  readonly viewAccessKeyList: (accountId: string) => Promise<AccessKeyList>;
  readonly dispatchNearSignedTransactionBorsh: ThresholdNearTransactionDispatcher;
};

export function createCloudflareDurableObjectThresholdSigningService(input: {
  readonly auth: CloudflareDurableObjectThresholdSigningAuthPort;
  readonly thresholdStore: ThresholdStoreConfigInput;
  readonly logger?: Logger | null;
}): ThresholdSigningService {
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
    throw new Error('Cloudflare D1 relay thresholdStore must use kind: "cloudflare-do"');
  }
  const ensureReady = async (): Promise<void> => {
    await input.auth.getRelayerAccount();
  };
  return new ThresholdSigningService({
    logger,
    keyStore: ed25519Stores.keyStore,
    sessionStore: ed25519Stores.sessionStore,
    walletSessionStore: ed25519Stores.walletSessionStore,
    walletBudgetSessionStore: walletBudgetStores.walletSessionStore,
    ecdsaKeyStore: ecdsaStores.keyStore,
    ecdsaSessionStore: ecdsaStores.sessionStore,
    ecdsaWalletSessionStore: ecdsaStores.walletSessionStore,
    ecdsaPoolFillSessionStore: ecdsaStores.poolFillSessionStore,
    ecdsaPresignaturePool: ecdsaStores.presignaturePool,
    signingRootShareResolver: createConfiguredSigningRootShareResolver(input.thresholdStore),
    config: input.thresholdStore,
    ensureReady,
    ensureSignerWasm: ensureReady,
    verifyWebAuthnAuthenticationLite: input.auth.verifyWebAuthnAuthenticationLite,
    viewAccessKeyList: input.auth.viewAccessKeyList,
    dispatchNearTransaction: input.auth.dispatchNearSignedTransactionBorsh,
  });
}
