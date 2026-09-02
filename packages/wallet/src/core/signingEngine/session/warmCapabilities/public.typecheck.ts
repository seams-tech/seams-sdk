import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { PersistThresholdEcdsaBootstrapForWalletTargetInput } from './public';
import { SIGNER_AUTH_METHODS, SIGNER_SOURCES } from '@shared/utils/signerDomain';

declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const bootstrap: ThresholdEcdsaSessionBootstrapResult;

const persistThresholdEcdsaBootstrapArgs: PersistThresholdEcdsaBootstrapForWalletTargetInput = {
  walletId,
  chainTarget,
  bootstrap,
  signerAuth: {
    authMethod: SIGNER_AUTH_METHODS.passkey,
    signerSource: SIGNER_SOURCES.passkeyRegistration,
  },
};
void persistThresholdEcdsaBootstrapArgs;

const invalidPersistThresholdEcdsaBootstrapArgs: PersistThresholdEcdsaBootstrapForWalletTargetInput =
  {
    // @ts-expect-error wallet-domain ECDSA bootstrap persistence requires WalletId.
    walletId: 'alice.testnet',
    chainTarget,
    bootstrap,
    signerAuth: {
      authMethod: SIGNER_AUTH_METHODS.passkey,
      signerSource: SIGNER_SOURCES.passkeyRegistration,
    },
  };
void invalidPersistThresholdEcdsaBootstrapArgs;
