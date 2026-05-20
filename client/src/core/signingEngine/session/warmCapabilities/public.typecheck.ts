import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { PersistThresholdEcdsaBootstrapForWalletTargetInput } from './public';

declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const bootstrap: ThresholdEcdsaSessionBootstrapResult;

const persistThresholdEcdsaBootstrapArgs: PersistThresholdEcdsaBootstrapForWalletTargetInput = {
  walletId,
  chainTarget,
  bootstrap,
};
void persistThresholdEcdsaBootstrapArgs;

const invalidPersistThresholdEcdsaBootstrapArgs: PersistThresholdEcdsaBootstrapForWalletTargetInput =
  {
    // @ts-expect-error wallet-domain ECDSA bootstrap persistence requires WalletId.
    walletId: 'alice.testnet',
    chainTarget,
    bootstrap,
  };
void invalidPersistThresholdEcdsaBootstrapArgs;
