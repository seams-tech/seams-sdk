import type { ThresholdEcdsaSessionBootstrapResult } from '../threshold/ecdsa/activation';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ListThresholdEcdsaSessionRecordsForWalletTargetInput,
  UpsertThresholdEcdsaSessionFromBootstrapInput,
} from './public';
import type { ThresholdEcdsaSessionStoreSource } from './identity/laneIdentity';

declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const bootstrap: ThresholdEcdsaSessionBootstrapResult;
declare const source: ThresholdEcdsaSessionStoreSource;

const upsertThresholdEcdsaSessionFromBootstrapArgs: UpsertThresholdEcdsaSessionFromBootstrapInput =
  {
    walletId,
    chainTarget,
    bootstrap,
    source,
  };
void upsertThresholdEcdsaSessionFromBootstrapArgs;

const invalidUpsertThresholdEcdsaSessionFromBootstrapArgs: UpsertThresholdEcdsaSessionFromBootstrapInput =
  {
    // @ts-expect-error wallet-domain ECDSA bootstrap upsert requires WalletId.
    walletId: 'alice.testnet',
    chainTarget,
    bootstrap,
    source,
  };
void invalidUpsertThresholdEcdsaSessionFromBootstrapArgs;

const listThresholdEcdsaSessionRecordsForWalletTargetArgs: ListThresholdEcdsaSessionRecordsForWalletTargetInput =
  {
    walletId,
    chainTarget,
    source,
  };
void listThresholdEcdsaSessionRecordsForWalletTargetArgs;

const invalidListThresholdEcdsaSessionRecordsForWalletTargetArgs: ListThresholdEcdsaSessionRecordsForWalletTargetInput =
  {
    walletId,
    chainTarget,
    source,
    // @ts-expect-error public wallet-target session listing no longer accepts signing-root filters.
    signingRootId: 'project:dev',
  };
void invalidListThresholdEcdsaSessionRecordsForWalletTargetArgs;
