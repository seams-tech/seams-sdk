import type { ThresholdEcdsaSessionBootstrapResult } from '../threshold/ecdsa/activation';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ListThresholdEcdsaSessionRecordsForWalletTargetInput,
  UpsertThresholdEcdsaSessionFromBootstrapInput,
} from './public';

declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const bootstrap: ThresholdEcdsaSessionBootstrapResult;
declare const emailOtpAuthContext: {
  policy: 'session';
  retention: 'session';
  reason: 'login';
  authMethod: 'email_otp';
};

const upsertThresholdEcdsaSessionFromBootstrapArgs: UpsertThresholdEcdsaSessionFromBootstrapInput =
  {
    walletId,
    chainTarget,
    bootstrap,
    source: 'registration',
  };
void upsertThresholdEcdsaSessionFromBootstrapArgs;

const emailOtpUpsertThresholdEcdsaSessionFromBootstrapArgs: UpsertThresholdEcdsaSessionFromBootstrapInput =
  {
    walletId,
    chainTarget,
    bootstrap,
    source: 'email_otp',
    emailOtpAuthContext,
  };
void emailOtpUpsertThresholdEcdsaSessionFromBootstrapArgs;

// @ts-expect-error Email OTP ECDSA upsert requires the auth context.
const invalidEmailOtpUpsertThresholdEcdsaSessionFromBootstrapArgs: UpsertThresholdEcdsaSessionFromBootstrapInput =
  {
    walletId,
    chainTarget,
    bootstrap,
    source: 'email_otp',
  };
void invalidEmailOtpUpsertThresholdEcdsaSessionFromBootstrapArgs;

const invalidUpsertThresholdEcdsaSessionFromBootstrapArgs: UpsertThresholdEcdsaSessionFromBootstrapInput =
  {
    // @ts-expect-error wallet-domain ECDSA bootstrap upsert requires WalletId.
    walletId: 'alice.testnet',
    chainTarget,
    bootstrap,
    source: 'registration',
  };
void invalidUpsertThresholdEcdsaSessionFromBootstrapArgs;

const listThresholdEcdsaSessionRecordsForWalletTargetArgs: ListThresholdEcdsaSessionRecordsForWalletTargetInput =
  {
    walletId,
    chainTarget,
    source: 'registration',
  };
void listThresholdEcdsaSessionRecordsForWalletTargetArgs;

const invalidListThresholdEcdsaSessionRecordsForWalletTargetArgs: ListThresholdEcdsaSessionRecordsForWalletTargetInput =
  {
    walletId,
    chainTarget,
    source: 'registration',
    // @ts-expect-error public wallet-target session listing no longer accepts signing-root filters.
    signingRootId: 'project:dev',
  };
void invalidListThresholdEcdsaSessionRecordsForWalletTargetArgs;
