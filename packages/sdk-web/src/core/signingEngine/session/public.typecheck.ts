import type { ThresholdEcdsaSessionBootstrapResult } from '../threshold/ecdsa/activation';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ListThresholdEcdsaSessionRecordsForWalletTargetInput,
  UpsertThresholdEcdsaSessionFromBootstrapInput,
} from './public';
import type { ConnectEd25519SessionArgs } from './passkey/public';
import type { RouterAbEd25519NormalSigningState } from '../threshold/ed25519/routerAbNormalSigningState';

declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const bootstrap: ThresholdEcdsaSessionBootstrapResult;
declare const routerAbNormalSigning: RouterAbEd25519NormalSigningState;
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

const connectEmailOtpEd25519SessionArgs: ConnectEd25519SessionArgs = {
  kind: 'exact_ed25519_provisioning',
  walletId,
  nearAccountId: 'alice.testnet',
  nearEd25519SigningKeyId: 'ed25519ks_alice',
  relayerKeyId: 'router-key-1',
  routerAbNormalSigning,
  participantIds: [1, 2],
  sessionKind: 'jwt',
  signerSlot: 1,
  sessionId: 'threshold-ed25519-session-1',
  signingGrantId: 'wallet-session-1',
  source: 'email_otp',
  authority: {
    kind: 'exact_authority_scope',
    authorityScope: {
      kind: 'email_otp',
      proofKind: 'otp_challenge',
      email: 'alice@example.test',
    },
  },
  emailOtpAuthContext,
};
void connectEmailOtpEd25519SessionArgs;

// @ts-expect-error Email OTP Ed25519 session minting must use exact email authority.
const invalidEmailOtpEd25519SessionPasskeyAuthorityArgs: ConnectEd25519SessionArgs = {
  kind: 'exact_ed25519_provisioning',
  walletId,
  nearAccountId: 'alice.testnet',
  nearEd25519SigningKeyId: 'ed25519ks_alice',
  relayerKeyId: 'router-key-1',
  routerAbNormalSigning,
  participantIds: [1, 2],
  sessionKind: 'jwt',
  signerSlot: 1,
  sessionId: 'threshold-ed25519-session-1',
  signingGrantId: 'wallet-session-1',
  source: 'email_otp',
  authority: { kind: 'passkey_rp', rpId: 'wallet.example.test' },
  emailOtpAuthContext,
};
void invalidEmailOtpEd25519SessionPasskeyAuthorityArgs;
