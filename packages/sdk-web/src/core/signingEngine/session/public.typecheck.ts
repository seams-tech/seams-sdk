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
import type {
  BuildEmailOtpEd25519SessionPolicyParams,
  BuildPasskeyEd25519SessionPolicyParams,
  Ed25519AuthorityScope,
} from '../threshold/sessionPolicy';
import type { WebAuthnRpId } from '@shared/utils/domainIds';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  type EmailOtpAuthUse,
} from './identity/laneIdentity';

declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const bootstrap: ThresholdEcdsaSessionBootstrapResult;
declare const routerAbNormalSigning: RouterAbEd25519NormalSigningState;
declare const rpId: WebAuthnRpId;
const passkeyWalletAuthAuthority = buildPasskeyWalletAuthAuthority({
  walletId,
  rpId,
  credentialIdB64u: 'credential-id',
});
const emailOtpAuthContext = buildEmailOtpAuthContextForWalletAuthMethod({
walletId: 'wallet.testnet',
emailHashHex: 'email-hash',
policy: 'session',
  retention: 'session',
  reason: 'login',
  provider: 'google',
  providerUserId: 'google-subject-1',
});

const invalidPendingSingleUseEmailOtpAuthUse = {
  kind: 'single_use_pending',
  // @ts-expect-error single-use Email OTP auth use is branch-defined and carries no constant reason.
  reason: 'sign',
} satisfies EmailOtpAuthUse;
void invalidPendingSingleUseEmailOtpAuthUse;

const invalidConsumedSingleUseEmailOtpAuthUse = {
  kind: 'single_use_consumed',
  consumedAtMs: 1,
  // @ts-expect-error consumed single-use Email OTP auth use is branch-defined and carries no constant reason.
  reason: 'sign',
} satisfies EmailOtpAuthUse;
void invalidConsumedSingleUseEmailOtpAuthUse;

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
  authority: { kind: 'wallet_auth_authority', authority: emailOtpAuthContext.authority },
  emailOtpAuthContext,
};
void connectEmailOtpEd25519SessionArgs;

const invalidEmailOtpEd25519AuthorityScopeWithProofKind = {
  kind: 'email_otp',
  provider: 'google',
  providerUserId: 'google:alice',
  // @ts-expect-error Email OTP Ed25519 authority scopes cannot carry registration proof kind.
  proofKind: 'otp_challenge',
} satisfies Ed25519AuthorityScope;

const invalidEmailOtpEd25519AuthorityScopeWithGoogleRegistrationIds = {
  kind: 'email_otp',
  provider: 'google',
  providerUserId: 'google:alice',
  // @ts-expect-error Email OTP Ed25519 authority scopes cannot carry Google registration proof IDs.
  googleEmailOtpRegistrationAttemptId: 'attempt-1',
} satisfies Ed25519AuthorityScope;
void invalidEmailOtpEd25519AuthorityScopeWithProofKind;
void invalidEmailOtpEd25519AuthorityScopeWithGoogleRegistrationIds;

const passkeyEd25519PolicyParams: BuildPasskeyEd25519SessionPolicyParams = {
  walletId,
  nearAccountId: 'alice.testnet',
  nearEd25519SigningKeyId: 'ed25519ks_alice',
  relayerKeyId: 'router-key-1',
  routerAbNormalSigning,
  authority: passkeyWalletAuthAuthority,
};
void passkeyEd25519PolicyParams;

const invalidPasskeyEd25519PolicyParamsWithRpId: BuildPasskeyEd25519SessionPolicyParams = {
  walletId,
  nearAccountId: 'alice.testnet',
  nearEd25519SigningKeyId: 'ed25519ks_alice',
  relayerKeyId: 'router-key-1',
  routerAbNormalSigning,
  authority: passkeyWalletAuthAuthority,
  // @ts-expect-error passkey Ed25519 policy builder requires wallet auth authority, not raw RP ID.
  rpId,
};
void invalidPasskeyEd25519PolicyParamsWithRpId;

const invalidPasskeyEd25519PolicyParamsWithAuthorityScope: BuildPasskeyEd25519SessionPolicyParams =
  {
    ...passkeyEd25519PolicyParams,
    // @ts-expect-error passkey Ed25519 policy builder rejects exact authority scope inputs.
    authorityScope: { kind: 'passkey_rp', rpId },
  };
void invalidPasskeyEd25519PolicyParamsWithAuthorityScope;

const emailOtpEd25519PolicyParams: BuildEmailOtpEd25519SessionPolicyParams = {
  walletId,
  nearAccountId: 'alice.testnet',
  nearEd25519SigningKeyId: 'ed25519ks_alice',
  relayerKeyId: 'router-key-1',
  routerAbNormalSigning,
  authority: emailOtpAuthContext.authority,
};
void emailOtpEd25519PolicyParams;

const invalidEmailOtpEd25519PolicyParamsWithRpId: BuildEmailOtpEd25519SessionPolicyParams = {
  ...emailOtpEd25519PolicyParams,
  // @ts-expect-error Email OTP Ed25519 policy builder rejects passkey RP ID inputs.
  rpId,
};
void invalidEmailOtpEd25519PolicyParamsWithRpId;

// @ts-expect-error Email OTP Ed25519 session minting must use Email OTP wallet authority.
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
  authority: { kind: 'wallet_auth_authority', authority: passkeyWalletAuthAuthority },
  emailOtpAuthContext,
};
void invalidEmailOtpEd25519SessionPasskeyAuthorityArgs;
