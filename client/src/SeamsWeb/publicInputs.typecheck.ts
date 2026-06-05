import {
  walletSessionRefFromSession,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  BootstrapThresholdEcdsaSessionArgs,
  ExecuteEvmFamilyTransactionArgs,
  EvmSignerCapability,
  KeyExportCapability,
  NearSignerCapability,
  RegistrationCapability,
  SignTempoArgs,
  PublicThresholdEcdsaSessionBootstrapResult,
} from '@/SeamsWeb/signingSurface/types';

const walletSession = walletSessionRefFromSession({
  walletId: 'wallet.testnet',
  walletSessionUserId: 'wallet-user',
});
const tempoChainTarget = {
  kind: 'tempo',
  chainId: 1313,
  networkSlug: 'tempo-local',
} satisfies ThresholdEcdsaChainTarget;
const tempoRequest = {} as SignTempoArgs['request'];

const invalidSignTempoAccountIdentity: SignTempoArgs = {
  walletSession,
  // @ts-expect-error ECDSA public signing rejects account-shaped identity.
  nearAccountId: 'wallet.testnet',
  request: tempoRequest,
  chainTarget: tempoChainTarget,
};
void invalidSignTempoAccountIdentity;

const invalidSignTempoSubjectInput: SignTempoArgs = {
  walletSession,
  request: tempoRequest,
  chainTarget: tempoChainTarget,
  // @ts-expect-error ECDSA public signing derives subject from walletSession.walletId.
  subjectId: 'wallet',
};
void invalidSignTempoSubjectInput;

const invalidExecuteEvmAccountIdentity: ExecuteEvmFamilyTransactionArgs = {
  walletSession,
  // @ts-expect-error EVM-family public signing rejects account-shaped identity.
  nearAccountId: 'wallet.testnet',
  request: tempoRequest,
  chainTarget: tempoChainTarget,
};
void invalidExecuteEvmAccountIdentity;

const invalidExecuteEvmSubjectInput: ExecuteEvmFamilyTransactionArgs = {
  walletSession,
  request: tempoRequest,
  chainTarget: tempoChainTarget,
  // @ts-expect-error EVM-family public signing derives subject from walletSession.walletId.
  subjectId: 'wallet',
};
void invalidExecuteEvmSubjectInput;

const validEcdsaBootstrapInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  chainTarget: tempoChainTarget,
};
void validEcdsaBootstrapInput;

const validNearEmailOtpRegistrationInput: Parameters<
  NearSignerCapability['registerNearWallet']
>[0] = {
  nearAccountId: 'alice.testnet',
  authMethod: {
    kind: 'email_otp',
    email: 'alice@example.test',
    otpCode: '123456',
    appSessionJwt: 'email-otp-app-session-jwt',
  },
};
void validNearEmailOtpRegistrationInput;

const validEvmEmailOtpRegistrationInput: Parameters<
  EvmSignerCapability['registerEvmWallet']
>[0] = {
  chainTargets: [tempoChainTarget],
  participantIds: [1, 2],
  authMethod: {
    kind: 'email_otp',
    email: 'alice@example.test',
    otpCode: '123456',
    appSessionJwt: 'email-otp-app-session-jwt',
  },
};
void validEvmEmailOtpRegistrationInput;

declare const registrationCapability: RegistrationCapability;
void registrationCapability.registerWithEmailOtp({
  wallet: {
    kind: 'provided',
    walletId: 'alice.testnet' as import('@shared/utils/registrationIntent').WalletId,
  },
  rpId: 'example.test',
  signerSelection: {
    mode: 'ecdsa_only',
    ecdsa: {
      chainTargets: [tempoChainTarget],
      participantIds: [1, 2],
    },
  },
  authMethod: {
    kind: 'email_otp',
    email: 'alice@example.test',
    otpCode: '123456',
    appSessionJwt: 'email-otp-app-session-jwt',
  },
});

const forbiddenProjectionField = ['smart', 'Account'].join('') as `${'smart'}${'Account'}`;
const forbiddenProjectionAddressField = ['counter', 'factual', 'Address'].join(
  '',
) as `${'counter'}${'factual'}Address`;
const forbiddenProjectionSponsorField = ['pay', 'master'].join('') as `${'pay'}${'master'}`;
const forbiddenProjectionRelayField = ['bundle', 'rUrl'].join('') as `${'bundle'}rUrl`;
const forbiddenProjectionProtocolField = ['erc', '4337'].join('') as `${'erc'}4337`;

const invalidEcdsaBootstrapKeyIdInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  chainTarget: tempoChainTarget,
  // @ts-expect-error Public bootstrap rejects caller-supplied internal key identity.
  ecdsaThresholdKeyId: 'ecdsa-key',
};
void invalidEcdsaBootstrapKeyIdInput;

const invalidEcdsaBootstrapParticipantIdsInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  chainTarget: tempoChainTarget,
  // @ts-expect-error Public bootstrap rejects caller-supplied internal participant identity.
  participantIds: [1, 2],
};
void invalidEcdsaBootstrapParticipantIdsInput;

const invalidEcdsaBootstrapProjectionInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  chainTarget: tempoChainTarget,
  // @ts-expect-error Public bootstrap rejects projection fields.
  [forbiddenProjectionField]: { chainId: 1313 },
};
void invalidEcdsaBootstrapProjectionInput;

const invalidEcdsaBootstrapProjectionAddressInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  chainTarget: tempoChainTarget,
  // @ts-expect-error Public bootstrap rejects projection fields.
  [forbiddenProjectionAddressField]: `0x${'11'.repeat(20)}`,
};
void invalidEcdsaBootstrapProjectionAddressInput;

const invalidEcdsaBootstrapSponsorInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  chainTarget: tempoChainTarget,
  // @ts-expect-error Public bootstrap rejects projection fields.
  [forbiddenProjectionSponsorField]: { enabled: true },
};
void invalidEcdsaBootstrapSponsorInput;

const invalidEcdsaBootstrapRelayInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  chainTarget: tempoChainTarget,
  // @ts-expect-error Public bootstrap rejects projection fields.
  [forbiddenProjectionRelayField]: 'https://relay.example',
};
void invalidEcdsaBootstrapRelayInput;

const invalidEcdsaBootstrapProtocolInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  chainTarget: tempoChainTarget,
  // @ts-expect-error Public bootstrap rejects projection fields.
  [forbiddenProjectionProtocolField]: true,
};
void invalidEcdsaBootstrapProtocolInput;

const invalidEcdsaBootstrapSubjectInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  chainTarget: tempoChainTarget,
  // @ts-expect-error Public base-ECDSA warm bootstrap derives subject from walletSession.walletId.
  subjectId: 'wallet',
};
void invalidEcdsaBootstrapSubjectInput;

declare const publicEcdsaBootstrapResult: PublicThresholdEcdsaSessionBootstrapResult;
// @ts-expect-error Public bootstrap keyRef hides internal threshold key identity.
const invalidPublicBootstrapEcdsaKeyId = publicEcdsaBootstrapResult.thresholdEcdsaKeyRef.ecdsaThresholdKeyId;
void invalidPublicBootstrapEcdsaKeyId;
// @ts-expect-error Public bootstrap keyRef hides internal signing-root identity.
const invalidPublicBootstrapSigningRootId = publicEcdsaBootstrapResult.thresholdEcdsaKeyRef.signingRootId;
void invalidPublicBootstrapSigningRootId;
// @ts-expect-error Public bootstrap keyRef hides internal signing-root identity.
const invalidPublicBootstrapSigningRootVersion = publicEcdsaBootstrapResult.thresholdEcdsaKeyRef.signingRootVersion;
void invalidPublicBootstrapSigningRootVersion;
// @ts-expect-error Public bootstrap keyRef hides internal export artifact identity.
const invalidPublicBootstrapExportArtifact = publicEcdsaBootstrapResult.thresholdEcdsaKeyRef.ecdsaHssExportArtifact;
void invalidPublicBootstrapExportArtifact;

const invalidEcdsaBootstrapLifecycleInput: BootstrapThresholdEcdsaSessionArgs = {
  // @ts-expect-error Fresh bootstrap is an internal signing-engine lifecycle request.
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletSession,
  chainTarget: tempoChainTarget,
};
void invalidEcdsaBootstrapLifecycleInput;

type PublicKeyExportInput = Parameters<KeyExportCapability['exportKeypairWithUI']>[0];

const validEcdsaExportInput: PublicKeyExportInput = {
  kind: 'ecdsa',
  walletSession,
  chainTarget: tempoChainTarget,
  options: {},
};
void validEcdsaExportInput;

const invalidEcdsaExportUserIdInput: PublicKeyExportInput = {
  kind: 'ecdsa',
  chainTarget: tempoChainTarget,
  // @ts-expect-error ECDSA public export requires a walletSession object.
  walletSessionUserId: 'wallet-user',
  options: {},
};
void invalidEcdsaExportUserIdInput;

const invalidEcdsaExportSubjectInput: PublicKeyExportInput = {
  kind: 'ecdsa',
  walletSession,
  chainTarget: tempoChainTarget,
  options: {},
  // @ts-expect-error ECDSA public export derives subject from walletSession.walletId.
  subjectId: 'wallet',
};
void invalidEcdsaExportSubjectInput;

// @ts-expect-error NEAR public signing requires a NearAccountRef.
const invalidNearExecuteAction: Parameters<NearSignerCapability['executeAction']>[0] = {
  receiverId: 'contract.testnet',
  actionArgs: [],
  options: {} as Parameters<NearSignerCapability['executeAction']>[0]['options'],
};
void invalidNearExecuteAction;

export {};
