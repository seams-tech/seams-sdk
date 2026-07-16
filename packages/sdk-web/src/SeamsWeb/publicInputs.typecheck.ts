import {
  walletSessionRefFromSession,
  nearAccountRefFromAccountId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ExactEcdsaSigningLaneIdentity } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { SignedTransaction } from '@/core/rpcClients/near/NearClient';
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
declare const exactEcdsaLaneIdentity: ExactEcdsaSigningLaneIdentity;

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

const evmExecuteRequest = {
  chain: 'evm',
  kind: 'eip1559',
  senderSignatureAlgorithm: 'secp256k1',
  tx: {
    chainId: 1313,
    maxPriorityFeePerGas: 1n,
    maxFeePerGas: 1n,
    gasLimit: 21_000n,
    to: '0x1111111111111111111111111111111111111111',
    value: 0n,
    data: '0x',
  },
} satisfies Extract<SignTempoArgs['request'], { chain: 'evm' }>;

const tempoExecuteRequest = {
  chain: 'tempo',
  kind: 'tempoTransaction',
  senderSignatureAlgorithm: 'secp256k1',
  tx: {
    chainId: 1313,
    maxPriorityFeePerGas: 1n,
    maxFeePerGas: 1n,
    gasLimit: 21_000n,
    calls: [
      {
        to: '0x2222222222222222222222222222222222222222',
        value: 0n,
        input: '0x',
      },
    ],
    nonceKey: 0n,
  },
} satisfies Extract<SignTempoArgs['request'], { chain: 'tempo' }>;

const validEvmExecuteWithPayloadExpectation: Extract<
  ExecuteEvmFamilyTransactionArgs,
  { request: { chain: 'evm' } }
> = {
  walletSession,
  request: evmExecuteRequest,
  chainTarget: tempoChainTarget,
  payloadExpectation: {
    kind: 'evm_eip1559',
    to: '0x1111111111111111111111111111111111111111',
    input: '0x',
  },
};
void validEvmExecuteWithPayloadExpectation;

const invalidEvmExecuteWithTempoPayloadExpectation: Extract<
  ExecuteEvmFamilyTransactionArgs,
  { request: { chain: 'evm' } }
> = {
  walletSession,
  request: evmExecuteRequest,
  chainTarget: tempoChainTarget,
  payloadExpectation: {
    // @ts-expect-error EVM execution only accepts top-level EIP-1559 payload expectations.
    kind: 'tempo_eip2718_calls',
    calls: [{ to: '0x2222222222222222222222222222222222222222', input: '0x' }],
  },
};
void invalidEvmExecuteWithTempoPayloadExpectation;

const validTempoExecuteWithPayloadExpectation: Extract<
  ExecuteEvmFamilyTransactionArgs,
  { request: { chain: 'tempo' } }
> = {
  walletSession,
  request: tempoExecuteRequest,
  chainTarget: tempoChainTarget,
  payloadExpectation: {
    kind: 'tempo_eip2718_calls',
    calls: [{ to: '0x2222222222222222222222222222222222222222', input: '0x' }],
  },
};
void validTempoExecuteWithPayloadExpectation;

const invalidTempoExecuteWithEvmPayloadExpectation: Extract<
  ExecuteEvmFamilyTransactionArgs,
  { request: { chain: 'tempo' } }
> = {
  walletSession,
  request: tempoExecuteRequest,
  chainTarget: tempoChainTarget,
  payloadExpectation: {
    // @ts-expect-error Tempo EIP-2718 execution only accepts call-list payload expectations.
    kind: 'evm_eip1559',
    to: '0x1111111111111111111111111111111111111111',
    input: '0x',
  },
};
void invalidTempoExecuteWithEvmPayloadExpectation;

const validEcdsaBootstrapInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  chainTarget: tempoChainTarget,
};
void validEcdsaBootstrapInput;

const validNearEmailOtpRegistrationInput: Parameters<
  NearSignerCapability['registerNearWallet']
>[0] = {
  authMethod: {
    kind: 'email_otp',
    proofKind: 'otp_challenge',
    email: 'alice@example.test',
    otpCode: '123456',
    appSessionJwt: 'email-otp-app-session-jwt',
  },
};
void validNearEmailOtpRegistrationInput;

declare const signedNearTransaction: SignedTransaction;

// @ts-expect-error Public NEAR broadcast requires wallet session and account subject.
const invalidNearSendTransactionMissingSubject: Parameters<
  NearSignerCapability['sendTransaction']
>[0] = {
  signedTransaction: signedNearTransaction,
};
void invalidNearSendTransactionMissingSubject;

const validNearSendTransactionInput: Parameters<NearSignerCapability['sendTransaction']>[0] = {
  walletSession,
  nearAccount: nearAccountRefFromAccountId('wallet.testnet'),
  signedTransaction: signedNearTransaction,
};
void validNearSendTransactionInput;

const validEvmEmailOtpRegistrationInput: Parameters<EvmSignerCapability['registerEvmWallet']>[0] = {
  chainTargets: [tempoChainTarget],
  participantIds: [1, 2],
  authMethod: {
    kind: 'email_otp',
    proofKind: 'otp_challenge',
    email: 'alice@example.test',
    otpCode: '123456',
    appSessionJwt: 'email-otp-app-session-jwt',
  },
};
void validEvmEmailOtpRegistrationInput;

declare const registrationCapability: RegistrationCapability;
const legacyPublicNearMode = ['ed25519', 'only'].join('_');
const legacyPublicEvmMode = ['ecdsa', 'only'].join('_');

void registrationCapability.registerWithEmailOtp({
  wallet: {
    kind: 'provided',
    walletId: 'alice.testnet' as import('@shared/utils/registrationIntent').WalletId,
  },
  signerSelection: {
    kind: 'signer_set',
    signers: [
      {
        kind: 'evm_family_ecdsa',
        chainTargets: [tempoChainTarget],
        participantIds: [1, 2],
      },
    ],
  },
  authMethod: {
    kind: 'email_otp',
    proofKind: 'otp_challenge',
    email: 'alice@example.test',
    otpCode: '123456',
    appSessionJwt: 'email-otp-app-session-jwt',
  },
});

void registrationCapability.registerWallet({
  wallet: {
    kind: 'provided',
    walletId: 'alice.testnet' as import('@shared/utils/registrationIntent').WalletId,
  },
  authMethod: {
    kind: 'passkey',
    rpId: 'wallet.example.test' as import('@shared/utils/domainIds').WebAuthnRpId,
  },
    signerSelection: {
    // @ts-expect-error Public wallet registration accepts signer-set requests, not legacy modes.
    mode: legacyPublicNearMode,
    // @ts-expect-error Public wallet registration accepts signer-set requests, not legacy modes.
    ed25519: {
      accountProvisioning: {
        kind: 'implicit_account',
        accountIdSource: 'ed25519_public_key',
      },
      signerSlot: 1,
      participantIds: [1, 2],
      keyPurpose: 'near_tx',
      keyVersion: 'router-ab-ed25519-yao-v1',
      derivationVersion: 1,
    },
  },
});

void registrationCapability.registerWithEmailOtp({
  wallet: {
    kind: 'provided',
    walletId: 'alice.testnet' as import('@shared/utils/registrationIntent').WalletId,
  },
  authMethod: {
    kind: 'email_otp',
    proofKind: 'otp_challenge',
    email: 'alice@example.test',
    otpCode: '123456',
    appSessionJwt: 'email-otp-app-session-jwt',
  },
  signerSelection: {
    // @ts-expect-error Public Email OTP registration accepts signer-set requests, not legacy modes.
    mode: legacyPublicEvmMode,
    // @ts-expect-error Public Email OTP registration accepts signer-set requests, not legacy modes.
    ecdsa: {
      chainTargets: [tempoChainTarget],
      participantIds: [1, 2],
    },
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

const invalidEcdsaBootstrapRouterApiInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  chainTarget: tempoChainTarget,
  // @ts-expect-error Public bootstrap rejects projection fields.
  [forbiddenProjectionRelayField]: 'https://relay.example',
};
void invalidEcdsaBootstrapRouterApiInput;

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
const invalidPublicBootstrapEcdsaKeyId =
  // @ts-expect-error Public bootstrap keyRef hides internal threshold key identity.
  publicEcdsaBootstrapResult.thresholdEcdsaKeyRef.ecdsaThresholdKeyId;
void invalidPublicBootstrapEcdsaKeyId;
const invalidPublicBootstrapSigningRootId =
  // @ts-expect-error Public bootstrap keyRef hides internal signing-root identity.
  publicEcdsaBootstrapResult.thresholdEcdsaKeyRef.signingRootId;
void invalidPublicBootstrapSigningRootId;
const invalidPublicBootstrapSigningRootVersion =
  // @ts-expect-error Public bootstrap keyRef hides internal signing-root identity.
  publicEcdsaBootstrapResult.thresholdEcdsaKeyRef.signingRootVersion;
void invalidPublicBootstrapSigningRootVersion;
const invalidPublicBootstrapExportArtifact =
  // @ts-expect-error Public bootstrap keyRef hides internal export artifact identity.
  publicEcdsaBootstrapResult.thresholdEcdsaKeyRef.ecdsaDerivationExportArtifact;
void invalidPublicBootstrapExportArtifact;
const invalidPublicBootstrapWalletSessionJwt =
  // @ts-expect-error Public bootstrap keyRef hides internal Wallet Session bearer auth.
  publicEcdsaBootstrapResult.thresholdEcdsaKeyRef.walletSessionJwt;
void invalidPublicBootstrapWalletSessionJwt;

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
  laneIdentity: exactEcdsaLaneIdentity,
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
