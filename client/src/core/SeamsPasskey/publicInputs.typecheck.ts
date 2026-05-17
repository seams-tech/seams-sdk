import {
  toWalletSubjectId,
  walletSessionRefFromSession,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  BootstrapThresholdEcdsaSessionArgs,
  ExecuteEvmFamilyTransactionArgs,
  KeyExportCapability,
  NearSignerCapability,
  SignTempoArgs,
} from './interfaces';

const walletSession = walletSessionRefFromSession({
  walletId: 'wallet.testnet',
  walletSessionUserId: 'wallet-user',
});
const subjectId = toWalletSubjectId('wallet-subject');
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
  subjectId,
  request: tempoRequest,
  chainTarget: tempoChainTarget,
};
void invalidSignTempoAccountIdentity;

const invalidExecuteEvmAccountIdentity: ExecuteEvmFamilyTransactionArgs = {
  walletSession,
  // @ts-expect-error EVM-family public signing rejects account-shaped identity.
  nearAccountId: 'wallet.testnet',
  subjectId,
  request: tempoRequest,
  chainTarget: tempoChainTarget,
};
void invalidExecuteEvmAccountIdentity;

const validEcdsaBootstrapInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  subjectId,
  chainTarget: tempoChainTarget,
};
void validEcdsaBootstrapInput;

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
  subjectId,
  chainTarget: tempoChainTarget,
  // @ts-expect-error Public bootstrap rejects caller-supplied internal key identity.
  ecdsaThresholdKeyId: 'ecdsa-key',
};
void invalidEcdsaBootstrapKeyIdInput;

const invalidEcdsaBootstrapParticipantIdsInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  subjectId,
  chainTarget: tempoChainTarget,
  // @ts-expect-error Public bootstrap rejects caller-supplied internal participant identity.
  participantIds: [1, 2],
};
void invalidEcdsaBootstrapParticipantIdsInput;

const invalidEcdsaBootstrapProjectionInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  subjectId,
  chainTarget: tempoChainTarget,
  // @ts-expect-error Public bootstrap rejects projection fields.
  [forbiddenProjectionField]: { chainId: 1313 },
};
void invalidEcdsaBootstrapProjectionInput;

const invalidEcdsaBootstrapProjectionAddressInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  subjectId,
  chainTarget: tempoChainTarget,
  // @ts-expect-error Public bootstrap rejects projection fields.
  [forbiddenProjectionAddressField]: `0x${'11'.repeat(20)}`,
};
void invalidEcdsaBootstrapProjectionAddressInput;

const invalidEcdsaBootstrapSponsorInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  subjectId,
  chainTarget: tempoChainTarget,
  // @ts-expect-error Public bootstrap rejects projection fields.
  [forbiddenProjectionSponsorField]: { enabled: true },
};
void invalidEcdsaBootstrapSponsorInput;

const invalidEcdsaBootstrapRelayInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  subjectId,
  chainTarget: tempoChainTarget,
  // @ts-expect-error Public bootstrap rejects projection fields.
  [forbiddenProjectionRelayField]: 'https://relay.example',
};
void invalidEcdsaBootstrapRelayInput;

const invalidEcdsaBootstrapProtocolInput: BootstrapThresholdEcdsaSessionArgs = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  subjectId,
  chainTarget: tempoChainTarget,
  // @ts-expect-error Public bootstrap rejects projection fields.
  [forbiddenProjectionProtocolField]: true,
};
void invalidEcdsaBootstrapProtocolInput;

const invalidEcdsaBootstrapLifecycleInput: BootstrapThresholdEcdsaSessionArgs = {
  // @ts-expect-error Fresh bootstrap is an internal signing-engine lifecycle request.
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletSession,
  subjectId,
  chainTarget: tempoChainTarget,
};
void invalidEcdsaBootstrapLifecycleInput;

type PublicKeyExportInput = Parameters<KeyExportCapability['exportKeypairWithUI']>[0];

const validEcdsaExportInput: PublicKeyExportInput = {
  kind: 'ecdsa',
  walletSession,
  subjectId,
  chainTarget: tempoChainTarget,
  options: {},
};
void validEcdsaExportInput;

const invalidEcdsaExportUserIdInput: PublicKeyExportInput = {
  kind: 'ecdsa',
  subjectId,
  chainTarget: tempoChainTarget,
  // @ts-expect-error ECDSA public export requires a walletSession object.
  walletSessionUserId: 'wallet-user',
  options: {},
};
void invalidEcdsaExportUserIdInput;

// @ts-expect-error NEAR public signing requires a NearAccountRef.
const invalidNearExecuteAction: Parameters<NearSignerCapability['executeAction']>[0] = {
  receiverId: 'contract.testnet',
  actionArgs: [],
  options: {} as Parameters<NearSignerCapability['executeAction']>[0]['options'],
};
void invalidNearExecuteAction;

export {};
