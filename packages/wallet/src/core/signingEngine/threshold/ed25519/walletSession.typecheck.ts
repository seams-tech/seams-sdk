import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type {
  Ed25519OperationStepUpAuthorizationRequest,
  Ed25519OperationStepUpProof,
  Ed25519WalletSessionMintAuthorization,
  ThresholdEd25519WebAuthnPrfSecretSource,
} from './walletSession';
import type { ProvisionWarmEd25519CapabilityArgs } from '../../session/warmCapabilities/types';
import type { RouterAbNormalSigningPrepareRequestV2Wire } from '@/core/rpcClients/relayer/routerAbNormalSigning';

declare const credential: WebAuthnAuthenticationCredential;
declare const webauthnPrfSource: ThresholdEd25519WebAuthnPrfSecretSource;
declare const normalSigningRequest: RouterAbNormalSigningPrepareRequestV2Wire;
declare const passkeyStepUpProof: Extract<Ed25519OperationStepUpProof, { kind: 'passkey' }>;
declare const emailOtpStepUpProof: Extract<Ed25519OperationStepUpProof, { kind: 'email_otp' }>;

const stepUpRequestBase = {
  relayerUrl: 'https://relay.example.test',
  normalSigningRequest,
  displayDigest: 'display-digest',
  credential: { kind: 'operation_step_up' as const },
};

const validPasskeyStepUpWithoutMaterialRecovery = {
  ...stepUpRequestBase,
  proof: passkeyStepUpProof,
  materialRecovery: { kind: 'not_requested' },
} satisfies Ed25519OperationStepUpAuthorizationRequest;
void validPasskeyStepUpWithoutMaterialRecovery;

const validEmailOtpStepUpWithoutMaterialRecovery = {
  ...stepUpRequestBase,
  proof: emailOtpStepUpProof,
  materialRecovery: { kind: 'not_requested' },
} satisfies Ed25519OperationStepUpAuthorizationRequest;
void validEmailOtpStepUpWithoutMaterialRecovery;

const invalidPasskeyStepUpWithLocalMaterialRecovery: Ed25519OperationStepUpAuthorizationRequest = {
  ...stepUpRequestBase,
  proof: passkeyStepUpProof,
  materialRecovery: {
    // @ts-expect-error Device-local Email OTP material recovery is retired.
    kind: 'email_otp_local_material_v1',
  },
};
void invalidPasskeyStepUpWithLocalMaterialRecovery;

const validThresholdPolicyWebAuthnAuth = {
  kind: 'threshold_session_policy_webauthn',
  policySecretSource: webauthnPrfSource,
} satisfies Ed25519WalletSessionMintAuthorization;
void validThresholdPolicyWebAuthnAuth;

const invalidThresholdPolicyWithLocalPrf: Ed25519WalletSessionMintAuthorization = {
  kind: 'threshold_session_policy_webauthn',
  policySecretSource: webauthnPrfSource,
  // @ts-expect-error Wallet Session policy WebAuthn auth cannot carry local PRF material.
  localSecretSource: webauthnPrfSource,
};
void invalidThresholdPolicyWithLocalPrf;

const invalidProvisionWithLooseLocalPrf = {
  kind: 'fresh_ed25519_provisioning',
  nearAccountId: 'alice.testnet',
  relayerKeyId: 'ed25519:relayer',
  participantIds: [1, 2],
  source: 'login',
  // @ts-expect-error Ed25519 provisioning requires discriminated auth instead of loose localPrfCredential.
  localPrfCredential: credential,
} satisfies ProvisionWarmEd25519CapabilityArgs;
void invalidProvisionWithLooseLocalPrf;
