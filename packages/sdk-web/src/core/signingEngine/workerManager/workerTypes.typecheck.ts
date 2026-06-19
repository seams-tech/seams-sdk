import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import type {
  EmailOtpEcdsaBootstrapStrictPayload,
  EmailOtpEcdsaSessionBootstrapHandlePayload,
  EmailOtpWalletRegistrationEcdsaPrepareHandlePayload,
  EmailOtpWorkerIssuedSessionHandlePayload,
  EmailOtpWorkerOperationRequestEnvelope,
  EmailOtpWorkerOperationMap,
  EthSignerWorkerOperationMap,
} from './workerTypes';

declare const chainTarget: ThresholdEcdsaChainTarget;
declare const publicationChainTargets: ThresholdEcdsaChainTarget[];
declare const runtimePolicyScope: ThresholdRuntimePolicyScope;
declare const routeAuth: AppOrWalletSessionAuth;
declare const incomingMessage: ArrayBuffer;

const clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload = {
  kind: 'email_otp_worker_session_handle_v1',
  sessionId: 'otp-root-session',
  walletId: 'wallet.testnet',
  rpId: 'localhost',
  authSubjectId: 'google:subject',
  action: 'threshold_ecdsa_bootstrap',
  operation: 'registration',
  chainTarget,
};

const walletRegistrationEcdsaPrepareHandle: EmailOtpWalletRegistrationEcdsaPrepareHandlePayload = {
  kind: 'email_otp_worker_session_handle_v1',
  sessionId: 'otp-registration-root-session',
  walletId: 'wallet.testnet',
  rpId: 'localhost',
  authSubjectId: 'google:subject',
  action: 'wallet_registration_ecdsa_prepare',
  operation: 'registration',
  keyScope: 'evm-family',
};
void walletRegistrationEcdsaPrepareHandle;

// @ts-expect-error Registration-prep worker handles cannot be used for session bootstrap.
const bootstrapHandleFromRegistrationPrepare: EmailOtpEcdsaSessionBootstrapHandlePayload =
  walletRegistrationEcdsaPrepareHandle;
void bootstrapHandleFromRegistrationPrepare;

const issuedHandle: EmailOtpWorkerIssuedSessionHandlePayload = walletRegistrationEcdsaPrepareHandle;
void issuedHandle;

const jwtBootstrap: EmailOtpEcdsaBootstrapStrictPayload = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  walletSessionUserId: 'wallet.testnet',
  userId: 'wallet.testnet',
  rpId: 'localhost',
  clientRootShareHandle,
  chainTarget,
  publicationChainTargets,
  runtimePolicyScope,
  sessionKind: 'jwt',
  routeAuth,
};
void jwtBootstrap;

// @ts-expect-error JWT ECDSA bootstrap requires route auth.
const jwtBootstrapWithoutRouteAuth: EmailOtpEcdsaBootstrapStrictPayload = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  walletSessionUserId: 'wallet.testnet',
  userId: 'wallet.testnet',
  rpId: 'localhost',
  clientRootShareHandle,
  chainTarget,
  publicationChainTargets,
  runtimePolicyScope,
  sessionKind: 'jwt',
};
void jwtBootstrapWithoutRouteAuth;

const cookieBootstrap = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  walletSessionUserId: 'wallet.testnet',
  userId: 'wallet.testnet',
  rpId: 'localhost',
  clientRootShareHandle,
  chainTarget,
  publicationChainTargets,
  runtimePolicyScope,
  // @ts-expect-error Email OTP ECDSA worker bootstrap must mint JWT Wallet Sessions.
  sessionKind: 'cookie',
} satisfies EmailOtpEcdsaBootstrapStrictPayload;
void cookieBootstrap;

const bootstrapWithRoleLocalIdentity = {
  ...jwtBootstrap,
  // @ts-expect-error ECDSA bootstrap derives role-local identity inside the worker.
  roleLocalKeyIdentity: {
    ecdsaThresholdKeyId: 'ecdsa-threshold-key',
    signingRootId: 'signing-root',
    signingRootVersion: 'default',
    relayerKeyId: 'relayer-key',
  },
} satisfies EmailOtpEcdsaBootstrapStrictPayload;
void bootstrapWithRoleLocalIdentity;

// @ts-expect-error ECDSA bootstrap requires runtimePolicyScope.
const bootstrapWithoutRuntimePolicyScope: EmailOtpEcdsaBootstrapStrictPayload = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  walletSessionUserId: 'wallet.testnet',
  userId: 'wallet.testnet',
  rpId: 'localhost',
  clientRootShareHandle,
  chainTarget,
  publicationChainTargets,
  sessionKind: 'jwt',
  routeAuth,
};
void bootstrapWithoutRuntimePolicyScope;

const cookieBootstrapWithRouteAuth: EmailOtpEcdsaBootstrapStrictPayload = {
  ...cookieBootstrap,
  // @ts-expect-error cookie ECDSA bootstrap is not a valid signing-capable payload.
  sessionKind: 'cookie',
  routeAuth,
};
void cookieBootstrapWithRouteAuth;

type PresignStepPayload = EthSignerWorkerOperationMap['thresholdEcdsaPresignSessionStep']['payload'];
type EmailOtpEcdsaExportPayload =
  EmailOtpWorkerOperationMap['exportThresholdEcdsaHssKeyWithEmailOtpAuthorization']['payload'];
type EmailOtpEd25519ExportPayload =
  EmailOtpWorkerOperationMap['exportEmailOtpEd25519SeedWithAuthorization']['payload'];
type EmailOtpWalletUnlockPayload =
  EmailOtpWorkerOperationMap['loginWithEmailOtpWallet']['payload'];
type EmailOtpDeviceEnrollmentRestoreResult =
  EmailOtpWorkerOperationMap['restoreEmailOtpDeviceEnrollmentEscrow']['result'];
type EmailOtpRecoveryCodeRotationResult =
  EmailOtpWorkerOperationMap['rotateEmailOtpRecoveryCodes']['result'];

const presignStep: PresignStepPayload = {
  sessionId: 'presign-session',
  relayerParticipantId: 2,
  stage: 'triples',
  incomingMessages: [incomingMessage],
};
void presignStep;

// @ts-expect-error presign session step requires incomingMessages; pass [] when empty.
const presignStepWithoutIncomingMessages: PresignStepPayload = {
  sessionId: 'presign-session',
  relayerParticipantId: 2,
  stage: 'triples',
};
void presignStepWithoutIncomingMessages;

const emailOtpBootstrapWorkerRequest: EmailOtpWorkerOperationRequestEnvelope = {
  id: 'request-1',
  type: 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle',
  payload: jwtBootstrap,
};
void emailOtpBootstrapWorkerRequest;

// @ts-expect-error worker request envelope binds each operation to its exact payload type.
const emailOtpBootstrapWorkerRequestWithoutStrictPayload: EmailOtpWorkerOperationRequestEnvelope = {
  id: 'request-2',
  type: 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle',
  payload: {
    relayUrl: 'https://relay.example',
    walletId: 'wallet.testnet',
  },
};
void emailOtpBootstrapWorkerRequestWithoutStrictPayload;

declare const emailOtpWalletUnlockRoutePlan: EmailOtpWalletUnlockPayload['routePlan'];

const emailOtpWalletUnlockPayload: EmailOtpWalletUnlockPayload = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  userId: 'wallet.testnet',
  challengeId: 'challenge-1',
  otpCode: '123456',
  shamirPrimeB64u: 'prime',
  routePlan: emailOtpWalletUnlockRoutePlan,
  runtimePolicyScope,
};
void emailOtpWalletUnlockPayload;

const emailOtpWalletUnlockPayloadWithoutRuntimeScope = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  otpCode: '123456',
  shamirPrimeB64u: 'prime',
  routePlan: emailOtpWalletUnlockRoutePlan,
};
// @ts-expect-error Email OTP wallet unlock must carry explicit runtimePolicyScope.
emailOtpWalletUnlockPayloadWithoutRuntimeScope satisfies EmailOtpWalletUnlockPayload;

const emailOtpDeviceEnrollmentRestoreResult: EmailOtpDeviceEnrollmentRestoreResult = {
  walletId: 'wallet.testnet',
  userId: 'wallet.testnet',
  authSubjectId: 'google:subject',
  enrollmentId: 'enrollment',
  enrollmentVersion: 'v1',
  enrollmentSealKeyVersion: 'seal-v1',
  recoveryKeyId: 'recovery-key',
  activeRecoveryWrappedEnrollmentEscrowCount: 1,
};
void emailOtpDeviceEnrollmentRestoreResult;

const emailOtpDeviceEnrollmentRestoreResultWithSigningRoot = {
  ...emailOtpDeviceEnrollmentRestoreResult,
  // @ts-expect-error Email OTP enrollment restore result keeps signing-root binding internal.
  signingRootId: 'signing-root',
} satisfies EmailOtpDeviceEnrollmentRestoreResult;
void emailOtpDeviceEnrollmentRestoreResultWithSigningRoot;

declare const recoveryKeys: EmailOtpRecoveryCodeRotationResult['recoveryKeys'];

const emailOtpRecoveryCodeRotationResult: EmailOtpRecoveryCodeRotationResult = {
  walletId: 'wallet.testnet',
  userId: 'wallet.testnet',
  authSubjectId: 'google:subject',
  enrollmentId: 'enrollment',
  enrollmentVersion: 'v1',
  enrollmentSealKeyVersion: 'seal-v1',
  recoveryKeys,
  recoveryCodesIssuedAtMs: 1_900_000_000_000,
  activeRecoveryCodeCount: 8,
  revokedRecoveryCodeCount: 1,
  totalRecoveryCodeCount: 9,
};
void emailOtpRecoveryCodeRotationResult;

const emailOtpRecoveryCodeRotationResultWithSigningRoot = {
  ...emailOtpRecoveryCodeRotationResult,
  // @ts-expect-error Email OTP recovery-code rotation result keeps signing-root binding internal.
  signingRootVersion: 'root-v1',
} satisfies EmailOtpRecoveryCodeRotationResult;
void emailOtpRecoveryCodeRotationResultWithSigningRoot;

declare const emailOtpEcdsaExportRoutePlan: EmailOtpEcdsaExportPayload['routePlan'];
declare const emailOtpEcdsaExportReadyRecord: EmailOtpEcdsaExportPayload['readyRecord'];

const emailOtpEcdsaExportPayload: EmailOtpEcdsaExportPayload = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  userId: 'wallet.testnet',
  challengeId: 'challenge-1',
  otpCode: '123456',
  shamirPrimeB64u: 'prime',
  routePlan: emailOtpEcdsaExportRoutePlan,
  rpId: 'localhost',
  walletSessionJwt: 'wallet-session-jwt',
  ecdsaThresholdKeyId: 'ecdsa-threshold-key',
  relayerKeyId: 'relayer-key',
  readyRecord: emailOtpEcdsaExportReadyRecord,
  thresholdSessionId: 'threshold-session',
  walletSigningSessionId: 'wallet-signing-session',
  thresholdExpiresAtMs: 1_900_000_000_000,
  participantIds: [1, 2],
  keyHandle: 'key-handle',
};
void emailOtpEcdsaExportPayload;

const emailOtpEcdsaExportPayloadWithSigningRoot = {
  ...emailOtpEcdsaExportPayload,
  // @ts-expect-error Email OTP ECDSA export derives signing root from readyRecord.publicFacts.
  signingRootId: 'signing-root',
} satisfies EmailOtpEcdsaExportPayload;
void emailOtpEcdsaExportPayloadWithSigningRoot;

declare const emailOtpEd25519ExportRoutePlan: EmailOtpEd25519ExportPayload['routePlan'];

const emailOtpEd25519ExportPayload: EmailOtpEd25519ExportPayload = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  nearAccountId: 'wallet.testnet',
  userId: 'wallet.testnet',
  challengeId: 'challenge-1',
  otpCode: '123456',
  shamirPrimeB64u: 'prime',
  routePlan: emailOtpEd25519ExportRoutePlan,
  otpChannel: 'email_otp',
  runtimePolicyScope,
  keyVersion: 'v1',
  participantIds: [1, 2],
  thresholdSessionId: 'threshold-session',
  walletSessionJwt: 'wallet-session-jwt',
  relayerKeyId: 'relayer-key',
  expectedPublicKey: 'ed25519:public',
};
void emailOtpEd25519ExportPayload;

const emailOtpEd25519ExportPayloadWithSigningRoot = {
  ...emailOtpEd25519ExportPayload,
  // @ts-expect-error Email OTP Ed25519 export derives signing root from runtimePolicyScope.
  signingRootId: 'signing-root',
} satisfies EmailOtpEd25519ExportPayload;
void emailOtpEd25519ExportPayloadWithSigningRoot;

export {};
