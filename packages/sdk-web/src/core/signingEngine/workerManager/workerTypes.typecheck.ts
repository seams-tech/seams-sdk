import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import type {
  EmailOtpEcdsaBootstrapStrictPayload,
  EmailOtpEcdsaSessionBootstrapHandlePayload,
  EmailOtpExportOperationRequest,
  EmailOtpWalletRegistrationEcdsaPrepareHandlePayload,
  EmailOtpWorkerIssuedSessionHandlePayload,
  EmailOtpWorkerOperationRequestEnvelope,
  EmailOtpWorkerOperationMap,
  EmailOtpWarmSessionOperationRequest,
  EthSignerThresholdEcdsaPresignOperationRequest,
  EthSignerTransactionOperationRequest,
  HssEcdsaRoleLocalMaterialOperationRequest,
  HssEcdsaRoleLocalPresignOperationRequest,
  HssEd25519ProtocolOperationRequest,
  NearEd25519DigestOperationRequest,
  NearEd25519MaterialOperationRequest,
  EthSignerWorkerOperationMap,
} from './workerTypes';
import {
  HssClientCustomRequestType,
} from './workerTypes';
import {
  NearSignerWorkerCustomRequestType,
  type ThresholdEd25519ClientPresignCreateFromMaterialHandleRequest,
  type ThresholdEd25519ClientPresignSignFromMaterialHandleRequest,
  type ThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandleRequest as NearSignerThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandleRequest,
  type ThresholdEd25519WorkerMaterialBinding,
  type ThresholdEd25519WorkerMaterialSessionBinding,
} from '@/core/types/signer-worker';

declare const chainTarget: ThresholdEcdsaChainTarget;
declare const publicationChainTargets: ThresholdEcdsaChainTarget[];
declare const runtimePolicyScope: ThresholdRuntimePolicyScope;
declare const routeAuth: AppOrWalletSessionAuth;
declare const incomingMessage: ArrayBuffer;

const nearSignerMaterialBinding: ThresholdEd25519WorkerMaterialBinding = {
  kind: 'ed25519_worker_material_binding_v1',
  curve: 'ed25519',
  protocol: 'router_ab_normal_signing',
  nearAccountId: 'alice.testnet',
  signerSlot: 1,
  signingRootId: 'signing-root',
  signingRootVersion: 'v1',
  relayerKeyId: 'near-relayer-key',
  participantIds: [1, 2],
  clientVerifyingShareB64u: 'client-verifying-share',
  materialFormatVersion: 'ed25519_worker_material_v1',
  materialKeyId: 'material-key-id',
  createdAtMs: 1_700_000_000_000,
};

const nearSignerSessionBinding: ThresholdEd25519WorkerMaterialSessionBinding = {
  kind: 'ed25519_worker_material_session_binding_v1',
  materialBindingDigest: 'material-binding-digest',
  nearAccountId: 'alice.testnet',
  signerSlot: 1,
  thresholdSessionId: 'threshold-session',
  signingGrantId: 'signing-grant',
  signingRootId: 'signing-root',
  signingRootVersion: 'v1',
  runtimePolicyScope,
  relayerKeyId: 'near-relayer-key',
  participantIds: [1, 2],
  signingWorkerId: 'signing-worker',
  expiresAtMs: 1_900_000_000_000,
};

const nearSignerPresignCreateRequest: ThresholdEd25519ClientPresignCreateFromMaterialHandleRequest = {
  clientParticipantId: 1,
  relayerParticipantId: 2,
  materialHandle: 'material-handle',
  expectedMaterialBinding: nearSignerMaterialBinding,
  expectedSessionBinding: nearSignerSessionBinding,
  expectedSessionBindingDigest: 'session-binding-digest',
  groupPublicKey: 'ed25519:group',
};
void nearSignerPresignCreateRequest;

const nearSignerPresignCreateRequestWithoutSessionDigest = {
  clientParticipantId: 1,
  relayerParticipantId: 2,
  materialHandle: 'material-handle',
  expectedMaterialBinding: nearSignerMaterialBinding,
  expectedSessionBinding: nearSignerSessionBinding,
  groupPublicKey: 'ed25519:group',
};

// @ts-expect-error Material-backed presign creation requires the session binding digest.
const invalidNearSignerPresignCreateRequest: ThresholdEd25519ClientPresignCreateFromMaterialHandleRequest =
  nearSignerPresignCreateRequestWithoutSessionDigest;
void invalidNearSignerPresignCreateRequest;

const nearSignerPresignSignRequest: ThresholdEd25519ClientPresignSignFromMaterialHandleRequest = {
  clientParticipantId: 1,
  relayerParticipantId: 2,
  materialHandle: 'material-handle',
  expectedMaterialBinding: nearSignerMaterialBinding,
  expectedSessionBinding: nearSignerSessionBinding,
  expectedSessionBindingDigest: 'session-binding-digest',
  groupPublicKey: 'ed25519:group',
  signingDigestB64u: 'signing-digest',
  clientNonceHandleB64u: 'nonce-handle',
  clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
  relayerCommitments: { hiding: 'relayer-hiding', binding: 'relayer-binding' },
};
void nearSignerPresignSignRequest;

const nearSignerPresignSignRequestWithoutSessionDigest = {
  ...nearSignerPresignSignRequest,
  expectedSessionBindingDigest: undefined,
};

// @ts-expect-error Material-backed presign signing requires the session binding digest.
const invalidNearSignerPresignSignRequest: ThresholdEd25519ClientPresignSignFromMaterialHandleRequest =
  nearSignerPresignSignRequestWithoutSessionDigest;
void invalidNearSignerPresignSignRequest;

const nearSignerRoleSeparatedRequest: NearSignerThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandleRequest =
  {
    materialHandle: 'material-handle',
    expectedMaterialBinding: nearSignerMaterialBinding,
    expectedSessionBinding: nearSignerSessionBinding,
    expectedSessionBindingDigest: 'session-binding-digest',
    groupPublicKey: 'ed25519:group',
    serverVerifyingShareB64u: 'server-verifying-share',
    serverCommitments: { hiding: 'server-hiding', binding: 'server-binding' },
    signingDigestB64u: 'signing-digest',
  };
void nearSignerRoleSeparatedRequest;

const nearSignerRoleSeparatedRequestWithoutSessionDigest = {
  ...nearSignerRoleSeparatedRequest,
  expectedSessionBindingDigest: undefined,
};

// @ts-expect-error Role-separated worker-material signing requires the session binding digest.
const invalidNearSignerRoleSeparatedRequest: NearSignerThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandleRequest =
  nearSignerRoleSeparatedRequestWithoutSessionDigest;
void invalidNearSignerRoleSeparatedRequest;

const clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload = {
  kind: 'email_otp_worker_session_handle_v1',
  sessionId: 'otp-root-session',
  walletId: 'wallet.testnet',
  walletKeyId: 'wallet-key-localhost',
  authSubjectId: 'google:subject',
  action: 'threshold_ecdsa_bootstrap',
  operation: 'registration',
  chainTarget,
};

const walletRegistrationEcdsaPrepareHandle: EmailOtpWalletRegistrationEcdsaPrepareHandlePayload = {
  kind: 'email_otp_worker_session_handle_v1',
  sessionId: 'otp-registration-root-session',
  walletId: 'wallet.testnet',
  walletKeyId: 'wallet-key-localhost',
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
  walletKeyId: 'wallet-key-localhost',
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
  walletKeyId: 'wallet-key-localhost',
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
  walletKeyId: 'wallet-key-localhost',
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
  walletKeyId: 'wallet-key-localhost',
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

const ethEcdsaPresignInitRequest: EthSignerThresholdEcdsaPresignOperationRequest<'thresholdEcdsaPresignSessionInit'> =
  {
    type: 'thresholdEcdsaPresignSessionInit',
    payload: {
      sessionId: 'presign-session',
      participantIds: [1, 2],
      clientParticipantId: 1,
      threshold: 2,
      clientThresholdSigningShare32: incomingMessage,
      groupPublicKey33: incomingMessage,
    },
  };
void ethEcdsaPresignInitRequest;

const ethEcdsaPresignInitRequestWithTx = {
  ...ethEcdsaPresignInitRequest,
  payload: {
    ...ethEcdsaPresignInitRequest.payload,
    // @ts-expect-error ECDSA presign worker operations reject transaction payload fields.
    tx: {},
  },
} satisfies EthSignerThresholdEcdsaPresignOperationRequest<'thresholdEcdsaPresignSessionInit'>;
void ethEcdsaPresignInitRequestWithTx;

// @ts-expect-error ECDSA presign operations are not ETH transaction encoding operations.
type InvalidEcdsaPresignAsEthTransaction = EthSignerTransactionOperationRequest<'thresholdEcdsaPresignSessionInit'>;
declare const invalidEcdsaPresignAsEthTransaction: InvalidEcdsaPresignAsEthTransaction;
void invalidEcdsaPresignAsEthTransaction;

// @ts-expect-error NEAR digest operations cannot be sent through the material domain.
type InvalidNearDigestAsMaterial = NearEd25519MaterialOperationRequest<typeof NearSignerWorkerCustomRequestType.ThresholdEd25519ComputeNep413SigningDigest>;
declare const invalidNearDigestAsMaterial: InvalidNearDigestAsMaterial;
void invalidNearDigestAsMaterial;

// @ts-expect-error NEAR worker material storage cannot be sent through the digest domain.
type InvalidNearMaterialAsDigest = NearEd25519DigestOperationRequest<typeof NearSignerWorkerCustomRequestType.ThresholdEd25519StoreWorkerMaterialFromHssOutput>;
declare const invalidNearMaterialAsDigest: InvalidNearMaterialAsDigest;
void invalidNearMaterialAsDigest;

// @ts-expect-error Ed25519 HSS material operations cannot use the ECDSA role-local domain.
type InvalidHssEd25519AsEcdsaRoleLocal = HssEcdsaRoleLocalMaterialOperationRequest<typeof HssClientCustomRequestType.ThresholdEd25519RoleSeparatedClientVerifyingShareFromBaseShare>;
declare const invalidHssEd25519AsEcdsaRoleLocal: InvalidHssEd25519AsEcdsaRoleLocal;
void invalidHssEd25519AsEcdsaRoleLocal;

// @ts-expect-error ECDSA role-local operations cannot use the Ed25519 HSS protocol domain.
type InvalidHssEcdsaRoleLocalAsEd25519 = HssEd25519ProtocolOperationRequest<typeof HssClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial>;
declare const invalidHssEcdsaRoleLocalAsEd25519: InvalidHssEcdsaRoleLocalAsEd25519;
void invalidHssEcdsaRoleLocalAsEd25519;

const hssEcdsaPresignInitRequest: HssEcdsaRoleLocalPresignOperationRequest<typeof HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandle> =
  {
    type: HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandle,
    payload: {
      materialHandle: 'ecdsa-material-handle',
      expectedBindingDigest: 'ecdsa-binding-digest',
      sessionId: 'presign-session',
      participantIds: [1, 2],
      clientParticipantId: 1,
      threshold: 2,
      groupPublicKey33: incomingMessage,
    },
  };
void hssEcdsaPresignInitRequest;

// @ts-expect-error ECDSA role-local material operations cannot use the presign domain.
type InvalidHssEcdsaMaterialAsPresign = HssEcdsaRoleLocalPresignOperationRequest<typeof HssClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial>;
declare const invalidHssEcdsaMaterialAsPresign: InvalidHssEcdsaMaterialAsPresign;
void invalidHssEcdsaMaterialAsPresign;

// @ts-expect-error ECDSA role-local presign operations cannot use the material domain.
type InvalidHssEcdsaPresignAsMaterial = HssEcdsaRoleLocalMaterialOperationRequest<typeof HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionStep>;
declare const invalidHssEcdsaPresignAsMaterial: InvalidHssEcdsaPresignAsMaterial;
void invalidHssEcdsaPresignAsMaterial;

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

const emailOtpBootstrapWorkerRequestWithoutStrictPayload: EmailOtpWorkerOperationRequestEnvelope = {
  id: 'request-2',
  type: 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle',
  // @ts-expect-error worker request envelope binds each operation to its exact payload type.
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
  walletKeyId: 'wallet-key-localhost',
  walletSessionJwt: 'wallet-session-jwt',
  ecdsaThresholdKeyId: 'ecdsa-threshold-key',
  relayerKeyId: 'relayer-key',
  readyRecord: emailOtpEcdsaExportReadyRecord,
  thresholdSessionId: 'threshold-session',
  signingGrantId: 'signing-grant',
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

const emailOtpEcdsaExportWorkerRequest: EmailOtpExportOperationRequest<'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization'> =
  {
    id: 'export-request-1',
    type: 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization',
    payload: emailOtpEcdsaExportPayload,
  };
void emailOtpEcdsaExportWorkerRequest;

// @ts-expect-error Email OTP export operations cannot use the warm-session domain.
type InvalidEmailOtpExportAsWarmSession = EmailOtpWarmSessionOperationRequest<'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization'>;
declare const invalidEmailOtpExportAsWarmSession: InvalidEmailOtpExportAsWarmSession;
void invalidEmailOtpExportAsWarmSession;

declare const emailOtpEd25519ExportRoutePlan: EmailOtpEd25519ExportPayload['routePlan'];

const emailOtpEd25519ExportPayload: EmailOtpEd25519ExportPayload = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  nearAccountId: 'wallet.testnet',
  ed25519KeyScopeId: 'wallet.testnet',
  userId: 'wallet.testnet',
  challengeId: 'challenge-1',
  otpCode: '123456',
  shamirPrimeB64u: 'prime',
  routePlan: emailOtpEd25519ExportRoutePlan,
  otpChannel: 'email_otp',
  runtimePolicyScope,
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
