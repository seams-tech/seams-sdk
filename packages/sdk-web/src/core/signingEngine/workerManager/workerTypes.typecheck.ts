import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import type {
  EmailOtpEcdsaBootstrapStrictPayload,
  EmailOtpEd25519YaoActiveCapabilityDescriptorV1,
  EmailOtpEcdsaPublicationTargetPlan,
  EmailOtpEcdsaSessionBootstrapHandlePayload,
  EmailOtpExportOperationRequest,
  EmailOtpWalletRegistrationEcdsaPrepareHandlePayload,
  EmailOtpWorkerIssuedSessionHandlePayload,
  EmailOtpWorkerOperationRequestEnvelope,
  EmailOtpWorkerOperationMap,
  EmailOtpWarmSessionOperationRequest,
  EvmCryptoLocalSecp256k1OperationRequest,
  EvmCryptoTransactionOperationRequest,
  EcdsaDerivationRoleLocalMaterialOperationRequest,
  EcdsaOnlineClientComputeSignatureShareRequest,
  EcdsaPresignClientSessionInitRequest,
  NearWorkerOperationRequest,
  EcdsaPresignClientSessionStepRequest,
} from './workerTypes';
import {
  EcdsaDerivationClientCustomRequestType,
  EcdsaPresignClientRequestType,
} from './workerTypes';
import { parseSigningSessionSealKeyVersion } from '../session/keyMaterialBrands';

declare const chainTarget: ThresholdEcdsaChainTarget;
declare const publicationTargetPlans: EmailOtpEcdsaPublicationTargetPlan[];
declare const runtimePolicyScope: ThresholdRuntimePolicyScope;
declare const emailOtpEd25519YaoActiveCapability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
declare const routeAuth: AppOrWalletSessionAuth;
declare const incomingMessage: ArrayBuffer;

const clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload = {
  kind: 'email_otp_worker_session_handle_v1',
  sessionId: 'otp-root-session',
  walletId: 'wallet.testnet',
  evmFamilySigningKeySlotId: 'wallet-key-localhost',
  authSubjectId: 'google:subject',
  action: 'threshold_ecdsa_bootstrap',
  operation: 'registration',
  chainTarget,
};

const walletRegistrationEcdsaPrepareHandle: EmailOtpWalletRegistrationEcdsaPrepareHandlePayload = {
  kind: 'email_otp_worker_session_handle_v1',
  sessionId: 'otp-registration-root-session',
  walletId: 'wallet.testnet',
  evmFamilySigningKeySlotId: 'wallet-key-localhost',
  authSubjectId: 'google:subject',
  action: 'wallet_registration_ecdsa_prepare',
  operation: 'registration',
  keyScope: 'evm-family',
  chainTarget,
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
  clientRootShareHandle,
  chainTarget,
  publicationTargetPlans,
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
  clientRootShareHandle,
  chainTarget,
  publicationTargetPlans,
  runtimePolicyScope,
  sessionKind: 'jwt',
};
void jwtBootstrapWithoutRouteAuth;

const cookieBootstrap = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  walletSessionUserId: 'wallet.testnet',
  userId: 'wallet.testnet',
  clientRootShareHandle,
  chainTarget,
  publicationTargetPlans,
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
  clientRootShareHandle,
  chainTarget,
  publicationTargetPlans,
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

type PresignStepPayload = EcdsaPresignClientSessionStepRequest;
type EmailOtpEcdsaExportPayload =
  EmailOtpWorkerOperationMap['exportThresholdEcdsaDerivationKeyWithEmailOtpAuthorization']['payload'];
type EmailOtpEd25519YaoExportPayload =
  EmailOtpWorkerOperationMap['exportEmailOtpEd25519YaoSeedWithAuthorization']['payload'];
type EmailOtpWalletUnlockPayload = EmailOtpWorkerOperationMap['loginWithEmailOtpWallet']['payload'];
type EmailOtpEcdsaWalletUnlockMaterial = Extract<
  EmailOtpWalletUnlockPayload['material'],
  { kind: 'ecdsa' }
>;
type EmailOtpEd25519YaoWalletUnlockMaterial = Extract<
  EmailOtpWalletUnlockPayload['material'],
  { kind: 'ed25519_yao_recovery' }
>;
type EmailOtpYaoBindPayload = EmailOtpWorkerOperationMap['bindEmailOtpEd25519YaoRoot']['payload'];
type EmailOtpYaoRootDisposalPayload =
  EmailOtpWorkerOperationMap['disposeEmailOtpEd25519YaoRoot']['payload'];
type EmailOtpYaoCommitPayload =
  EmailOtpWorkerOperationMap['commitEmailOtpEd25519YaoRegistration']['payload'];
type EmailOtpYaoRecoveryPayload =
  EmailOtpWorkerOperationMap['recoverEmailOtpEd25519Yao']['payload'];
type EmailOtpEcdsaRegistrationWarmMaterialCommitPayload =
  EmailOtpWorkerOperationMap['commitEmailOtpEcdsaRegistrationWarmMaterial']['payload'];
type EmailOtpDeviceEnrollmentRestoreResult =
  EmailOtpWorkerOperationMap['restoreEmailOtpDeviceEnrollmentEscrow']['result'];
type EmailOtpRecoveryCodeRotationResult =
  EmailOtpWorkerOperationMap['rotateEmailOtpRecoveryCodes']['result'];
type EmailOtpEd25519YaoFactorRehydratePayload =
  EmailOtpWorkerOperationMap['rehydrateEmailOtpEd25519YaoFactor']['payload'];

const emailOtpEd25519YaoFactorRehydrate: EmailOtpEd25519YaoFactorRehydratePayload = {
  sealedSecretB64u: 'sealed-ed25519-yao-factor',
  remainingUses: 3,
  expiresAtMs: Date.now() + 60_000,
  transport: {
    relayerUrl: 'https://relay.example.test',
    walletSessionJwt: 'wallet.session.jwt',
    signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion('seal-v1'),
    shamirPrimeB64u: 'shamir-prime',
  },
  restore: {
    sessionId: 'threshold-session',
    walletId: 'wallet.testnet',
    providerSubject: 'google:subject',
  },
};
void emailOtpEd25519YaoFactorRehydrate;

const emailOtpEd25519YaoFactorRehydrateWithOtp = {
  ...emailOtpEd25519YaoFactorRehydrate,
  // @ts-expect-error Silent durable recovery never accepts a fresh OTP challenge.
  otpCode: '123456',
} satisfies EmailOtpEd25519YaoFactorRehydratePayload;
void emailOtpEd25519YaoFactorRehydrateWithOtp;

const emailOtpEd25519YaoFactorRehydrateWithoutWalletSession = {
  ...emailOtpEd25519YaoFactorRehydrate,
  // @ts-expect-error Silent durable recovery requires its exact Wallet Session credential.
  transport: {
    relayerUrl: 'https://relay.example.test',
    signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion('seal-v1'),
    shamirPrimeB64u: 'shamir-prime',
  },
} satisfies EmailOtpEd25519YaoFactorRehydratePayload;
void emailOtpEd25519YaoFactorRehydrateWithoutWalletSession;

const emailOtpEd25519YaoWalletUnlockMaterial: EmailOtpEd25519YaoWalletUnlockMaterial = {
  kind: 'ed25519_yao_recovery',
  providerSubject: 'google:subject',
  ed25519YaoRecovery: {
    kind: 'router_ab_ed25519_yao_email_otp_recovery_v1',
    signerSlot: 1,
    remainingUses: 3,
    orgId: 'org-test',
  },
};
void emailOtpEd25519YaoWalletUnlockMaterial;

const emailOtpEd25519YaoWalletUnlockWithPriorSession = {
  ...emailOtpEd25519YaoWalletUnlockMaterial,
  // @ts-expect-error Fresh OTP recovery rejects a prior Wallet Session credential.
  walletSessionAuth: { kind: 'wallet_session', jwt: 'prior.jwt' },
} satisfies EmailOtpEd25519YaoWalletUnlockMaterial;
void emailOtpEd25519YaoWalletUnlockWithPriorSession;

const emailOtpEd25519YaoWalletUnlockWithClientPolicy = {
  ...emailOtpEd25519YaoWalletUnlockMaterial,
  // @ts-expect-error Fresh OTP recovery rejects a client-authored session policy.
  sessionPolicy: { version: 'threshold_session_v1' },
} satisfies EmailOtpEd25519YaoWalletUnlockMaterial;
void emailOtpEd25519YaoWalletUnlockWithClientPolicy;

const presignStep: PresignStepPayload = {
  sessionId: 'presign-session',
  stage: 'triples',
  incomingMessages: [incomingMessage],
};
void presignStep;

const ethRecoverableSignatureVerifyRequest: EvmCryptoLocalSecp256k1OperationRequest<'verifySecp256k1RecoverableSignatureAgainstPublicKey33'> =
  {
    type: 'verifySecp256k1RecoverableSignatureAgainstPublicKey33',
    payload: {
      digest32: incomingMessage,
      signature65: incomingMessage,
      publicKey33: incomingMessage,
    },
  };
void ethRecoverableSignatureVerifyRequest;

type InvalidRecoverableSignatureVerifyAsEthTransaction =
  // @ts-expect-error Recoverable signature verification is not an ETH transaction encoding operation.
  EvmCryptoTransactionOperationRequest<'verifySecp256k1RecoverableSignatureAgainstPublicKey33'>;
declare const invalidRecoverableSignatureVerifyAsEthTransaction: InvalidRecoverableSignatureVerifyAsEthTransaction;
void invalidRecoverableSignatureVerifyAsEthTransaction;

const ecdsaPresignInitRequest: EcdsaPresignClientSessionInitRequest = {
  authority: {
    kind: 'role_local_derivation_handle',
    materialHandle: 'ecdsa-material-handle',
    expectedBindingDigest: 'ecdsa-binding-digest',
  },
  sessionId: 'presign-session',
  topology: { kind: 'threshold_secp256k1_ecdsa_2p_v1' },
  groupPublicKey33: incomingMessage,
};
void ecdsaPresignInitRequest;

const invalidMixedEcdsaPresignAuthority: EcdsaPresignClientSessionInitRequest = {
  // @ts-expect-error Email OTP authority cannot carry a derivation material handle.
  authority: {
    kind: 'email_otp_worker_session',
    emailOtpSessionId: 'email-otp-session',
    materialHandle: 'ecdsa-material-handle',
  },
  sessionId: 'presign-session',
  topology: { kind: 'threshold_secp256k1_ecdsa_2p_v1' },
  groupPublicKey33: incomingMessage,
};
void invalidMixedEcdsaPresignAuthority;

const invalidRoleLocalPresignAuthorityWithEmailOtpSession: EcdsaPresignClientSessionInitRequest = {
  // @ts-expect-error Role-local derivation authority cannot carry an Email OTP worker session.
  authority: {
    kind: 'role_local_derivation_handle',
    materialHandle: 'ecdsa-material-handle',
    expectedBindingDigest: 'ecdsa-binding-digest',
    emailOtpSessionId: 'email-otp-session',
  },
  sessionId: 'presign-session',
  topology: { kind: 'threshold_secp256k1_ecdsa_2p_v1' },
  groupPublicKey33: incomingMessage,
};
void invalidRoleLocalPresignAuthorityWithEmailOtpSession;

type InvalidEcdsaDerivationPresignAsMaterial = EcdsaDerivationRoleLocalMaterialOperationRequest<
  // @ts-expect-error Presign operations cannot use the derivation material domain.
  typeof EcdsaPresignClientRequestType.SessionStep
>;
declare const invalidEcdsaDerivationPresignAsMaterial: InvalidEcdsaDerivationPresignAsMaterial;
void invalidEcdsaDerivationPresignAsMaterial;

const invalidRawOnlineSecretShares: EcdsaOnlineClientComputeSignatureShareRequest = {
  materialHandle: 'opaque-presign-handle',
  groupPublicKey33: incomingMessage,
  expectedPresignBigR33: incomingMessage,
  digest32: incomingMessage,
  entropy32: incomingMessage,
  // @ts-expect-error host-facing online requests must use an opaque presign handle.
  kShare32: incomingMessage,
};
void invalidRawOnlineSecretShares;

// @ts-expect-error presign session step requires incomingMessages; pass [] when empty.
const presignStepWithoutIncomingMessages: PresignStepPayload = {
  sessionId: 'presign-session',
  stage: 'triples',
};
void presignStepWithoutIncomingMessages;

const invalidEcdsaPresignTopology: EcdsaPresignClientSessionInitRequest = {
  authority: {
    kind: 'role_local_derivation_handle',
    materialHandle: 'ecdsa-material-handle',
    expectedBindingDigest: 'ecdsa-binding-digest',
  },
  sessionId: 'presign-session',
  // @ts-expect-error fixed ECDSA2P workers reject alternate topology identifiers.
  topology: { kind: 'threshold_secp256k1_ecdsa_3p_v1' },
  groupPublicKey33: incomingMessage,
};
void invalidEcdsaPresignTopology;

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
declare const emailOtpEcdsaWalletUnlockMaterial: EmailOtpEcdsaWalletUnlockMaterial;

const emailOtpWalletUnlockPayload: EmailOtpWalletUnlockPayload = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  userId: 'wallet.testnet',
  challengeId: 'challenge-1',
  otpCode: '123456',
  shamirPrimeB64u: 'prime',
  routePlan: emailOtpWalletUnlockRoutePlan,
  material: emailOtpEcdsaWalletUnlockMaterial,
};
void emailOtpWalletUnlockPayload;

const emailOtpWalletUnlockPayloadWithoutRuntimeScope = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  otpCode: '123456',
  shamirPrimeB64u: 'prime',
  routePlan: emailOtpWalletUnlockRoutePlan,
};
// @ts-expect-error Email OTP wallet unlock must carry one exact material branch.
emailOtpWalletUnlockPayloadWithoutRuntimeScope satisfies EmailOtpWalletUnlockPayload;

declare const pendingFactorHandle: EmailOtpYaoBindPayload['pendingFactorHandle'];
declare const emailOtpYaoRootScope: EmailOtpYaoBindPayload['scope'];
declare const emailOtpYaoRootHandle: EmailOtpYaoRootDisposalPayload['rootHandle'];
declare const emailOtpYaoWalletSessionState: EmailOtpYaoCommitPayload['walletSessionState'];
declare const emailOtpYaoRecoveryAdmission: EmailOtpYaoRecoveryPayload['admissionRequest'];

const emailOtpYaoRootDisposalPayload: EmailOtpYaoRootDisposalPayload = {
  rootHandle: emailOtpYaoRootHandle,
};
void emailOtpYaoRootDisposalPayload;

const emailOtpYaoBindPayload: EmailOtpYaoBindPayload = {
  pendingFactorHandle,
  scope: emailOtpYaoRootScope,
};
void emailOtpYaoBindPayload;

const emailOtpYaoBindPayloadWithCallerExpiry = {
  pendingFactorHandle,
  scope: emailOtpYaoRootScope,
  // @ts-expect-error Pending-factor binding derives expiry from the issued handle.
  expiresAtMs: 1_900_000_000_000,
} satisfies EmailOtpYaoBindPayload;
void emailOtpYaoBindPayloadWithCallerExpiry;

const emailOtpYaoCommitPayload: EmailOtpYaoCommitPayload = {
  pendingHandle: 'pending-registration',
  walletSessionState: emailOtpYaoWalletSessionState,
};
void emailOtpYaoCommitPayload;

// @ts-expect-error Registration commit requires the exact Wallet Session state.
const emailOtpYaoCommitWithoutWalletSession: EmailOtpYaoCommitPayload = {
  pendingHandle: 'pending-registration',
};
void emailOtpYaoCommitWithoutWalletSession;

const emailOtpYaoRecoveryPayload: EmailOtpYaoRecoveryPayload = {
  rootHandle: emailOtpYaoRootHandle,
  admissionRequest: emailOtpYaoRecoveryAdmission,
  walletId: 'wallet.testnet',
  providerSubject: 'google:subject',
  registrationAuthorityId: 'registration-authority',
  bearerToken: 'wallet-session-jwt',
  routerOrigin: 'https://relay.example',
  sessionPolicy: {
    thresholdSessionId: 'threshold-ed25519-session',
    expiresAtMs: 1_900_000_000_000,
    remainingUses: 3,
  },
};
void emailOtpYaoRecoveryPayload;

// @ts-expect-error Yao recovery must bind retained factor material to one exact session policy.
const emailOtpYaoRecoveryWithoutSessionPolicy: EmailOtpYaoRecoveryPayload = {
  rootHandle: emailOtpYaoRootHandle,
  admissionRequest: emailOtpYaoRecoveryAdmission,
  walletId: 'wallet.testnet',
  providerSubject: 'google:subject',
  registrationAuthorityId: 'registration-authority',
  bearerToken: 'wallet-session-jwt',
  routerOrigin: 'https://relay.example',
};
void emailOtpYaoRecoveryWithoutSessionPolicy;

const emailOtpEcdsaRegistrationWarmMaterialCommit: EmailOtpEcdsaRegistrationWarmMaterialCommitPayload =
  {
    walletId: 'wallet.testnet',
    chainTarget,
    retainedClientRootShareHandle: walletRegistrationEcdsaPrepareHandle,
    thresholdSessionId: 'threshold-ecdsa-session',
    expiresAtMs: 1_900_000_000_000,
    remainingUses: 3,
  };
void emailOtpEcdsaRegistrationWarmMaterialCommit;

const emailOtpEcdsaRegistrationWarmMaterialCommitWithBootstrapHandle = {
  walletId: 'wallet.testnet',
  chainTarget,
  // @ts-expect-error Registration warm-material commit rejects a session-bootstrap handle.
  retainedClientRootShareHandle: clientRootShareHandle,
  thresholdSessionId: 'threshold-ecdsa-session',
  expiresAtMs: 1_900_000_000_000,
  remainingUses: 3,
} satisfies EmailOtpEcdsaRegistrationWarmMaterialCommitPayload;
void emailOtpEcdsaRegistrationWarmMaterialCommitWithBootstrapHandle;

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
  evmFamilySigningKeySlotId: 'wallet-key-localhost',
  walletSessionJwt: 'wallet-session-jwt',
  ecdsaThresholdKeyId: 'ecdsa-threshold-key',
  relayerKeyId: 'relayer-key',
  readyRecord: emailOtpEcdsaExportReadyRecord,
  thresholdSessionId: 'threshold-session',
  signingGrantId: 'signing-grant',
  thresholdExpiresAtMs: 1_900_000_000_000,
  participantIds: [1, 2],
  keyHandle: 'key-handle',
  runtimePolicyScope,
};
void emailOtpEcdsaExportPayload;

const emailOtpEcdsaExportPayloadWithoutRuntimePolicyScope = {
  ...emailOtpEcdsaExportPayload,
  // @ts-expect-error Email OTP ECDSA export requires runtimePolicyScope.
  runtimePolicyScope: undefined,
} satisfies EmailOtpEcdsaExportPayload;
void emailOtpEcdsaExportPayloadWithoutRuntimePolicyScope;

const emailOtpEcdsaExportPayloadWithSigningRoot = {
  ...emailOtpEcdsaExportPayload,
  // @ts-expect-error Email OTP ECDSA export derives signing root from readyRecord.publicFacts.
  signingRootId: 'signing-root',
} satisfies EmailOtpEcdsaExportPayload;
void emailOtpEcdsaExportPayloadWithSigningRoot;

const emailOtpEcdsaExportWorkerRequest: EmailOtpExportOperationRequest<'exportThresholdEcdsaDerivationKeyWithEmailOtpAuthorization'> =
  {
    id: 'export-request-1',
    type: 'exportThresholdEcdsaDerivationKeyWithEmailOtpAuthorization',
    payload: emailOtpEcdsaExportPayload,
  };
void emailOtpEcdsaExportWorkerRequest;

declare const emailOtpEd25519YaoExportRoutePlan: EmailOtpEd25519YaoExportPayload['routePlan'];
const emailOtpEd25519YaoExportPayload: EmailOtpEd25519YaoExportPayload = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  userId: 'google:subject',
  challengeId: 'challenge-ed25519-export',
  otpCode: '123456',
  shamirPrimeB64u: 'prime',
  routePlan: emailOtpEd25519YaoExportRoutePlan,
  walletSessionJwt: 'wallet-session-jwt',
  nearAccountId: 'alice.testnet',
  nearEd25519SigningKeyId: 'near-key-1',
  signerSlot: 1,
  thresholdSessionId: 'threshold-ed25519-export',
  signingGrantId: 'grant-ed25519-export',
  runtimePolicyScope,
  capability: emailOtpEd25519YaoActiveCapability,
};
void emailOtpEd25519YaoExportPayload;

const emailOtpEd25519YaoExportPayloadWithPasskey = {
  ...emailOtpEd25519YaoExportPayload,
  // @ts-expect-error Email OTP Ed25519 export rejects passkey credentials.
  webauthnAuthentication: {},
} satisfies EmailOtpEd25519YaoExportPayload;
void emailOtpEd25519YaoExportPayloadWithPasskey;

type InvalidEmailOtpExportAsWarmSession =
  // @ts-expect-error Email OTP export operations cannot use the warm-session domain.
  EmailOtpWarmSessionOperationRequest<'exportThresholdEcdsaDerivationKeyWithEmailOtpAuthorization'>;
declare const invalidEmailOtpExportAsWarmSession: InvalidEmailOtpExportAsWarmSession;
void invalidEmailOtpExportAsWarmSession;

export {};
