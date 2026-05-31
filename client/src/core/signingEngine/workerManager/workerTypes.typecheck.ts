import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import type {
  EmailOtpEcdsaBootstrapRoleLocalKeyIdentity,
  EmailOtpEcdsaBootstrapStrictPayload,
  EmailOtpEcdsaSessionBootstrapHandlePayload,
  EmailOtpWalletRegistrationEcdsaPrepareHandlePayload,
  EmailOtpWorkerIssuedSessionHandlePayload,
  EmailOtpWorkerOperationRequestEnvelope,
  EthSignerWorkerOperationMap,
} from './workerTypes';

declare const chainTarget: ThresholdEcdsaChainTarget;
declare const publicationChainTargets: ThresholdEcdsaChainTarget[];
declare const runtimePolicyScope: ThresholdRuntimePolicyScope;
declare const routeAuth: AppOrThresholdSessionAuth;
declare const roleLocalKeyIdentity: EmailOtpEcdsaBootstrapRoleLocalKeyIdentity;
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
  roleLocalKeyIdentity,
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
  roleLocalKeyIdentity,
  runtimePolicyScope,
  sessionKind: 'jwt',
};
void jwtBootstrapWithoutRouteAuth;

const cookieBootstrap: EmailOtpEcdsaBootstrapStrictPayload = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  walletSessionUserId: 'wallet.testnet',
  userId: 'wallet.testnet',
  rpId: 'localhost',
  clientRootShareHandle,
  chainTarget,
  publicationChainTargets,
  roleLocalKeyIdentity,
  runtimePolicyScope,
  sessionKind: 'cookie',
};
void cookieBootstrap;

// @ts-expect-error ECDSA bootstrap requires role-local key identity.
const bootstrapWithoutRoleLocalIdentity: EmailOtpEcdsaBootstrapStrictPayload = {
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
void bootstrapWithoutRoleLocalIdentity;

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
  roleLocalKeyIdentity,
  sessionKind: 'jwt',
  routeAuth,
};
void bootstrapWithoutRuntimePolicyScope;

// @ts-expect-error cookie ECDSA bootstrap rejects route auth.
const cookieBootstrapWithRouteAuth: EmailOtpEcdsaBootstrapStrictPayload = {
  ...cookieBootstrap,
  routeAuth,
};
void cookieBootstrapWithRouteAuth;

type PresignStepPayload = EthSignerWorkerOperationMap['thresholdEcdsaPresignSessionStep']['payload'];

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

export {};
