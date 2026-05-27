import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import type {
  EmailOtpEcdsaBootstrapRoleLocalKeyIdentity,
  EmailOtpEcdsaBootstrapStrictPayload,
  EmailOtpWorkerOperationRequestEnvelope,
  EthSignerWorkerOperationMap,
} from './workerTypes';

declare const chainTarget: ThresholdEcdsaChainTarget;
declare const publicationChainTargets: ThresholdEcdsaChainTarget[];
declare const runtimePolicyScope: ThresholdRuntimePolicyScope;
declare const routeAuth: AppOrThresholdSessionAuth;
declare const roleLocalKeyIdentity: EmailOtpEcdsaBootstrapRoleLocalKeyIdentity;
declare const incomingMessage: ArrayBuffer;

const jwtBootstrap: EmailOtpEcdsaBootstrapStrictPayload = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  walletSessionUserId: 'wallet.testnet',
  userId: 'wallet.testnet',
  rpId: 'localhost',
  clientRootShare32B64u: 'client-root-share',
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
  clientRootShare32B64u: 'client-root-share',
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
  clientRootShare32B64u: 'client-root-share',
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
  clientRootShare32B64u: 'client-root-share',
  chainTarget,
  publicationChainTargets,
  runtimePolicyScope,
  sessionKind: 'jwt',
  routeAuth,
};
void bootstrapWithoutRoleLocalIdentity;

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
  type: 'bootstrapEmailOtpEcdsaSessionsFromClientRootShare',
  payload: jwtBootstrap,
};
void emailOtpBootstrapWorkerRequest;

// @ts-expect-error worker request envelope binds each operation to its exact payload type.
const emailOtpBootstrapWorkerRequestWithoutStrictPayload: EmailOtpWorkerOperationRequestEnvelope = {
  id: 'request-2',
  type: 'bootstrapEmailOtpEcdsaSessionsFromClientRootShare',
  payload: {
    relayUrl: 'https://relay.example',
    walletId: 'wallet.testnet',
  },
};
void emailOtpBootstrapWorkerRequestWithoutStrictPayload;

export {};
