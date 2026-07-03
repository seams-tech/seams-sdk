import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpEcdsaCommittedLane } from '../../flows/signEvmFamily/ecdsaSelection';
import type { EmailOtpRoutePlan } from '../../stepUpConfirmation/otpPrompt/authLane';
import type {
  EmailOtpEcdsaTransactionStepUpInput,
  LoginEmailOtpEcdsaCapabilityForSigningArgs,
  LoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaLogin';

declare const walletSession: WalletSessionRef;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const committedLane: EmailOtpEcdsaCommittedLane;
declare const routePlan: EmailOtpRoutePlan;

const transactionStepUpWithCommittedLane: EmailOtpEcdsaTransactionStepUpInput = {
  mode: 'transaction_step_up',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  committedLane,
};
void transactionStepUpWithCommittedLane;

const transactionStepUpWithRecordAuthLane: EmailOtpEcdsaTransactionStepUpInput = {
  mode: 'transaction_step_up',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  committedLane,
  // @ts-expect-error transaction step-up does not accept loose auth lanes.
  authLane: { kind: 'cookie' },
};
void transactionStepUpWithRecordAuthLane;

const transactionStepUpWithRouteAuth: EmailOtpEcdsaTransactionStepUpInput = {
  mode: 'transaction_step_up',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  committedLane,
  // @ts-expect-error transaction step-up does not accept loose route auth.
  routeAuth: { kind: 'wallet_session', jwt: 'jwt' },
};
void transactionStepUpWithRouteAuth;

// @ts-expect-error transaction step-up requires a committed ECDSA lane.
const transactionStepUpMissingAuth: EmailOtpEcdsaTransactionStepUpInput = {
  mode: 'transaction_step_up',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
};
void transactionStepUpMissingAuth;

const transactionStepUpWithRegistrationAttempt: EmailOtpEcdsaTransactionStepUpInput = {
  mode: 'transaction_step_up',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  committedLane,
  // @ts-expect-error transaction step-up does not accept registration attempts.
  registrationAttemptId: 'registration-attempt',
};
void transactionStepUpWithRegistrationAttempt;

const signingCapabilityWithCommittedLane: LoginEmailOtpEcdsaCapabilityForSigningArgs = {
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  committedLane,
};
void signingCapabilityWithCommittedLane;

// @ts-expect-error signing capability refresh requires a committed ECDSA lane.
const signingCapabilityWithoutCommittedLane: LoginEmailOtpEcdsaCapabilityForSigningArgs = {
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
};
void signingCapabilityWithoutCommittedLane;

const validCapabilityLoginWithDerivedProvider: LoginEmailOtpEcdsaCapabilityArgs = {
  walletSession,
  chainTarget,
  otpCode: '123456',
  routePlan,
  emailHashHex: 'email-hash',
  ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
  ed25519ReconstructionMode: 'skip',
  ed25519SessionReconstruction: {
    kind: 'defer',
    reason: 'not_needed_for_ecdsa',
  },
  providerIdentity: { kind: 'derive_from_route_auth' },
};
void validCapabilityLoginWithDerivedProvider;

const validCapabilityLoginWithExplicitProvider: LoginEmailOtpEcdsaCapabilityArgs = {
  walletSession,
  chainTarget,
  otpCode: '123456',
  routePlan,
  emailHashHex: 'email-hash',
  ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
  ed25519ReconstructionMode: 'skip',
  ed25519SessionReconstruction: {
    kind: 'defer',
    reason: 'not_needed_for_ecdsa',
  },
  providerIdentity: {
    kind: 'explicit_provider_user',
    providerUserId: 'google-provider-user-1',
  },
};
void validCapabilityLoginWithExplicitProvider;

// @ts-expect-error ECDSA login requires a provider-identity branch.
const invalidCapabilityLoginWithoutProvider: LoginEmailOtpEcdsaCapabilityArgs = {
  walletSession,
  chainTarget,
  otpCode: '123456',
  routePlan,
  emailHashHex: 'email-hash',
  ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
  ed25519ReconstructionMode: 'skip',
  ed25519SessionReconstruction: {
    kind: 'defer',
    reason: 'not_needed_for_ecdsa',
  },
};
void invalidCapabilityLoginWithoutProvider;

const invalidCapabilityLoginWithAuthSubject: LoginEmailOtpEcdsaCapabilityArgs = {
  walletSession,
  chainTarget,
  otpCode: '123456',
  routePlan,
  emailHashHex: 'email-hash',
  ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
  ed25519ReconstructionMode: 'skip',
  ed25519SessionReconstruction: {
    kind: 'defer',
    reason: 'not_needed_for_ecdsa',
  },
  providerIdentity: { kind: 'derive_from_route_auth' },
  // @ts-expect-error authSubjectId is a worker boundary field, not a login authority input.
  authSubjectId: 'legacy-auth-subject',
};
void invalidCapabilityLoginWithAuthSubject;

// @ts-expect-error ECDSA login core requires a committed route plan.
const invalidCapabilityLoginWithoutRoutePlan: LoginEmailOtpEcdsaCapabilityArgs = {
  walletSession,
  chainTarget,
  otpCode: '123456',
  emailHashHex: 'email-hash',
  ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
  ed25519ReconstructionMode: 'skip',
  ed25519SessionReconstruction: {
    kind: 'defer',
    reason: 'not_needed_for_ecdsa',
  },
  providerIdentity: { kind: 'derive_from_route_auth' },
};
void invalidCapabilityLoginWithoutRoutePlan;

const invalidCapabilityLoginWithRawAppSession: LoginEmailOtpEcdsaCapabilityArgs = {
  walletSession,
  chainTarget,
  otpCode: '123456',
  routePlan,
  emailHashHex: 'email-hash',
  ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
  ed25519ReconstructionMode: 'skip',
  ed25519SessionReconstruction: {
    kind: 'defer',
    reason: 'not_needed_for_ecdsa',
  },
  providerIdentity: { kind: 'derive_from_route_auth' },
  // @ts-expect-error ECDSA login core must not accept raw app-session JWTs.
  appSessionJwt: 'app-session-jwt',
};
void invalidCapabilityLoginWithRawAppSession;

const invalidCapabilityLoginWithRawRouteAuth: LoginEmailOtpEcdsaCapabilityArgs = {
  walletSession,
  chainTarget,
  otpCode: '123456',
  routePlan,
  emailHashHex: 'email-hash',
  ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
  ed25519ReconstructionMode: 'skip',
  ed25519SessionReconstruction: {
    kind: 'defer',
    reason: 'not_needed_for_ecdsa',
  },
  providerIdentity: { kind: 'derive_from_route_auth' },
  // @ts-expect-error ECDSA login core must not accept raw route auth.
  routeAuth: { kind: 'app_session', jwt: 'app-session-jwt' },
};
void invalidCapabilityLoginWithRawRouteAuth;

const invalidCapabilityLoginWithSessionKind: LoginEmailOtpEcdsaCapabilityArgs = {
  walletSession,
  chainTarget,
  otpCode: '123456',
  routePlan,
  emailHashHex: 'email-hash',
  ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
  ed25519ReconstructionMode: 'skip',
  ed25519SessionReconstruction: {
    kind: 'defer',
    reason: 'not_needed_for_ecdsa',
  },
  providerIdentity: { kind: 'derive_from_route_auth' },
  // @ts-expect-error ECDSA login core receives session transport through routePlan.
  sessionKind: 'jwt',
};
void invalidCapabilityLoginWithSessionKind;

export {};
