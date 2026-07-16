import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import type { EmailOtpRoutePlan } from '../../stepUpConfirmation/otpPrompt/authLane';
import type {
  EmailOtpEcdsaRegistrationBootstrapInput,
  EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaEnrollment';

declare const walletSession: WalletSessionRef;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const routePlan: EmailOtpRoutePlan;
declare const routeAuth: AppOrWalletSessionAuth;
declare const runtimePolicyScope: ThresholdRuntimePolicyScope;

const validEnrollAndLogin: EnrollAndLoginEmailOtpEcdsaCapabilityArgs = {
  walletSession,
  chainTarget,
  otpCode: '123456',
  routePlan,
  registrationAttemptId: 'registration-attempt-1',
  emailHashHex: 'email-hash',
};
void validEnrollAndLogin;

// @ts-expect-error ECDSA registration core requires a committed route plan.
const invalidEnrollAndLoginWithoutRoutePlan: EnrollAndLoginEmailOtpEcdsaCapabilityArgs = {
  walletSession,
  chainTarget,
  otpCode: '123456',
  registrationAttemptId: 'registration-attempt-1',
  emailHashHex: 'email-hash',
};
void invalidEnrollAndLoginWithoutRoutePlan;

const invalidEnrollAndLoginWithRawAppSession: EnrollAndLoginEmailOtpEcdsaCapabilityArgs = {
  walletSession,
  chainTarget,
  otpCode: '123456',
  routePlan,
  registrationAttemptId: 'registration-attempt-1',
  emailHashHex: 'email-hash',
  // @ts-expect-error ECDSA registration core must not accept raw app-session JWTs.
  appSessionJwt: 'app-session-jwt',
};
void invalidEnrollAndLoginWithRawAppSession;

const invalidEnrollAndLoginWithRawRouteAuth: EnrollAndLoginEmailOtpEcdsaCapabilityArgs = {
  walletSession,
  chainTarget,
  otpCode: '123456',
  routePlan,
  registrationAttemptId: 'registration-attempt-1',
  emailHashHex: 'email-hash',
  // @ts-expect-error ECDSA registration core must not accept loose route auth.
  routeAuth,
};
void invalidEnrollAndLoginWithRawRouteAuth;

const invalidEnrollAndLoginWithSessionKind: EnrollAndLoginEmailOtpEcdsaCapabilityArgs = {
  walletSession,
  chainTarget,
  otpCode: '123456',
  routePlan,
  registrationAttemptId: 'registration-attempt-1',
  emailHashHex: 'email-hash',
  // @ts-expect-error ECDSA registration core receives session transport through routePlan.
  sessionKind: 'jwt',
};
void invalidEnrollAndLoginWithSessionKind;

const existingKeyRegistration: EmailOtpEcdsaRegistrationBootstrapInput = {
  mode: 'registration_bootstrap',
  walletSession,
  chainTarget,
  routePlan,
  registrationAttemptId: 'registration-attempt-1',
  runtimePolicyScope,
  sessionKind: 'jwt',
  routeAuth,
  keyMode: 'existing_role_local_key',
  keyHandle: 'ederivation-key-handle-1',
};
void existingKeyRegistration;

const newKeyRegistration: EmailOtpEcdsaRegistrationBootstrapInput = {
  mode: 'registration_bootstrap',
  walletSession,
  chainTarget,
  routePlan,
  registrationAttemptId: 'registration-attempt-1',
  runtimePolicyScope,
  sessionKind: 'jwt',
  routeAuth,
  keyMode: 'new_role_local_key',
};
void newKeyRegistration;

const cookieRegistration = {
  mode: 'registration_bootstrap',
  walletSession,
  chainTarget,
  routePlan,
  registrationAttemptId: 'registration-attempt-1',
  runtimePolicyScope,
  // @ts-expect-error Email OTP ECDSA registration must mint JWT Wallet Sessions.
  sessionKind: 'cookie',
  keyMode: 'new_role_local_key',
} satisfies EmailOtpEcdsaRegistrationBootstrapInput;
void cookieRegistration;

const registrationWithRoleLocalIdentity = {
  ...existingKeyRegistration,
  // @ts-expect-error Email OTP registration derives role-local identity inside the worker.
  roleLocalKeyIdentity: {
    ecdsaThresholdKeyId: 'ecdsa-threshold-key',
    signingRootId: 'signing-root',
    signingRootVersion: 'default',
    relayerKeyId: 'relayer-key',
  },
} satisfies EmailOtpEcdsaRegistrationBootstrapInput;
void registrationWithRoleLocalIdentity;

// @ts-expect-error registration bootstrap requires registrationAttemptId.
const registrationWithoutAttempt: EmailOtpEcdsaRegistrationBootstrapInput = {
  mode: 'registration_bootstrap',
  walletSession,
  chainTarget,
  routePlan,
  runtimePolicyScope,
  sessionKind: 'jwt',
  routeAuth,
  keyMode: 'existing_role_local_key',
  keyHandle: 'ederivation-key-handle-1',
};
void registrationWithoutAttempt;

// @ts-expect-error new role-local registration does not accept a keyHandle.
const registrationWithMixedKeyMode: EmailOtpEcdsaRegistrationBootstrapInput = {
  mode: 'registration_bootstrap',
  walletSession,
  chainTarget,
  routePlan,
  registrationAttemptId: 'registration-attempt-1',
  runtimePolicyScope,
  sessionKind: 'jwt',
  routeAuth,
  keyMode: 'new_role_local_key',
  keyHandle: 'ederivation-key-handle-1',
};
void registrationWithMixedKeyMode;

export {};
