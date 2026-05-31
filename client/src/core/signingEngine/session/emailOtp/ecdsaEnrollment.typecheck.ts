import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import type { EmailOtpRoutePlan } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpEcdsaRoleLocalKeyIdentity } from './ecdsaRoleLocalIdentity';
import type { EmailOtpEcdsaRegistrationBootstrapInput } from './ecdsaEnrollment';

declare const walletSession: WalletSessionRef;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const routePlan: EmailOtpRoutePlan;
declare const routeAuth: AppOrThresholdSessionAuth;
declare const runtimePolicyScope: ThresholdRuntimePolicyScope;
declare const roleLocalKeyIdentity: EmailOtpEcdsaRoleLocalKeyIdentity;

const existingKeyRegistration: EmailOtpEcdsaRegistrationBootstrapInput = {
  mode: 'registration_bootstrap',
  walletSession,
  chainTarget,
  routePlan,
  registrationAttemptId: 'registration-attempt-1',
  runtimePolicyScope,
  roleLocalKeyIdentity,
  sessionKind: 'jwt',
  routeAuth,
  keyMode: 'existing_role_local_key',
  keyHandle: 'ehss-key-handle-1',
};
void existingKeyRegistration;

const newKeyRegistration: EmailOtpEcdsaRegistrationBootstrapInput = {
  mode: 'registration_bootstrap',
  walletSession,
  chainTarget,
  routePlan,
  registrationAttemptId: 'registration-attempt-1',
  runtimePolicyScope,
  roleLocalKeyIdentity,
  sessionKind: 'cookie',
  keyMode: 'new_role_local_key',
};
void newKeyRegistration;

// @ts-expect-error registration bootstrap requires registrationAttemptId.
const registrationWithoutAttempt: EmailOtpEcdsaRegistrationBootstrapInput = {
  mode: 'registration_bootstrap',
  walletSession,
  chainTarget,
  routePlan,
  runtimePolicyScope,
  roleLocalKeyIdentity,
  sessionKind: 'jwt',
  routeAuth,
  keyMode: 'existing_role_local_key',
  keyHandle: 'ehss-key-handle-1',
};
void registrationWithoutAttempt;

// @ts-expect-error registration bootstrap requires role-local key identity.
const registrationWithoutRoleLocalIdentity: EmailOtpEcdsaRegistrationBootstrapInput = {
  mode: 'registration_bootstrap',
  walletSession,
  chainTarget,
  routePlan,
  registrationAttemptId: 'registration-attempt-1',
  runtimePolicyScope,
  sessionKind: 'jwt',
  routeAuth,
  keyMode: 'existing_role_local_key',
  keyHandle: 'ehss-key-handle-1',
};
void registrationWithoutRoleLocalIdentity;

// @ts-expect-error new role-local registration does not accept a keyHandle.
const registrationWithMixedKeyMode: EmailOtpEcdsaRegistrationBootstrapInput = {
  mode: 'registration_bootstrap',
  walletSession,
  chainTarget,
  routePlan,
  registrationAttemptId: 'registration-attempt-1',
  runtimePolicyScope,
  roleLocalKeyIdentity,
  sessionKind: 'cookie',
  keyMode: 'new_role_local_key',
  keyHandle: 'ehss-key-handle-1',
};
void registrationWithMixedKeyMode;

export {};
