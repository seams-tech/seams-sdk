import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { isSigningSessionBudgetExhaustedError } from '../../session/budget/budget';
import { isThresholdSessionAuthUnavailableError } from '../../threshold/sessionPolicy';
import { isFreshEmailOtpReauthRequiredError } from './errors';
import type { EvmFamilySenderSignatureAlgorithm } from './types';

export type EvmFamilyFreshAuthRetrySideEffectState =
  | 'no_auth_side_effect_started'
  | 'auth_prompt_shown'
  | 'auth_confirmed'
  | 'threshold_reconnect_started';

export type EvmFamilySigningAuthSideEffect =
  | 'auth_prompt_shown'
  | 'email_otp_challenge'
  | 'passkey_reauth'
  | 'auth_confirmed'
  | 'threshold_reconnect';

export type EvmFamilyFreshAuthRetryTrigger =
  | 'email_otp_auth_unavailable'
  | 'wallet_signing_budget_exhausted';

export type EvmFamilyFreshAuthRetryBlockedReason =
  | 'already_retrying'
  | 'non_secp256k1_sender'
  | 'auth_side_effect_started'
  | 'email_otp_signing_plan_already_selected'
  | 'step_up_auth_plan_already_selected'
  | 'error_not_retryable'
  | 'primary_auth_not_email_otp';

export type EvmFamilyFreshAuthRetryDecision =
  | {
      kind: 'retry';
      trigger: EvmFamilyFreshAuthRetryTrigger;
      sideEffectState: EvmFamilyFreshAuthRetrySideEffectState;
      blockedReason?: never;
    }
  | {
      kind: 'do_not_retry';
      trigger: EvmFamilyFreshAuthRetryTrigger;
      sideEffectState: EvmFamilyFreshAuthRetrySideEffectState;
      blockedReason: EvmFamilyFreshAuthRetryBlockedReason;
    };

export function nextEvmFamilyFreshAuthRetrySideEffectState(args: {
  current: EvmFamilyFreshAuthRetrySideEffectState;
  sideEffect: EvmFamilySigningAuthSideEffect;
}): EvmFamilyFreshAuthRetrySideEffectState {
  if (args.current === 'threshold_reconnect_started') return args.current;
  switch (args.sideEffect) {
    case 'auth_prompt_shown':
    case 'email_otp_challenge':
    case 'passkey_reauth':
      return args.current === 'no_auth_side_effect_started'
        ? 'auth_prompt_shown'
        : args.current;
    case 'auth_confirmed':
      return 'auth_confirmed';
    case 'threshold_reconnect':
      return 'threshold_reconnect_started';
  }
}

export function classifyEvmFamilyFreshAuthRetry(args: {
  trigger: EvmFamilyFreshAuthRetryTrigger;
  error: unknown;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  accountAuth: AccountAuthMetadata;
  alreadyRetryingFreshAuth?: boolean;
  hasEmailOtpSigningPlan?: boolean;
  hasStepUpAuthPlan?: boolean;
  sideEffectState: EvmFamilyFreshAuthRetrySideEffectState;
}): EvmFamilyFreshAuthRetryDecision {
  const blocked = (
    blockedReason: EvmFamilyFreshAuthRetryBlockedReason,
  ): EvmFamilyFreshAuthRetryDecision => ({
    kind: 'do_not_retry',
    trigger: args.trigger,
    sideEffectState: args.sideEffectState,
    blockedReason,
  });
  if (args.alreadyRetryingFreshAuth) return blocked('already_retrying');
  if (args.senderSignatureAlgorithm !== 'secp256k1') return blocked('non_secp256k1_sender');
  if (args.sideEffectState !== 'no_auth_side_effect_started') {
    return blocked('auth_side_effect_started');
  }

  if (args.trigger === 'email_otp_auth_unavailable') {
    if (args.hasEmailOtpSigningPlan) return blocked('email_otp_signing_plan_already_selected');
    if (
      !isThresholdSessionAuthUnavailableError(args.error) &&
      !isFreshEmailOtpReauthRequiredError(args.error)
    ) {
      return blocked('error_not_retryable');
    }
    if (args.accountAuth.primaryAuthMethod !== SIGNER_AUTH_METHODS.emailOtp) {
      return blocked('primary_auth_not_email_otp');
    }
  } else {
    if (args.hasStepUpAuthPlan) return blocked('step_up_auth_plan_already_selected');
    if (!isSigningSessionBudgetExhaustedError(args.error)) return blocked('error_not_retryable');
  }

  return {
    kind: 'retry',
    trigger: args.trigger,
    sideEffectState: args.sideEffectState,
  };
}
