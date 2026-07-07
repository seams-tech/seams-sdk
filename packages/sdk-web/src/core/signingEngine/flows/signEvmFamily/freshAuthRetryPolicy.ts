import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  decideSigningGrantAdmissionError,
  type SigningGrantAdmissionDecision,
} from '../../session/budget/admission';
import { isSigningSessionAuthUnavailableError } from '../../threshold/sessionPolicy';
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
      retryMode: 'fresh_auth';
      admissionDecision?: never;
      retryAfterMs?: never;
      blockedReason?: never;
    }
  | {
      kind: 'retry';
      trigger: Extract<EvmFamilyFreshAuthRetryTrigger, 'wallet_signing_budget_exhausted'>;
      sideEffectState: EvmFamilyFreshAuthRetrySideEffectState;
      retryMode: 'wait_and_retry_admission';
      retryAfterMs: number;
      admissionDecision: Extract<
        SigningGrantAdmissionDecision,
        { kind: 'wait_and_retry_admission' }
      >;
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
  const admissionDecision =
    args.trigger === 'wallet_signing_budget_exhausted'
      ? decideSigningGrantAdmissionError(args.error)
      : null;
  const admissionCanRetryAfterSideEffect =
    admissionDecision?.kind === 'request_fresh_step_up' ||
    admissionDecision?.kind === 'wait_and_retry_admission';
  if (
    args.sideEffectState !== 'no_auth_side_effect_started' &&
    !admissionCanRetryAfterSideEffect
  ) {
    return blocked('auth_side_effect_started');
  }

  if (args.trigger === 'email_otp_auth_unavailable') {
    if (args.hasEmailOtpSigningPlan) return blocked('email_otp_signing_plan_already_selected');
    if (
      !isSigningSessionAuthUnavailableError(args.error) &&
      !isFreshEmailOtpReauthRequiredError(args.error)
    ) {
      return blocked('error_not_retryable');
    }
    if (args.accountAuth.primaryAuthMethod !== SIGNER_AUTH_METHODS.emailOtp) {
      return blocked('primary_auth_not_email_otp');
    }
  } else {
    if (!admissionDecision) {
      return blocked('error_not_retryable');
    }
    if (
      args.hasStepUpAuthPlan &&
      admissionDecision.kind !== 'request_fresh_step_up' &&
      admissionDecision.kind !== 'wait_and_retry_admission'
    ) {
      return blocked('step_up_auth_plan_already_selected');
    }
    if (admissionDecision.kind === 'wait_and_retry_admission') {
      return {
        kind: 'retry',
        trigger: args.trigger,
        sideEffectState: args.sideEffectState,
        retryMode: 'wait_and_retry_admission',
        retryAfterMs: admissionDecision.retryAfterMs,
        admissionDecision,
      };
    }
  }

  return {
    kind: 'retry',
    trigger: args.trigger,
    sideEffectState: args.sideEffectState,
    retryMode: 'fresh_auth',
  };
}
