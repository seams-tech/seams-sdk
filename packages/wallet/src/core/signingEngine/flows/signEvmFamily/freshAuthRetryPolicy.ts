import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import {
  SIGNER_AUTH_METHODS,
  type SignerAuthMethod,
} from '@shared/utils/signerDomain';
import {
  WalletSessionQuotaAdmissionError,
  classifyWalletSessionQuotaAdmissionFailure,
  decideWalletSessionQuotaAdmissionFailure,
  type RouterAbOwnerOperationAuthorizationDecisionV1Wire,
  type OperationAuthorizationQueueKey,
  type WalletSessionQuotaAdmissionDecision,
} from '../../session/operationState/authorizationAdmission';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { EvmFamilySenderSignatureAlgorithm } from './types';

function ownerOperationAuthorizationDecisionFromError(
  error: unknown,
): RouterAbOwnerOperationAuthorizationDecisionV1Wire | undefined {
  return error instanceof WalletSessionQuotaAdmissionError
    ? error.authorizationDecision
    : undefined;
}

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
  | 'wallet_session_reauthorization_required'
  | 'wallet_signing_budget_exhausted';

export type EvmFamilyFreshAuthRetryBlockedReason =
  | 'already_retrying'
  | 'non_secp256k1_sender'
  | 'auth_side_effect_started'
  | 'signing_auth_plan_already_selected'
  | 'step_up_auth_plan_already_selected'
  | 'authoritative_readiness_still_in_flight'
  | 'error_not_retryable'
  | 'unsupported_primary_auth';

export type EvmFamilyAdmissionRetryState =
  | { kind: 'initial_admission' }
  | { kind: 'authoritative_readiness_reread' };

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
      retryMode: 'await_admission_owner_completion';
      retryAfterMs?: never;
      admissionDecision: Extract<
        WalletSessionQuotaAdmissionDecision,
        { kind: 'wait_and_retry_admission' }
      >;
      blockedReason?: never;
    }
  | {
      kind: 'retry';
      trigger: Extract<EvmFamilyFreshAuthRetryTrigger, 'wallet_signing_budget_exhausted'>;
      sideEffectState: EvmFamilyFreshAuthRetrySideEffectState;
      retryMode: 'email_otp_single_operation_step_up';
      retryAfterMs?: never;
      admissionDecision: Extract<
        WalletSessionQuotaAdmissionDecision,
        { kind: 'request_fresh_step_up' }
      >;
      blockedReason?: never;
    }
  | {
      kind: 'do_not_retry';
      trigger: EvmFamilyFreshAuthRetryTrigger;
      sideEffectState: EvmFamilyFreshAuthRetrySideEffectState;
      blockedReason: EvmFamilyFreshAuthRetryBlockedReason;
    };

export async function runEvmFamilyFreshAuthRetry<TValue>(args: {
  decision: Extract<EvmFamilyFreshAuthRetryDecision, { kind: 'retry' }>;
  queueKey: OperationAuthorizationQueueKey;
  signingSessionCoordinator: SigningSessionCoordinator;
  rereadAuthoritativeReadiness: () => Promise<TValue>;
  performFreshAuth: () => Promise<TValue>;
}): Promise<TValue> {
  switch (args.decision.retryMode) {
    case 'await_admission_owner_completion':
      return await args.signingSessionCoordinator.runWalletSessionQuotaAdmissionRetry({
        queueKey: args.queueKey,
        refresh: args.rereadAuthoritativeReadiness,
        retryAfterRefresh: args.rereadAuthoritativeReadiness,
      });
    case 'email_otp_single_operation_step_up':
    case 'fresh_auth':
      return await args.signingSessionCoordinator.runWalletSessionQuotaAdmissionRetry({
        queueKey: args.queueKey,
        refresh: args.performFreshAuth,
        retryAfterRefresh: args.rereadAuthoritativeReadiness,
      });
    default:
      return assertNeverEvmFamilyFreshAuthRetryMode(args.decision);
  }
}

function assertNeverEvmFamilyFreshAuthRetryMode(value: never): never {
  throw new Error(`[SigningEngine][ecdsa] unsupported fresh-auth retry mode: ${String(value)}`);
}

function buildBlockedEvmFamilyFreshAuthRetryDecision(args: {
  trigger: EvmFamilyFreshAuthRetryTrigger;
  sideEffectState: EvmFamilyFreshAuthRetrySideEffectState;
  blockedReason: EvmFamilyFreshAuthRetryBlockedReason;
}): EvmFamilyFreshAuthRetryDecision {
  return {
    kind: 'do_not_retry',
    trigger: args.trigger,
    sideEffectState: args.sideEffectState,
    blockedReason: args.blockedReason,
  };
}

type EvmFamilyFreshAuthRetryInputBase = {
  error: unknown;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  accountAuth: AccountAuthMetadata;
  alreadyRetryingFreshAuth?: boolean;
  hasEmailOtpSigningPlan?: boolean;
  hasStepUpAuthPlan?: boolean;
  sideEffectState: EvmFamilyFreshAuthRetrySideEffectState;
};

export type EvmFamilyFreshAuthRetryInput = EvmFamilyFreshAuthRetryInputBase &
  (
    | {
        trigger: 'wallet_session_reauthorization_required';
        activeSigningAuthMethod?: never;
        admissionRetryState?: never;
      }
    | {
        trigger: 'wallet_signing_budget_exhausted';
        activeSigningAuthMethod: SignerAuthMethod;
        admissionRetryState: EvmFamilyAdmissionRetryState;
      }
  );

function blockEvmFamilyFreshAuthRetry(
  args: EvmFamilyFreshAuthRetryInput,
  blockedReason: EvmFamilyFreshAuthRetryBlockedReason,
): EvmFamilyFreshAuthRetryDecision {
  return buildBlockedEvmFamilyFreshAuthRetryDecision({
    trigger: args.trigger,
    sideEffectState: args.sideEffectState,
    blockedReason,
  });
}

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

export function classifyEvmFamilyFreshAuthRetry(
  args: EvmFamilyFreshAuthRetryInput,
): EvmFamilyFreshAuthRetryDecision {
  if (args.alreadyRetryingFreshAuth) {
    return blockEvmFamilyFreshAuthRetry(args, 'already_retrying');
  }
  if (args.senderSignatureAlgorithm !== 'secp256k1') {
    return blockEvmFamilyFreshAuthRetry(args, 'non_secp256k1_sender');
  }
  const ownerDecision = ownerOperationAuthorizationDecisionFromError(args.error);
  const admissionFailure = classifyWalletSessionQuotaAdmissionFailure(args.error);
  const admissionDecision =
    args.trigger === 'wallet_signing_budget_exhausted'
      ? ownerDecision?.kind === 'step_up_required'
        ? decideWalletSessionQuotaAdmissionFailure(
            admissionFailure ?? {
              kind: 'exhausted',
              source: 'server_prepare',
              detail: 'Server requires owner operation step-up',
            },
          )
        : admissionFailure?.kind === 'in_flight'
          ? decideWalletSessionQuotaAdmissionFailure(admissionFailure)
          : null
      : null;
  const admissionCanRetryAfterSideEffect =
    admissionDecision?.kind === 'request_fresh_step_up' ||
    admissionDecision?.kind === 'wait_and_retry_admission';
  if (
    args.sideEffectState !== 'no_auth_side_effect_started' &&
    !admissionCanRetryAfterSideEffect
  ) {
    return blockEvmFamilyFreshAuthRetry(args, 'auth_side_effect_started');
  }

  if (args.trigger === 'wallet_session_reauthorization_required') {
    if (args.hasEmailOtpSigningPlan || args.hasStepUpAuthPlan) {
      return blockEvmFamilyFreshAuthRetry(args, 'signing_auth_plan_already_selected');
    }
    if (ownerDecision?.kind !== 'step_up_required') {
      return blockEvmFamilyFreshAuthRetry(args, 'error_not_retryable');
    }
    if (
      args.accountAuth.primaryAuthMethod !== SIGNER_AUTH_METHODS.emailOtp &&
      args.accountAuth.primaryAuthMethod !== SIGNER_AUTH_METHODS.passkey
    ) {
      return blockEvmFamilyFreshAuthRetry(args, 'unsupported_primary_auth');
    }
  } else {
    if (!admissionDecision) {
      return blockEvmFamilyFreshAuthRetry(args, 'error_not_retryable');
    }
    if (
      args.hasStepUpAuthPlan &&
      admissionDecision.kind !== 'request_fresh_step_up' &&
      admissionDecision.kind !== 'wait_and_retry_admission'
    ) {
      return blockEvmFamilyFreshAuthRetry(args, 'step_up_auth_plan_already_selected');
    }
    if (admissionDecision.kind === 'wait_and_retry_admission') {
      if (args.admissionRetryState.kind === 'authoritative_readiness_reread') {
        return blockEvmFamilyFreshAuthRetry(
          args,
          'authoritative_readiness_still_in_flight',
        );
      }
      return {
        kind: 'retry',
        trigger: args.trigger,
        sideEffectState: args.sideEffectState,
        retryMode: 'await_admission_owner_completion',
        admissionDecision,
      };
    }
    if (args.activeSigningAuthMethod === SIGNER_AUTH_METHODS.emailOtp) {
      return {
        kind: 'retry',
        trigger: args.trigger,
        sideEffectState: args.sideEffectState,
        retryMode: 'email_otp_single_operation_step_up',
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
