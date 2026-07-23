import { expect, test } from '@playwright/test';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  classifyEvmFamilyFreshAuthRetry,
  type EvmFamilyFreshAuthRetryDecision,
} from '../../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/freshAuthRetryPolicy';
import {
  SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR,
  SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR,
} from '../../packages/sdk-web/src/core/signingEngine/session/budget/budget';

function classifyBudgetRetry(
  error: Error,
  args: {
    readonly authMethod: 'passkey' | 'email_otp';
    readonly admissionRetryState: 'initial_admission' | 'authoritative_readiness_reread';
    readonly hasStepUpAuthPlan: boolean;
    readonly sideEffectState: 'no_auth_side_effect_started' | 'auth_confirmed';
  },
): EvmFamilyFreshAuthRetryDecision {
  const authMethod =
    args.authMethod === 'passkey' ? SIGNER_AUTH_METHODS.passkey : SIGNER_AUTH_METHODS.emailOtp;
  return classifyEvmFamilyFreshAuthRetry({
    trigger: 'wallet_signing_budget_exhausted',
    error,
    senderSignatureAlgorithm: 'secp256k1',
    accountAuth: {
      primaryAuthMethod: authMethod,
      linkedAuthMethods: [authMethod],
    },
    activeSigningAuthMethod: authMethod,
    admissionRetryState: { kind: args.admissionRetryState },
    alreadyRetryingFreshAuth: false,
    hasEmailOtpSigningPlan: false,
    hasStepUpAuthPlan: args.hasStepUpAuthPlan,
    sideEffectState: args.sideEffectState,
  });
}

test.describe('EVM-family fresh-auth retry policy', () => {
  test('treats server in-flight budget admission as a fresh-auth retry trigger', () => {
    expect(
      classifyBudgetRetry(new Error(SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR), {
        authMethod: 'passkey',
        admissionRetryState: 'initial_admission',
        hasStepUpAuthPlan: false,
        sideEffectState: 'no_auth_side_effect_started',
      }),
    ).toEqual({
      kind: 'retry',
      trigger: 'wallet_signing_budget_exhausted',
      sideEffectState: 'no_auth_side_effect_started',
      retryMode: 'await_admission_owner_completion',
      admissionDecision: {
        kind: 'wait_and_retry_admission',
        retryAfterMs: 150,
        failure: {
          kind: 'in_flight',
          source: 'local_projection',
          detail: SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR,
          retryAfterMs: 150,
        },
      },
    });
  });

  test('does not loop when authoritative readiness still reports admission in flight', () => {
    expect(
      classifyBudgetRetry(new Error(SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR), {
        authMethod: 'passkey',
        admissionRetryState: 'authoritative_readiness_reread',
        hasStepUpAuthPlan: false,
        sideEffectState: 'no_auth_side_effect_started',
      }),
    ).toEqual({
      kind: 'do_not_retry',
      trigger: 'wallet_signing_budget_exhausted',
      sideEffectState: 'no_auth_side_effect_started',
      blockedReason: 'authoritative_readiness_still_in_flight',
    });
  });

  test('allows budget exhaustion retry after auth side effects when server admission loses the race', () => {
    expect(
      classifyBudgetRetry(new Error(SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR), {
        authMethod: 'passkey',
        admissionRetryState: 'initial_admission',
        hasStepUpAuthPlan: true,
        sideEffectState: 'auth_confirmed',
      }),
    ).toEqual({
      kind: 'retry',
      trigger: 'wallet_signing_budget_exhausted',
      sideEffectState: 'auth_confirmed',
      retryMode: 'fresh_auth',
    });
  });

  test('uses a single-operation Email OTP step-up after authoritative exhaustion', () => {
    const decision = classifyBudgetRetry(new Error(SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR), {
      authMethod: 'email_otp',
      admissionRetryState: 'initial_admission',
      hasStepUpAuthPlan: false,
      sideEffectState: 'no_auth_side_effect_started',
    });
    expect(decision.kind).toBe('retry');
    if (decision.kind !== 'retry') throw new Error('expected retry decision');
    expect(decision.retryMode).toBe('email_otp_single_operation_step_up');
  });
});
