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
  overrides: Partial<Parameters<typeof classifyEvmFamilyFreshAuthRetry>[0]> = {},
): EvmFamilyFreshAuthRetryDecision {
  return classifyEvmFamilyFreshAuthRetry({
    trigger: 'wallet_signing_budget_exhausted',
    error,
    senderSignatureAlgorithm: 'secp256k1',
    accountAuth: {
      primaryAuthMethod: SIGNER_AUTH_METHODS.passkey,
      linkedAuthMethods: [SIGNER_AUTH_METHODS.passkey],
    },
    sideEffectState: 'no_auth_side_effect_started',
    ...overrides,
  });
}

test.describe('EVM-family fresh-auth retry policy', () => {
  test('treats server in-flight budget admission as a fresh-auth retry trigger', () => {
    expect(classifyBudgetRetry(new Error(SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR))).toEqual({
      kind: 'retry',
      trigger: 'wallet_signing_budget_exhausted',
      sideEffectState: 'no_auth_side_effect_started',
      retryMode: 'wait_and_retry_admission',
      retryAfterMs: 150,
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

  test('allows budget exhaustion retry after auth side effects when server admission loses the race', () => {
    expect(
      classifyBudgetRetry(new Error(SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR), {
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
});
