import { expect, test } from '@playwright/test';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  classifyEvmFamilyFreshAuthRetry,
  type EvmFamilyFreshAuthRetryDecision,
} from '../../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/freshAuthRetryPolicy';
import { SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR } from '../../packages/sdk-web/src/core/signingEngine/session/budget/budget';

function classifyBudgetRetry(error: Error): EvmFamilyFreshAuthRetryDecision {
  return classifyEvmFamilyFreshAuthRetry({
    trigger: 'wallet_signing_budget_exhausted',
    error,
    senderSignatureAlgorithm: 'secp256k1',
    accountAuth: {
      primaryAuthMethod: SIGNER_AUTH_METHODS.passkey,
      linkedAuthMethods: [SIGNER_AUTH_METHODS.passkey],
    },
    sideEffectState: 'no_auth_side_effect_started',
  });
}

test.describe('EVM-family fresh-auth retry policy', () => {
  test('treats server in-flight budget admission as a fresh-auth retry trigger', () => {
    expect(classifyBudgetRetry(new Error(SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR))).toEqual({
      kind: 'retry',
      trigger: 'wallet_signing_budget_exhausted',
      sideEffectState: 'no_auth_side_effect_started',
    });
  });
});
