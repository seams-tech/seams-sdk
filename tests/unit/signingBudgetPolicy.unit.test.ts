import { expect, test } from '@playwright/test';
import { SigningSessionIds } from '../../client/src/core/signingEngine/session/operationState/types';
import {
  DEV_DEFAULT_UNLOCK_REMAINING_USES,
  buildWalletUnlockBudgetPolicy,
  parseServerEnvironmentBudgetAllowance,
  resolvePostExhaustionStepUpBudgetPolicy,
  resolveSigningBudgetPolicyRemainingUses,
  resolveWalletUnlockBudgetPolicyFromRequestedUses,
} from '../../client/src/core/signingEngine/session/budget/policy';

test.describe('signing budget policy', () => {
  test('uses literal dev-default unlock budget of three uses', () => {
    const policy = buildWalletUnlockBudgetPolicy();
    expect(policy.kind).toBe('wallet_unlock_budget_policy');
    expect(policy.allowance).toEqual({
      kind: 'dev_default_budget_allowance',
      remainingUses: DEV_DEFAULT_UNLOCK_REMAINING_USES,
      source: 'sdk_dev_default',
    });
    expect(resolveSigningBudgetPolicyRemainingUses(policy)).toBe(3);
  });

  test('parses server/environment allowance at the boundary', () => {
    const allowance = parseServerEnvironmentBudgetAllowance({
      remainingUses: 2,
      policyVersion: 'server-policy-v2',
    });
    expect(allowance).toEqual({
      kind: 'server_environment_budget_allowance',
      remainingUses: 2,
      policyVersion: 'server-policy-v2',
      source: 'server_environment_policy',
    });
  });

  test('defaults post-exhaustion step-up to a single-use budget', () => {
    const policy = resolvePostExhaustionStepUpBudgetPolicy({
      operationId: SigningSessionIds.signingOperation('tx-step-up-1'),
    });
    expect(policy.kind).toBe('single_operation_step_up_budget_policy');
    expect(resolveSigningBudgetPolicyRemainingUses(policy)).toBe(1);
  });

  test('requires explicit warm-budget-refresh opt-in', () => {
    const allowance = parseServerEnvironmentBudgetAllowance({
      remainingUses: 2,
      policyVersion: 'server-policy-v2',
    });
    const policy = resolvePostExhaustionStepUpBudgetPolicy({
      operationId: SigningSessionIds.signingOperation('tx-step-up-2'),
      warmBudgetRefreshAllowance: allowance,
    });
    expect(policy.kind).toBe('warm_budget_refresh_step_up_policy');
    expect(resolveSigningBudgetPolicyRemainingUses(policy)).toBe(2);
  });

  test('normalizes unlock overrides through wallet-unlock policy parsing', () => {
    const policy = resolveWalletUnlockBudgetPolicyFromRequestedUses({
      requestedRemainingUses: 7,
      policyVersion: 'sdk-config-v1',
    });
    expect(policy).not.toBeNull();
    expect(policy?.kind).toBe('wallet_unlock_budget_policy');
    expect(resolveSigningBudgetPolicyRemainingUses(policy!)).toBe(3);
  });
});
