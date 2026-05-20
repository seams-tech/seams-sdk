import { SigningSessionIds } from '../operationState/types';
import {
  buildSingleOperationStepUpBudgetPolicy,
  buildWalletUnlockBudgetPolicy,
  buildWarmBudgetRefreshStepUpBudgetPolicy,
  parseServerEnvironmentBudgetAllowance,
} from './policy';

const operationId = SigningSessionIds.signingOperation('operation-1');

void buildWalletUnlockBudgetPolicy();

void buildWalletUnlockBudgetPolicy({
  allowance: parseServerEnvironmentBudgetAllowance({
    remainingUses: 2,
    policyVersion: 'server-policy-v1',
  }),
});

void buildSingleOperationStepUpBudgetPolicy({
  operationId,
});

void buildWarmBudgetRefreshStepUpBudgetPolicy({
  operationId,
  allowance: parseServerEnvironmentBudgetAllowance({
    remainingUses: 2,
    policyVersion: 'server-policy-v1',
  }),
});

// @ts-expect-error single-operation step-up requires operationId
void buildSingleOperationStepUpBudgetPolicy({});

// @ts-expect-error wallet unlock policy must not accept operation-scoped fields
void buildWalletUnlockBudgetPolicy({ operationId });

// @ts-expect-error warm refresh step-up requires allowance
void buildWarmBudgetRefreshStepUpBudgetPolicy({
  operationId,
});

export {};
