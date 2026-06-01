import { SigningSessionIds } from '../operationState/types';
import {
  buildSingleOperationStepUpBudgetPolicy,
  buildWalletUnlockBudgetPolicy,
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
  requiredSignatureUses: 1,
});

// @ts-expect-error single-operation step-up requires operationId
void buildSingleOperationStepUpBudgetPolicy({});

// @ts-expect-error single-operation step-up requires the operation signature count
void buildSingleOperationStepUpBudgetPolicy({ operationId });

// @ts-expect-error wallet unlock policy must not accept operation-scoped fields
void buildWalletUnlockBudgetPolicy({ operationId });

export {};
