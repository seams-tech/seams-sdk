import { expect, test } from '@playwright/test';
import { buildTempoTransactionSigningLane } from '@/core/signingEngine/session/SigningLaneBuilders';
import { createTransactionSigningBudgetFinalizer } from '@/core/signingEngine/session/TransactionSigningBudgetFinalizer';
import { SigningSessionIds } from '@/core/signingEngine/session/signingSessionTypes';
import { toAccountId } from '@/core/types/accountIds';

test.describe('TransactionSigningBudgetFinalizer', () => {
  test('fails closed when authoritative budget success recording fails', async () => {
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('budget-finalizer.testnet'),
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-budget-finalizer'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-budget-finalizer'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const observedErrors: string[] = [];
    const finalizer = createTransactionSigningBudgetFinalizer({
      walletSigningBudgetLedger: {
        reserve: async () => null,
        getAvailableStatus: async () => null,
        recordSuccess: async () => {
          throw new Error('authoritative consume failed');
        },
        recordZeroSpend: () => {},
        hasRecorded: () => false,
      },
      operation: {
        operationId: SigningSessionIds.signingOperation('op-budget-finalizer-fail-closed'),
        intent: 'transaction_sign',
      },
      lane,
      onRecordSuccessError: (error) => {
        observedErrors.push(error instanceof Error ? error.message : String(error));
      },
    });

    await expect(finalizer.recordSuccess()).rejects.toThrow('authoritative consume failed');
    expect(observedErrors).toEqual(['authoritative consume failed']);
  });
});
