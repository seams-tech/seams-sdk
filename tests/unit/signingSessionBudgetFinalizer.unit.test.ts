import { expect, test } from '@playwright/test';
import { toAccountId } from '../../client/src/core/types/accountIds';
import { BudgetCoordinator } from '../../client/src/core/signingEngine/session/budget/BudgetCoordinator';
import type {
  BudgetFinalizationSpend,
  ExternallyConsumedBudgetFinalizationSpend,
  ReservedBudgetFinalizationSpend,
  SigningSessionBudget,
  SigningSessionPreparedBudgetIdentity,
  UnreservedBudgetFinalizationSpend,
  ZeroBudgetFinalizationSpend,
} from '../../client/src/core/signingEngine/session/budget/budget';
import { createSigningSessionBudgetFinalizer } from '../../client/src/core/signingEngine/session/budget/budgetFinalizer';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type WalletSigningSpendPlan,
} from '../../client/src/core/signingEngine/session/operationState/types';
import {
  buildNearTransactionSigningLane,
  type NearTransactionSigningLane,
} from '../../client/src/core/signingEngine/session/operationState/lanes';

function makeLane(args?: {
  walletSigningSessionId?: string;
  thresholdSessionId?: string;
}): NearTransactionSigningLane {
  return buildNearTransactionSigningLane({
    accountId: toAccountId('alice.testnet'),
    authMethod: 'passkey',
    walletSigningSessionId: SigningSessionIds.walletSigningSession(
      args?.walletSigningSessionId || 'wallet-session-1',
    ),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
      args?.thresholdSessionId || 'threshold-session-1',
    ),
    storageSource: 'login',
  });
}

function makeSpend(args?: {
  walletSigningSessionId?: string;
  thresholdSessionId?: string;
}): WalletSigningSpendPlan {
  const lane = makeLane(args);
  return {
    operationId: SigningSessionIds.signingOperation('operation-1'),
    operationFingerprint: SigningSessionIds.signingOperationFingerprint('fingerprint-1'),
    walletId: lane.accountId,
    walletSigningSessionId: lane.walletSigningSessionId,
    lane,
    thresholdSessionIds: [lane.thresholdSessionId],
    backingMaterialSessionIds: [],
    uses: 1,
    reason: SigningOperationIntent.TransactionSign,
  };
}

function makeBudgetIdentity(spend: WalletSigningSpendPlan): SigningSessionPreparedBudgetIdentity {
  return {
    walletSigningSessionId: spend.walletSigningSessionId,
    projectionVersion: 'projection-1',
    status: {
      sessionId: String(spend.walletSigningSessionId),
      status: 'active',
      projectionVersion: 'projection-1',
      remainingUses: 2,
      expiresAtMs: 1_900_000_000_000,
    },
  };
}

function makeReservedSuccess(): ReservedBudgetFinalizationSpend {
  return {
    kind: 'reserved_success',
    spend: makeSpend(),
    expectedBudgetProjectionVersion: 'projection-1',
    trustedStatusAuth: {
      relayerUrl: 'https://relayer.example.test',
      thresholdSessionId: 'threshold-session-1',
    },
  };
}

function makeUnreservedSuccess(): UnreservedBudgetFinalizationSpend {
  return {
    kind: 'unreserved_success',
    spend: makeSpend(),
    expectedBudgetProjectionVersion: 'projection-1',
  };
}

function makeExternallyConsumedSuccess(): ExternallyConsumedBudgetFinalizationSpend {
  const spend = makeSpend();
  return {
    kind: 'externally_consumed_success',
    spend,
    alreadyConsumedThresholdSessionIds: [spend.lane.thresholdSessionId],
  };
}

function makeZeroSpend(): ZeroBudgetFinalizationSpend {
  return {
    kind: 'zero_spend',
    operationId: SigningSessionIds.signingOperation('operation-1'),
    lane: makeLane(),
    reason: 'signing_failed',
  };
}

function makeBudgetRecorder(): {
  budget: SigningSessionBudget;
  recordedSuccesses: BudgetFinalizationSpend[];
  recordedZeroSpends: ZeroBudgetFinalizationSpend[];
} {
  const recordedSuccesses: BudgetFinalizationSpend[] = [];
  const recordedZeroSpends: ZeroBudgetFinalizationSpend[] = [];
  return {
    recordedSuccesses,
    recordedZeroSpends,
    budget: {
      async reserve() {
        return null;
      },
      async getAvailableStatus() {
        return null;
      },
      async recordSuccess(input) {
        recordedSuccesses.push(input);
        return null;
      },
      recordZeroSpend(input) {
        recordedZeroSpends.push(input);
      },
      hasRecorded() {
        return false;
      },
    },
  };
}

test.describe('signing session budget finalizer', () => {
  test('forwards reserved_success to the budget recorder', async () => {
    const { budget, recordedSuccesses } = makeBudgetRecorder();
    const finalization = makeReservedSuccess();
    const finalizer = createSigningSessionBudgetFinalizer({
      signingSessionBudget: budget,
      budgetIdentity: makeBudgetIdentity(finalization.spend),
      finalization,
    });

    await finalizer.recordSuccess();

    expect(recordedSuccesses).toEqual([finalization]);
  });

  test('forwards unreserved_success to the budget recorder', async () => {
    const { budget, recordedSuccesses } = makeBudgetRecorder();
    const finalization = makeUnreservedSuccess();
    const finalizer = createSigningSessionBudgetFinalizer({
      signingSessionBudget: budget,
      budgetIdentity: makeBudgetIdentity(finalization.spend),
      finalization,
    });

    await finalizer.recordSuccess();

    expect(recordedSuccesses).toEqual([finalization]);
  });

  test('forwards externally_consumed_success to the budget recorder', async () => {
    const { budget, recordedSuccesses } = makeBudgetRecorder();
    const finalization = makeExternallyConsumedSuccess();
    const finalizer = createSigningSessionBudgetFinalizer({
      signingSessionBudget: budget,
      budgetIdentity: makeBudgetIdentity(finalization.spend),
      finalization,
    });

    await finalizer.recordSuccess();

    expect(recordedSuccesses).toEqual([finalization]);
  });

  test('uses the stored zero_spend branch when recording zero spend', () => {
    const { budget, recordedZeroSpends } = makeBudgetRecorder();
    const finalization = makeZeroSpend();
    const finalizer = createSigningSessionBudgetFinalizer({
      signingSessionBudget: budget,
      budgetIdentity: makeBudgetIdentity(makeSpend()),
      finalization,
    });
    const error = new Error('request cancelled by user');

    finalizer.recordZeroSpend(error);

    expect(recordedZeroSpends).toEqual([
      {
        ...finalization,
        reason: 'confirmation_cancelled',
        error,
      },
    ]);
  });
});

test.describe('budget coordinator reserved success handling', () => {
  test('accepts reserved_success after an explicit reservation', async () => {
    const consumeUseCalls: BudgetFinalizationSpend[] = [];
    const coordinator = new BudgetCoordinator({
      async readStatus() {
        return {
          sessionId: 'wallet-session-1',
          status: 'active',
          projectionVersion: 'projection-1',
          remainingUses: 2,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      async consumeUse(args) {
        consumeUseCalls.push({
          kind: 'externally_consumed_success',
          spend: {
            operationId: SigningSessionIds.signingOperation('observation-only'),
            walletId: toAccountId(String(args.walletId)),
            walletSigningSessionId: SigningSessionIds.walletSigningSession(
              args.walletSigningSessionId,
            ),
            lane: makeLane(),
            thresholdSessionIds: [],
            backingMaterialSessionIds: [],
            uses: 1,
            reason: SigningOperationIntent.TransactionSign,
          },
          alreadyConsumedThresholdSessionIds: [
            SigningSessionIds.thresholdEd25519Session('threshold-session-1'),
          ],
        });
        return {
          sessionId: args.walletSigningSessionId,
          status: 'active',
          projectionVersion: 'projection-2',
          remainingUses: 1,
          expiresAtMs: 1_900_000_000_000,
        };
      },
    });
    const finalization = makeReservedSuccess();

    await coordinator.reserve({
      spend: finalization.spend,
      expectedBudgetProjectionVersion: finalization.expectedBudgetProjectionVersion,
      trustedStatusAuth: finalization.trustedStatusAuth,
    });
    await coordinator.recordSuccess(finalization);

    expect(consumeUseCalls).toHaveLength(1);
  });

  test('accepts reserved_success when another spend advances the projection before finalization', async () => {
    const consumeUseCalls: string[] = [];
    const coordinator = new BudgetCoordinator({
      async readStatus() {
        return {
          sessionId: 'wallet-session-1',
          status: 'active',
          projectionVersion: 'projection-1',
          remainingUses: 3,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      async consumeUse(args) {
        consumeUseCalls.push(args.walletSigningSessionId);
        return {
          sessionId: args.walletSigningSessionId,
          status: 'active',
          projectionVersion: 'projection-3',
          remainingUses: 1,
          expiresAtMs: 1_900_000_000_000,
        };
      },
    });
    const reserved = makeReservedSuccess();
    await coordinator.reserve({
      spend: reserved.spend,
      expectedBudgetProjectionVersion: reserved.expectedBudgetProjectionVersion,
      trustedStatusAuth: reserved.trustedStatusAuth,
    });

    await coordinator.recordSuccess({
      ...reserved,
      expectedBudgetProjectionVersion: 'projection-2',
    });

    expect(consumeUseCalls).toEqual(['wallet-session-1']);
  });

  test('rejects reserved_success when finalization changes the reserved spend identity', async () => {
    const coordinator = new BudgetCoordinator({
      async readStatus() {
        return {
          sessionId: 'wallet-session-1',
          status: 'active',
          projectionVersion: 'projection-1',
          remainingUses: 3,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      async consumeUse() {
        throw new Error('consumeUse should not run');
      },
    });
    const reserved = makeReservedSuccess();
    await coordinator.reserve({
      spend: reserved.spend,
      expectedBudgetProjectionVersion: reserved.expectedBudgetProjectionVersion,
      trustedStatusAuth: reserved.trustedStatusAuth,
    });

    await expect(
      coordinator.recordSuccess({
        ...reserved,
        spend: makeSpend({ walletSigningSessionId: 'wallet-session-2' }),
      }),
    ).rejects.toThrow('[SigningSessionBudget] reserved_success spend does not match reservation');
  });

  test('rejects unreserved_success when a reservation exists', async () => {
    const coordinator = new BudgetCoordinator({
      async readStatus() {
        return {
          sessionId: 'wallet-session-1',
          status: 'active',
          projectionVersion: 'projection-1',
          remainingUses: 2,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      async consumeUse() {
        throw new Error('consumeUse should not run');
      },
    });
    const reserved = makeReservedSuccess();
    const unreserved = makeUnreservedSuccess();

    await coordinator.reserve({
      spend: reserved.spend,
      expectedBudgetProjectionVersion: reserved.expectedBudgetProjectionVersion,
      trustedStatusAuth: reserved.trustedStatusAuth,
    });

    await expect(coordinator.recordSuccess(unreserved)).rejects.toThrow(
      '[SigningSessionBudget] reserved operations must finalize with reserved_success',
    );
  });

  test('rejects externally_consumed_success without consumed identity lists at normalization', async () => {
    const coordinator = new BudgetCoordinator({
      async readStatus() {
        return {
          sessionId: 'wallet-session-1',
          status: 'active',
          projectionVersion: 'projection-1',
          remainingUses: 2,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      async consumeUse() {
        throw new Error('consumeUse should not run');
      },
    });

    await expect(
      coordinator.recordSuccess({
        kind: 'externally_consumed_success',
        spend: makeSpend(),
      } as ExternallyConsumedBudgetFinalizationSpend),
    ).rejects.toThrow(
      '[SigningSessionBudget] externally_consumed_success requires consumed session identities',
    );
  });
});
