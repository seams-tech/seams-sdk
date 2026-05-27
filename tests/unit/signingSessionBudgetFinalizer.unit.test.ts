import { expect, test } from '@playwright/test';
import { toAccountId } from '../../client/src/core/types/accountIds';
import { BudgetCoordinator } from '../../client/src/core/signingEngine/session/budget/BudgetCoordinator';
import type {
  BudgetFinalizationSpend,
  ExternallyConsumedBudgetFinalizationSpend,
  ReservedBudgetFinalizationSpend,
  SigningBudgetFinalizationResult,
  SigningSessionBudget,
  SigningSessionPreparedBudgetIdentity,
  SigningSessionBudgetSuccessInput,
  SigningSessionBudgetTraceEvent,
  UnreservedBudgetFinalizationSpend,
  ZeroBudgetFinalizationSpend,
  ZeroWalletBudgetSpend,
} from '../../client/src/core/signingEngine/session/budget/budget';
import {
  buildSigningBudgetReservationIdentity,
  walletBudgetOwnerId,
} from '../../client/src/core/signingEngine/session/budget/budget';
import { createSigningSessionBudgetFinalizer } from '../../client/src/core/signingEngine/session/budget/budgetFinalizer';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type WalletSigningSpendPlan,
} from '../../client/src/core/signingEngine/session/operationState/types';
import {
  buildNearTransactionSigningLane,
  buildTempoTransactionSigningLane,
  type NearTransactionSigningLane,
} from '../../client/src/core/signingEngine/session/operationState/lanes';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
} from '../../client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';

type ReservedSuccessInput = Extract<SigningSessionBudgetSuccessInput, { kind: 'reserved_success' }>;
type UnreservedSuccessInput = Extract<
  SigningSessionBudgetSuccessInput,
  { kind: 'unreserved_success' }
>;
type ExternallyConsumedSuccessInput = Extract<
  SigningSessionBudgetSuccessInput,
  { kind: 'externally_consumed_success' }
>;

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
  operationFingerprint?: string;
  operationId?: string;
}): WalletSigningSpendPlan {
  const lane = makeLane(args);
  return {
    operationId: SigningSessionIds.signingOperation(args?.operationId || 'operation-1'),
    operationFingerprint: SigningSessionIds.signingOperationFingerprint(
      args?.operationFingerprint || 'fingerprint-1',
    ),
    walletId: lane.accountId,
    walletSigningSessionId: lane.walletSigningSessionId,
    lane,
    thresholdSessionIds: [lane.thresholdSessionId],
    backingMaterialSessionIds: [],
    uses: 1,
    reason: SigningOperationIntent.TransactionSign,
  };
}

function makeTempoSpend(args?: {
  walletSigningSessionId?: string;
  thresholdSessionId?: string;
  operationFingerprint?: string;
  operationId?: string;
}): WalletSigningSpendPlan {
  const walletId = toAccountId('alice.testnet');
  const lane = buildTempoTransactionSigningLane({
    key: buildBaseEvmFamilyEcdsaKeyIdentity({
      walletId,
      rpId: 'localhost',
      ecdsaThresholdKeyId: 'ehss-tempo-budget',
      signingRootId: 'project:dev',
      signingRootVersion: 'default',
      participantIds: [1, 2],
      thresholdOwnerAddress: `0x${'22'.repeat(20)}`,
    }),
    keyHandle: toEvmFamilyEcdsaKeyHandle('ehss-tempo-budget-handle'),
    walletId,
    authMethod: 'passkey',
    storageSource: 'login',
    chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
    walletSigningSessionId: SigningSessionIds.walletSigningSession(
      args?.walletSigningSessionId || 'tempo-wallet-session-1',
    ),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(
      args?.thresholdSessionId || 'tempo-threshold-session-1',
    ),
  });
  return {
    operationId: SigningSessionIds.signingOperation(args?.operationId || 'tempo-operation-1'),
    operationFingerprint: SigningSessionIds.signingOperationFingerprint(
      args?.operationFingerprint || 'tempo-fingerprint-1',
    ),
    walletId,
    walletSigningSessionId: lane.walletSigningSessionId,
    lane,
    ecdsaKey: lane.key,
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

function withSuccessCommand<
  TInput extends
    | ReservedBudgetFinalizationSpend
    | UnreservedBudgetFinalizationSpend
    | ExternallyConsumedBudgetFinalizationSpend,
>(
  input: TInput,
): TInput & { finalizationCommand: SigningSessionBudgetSuccessInput['finalizationCommand'] } {
  const projectionVersion =
    input.kind === 'externally_consumed_success'
      ? 'projection-1'
      : input.expectedBudgetProjectionVersion;
  return {
    ...input,
    finalizationCommand: {
      kind: 'budget_reservation_finalization_command',
      reservation: buildSigningBudgetReservationIdentity({
        spend: input.spend,
        projectionVersion,
      }),
      outcome: 'signed',
    },
  };
}

function makeReservedSuccess(): ReservedSuccessInput {
  return withSuccessCommand({
    kind: 'reserved_success',
    spend: makeSpend(),
    expectedBudgetProjectionVersion: 'projection-1',
    trustedStatusAuth: {
      relayerUrl: 'https://relayer.example.test',
      thresholdSessionId: 'threshold-session-1',
    },
  });
}

function makeUnreservedSuccess(): UnreservedSuccessInput {
  return withSuccessCommand({
    kind: 'unreserved_success',
    spend: makeSpend(),
    expectedBudgetProjectionVersion: 'projection-1',
  });
}

function makeExternallyConsumedSuccess(): ExternallyConsumedSuccessInput {
  const spend = makeSpend();
  return withSuccessCommand({
    kind: 'externally_consumed_success',
    spend,
    alreadyConsumedThresholdSessionIds: [spend.lane.thresholdSessionId],
  });
}

function makeZeroSpend(): ZeroBudgetFinalizationSpend {
  return {
    kind: 'zero_spend',
    operationId: SigningSessionIds.signingOperation('operation-1'),
    operationFingerprint: SigningSessionIds.signingOperationFingerprint('fingerprint-1'),
    lane: makeLane(),
    reason: 'signing_failed',
  };
}

function makeZeroWalletSpend(args?: {
  walletSigningSessionId?: string;
  thresholdSessionId?: string;
}): ZeroWalletBudgetSpend {
  const zeroSpend = {
    ...makeZeroSpend(),
    lane: makeLane(args),
  };
  return {
    ...zeroSpend,
    finalizationCommand: {
      kind: 'budget_reservation_finalization_command',
      reservation: buildSigningBudgetReservationIdentity({
        spend: makeSpend(args),
        projectionVersion: 'projection-1',
      }),
      outcome: 'failed_before_sign',
    },
  };
}

function makeBudgetRecorder(): {
  budget: SigningSessionBudget;
  recordedSuccesses: SigningSessionBudgetSuccessInput[];
  recordedZeroSpends: ZeroWalletBudgetSpend[];
} {
  const recordedSuccesses: SigningSessionBudgetSuccessInput[] = [];
  const recordedZeroSpends: ZeroWalletBudgetSpend[] = [];
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
        return makeFinalizedResult(input);
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

function makeFinalizedResult(
  input: SigningSessionBudgetSuccessInput,
): SigningBudgetFinalizationResult {
  return {
    kind: 'finalized',
    reservation: buildSigningBudgetReservationIdentity({
      spend: input.spend,
      projectionVersion:
        input.kind === 'externally_consumed_success'
          ? 'projection-1'
          : input.expectedBudgetProjectionVersion,
    }),
    remainingUses: 1,
    projectionVersion: 'projection-1',
  };
}

test.describe('signing session budget finalizer', () => {
  test('forwards reserved_success to the budget recorder', async () => {
    const { budget, recordedSuccesses } = makeBudgetRecorder();
    const finalization = makeReservedSuccess();
    const finalizer = createSigningSessionBudgetFinalizer({
      budgetMode: 'with_budget',
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
      budgetMode: 'with_budget',
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
      budgetMode: 'with_budget',
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
      budgetMode: 'with_budget',
      signingSessionBudget: budget,
      budgetIdentity: makeBudgetIdentity(makeSpend()),
      finalization,
    });
    const error = new Error('request cancelled by user');

    finalizer.recordZeroSpend(error);

    expect(recordedZeroSpends).toEqual([
      expect.objectContaining({
        ...finalization,
        reason: 'confirmation_cancelled',
        error,
      }),
    ]);
    expect(recordedZeroSpends[0].finalizationCommand).toMatchObject({
      kind: 'budget_reservation_finalization_command',
      outcome: 'failed_before_sign',
      reservation: {
        operationId: finalization.operationId,
        operationFingerprint: finalization.operationFingerprint,
      },
    });
  });
});

test.describe('budget coordinator reserved success handling', () => {
  test('keeps concurrent NEAR and Tempo reservations separate by operation and lane identity', async () => {
    const readStatusCalls: string[] = [];
    const consumeCalls: string[] = [];
    const coordinator = new BudgetCoordinator({
      async readStatus({ walletSigningSessionId }) {
        const sessionId = String(walletSigningSessionId);
        readStatusCalls.push(sessionId);
        return {
          sessionId,
          status: 'active',
          projectionVersion: 'projection-1',
          remainingUses: 2,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      async consumeUse({ walletSigningSessionId }) {
        const sessionId = String(walletSigningSessionId);
        consumeCalls.push(sessionId);
        return {
          sessionId,
          status: 'active',
          projectionVersion: 'projection-1',
          remainingUses: 1,
          expiresAtMs: 1_900_000_000_000,
        };
      },
    });
    const nearSpend = makeSpend({
      operationId: 'near-operation-1',
      operationFingerprint: 'near-fingerprint-1',
      walletSigningSessionId: 'near-wallet-session-1',
      thresholdSessionId: 'near-threshold-session-1',
    });
    const tempoSpend = makeTempoSpend({
      operationId: 'tempo-operation-1',
      operationFingerprint: 'tempo-fingerprint-1',
      walletSigningSessionId: 'tempo-wallet-session-1',
      thresholdSessionId: 'tempo-threshold-session-1',
    });

    const [nearReservation, tempoReservation] = await Promise.all([
      coordinator.reserve({
        spend: nearSpend,
        expectedBudgetProjectionVersion: 'projection-1',
      }),
      coordinator.reserve({
        spend: tempoSpend,
        expectedBudgetProjectionVersion: 'projection-1',
      }),
    ]);

    expect(nearReservation).toMatchObject({
      kind: 'reserved',
      operationId: nearSpend.operationId,
    });
    expect(tempoReservation).toMatchObject({
      kind: 'reserved',
      operationId: tempoSpend.operationId,
    });
    await Promise.all([
      coordinator.recordSuccess(
        withSuccessCommand({
          kind: 'reserved_success',
          spend: nearSpend,
          expectedBudgetProjectionVersion: 'projection-1',
        }),
      ),
      coordinator.recordSuccess(
        withSuccessCommand({
          kind: 'reserved_success',
          spend: tempoSpend,
          expectedBudgetProjectionVersion: 'projection-1',
        }),
      ),
    ]);

    expect(readStatusCalls.sort()).toEqual(['near-wallet-session-1', 'tempo-wallet-session-1']);
    expect(consumeCalls.sort()).toEqual(['near-wallet-session-1', 'tempo-wallet-session-1']);
  });

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
            walletId: toAccountId(String(walletBudgetOwnerId(args.owner))),
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
    const result = await coordinator.recordSuccess(finalization);

    expect(consumeUseCalls).toHaveLength(1);
    expect(result.kind).toBe('finalized');
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

  test('returns identity mismatch when reserved_success changes the reserved spend identity', async () => {
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

    const result = await coordinator.recordSuccess({
      ...reserved,
      spend: makeSpend({ walletSigningSessionId: 'wallet-session-2' }),
    });

    expect(result.kind).toBe('reservation_identity_mismatch');
  });

  test('returns identity mismatch when success finalization command changes reservation identity', async () => {
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

    const result = await coordinator.recordSuccess({
      ...reserved,
      finalizationCommand: {
        ...reserved.finalizationCommand,
        reservation: buildSigningBudgetReservationIdentity({
          spend: makeSpend({ thresholdSessionId: 'threshold-session-2' }),
          projectionVersion: reserved.expectedBudgetProjectionVersion,
        }),
      },
    });

    expect(result.kind).toBe('reservation_identity_mismatch');
  });

  test('returns identity mismatch when reserved_success reuses an operation id with a different fingerprint', async () => {
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

    const result = await coordinator.recordSuccess({
      ...reserved,
      spend: {
        ...reserved.spend,
        operationFingerprint: SigningSessionIds.signingOperationFingerprint('fingerprint-2'),
      },
    });

    expect(result.kind).toBe('reservation_identity_mismatch');
  });

  test('dedupes repeated reserved_success only for the same canonical reservation identity', async () => {
    let consumeUseCalls = 0;
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
        consumeUseCalls += 1;
        return {
          sessionId: args.walletSigningSessionId,
          status: 'active',
          projectionVersion: 'projection-2',
          remainingUses: 2,
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

    const first = await coordinator.recordSuccess(reserved);
    const second = await coordinator.recordSuccess(reserved);

    expect(consumeUseCalls).toBe(1);
    expect(first.kind).toBe('finalized');
    expect(second.kind).toBe('already_finalized');
  });

  test('returns identity mismatch when reserve reuses an operation id with a different in-flight fingerprint', async () => {
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
    const first = await coordinator.reserve({
      spend: reserved.spend,
      expectedBudgetProjectionVersion: reserved.expectedBudgetProjectionVersion,
      trustedStatusAuth: reserved.trustedStatusAuth,
    });

    const second = await coordinator.reserve({
      spend: makeSpend({ operationFingerprint: 'fingerprint-2' }),
      expectedBudgetProjectionVersion: reserved.expectedBudgetProjectionVersion,
      trustedStatusAuth: reserved.trustedStatusAuth,
    });

    expect(first?.kind).toBe('reserved');
    expect(second?.kind).toBe('reservation_identity_mismatch');
  });

  test('returns identity mismatch when reserve reuses an operation id after successful spend with a different fingerprint', async () => {
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
        return {
          sessionId: args.walletSigningSessionId,
          status: 'active',
          projectionVersion: 'projection-2',
          remainingUses: 2,
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
    await coordinator.recordSuccess(reserved);

    const result = await coordinator.reserve({
      spend: makeSpend({ operationFingerprint: 'fingerprint-2' }),
      expectedBudgetProjectionVersion: reserved.expectedBudgetProjectionVersion,
      trustedStatusAuth: reserved.trustedStatusAuth,
    });

    expect(result?.kind).toBe('reservation_identity_mismatch');
  });

  test('dedupes repeated zero_spend finalization for the same canonical reservation identity', async () => {
    const events: SigningSessionBudgetTraceEvent['event'][] = [];
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
      onTrace(event) {
        events.push(event.event);
      },
    });
    const reserved = makeReservedSuccess();
    await coordinator.reserve({
      spend: reserved.spend,
      expectedBudgetProjectionVersion: reserved.expectedBudgetProjectionVersion,
      trustedStatusAuth: reserved.trustedStatusAuth,
    });
    const zeroSpend = makeZeroWalletSpend();

    coordinator.recordZeroSpend(zeroSpend);
    coordinator.recordZeroSpend(zeroSpend);

    expect(events.filter((event) => event === 'wallet_signing_budget_reservation_released'))
      .toHaveLength(1);
    expect(events.filter((event) => event === 'wallet_signing_budget_zero_spend_recorded'))
      .toHaveLength(1);
  });

  test('rejects zero_spend when the finalization command changes reservation identity', async () => {
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

    expect(() =>
      coordinator.recordZeroSpend(makeZeroWalletSpend({ thresholdSessionId: 'threshold-session-2' })),
    ).toThrow('[SigningSessionBudget] zero_spend reservation identity does not match reservation');
  });

  test('returns identity mismatch when repeated reserved_success changes identity', async () => {
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
        return {
          sessionId: args.walletSigningSessionId,
          status: 'active',
          projectionVersion: 'projection-2',
          remainingUses: 2,
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
    await coordinator.recordSuccess(reserved);

    const result = await coordinator.recordSuccess({
      ...reserved,
      spend: makeSpend({ thresholdSessionId: 'threshold-session-2' }),
    });

    expect(result.kind).toBe('reservation_identity_mismatch');
  });

  test('returns identity mismatch when repeated reserved_success reuses operation id with a different fingerprint', async () => {
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
        return {
          sessionId: args.walletSigningSessionId,
          status: 'active',
          projectionVersion: 'projection-2',
          remainingUses: 2,
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
    await coordinator.recordSuccess(reserved);

    const result = await coordinator.recordSuccess({
      ...reserved,
      spend: {
        ...reserved.spend,
        operationFingerprint: SigningSessionIds.signingOperationFingerprint('fingerprint-2'),
      },
    });

    expect(result.kind).toBe('reservation_identity_mismatch');
  });

  test('returns identity mismatch when unreserved_success finalizes a reserved operation', async () => {
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

    const result = await coordinator.recordSuccess(unreserved);

    expect(result.kind).toBe('reservation_identity_mismatch');
  });

  test('returns missing_reservation when reserved_success has no reservation', async () => {
    const coordinator = new BudgetCoordinator({
      async readStatus() {
        throw new Error('readStatus should not run');
      },
      async consumeUse() {
        throw new Error('consumeUse should not run');
      },
    });

    const result = await coordinator.recordSuccess(makeReservedSuccess());

    expect(result.kind).toBe('missing_reservation');
  });

  test('returns projection_mismatch instead of throwing for stale prepared projection', async () => {
    const coordinator = new BudgetCoordinator({
      async readStatus() {
        return {
          sessionId: 'wallet-session-1',
          status: 'active',
          projectionVersion: 'projection-2',
          remainingUses: 2,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      async consumeUse() {
        throw new Error('consumeUse should not run');
      },
    });

    const result = await coordinator.recordSuccess(makeUnreservedSuccess());

    expect(result).toMatchObject({
      kind: 'projection_mismatch',
      expectedProjectionVersion: 'projection-1',
      actualProjectionVersion: 'projection-2',
    });
  });

  test('returns budget_status_unavailable when spend returns budget_unknown', async () => {
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
        return {
          sessionId: args.walletSigningSessionId,
          status: 'budget_unknown',
          statusCode: 'status_unavailable',
        };
      },
    });

    const result = await coordinator.recordSuccess(makeUnreservedSuccess());

    expect(result).toMatchObject({
      kind: 'budget_status_unavailable',
      status: 'budget_unknown',
    });
  });

  test('emits finalization result trace events for handled result branches', async () => {
    const events: SigningSessionBudgetTraceEvent['event'][] = [];
    const makeCoordinator = (args: {
      readProjection?: string;
      consumeStatus?: 'active' | 'budget_unknown';
    }) =>
      new BudgetCoordinator({
        async readStatus() {
          return {
            sessionId: 'wallet-session-1',
            status: 'active',
            projectionVersion: args.readProjection || 'projection-1',
            remainingUses: 2,
            expiresAtMs: 1_900_000_000_000,
          };
        },
        async consumeUse(consumeArgs) {
          if (args.consumeStatus === 'budget_unknown') {
            return {
              sessionId: consumeArgs.walletSigningSessionId,
              status: 'budget_unknown',
              statusCode: 'status_unavailable',
            };
          }
          return {
            sessionId: consumeArgs.walletSigningSessionId,
            status: 'active',
            projectionVersion: 'projection-2',
            remainingUses: 1,
            expiresAtMs: 1_900_000_000_000,
          };
        },
        onTrace(event) {
          events.push(event.event);
        },
      });

    const finalizedCoordinator = makeCoordinator({});
    const reserved = makeReservedSuccess();
    await finalizedCoordinator.reserve({
      spend: reserved.spend,
      expectedBudgetProjectionVersion: reserved.expectedBudgetProjectionVersion,
      trustedStatusAuth: reserved.trustedStatusAuth,
    });
    await finalizedCoordinator.recordSuccess(reserved);
    await finalizedCoordinator.recordSuccess(reserved);

    await makeCoordinator({}).recordSuccess(makeReservedSuccess());
    const mismatchCoordinator = makeCoordinator({});
    await mismatchCoordinator.reserve({
      spend: reserved.spend,
      expectedBudgetProjectionVersion: reserved.expectedBudgetProjectionVersion,
      trustedStatusAuth: reserved.trustedStatusAuth,
    });
    await mismatchCoordinator.recordSuccess({
      ...reserved,
      spend: makeSpend({ thresholdSessionId: 'threshold-session-mismatch' }),
    });
    await makeCoordinator({ readProjection: 'projection-2' }).recordSuccess(
      makeUnreservedSuccess(),
    );
    await makeCoordinator({ consumeStatus: 'budget_unknown' }).recordSuccess(
      makeUnreservedSuccess(),
    );

    expect(events).toEqual(
      expect.arrayContaining([
        'wallet_signing_budget_finalization_finalized',
        'wallet_signing_budget_finalization_already_finalized',
        'wallet_signing_budget_finalization_missing_reservation',
        'wallet_signing_budget_finalization_identity_mismatch',
        'wallet_signing_budget_finalization_projection_mismatch',
        'wallet_signing_budget_finalization_status_unavailable',
      ]),
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
        finalizationCommand: {
          kind: 'budget_reservation_finalization_command',
          reservation: buildSigningBudgetReservationIdentity({
            spend: makeSpend(),
            projectionVersion: 'projection-1',
          }),
          outcome: 'signed',
        },
      } as SigningSessionBudgetSuccessInput),
    ).rejects.toThrow(
      '[SigningSessionBudget] externally_consumed_success requires consumed session identities',
    );
  });
});
