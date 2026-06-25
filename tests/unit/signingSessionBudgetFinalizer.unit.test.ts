import { expect, test } from '@playwright/test';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import { BudgetCoordinator } from '../../packages/sdk-web/src/core/signingEngine/session/budget/BudgetCoordinator';
import type {
  BudgetFinalizationSpend,
  ExternallyConsumedBudgetFinalizationSpend,
  ReservedBudgetFinalizationSpend,
  SigningBudgetFinalizationResult,
  SigningSessionBudget,
  SigningSessionPreparedBudgetIdentity,
  SigningSessionBudgetSuccessInput,
  SigningSessionBudgetStatusSync,
  SigningSessionBudgetTraceEvent,
  UnreservedBudgetFinalizationSpend,
  ZeroBudgetFinalizationSpend,
  ZeroWalletBudgetSpend,
} from '../../packages/sdk-web/src/core/signingEngine/session/budget/budget';
import {
  buildSigningSessionBudgetStatusCheckForSpend,
  buildSigningBudgetReservationIdentity,
  walletBudgetOwnerId,
} from '../../packages/sdk-web/src/core/signingEngine/session/budget/budget';
import { createSigningSessionBudgetFinalizer } from '../../packages/sdk-web/src/core/signingEngine/session/budget/budgetFinalizer';
import {
  createNonceCoordinator,
  NonceCoordinatorTraceEventName,
  type EvmNonceLane,
  type NonceCoordinatorTraceEvent,
} from '../../packages/sdk-web/src/core/signingEngine/nonce/NonceCoordinator';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type WalletSigningSpendPlan,
} from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import {
  buildNearTransactionSigningLane,
  buildTempoTransactionSigningLane,
  type NearTransactionSigningLane,
} from '../../packages/sdk-web/src/core/signingEngine/session/operationState/lanes';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toRpId,
  toEvmFamilyEcdsaKeyHandle,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { toWalletId } from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import { nearEd25519SigningKeyIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';

type ReservedSuccessInput = Extract<SigningSessionBudgetSuccessInput, { kind: 'reserved_success' }>;
type UnreservedSuccessInput = Extract<
  SigningSessionBudgetSuccessInput,
  { kind: 'unreserved_success' }
>;
type ExternallyConsumedSuccessInput = Extract<
  SigningSessionBudgetSuccessInput,
  { kind: 'externally_consumed_success' }
>;

const NEAR_WALLET_ID = toWalletId('frost-vermillion-k7p9m2');
const NEAR_ACCOUNT_ID = toAccountId('alice.testnet');
const ED25519_KEY_SCOPE_ID = nearEd25519SigningKeyIdFromString('scope-frost-vermillion-k7p9m2');
const PASSKEY_AUTH = {
  kind: 'passkey' as const,
  rpId: toRpId('localhost'),
  credentialIdB64u: 'credential-budget-finalizer',
};

function makeLane(args?: {
  signingGrantId?: string;
  thresholdSessionId?: string;
}): NearTransactionSigningLane {
  return buildNearTransactionSigningLane({
    walletId: NEAR_WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
    signerSlot: 1,
    auth: PASSKEY_AUTH,
    signingGrantId: SigningSessionIds.signingGrant(
      args?.signingGrantId || 'wallet-session-1',
    ),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
      args?.thresholdSessionId || 'threshold-session-1',
    ),
    storageSource: 'login',
  });
}

function makeSpend(args?: {
  signingGrantId?: string;
  thresholdSessionId?: string;
  operationFingerprint?: string;
  operationId?: string;
  uses?: number;
}): WalletSigningSpendPlan {
  const lane = makeLane(args);
  return {
    operationId: SigningSessionIds.signingOperation(args?.operationId || 'operation-1'),
    operationFingerprint: SigningSessionIds.signingOperationFingerprint(
      args?.operationFingerprint || 'fingerprint-1',
    ),
    lane,
    backingMaterialSessionIds: [],
    uses: args?.uses ?? 1,
    reason: SigningOperationIntent.TransactionSign,
  };
}

function makeTempoSpend(args?: {
  signingGrantId?: string;
  thresholdSessionId?: string;
  operationFingerprint?: string;
  operationId?: string;
}): WalletSigningSpendPlan {
  const walletId = toWalletId('alice.testnet');
  const lane = buildTempoTransactionSigningLane({
    key: buildBaseEvmFamilyEcdsaKeyIdentity({
      walletId,
      walletKeyId: 'wallet-key-tempo-budget',
      ecdsaThresholdKeyId: 'ehss-tempo-budget',
      signingRootId: 'project:dev',
      signingRootVersion: 'default',
      participantIds: [1, 2],
      thresholdOwnerAddress: `0x${'22'.repeat(20)}`,
    }),
    keyHandle: toEvmFamilyEcdsaKeyHandle('ehss-tempo-budget-handle'),
    walletId,
    auth: PASSKEY_AUTH,
    storageSource: 'login',
    chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
    signingGrantId: SigningSessionIds.signingGrant(
      args?.signingGrantId || 'tempo-wallet-session-1',
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
    lane,
    backingMaterialSessionIds: [],
    uses: 1,
    reason: SigningOperationIntent.TransactionSign,
  };
}

function makeTempoNonceLane(spend: WalletSigningSpendPlan): EvmNonceLane {
  if (spend.lane.curve !== 'ecdsa') {
    throw new Error('expected ECDSA spend');
  }
  const signer = ecdsaSignerFromSpend(spend);
  return {
    family: 'evm',
    chainTarget: signer.chainTarget,
    subjectId: toWalletId(signer.walletId),
    sender: `0x${'33'.repeat(20)}`,
    nonceKey: 1n,
  };
}

function ecdsaSignerFromSpend(spend: WalletSigningSpendPlan) {
  const signer = spend.lane.identity.signer;
  if (signer.kind !== 'evm_family_ecdsa_signer') {
    throw new Error('expected ECDSA spend signer');
  }
  return signer;
}

function walletIdFromSpend(spend: WalletSigningSpendPlan): string {
  const signer = spend.lane.identity.signer;
  switch (signer.kind) {
    case 'evm_family_ecdsa_signer':
      return String(signer.walletId);
    case 'near_ed25519_signer':
      return String(signer.account.wallet.walletId);
  }
}

function makeBudgetIdentity(spend: WalletSigningSpendPlan): SigningSessionPreparedBudgetIdentity {
  return {
    signingGrantId: spend.lane.signingGrantId,
    projectionVersion: 'projection-1',
    status: {
      sessionId: String(spend.lane.signingGrantId),
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
      walletSessionJwt: 'wallet-session-jwt',
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
  signingGrantId?: string;
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
  test('records a broadcast-failed signed operation once and releases the nonce lane', async () => {
    const statusSyncCalls: Parameters<SigningSessionBudgetStatusSync>[0][] = [];
    const budgetEvents: SigningSessionBudgetTraceEvent[] = [];
    const nonceEvents: NonceCoordinatorTraceEvent[] = [];
    const budget = new BudgetCoordinator({
      async readStatus() {
        return {
          sessionId: 'tempo-wallet-session-broadcast-failed',
          status: 'active',
          projectionVersion: 'projection-1',
          remainingUses: 1,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      async syncSuccessfulSpendStatus(args) {
        statusSyncCalls.push(args);
        return {
          sessionId: args.signingGrantId,
          status: 'exhausted',
          projectionVersion: 'projection-2',
          remainingUses: 0,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      onTrace(event) {
        budgetEvents.push(event);
      },
    });
    const nonceCoordinator = createNonceCoordinator({
      evmNonceBackend: {
        fetchChainNonce: async () => 7n,
      },
      onTrace(event) {
        nonceEvents.push(event);
      },
    });
    const spend = makeTempoSpend({
      operationId: 'tempo-broadcast-failed-operation',
      operationFingerprint: 'tempo-broadcast-failed-fingerprint',
      signingGrantId: 'tempo-wallet-session-broadcast-failed',
      thresholdSessionId: 'tempo-threshold-session-broadcast-failed',
    });
    if (spend.lane.curve !== 'ecdsa') {
      throw new Error('expected ECDSA Tempo spend');
    }
    const reserved = withSuccessCommand({
      kind: 'reserved_success',
      spend,
      expectedBudgetProjectionVersion: 'projection-1',
    });
    const broadcastFailedFinalization = {
      ...reserved,
      finalizationCommand: {
        ...reserved.finalizationCommand,
        outcome: 'broadcast_failed' as const,
      },
    };

    await budget.reserve({
      spend,
      expectedBudgetProjectionVersion: reserved.expectedBudgetProjectionVersion,
    });
    const nonceLease = await nonceCoordinator.reserve({
      lane: makeTempoNonceLane(spend),
      operation: {
        operationId: spend.operationId,
        operationFingerprint: spend.operationFingerprint!,
        intent: SigningOperationIntent.TransactionSign,
        accountId: walletIdFromSpend(spend),
      },
    });
    await nonceCoordinator.markSigned({
      leaseId: nonceLease.leaseId,
      operationId: spend.operationId,
      operationFingerprint: spend.operationFingerprint!,
      signedTxHash: `0x${'44'.repeat(32)}`,
    });
    await nonceCoordinator.markBroadcastRejected({
      leaseId: nonceLease.leaseId,
      operationId: spend.operationId,
      operationFingerprint: spend.operationFingerprint!,
      error: new Error('broadcast failed after signature'),
    });

    const first = await budget.recordSuccess(broadcastFailedFinalization);
    const second = await budget.recordSuccess(broadcastFailedFinalization);
    const reusedNonceLease = await nonceCoordinator.reserve({
      lane: makeTempoNonceLane(spend),
      operation: {
        operationId: SigningSessionIds.signingOperation('tempo-broadcast-failed-retry'),
        operationFingerprint: SigningSessionIds.signingOperationFingerprint(
          'tempo-broadcast-failed-retry-fingerprint',
        ),
        intent: SigningOperationIntent.TransactionSign,
        accountId: walletIdFromSpend(spend),
      },
    });

    expect(statusSyncCalls).toHaveLength(1);
    expect(statusSyncCalls[0]).toMatchObject({
      signingGrantId: 'tempo-wallet-session-broadcast-failed',
      uses: 1,
      reason: SigningOperationIntent.TransactionSign,
      budgetStatusCheck: {
        kind: 'ecdsa_lane_budget_status_check',
        signingGrantId: 'tempo-wallet-session-broadcast-failed',
        thresholdSessionId: 'tempo-threshold-session-broadcast-failed',
        chainTarget: {
          kind: 'tempo',
          chainId: 42431,
          networkSlug: 'tempo-moderato',
        },
        key: ecdsaSignerFromSpend(spend).key,
      },
    });
    expect(broadcastFailedFinalization.finalizationCommand.outcome).toBe('broadcast_failed');
    expect(first.kind).toBe('finalized');
    expect(second.kind).toBe('already_finalized');
    expect(reusedNonceLease.nonce).toBe(nonceLease.nonce);
    expect(
      budgetEvents.filter((event) => event.event === 'wallet_signing_budget_spend_succeeded'),
    ).toHaveLength(1);
    expect(
      nonceEvents.filter((event) => event.event === NonceCoordinatorTraceEventName.LeaseSigned),
    ).toHaveLength(1);
    expect(
      nonceEvents.filter(
        (event) => event.event === NonceCoordinatorTraceEventName.LeaseBroadcastRejected,
      ),
    ).toHaveLength(1);
  });

  test('exhausts local wallet-session availability after two in-flight reservations', async () => {
    const coordinator = new BudgetCoordinator({
      async readStatus() {
        return {
          sessionId: 'tempo-wallet-session-inflight',
          status: 'active',
          projectionVersion: 'projection-1',
          remainingUses: 2,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      async syncSuccessfulSpendStatus() {
        throw new Error('status sync should not run');
      },
    });
    const firstSpend = makeTempoSpend({
      operationId: 'tempo-inflight-1',
      operationFingerprint: 'tempo-inflight-fingerprint-1',
      signingGrantId: 'tempo-wallet-session-inflight',
      thresholdSessionId: 'tempo-threshold-session-inflight',
    });
    const secondSpend = makeTempoSpend({
      operationId: 'tempo-inflight-2',
      operationFingerprint: 'tempo-inflight-fingerprint-2',
      signingGrantId: 'tempo-wallet-session-inflight',
      thresholdSessionId: 'tempo-threshold-session-inflight',
    });
    const thirdSpend = makeTempoSpend({
      operationId: 'tempo-inflight-3',
      operationFingerprint: 'tempo-inflight-fingerprint-3',
      signingGrantId: 'tempo-wallet-session-inflight',
      thresholdSessionId: 'tempo-threshold-session-inflight',
    });

    await expect(
      coordinator.reserve({
        spend: firstSpend,
        expectedBudgetProjectionVersion: 'projection-1',
      }),
    ).resolves.toMatchObject({ kind: 'reserved', operationId: firstSpend.operationId });
    await expect(
      coordinator.reserve({
        spend: secondSpend,
        expectedBudgetProjectionVersion: 'projection-1',
      }),
    ).resolves.toMatchObject({ kind: 'reserved', operationId: secondSpend.operationId });
    await expect(
      coordinator.reserve({
        spend: thirdSpend,
        expectedBudgetProjectionVersion: 'projection-1',
      }),
    ).rejects.toThrow('[SigningSessionBudget] signing grant budget is reserved by in-flight operations');
  });

  test('rejects admission when server status reports all uses reserved in flight', async () => {
    const coordinator = new BudgetCoordinator({
      async readStatus() {
        return {
          sessionId: 'server-inflight-wallet-session',
          status: 'active',
          projectionVersion: 'projection-1',
          remainingUses: 3,
          availableUses: 0,
          inFlightReservedUses: 3,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      async syncSuccessfulSpendStatus() {
        throw new Error('status sync should not run');
      },
    });

    await expect(
      coordinator.reserve({
        spend: makeSpend({
          operationId: 'server-inflight-operation',
          operationFingerprint: 'server-inflight-fingerprint',
          signingGrantId: 'server-inflight-wallet-session',
          thresholdSessionId: 'server-inflight-threshold-session',
        }),
        expectedBudgetProjectionVersion: 'projection-1',
      }),
    ).rejects.toThrow('[SigningSessionBudget] signing grant budget is reserved by in-flight operations');
  });

  test('emits one budget reservation and one nonce lease for a transaction operation', async () => {
    const budgetEvents: SigningSessionBudgetTraceEvent[] = [];
    const nonceEvents: NonceCoordinatorTraceEvent[] = [];
    const budget = new BudgetCoordinator({
      async readStatus() {
        return {
          sessionId: 'tempo-wallet-session-trace',
          status: 'active',
          projectionVersion: 'projection-1',
          remainingUses: 1,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      async syncSuccessfulSpendStatus() {
        throw new Error('status sync should not run');
      },
      onTrace(event) {
        budgetEvents.push(event);
      },
    });
    const nonceCoordinator = createNonceCoordinator({
      evmNonceBackend: {
        fetchChainNonce: async () => 12n,
      },
      onTrace(event) {
        nonceEvents.push(event);
      },
    });
    const spend = makeTempoSpend({
      operationId: 'tempo-trace-operation',
      operationFingerprint: 'tempo-trace-fingerprint',
      signingGrantId: 'tempo-wallet-session-trace',
      thresholdSessionId: 'tempo-threshold-session-trace',
    });

    await budget.reserve({
      spend,
      expectedBudgetProjectionVersion: 'projection-1',
    });
    const lease = await nonceCoordinator.reserve({
      lane: makeTempoNonceLane(spend),
      operation: {
        operationId: spend.operationId,
        operationFingerprint: spend.operationFingerprint!,
        intent: SigningOperationIntent.TransactionSign,
        accountId: walletIdFromSpend(spend),
      },
    });

    const budgetReservations = budgetEvents.filter(
      (event) => event.event === 'wallet_signing_budget_reservation_succeeded',
    );
    const nonceReservations = nonceEvents.filter(
      (event) => event.event === NonceCoordinatorTraceEventName.LeaseReserved,
    );
    expect(budgetReservations).toHaveLength(1);
    expect(nonceReservations).toHaveLength(1);
    expect(budgetReservations[0]).toMatchObject({
      operationId: spend.operationId,
    });
    expect(nonceReservations[0]?.lease).toMatchObject({
      leaseId: lease.leaseId,
      operationId: spend.operationId,
      operationFingerprint: spend.operationFingerprint,
    });
  });

  test('keeps concurrent NEAR and Tempo reservations separate by operation and lane identity', async () => {
    const readStatusCalls: string[] = [];
    const statusSyncCalls: string[] = [];
    const coordinator = new BudgetCoordinator({
      async readStatus({ signingGrantId }) {
        const sessionId = String(signingGrantId);
        readStatusCalls.push(sessionId);
        return {
          sessionId,
          status: 'active',
          projectionVersion: 'projection-1',
          remainingUses: 2,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      async syncSuccessfulSpendStatus({ signingGrantId }) {
        const sessionId = String(signingGrantId);
        statusSyncCalls.push(sessionId);
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
      signingGrantId: 'near-wallet-session-1',
      thresholdSessionId: 'near-threshold-session-1',
    });
    const tempoSpend = makeTempoSpend({
      operationId: 'tempo-operation-1',
      operationFingerprint: 'tempo-fingerprint-1',
      signingGrantId: 'tempo-wallet-session-1',
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
    expect(statusSyncCalls.sort()).toEqual(['near-wallet-session-1', 'tempo-wallet-session-1']);
  });

  test('accepts reserved_success after an explicit reservation', async () => {
    const statusSyncCalls: BudgetFinalizationSpend[] = [];
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
      async syncSuccessfulSpendStatus(args) {
        statusSyncCalls.push({
          kind: 'externally_consumed_success',
          spend: {
            operationId: SigningSessionIds.signingOperation('observation-only'),
            lane: makeLane(),
            backingMaterialSessionIds: [],
            uses: 1,
            reason: SigningOperationIntent.TransactionSign,
          },
          alreadyConsumedThresholdSessionIds: [
            SigningSessionIds.thresholdEd25519Session('threshold-session-1'),
          ],
        });
        return {
          sessionId: args.signingGrantId,
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

    expect(statusSyncCalls).toHaveLength(1);
    expect(result.kind).toBe('finalized');
  });

  test('projects completed unreserved spends into later wallet-session admission', async () => {
    const coordinator = new BudgetCoordinator({
      async readStatus(args) {
        return {
          sessionId: args.signingGrantId,
          status: 'active',
          projectionVersion: 'projection-1',
          remainingUses: 3,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      async syncSuccessfulSpendStatus(args) {
        return {
          sessionId: args.signingGrantId,
          status: 'active',
          projectionVersion: 'projection-1',
          remainingUses: 2,
          expiresAtMs: 1_900_000_000_000,
        };
      },
    });
    const firstSpend = makeSpend({
      operationId: 'completed-unreserved-1',
      operationFingerprint: 'completed-unreserved-fingerprint-1',
      signingGrantId: 'completed-unreserved-wallet-session',
      thresholdSessionId: 'completed-unreserved-threshold-session-1',
    });
    await coordinator.recordSuccess(
      withSuccessCommand({
        kind: 'unreserved_success',
        spend: firstSpend,
        expectedBudgetProjectionVersion: 'projection-1',
      }),
    );

    const status = await coordinator.getAvailableStatus(
      buildSigningSessionBudgetStatusCheckForSpend({
        spend: makeSpend({
          operationId: 'completed-unreserved-2',
          operationFingerprint: 'completed-unreserved-fingerprint-2',
          signingGrantId: 'completed-unreserved-wallet-session',
          thresholdSessionId: 'completed-unreserved-threshold-session-2',
        }),
      }),
    );

    expect(status).toMatchObject({
      sessionId: 'completed-unreserved-wallet-session',
      status: 'active',
      remainingUses: 2,
      availableUses: 2,
      projectionVersion: 'projection-1',
    });
  });

  test('does not subtract local completed spends after server projection advances', async () => {
    const coordinator = new BudgetCoordinator({
      async readStatus(args) {
        return {
          sessionId: args.signingGrantId,
          status: 'active',
          projectionVersion: 'projection-2',
          remainingUses: 2,
          availableUses: 2,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      async syncSuccessfulSpendStatus(args) {
        return {
          sessionId: args.signingGrantId,
          status: 'active',
          projectionVersion: 'projection-2',
          remainingUses: 2,
          availableUses: 2,
          expiresAtMs: 1_900_000_000_000,
        };
      },
    });
    const firstSpend = makeSpend({
      operationId: 'server-projected-completed-1',
      operationFingerprint: 'server-projected-completed-fingerprint-1',
      signingGrantId: 'server-projected-wallet-session',
      thresholdSessionId: 'server-projected-threshold-session-1',
    });

    await coordinator.recordSuccess(
      withSuccessCommand({
        kind: 'unreserved_success',
        spend: firstSpend,
        expectedBudgetProjectionVersion: 'projection-1',
      }),
    );
    const status = await coordinator.getAvailableStatus(
      buildSigningSessionBudgetStatusCheckForSpend({
        spend: makeSpend({
          operationId: 'server-projected-completed-2',
          operationFingerprint: 'server-projected-completed-fingerprint-2',
          signingGrantId: 'server-projected-wallet-session',
          thresholdSessionId: 'server-projected-threshold-session-2',
        }),
      }),
    );

    expect(status).toMatchObject({
      sessionId: 'server-projected-wallet-session',
      status: 'active',
      remainingUses: 2,
      availableUses: 2,
      projectionVersion: 'projection-2',
    });
  });

  test('rejects admission after completed unreserved spends exhaust the projection', async () => {
    const coordinator = new BudgetCoordinator({
      async readStatus(args) {
        return {
          sessionId: args.signingGrantId,
          status: 'active',
          projectionVersion: 'projection-1',
          remainingUses: 3,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      async syncSuccessfulSpendStatus(args) {
        return {
          sessionId: args.signingGrantId,
          status: 'active',
          projectionVersion: 'projection-1',
          remainingUses: 3,
          expiresAtMs: 1_900_000_000_000,
        };
      },
    });
    for (let index = 1; index <= 3; index += 1) {
      const spend = makeSpend({
        operationId: `completed-exhaustion-${index}`,
        operationFingerprint: `completed-exhaustion-fingerprint-${index}`,
        signingGrantId: 'completed-exhaustion-wallet-session',
        thresholdSessionId: `completed-exhaustion-threshold-session-${index}`,
      });
      await coordinator.recordSuccess(
        withSuccessCommand({
          kind: 'unreserved_success',
          spend,
          expectedBudgetProjectionVersion: 'projection-1',
        }),
      );
    }

    await expect(
      coordinator.reserve({
        spend: makeSpend({
          operationId: 'completed-exhaustion-4',
          operationFingerprint: 'completed-exhaustion-fingerprint-4',
          signingGrantId: 'completed-exhaustion-wallet-session',
          thresholdSessionId: 'completed-exhaustion-threshold-session-4',
        }),
        expectedBudgetProjectionVersion: 'projection-1',
      }),
    ).rejects.toThrow('[SigningSessionBudget] signing grant budget is exhausted');
  });

  test('rejects stale local admission when trusted server status is exhausted', async () => {
    const coordinator = new BudgetCoordinator({
      async readStatus(args) {
        return {
          sessionId: args.signingGrantId,
          status: 'active',
          projectionVersion: 'server-exhausted-projection',
          remainingUses: 0,
          availableUses: 0,
          expiresAtMs: 1_900_000_000_000,
        };
      },
      async syncSuccessfulSpendStatus() {
        throw new Error('status sync should not run');
      },
    });

    await expect(
      coordinator.reserve({
        spend: makeSpend({
          operationId: 'server-exhausted-operation',
          operationFingerprint: 'server-exhausted-fingerprint',
          signingGrantId: 'server-exhausted-wallet-session',
          thresholdSessionId: 'server-exhausted-threshold-session',
        }),
        expectedBudgetProjectionVersion: 'stale-positive-local-projection',
      }),
    ).rejects.toThrow('[SigningSessionBudget] signing grant budget is exhausted');
  });

  test('accepts reserved_success when another spend advances the projection before finalization', async () => {
    const statusSyncCalls: string[] = [];
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
      async syncSuccessfulSpendStatus(args) {
        statusSyncCalls.push(args.signingGrantId);
        return {
          sessionId: args.signingGrantId,
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

    expect(statusSyncCalls).toEqual(['wallet-session-1']);
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
      async syncSuccessfulSpendStatus() {
        throw new Error('status sync should not run');
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
      spend: makeSpend({ signingGrantId: 'wallet-session-2' }),
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
      async syncSuccessfulSpendStatus() {
        throw new Error('status sync should not run');
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
      async syncSuccessfulSpendStatus() {
        throw new Error('status sync should not run');
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
    let statusSyncCalls = 0;
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
      async syncSuccessfulSpendStatus(args) {
        statusSyncCalls += 1;
        return {
          sessionId: args.signingGrantId,
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

    expect(statusSyncCalls).toBe(1);
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
      async syncSuccessfulSpendStatus() {
        throw new Error('status sync should not run');
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
      async syncSuccessfulSpendStatus(args) {
        return {
          sessionId: args.signingGrantId,
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
      async syncSuccessfulSpendStatus() {
        throw new Error('status sync should not run');
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
      async syncSuccessfulSpendStatus() {
        throw new Error('status sync should not run');
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
      async syncSuccessfulSpendStatus(args) {
        return {
          sessionId: args.signingGrantId,
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
      async syncSuccessfulSpendStatus(args) {
        return {
          sessionId: args.signingGrantId,
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
      async syncSuccessfulSpendStatus() {
        throw new Error('status sync should not run');
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
      async syncSuccessfulSpendStatus() {
        throw new Error('status sync should not run');
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
      async syncSuccessfulSpendStatus() {
        throw new Error('status sync should not run');
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
      async syncSuccessfulSpendStatus(args) {
        return {
          sessionId: args.signingGrantId,
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
        async syncSuccessfulSpendStatus(consumeArgs) {
          if (args.consumeStatus === 'budget_unknown') {
            return {
              sessionId: consumeArgs.signingGrantId,
              status: 'budget_unknown',
              statusCode: 'status_unavailable',
            };
          }
          return {
            sessionId: consumeArgs.signingGrantId,
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
      async syncSuccessfulSpendStatus() {
        throw new Error('status sync should not run');
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
