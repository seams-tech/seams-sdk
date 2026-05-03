import { expect, test } from '@playwright/test';
import {
  buildEvmTransactionSigningLane,
  buildNearTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from '@/core/signingEngine/session/signingSession/lanes';
import { createSigningSessionBudgetFinalizer } from '@/core/signingEngine/session/signingSession/budgetFinalizer';
import { SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR } from '@/core/signingEngine/session/signingSession/budget';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type SelectedSigningLaneContext,
} from '@/core/signingEngine/session/signingSession/types';
import type { NearEd25519TransactionLane } from '@/core/signingEngine/session/signingSession/transactionState';
import { createNonceCoordinator } from '@/core/signingEngine/nonce/NonceCoordinator';
import { toAccountId } from '@/core/types/accountIds';

function selectedLane(lane: SelectedSigningLaneContext): SelectedSigningLaneContext {
  return lane;
}

function budgetIdentity(walletSigningSessionId: string) {
  const projectionVersion = `projection:${walletSigningSessionId}:1`;
  return {
    walletSigningSessionId,
    projectionVersion,
    status: {
      sessionId: walletSigningSessionId,
      status: 'active' as const,
      remainingUses: 1,
      expiresAtMs: Date.now() + 60_000,
      projectionVersion,
    },
  };
}

test.describe('SigningSessionBudgetFinalizer', () => {
  test('prepares budget identity from an exact transaction lane', async () => {
    const accountId = toAccountId('budget-identity-transaction-lane.testnet');
    const walletSigningSessionId = SigningSessionIds.walletSigningSession(
      'wsess-budget-identity-transaction-lane',
    );
    const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(
      'tsess-budget-identity-transaction-lane',
    );
    const lane: NearEd25519TransactionLane = {
      accountId,
      authMethod: 'passkey',
      curve: 'ed25519',
      chain: 'near',
      walletSigningSessionId,
      thresholdSessionId,
    };
    const observedTargets: unknown[] = [];
    const ledger = new SigningSessionCoordinator({
      getStatus: async (input) => {
        observedTargets.push(input);
        return {
          sessionId: walletSigningSessionId,
          status: 'active',
          remainingUses: 1,
          expiresAtMs: Date.now() + 60_000,
          projectionVersion: 'projection:transaction-lane',
        };
      },
      consumeUse: async () => {
        throw new Error('not used');
      },
    });

    await expect(
      ledger.prepareBudgetIdentity({
        nearAccountId: accountId,
        lane,
        operationUsesNeeded: 1,
      }),
    ).resolves.toMatchObject({
      walletSigningSessionId,
      projectionVersion: 'projection:transaction-lane',
    });
    expect(observedTargets).toEqual([
      expect.objectContaining({
        nearAccountId: accountId,
        walletSigningSessionId,
        targetThresholdSessionIds: [thresholdSessionId],
      }),
    ]);
  });

  test('accepts an exact transaction lane for budget finalization', async () => {
    const accountId = toAccountId('budget-finalizer-transaction-lane.testnet');
    const walletSigningSessionId = SigningSessionIds.walletSigningSession(
      'wsess-budget-finalizer-transaction-lane',
    );
    const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(
      'tsess-budget-finalizer-transaction-lane',
    );
    const lane: NearEd25519TransactionLane = {
      accountId,
      authMethod: 'email_otp',
      curve: 'ed25519',
      chain: 'near',
      walletSigningSessionId,
      thresholdSessionId,
    };
    const recordedSpends: unknown[] = [];
    const finalizer = createSigningSessionBudgetFinalizer({
      signingSessionBudget: {
        reserve: async () => null,
        getAvailableStatus: async () => null,
        recordSuccess: async (input) => {
          recordedSpends.push(input.spend);
          return null;
        },
        recordZeroSpend: () => {},
        hasRecorded: () => false,
      },
      operation: {
        operationId: SigningSessionIds.signingOperation(
          'op-budget-finalizer-transaction-lane',
        ),
        operationFingerprint: SigningSessionIds.signingOperationFingerprint(
          'sha256:budget-finalizer-transaction-lane',
        ),
        intent: SigningOperationIntent.TransactionSign,
      },
      lane,
      budgetIdentity: budgetIdentity(String(walletSigningSessionId)),
    });

    await finalizer.recordSuccess({ alreadyConsumedThresholdSessionIds: [thresholdSessionId] });

    expect(recordedSpends).toEqual([
      expect.objectContaining({
        nearAccountId: accountId,
        walletSigningSessionId,
        thresholdSessionIds: [thresholdSessionId],
        uses: 1,
      }),
    ]);
  });

  test('retries local in-flight budget contention before surfacing a reservation failure', async () => {
    const lane = selectedLane(buildTempoTransactionSigningLane({
      accountId: toAccountId('budget-finalizer-in-flight.testnet'),
      authMethod: 'passkey',
      walletSigningSessionId: SigningSessionIds.walletSigningSession(
        'wsess-budget-finalizer-in-flight',
      ),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(
        'tsess-budget-finalizer-in-flight',
      ),
      storageSource: 'login',
      signingRootId: 'proj_budget:tempo',
      signingRootVersion: 'default',
    }) as SelectedSigningLaneContext);
    let attempts = 0;
    const finalizer = createSigningSessionBudgetFinalizer({
      signingSessionBudget: {
        reserve: async () => {
          attempts += 1;
          if (attempts === 1) throw new Error(SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR);
          return {
            operationId: SigningSessionIds.signingOperation('op-budget-finalizer-in-flight'),
            release: () => undefined,
          };
        },
        getAvailableStatus: async () => null,
        recordSuccess: async () => null,
        recordZeroSpend: () => {},
        hasRecorded: () => false,
      },
      operation: {
        operationId: SigningSessionIds.signingOperation('op-budget-finalizer-in-flight'),
        operationFingerprint: SigningSessionIds.signingOperationFingerprint(
          'sha256:budget-finalizer-in-flight',
        ),
        intent: 'transaction_sign',
      },
      lane,
      budgetIdentity: budgetIdentity(String(lane.walletSigningSessionId)),
    });

    await expect(finalizer.reserve()).resolves.toMatchObject({
      operationId: 'op-budget-finalizer-in-flight',
    });
    expect(attempts).toBe(2);
  });

  test('fails closed after produced signatures when authoritative budget recording fails', async () => {
    const rows: Array<{ name: string; lane: SelectedSigningLaneContext }> = [
      {
        name: 'near',
        lane: selectedLane(buildNearTransactionSigningLane({
          accountId: toAccountId('budget-finalizer-near.testnet'),
          authMethod: 'email_otp',
          walletSigningSessionId: SigningSessionIds.walletSigningSession(
            'wsess-budget-finalizer-near',
          ),
          thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
            'tsess-budget-finalizer-near',
          ),
          signingRootId: 'proj_budget:near',
          signingRootVersion: 'default',
        }) as SelectedSigningLaneContext),
      },
      {
        name: 'evm',
        lane: selectedLane(buildEvmTransactionSigningLane({
          accountId: toAccountId('budget-finalizer-evm.testnet'),
          authMethod: 'email_otp',
          walletSigningSessionId: SigningSessionIds.walletSigningSession(
            'wsess-budget-finalizer-evm',
          ),
          thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(
            'tsess-budget-finalizer-evm',
          ),
          signingRootId: 'proj_budget:evm',
          signingRootVersion: 'default',
        }) as SelectedSigningLaneContext),
      },
      {
        name: 'tempo',
        lane: selectedLane(buildTempoTransactionSigningLane({
          accountId: toAccountId('budget-finalizer-tempo.testnet'),
          authMethod: 'email_otp',
          walletSigningSessionId: SigningSessionIds.walletSigningSession(
            'wsess-budget-finalizer-tempo',
          ),
          thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(
            'tsess-budget-finalizer-tempo',
          ),
          signingRootId: 'proj_budget:tempo',
          signingRootVersion: 'default',
        }) as SelectedSigningLaneContext),
      },
    ];

    for (const row of rows) {
      const observedErrors: string[] = [];
      const finalizer = createSigningSessionBudgetFinalizer({
        signingSessionBudget: {
          reserve: async () => null,
          getAvailableStatus: async () => null,
          recordSuccess: async () => {
            throw new Error(`authoritative consume failed:${row.name}`);
          },
          recordZeroSpend: () => {},
          hasRecorded: () => false,
        },
        operation: {
          operationId: SigningSessionIds.signingOperation(
            `op-budget-finalizer-fail-closed-${row.name}`,
          ),
          operationFingerprint: SigningSessionIds.signingOperationFingerprint(
            `sha256:${row.name}`,
          ),
          intent: 'transaction_sign',
        },
        lane: row.lane,
        budgetIdentity: budgetIdentity(String(row.lane.walletSigningSessionId)),
        onRecordSuccessError: (error) => {
          observedErrors.push(error instanceof Error ? error.message : String(error));
        },
      });

      await expect(finalizer.recordSuccess(), row.name).rejects.toThrow(
        `authoritative consume failed:${row.name}`,
      );
      expect(observedErrors, row.name).toEqual([`authoritative consume failed:${row.name}`]);
    }
  });

  test('cancellation before signature releases nonce lease and wallet budget reservation', async () => {
    const accountId = toAccountId('budget-cancel-near.testnet');
    const walletSigningSessionId =
      SigningSessionIds.walletSigningSession('wsess-budget-cancel-near');
    const operationId = SigningSessionIds.signingOperation('op-budget-cancel-near');
    const operationFingerprint =
      SigningSessionIds.signingOperationFingerprint('sha256:budget-cancel-near');
    const lane = selectedLane(buildNearTransactionSigningLane({
      accountId,
      authMethod: 'passkey',
      storageSource: 'login',
      walletSigningSessionId,
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
        'tsess-budget-cancel-near',
      ),
      signingRootId: 'proj_budget:near',
      signingRootVersion: 'default',
    }) as SelectedSigningLaneContext);
    let consumeCalls = 0;
    const budgetTraceEvents: string[] = [];
    const ledger = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: walletSigningSessionId,
        status: 'active',
        remainingUses: 1,
        expiresAtMs: Date.now() + 60_000,
        projectionVersion: budgetIdentity(String(walletSigningSessionId)).projectionVersion,
      }),
      consumeUse: async () => {
        consumeCalls += 1;
        return {
          sessionId: walletSigningSessionId,
          status: 'active',
          remainingUses: 0,
          expiresAtMs: Date.now() + 60_000,
          projectionVersion: `projection:${walletSigningSessionId}:0`,
        };
      },
      onTrace: (event) => budgetTraceEvents.push(event.event),
    });
    const finalizer = createSigningSessionBudgetFinalizer({
      signingSessionBudget: ledger,
      operation: {
        operationId,
        operationFingerprint,
        intent: SigningOperationIntent.TransactionSign,
      },
      lane,
      budgetIdentity: budgetIdentity(String(walletSigningSessionId)),
    });
    const releasedNearNonces: string[] = [];
    const nonceCoordinator = createNonceCoordinator({
      evmNonceBackend: {
        fetchChainNonce: async () => 0n,
      },
      onTrace: (event) => {
        if (event.event === 'nonce_lease_released' && event.lease?.lane.family === 'near') {
          releasedNearNonces.push(String(event.lease.nonce));
        }
      },
    });

    await finalizer.reserve();
    await expect(
      ledger.getAvailableStatus({ nearAccountId: accountId, walletSigningSessionId }),
    ).resolves.toMatchObject({
      status: 'active',
      remainingUses: 1,
      inFlightReservedUses: 1,
      availableUses: 0,
    });

    const { leases } = await nonceCoordinator.reserveNearContext({
      lane: {
        family: 'near',
        networkKey: 'near-testnet',
        accountId,
        publicKey: 'ed25519:budget-cancel-near',
      },
      operation: {
        operationId,
        operationFingerprint,
        intent: SigningOperationIntent.TransactionSign,
        accountId,
        walletSigningSessionId,
        chainFamily: 'near',
      },
      count: 1,
      fetchContext: async () => ({
        nearPublicKeyStr: 'ed25519:budget-cancel-near',
        accessKeyInfo: {
          nonce: 100n,
          permission: 'FullAccess',
          block_height: 1,
          block_hash: 'test-access-key-block',
        },
        nextNonce: '101',
        txBlockHeight: '1',
        txBlockHash: 'test-block',
      }),
    });
    const nonceLease = leases[0]!;

    await nonceCoordinator.release({
      leaseId: nonceLease.leaseId,
      operationId,
      reason: 'cancelled',
    });
    finalizer.recordZeroSpend({ code: 'user_cancelled', message: 'cancelled by user' });

    expect(releasedNearNonces).toEqual(['101']);
    expect(consumeCalls).toBe(0);
    expect(budgetTraceEvents).toContain('wallet_signing_budget_reservation_released');
    expect(budgetTraceEvents).toContain('wallet_signing_budget_zero_spend_recorded');
    await expect(
      ledger.getAvailableStatus({ nearAccountId: accountId, walletSigningSessionId }),
    ).resolves.toMatchObject({
      status: 'active',
      remainingUses: 1,
      inFlightReservedUses: 0,
      availableUses: 1,
    });
  });

  test('post-sign broadcast rejection consumes budget once and reconciles nonce state', async () => {
    const accountId = toAccountId('budget-broadcast-reject.testnet');
    const walletSigningSessionId =
      SigningSessionIds.walletSigningSession('wsess-budget-broadcast-reject');
    const operationId = SigningSessionIds.signingOperation('op-budget-broadcast-reject');
    const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
      'sha256:budget-broadcast-reject',
    );
    const lane = selectedLane(buildEvmTransactionSigningLane({
      accountId,
      authMethod: 'passkey',
      storageSource: 'login',
      walletSigningSessionId,
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(
        'tsess-budget-broadcast-reject',
      ),
      signingRootId: 'proj_budget:evm',
      signingRootVersion: 'default',
    }) as SelectedSigningLaneContext);
    let consumeCalls = 0;
    let sessionRemainingUses = 1;
    const nonceTraces: string[] = [];
    const ledger = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: walletSigningSessionId,
        status: sessionRemainingUses > 0 ? 'active' : 'exhausted',
        remainingUses: sessionRemainingUses,
        expiresAtMs: Date.now() + 60_000,
        projectionVersion: `projection:${walletSigningSessionId}:${sessionRemainingUses}`,
      }),
      consumeUse: async () => {
        consumeCalls += 1;
        sessionRemainingUses = Math.max(0, sessionRemainingUses - 1);
        return {
          sessionId: walletSigningSessionId,
          status: sessionRemainingUses > 0 ? 'active' : 'exhausted',
          remainingUses: sessionRemainingUses,
          expiresAtMs: Date.now() + 60_000,
          projectionVersion: `projection:${walletSigningSessionId}:${sessionRemainingUses}`,
        };
      },
    });
    const finalizer = createSigningSessionBudgetFinalizer({
      signingSessionBudget: ledger,
      operation: {
        operationId,
        operationFingerprint,
        intent: SigningOperationIntent.TransactionSign,
      },
      lane,
      budgetIdentity: budgetIdentity(String(walletSigningSessionId)),
    });
    const nonceCoordinator = createNonceCoordinator({
      evmNonceBackend: {
        fetchChainNonce: async () => 7n,
      },
      onTrace: (event) => nonceTraces.push(event.event),
    });
    const nonceLane = {
      family: 'evm' as const,
      chain: 'evm' as const,
      networkKey: 'evm:arc-testnet',
      chainId: 999,
      sender: '0x1111111111111111111111111111111111111111' as const,
      accountId,
    };

    await finalizer.reserve();
    const nonceLease = await nonceCoordinator.reserve({
      lane: nonceLane,
      operation: {
        operationId,
        operationFingerprint,
        intent: SigningOperationIntent.TransactionSign,
        accountId,
        walletSigningSessionId,
        chainFamily: 'evm',
      },
    });
    await nonceCoordinator.markSigned({
      leaseId: nonceLease.leaseId,
      operationId,
      signedTxHash: '0xabc',
    });

    await finalizer.recordSuccess();
    await finalizer.recordSuccess();
    await nonceCoordinator.markBroadcastRejected({
      leaseId: nonceLease.leaseId,
      operationId,
      error: new Error('rpc rejected transaction'),
    });
    await nonceCoordinator.reconcile({ lane: nonceLane });

    expect(consumeCalls).toBe(1);
    expect(nonceTraces).toContain('nonce_lease_broadcast_rejected');
    expect(nonceTraces).toContain('nonce_lane_reconciled');
    await expect(
      ledger.getAvailableStatus({ nearAccountId: accountId, walletSigningSessionId }),
    ).resolves.toMatchObject({ status: 'exhausted', remainingUses: 0 });
  });

  test('correlates wallet budget reservation and nonce lease traces by operation id', async () => {
    const accountId = toAccountId('budget-trace-correlation.testnet');
    const walletSigningSessionId = SigningSessionIds.walletSigningSession(
      'wsess-budget-trace-correlation',
    );
    const operationId = SigningSessionIds.signingOperation(
      'op-budget-trace-correlation',
    );
    const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
      'sha256:budget-trace-correlation',
    );
    const lane = selectedLane(buildTempoTransactionSigningLane({
      accountId,
      authMethod: 'email_otp',
      walletSigningSessionId,
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(
        'tsess-budget-trace-correlation',
      ),
      signingRootId: 'proj_budget:tempo',
      signingRootVersion: 'default',
    }) as SelectedSigningLaneContext);
    const budgetTraces: unknown[] = [];
    const nonceTraces: unknown[] = [];
    const ledger = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: walletSigningSessionId,
        status: 'active',
        remainingUses: 1,
        expiresAtMs: Date.now() + 60_000,
        projectionVersion: budgetIdentity(String(walletSigningSessionId)).projectionVersion,
      }),
      consumeUse: async () => ({
        sessionId: walletSigningSessionId,
        status: 'exhausted',
        remainingUses: 0,
        expiresAtMs: Date.now() + 60_000,
        projectionVersion: `projection:${walletSigningSessionId}:0`,
      }),
      onTrace: (event) => budgetTraces.push(event),
    });
    const finalizer = createSigningSessionBudgetFinalizer({
      signingSessionBudget: ledger,
      operation: {
        operationId,
        operationFingerprint,
        intent: SigningOperationIntent.TransactionSign,
      },
      lane,
      budgetIdentity: budgetIdentity(String(walletSigningSessionId)),
    });
    const nonceCoordinator = createNonceCoordinator({
      evmNonceBackend: {
        fetchChainNonce: async () => 44n,
      },
      onTrace: (event) => nonceTraces.push(event),
    });

    const reservation = await finalizer.reserve();
    const nonceLease = await nonceCoordinator.reserve({
      lane: {
        family: 'evm',
        chain: 'tempo',
        networkKey: 'tempo-testnet',
        chainId: 42_431,
        sender: '0x1111111111111111111111111111111111111111',
        nonceKey: 1n,
        accountId,
      },
      operation: {
        operationId,
        operationFingerprint,
        intent: SigningOperationIntent.TransactionSign,
        accountId,
        walletSigningSessionId,
        chainFamily: 'tempo',
      },
    });

    expect(budgetTraces).toContainEqual(
      expect.objectContaining({
        event: 'wallet_signing_budget_reservation_succeeded',
        operationId,
        nearAccountId: accountId,
        uses: 1,
      }),
    );
    expect(nonceTraces).toContainEqual(
      expect.objectContaining({
        event: 'nonce_lease_reserved',
        lease: expect.objectContaining({
          leaseId: nonceLease.leaseId,
          operationId,
          operationFingerprint,
          nonce: 44n,
        }),
      }),
    );

    await nonceCoordinator.release({
      leaseId: nonceLease.leaseId,
      operationId,
      reason: 'cancelled',
    });
    reservation?.release('confirmation_cancelled');
  });
});
