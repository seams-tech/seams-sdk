import { expect, test } from '@playwright/test';
import {
  buildEvmTransactionSigningLane,
  buildNearTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from '@/core/signingEngine/session/signingSession/lanes';
import { createSigningSessionBudgetFinalizer } from '@/core/signingEngine/session/signingSession/budgetFinalizer';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type SigningLaneContext,
} from '@/core/signingEngine/session/signingSession/types';
import { createNonceCoordinator } from '@/core/signingEngine/nonce/NonceCoordinator';
import { toAccountId } from '@/core/types/accountIds';

test.describe('SigningSessionBudgetFinalizer', () => {
  test('fails closed after produced signatures when authoritative budget recording fails', async () => {
    const rows: Array<{ name: string; lane: SigningLaneContext }> = [
      {
        name: 'near',
        lane: buildNearTransactionSigningLane({
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
        }),
      },
      {
        name: 'evm',
        lane: buildEvmTransactionSigningLane({
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
        }),
      },
      {
        name: 'tempo',
        lane: buildTempoTransactionSigningLane({
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
        }),
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
    const lane = buildNearTransactionSigningLane({
      accountId,
      authMethod: 'passkey',
      storageSource: 'login',
      walletSigningSessionId,
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
        'tsess-budget-cancel-near',
      ),
      signingRootId: 'proj_budget:near',
      signingRootVersion: 'default',
    });
    let consumeCalls = 0;
    const budgetTraceEvents: string[] = [];
    const ledger = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: walletSigningSessionId,
        status: 'active',
        remainingUses: 1,
        expiresAtMs: Date.now() + 60_000,
      }),
      consumeUse: async () => {
        consumeCalls += 1;
        return {
          sessionId: walletSigningSessionId,
          status: 'active',
          remainingUses: 0,
          expiresAtMs: Date.now() + 60_000,
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
    ).resolves.toMatchObject({ status: 'exhausted', remainingUses: 0 });

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
    ).resolves.toMatchObject({ status: 'active', remainingUses: 1 });
  });

  test('post-sign broadcast rejection consumes budget once and reconciles nonce state', async () => {
    const accountId = toAccountId('budget-broadcast-reject.testnet');
    const walletSigningSessionId =
      SigningSessionIds.walletSigningSession('wsess-budget-broadcast-reject');
    const operationId = SigningSessionIds.signingOperation('op-budget-broadcast-reject');
    const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
      'sha256:budget-broadcast-reject',
    );
    const lane = buildEvmTransactionSigningLane({
      accountId,
      authMethod: 'passkey',
      storageSource: 'login',
      walletSigningSessionId,
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(
        'tsess-budget-broadcast-reject',
      ),
      signingRootId: 'proj_budget:evm',
      signingRootVersion: 'default',
    });
    let consumeCalls = 0;
    let sessionRemainingUses = 1;
    const nonceTraces: string[] = [];
    const ledger = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: walletSigningSessionId,
        status: sessionRemainingUses > 0 ? 'active' : 'exhausted',
        remainingUses: sessionRemainingUses,
        expiresAtMs: Date.now() + 60_000,
      }),
      consumeUse: async () => {
        consumeCalls += 1;
        sessionRemainingUses = Math.max(0, sessionRemainingUses - 1);
        return {
          sessionId: walletSigningSessionId,
          status: sessionRemainingUses > 0 ? 'active' : 'exhausted',
          remainingUses: sessionRemainingUses,
          expiresAtMs: Date.now() + 60_000,
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
    const lane = buildTempoTransactionSigningLane({
      accountId,
      authMethod: 'email_otp',
      walletSigningSessionId,
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(
        'tsess-budget-trace-correlation',
      ),
      signingRootId: 'proj_budget:tempo',
      signingRootVersion: 'default',
    });
    const budgetTraces: unknown[] = [];
    const nonceTraces: unknown[] = [];
    const ledger = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: walletSigningSessionId,
        status: 'active',
        remainingUses: 1,
        expiresAtMs: Date.now() + 60_000,
      }),
      consumeUse: async () => ({
        sessionId: walletSigningSessionId,
        status: 'exhausted',
        remainingUses: 0,
        expiresAtMs: Date.now() + 60_000,
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
