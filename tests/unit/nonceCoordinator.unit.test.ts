import { expect, test } from '@playwright/test';
import type { EvmNonceManager } from '@/core/rpcClients/evm/nonceManager';
import { fromManagedNonceReservationSnapshot } from '@/core/rpcClients/evm/nonceManager';
import {
  createNonceCoordinator,
  evmNonceLeaseToManagedReservation,
  reduceNonceLeaseState,
  type EvmNonceLane,
} from '@/core/signingEngine/nonce/NonceCoordinator';
import { SigningSessionIds } from '@/core/signingEngine/session/signingSessionTypes';

const TEST_SENDER = `0x${'22'.repeat(20)}` as const;

function createFakeEvmNonceManager(calls: unknown[]): EvmNonceManager {
  return {
    reserveNextNonce: async (input) => {
      calls.push({ fn: 'reserveNextNonce', input });
      return 7n;
    },
    markBroadcastAccepted: async (input) => {
      calls.push({ fn: 'markBroadcastAccepted', input });
    },
    markBroadcastRejected: async (input) => {
      calls.push({ fn: 'markBroadcastRejected', input });
    },
    markFinalized: async (input) => {
      calls.push({ fn: 'markFinalized', input });
    },
    markDroppedOrReplaced: async (input) => {
      calls.push({ fn: 'markDroppedOrReplaced', input });
    },
    reconcileLane: async (input) => {
      calls.push({ fn: 'reconcileLane', input });
      return {
        chainNextNonce: 8n,
        unresolvedInFlightNonces: [],
        blocked: false,
      };
    },
    clearForAccount: (nearAccountId) => {
      calls.push({ fn: 'clearForAccount', nearAccountId });
    },
  };
}

function createOperation() {
  return {
    operationId: SigningSessionIds.signingOperation('op-nonce-coordinator'),
    operationFingerprint: SigningSessionIds.signingOperationFingerprint(
      'sha256:test-nonce-coordinator',
    ),
    accountId: 'nonce-coordinator.testnet',
    walletSigningSessionId: 'wallet-session-nonce-coordinator',
    chainFamily: 'tempo' as const,
  };
}

function createLane(): EvmNonceLane {
  return {
    family: 'evm',
    chain: 'tempo',
    networkKey: 'tempo:42431',
    chainId: 42_431,
    sender: TEST_SENDER,
    nonceKey: 3n,
    accountId: 'nonce-coordinator.testnet',
  };
}

test.describe('NonceCoordinator', () => {
  test('enforces nonce lease transition order', () => {
    expect(reduceNonceLeaseState('reserved', 'mark_signed')).toBe('signed');
    expect(reduceNonceLeaseState('signed', 'broadcast_accepted')).toBe(
      'broadcast_accepted',
    );
    expect(reduceNonceLeaseState('broadcast_accepted', 'finalize')).toBe('finalized');
    expect(() => reduceNonceLeaseState('signed', 'release')).toThrow(
      'illegal nonce lease transition',
    );
  });

  test('reserves and releases an EVM-family nonce lease with operation binding', async () => {
    const calls: unknown[] = [];
    const coordinator = createNonceCoordinator({
      evmNonceManager: createFakeEvmNonceManager(calls),
      now: () => 1_000,
      leaseTtlMs: 5_000,
    });
    const operation = createOperation();
    const lease = await coordinator.reserve({
      lane: createLane(),
      operation,
    });

    expect(lease).toMatchObject({
      nonce: 7n,
      state: 'reserved',
      operationId: operation.operationId,
      operationFingerprint: operation.operationFingerprint,
      reservedAtMs: 1_000,
      expiresAtMs: 6_000,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      fn: 'reserveNextNonce',
      input: {
        chain: 'tempo',
        networkKey: 'tempo:42431',
        chainId: 42_431,
        sender: TEST_SENDER,
        nonceKey: 3n,
        nearAccountId: 'nonce-coordinator.testnet',
      },
    });

    await expect(
      coordinator.release({
        leaseId: lease.leaseId,
        operationId: SigningSessionIds.signingOperation('op-other'),
        reason: 'cancelled',
      }),
    ).rejects.toThrow('operation mismatch');

    await coordinator.release({
      leaseId: lease.leaseId,
      operationId: operation.operationId,
      reason: 'cancelled',
    });
    expect(calls.at(-1)).toMatchObject({
      fn: 'markBroadcastRejected',
      input: {
        chain: 'tempo',
        nonce: 7n,
      },
    });
  });

  test('carries lease metadata through managed nonce snapshots', async () => {
    const calls: unknown[] = [];
    const coordinator = createNonceCoordinator({
      evmNonceManager: createFakeEvmNonceManager(calls),
      now: () => 10_000,
    });
    const operation = createOperation();
    const lease = await coordinator.reserve({
      lane: createLane(),
      operation,
    });
    const reservation = evmNonceLeaseToManagedReservation(lease);
    const parsed = fromManagedNonceReservationSnapshot({
      chain: reservation.chain,
      networkKey: reservation.networkKey,
      chainId: reservation.chainId,
      sender: reservation.sender,
      nonceKey: reservation.nonceKey?.toString(),
      nonce: reservation.nonce.toString(),
      nearAccountId: reservation.nearAccountId,
      leaseId: reservation.leaseId,
      operationId: reservation.operationId,
      operationFingerprint: reservation.operationFingerprint,
      reservedAtMs: reservation.reservedAtMs,
      expiresAtMs: reservation.expiresAtMs,
    });

    expect(parsed).toMatchObject({
      chain: 'tempo',
      nonce: 7n,
      leaseId: lease.leaseId,
      operationId: String(operation.operationId),
      operationFingerprint: String(operation.operationFingerprint),
      reservedAtMs: 10_000,
    });
  });
});
