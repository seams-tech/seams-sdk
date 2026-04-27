import { expect, test } from '@playwright/test';
import type { EvmNonceBackend } from '@/core/rpcClients/evm/nonceBackend';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import {
  createNonceCoordinator,
  type NearNonceLane,
} from '@/core/signingEngine/nonce/NonceCoordinator';
import {
  SigningOperationIntent,
  SigningSessionIds,
} from '@/core/signingEngine/session/signingSession/types';

function createFakeEvmNonceBackend(): EvmNonceBackend {
  return {
    fetchChainNonce: async () => 0n,
  };
}

function createNearLane(publicKey = 'ed25519:test-key'): NearNonceLane {
  return {
    family: 'near',
    networkKey: 'near-testnet',
    accountId: 'nonce-coordinator.testnet',
    publicKey,
  };
}

function createNearOperation() {
  return {
    operationId: SigningSessionIds.signingOperation(
      `op-near-context-${globalThis.crypto.randomUUID()}`,
    ),
    operationFingerprint: SigningSessionIds.signingOperationFingerprint(
      `sha256:near-context-${globalThis.crypto.randomUUID()}`,
    ),
    intent: SigningOperationIntent.TransactionSign,
    accountId: 'nonce-coordinator.testnet',
    chainFamily: 'near' as const,
  };
}

function createContext(nextNonce: string) {
  return {
    nearPublicKeyStr: 'ed25519:test-key',
    accessKeyInfo: {
      nonce: BigInt(nextNonce) - 1n,
      permission: 'FullAccess' as const,
      block_height: 1,
      block_hash: 'test-access-key-block',
    },
    nextNonce,
    txBlockHeight: '100',
    txBlockHash: 'test-block',
  };
}

test.describe('NonceCoordinator NEAR context ownership', () => {
  test('reserves NEAR batches and reuses a released highest nonce', async () => {
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(),
    });
    const operation = createNearOperation();
    const lane = createNearLane();
    const first = await coordinator.reserveNearContext({
      lane,
      operation,
      count: 2,
      fetchContext: async () => createContext('101'),
    });

    expect(first.leases.map((lease) => String(lease.nonce))).toEqual(['101', '102']);

    await coordinator.release({
      leaseId: first.leases[1]!.leaseId,
      operationId: operation.operationId,
      reason: 'cancelled',
    });

    const [reused] = await coordinator.reserveBatch({
      lane,
      operation: createNearOperation(),
      count: 1,
    });
    expect(String(reused!.nonce)).toBe('102');
  });

  test('keeps same-key initialization idempotent and clears state on key switch', async () => {
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(),
    });
    const lane = createNearLane();
    await coordinator.reserveNearContext({
      lane,
      operation: createNearOperation(),
      count: 1,
      fetchContext: async () => createContext('11'),
    });

    coordinator.initializeNearAccessKey({
      accountId: lane.accountId,
      publicKey: lane.publicKey,
    });
    const [second] = await coordinator.reserveBatch({
      lane,
      operation: createNearOperation(),
      count: 1,
    });
    expect(String(second!.nonce)).toBe('12');

    const switchedLane = createNearLane('ed25519:other-key');
    coordinator.initializeNearAccessKey({
      accountId: switchedLane.accountId,
      publicKey: switchedLane.publicKey,
    });
    await expect(
      coordinator.reserveBatch({
        lane: switchedLane,
        operation: createNearOperation(),
        count: 1,
      }),
    ).rejects.toThrow('NEAR transaction context not available');
  });

  test('refreshes finalized NEAR leases from the configured NEAR client', async () => {
    let chainNonce = 40;
    const calls: string[] = [];
    const nearClient = {
      viewAccessKey: async () => {
        calls.push(`viewAccessKey:${chainNonce}`);
        return {
          nonce: chainNonce,
          permission: 'FullAccess',
          block_height: 1,
          block_hash: 'test-access-key-block',
        };
      },
      viewBlock: async () => {
        calls.push('viewBlock');
        return { header: { height: 100, hash: 'test-block' } };
      },
    } as unknown as NearClient;
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(),
      nearClient,
    });
    const lane = createNearLane();
    const operation = createNearOperation();
    const first = await coordinator.reserveNearContext({
      lane,
      operation,
      count: 1,
      nearClient,
    });
    const lease = first.leases[0]!;
    expect(String(lease.nonce)).toBe('41');

    chainNonce = 41;
    await coordinator.markSigned({
      leaseId: lease.leaseId,
      operationId: operation.operationId,
    });
    await coordinator.markBroadcastAccepted({
      leaseId: lease.leaseId,
      operationId: operation.operationId,
      txHash: 'near-tx-hash',
    });
    await coordinator.markFinalized({
      leaseId: lease.leaseId,
      operationId: operation.operationId,
      txHash: 'near-tx-hash',
    });

    const next = await coordinator.reserveNearContext({
      lane,
      operation: createNearOperation(),
      count: 1,
      nearClient,
    });
    expect(String(next.leases[0]!.nonce)).toBe('42');
    expect(calls).toContain('viewAccessKey:41');
  });

  test('fails closed when callers reserve a NEAR batch without a context', async () => {
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(),
    });
    await expect(
      coordinator.reserveBatch({
        lane: createNearLane(),
        operation: createNearOperation(),
        count: 1,
      }),
    ).rejects.toThrow('NEAR transaction context not available');
  });
});
