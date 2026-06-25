import { expect, test } from '@playwright/test';
import type { EvmNonceBackend } from '@/core/rpcClients/evm/nonceBackend';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import {
  createNonceCoordinator,
  NearNonceReconcileReason,
  NonceCoordinatorTraceEventName,
  type NearNonceLane,
} from '@/core/signingEngine/nonce/NonceCoordinator';
import {
  SigningOperationIntent,
  SigningSessionIds,
} from '@/core/signingEngine/session/operationState/types';
import {
  classifyNearExecutionReadiness,
  NearAccountLookupFailedError,
  NearImplicitAccountFundingRequiredError,
} from '@/core/signingEngine/nonce/nearNonceLane';

function createFakeEvmNonceBackend(): EvmNonceBackend {
  return {
    fetchChainNonce: async () => 0n,
  };
}

function createNearLane(args?: {
  walletId?: string;
  nearAccountId?: string;
  publicKey?: string;
}): NearNonceLane {
  const nearAccountId = args?.nearAccountId || 'nonce-coordinator.testnet';
  return {
    family: 'near',
    networkKey: 'near-testnet',
    walletId: args?.walletId || 'nonce-coordinator.testnet',
    nearAccountId,
    publicKey: args?.publicKey || 'ed25519:test-key',
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

type MutableNearNonce = {
  value: number;
};

function createMutableNearClient(args: {
  nonce: MutableNearNonce;
  calls: string[];
}): NearClient {
  return {
    viewAccessKey: async () => {
      args.calls.push(`viewAccessKey:${args.nonce.value}`);
      return {
        nonce: args.nonce.value,
        permission: 'FullAccess',
        block_height: 1,
        block_hash: 'test-access-key-block',
      };
    },
    viewBlock: async () => {
      args.calls.push('viewBlock');
      return { header: { height: 100, hash: 'test-block' } };
    },
  } as unknown as NearClient;
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
  test('classifies unfunded implicit account readiness with generated wallet identity', () => {
    const walletId = 'frost-vermillion-k7p9m2';
    const nearAccountId = 'a'.repeat(64);
    const readiness = classifyNearExecutionReadiness({
      walletId,
      nearAccountId,
      nearPublicKeyStr: `ed25519:${nearAccountId}`,
      accessKeyAvailable: false,
    });

    expect(readiness).toEqual({
      kind: 'implicit_unfunded',
      walletId,
      nearAccountId,
      nearPublicKeyStr: `ed25519:${nearAccountId}`,
    });
  });

  test('classifies funded implicit readiness with nonce and generated wallet identity', () => {
    const walletId = 'frost-vermillion-k7p9m2';
    const nearAccountId = 'b'.repeat(64);
    const readiness = classifyNearExecutionReadiness({
      walletId,
      nearAccountId,
      nearPublicKeyStr: `ed25519:${nearAccountId}`,
      accessKeyAvailable: true,
      transactionContext: createContext('31'),
    });

    expect(readiness).toEqual({
      kind: 'access_key_available',
      walletId,
      nearAccountId,
      nearPublicKeyStr: `ed25519:${nearAccountId}`,
      nonce: 31n,
      accessKeyNonce: '30',
      nextNonce: '31',
      txBlockHeight: '100',
      txBlockHash: 'test-block',
    });
  });

  test('classifies sponsored named readiness with nonce', () => {
    const readiness = classifyNearExecutionReadiness({
      walletId: 'alice.testnet',
      nearAccountId: 'alice.testnet',
      nearPublicKeyStr: 'ed25519:test-key',
      accessKeyAvailable: true,
      transactionContext: createContext('44'),
    });

    expect(readiness).toEqual({
      kind: 'sponsored_named_ready',
      walletId: 'alice.testnet',
      nearAccountId: 'alice.testnet',
      nearPublicKeyStr: 'ed25519:test-key',
      nonce: 44n,
      accessKeyNonce: '43',
      nextNonce: '44',
      txBlockHeight: '100',
      txBlockHash: 'test-block',
    });
  });

  test('classifies account lookup failures without collapsing wallet identity', () => {
    const error = new NearAccountLookupFailedError({
      walletId: 'frost-vermillion-k7p9m2',
      nearAccountId: 'alice.testnet',
      nearPublicKeyStr: 'ed25519:test-key',
      message: 'Access key not found',
    });

    expect(error.readiness).toEqual({
      kind: 'account_lookup_failed',
      walletId: 'frost-vermillion-k7p9m2',
      nearAccountId: 'alice.testnet',
      nearPublicKeyStr: 'ed25519:test-key',
      message: 'Access key not found',
    });
  });

  test('surfaces first direct implicit action as unfunded readiness with generated wallet identity', async () => {
    const walletId = 'frost-vermillion-k7p9m2';
    const nearAccountId = 'c'.repeat(64);
    const publicKey = `ed25519:${nearAccountId}`;
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(),
    });
    const nearClient = {
      viewAccessKey: async () => {
        throw new Error('Access key not found');
      },
      viewBlock: async () => ({ header: { height: 100, hash: 'test-block' } }),
    } as unknown as NearClient;

    let caught: unknown = null;
    try {
      await coordinator.fetchNearContext({
        lane: createNearLane({ walletId, nearAccountId, publicKey }),
        nearClient,
        force: true,
      });
    } catch (error: unknown) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(NearImplicitAccountFundingRequiredError);
    expect((caught as NearImplicitAccountFundingRequiredError).readiness).toEqual({
      kind: 'implicit_unfunded',
      walletId,
      nearAccountId,
      nearPublicKeyStr: publicKey,
    });
  });

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
      operationFingerprint: operation.operationFingerprint,
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
      walletId: lane.walletId,
      nearAccountId: lane.nearAccountId,
      publicKey: lane.publicKey,
    });
    const [second] = await coordinator.reserveBatch({
      lane,
      operation: createNearOperation(),
      count: 1,
    });
    expect(String(second!.nonce)).toBe('12');

    const switchedLane = createNearLane({ publicKey: 'ed25519:other-key' });
    coordinator.initializeNearAccessKey({
      walletId: switchedLane.walletId,
      nearAccountId: switchedLane.nearAccountId,
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
      operationFingerprint: operation.operationFingerprint,
    });
    await coordinator.markBroadcastAccepted({
      leaseId: lease.leaseId,
      operationId: operation.operationId,
      operationFingerprint: operation.operationFingerprint,
      txHash: 'near-tx-hash',
    });
    await coordinator.markFinalized({
      leaseId: lease.leaseId,
      operationId: operation.operationId,
      operationFingerprint: operation.operationFingerprint,
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

  test('refreshes NEAR access-key nonce before coordinator-owned signing reservations', async () => {
    const chainNonce = { value: 40 };
    const calls: string[] = [];
    const nearClient = createMutableNearClient({ nonce: chainNonce, calls });
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(),
      nearClient,
    });
    const lane = createNearLane();

    const first = await coordinator.reserveNearContext({
      lane,
      operation: createNearOperation(),
      count: 1,
      nearClient,
    });
    expect(String(first.leases[0]!.nonce)).toBe('41');

    chainNonce.value = 41;
    const second = await coordinator.reserveNearContext({
      lane,
      operation: createNearOperation(),
      count: 1,
      nearClient,
    });
    expect(String(second.leases[0]!.nonce)).toBe('42');
    expect(calls.filter((entry) => entry.startsWith('viewAccessKey:'))).toEqual([
      'viewAccessKey:40',
      'viewAccessKey:41',
    ]);
  });

  test('refreshes NEAR access-key nonce after broadcast rejection', async () => {
    const chainNonce = { value: 40 };
    const calls: string[] = [];
    const nearClient = createMutableNearClient({ nonce: chainNonce, calls });
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(),
      nearClient,
    });
    const lane = createNearLane();
    const operation = createNearOperation();

    const reservation = await coordinator.reserveNearContext({
      lane,
      operation,
      count: 1,
      nearClient,
    });
    const lease = reservation.leases[0]!;
    expect(String(lease.nonce)).toBe('41');

    await coordinator.markSigned({
      leaseId: lease.leaseId,
      operationId: operation.operationId,
      operationFingerprint: operation.operationFingerprint,
    });
    chainNonce.value = 50;
    await coordinator.markBroadcastRejected({
      leaseId: lease.leaseId,
      operationId: operation.operationId,
      operationFingerprint: operation.operationFingerprint,
      error: new Error('InvalidTxError: InvalidNonce'),
    });

    const context = await coordinator.fetchNearContext({
      lane,
      nearClient,
      force: false,
    });
    expect(context.nextNonce).toBe('51');
    expect(calls).toContain('viewAccessKey:50');
  });

  test('reconciles advanced NEAR nonce with missing tx hash as dropped', async () => {
    let chainNonce = 40;
    const events: Array<{ event: string; reason?: string; txHash?: string }> = [];
    const nearClient = {
      viewAccessKey: async () => ({
        nonce: chainNonce,
        permission: 'FullAccess',
        block_height: 1,
        block_hash: 'test-access-key-block',
      }),
      viewBlock: async () => ({ header: { height: 100, hash: 'test-block' } }),
      txStatus: async () => {
        throw new Error('Unknown transaction');
      },
    } as unknown as NearClient;
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(),
      nearClient,
      onTrace: (event) =>
        events.push({
          event: event.event,
          reason: event.reason,
          txHash: event.txHash,
        }),
    });
    const lane = createNearLane();
    const operation = createNearOperation();
    const reservation = await coordinator.reserveNearContext({
      lane,
      operation,
      count: 1,
      nearClient,
    });
    const lease = reservation.leases[0]!;

    await coordinator.markSigned({
      leaseId: lease.leaseId,
      operationId: operation.operationId,
      operationFingerprint: operation.operationFingerprint,
    });
    await coordinator.markBroadcastAccepted({
      leaseId: lease.leaseId,
      operationId: operation.operationId,
      operationFingerprint: operation.operationFingerprint,
      txHash: 'near-missing-hash',
    });
    chainNonce = 41;

    const status = await coordinator.reconcile({ lane });

    expect(status).toEqual({
      chainNextNonce: 42n,
      unresolvedInFlightNonces: [],
      blocked: false,
    });
    expect(events).toContainEqual({
      event: NonceCoordinatorTraceEventName.LeaseDropped,
      reason: NearNonceReconcileReason.NonceAdvancedHashMissing,
      txHash: 'near-missing-hash',
    });
    const next = await coordinator.reserveNearContext({
      lane,
      operation: createNearOperation(),
      count: 1,
      nearClient,
    });
    expect(String(next.leases[0]!.nonce)).toBe('42');
  });

  test('reconciles advanced NEAR nonce with found tx hash as finalized', async () => {
    let chainNonce = 40;
    const events: Array<{ event: string; reason?: string; txHash?: string }> = [];
    const nearClient = {
      viewAccessKey: async () => ({
        nonce: chainNonce,
        permission: 'FullAccess',
        block_height: 1,
        block_hash: 'test-access-key-block',
      }),
      viewBlock: async () => ({ header: { height: 100, hash: 'test-block' } }),
      txStatus: async () => ({ status: { SuccessValue: '' } }),
    } as unknown as NearClient;
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(),
      nearClient,
      onTrace: (event) =>
        events.push({
          event: event.event,
          reason: event.reason,
          txHash: event.txHash,
        }),
    });
    const lane = createNearLane();
    const operation = createNearOperation();
    const reservation = await coordinator.reserveNearContext({
      lane,
      operation,
      count: 1,
      nearClient,
    });
    const lease = reservation.leases[0]!;

    await coordinator.markSigned({
      leaseId: lease.leaseId,
      operationId: operation.operationId,
      operationFingerprint: operation.operationFingerprint,
    });
    await coordinator.markBroadcastAccepted({
      leaseId: lease.leaseId,
      operationId: operation.operationId,
      operationFingerprint: operation.operationFingerprint,
      txHash: 'near-finalized-hash',
    });
    chainNonce = 41;

    const status = await coordinator.reconcile({ lane });

    expect(status).toEqual({
      chainNextNonce: 42n,
      unresolvedInFlightNonces: [],
      blocked: false,
    });
    expect(events).toContainEqual({
      event: NonceCoordinatorTraceEventName.LeaseFinalized,
      reason: 'near_tx_status_finalized',
      txHash: 'near-finalized-hash',
    });
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
