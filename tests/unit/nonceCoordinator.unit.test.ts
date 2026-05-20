import { expect, test } from '@playwright/test';
import type { EvmNonceBackend } from '@/core/rpcClients/evm/nonceBackend';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import { fromManagedNonceReservationSnapshot } from '@/core/rpcClients/evm/nonceBackend';
import {
  createNonceCoordinator,
  evmNonceLeaseToManagedReservation,
  reduceNonceLeaseState,
  type EvmNonceLane,
  type NearNonceLane,
  type NonceLaneCoordinationRecord,
  type NonceLaneCoordinationStore,
} from '@/core/signingEngine/nonce/NonceCoordinator';
import {
  SigningOperationIntent,
  SigningSessionIds,
} from '@/core/signingEngine/session/operationState/types';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const TEST_SENDER = `0x${'22'.repeat(20)}` as const;

function createFakeEvmNonceBackend(calls: unknown[], nonce = 7n): EvmNonceBackend {
  return {
    fetchChainNonce: async (input) => {
      calls.push({ fn: 'fetchChainNonce', input });
      return nonce;
    },
  };
}

function createFakeNearClient(calls: unknown[], nonce = 30): NearClient {
  return {
    viewAccessKey: async (accountId: string, publicKey: string) => {
      calls.push({ fn: 'near.viewAccessKey', accountId, publicKey });
      return {
        nonce,
        permission: 'FullAccess' as const,
        block_height: 1,
        block_hash: 'test-access-key-block',
      };
    },
    viewBlock: async () => {
      calls.push({ fn: 'near.viewBlock' });
      return {
        header: {
          height: 1,
          hash: 'test-block',
        },
      };
    },
  } as unknown as NearClient;
}

function createOperation() {
  return {
    operationId: SigningSessionIds.signingOperation('op-nonce-coordinator'),
    operationFingerprint: SigningSessionIds.signingOperationFingerprint(
      'sha256:test-nonce-coordinator',
    ),
    intent: SigningOperationIntent.TransactionSign,
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

function createNearLane(): NearNonceLane {
  return {
    family: 'near',
    networkKey: 'near-testnet',
    accountId: 'nonce-coordinator.testnet',
    publicKey: 'ed25519:test-key',
  };
}

function createMemoryNonceLaneCoordinationStore(
  initial?: NonceLaneCoordinationRecord[],
): { store: NonceLaneCoordinationStore; records: Map<string, NonceLaneCoordinationRecord> } {
  const records = new Map<string, NonceLaneCoordinationRecord>();
  for (const record of initial || []) {
    records.set(`${record.laneKey}:${record.leaseId}`, { ...record });
  }
  let lockTail = Promise.resolve();
  const store: NonceLaneCoordinationStore = {
    readLane: async (laneKey) =>
      Array.from(records.values()).filter((record) => record.laneKey === laneKey),
    readAll: async (input) =>
      Array.from(records.values()).filter(
        (record) => !input?.accountId || record.accountId === input.accountId,
      ),
    upsert: async (record) => {
      records.set(`${record.laneKey}:${record.leaseId}`, { ...record });
    },
    remove: async ({ laneKey, leaseId }) => {
      records.delete(`${laneKey}:${leaseId}`);
    },
    clearForAccount: async (accountId) => {
      for (const [key, record] of records.entries()) {
        if (record.accountId === accountId) records.delete(key);
      }
    },
    clearAll: async () => records.clear(),
    pruneExpired: async (nowMs) => {
      for (const [key, record] of records.entries()) {
        if (record.expiresAtMs <= nowMs) records.delete(key);
      }
    },
    withLock: async (_input, task) => {
      const previous = lockTail;
      let release!: () => void;
      lockTail = new Promise<void>((resolve) => {
        release = resolve;
      });
      await previous;
      try {
        return await task();
      } finally {
        release();
      }
    },
  };
  return { store, records };
}

function createEvmCoordinationRecord(
  overrides?: Partial<Extract<NonceLaneCoordinationRecord, { family: 'evm' }>>,
): NonceLaneCoordinationRecord {
  const lane = createLane();
  return {
    v: 1,
    leaseId: 'durable-lease-1',
    laneKey: [
      'evm',
      lane.chain,
      lane.networkKey,
      String(lane.chainId),
      lane.sender.toLowerCase(),
      String(lane.nonceKey),
    ].join(':'),
    family: 'evm',
    chainTarget: thresholdEcdsaChainTargetFromChainFamily({
      chain: lane.chain,
      chainId: lane.chainId,
      networkSlug: lane.networkKey,
    }),
    networkKey: lane.networkKey,
    sender: lane.sender,
    nonceKey: String(lane.nonceKey),
    accountId: lane.accountId,
    nonce: '7',
    state: 'broadcast_accepted',
    operationId: String(createOperation().operationId),
    operationFingerprint: String(createOperation().operationFingerprint),
    reservedAtMs: 1_000,
    expiresAtMs: 10_000,
    updatedAtMs: 1_000,
    ...overrides,
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
      evmNonceBackend: createFakeEvmNonceBackend(calls),
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
      fn: 'fetchChainNonce',
      input: {
        chain: 'tempo',
        networkKey: 'tempo:42431',
        chainId: 42_431,
        sender: TEST_SENDER,
        nonceKey: 3n,
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
    expect(calls).toHaveLength(1);
  });

  test('carries lease metadata through managed nonce snapshots', async () => {
    const calls: unknown[] = [];
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls),
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
      walletId: reservation.walletId,
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

  test('reserves and releases multi-nonce NEAR leases through the coordinator', async () => {
    const calls: unknown[] = [];
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls),
      nearClient: createFakeNearClient(calls),
      now: () => 2_000,
      leaseTtlMs: 10_000,
    });
    const operation = {
      ...createOperation(),
      chainFamily: 'near' as const,
    };
    const { leases } = await coordinator.reserveNearContext({
      lane: createNearLane(),
      operation,
      count: 3,
    });
    const lease = leases[0]!;

    expect(lease).toMatchObject({
      nonce: '31',
      state: 'reserved',
      reservedAtMs: 2_000,
      expiresAtMs: 12_000,
      txIndex: 0,
    });
    expect(lease.batchId).toContain('nonce-batch-v1:near:');
    expect(leases.map((entry) => String(entry.nonce))).toEqual(['31', '32', '33']);
    expect(calls).toEqual([
      {
        fn: 'near.viewAccessKey',
        accountId: 'nonce-coordinator.testnet',
        publicKey: 'ed25519:test-key',
      },
      { fn: 'near.viewBlock' },
    ]);

    for (const nonceLease of leases) {
      await coordinator.release({
        leaseId: nonceLease.leaseId,
        operationId: operation.operationId,
        reason: 'cancelled',
      });
    }
  });

  test('reserves NEAR transaction context and leases under one coordinator lane operation', async () => {
    const calls: unknown[] = [];
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls),
      now: () => 2_500,
      leaseTtlMs: 10_000,
    });
    const operation = {
      ...createOperation(),
      chainFamily: 'near' as const,
    };

    const result = await coordinator.reserveNearContext({
      lane: createNearLane(),
      operation,
      count: 2,
      fetchContext: async () => {
        calls.push({ fn: 'near.fetchContext' });
        return {
          nearPublicKeyStr: 'ed25519:test-key',
          accessKeyInfo: {
            nonce: 30n,
            permission: 'FullAccess',
            block_height: 1,
            block_hash: 'test-access-key-block',
          },
          nextNonce: '31',
          txBlockHeight: '2000',
          txBlockHash: 'h2000',
        };
      },
    });

    expect(result.context.nextNonce).toBe('31');
    expect(result.leases.map((lease) => String(lease.nonce))).toEqual(['31', '32']);
    expect(calls).toEqual([{ fn: 'near.fetchContext' }]);
  });

  test('marks a NEAR lease signed with operation binding', async () => {
    const calls: unknown[] = [];
    const traces: unknown[] = [];
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls),
      now: () => 3_000,
      onTrace: (event) => traces.push(event),
    });
    const operation = {
      ...createOperation(),
      chainFamily: 'near' as const,
    };
    const { leases } = await coordinator.reserveNearContext({
      lane: createNearLane(),
      operation,
      count: 2,
      fetchContext: async () => ({
        nearPublicKeyStr: 'ed25519:test-key',
        accessKeyInfo: {
          nonce: 30n,
          permission: 'FullAccess',
          block_height: 1,
          block_hash: 'test-access-key-block',
        },
        nextNonce: '31',
        txBlockHeight: '2000',
        txBlockHash: 'h2000',
      }),
    });
    const lease = leases[0]!;

    await expect(
      coordinator.markSigned({
        leaseId: lease.leaseId,
        operationId: SigningSessionIds.signingOperation('op-other'),
      }),
    ).rejects.toThrow('operation mismatch');

    await coordinator.markSigned({
      leaseId: lease.leaseId,
      operationId: operation.operationId,
    });

    expect(traces).toContainEqual(
      expect.objectContaining({
        event: 'nonce_lease_signed',
        previousState: 'reserved',
        nextState: 'signed',
      }),
    );
    await expect(
      coordinator.release({
        leaseId: lease.leaseId,
        operationId: operation.operationId,
        reason: 'signing_failed',
      }),
    ).rejects.toThrow('illegal nonce lease transition');
  });

  test('routes finalized NEAR leases through coordinator-owned NEAR chain refresh', async () => {
    const calls: unknown[] = [];
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls),
      nearClient: createFakeNearClient(calls, 31),
      now: () => 4_000,
    });
    const operation = {
      ...createOperation(),
      chainFamily: 'near' as const,
    };
    const { leases } = await coordinator.reserveNearContext({
      lane: createNearLane(),
      operation,
      count: 1,
      fetchContext: async () => ({
        nearPublicKeyStr: 'ed25519:test-key',
        accessKeyInfo: {
          nonce: 30n,
          permission: 'FullAccess',
          block_height: 1,
          block_hash: 'test-access-key-block',
        },
        nextNonce: '31',
        txBlockHeight: '2000',
        txBlockHash: 'h2000',
      }),
    });
    const lease = leases[0]!;

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

    expect(calls.at(-1)).toMatchObject({
      fn: 'near.viewAccessKey',
      accountId: 'nonce-coordinator.testnet',
      publicKey: 'ed25519:test-key',
    });
  });

  test('expires reserved leases and releases backend reservations before reuse', async () => {
    const calls: unknown[] = [];
    const traces: unknown[] = [];
    let nowMs = 1_000;
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls),
      now: () => nowMs,
      leaseTtlMs: 50,
      onTrace: (event) => traces.push(event),
    });
    const operation = createOperation();
    const lease = await coordinator.reserve({
      lane: createLane(),
      operation,
    });

    nowMs = 1_051;
    const expired = await coordinator.expireLeases({
      accountId: 'nonce-coordinator.testnet',
    });

    expect(expired).toHaveLength(1);
    expect(expired[0]).toMatchObject({
      leaseId: lease.leaseId,
      state: 'expired',
    });
    expect(calls).toHaveLength(1);
    expect(traces).toContainEqual(
      expect.objectContaining({
        event: 'nonce_lease_expired',
        previousState: 'reserved',
        nextState: 'expired',
      }),
    );
  });

  test('expires signed EVM leases through rejected release plus lane reconciliation', async () => {
    const calls: unknown[] = [];
    const traces: unknown[] = [];
    let nowMs = 1_000;
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls),
      now: () => nowMs,
      leaseTtlMs: 10_000,
      signedLeaseTtlMs: 25,
      onTrace: (event) => traces.push(event),
    });
    const operation = createOperation();
    const lease = await coordinator.reserve({
      lane: createLane(),
      operation,
    });

    nowMs = 1_010;
    await coordinator.markSigned({
      leaseId: lease.leaseId,
      operationId: operation.operationId,
      signedTxHash: 'signed-tx-hash',
    });
    expect(coordinator.getDiagnostics().leasesByState.signed).toBe(1);

    nowMs = 1_036;
    const expired = await coordinator.expireLeases({
      accountId: 'nonce-coordinator.testnet',
    });

    expect(expired).toHaveLength(1);
    expect(expired[0]).toMatchObject({
      leaseId: lease.leaseId,
      state: 'signed_lease_expired',
    });
    expect(calls.slice(-1)).toEqual([
      expect.objectContaining({
        fn: 'fetchChainNonce',
        input: expect.objectContaining({
          chain: 'tempo',
          networkKey: 'tempo:42431',
        }),
      }),
    ]);
    expect(traces).toContainEqual(
      expect.objectContaining({
        event: 'nonce_lease_expired',
        previousState: 'signed',
        nextState: 'signed_lease_expired',
        reason: 'signed_lease_ttl_elapsed',
      }),
    );
    expect(traces).toContainEqual(
      expect.objectContaining({
        event: 'nonce_lane_reconciled',
      }),
    );
  });

  test('serializes EVM-family nonce reservations through same-origin lane locks', async () => {
    const calls: unknown[] = [];
    const lockKeys: string[] = [];
    let activeLocks = 0;
    let maxActiveLocks = 0;
    let lockTail = Promise.resolve();
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls),
      sameOriginLock: {
        async withLock(key, task) {
          const previous = lockTail;
          let release!: () => void;
          lockTail = new Promise<void>((resolve) => {
            release = resolve;
          });
          await previous;
          lockKeys.push(key);
          activeLocks += 1;
          maxActiveLocks = Math.max(maxActiveLocks, activeLocks);
          try {
            return await task();
          } finally {
            activeLocks -= 1;
            release();
          }
        },
      },
    });

    const lane = createLane();
    const leases = await Promise.all([
      coordinator.reserve({ lane, operation: createOperation() }),
      coordinator.reserve({
        lane,
        operation: {
          ...createOperation(),
          operationId: SigningSessionIds.signingOperation('op-nonce-coordinator-2'),
        },
      }),
      coordinator.reserve({
        lane,
        operation: {
          ...createOperation(),
          operationId: SigningSessionIds.signingOperation('op-nonce-coordinator-3'),
        },
      }),
    ]);

    expect(lockKeys).toHaveLength(3);
    expect(lockKeys.every((key) => key.startsWith('nonce-coordinator:evm:tempo:'))).toBe(true);
    expect(maxActiveLocks).toBe(1);
    expect(leases.map((lease) => String(lease.nonce))).toEqual(['7', '8', '9']);
    expect(calls).toHaveLength(1);
  });

  test('shares active EVM-family nonce leases across coordinator instances in one origin', async () => {
    const callsA: unknown[] = [];
    const callsB: unknown[] = [];
    const records = new Map<string, any>();
    const leaseStore = {
      readLane: async (laneKey: string) =>
        Array.from(records.values()).filter((record) => record.laneKey === laneKey),
      readAll: async () => Array.from(records.values()),
      upsert: async (record: any) => {
        records.set(`${record.laneKey}:${record.leaseId}`, { ...record });
      },
      remove: async ({ laneKey, leaseId }: { laneKey: string; leaseId: string }) => {
        records.delete(`${laneKey}:${leaseId}`);
      },
      clearForAccount: async (accountId: string) => {
        for (const [key, record] of records.entries()) {
          if (record.accountId === accountId) records.delete(key);
        }
      },
      clearAll: async () => records.clear(),
      pruneExpired: async (nowMs: number) => {
        for (const [key, record] of records.entries()) {
          if (record.expiresAtMs <= nowMs) records.delete(key);
        }
      },
    };
    let lockTail = Promise.resolve();
    const sameOriginLock = {
      async withLock<T>(_key: string, task: () => Promise<T>): Promise<T> {
        const previous = lockTail;
        let release!: () => void;
        lockTail = new Promise<void>((resolve) => {
          release = resolve;
        });
        await previous;
        try {
          return await task();
        } finally {
          release();
        }
      },
    };
    const coordinatorA = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(callsA),
      sameOriginLock,
      nonceLaneCoordinationStore: leaseStore,
      now: () => 1_000,
    });
    const coordinatorB = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(callsB),
      sameOriginLock,
      nonceLaneCoordinationStore: leaseStore,
      now: () => 1_010,
    });
    const lane = createLane();

    const first = await coordinatorA.reserve({ lane, operation: createOperation() });
    const second = await coordinatorB.reserve({
      lane,
      operation: {
        ...createOperation(),
        operationId: SigningSessionIds.signingOperation('op-other-tab'),
      },
    });

    expect(String(first.nonce)).toBe('7');
    expect(String(second.nonce)).toBe('8');
    expect(records.size).toBe(2);
    expect(callsA).toHaveLength(1);
    expect(callsB).toHaveLength(1);
  });

  test('uses durable store locking when Web Locks are unavailable', async () => {
    const callsA: unknown[] = [];
    const callsB: unknown[] = [];
    const { store, records } = createMemoryNonceLaneCoordinationStore();
    const coordinatorA = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(callsA),
      sameOriginLock: null,
      nonceLaneCoordinationStore: store,
      now: () => 1_000,
    });
    const coordinatorB = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(callsB),
      sameOriginLock: null,
      nonceLaneCoordinationStore: store,
      now: () => 1_010,
    });
    const lane = createLane();

    const [first, second] = await Promise.all([
      coordinatorA.reserve({ lane, operation: createOperation() }),
      coordinatorB.reserve({
        lane,
        operation: {
          ...createOperation(),
          operationId: SigningSessionIds.signingOperation('op-durable-lock-other-tab'),
        },
      }),
    ]);

    expect([String(first.nonce), String(second.nonce)].sort()).toEqual(['7', '8']);
    expect(records.size).toBe(2);
  });

  test('prunes expired durable EVM records before reservation', async () => {
    const calls: unknown[] = [];
    const { store, records } = createMemoryNonceLaneCoordinationStore([
      createEvmCoordinationRecord({
        leaseId: 'expired-durable-lease',
        nonce: '7',
        state: 'reserved',
        expiresAtMs: Date.now() - 1,
      }),
    ]);
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls, 7n),
      sameOriginLock: null,
      nonceLaneCoordinationStore: store,
    });

    const lease = await coordinator.reserve({ lane: createLane(), operation: createOperation() });

    expect(lease.nonce.toString()).toBe('7');
    expect(Array.from(records.values())).toHaveLength(1);
    expect(Array.from(records.values())[0]?.leaseId).toBe(lease.leaseId);
  });

  test('startup recovery clears finalized EVM durable broadcast leases', async () => {
    const calls: unknown[] = [];
    const { store, records } = createMemoryNonceLaneCoordinationStore([
      createEvmCoordinationRecord({
        leaseId: 'durable-broadcast',
        nonce: '7',
        state: 'broadcast_accepted',
      }),
    ]);
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls, 8n),
      sameOriginLock: null,
      nonceLaneCoordinationStore: store,
      now: () => 2_000,
    });

    await coordinator.recoverDurableLeases({ accountId: 'nonce-coordinator.testnet' });

    expect(records.size).toBe(0);
    expect(calls).toEqual([
      expect.objectContaining({
        fn: 'fetchChainNonce',
      }),
    ]);
  });

  test('same-origin durable NEAR leases prevent overlapping batch reservations', async () => {
    const { store, records } = createMemoryNonceLaneCoordinationStore();
    const lane = createNearLane();
    const coordinatorA = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend([]),
      sameOriginLock: null,
      nonceLaneCoordinationStore: store,
    });
    const coordinatorB = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend([]),
      sameOriginLock: null,
      nonceLaneCoordinationStore: store,
    });

    const first = await coordinatorA.reserveNearContext({
      lane,
      operation: { ...createOperation(), chainFamily: 'near' as const },
      count: 2,
      fetchContext: async () => ({
        nearPublicKeyStr: lane.publicKey,
        accessKeyInfo: {
          nonce: 30n,
          permission: 'FullAccess',
          block_height: 1,
          block_hash: 'test-access-key-block',
        },
        nextNonce: '31',
        txBlockHeight: '2000',
        txBlockHash: 'h2000',
      }),
    });
    const second = await coordinatorB.reserveNearContext({
      lane,
      operation: {
        ...createOperation(),
        operationId: SigningSessionIds.signingOperation('op-near-durable-other-tab'),
        chainFamily: 'near' as const,
      },
      count: 1,
      fetchContext: async () => ({
        nearPublicKeyStr: lane.publicKey,
        accessKeyInfo: {
          nonce: 30n,
          permission: 'FullAccess',
          block_height: 1,
          block_hash: 'test-access-key-block',
        },
        nextNonce: '31',
        txBlockHeight: '2000',
        txBlockHash: 'h2000',
      }),
    });

    expect(first.leases.map((lease) => String(lease.nonce))).toEqual(['31', '32']);
    expect(second.leases.map((lease) => String(lease.nonce))).toEqual(['33']);
    expect(records.size).toBe(3);
  });

  test('account clear removes durable nonce lease records', async () => {
    const calls: unknown[] = [];
    const { store, records } = createMemoryNonceLaneCoordinationStore();
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls),
      sameOriginLock: null,
      nonceLaneCoordinationStore: store,
    });

    await coordinator.reserve({ lane: createLane(), operation: createOperation() });
    expect(records.size).toBe(1);

    coordinator.clearForAccount('nonce-coordinator.testnet');
    await Promise.resolve();

    expect(records.size).toBe(0);
  });

  test('emits a degraded coordination warning when durable store access fails', async () => {
    const calls: unknown[] = [];
    const traces: unknown[] = [];
    const warnings: unknown[][] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args);
    };
    const failingStore: NonceLaneCoordinationStore = {
      readLane: async () => {
        throw new Error('indexeddb failed');
      },
      readAll: async () => [],
      upsert: async () => {
        throw new Error('indexeddb failed');
      },
      remove: async () => undefined,
      clearForAccount: async () => undefined,
      clearAll: async () => undefined,
      pruneExpired: async () => undefined,
      withLock: async (_input, task) => await task(),
    };
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls),
      sameOriginLock: null,
      nonceLaneCoordinationStore: failingStore,
      onTrace: (event) => traces.push(event),
    });

    try {
      await coordinator.reserve({ lane: createLane(), operation: createOperation() });
    } finally {
      console.warn = originalWarn;
    }

    expect(traces).toContainEqual(
      expect.objectContaining({
        event: 'nonce_coordination_degraded',
        degradation: expect.objectContaining({
          reason: 'durable_store_error',
          fallback: 'in_runtime_lock',
        }),
      }),
    );
    expect(warnings).toContainEqual([
      '[NonceCoordinator] nonce coordination degraded',
      expect.objectContaining({ reason: 'durable_store_error' }),
    ]);
    expect(coordinator.getDiagnostics().coordinationWarnings).toEqual([
      expect.objectContaining({
        reason: 'durable_store_error',
        fallback: 'in_runtime_lock',
      }),
    ]);
  });

  test('emits an alert and console warning for repeated dropped/replaced EVM outcomes', async () => {
    const calls: unknown[] = [];
    const traces: unknown[] = [];
    const warnings: unknown[][] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args);
    };
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls),
      droppedReplacedAlertThreshold: 2,
      onTrace: (event) => traces.push(event),
    });
    const lane = createLane();

    try {
      for (let index = 0; index < 2; index += 1) {
        const operation = {
          ...createOperation(),
          operationId: SigningSessionIds.signingOperation(`op-dropped-alert-${index}`),
        };
        const lease = await coordinator.reserve({ lane, operation });
        await coordinator.markSigned({ leaseId: lease.leaseId, operationId: operation.operationId });
        await coordinator.markBroadcastAccepted({
          leaseId: lease.leaseId,
          operationId: operation.operationId,
          txHash: `0x${String(index + 1).padStart(64, '0')}`,
        });
        await coordinator.markDroppedOrReplaced({
          leaseId: lease.leaseId,
          operationId: operation.operationId,
          reason: 'dropped',
        });
      }
    } finally {
      console.warn = originalWarn;
    }

    expect(traces).toContainEqual(
      expect.objectContaining({
        event: 'nonce_lane_alert',
        alert: expect.objectContaining({
          kind: 'repeated_dropped_or_replaced',
          reason: 'dropped',
          count: 2,
        }),
      }),
    );
    expect(warnings[0]?.[0]).toBe(
      '[NonceCoordinator] repeated EVM-family dropped/replaced nonce outcomes',
    );
  });

  test('clearForAccount clears EVM lanes and full active NEAR access-key state', async () => {
    const calls: unknown[] = [];
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls),
      now: () => 5_000,
    });
    const operation = {
      ...createOperation(),
      chainFamily: 'near' as const,
    };
    const lane = createNearLane();
    await coordinator.reserveNearContext({
      lane,
      operation,
      count: 1,
      fetchContext: async () => ({
        nearPublicKeyStr: 'ed25519:test-key',
        accessKeyInfo: {
          nonce: 30n,
          permission: 'FullAccess',
          block_height: 1,
          block_hash: 'test-access-key-block',
        },
        nextNonce: '31',
        txBlockHeight: '2000',
        txBlockHash: 'h2000',
      }),
    });

    coordinator.clearForAccount('nonce-coordinator.testnet');

    expect(coordinator.getActiveNearPublicKey()).toBeNull();
    expect(coordinator.getDiagnostics().leaseCount).toBe(0);
    expect(calls).toEqual([]);
    await expect(
      coordinator.reserveBatch({
        lane,
        operation: {
          ...operation,
          operationId: SigningSessionIds.signingOperation('op-after-clear'),
        },
        count: 1,
      }),
    ).rejects.toThrow('NEAR transaction context not available');
  });

  test('emits redacted aggregate metrics for stale in-flight nonce leases', async () => {
    const calls: unknown[] = [];
    const traces: unknown[] = [];
    let nowMs = 1_000;
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls),
      now: () => nowMs,
      leaseTtlMs: 100,
      signedLeaseTtlMs: 50,
      onTrace: (event) => traces.push(event),
    });
    const operation = createOperation();
    const lease = await coordinator.reserve({
      lane: createLane(),
      operation,
    });

    nowMs = 1_030;
    await coordinator.markSigned({
      leaseId: lease.leaseId,
      operationId: operation.operationId,
    });
    nowMs = 1_090;

    const diagnostics = coordinator.getDiagnostics({
      accountId: 'nonce-coordinator.testnet',
      emitMetrics: true,
    });

    expect(diagnostics.metrics).toMatchObject({
      accountId: 'nonce-coordinator.testnet',
      leaseCount: 1,
      laneCount: 1,
      oldestLeaseAgeMs: 90,
      oldestInFlightLeaseAgeMs: 90,
      staleInFlightLeaseCount: 1,
      staleInFlightLaneCount: 1,
      reservedLeaseCount: 0,
      signedLeaseCount: 1,
    });
    expect(traces.at(-1)).toMatchObject({
      event: 'nonce_coordinator_metrics',
      accountId: 'nonce-coordinator.testnet',
      metrics: expect.objectContaining({
        staleInFlightLeaseCount: 1,
        staleInFlightLaneCount: 1,
      }),
    });
  });

  test('emits redacted outcome metrics for release, reconcile, and dropped lanes', async () => {
    const calls: unknown[] = [];
    const traces: unknown[] = [];
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls),
      onTrace: (event) => traces.push(event),
    });
    const lane = createLane();
    const releaseOperation = createOperation();
    const releaseLease = await coordinator.reserve({
      lane,
      operation: releaseOperation,
    });
    await coordinator.release({
      leaseId: releaseLease.leaseId,
      operationId: releaseOperation.operationId,
      reason: 'cancelled',
    });

    const droppedOperation = {
      ...createOperation(),
      operationId: SigningSessionIds.signingOperation('op-outcome-dropped'),
    };
    const droppedLease = await coordinator.reserve({
      lane,
      operation: droppedOperation,
    });
    await coordinator.markSigned({
      leaseId: droppedLease.leaseId,
      operationId: droppedOperation.operationId,
    });
    await coordinator.markBroadcastAccepted({
      leaseId: droppedLease.leaseId,
      operationId: droppedOperation.operationId,
      txHash: `0x${'33'.repeat(32)}`,
    });
    await coordinator.markDroppedOrReplaced({
      leaseId: droppedLease.leaseId,
      operationId: droppedOperation.operationId,
      reason: 'dropped',
    });
    await coordinator.reconcile({ lane });

    const diagnostics = coordinator.getDiagnostics({
      accountId: 'nonce-coordinator.testnet',
      emitMetrics: true,
    });

    expect(diagnostics.metrics.outcomes).toMatchObject({
      droppedCount: 1,
      replacedCount: 0,
      releasedCount: 1,
      reconciledCount: 1,
      releaseReasons: { cancelled: 1 },
      reconcileReasons: { manual: 1 },
    });
    expect(traces.at(-1)).toMatchObject({
      event: 'nonce_coordinator_metrics',
      metrics: expect.objectContaining({
        outcomes: expect.objectContaining({
          droppedCount: 1,
          releasedCount: 1,
          reconciledCount: 1,
        }),
      }),
    });
  });

  test('clearAll clears every coordinator lane and same-origin lease state', async () => {
    const calls: unknown[] = [];
    const coordinator = createNonceCoordinator({
      evmNonceBackend: createFakeEvmNonceBackend(calls),
      now: () => 6_000,
    });
    const operation = createOperation();
    const evmLease = await coordinator.reserve({
      lane: createLane(),
      operation,
    });
    await coordinator.reserveNearContext({
      lane: createNearLane(),
      operation: {
        ...operation,
        operationId: SigningSessionIds.signingOperation('op-clear-all-near'),
        chainFamily: 'near' as const,
      },
      count: 1,
      fetchContext: async () => ({
        nearPublicKeyStr: 'ed25519:test-key',
        accessKeyInfo: {
          nonce: 30n,
          permission: 'FullAccess',
          block_height: 1,
          block_hash: 'test-access-key-block',
        },
        nextNonce: '31',
        txBlockHeight: '2000',
        txBlockHash: 'h2000',
      }),
    });

    coordinator.clearAll();

    expect(calls).toEqual([
      expect.objectContaining({
        fn: 'fetchChainNonce',
      }),
    ]);
    expect(coordinator.getDiagnostics()).toMatchObject({
      leaseCount: 0,
      laneCount: 0,
      near: {
        hasContext: false,
        reservedNonceCount: 0,
      },
    });
    await expect(
      coordinator.release({
        leaseId: evmLease.leaseId,
        operationId: operation.operationId,
        reason: 'cancelled',
      }),
    ).rejects.toThrow('nonce lease not found');
  });
});
