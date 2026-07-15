import type { UnifiedIndexedDBManager } from './unifiedIndexedDBManager';
import type { NonceLaneCoordinationStore } from '../signingEngine/nonce/NonceCoordinator';
import { parseNonceLaneCoordinationRecord } from '../signingEngine/nonce/nonceCoordinationRecordBoundary';

type IndexedDBNonceLaneCoordinationStoreDeps = {
  indexedDB: UnifiedIndexedDBManager;
};

type IndexedDBNonceLaneLeaseRecord = Parameters<
  UnifiedIndexedDBManager['upsertNonceLaneLeaseRecord']
>[0];

export function createIndexedDBNonceLaneCoordinationStore(
  deps: IndexedDBNonceLaneCoordinationStoreDeps,
): NonceLaneCoordinationStore {
  return {
    readLane: async (laneKey) =>
      (await deps.indexedDB.readNonceLaneLeaseRecords(laneKey)).flatMap((record) => {
        const parsed = parseNonceLaneCoordinationRecord(record);
        return parsed.ok ? [parsed.parsed] : [];
      }),
    readAll: async (input) =>
      (await deps.indexedDB.listNonceLaneLeaseRecords(input)).flatMap((record) => {
        const parsed = parseNonceLaneCoordinationRecord(record);
        return parsed.ok ? [parsed.parsed] : [];
      }),
    readAllForRecovery: async (input) =>
      (await deps.indexedDB.listNonceLaneLeaseRecords(input)).map((record) =>
        parseNonceLaneCoordinationRecord(record),
      ),
    upsert: async (record) => {
      if (record.family === 'evm') {
        await deps.indexedDB.upsertNonceLaneLeaseRecord(serializeEvmCoordinationRecord(record));
        return;
      }

      await deps.indexedDB.upsertNonceLaneLeaseRecord(serializeNearCoordinationRecord(record));
    },
    remove: async (input) => {
      await deps.indexedDB.removeNonceLaneLeaseRecord({ leaseId: input.leaseId });
    },
    clearForWallet: async (walletId) => {
      await deps.indexedDB.clearNonceLaneLeaseRecordsForWallet(walletId);
    },
    clearAll: async () => {
      await deps.indexedDB.clearAllNonceLaneLeaseRecords();
    },
    pruneExpired: async (nowMs) => {
      await deps.indexedDB.pruneExpiredNonceLaneLeaseRecords(nowMs);
    },
    withLock: async (input, task) =>
      await deps.indexedDB.withNonceLaneCoordinationLock(
        {
          lockKey: input.lockKey,
          ownerId: input.ownerId,
          ...(input.ttlMs != null ? { ttlMs: input.ttlMs } : {}),
          ...(input.waitTimeoutMs != null ? { waitTimeoutMs: input.waitTimeoutMs } : {}),
        },
        task,
      ),
  };
}

type ParsedCoordinationRecord = Parameters<NonceLaneCoordinationStore['upsert']>[0];

function serializedRecordMetadata(record: ParsedCoordinationRecord): {
  runtimeId?: string;
  fencingToken?: string;
  batchId?: string;
  txIndex?: number;
} {
  return {
    ...(record.runtimeId ? { runtimeId: record.runtimeId } : {}),
    ...(record.fencingToken ? { fencingToken: record.fencingToken } : {}),
    ...(record.batchId ? { batchId: record.batchId } : {}),
    ...(typeof record.txIndex === 'number' && Number.isSafeInteger(record.txIndex)
      ? { txIndex: record.txIndex }
      : {}),
  };
}

function serializeEvmCoordinationRecord(
  record: Extract<ParsedCoordinationRecord, { family: 'evm' }>,
): Extract<IndexedDBNonceLaneLeaseRecord, { family: 'evm' }> {
  const common = {
    v: 1 as const,
    laneKey: record.laneKey,
    leaseId: record.leaseId,
    networkKey: record.networkKey,
    nonce: record.nonce.toString(),
    operationId: record.operationId,
    operationFingerprint: record.operationFingerprint,
    reservedAtMs: record.reservedAtMs,
    expiresAtMs: record.expiresAtMs,
    updatedAtMs: record.updatedAtMs,
    family: 'evm' as const,
    chainTarget: record.chainTarget,
    accountId: record.accountId,
    sender: record.sender,
    ...(record.nonceKey != null ? { nonceKey: record.nonceKey.toString() } : {}),
    ...serializedRecordMetadata(record),
  };
  switch (record.state) {
    case 'reserved':
    case 'signed':
      return { ...common, state: record.state };
    case 'broadcast_accepted':
      return { ...common, state: 'broadcast_accepted', txHash: record.txHash };
  }
}

function serializeNearCoordinationRecord(
  record: Extract<ParsedCoordinationRecord, { family: 'near' }>,
): Extract<IndexedDBNonceLaneLeaseRecord, { family: 'near' }> {
  const common = {
    v: 1 as const,
    laneKey: record.laneKey,
    leaseId: record.leaseId,
    networkKey: record.networkKey,
    nonce: record.nonce.toString(),
    operationId: record.operationId,
    operationFingerprint: record.operationFingerprint,
    reservedAtMs: record.reservedAtMs,
    expiresAtMs: record.expiresAtMs,
    updatedAtMs: record.updatedAtMs,
    family: 'near' as const,
    walletId: record.walletId,
    nearAccountId: record.nearAccountId,
    publicKey: record.publicKey,
    ...serializedRecordMetadata(record),
  };
  switch (record.state) {
    case 'reserved':
    case 'signed':
      return { ...common, state: record.state };
    case 'broadcast_accepted':
      return { ...common, state: 'broadcast_accepted', txHash: record.txHash };
  }
}
