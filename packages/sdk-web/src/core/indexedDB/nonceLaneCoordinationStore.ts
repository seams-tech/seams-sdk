import type { UnifiedIndexedDBManager } from './unifiedIndexedDBManager';
import type {
  NonceLaneCoordinationStore,
} from '../signingEngine/nonce/NonceCoordinator';
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
        const serialized: Extract<IndexedDBNonceLaneLeaseRecord, { family: 'evm' }> = {
          v: 1,
          laneKey: record.laneKey,
          leaseId: record.leaseId,
          networkKey: record.networkKey,
          nonce: record.nonce.toString(),
          state: record.state,
          operationId: record.operationId,
          operationFingerprint: record.operationFingerprint,
          reservedAtMs: record.reservedAtMs,
          expiresAtMs: record.expiresAtMs,
          updatedAtMs: record.updatedAtMs,
          family: 'evm',
          chainTarget: record.chainTarget,
          accountId: record.accountId,
          sender: record.sender,
        };
        if (record.runtimeId) serialized.runtimeId = record.runtimeId;
        if (record.fencingToken) serialized.fencingToken = record.fencingToken;
        if (record.batchId) serialized.batchId = record.batchId;
        if (Number.isSafeInteger(record.txIndex)) serialized.txIndex = record.txIndex;
        if (record.nonceKey != null) serialized.nonceKey = record.nonceKey.toString();
        await deps.indexedDB.upsertNonceLaneLeaseRecord(serialized);
        return;
      }

      const serialized: Extract<IndexedDBNonceLaneLeaseRecord, { family: 'near' }> = {
        v: 1,
        laneKey: record.laneKey,
        leaseId: record.leaseId,
        networkKey: record.networkKey,
        nonce: record.nonce.toString(),
        state: record.state,
        operationId: record.operationId,
        operationFingerprint: record.operationFingerprint,
        reservedAtMs: record.reservedAtMs,
        expiresAtMs: record.expiresAtMs,
        updatedAtMs: record.updatedAtMs,
        family: 'near',
        walletId: record.walletId,
        accountId: record.accountId,
        publicKey: record.publicKey,
      };
      if (record.runtimeId) serialized.runtimeId = record.runtimeId;
      if (record.fencingToken) serialized.fencingToken = record.fencingToken;
      if (record.batchId) serialized.batchId = record.batchId;
      if (Number.isSafeInteger(record.txIndex)) serialized.txIndex = record.txIndex;
      await deps.indexedDB.upsertNonceLaneLeaseRecord(serialized);
    },
    remove: async (input) => {
      await deps.indexedDB.removeNonceLaneLeaseRecord({ leaseId: input.leaseId });
    },
    clearForAccount: async (accountId) => {
      await deps.indexedDB.clearNonceLaneLeaseRecordsForAccount(accountId);
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
