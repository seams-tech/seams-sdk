import type { UnifiedIndexedDBManager } from './unifiedIndexedDBManager';
import type {
  NonceLaneCoordinationRecord,
  NonceLaneCoordinationStore,
} from '../signingEngine/nonce/NonceCoordinator';

type IndexedDBNonceLaneCoordinationStoreDeps = {
  indexedDB: UnifiedIndexedDBManager;
};

export function createIndexedDBNonceLaneCoordinationStore(
  deps: IndexedDBNonceLaneCoordinationStoreDeps,
): NonceLaneCoordinationStore {
  return {
    readLane: async (laneKey) =>
      (await deps.indexedDB.readNonceLaneLeaseRecords(laneKey)).flatMap((record) => {
        const parsed = toNonceLaneCoordinationRecord(record);
        return parsed ? [parsed] : [];
      }),
    readAll: async (input) =>
      (await deps.indexedDB.listNonceLaneLeaseRecords(input)).flatMap((record) => {
        const parsed = toNonceLaneCoordinationRecord(record);
        return parsed ? [parsed] : [];
      }),
    upsert: async (record) => {
      await deps.indexedDB.upsertNonceLaneLeaseRecord({
        ...record,
        v: 1,
      });
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

function toNonceLaneCoordinationRecord(value: unknown): NonceLaneCoordinationRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const obj = value as Record<string, unknown>;
  if (Number(obj.v) !== 1) return null;
  const leaseId = normalizeString(obj.leaseId);
  const laneKey = normalizeString(obj.laneKey);
  const family = normalizeString(obj.family);
  const networkKey = normalizeString(obj.networkKey);
  const nonce = normalizeString(obj.nonce);
  const state = normalizeString(obj.state);
  const operationId = normalizeString(obj.operationId);
  const operationFingerprint = normalizeString(obj.operationFingerprint);
  const reservedAtMs = normalizeInteger(obj.reservedAtMs);
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  const updatedAtMs = normalizeInteger(obj.updatedAtMs);
  if (
    !leaseId ||
    !laneKey ||
    (family !== 'evm' && family !== 'near') ||
    !networkKey ||
    !/^\d+$/.test(nonce) ||
    (state !== 'reserved' && state !== 'signed' && state !== 'broadcast_accepted') ||
    !operationId ||
    !operationFingerprint ||
    reservedAtMs == null ||
    expiresAtMs == null ||
    updatedAtMs == null
  ) {
    return null;
  }

  const chain = normalizeString(obj.chain);
  const chainId = normalizeInteger(obj.chainId);
  const sender = normalizeString(obj.sender);
  const nonceKey = normalizeString(obj.nonceKey);
  const accountId = normalizeString(obj.accountId);
  const publicKey = normalizeString(obj.publicKey);
  const runtimeId = normalizeString(obj.runtimeId);
  const fencingToken = normalizeString(obj.fencingToken);
  const batchId = normalizeString(obj.batchId);
  const txIndex = normalizeInteger(obj.txIndex);

  if (family === 'evm') {
    if ((chain !== 'evm' && chain !== 'tempo') || chainId == null || !sender) return null;
  }
  if (family === 'near' && (!accountId || !publicKey)) return null;

  return {
    v: 1,
    leaseId,
    laneKey,
    family,
    ...(chain === 'evm' || chain === 'tempo' ? { chain } : {}),
    networkKey,
    ...(chainId != null ? { chainId } : {}),
    ...(sender ? { sender } : {}),
    ...(nonceKey ? { nonceKey } : {}),
    ...(accountId ? { accountId } : {}),
    ...(publicKey ? { publicKey } : {}),
    nonce,
    state,
    operationId,
    operationFingerprint,
    reservedAtMs,
    expiresAtMs,
    updatedAtMs,
    ...(runtimeId ? { runtimeId } : {}),
    ...(fencingToken ? { fencingToken } : {}),
    ...(batchId ? { batchId } : {}),
    ...(txIndex != null ? { txIndex } : {}),
  };
}

function normalizeString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizeInteger(value: unknown): number | null {
  const parsed = Math.floor(Number(value));
  return Number.isSafeInteger(parsed) ? parsed : null;
}
