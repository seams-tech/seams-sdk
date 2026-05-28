import { seamsWalletDB } from '../singletons';
import { SEAMS_WALLET_INDEXES } from '../schemaNames';
import { upgradeSeamsWalletDBSchema } from './schema';
import {
  SIGNING_SESSION_RESTORE_LEASE_STORE_NAME,
  SIGNING_SESSION_SEAL_DB_NAME,
  SIGNING_SESSION_SEAL_DB_VERSION,
  SIGNING_SESSION_SEAL_STORE_NAME,
} from '@shared/utils/signingSessionSeal';

export const SIGNING_SESSION_SEALS_STORE_NAME = SIGNING_SESSION_SEAL_STORE_NAME;
export const SIGNING_SESSION_RESTORE_LEASES_STORE_NAME =
  SIGNING_SESSION_RESTORE_LEASE_STORE_NAME;

export type StoredRawSealedRecordEntry = {
  primaryKey: unknown;
  value: unknown;
};

export type SigningSessionRestoreLeaseTransaction = {
  entries: StoredRawSealedRecordEntry[];
  getRawRestoreLease(leaseKey: string): Promise<unknown>;
  putRestoreLease(row: Record<string, unknown>): void;
  abort(): void;
};

const SEALED_RECORD_THRESHOLD_SESSION_INDEXES = [
  SEAMS_WALLET_INDEXES.ed25519ThresholdSessionId,
  SEAMS_WALLET_INDEXES.ecdsaThresholdSessionId,
] as const;

function getIndexedDbSafe(): IDBFactory | null {
  if (seamsWalletDB.isDisabled()) return null;
  return (globalThis as { indexedDB?: IDBFactory }).indexedDB || null;
}

function requestToPromise<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('IndexedDB request failed'));
  });
}

function transactionDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(tx.error || new Error('IndexedDB transaction aborted'));
    tx.onerror = () => reject(tx.error || new Error('IndexedDB transaction failed'));
  });
}

function openSigningSessionSealsDb(): Promise<IDBDatabase | null> {
  const indexedDBFactory = getIndexedDbSafe();
  if (!indexedDBFactory) return Promise.resolve(null);
  return new Promise((resolve) => {
    let request: IDBOpenDBRequest;
    try {
      request = indexedDBFactory.open(SIGNING_SESSION_SEAL_DB_NAME, SIGNING_SESSION_SEAL_DB_VERSION);
    } catch {
      resolve(null);
      return;
    }
    request.onupgradeneeded = () => {
      upgradeSeamsWalletDBSchema(request.result, request.transaction);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => resolve(null);
    request.onblocked = () => resolve(null);
  });
}

function collectIndexedRawSealedRecordEntries(
  index: IDBIndex,
  thresholdSessionId: string,
): Promise<StoredRawSealedRecordEntry[]> {
  return new Promise((resolve, reject) => {
    const entries: StoredRawSealedRecordEntry[] = [];
    const request = index.openCursor(thresholdSessionId);
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) {
        resolve(entries);
        return;
      }
      entries.push({
        primaryKey: cursor.primaryKey,
        value: cursor.value,
      });
      cursor.continue();
    };
    request.onerror = () => reject(request.error || new Error('IndexedDB cursor failed'));
  });
}

function collectAllRawSealedRecordEntriesFromStore(
  store: IDBObjectStore,
): Promise<StoredRawSealedRecordEntry[]> {
  return new Promise((resolve, reject) => {
    const entries: StoredRawSealedRecordEntry[] = [];
    const request = store.openCursor();
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) {
        resolve(entries);
        return;
      }
      entries.push({
        primaryKey: cursor.primaryKey,
        value: cursor.value,
      });
      cursor.continue();
    };
    request.onerror = () => reject(request.error || new Error('IndexedDB cursor failed'));
  });
}

async function collectRawSealedRecordEntriesByThresholdSessionIdFromStore(
  store: IDBObjectStore,
  thresholdSessionId: string,
): Promise<StoredRawSealedRecordEntry[]> {
  const entriesByPrimaryKey = new Map<string, StoredRawSealedRecordEntry>();
  for (const indexName of SEALED_RECORD_THRESHOLD_SESSION_INDEXES) {
    try {
      const entries = await collectIndexedRawSealedRecordEntries(
        store.index(indexName),
        thresholdSessionId,
      );
      for (const entry of entries) {
        entriesByPrimaryKey.set(String(entry.primaryKey), entry);
      }
    } catch {}
  }
  if (entriesByPrimaryKey.size) return [...entriesByPrimaryKey.values()];
  return await collectAllRawSealedRecordEntriesFromStore(store).catch(() => []);
}

export class SigningSessionSealsRepository {
  async collectAllRawSealedRecordEntries(): Promise<StoredRawSealedRecordEntry[]> {
    const db = await openSigningSessionSealsDb();
    if (!db) return [];
    try {
      const tx = db.transaction(SIGNING_SESSION_SEALS_STORE_NAME, 'readonly');
      const store = tx.objectStore(SIGNING_SESSION_SEALS_STORE_NAME);
      const entries = await collectAllRawSealedRecordEntriesFromStore(store);
      await transactionDone(tx).catch(() => undefined);
      return entries;
    } finally {
      db.close();
    }
  }

  async collectRawSealedRecordEntriesByThresholdSessionId(
    thresholdSessionId: string,
  ): Promise<StoredRawSealedRecordEntry[]> {
    const db = await openSigningSessionSealsDb();
    if (!db) return [];
    try {
      const tx = db.transaction(SIGNING_SESSION_SEALS_STORE_NAME, 'readonly');
      const store = tx.objectStore(SIGNING_SESSION_SEALS_STORE_NAME);
      const entries = await collectRawSealedRecordEntriesByThresholdSessionIdFromStore(
        store,
        thresholdSessionId,
      );
      await transactionDone(tx).catch(() => undefined);
      return entries;
    } finally {
      db.close();
    }
  }

  async putSealedRecord(row: Record<string, unknown>): Promise<void> {
    const db = await openSigningSessionSealsDb();
    if (!db) return;
    try {
      const tx = db.transaction(SIGNING_SESSION_SEALS_STORE_NAME, 'readwrite');
      tx.objectStore(SIGNING_SESSION_SEALS_STORE_NAME).put(row);
      await transactionDone(tx).catch(() => undefined);
    } finally {
      db.close();
    }
  }

  async replaceSealedRecord(args: {
    row: Record<string, unknown>;
    staleStoreKeys: string[];
  }): Promise<void> {
    const db = await openSigningSessionSealsDb();
    if (!db) return;
    try {
      const tx = db.transaction(SIGNING_SESSION_SEALS_STORE_NAME, 'readwrite');
      const store = tx.objectStore(SIGNING_SESSION_SEALS_STORE_NAME);
      for (const storeKey of args.staleStoreKeys) {
        store.delete(storeKey);
      }
      store.put(args.row);
      await transactionDone(tx).catch(() => undefined);
    } finally {
      db.close();
    }
  }

  async deleteSealedRecords(primaryKeys: unknown[]): Promise<void> {
    if (!primaryKeys.length) return;
    const db = await openSigningSessionSealsDb();
    if (!db) return;
    try {
      const tx = db.transaction(SIGNING_SESSION_SEALS_STORE_NAME, 'readwrite');
      const store = tx.objectStore(SIGNING_SESSION_SEALS_STORE_NAME);
      for (const primaryKey of primaryKeys) {
        store.delete(primaryKey as IDBValidKey);
      }
      await transactionDone(tx).catch(() => undefined);
    } finally {
      db.close();
    }
  }

  async deleteRestoreLease(leaseKey: string): Promise<void> {
    const db = await openSigningSessionSealsDb();
    if (!db) return;
    try {
      const tx = db.transaction(SIGNING_SESSION_RESTORE_LEASES_STORE_NAME, 'readwrite');
      tx.objectStore(SIGNING_SESSION_RESTORE_LEASES_STORE_NAME).delete(leaseKey);
      await transactionDone(tx).catch(() => undefined);
    } finally {
      db.close();
    }
  }

  async deleteRestoreLeaseIf(args: {
    leaseKey: string;
    shouldDelete(rawLease: unknown): boolean;
  }): Promise<void> {
    const db = await openSigningSessionSealsDb();
    if (!db) return;
    try {
      const tx = db.transaction(SIGNING_SESSION_RESTORE_LEASES_STORE_NAME, 'readwrite');
      const store = tx.objectStore(SIGNING_SESSION_RESTORE_LEASES_STORE_NAME);
      const rawLease = await requestToPromise(store.get(args.leaseKey));
      if (args.shouldDelete(rawLease)) {
        store.delete(args.leaseKey);
      }
      await transactionDone(tx).catch(() => undefined);
    } finally {
      db.close();
    }
  }

  async withRestoreLeaseTransaction<T>(
    thresholdSessionId: string,
    task: (tx: SigningSessionRestoreLeaseTransaction) => Promise<T> | T,
  ): Promise<T | null> {
    const db = await openSigningSessionSealsDb();
    if (!db) return null;
    try {
      const idbTx = db.transaction(
        [SIGNING_SESSION_SEALS_STORE_NAME, SIGNING_SESSION_RESTORE_LEASES_STORE_NAME],
        'readwrite',
      );
      const sealStore = idbTx.objectStore(SIGNING_SESSION_SEALS_STORE_NAME);
      const leaseStore = idbTx.objectStore(SIGNING_SESSION_RESTORE_LEASES_STORE_NAME);
      const entries = await collectRawSealedRecordEntriesByThresholdSessionIdFromStore(
        sealStore,
        thresholdSessionId,
      );
      let abortRequested = false;
      const result = await task({
        entries,
        getRawRestoreLease: async (leaseKey) => await requestToPromise(leaseStore.get(leaseKey)),
        putRestoreLease: (row) => leaseStore.put(row),
        abort: () => {
          abortRequested = true;
        },
      });
      if (abortRequested) {
        idbTx.abort();
        return result;
      }
      await transactionDone(idbTx);
      return result;
    } catch {
      return null;
    } finally {
      db.close();
    }
  }

  async clearAll(): Promise<void> {
    const db = await openSigningSessionSealsDb();
    if (!db) return;
    try {
      const tx = db.transaction(
        [SIGNING_SESSION_SEALS_STORE_NAME, SIGNING_SESSION_RESTORE_LEASES_STORE_NAME],
        'readwrite',
      );
      tx.objectStore(SIGNING_SESSION_SEALS_STORE_NAME).clear();
      tx.objectStore(SIGNING_SESSION_RESTORE_LEASES_STORE_NAME).clear();
      await transactionDone(tx).catch(() => undefined);
    } finally {
      db.close();
    }
  }
}

export const signingSessionSealsRepository = new SigningSessionSealsRepository();
