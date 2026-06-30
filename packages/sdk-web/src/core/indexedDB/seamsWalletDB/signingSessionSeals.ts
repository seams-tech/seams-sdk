import { unwrap } from 'idb';
import { seamsWalletDB } from '../singletons';
import {
  SEAMS_WALLET_INDEXES,
  SEAMS_WALLET_STORES,
} from '../schemaNames';

const SIGNING_SESSION_SEALS_STORE_NAME = SEAMS_WALLET_STORES.signingSessionSeals;
const SIGNING_SESSION_RESTORE_LEASES_STORE_NAME =
  SEAMS_WALLET_STORES.signingSessionRestoreLeases;

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

async function getSigningSessionSealsDb(): Promise<IDBDatabase | null> {
  if (seamsWalletDB.isDisabled()) return null;
  try {
    return unwrap(await seamsWalletDB.getDB()) as IDBDatabase;
  } catch {
    return null;
  }
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
    const db = await getSigningSessionSealsDb();
    if (!db) return [];
    const tx = db.transaction(SIGNING_SESSION_SEALS_STORE_NAME, 'readonly');
    const store = tx.objectStore(SIGNING_SESSION_SEALS_STORE_NAME);
    const entries = await collectAllRawSealedRecordEntriesFromStore(store);
    await transactionDone(tx).catch(() => undefined);
    return entries;
  }

  async collectRawSealedRecordEntriesByThresholdSessionId(
    thresholdSessionId: string,
  ): Promise<StoredRawSealedRecordEntry[]> {
    const db = await getSigningSessionSealsDb();
    if (!db) return [];
    const tx = db.transaction(SIGNING_SESSION_SEALS_STORE_NAME, 'readonly');
    const store = tx.objectStore(SIGNING_SESSION_SEALS_STORE_NAME);
    const entries = await collectRawSealedRecordEntriesByThresholdSessionIdFromStore(
      store,
      thresholdSessionId,
    );
    await transactionDone(tx).catch(() => undefined);
    return entries;
  }

  async putSealedRecord(row: Record<string, unknown>): Promise<void> {
    const db = await getSigningSessionSealsDb();
    if (!db) return;
    const tx = db.transaction(SIGNING_SESSION_SEALS_STORE_NAME, 'readwrite');
    tx.objectStore(SIGNING_SESSION_SEALS_STORE_NAME).put(row);
    await transactionDone(tx).catch(() => undefined);
  }

  async replaceSealedRecord(args: {
    row: Record<string, unknown>;
    staleStoreKeys: string[];
  }): Promise<void> {
    const db = await getSigningSessionSealsDb();
    if (!db) return;
    const tx = db.transaction(SIGNING_SESSION_SEALS_STORE_NAME, 'readwrite');
    const store = tx.objectStore(SIGNING_SESSION_SEALS_STORE_NAME);
    for (const storeKey of args.staleStoreKeys) {
      store.delete(storeKey);
    }
    store.put(args.row);
    await transactionDone(tx).catch(() => undefined);
  }

  async deleteSealedRecords(primaryKeys: unknown[]): Promise<void> {
    if (!primaryKeys.length) return;
    const db = await getSigningSessionSealsDb();
    if (!db) return;
    const tx = db.transaction(SIGNING_SESSION_SEALS_STORE_NAME, 'readwrite');
    const store = tx.objectStore(SIGNING_SESSION_SEALS_STORE_NAME);
    for (const primaryKey of primaryKeys) {
      store.delete(primaryKey as IDBValidKey);
    }
    await transactionDone(tx).catch(() => undefined);
  }

  async deleteRestoreLease(leaseKey: string): Promise<void> {
    const db = await getSigningSessionSealsDb();
    if (!db) return;
    const tx = db.transaction(SIGNING_SESSION_RESTORE_LEASES_STORE_NAME, 'readwrite');
    tx.objectStore(SIGNING_SESSION_RESTORE_LEASES_STORE_NAME).delete(leaseKey);
    await transactionDone(tx).catch(() => undefined);
  }

  async deleteRestoreLeaseIf(args: {
    leaseKey: string;
    shouldDelete(rawLease: unknown): boolean;
  }): Promise<void> {
    const db = await getSigningSessionSealsDb();
    if (!db) return;
    const tx = db.transaction(SIGNING_SESSION_RESTORE_LEASES_STORE_NAME, 'readwrite');
    const store = tx.objectStore(SIGNING_SESSION_RESTORE_LEASES_STORE_NAME);
    const rawLease = await requestToPromise(store.get(args.leaseKey));
    if (args.shouldDelete(rawLease)) {
      store.delete(args.leaseKey);
    }
    await transactionDone(tx).catch(() => undefined);
  }

  async withRestoreLeaseTransaction<T>(
    thresholdSessionId: string,
    task: (tx: SigningSessionRestoreLeaseTransaction) => Promise<T> | T,
  ): Promise<T | null> {
    const db = await getSigningSessionSealsDb();
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
    }
  }

  async clearAll(): Promise<void> {
    const db = await getSigningSessionSealsDb();
    if (!db) return;
    const tx = db.transaction(
      [SIGNING_SESSION_SEALS_STORE_NAME, SIGNING_SESSION_RESTORE_LEASES_STORE_NAME],
      'readwrite',
    );
    tx.objectStore(SIGNING_SESSION_SEALS_STORE_NAME).clear();
    tx.objectStore(SIGNING_SESSION_RESTORE_LEASES_STORE_NAME).clear();
    await transactionDone(tx).catch(() => undefined);
  }
}

export const signingSessionSealsRepository = new SigningSessionSealsRepository();
