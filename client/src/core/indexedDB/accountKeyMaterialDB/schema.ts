import type { IDBPDatabase } from 'idb';

export interface PasskeyAccountKeyMaterialDBConfig {
  dbName: string;
  dbVersion: number;
  storeName: string;
  storeKeyPath: string | string[];
}

export const DB_CONFIG: PasskeyAccountKeyMaterialDBConfig = {
  dbName: 'PasskeyAccountKeyMaterial',
  dbVersion: 11,
  storeName: 'keyMaterial',
  storeKeyPath: ['profileId', 'signerSlot', 'chainIdKey', 'keyKind'],
} as const;

function ensureStoreIndexes(store: any): void {
  try {
    store.createIndex('profileId_signerSlot', ['profileId', 'signerSlot'], {
      unique: false,
    });
  } catch {}
  try {
    store.createIndex('chainIdKey_keyKind', ['chainIdKey', 'keyKind'], { unique: false });
  } catch {}
  try {
    store.createIndex('publicKey', 'publicKey', { unique: false });
  } catch {}
}

export function upgradePasskeyAccountKeyMaterialDBSchema(
  db: IDBPDatabase,
  transaction: any,
): void {
  if (!db.objectStoreNames.contains(DB_CONFIG.storeName)) {
    const store = db.createObjectStore(DB_CONFIG.storeName, { keyPath: DB_CONFIG.storeKeyPath });
    ensureStoreIndexes(store);
  } else {
    try {
      const existing = transaction.objectStore(DB_CONFIG.storeName);
      ensureStoreIndexes(existing);
    } catch {}
  }
}
