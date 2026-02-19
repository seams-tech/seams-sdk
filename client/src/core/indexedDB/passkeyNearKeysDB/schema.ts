import type { IDBPDatabase } from 'idb';

export interface PasskeyNearKeysDBConfig {
  dbName: string;
  dbVersion: number;
  storeName: string;
  storeKeyPath: string | string[];
}

export const DB_CONFIG: PasskeyNearKeysDBConfig = {
  dbName: 'PasskeyNearKeys',
  // v7: cutover to canonical key material store; drop obsolete keyMaterial store
  dbVersion: 7,
  storeName: 'keyMaterialV2',
  storeKeyPath: ['profileId', 'deviceNumber', 'chainId', 'keyKind'],
} as const;

function ensureStoreIndexes(store: any): void {
  try {
    store.createIndex(
      'profileId_deviceNumber',
      ['profileId', 'deviceNumber'],
      { unique: false },
    );
  } catch {}
  try {
    store.createIndex(
      'chainId_keyKind',
      ['chainId', 'keyKind'],
      { unique: false },
    );
  } catch {}
  try { store.createIndex('publicKey', 'publicKey', { unique: false }); } catch {}
}

export function upgradePasskeyNearKeysDBSchema(
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

  // Stable cutover completed: remove obsolete NEAR key store.
  try {
    if (db.objectStoreNames.contains('keyMaterial')) {
      db.deleteObjectStore('keyMaterial');
    }
  } catch {}
}
