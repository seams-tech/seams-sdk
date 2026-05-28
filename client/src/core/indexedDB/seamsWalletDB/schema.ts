import type { IDBPDatabase } from 'idb';
import {
  SEAMS_WALLET_DB_NAME,
  SEAMS_WALLET_DB_VERSION,
  SEAMS_WALLET_SCHEMA_MANIFEST,
  type SeamsWalletStoreDefinition,
} from '../schemaNames';

export type SeamsWalletDBConfig = {
  dbName: string;
  dbVersion: number;
};

export const SEAMS_WALLET_DB_CONFIG: SeamsWalletDBConfig = {
  dbName: SEAMS_WALLET_DB_NAME,
  dbVersion: SEAMS_WALLET_DB_VERSION,
} as const;

const OBSOLETE_STORE_NAMES = [
  'seams_wallet_auth_method_bindings',
  'seams_wallet_authenticators',
] as const;

function keyPathForIndexedDB(keyPath: string | readonly string[]): string | string[] {
  return typeof keyPath === 'string' ? keyPath : [...keyPath];
}

function createOrUpdateStore(
  db: IDBPDatabase | IDBDatabase,
  transaction: { objectStore(name: string): any } | null | undefined,
  definition: SeamsWalletStoreDefinition,
): void {
  const store = !db.objectStoreNames.contains(definition.store)
    ? db.createObjectStore(definition.store, { keyPath: keyPathForIndexedDB(definition.keyPath) })
    : transaction?.objectStore(definition.store);
  if (!store) return;

  for (const index of definition.indexes) {
    try {
      store.createIndex(index.name, keyPathForIndexedDB(index.keyPath), { unique: index.unique });
    } catch {}
  }
}

export function upgradeSeamsWalletDBSchema(
  db: IDBPDatabase | IDBDatabase,
  transaction?: { objectStore(name: string): any } | null,
): void {
  for (const storeName of OBSOLETE_STORE_NAMES) {
    if (db.objectStoreNames.contains(storeName)) {
      db.deleteObjectStore(storeName);
    }
  }
  for (const definition of SEAMS_WALLET_SCHEMA_MANIFEST) {
    createOrUpdateStore(db, transaction, definition);
  }
}
