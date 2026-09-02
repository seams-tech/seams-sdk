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

function keyPathForIndexedDB(keyPath: string | readonly string[]): string | string[] {
  return typeof keyPath === 'string' ? keyPath : [...keyPath];
}

function createCanonicalStore(
  db: IDBPDatabase | IDBDatabase,
  definition: SeamsWalletStoreDefinition,
): void {
  const store = db.createObjectStore(definition.store, {
    keyPath: keyPathForIndexedDB(definition.keyPath),
  });
  for (const index of definition.indexes) {
    store.createIndex(index.name, keyPathForIndexedDB(index.keyPath), { unique: index.unique });
  }
}

export function upgradeSeamsWalletDBSchema(db: IDBPDatabase | IDBDatabase): void {
  for (const storeName of Array.from(db.objectStoreNames)) {
    db.deleteObjectStore(storeName);
  }
  for (const definition of SEAMS_WALLET_SCHEMA_MANIFEST) {
    createCanonicalStore(db, definition);
  }
}
