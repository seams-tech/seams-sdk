import type { IDBPDatabase } from 'idb';
import {
  SEAMS_WALLET_DB_NAME,
  SEAMS_WALLET_SCHEMA_MANIFEST,
  type SeamsWalletStoreDefinition,
} from '../schemaNames';

export const SEAMS_WALLET_SCHEMA_VERSION = 17 as const;

export type SeamsWalletDBConfig = {
  dbName: string;
};

export const SEAMS_WALLET_DB_CONFIG: SeamsWalletDBConfig = {
  dbName: SEAMS_WALLET_DB_NAME,
} as const;

function keyPathForIndexedDB(keyPath: string | readonly string[]): string | string[] {
  return typeof keyPath === 'string' ? keyPath : [...keyPath];
}

function createStore(
  db: IDBPDatabase | IDBDatabase,
  definition: SeamsWalletStoreDefinition,
): void {
  const store = db.createObjectStore(definition.store, {
    keyPath: keyPathForIndexedDB(definition.keyPath),
  });

  for (const index of definition.indexes) {
    const keyPath = keyPathForIndexedDB(index.keyPath);
    store.createIndex(index.name, keyPath, { unique: index.unique });
  }
}

export function initializeSeamsWalletDBSchema(db: IDBPDatabase | IDBDatabase): void {
  for (const definition of SEAMS_WALLET_SCHEMA_MANIFEST) {
    createStore(db, definition);
  }
}
