import type { IDBPDatabase } from 'idb';
import {
  SEAMS_WALLET_DB_NAME,
  SEAMS_WALLET_SCHEMA_MANIFEST,
  type SeamsWalletStoreDefinition,
} from '../schemaNames';

export const PRODUCTION_SEAMS_WALLET_SCHEMA_VERSION = 1 as const;

export type SeamsWalletSchemaPolicy =
  | {
      kind: 'development';
      version?: never;
    }
  | {
      kind: 'production';
      version: typeof PRODUCTION_SEAMS_WALLET_SCHEMA_VERSION;
    };

export type SeamsWalletDBConfig = {
  dbName: string;
  schemaPolicy: SeamsWalletSchemaPolicy;
};

function runtimeHostname(): string {
  return typeof location === 'undefined' ? '' : location.hostname;
}

export function resolveSeamsWalletSchemaPolicy(hostname: string): SeamsWalletSchemaPolicy {
  if (
    /localhost|127\.(?:0|[1-9]\d?)\.(?:0|[1-9]\d?)\.(?:0|[1-9]\d?)|\.local(?:host)?$/i.test(
      hostname,
    )
  ) {
    return { kind: 'development' };
  }
  return { kind: 'production', version: PRODUCTION_SEAMS_WALLET_SCHEMA_VERSION };
}

export const SEAMS_WALLET_DB_CONFIG: SeamsWalletDBConfig = {
  dbName: SEAMS_WALLET_DB_NAME,
  schemaPolicy: resolveSeamsWalletSchemaPolicy(runtimeHostname()),
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

export function applySeamsWalletDBSchemaUpgrade(
  db: IDBPDatabase | IDBDatabase,
  oldVersion: number,
): void {
  if (oldVersion === 0) {
    initializeSeamsWalletDBSchema(db);
    return;
  }
  throw new Error(`No IndexedDB schema migration is registered from production v${oldVersion}`);
}
