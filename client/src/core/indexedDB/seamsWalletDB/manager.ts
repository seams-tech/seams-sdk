import { openDB, type IDBPDatabase } from 'idb';
import {
  SEAMS_WALLET_DB_CONFIG,
  upgradeSeamsWalletDBSchema,
  type SeamsWalletDBConfig,
} from './schema';
import {
  SEAMS_WALLET_DB_NAME,
  type SeamsWalletStoreName,
} from '../schemaNames';

export type SeamsWalletTransactionMode = 'readonly' | 'readwrite';

export type SeamsWalletTransactionContext = {
  db: IDBPDatabase;
  tx: any;
  store<Name extends SeamsWalletStoreName>(name: Name): any;
};

export class SeamsWalletDBManager {
  private config: SeamsWalletDBConfig;
  private dbPromise: Promise<IDBPDatabase> | null = null;
  private disabled = false;
  private legacyDatabaseNamesToDelete: readonly string[] = [];
  private legacyDatabaseCleanupPromise: Promise<void> | null = null;

  constructor(config: SeamsWalletDBConfig = SEAMS_WALLET_DB_CONFIG) {
    this.config = config;
  }

  getDbName(): string {
    return this.config.dbName;
  }

  setDbName(dbName: typeof SEAMS_WALLET_DB_NAME | `seams_test_wallet_${string}`): void {
    if (this.config.dbName === dbName) return;
    this.close();
    this.config = { ...this.config, dbName };
  }

  setDisabled(disabled: boolean): void {
    this.disabled = disabled;
    if (disabled) this.close();
  }

  setLegacyDatabaseCleanup(databaseNames: readonly string[]): void {
    this.legacyDatabaseNamesToDelete = [...databaseNames];
    this.legacyDatabaseCleanupPromise = null;
  }

  isDisabled(): boolean {
    return this.disabled;
  }

  close(): void {
    if (this.dbPromise) {
      void this.dbPromise.then((db) => db.close()).catch(() => undefined);
      this.dbPromise = null;
    }
  }

  async getDB(): Promise<IDBPDatabase> {
    if (this.disabled) {
      throw new Error('[SeamsWalletDBManager] IndexedDB is disabled in this environment.');
    }
    await this.deleteLegacyDatabasesBeforeOpen();
    if (!this.dbPromise) {
      this.dbPromise = openDB(this.config.dbName, this.config.dbVersion, {
        upgrade(db, _oldVersion, _newVersion, tx) {
          upgradeSeamsWalletDBSchema(db, tx);
        },
        blocked() {
          console.warn('seams_wallet IndexedDB connection is blocked.');
        },
        blocking() {
          console.warn('seams_wallet IndexedDB connection is blocking another connection.');
        },
        terminated() {
          console.warn('seams_wallet IndexedDB connection has been terminated.');
        },
      });
    }
    return await this.dbPromise;
  }

  private async deleteLegacyDatabasesBeforeOpen(): Promise<void> {
    if (this.legacyDatabaseNamesToDelete.length === 0) return;
    if (this.legacyDatabaseCleanupPromise) {
      await this.legacyDatabaseCleanupPromise;
      return;
    }
    this.legacyDatabaseCleanupPromise = Promise.all(
      this.legacyDatabaseNamesToDelete.map((databaseName) => deleteIndexedDBDatabase(databaseName)),
    ).then(() => undefined);
    await this.legacyDatabaseCleanupPromise;
  }

  async runTransaction<T>(
    stores: readonly SeamsWalletStoreName[],
    mode: SeamsWalletTransactionMode,
    task: (context: SeamsWalletTransactionContext) => Promise<T> | T,
  ): Promise<T> {
    const db = await this.getDB();
    const tx = db.transaction([...stores], mode);
    const context: SeamsWalletTransactionContext = {
      db,
      tx,
      store(name) {
        return tx.objectStore(name);
      },
    };
    try {
      const result = await task(context);
      await tx.done;
      return result;
    } catch (error) {
      try {
        tx.abort();
      } catch {}
      await tx.done.catch(() => undefined);
      throw error;
    }
  }
}

async function deleteIndexedDBDatabase(databaseName: string): Promise<void> {
  const indexedDBFactory = globalThis.indexedDB;
  if (!indexedDBFactory) return;
  await new Promise<void>((resolve) => {
    const request = indexedDBFactory.deleteDatabase(databaseName);
    request.onsuccess = () => resolve();
    request.onerror = () => {
      console.warn('[SeamsWalletDBManager] Legacy IndexedDB cleanup failed.', {
        databaseName,
        error: request.error?.message || request.error?.name || 'unknown_error',
      });
      resolve();
    };
    request.onblocked = () => {
      console.warn('[SeamsWalletDBManager] Legacy IndexedDB cleanup blocked.', { databaseName });
      resolve();
    };
  });
}
