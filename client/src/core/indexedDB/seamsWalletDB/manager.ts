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
    const result = await task(context);
    await tx.done;
    return result;
  }
}
