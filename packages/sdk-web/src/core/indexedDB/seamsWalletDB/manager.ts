import { openDB, type IDBPDatabase } from 'idb';
import {
  SEAMS_WALLET_DB_CONFIG,
  upgradeSeamsWalletDBSchema,
  type SeamsWalletDBConfig,
} from './schema';
import { SEAMS_WALLET_DB_NAME, type SeamsWalletStoreName } from '../schemaNames';
import { deleteObsoleteStandaloneWalletDatabases } from './obsoleteDatabases';

export type SeamsWalletTransactionMode = 'readonly' | 'readwrite';

export type SeamsWalletTransactionContext = {
  db: IDBPDatabase;
  tx: any;
  store<Name extends SeamsWalletStoreName>(name: Name): any;
};

const INDEXED_DB_BLOCKED_OPEN_TIMEOUT_MS = 3_000;
const INDEXED_DB_OPEN_TIMEOUT_MS = 8_000;
const INDEXED_DB_TRANSACTION_TIMEOUT_MS = 8_000;

function seamsWalletDbOpenBlockedError(dbName: string): Error {
  return new Error(
    `[SeamsWalletDBManager] IndexedDB open is blocked for ${dbName}. Close other tabs using this app and retry.`,
  );
}

function indexedDbTimeoutError(message: string): Error {
  return new Error(message);
}

async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  error: Error,
  onTimeout?: () => void,
): Promise<T> {
  let settled = false;
  let timeout: ReturnType<typeof setTimeout> | null = null;
  const timeoutPromise = new Promise<T>((_resolve, reject) => {
    timeout = setTimeout(() => {
      if (settled) return;
      onTimeout?.();
      reject(error);
    }, ms);
  });
  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    settled = true;
    if (timeout) clearTimeout(timeout);
  }
}

async function runIndexedDbTransactionTask<T>(
  context: SeamsWalletTransactionContext,
  task: (context: SeamsWalletTransactionContext) => Promise<T> | T,
): Promise<T> {
  const result = await task(context);
  await context.tx.done;
  return result;
}

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
    if (!this.dbPromise) {
      const dbName = this.config.dbName;
      const dbVersion = this.config.dbVersion;
      console.info('[SeamsWalletDBManager] Opening IndexedDB.', { dbName, dbVersion });
      let blockedTimer: ReturnType<typeof setTimeout> | null = null;
      let rejectBlockedOpen: ((error: Error) => void) | null = null;
      const blockedOpen = new Promise<IDBPDatabase>((_resolve, reject) => {
        rejectBlockedOpen = reject;
      });
      const openPromise = openDB(dbName, dbVersion, {
        upgrade(db, _oldVersion, _newVersion, tx) {
          upgradeSeamsWalletDBSchema(db, tx);
        },
        blocked() {
          console.warn('[SeamsWalletDBManager] IndexedDB open is blocked.', {
            dbName,
            dbVersion,
          });
          blockedTimer = setTimeout(() => {
            rejectBlockedOpen?.(seamsWalletDbOpenBlockedError(dbName));
          }, INDEXED_DB_BLOCKED_OPEN_TIMEOUT_MS);
        },
        blocking() {
          console.warn('[SeamsWalletDBManager] IndexedDB connection is blocking an upgrade.', {
            dbName,
            dbVersion,
          });
        },
        terminated() {
          console.warn('[SeamsWalletDBManager] IndexedDB connection has been terminated.', {
            dbName,
            dbVersion,
          });
        },
      });
      const guardedOpen = withTimeout(
        Promise.race([openPromise, blockedOpen]).finally(() => {
          if (blockedTimer) clearTimeout(blockedTimer);
        }),
        INDEXED_DB_OPEN_TIMEOUT_MS,
        indexedDbTimeoutError(
          `[SeamsWalletDBManager] IndexedDB open timed out for ${dbName}. Close other tabs using this app and retry.`,
        ),
      );
      this.dbPromise = guardedOpen.catch((error) => {
        this.dbPromise = null;
        void openPromise.then((db) => db.close()).catch(() => undefined);
        throw error;
      });
    }
    const db = await this.dbPromise;
    if (this.config.dbName === SEAMS_WALLET_DB_NAME) {
      await deleteObsoleteStandaloneWalletDatabases();
    }
    return db;
  }

  async runTransaction<T>(
    stores: readonly SeamsWalletStoreName[],
    mode: SeamsWalletTransactionMode,
    task: (context: SeamsWalletTransactionContext) => Promise<T> | T,
  ): Promise<T> {
    const db = await withTimeout(
      this.getDB(),
      INDEXED_DB_OPEN_TIMEOUT_MS,
      indexedDbTimeoutError(
        `[SeamsWalletDBManager] IndexedDB connection timed out for ${this.config.dbName}. Close other tabs using this app and retry.`,
      ),
    );
    console.info('[SeamsWalletDBManager] IndexedDB transaction connection ready.', {
      dbName: this.config.dbName,
      mode,
      stores,
    });
    const tx = db.transaction([...stores], mode);
    console.info('[SeamsWalletDBManager] IndexedDB transaction created.', {
      dbName: this.config.dbName,
      mode,
      stores,
    });
    const context: SeamsWalletTransactionContext = {
      db,
      tx,
      store(name) {
        return tx.objectStore(name);
      },
    };
    try {
      return await withTimeout(
        runIndexedDbTransactionTask(context, task),
        INDEXED_DB_TRANSACTION_TIMEOUT_MS,
        indexedDbTimeoutError(
          `[SeamsWalletDBManager] IndexedDB transaction timed out for ${this.config.dbName}. Close other tabs using this app and retry.`,
        ),
        () => {
          try {
            tx.abort();
          } catch {}
        },
      );
    } catch (error) {
      try {
        tx.abort();
      } catch {}
      await tx.done.catch(() => undefined);
      throw error;
    }
  }
}
