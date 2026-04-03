import type { IDBPDatabase } from 'idb';

export interface PasskeyClientDBConfig {
  dbName: string;
  dbVersion: number;
  appStateStore: string;
  profileAuthenticatorStore: string;
  profilesStore: string;
  chainAccountsStore: string;
  accountSignersStore: string;
  signerOpsOutboxStore: string;
  recoveryEmailStore: string;
  migrationQuarantineStore: string;
}

export const SIGNER_OPS_OUTBOX_STATUS_NEXT_ATTEMPT_INDEX = 'status_nextAttemptAt' as const;

export const DB_CONFIG: PasskeyClientDBConfig = {
  dbName: 'PasskeyClientDB',
  dbVersion: 27, // v27: full IndexedDB reset on upgrade; canonical stores only
  appStateStore: 'appState',
  profileAuthenticatorStore: 'profileAuthenticators',
  profilesStore: 'profiles',
  chainAccountsStore: 'chainAccounts',
  accountSignersStore: 'accountSigners',
  signerOpsOutboxStore: 'signerOpsOutbox',
  recoveryEmailStore: 'recoveryEmailsV2',
  migrationQuarantineStore: 'migrationQuarantine',
} as const;

export const LAST_PROFILE_STATE_APP_STATE_KEY = 'lastProfileState' as const;
export const DB_MULTICHAIN_MIGRATION_STATE_KEY = 'migration.dbMultichainSchema.v1' as const;
export const DB_MULTICHAIN_MIGRATION_LOCK_KEY = 'migration.dbMultichainSchema.v1.lock' as const;
export const DB_MULTICHAIN_MIGRATION_CHECKPOINTS_KEY =
  'migration.dbMultichainSchema.v1.checkpoints' as const;
export const DB_MULTICHAIN_MIGRATION_LOCK_NAME =
  'passkey-client-db-multichain-migration-v1' as const;
export const DB_MULTICHAIN_MIGRATION_LOCK_TTL_MS = 2 * 60_000;
export const DB_MULTICHAIN_MIGRATION_HEARTBEAT_INTERVAL_MS = 5_000;
export const DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION = 8 as const;
const DB_FULL_RESET_ON_UPGRADE_VERSION = 27 as const;

const OBSOLETE_CLIENT_STORES_TO_DROP = [
  'users',
  'authenticators',
  'derivedAddresses',
  'derivedAddressesV2',
  'recoveryEmails',
] as const;

export function upgradePasskeyClientDBSchema(
  db: IDBPDatabase,
  oldVersion: number,
  transaction: any,
): void {
  if (oldVersion > 0 && oldVersion < DB_FULL_RESET_ON_UPGRADE_VERSION) {
    // Breaking cutover: wipe all legacy/mixed-shape data and recreate canonical stores.
    for (const storeName of Array.from(db.objectStoreNames)) {
      db.deleteObjectStore(storeName);
    }
  }

  if (!db.objectStoreNames.contains(DB_CONFIG.appStateStore)) {
    db.createObjectStore(DB_CONFIG.appStateStore, { keyPath: 'key' });
  }
  {
    const profileAuthenticators = !db.objectStoreNames.contains(DB_CONFIG.profileAuthenticatorStore)
      ? db.createObjectStore(DB_CONFIG.profileAuthenticatorStore, {
          keyPath: ['profileId', 'deviceNumber', 'credentialId'],
        })
      : transaction.objectStore(DB_CONFIG.profileAuthenticatorStore);
    try {
      profileAuthenticators.createIndex('profileId', 'profileId', { unique: false });
    } catch {}
    try {
      profileAuthenticators.createIndex('credentialId', 'credentialId', { unique: false });
    } catch {}
    try {
      profileAuthenticators.createIndex('profileId_credentialId', ['profileId', 'credentialId'], {
        unique: false,
      });
    } catch {}
    try {
      profileAuthenticators.createIndex('profileId_deviceNumber', ['profileId', 'deviceNumber'], {
        unique: false,
      });
    } catch {}
  }

  {
    const profiles = !db.objectStoreNames.contains(DB_CONFIG.profilesStore)
      ? db.createObjectStore(DB_CONFIG.profilesStore, { keyPath: 'profileId' })
      : transaction.objectStore(DB_CONFIG.profilesStore);
    try {
      profiles.createIndex('updatedAt', 'updatedAt', { unique: false });
    } catch {}
  }

  {
    const chainAccounts = !db.objectStoreNames.contains(DB_CONFIG.chainAccountsStore)
      ? db.createObjectStore(DB_CONFIG.chainAccountsStore, {
          keyPath: ['profileId', 'chainIdKey', 'accountAddress'],
        })
      : transaction.objectStore(DB_CONFIG.chainAccountsStore);
    try {
      chainAccounts.createIndex('profileId', 'profileId', { unique: false });
    } catch {}
    try {
      chainAccounts.createIndex('chainIdKey', 'chainIdKey', { unique: false });
    } catch {}
    try {
      chainAccounts.createIndex('chainIdKey_accountAddress', ['chainIdKey', 'accountAddress'], {
        unique: false,
      });
    } catch {}
    try {
      chainAccounts.createIndex('profileId_chainIdKey', ['profileId', 'chainIdKey'], { unique: false });
    } catch {}
  }

  {
    const accountSigners = !db.objectStoreNames.contains(DB_CONFIG.accountSignersStore)
      ? db.createObjectStore(DB_CONFIG.accountSignersStore, {
          keyPath: ['chainIdKey', 'accountAddress', 'signerId'],
        })
      : transaction.objectStore(DB_CONFIG.accountSignersStore);
    try {
      accountSigners.createIndex('profileId', 'profileId', { unique: false });
    } catch {}
    try {
      accountSigners.createIndex('profileId_chainIdKey', ['profileId', 'chainIdKey'], {
        unique: false,
      });
    } catch {}
    try {
      accountSigners.createIndex('chainIdKey_accountAddress', ['chainIdKey', 'accountAddress'], {
        unique: false,
      });
    } catch {}
    try {
      accountSigners.createIndex(
        'chainIdKey_accountAddress_status',
        ['chainIdKey', 'accountAddress', 'status'],
        { unique: false },
      );
    } catch {}
  }

  {
    const signerOpsOutbox = !db.objectStoreNames.contains(DB_CONFIG.signerOpsOutboxStore)
      ? db.createObjectStore(DB_CONFIG.signerOpsOutboxStore, { keyPath: 'opId' })
      : transaction.objectStore(DB_CONFIG.signerOpsOutboxStore);
    try {
      signerOpsOutbox.createIndex('status', 'status', { unique: false });
    } catch {}
    try {
      signerOpsOutbox.createIndex('nextAttemptAt', 'nextAttemptAt', { unique: false });
    } catch {}
    try {
      signerOpsOutbox.createIndex(
        SIGNER_OPS_OUTBOX_STATUS_NEXT_ATTEMPT_INDEX,
        ['status', 'nextAttemptAt'],
        { unique: false },
      );
    } catch {}
    try {
      signerOpsOutbox.createIndex('idempotencyKey', 'idempotencyKey', { unique: true });
    } catch {}
    try {
      signerOpsOutbox.createIndex('chainIdKey_accountAddress', ['chainIdKey', 'accountAddress'], {
        unique: false,
      });
    } catch {}
  }

  {
    const recoveryEmails = !db.objectStoreNames.contains(DB_CONFIG.recoveryEmailStore)
      ? db.createObjectStore(DB_CONFIG.recoveryEmailStore, {
          keyPath: ['profileId', 'hashHex'],
        })
      : transaction.objectStore(DB_CONFIG.recoveryEmailStore);
    try {
      recoveryEmails.createIndex('profileId', 'profileId', { unique: false });
    } catch {}
  }

  {
    const quarantine = !db.objectStoreNames.contains(DB_CONFIG.migrationQuarantineStore)
      ? db.createObjectStore(DB_CONFIG.migrationQuarantineStore, {
          keyPath: 'quarantineId',
          autoIncrement: true,
        })
      : transaction.objectStore(DB_CONFIG.migrationQuarantineStore);
    try {
      quarantine.createIndex('sourceStore', 'sourceStore', { unique: false });
    } catch {}
    try {
      quarantine.createIndex('detectedAt', 'detectedAt', { unique: false });
    } catch {}
  }

  if (oldVersion < 24) {
    for (const storeName of OBSOLETE_CLIENT_STORES_TO_DROP) {
      if (db.objectStoreNames.contains(storeName)) {
        db.deleteObjectStore(storeName);
      }
    }
  }
}
