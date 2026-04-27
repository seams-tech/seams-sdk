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
  nonceLaneLeasesStore: string;
  nonceLaneLocksStore: string;
}

export const SIGNER_OPS_OUTBOX_STATUS_NEXT_ATTEMPT_INDEX = 'status_nextAttemptAt' as const;

export const DB_CONFIG: PasskeyClientDBConfig = {
  dbName: 'PasskeyClientDB',
  dbVersion: 31,
  appStateStore: 'appState',
  profileAuthenticatorStore: 'profileAuthenticators',
  profilesStore: 'profiles',
  chainAccountsStore: 'chainAccounts',
  accountSignersStore: 'accountSigners',
  signerOpsOutboxStore: 'signerOpsOutbox',
  recoveryEmailStore: 'recoveryEmailsV2',
  nonceLaneLeasesStore: 'nonceLaneLeasesV1',
  nonceLaneLocksStore: 'nonceLaneLocksV1',
} as const;

export const LAST_PROFILE_STATE_APP_STATE_KEY = 'lastProfileState' as const;

export function upgradePasskeyClientDBSchema(
  db: IDBPDatabase,
  transaction: any,
): void {
  if (!db.objectStoreNames.contains(DB_CONFIG.appStateStore)) {
    db.createObjectStore(DB_CONFIG.appStateStore, { keyPath: 'key' });
  }
  {
    const profileAuthenticators = !db.objectStoreNames.contains(DB_CONFIG.profileAuthenticatorStore)
      ? db.createObjectStore(DB_CONFIG.profileAuthenticatorStore, {
          keyPath: ['profileId', 'signerSlot', 'credentialId'],
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
      profileAuthenticators.createIndex('profileId_signerSlot', ['profileId', 'signerSlot'], {
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
      chainAccounts.createIndex('profileId_chainIdKey', ['profileId', 'chainIdKey'], {
        unique: false,
      });
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
    const nonceLaneLeases = !db.objectStoreNames.contains(DB_CONFIG.nonceLaneLeasesStore)
      ? db.createObjectStore(DB_CONFIG.nonceLaneLeasesStore, { keyPath: 'leaseId' })
      : transaction.objectStore(DB_CONFIG.nonceLaneLeasesStore);
    try {
      nonceLaneLeases.createIndex('laneKey', 'laneKey', { unique: false });
    } catch {}
    try {
      nonceLaneLeases.createIndex('accountId', 'accountId', { unique: false });
    } catch {}
    try {
      nonceLaneLeases.createIndex('state', 'state', { unique: false });
    } catch {}
    try {
      nonceLaneLeases.createIndex('expiresAtMs', 'expiresAtMs', { unique: false });
    } catch {}
    try {
      nonceLaneLeases.createIndex('lane_state', ['laneKey', 'state'], { unique: false });
    } catch {}
    try {
      nonceLaneLeases.createIndex('account_expiresAt', ['accountId', 'expiresAtMs'], {
        unique: false,
      });
    } catch {}
  }

  {
    const nonceLaneLocks = !db.objectStoreNames.contains(DB_CONFIG.nonceLaneLocksStore)
      ? db.createObjectStore(DB_CONFIG.nonceLaneLocksStore, { keyPath: 'lockKey' })
      : transaction.objectStore(DB_CONFIG.nonceLaneLocksStore);
    try {
      nonceLaneLocks.createIndex('expiresAtMs', 'expiresAtMs', { unique: false });
    } catch {}
    try {
      nonceLaneLocks.createIndex('ownerId', 'ownerId', { unique: false });
    } catch {}
  }
}
