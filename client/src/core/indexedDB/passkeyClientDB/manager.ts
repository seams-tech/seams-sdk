import { openDB, type IDBPDatabase } from 'idb';
import { normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import type { UndeployedSmartAccountSignerSet } from '@shared/utils';
import { toTrimmedString } from '@shared/utils/validation';
import type { AccountId } from '../../types/accountIds';
import type {
  AccountAddress,
  AccountModel,
  AccountModelCapabilities,
  AccountRef,
  AccountSignerRecord,
  AccountSignerStatus,
  AccountSignerType,
  ChainAccountRecord,
  ChainIdKey,
  DBConstraintErrorCode,
  EnqueueSignerOperationInput,
  IndexedDBEvent,
  LastProfileState,
  ProfileAuthenticatorRecord,
  ProfileContinuitySnapshot,
  ProfileId,
  ProfileRecord,
  ProfileRecoveryEmailRecord,
  SignerId,
  SignerMutationOptions,
  SignerOperationStatus,
  SignerOperationType,
  SignerOpOutboxRecord,
  UpsertAccountSignerInput,
  UpsertChainAccountInput,
  UpsertProfileInput,
  UserPreferences,
} from '../passkeyClientDB.types';
import {
  DB_CONFIG,
  DB_MULTICHAIN_MIGRATION_LOCK_KEY,
  DB_MULTICHAIN_MIGRATION_LOCK_NAME,
  DB_MULTICHAIN_MIGRATION_LOCK_TTL_MS,
  DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION,
  LAST_PROFILE_STATE_APP_STATE_KEY,
  type PasskeyClientDBConfig,
  upgradePasskeyClientDBSchema,
} from './schema';
import {
  createSignerOperationId as createSignerOperationIdValue,
  enqueueSignerOperationRecord,
  listSignerOperationRecords,
  setSignerOperationRecordStatus,
} from './outbox';
import { parseLastProfileState } from '../lastProfileState';
import {
  collectMigrationParity as collectMigrationParityValue,
  validateAndQuarantineInvariantViolations as validateAndQuarantineInvariantViolationsValue,
} from './invariants';
import {
  type DbMultichainMigrationLock,
  runMigrationsIfNeeded as runMigrationsIfNeededValue,
} from './migrations';
import { deleteProfileData as deleteProfileDataValue } from './profileCleanup';
import {
  normalizeIndexedDbAccountAddress as normalizeAccountAddress,
  normalizeIndexedDbAccountModel as normalizeAccountModel,
  normalizeIndexedDbChainIdKey as normalizeChainIdKey,
  normalizeLastUserScope,
} from '../normalization';

export type {
  AccountAddress,
  AccountModel,
  AccountModelCapabilities,
  AccountRef,
  AccountSignerRecord,
  AccountSignerStatus,
  AccountSignerType,
  ChainAccountRecord,
  ChainIdKey,
  DBConstraintErrorCode,
  EnqueueSignerOperationInput,
  IndexedDBEvent,
  LastProfileState,
  MigrationQuarantineRecord,
  ProfileAuthenticatorRecord,
  ProfileContinuitySnapshot,
  ProfileId,
  ProfileRecord,
  ProfileRecoveryEmailRecord,
  SignerId,
  SignerMutationOptions,
  SignerOperationStatus,
  SignerOperationType,
  SignerOpOutboxRecord,
  UpsertAccountSignerInput,
  UpsertChainAccountInput,
  UpsertProfileInput,
  UserPreferences,
} from '../passkeyClientDB.types';

interface AppStateEntry<T = unknown> {
  key: string;
  value: T;
}

function makeScopedAppStateKey(baseKey: string, scope: unknown): string | null {
  const normalized = normalizeLastUserScope(scope);
  if (!normalized) return null;
  return `${baseKey}::${normalized}`;
}

function normalizeUndeployedSmartAccountSignerSet(
  value: unknown,
): UndeployedSmartAccountSignerSet | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const raw = value as Record<string, unknown>;
  const ownerAddresses = Array.isArray(raw.ownerAddresses)
    ? raw.ownerAddresses.map((entry) => normalizeAccountAddress(entry)).filter((entry) => !!entry)
    : [];
  const activeOwnerAddresses = Array.isArray(raw.activeOwnerAddresses)
    ? raw.activeOwnerAddresses
        .map((entry) => normalizeAccountAddress(entry))
        .filter((entry) => !!entry)
    : [];
  const pendingOwnerAddresses = Array.isArray(raw.pendingOwnerAddresses)
    ? raw.pendingOwnerAddresses
        .map((entry) => normalizeAccountAddress(entry))
        .filter((entry) => !!entry)
    : [];
  const owners = Array.isArray(raw.owners)
    ? raw.owners
        .map((entry) => {
          if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
          const candidate = entry as Record<string, unknown>;
          const signerId = normalizeAccountAddress(candidate.signerId);
          const signerType = normalizeOptionalNonEmptyString(candidate.signerType) || 'threshold';
          const status = normalizeOptionalNonEmptyString(candidate.status);
          if (!signerId || (status !== 'active' && status !== 'pending')) return null;
          const deviceNumberRaw = Number(candidate.deviceNumber);
          const participantIds = Array.isArray(candidate.participantIds)
            ? candidate.participantIds
                .map((value) => Math.floor(Number(value)))
                .filter((value) => Number.isFinite(value) && value > 0)
            : [];
          return {
            signerId,
            signerType,
            status,
            ...(Number.isFinite(deviceNumberRaw) && deviceNumberRaw > 0
              ? { deviceNumber: Math.floor(deviceNumberRaw) }
              : {}),
            ...(normalizeOptionalNonEmptyString(candidate.relayerKeyId)
              ? { relayerKeyId: normalizeOptionalNonEmptyString(candidate.relayerKeyId)! }
              : {}),
            ...(normalizeOptionalNonEmptyString(candidate.thresholdEcdsaPublicKeyB64u)
              ? {
                  thresholdEcdsaPublicKeyB64u: normalizeOptionalNonEmptyString(
                    candidate.thresholdEcdsaPublicKeyB64u,
                  )!,
                }
              : {}),
            ...(participantIds.length ? { participantIds } : {}),
            ...(normalizeOptionalNonEmptyString(candidate.credentialIdB64u)
              ? { credentialIdB64u: normalizeOptionalNonEmptyString(candidate.credentialIdB64u)! }
              : {}),
            ...(normalizeOptionalNonEmptyString(candidate.rpId)
              ? { rpId: normalizeOptionalNonEmptyString(candidate.rpId)! }
              : {}),
          };
        })
        .filter(Boolean)
    : [];
  if (!ownerAddresses.length && !owners.length) return undefined;
  return {
    version: 'undeployed_smart_account_signer_set_v1',
    ownerAddresses,
    activeOwnerAddresses,
    pendingOwnerAddresses,
    owners: owners as UndeployedSmartAccountSignerSet['owners'],
  };
}

export class DBConstraintError extends Error {
  readonly code: DBConstraintErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(code: DBConstraintErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'DBConstraintError';
    this.code = code;
    this.details = details;
  }
}

const DEFAULT_ACCOUNT_MODEL_CAPABILITIES: AccountModelCapabilities = {
  supportsMultiSigner: true,
  supportsAddRemoveSigner: true,
  supportsSessionSigner: true,
  supportsRecoverySigner: true,
};

const ACCOUNT_MODEL_CAPABILITY_MATRIX: Record<string, AccountModelCapabilities> = {
  'near-native': {
    supportsMultiSigner: true,
    supportsAddRemoveSigner: true,
    supportsSessionSigner: true,
    supportsRecoverySigner: true,
  },
  erc4337: {
    supportsMultiSigner: true,
    supportsAddRemoveSigner: true,
    supportsSessionSigner: true,
    supportsRecoverySigner: true,
  },
  eoa: {
    supportsMultiSigner: false,
    supportsAddRemoveSigner: false,
    supportsSessionSigner: false,
    supportsRecoverySigner: false,
  },
  'tempo-native': {
    supportsMultiSigner: true,
    supportsAddRemoveSigner: true,
    supportsSessionSigner: true,
    supportsRecoverySigner: true,
  },
};

const ALLOWED_SIGNER_STATUS_TRANSITIONS: Record<
  AccountSignerStatus,
  ReadonlySet<AccountSignerStatus>
> = {
  pending: new Set<AccountSignerStatus>(['pending', 'active', 'revoked']),
  active: new Set<AccountSignerStatus>(['active', 'revoked']),
  revoked: new Set<AccountSignerStatus>(['revoked']),
};

export class PasskeyClientDBManager {
  private config: PasskeyClientDBConfig;
  private db: IDBPDatabase | null = null;
  private disabled = false;
  private eventListeners: Set<(event: IndexedDBEvent) => void> = new Set();
  private lastUserScope: string | null = null;

  constructor(config: PasskeyClientDBConfig = DB_CONFIG) {
    this.config = config;
  }

  getDbName(): string {
    return this.config.dbName;
  }

  setDbName(dbName: string): void {
    const next = toTrimmedString(dbName || '');
    if (!next || next === this.config.dbName) return;
    try {
      (this.db as any)?.close?.();
    } catch {}
    this.db = null;
    this.config = { ...this.config, dbName: next };
  }

  isDisabled(): boolean {
    return this.disabled;
  }

  setDisabled(disabled: boolean): void {
    const next = !!disabled;
    if (next === this.disabled) return;
    this.disabled = next;
    if (next) {
      try {
        (this.db as any)?.close?.();
      } catch {}
      this.db = null;
    }
  }

  // Events

  onChange(listener: (event: IndexedDBEvent) => void): () => void {
    this.eventListeners.add(listener);
    return () => {
      this.eventListeners.delete(listener);
    };
  }

  private emitEvent(event: IndexedDBEvent): void {
    this.eventListeners.forEach((listener) => {
      try {
        listener(event);
      } catch (error) {
        console.warn('[IndexedDBManager]: Error in event listener:', error);
      }
    });
  }

  private async getDB(): Promise<IDBPDatabase> {
    if (this.disabled) {
      throw new Error('[PasskeyClientDBManager] IndexedDB is disabled in this environment.');
    }
    if (this.db) {
      return this.db;
    }

    try {
      this.db = await openDB(this.config.dbName, this.config.dbVersion, {
        upgrade: (db, oldVersion, _newVersion, transaction): void => {
          upgradePasskeyClientDBSchema(db, oldVersion, transaction);
        },
        blocked() {
          console.warn('PasskeyClientDB connection is blocked.');
        },
        blocking() {
          console.warn('PasskeyClientDB connection is blocking another connection.');
        },
        terminated: () => {
          console.warn('PasskeyClientDB connection has been terminated.');
          this.db = null;
        },
      });

      // Post-open migrations (non-blocking)
      try {
        await this.runMigrationsIfNeeded(this.db);
      } catch {}
    } catch (err: any) {
      const msg = String(err?.message || '');
      if (err?.name === 'VersionError' || /less than the existing version/i.test(msg)) {
        // Mixed-version contexts (host/app) — open without version to adopt existing DB
        try {
          console.warn('PasskeyClientDB: opening existing DB without version due to VersionError');
          this.db = await openDB(this.config.dbName);
        } catch (e) {
          throw err;
        }
      } else {
        throw err;
      }
    }

    return this.db;
  }

  private async getAppStateFromDb<T = unknown>(
    db: IDBPDatabase,
    key: string,
  ): Promise<T | undefined> {
    const result = await db.get(DB_CONFIG.appStateStore, key);
    return result?.value as T | undefined;
  }

  private async setAppStateInDb<T = unknown>(
    db: IDBPDatabase,
    key: string,
    value: T,
  ): Promise<void> {
    const entry: AppStateEntry<T> = { key, value };
    await db.put(DB_CONFIG.appStateStore, entry);
  }

  private createMigrationOwnerId(): string {
    return typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `migration-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  private isMigrationLockFresh(
    lock: DbMultichainMigrationLock | null | undefined,
    now: number = Date.now(),
  ): boolean {
    if (!lock) return false;
    if (!lock.ownerTabId) return false;
    if (!Number.isFinite(lock.heartbeatAt)) return false;
    return now - lock.heartbeatAt <= DB_MULTICHAIN_MIGRATION_LOCK_TTL_MS;
  }

  private async tryAcquireMigrationLeaseInAppState(
    db: IDBPDatabase,
    ownerTabId: string,
    acquiredAt: number,
  ): Promise<boolean> {
    const now = Date.now();
    const tx = db.transaction(DB_CONFIG.appStateStore, 'readwrite');
    const existing = (await tx.store.get(DB_MULTICHAIN_MIGRATION_LOCK_KEY)) as
      | AppStateEntry<DbMultichainMigrationLock | null>
      | undefined;
    const lock = (existing?.value || null) as DbMultichainMigrationLock | null;
    if (lock && lock.ownerTabId !== ownerTabId && this.isMigrationLockFresh(lock, now)) {
      await tx.done;
      return false;
    }
    const nextLock: DbMultichainMigrationLock = {
      ownerTabId,
      acquiredAt:
        lock?.ownerTabId === ownerTabId && Number.isFinite(lock?.acquiredAt)
          ? lock.acquiredAt
          : acquiredAt,
      heartbeatAt: now,
    };
    await tx.store.put({ key: DB_MULTICHAIN_MIGRATION_LOCK_KEY, value: nextLock });
    await tx.done;
    return true;
  }

  private async refreshMigrationLeaseInAppState(
    db: IDBPDatabase,
    ownerTabId: string,
    acquiredAt: number,
  ): Promise<void> {
    await this.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_LOCK_KEY, {
      ownerTabId,
      acquiredAt,
      heartbeatAt: Date.now(),
    } satisfies DbMultichainMigrationLock);
  }

  private async clearMigrationLeaseInAppState(db: IDBPDatabase, ownerTabId: string): Promise<void> {
    const tx = db.transaction(DB_CONFIG.appStateStore, 'readwrite');
    const existing = (await tx.store.get(DB_MULTICHAIN_MIGRATION_LOCK_KEY)) as
      | AppStateEntry<DbMultichainMigrationLock | null>
      | undefined;
    const lock = (existing?.value || null) as DbMultichainMigrationLock | null;
    if (!lock || lock.ownerTabId === ownerTabId) {
      await tx.store.put({ key: DB_MULTICHAIN_MIGRATION_LOCK_KEY, value: null });
    }
    await tx.done;
  }

  private async tryRunWithNavigatorMigrationLock(
    runner: () => Promise<void>,
  ): Promise<'executed' | 'unavailable' | 'unsupported'> {
    const lockManager = typeof navigator !== 'undefined' ? (navigator as any)?.locks : null;
    if (!lockManager || typeof lockManager.request !== 'function') {
      return 'unsupported';
    }
    try {
      let executed = false;
      await lockManager.request(
        DB_MULTICHAIN_MIGRATION_LOCK_NAME,
        { mode: 'exclusive', ifAvailable: true },
        async (lock: unknown) => {
          if (!lock) return;
          executed = true;
          await runner();
        },
      );
      return executed ? 'executed' : 'unavailable';
    } catch (error) {
      console.warn(
        'PasskeyClientDB: navigator.locks coordination failed; falling back to app-state migration lock',
        error,
      );
      return 'unsupported';
    }
  }

  private async collectMigrationParity(db: IDBPDatabase) {
    return collectMigrationParityValue(db, {
      stores: {
        profileAuthenticatorStore: DB_CONFIG.profileAuthenticatorStore,
        profilesStore: DB_CONFIG.profilesStore,
        chainAccountsStore: DB_CONFIG.chainAccountsStore,
        accountSignersStore: DB_CONFIG.accountSignersStore,
        recoveryEmailStore: DB_CONFIG.recoveryEmailStore,
      },
    });
  }

  private async validateAndQuarantineInvariantViolations(
    db: IDBPDatabase,
  ): Promise<{ checked: number; violations: number; quarantined: number }> {
    return validateAndQuarantineInvariantViolationsValue(db, {
      stores: {
        appStateStore: DB_CONFIG.appStateStore,
        profileAuthenticatorStore: DB_CONFIG.profileAuthenticatorStore,
        profilesStore: DB_CONFIG.profilesStore,
        chainAccountsStore: DB_CONFIG.chainAccountsStore,
        accountSignersStore: DB_CONFIG.accountSignersStore,
        recoveryEmailStore: DB_CONFIG.recoveryEmailStore,
        migrationQuarantineStore: DB_CONFIG.migrationQuarantineStore,
      },
      schemaVersion: DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION,
      lastProfileStateAppStateKey: LAST_PROFILE_STATE_APP_STATE_KEY,
      parseLastProfileState,
      allowedSignerStatuses: ALLOWED_SIGNER_STATUS_TRANSITIONS.pending,
    });
  }

  private async runMigrationsIfNeeded(db: IDBPDatabase): Promise<void> {
    await runMigrationsIfNeededValue({
      db,
      getAppStateFromDb: (targetDb, key) => this.getAppStateFromDb(targetDb, key),
      setAppStateInDb: (targetDb, key, value) => this.setAppStateInDb(targetDb, key, value),
      createMigrationOwnerId: () => this.createMigrationOwnerId(),
      tryAcquireMigrationLeaseInAppState: (targetDb, ownerTabId, acquiredAt) =>
        this.tryAcquireMigrationLeaseInAppState(targetDb, ownerTabId, acquiredAt),
      refreshMigrationLeaseInAppState: (targetDb, ownerTabId, acquiredAt) =>
        this.refreshMigrationLeaseInAppState(targetDb, ownerTabId, acquiredAt),
      clearMigrationLeaseInAppState: (targetDb, ownerTabId) =>
        this.clearMigrationLeaseInAppState(targetDb, ownerTabId),
      tryRunWithNavigatorMigrationLock: (runner) => this.tryRunWithNavigatorMigrationLock(runner),
      collectMigrationParity: (targetDb) => this.collectMigrationParity(targetDb),
      validateAndQuarantineInvariantViolations: (targetDb) =>
        this.validateAndQuarantineInvariantViolations(targetDb),
    });
  }

  // App state

  async getAppState<T = unknown>(key: string): Promise<T | undefined> {
    const db = await this.getDB();
    const result = await db.get(DB_CONFIG.appStateStore, key);
    return result?.value as T | undefined;
  }

  async setAppState<T = unknown>(key: string, value: T): Promise<void> {
    const db = await this.getDB();
    const entry: AppStateEntry<T> = { key, value };
    await db.put(DB_CONFIG.appStateStore, entry);
  }

  // multichain records

  async getProfile(profileId: string): Promise<ProfileRecord | null> {
    const normalized = toTrimmedString(profileId || '');
    if (!normalized) return null;
    const db = await this.getDB();
    const rec = await db.get(DB_CONFIG.profilesStore, normalized);
    return (rec as ProfileRecord) || null;
  }

  async upsertProfile(input: UpsertProfileInput): Promise<ProfileRecord> {
    const profileId = toTrimmedString(input.profileId || '');
    if (!profileId) throw new Error('PasskeyClientDB: profileId is required');
    const db = await this.getDB();
    const now = Date.now();
    const existing = (await db.get(DB_CONFIG.profilesStore, profileId)) as
      | ProfileRecord
      | undefined;
    const passkeyCredential =
      input.passkeyCredential?.rawId ? input.passkeyCredential : existing?.passkeyCredential;
    const next: ProfileRecord = {
      profileId,
      defaultDeviceNumber: input.defaultDeviceNumber ?? existing?.defaultDeviceNumber ?? 1,
      ...(passkeyCredential ? { passkeyCredential } : {}),
      preferences: input.preferences ?? existing?.preferences,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    await db.put(DB_CONFIG.profilesStore, next);
    return next;
  }

  private getAccountModelCapabilities(accountModel: AccountModel): AccountModelCapabilities {
    const normalized = normalizeAccountModel(accountModel);
    return ACCOUNT_MODEL_CAPABILITY_MATRIX[normalized] || DEFAULT_ACCOUNT_MODEL_CAPABILITIES;
  }

  private assertSignerTypeCapability(
    signerType: AccountSignerType,
    accountModel: AccountModel,
    accountRef: { chainIdKey: string; accountAddress: string },
  ): void {
    const normalizedSignerType = toTrimmedString(signerType || '').toLowerCase();
    const capabilities = this.getAccountModelCapabilities(accountModel);
    if (normalizedSignerType === 'session' && !capabilities.supportsSessionSigner) {
      throw new DBConstraintError(
        'SESSION_SIGNER_NOT_SUPPORTED',
        `Signer type "session" is not supported for account model ${String(accountModel || '')}`,
        {
          signerType: normalizedSignerType,
          accountModel,
          chainIdKey: accountRef.chainIdKey,
          accountAddress: accountRef.accountAddress,
        },
      );
    }
    if (normalizedSignerType === 'recovery' && !capabilities.supportsRecoverySigner) {
      throw new DBConstraintError(
        'RECOVERY_SIGNER_NOT_SUPPORTED',
        `Signer type "recovery" is not supported for account model ${String(accountModel || '')}`,
        {
          signerType: normalizedSignerType,
          accountModel,
          chainIdKey: accountRef.chainIdKey,
          accountAddress: accountRef.accountAddress,
        },
      );
    }
  }

  private assertSignerStatusTransition(args: {
    previousStatus: AccountSignerStatus;
    nextStatus: AccountSignerStatus;
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
  }): void {
    const allowed = ALLOWED_SIGNER_STATUS_TRANSITIONS[args.previousStatus];
    if (allowed?.has(args.nextStatus)) return;
    throw new DBConstraintError(
      'INVALID_SIGNER_STATUS_TRANSITION',
      `Invalid signer status transition: ${args.previousStatus} -> ${args.nextStatus}`,
      {
        previousStatus: args.previousStatus,
        nextStatus: args.nextStatus,
        chainIdKey: args.chainIdKey,
        accountAddress: args.accountAddress,
        signerId: args.signerId,
      },
    );
  }

  private ensureRevokedSignerHasRemovedAt(args: {
    status: AccountSignerStatus;
    removedAt?: number;
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
  }): number | undefined {
    if (args.status !== 'revoked') return undefined;
    if (typeof args.removedAt === 'number' && Number.isFinite(args.removedAt))
      return args.removedAt;
    const now = Date.now();
    if (!Number.isFinite(now)) {
      throw new DBConstraintError(
        'REVOKED_SIGNER_REQUIRES_REMOVED_AT',
        'Revoked signer requires removedAt timestamp',
        {
          chainIdKey: args.chainIdKey,
          accountAddress: args.accountAddress,
          signerId: args.signerId,
        },
      );
    }
    return now;
  }

  private async assertSignerWriteInvariants(
    store: any,
    args: {
      next: AccountSignerRecord;
      accountModel: AccountModel;
      existingSignerId?: string;
      existingStatus?: AccountSignerStatus;
    },
  ): Promise<void> {
    const capabilities = this.getAccountModelCapabilities(args.accountModel);
    const accountStatusIndex = store.index('chainIdKey_accountAddress_status');
    const accountIndex = store.index('chainIdKey_accountAddress');

    const allForAccount = (await accountIndex.getAll([
      args.next.chainIdKey,
      args.next.accountAddress,
    ])) as AccountSignerRecord[];
    const otherSigners = allForAccount.filter((row) => row.signerId !== args.next.signerId);
    if (!capabilities.supportsMultiSigner && !args.existingSignerId && otherSigners.length > 0) {
      throw new DBConstraintError(
        'MULTI_SIGNER_NOT_SUPPORTED',
        `Account model ${String(args.accountModel || '')} does not support additional signers`,
        {
          accountModel: args.accountModel,
          chainIdKey: args.next.chainIdKey,
          accountAddress: args.next.accountAddress,
          signerId: args.next.signerId,
        },
      );
    }

    if (
      !capabilities.supportsAddRemoveSigner &&
      !args.existingSignerId &&
      otherSigners.length > 0
    ) {
      throw new DBConstraintError(
        'SIGNER_MUTATION_NOT_SUPPORTED',
        `Account model ${String(args.accountModel || '')} does not support signer mutations`,
        {
          accountModel: args.accountModel,
          chainIdKey: args.next.chainIdKey,
          accountAddress: args.next.accountAddress,
          signerId: args.next.signerId,
        },
      );
    }

    if (args.next.status === 'active') {
      const activeRows = (await accountStatusIndex.getAll([
        args.next.chainIdKey,
        args.next.accountAddress,
        'active',
      ])) as AccountSignerRecord[];
      const conflictingSlot = activeRows.find(
        (row) => row.signerId !== args.next.signerId && row.signerSlot === args.next.signerSlot,
      );
      if (conflictingSlot) {
        throw new DBConstraintError(
          'DUPLICATE_ACTIVE_SIGNER_SLOT',
          `Active signer slot ${args.next.signerSlot} is already used for ${args.next.chainIdKey}/${args.next.accountAddress}`,
          {
            chainIdKey: args.next.chainIdKey,
            accountAddress: args.next.accountAddress,
            signerId: args.next.signerId,
            signerSlot: args.next.signerSlot,
            conflictingSignerId: conflictingSlot.signerId,
          },
        );
      }

      if (normalizeAccountModel(args.accountModel) === 'eoa') {
        const activeOthers = activeRows.filter((row) => row.signerId !== args.next.signerId);
        if (activeOthers.length > 0) {
          throw new DBConstraintError(
            'EOA_ACTIVE_SIGNER_LIMIT',
            'EOA accounts can have at most one active signer',
            {
              chainIdKey: args.next.chainIdKey,
              accountAddress: args.next.accountAddress,
              signerId: args.next.signerId,
            },
          );
        }
      }
    }

    if (args.existingStatus && args.existingStatus !== args.next.status) {
      this.assertSignerStatusTransition({
        previousStatus: args.existingStatus,
        nextStatus: args.next.status,
        chainIdKey: args.next.chainIdKey,
        accountAddress: args.next.accountAddress,
        signerId: args.next.signerId,
      });
    }
  }

  private isDeployableSmartAccountModel(accountModel: AccountModel): boolean {
    const normalized = normalizeAccountModel(accountModel);
    return normalized === 'erc4337' || normalized === 'tempo-native';
  }

  private async reconcilePendingSignerStateOnDeployment(args: {
    tx: any;
    previous?: ChainAccountRecord;
    next: ChainAccountRecord;
    now: number;
  }): Promise<void> {
    if (args.next.deployed !== true || args.previous?.deployed === true) return;
    if (!this.isDeployableSmartAccountModel(args.next.accountModel)) return;

    const signerStore = args.tx.objectStore(DB_CONFIG.accountSignersStore);
    const pendingSigners = (await signerStore
      .index('chainIdKey_accountAddress_status')
      .getAll([
        args.next.chainIdKey,
        args.next.accountAddress,
        'pending',
      ])) as AccountSignerRecord[];
    if (!pendingSigners.length) return;

    const promotedSignerIds = new Set<string>();
    for (const signer of pendingSigners) {
      const promoted: AccountSignerRecord = {
        ...signer,
        status: 'active',
        updatedAt: args.now,
      };
      await this.assertSignerWriteInvariants(signerStore, {
        next: promoted,
        accountModel: args.next.accountModel,
        existingSignerId: signer.signerId,
        existingStatus: signer.status,
      });
      await signerStore.put(promoted);
      promotedSignerIds.add(promoted.signerId);
    }

    const outboxStore = args.tx.objectStore(DB_CONFIG.signerOpsOutboxStore);
    const queuedOps = (await outboxStore
      .index('chainIdKey_accountAddress')
      .getAll([args.next.chainIdKey, args.next.accountAddress])) as SignerOpOutboxRecord[];
    for (const op of queuedOps) {
      if (!promotedSignerIds.has(toTrimmedString(op.signerId || ''))) continue;
      if (op.opType !== 'add-signer' && op.opType !== 'activate-recovery-signer') continue;
      if (op.status === 'confirmed' || op.status === 'dead-letter') continue;
      await outboxStore.put({
        ...op,
        status: 'confirmed',
        nextAttemptAt: args.now,
        updatedAt: args.now,
        lastError: undefined,
        ...(args.next.deploymentTxHash ? { txHash: args.next.deploymentTxHash } : {}),
      } satisfies SignerOpOutboxRecord);
    }
  }

  async upsertChainAccount(input: UpsertChainAccountInput): Promise<ChainAccountRecord> {
    const profileId = toTrimmedString(input.profileId || '');
    const chainIdKey = normalizeChainIdKey(input.chainIdKey);
    const accountAddress = normalizeAccountAddress(input.accountAddress);
    const accountModel = normalizeAccountModel(input.accountModel);
    if (!profileId || !chainIdKey || !accountAddress) {
      throw new Error('PasskeyClientDB: profileId, chainIdKey, and accountAddress are required');
    }
    if (!accountModel) {
      throw new Error('PasskeyClientDB: accountModel is required');
    }
    const db = await this.getDB();
    const now = Date.now();
    const profile = (await db.get(DB_CONFIG.profilesStore, profileId)) as ProfileRecord | undefined;
    if (!profile) {
      throw new DBConstraintError(
        'MISSING_PROFILE',
        `Cannot upsert chain account for unknown profile: ${profileId}`,
        { profileId, chainIdKey, accountAddress },
      );
    }
    const tx = db.transaction(
      [DB_CONFIG.chainAccountsStore, DB_CONFIG.accountSignersStore, DB_CONFIG.signerOpsOutboxStore],
      'readwrite',
    );
    const store = tx.objectStore(DB_CONFIG.chainAccountsStore);
    const existing = (await store.get([profileId, chainIdKey, accountAddress])) as
      | ChainAccountRecord
      | undefined;
    const factory =
      input.factory === null
        ? undefined
        : normalizeOptionalNonEmptyString(input.factory ?? existing?.factory);
    const entryPoint =
      input.entryPoint === null
        ? undefined
        : normalizeOptionalNonEmptyString(input.entryPoint ?? existing?.entryPoint);
    const salt =
      input.salt === null
        ? undefined
        : normalizeOptionalNonEmptyString(input.salt ?? existing?.salt);
    const counterfactualAddressInput =
      input.counterfactualAddress === null
        ? undefined
        : (input.counterfactualAddress ?? existing?.counterfactualAddress);
    const isSmartAccountModel = accountModel === 'erc4337' || accountModel === 'tempo-native';
    const hasSmartAccountShape = Boolean(
      factory || entryPoint || salt || counterfactualAddressInput || isSmartAccountModel,
    );
    const counterfactualAddress = hasSmartAccountShape
      ? normalizeAccountAddress(counterfactualAddressInput || accountAddress)
      : undefined;
    const deployed =
      typeof input.deployed === 'boolean'
        ? input.deployed
        : typeof existing?.deployed === 'boolean'
          ? existing.deployed
          : hasSmartAccountShape
            ? false
            : undefined;
    const deploymentTxHash =
      input.deploymentTxHash === null
        ? undefined
        : normalizeOptionalNonEmptyString(input.deploymentTxHash ?? existing?.deploymentTxHash);
    const deploymentCheckCandidate =
      input.lastDeploymentCheckAt === null
        ? undefined
        : typeof input.lastDeploymentCheckAt === 'number'
          ? input.lastDeploymentCheckAt
          : existing?.lastDeploymentCheckAt;
    const lastDeploymentCheckAt =
      typeof deploymentCheckCandidate === 'number' && Number.isFinite(deploymentCheckCandidate)
        ? deploymentCheckCandidate
        : undefined;
    const undeployedSignerSet =
      input.undeployedSignerSet === null
        ? undefined
        : normalizeUndeployedSmartAccountSignerSet(
            input.undeployedSignerSet ?? existing?.undeployedSignerSet,
          );
    const next: ChainAccountRecord = {
      profileId,
      chainIdKey,
      accountAddress,
      accountModel,
      isPrimary: input.isPrimary ?? existing?.isPrimary ?? false,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
      ...(factory ? { factory } : {}),
      ...(entryPoint ? { entryPoint } : {}),
      ...(salt ? { salt } : {}),
      ...(counterfactualAddress ? { counterfactualAddress } : {}),
      ...(typeof deployed === 'boolean' ? { deployed } : {}),
      ...(deploymentTxHash ? { deploymentTxHash } : {}),
      ...(typeof lastDeploymentCheckAt === 'number' ? { lastDeploymentCheckAt } : {}),
      ...(undeployedSignerSet ? { undeployedSignerSet } : {}),
    };

    if (next.isPrimary) {
      const idx = store.index('profileId_chainIdKey');
      let cursor = await idx.openCursor([profileId, chainIdKey]);
      while (cursor) {
        const row = cursor.value as ChainAccountRecord;
        if (row.isPrimary && normalizeAccountAddress(row.accountAddress) !== accountAddress) {
          await cursor.update({
            ...row,
            isPrimary: false,
            updatedAt: now,
          });
        }
        cursor = await cursor.continue();
      }
    }

    await store.put(next);
    await this.reconcilePendingSignerStateOnDeployment({
      tx,
      previous: existing,
      next,
      now,
    });
    await tx.done;
    return next;
  }

  async listChainAccountsByProfile(profileId: string): Promise<ChainAccountRecord[]> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return [];
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.chainAccountsStore, 'readonly');
    const rows = await tx.store.index('profileId').getAll(normalizedProfileId);
    await tx.done;
    return (rows as ChainAccountRecord[]) || [];
  }

  async listChainAccountsByProfileAndChain(
    profileId: string,
    chainIdKey: string,
  ): Promise<ChainAccountRecord[]> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedChainIdKey = normalizeChainIdKey(chainIdKey);
    if (!normalizedProfileId || !normalizedChainIdKey) return [];
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.chainAccountsStore, 'readonly');
    const rows = await tx.store
      .index('profileId_chainIdKey')
      .getAll([normalizedProfileId, normalizedChainIdKey]);
    await tx.done;
    return (rows as ChainAccountRecord[]) || [];
  }

  async listAccountSignersByProfile(args: {
    profileId: string;
    status?: AccountSignerStatus;
  }): Promise<AccountSignerRecord[]> {
    const profileId = toTrimmedString(args.profileId || '');
    if (!profileId) return [];
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.accountSignersStore, 'readonly');
    const rows = (await tx.store.index('profileId').getAll(profileId)) as AccountSignerRecord[];
    await tx.done;
    if (!args.status) return rows || [];
    return (rows || []).filter((row) => row.status === args.status);
  }

  async getChainAccount(args: {
    profileId: string;
    chainIdKey: string;
    accountAddress: string;
  }): Promise<ChainAccountRecord | null> {
    const profileId = toTrimmedString(args.profileId || '');
    const chainIdKey = normalizeChainIdKey(args.chainIdKey);
    const accountAddress = normalizeAccountAddress(args.accountAddress);
    if (!profileId || !chainIdKey || !accountAddress) return null;
    const db = await this.getDB();
    const row = (await db.get(DB_CONFIG.chainAccountsStore, [
      profileId,
      chainIdKey,
      accountAddress,
    ])) as ChainAccountRecord | undefined;
    return row || null;
  }

  async resolveProfileAccountContext(
    accountRef: AccountRef,
  ): Promise<{ profileId: string; accountRef: AccountRef } | null> {
    const chainIdKey = normalizeChainIdKey(accountRef.chainIdKey);
    const accountAddress = normalizeAccountAddress(accountRef.accountAddress);
    if (!chainIdKey || !accountAddress) return null;

    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.chainAccountsStore, 'readonly');
    const row = (await tx.store
      .index('chainIdKey_accountAddress')
      .get([chainIdKey, accountAddress])) as ChainAccountRecord | undefined;
    await tx.done;
    if (!row?.profileId) return null;

    return {
      profileId: row.profileId,
      accountRef: {
        chainIdKey,
        accountAddress,
      },
    };
  }

  async listChainAccountsByChain(chainIdKey: string): Promise<ChainAccountRecord[]> {
    const normalizedChainIdKey = normalizeChainIdKey(chainIdKey);
    if (!normalizedChainIdKey) return [];
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.chainAccountsStore, 'readonly');
    const rows = (await tx.store.index('chainIdKey').getAll(normalizedChainIdKey)) as
      | ChainAccountRecord[]
      | undefined;
    await tx.done;
    return rows || [];
  }

  async getProfileContinuitySnapshot(profileId: string): Promise<ProfileContinuitySnapshot | null> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return null;

    const [profile, chainAccounts, accountSigners] = await Promise.all([
      this.getProfile(normalizedProfileId),
      this.listChainAccountsByProfile(normalizedProfileId),
      this.listAccountSignersByProfile({ profileId: normalizedProfileId }),
    ]);
    if (!profile) return null;

    return {
      profile,
      chainAccounts,
      accountSigners,
    };
  }

  async setLastProfileStateForProfile(profileId: string, deviceNumber: number): Promise<void> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedDeviceNumber = Number(deviceNumber);
    if (!normalizedProfileId) {
      throw new Error('PasskeyClientDB: profileId is required');
    }
    if (!Number.isSafeInteger(normalizedDeviceNumber) || normalizedDeviceNumber < 1) {
      throw new Error('PasskeyClientDB: deviceNumber must be an integer >= 1');
    }
    await this.setLastProfileState({
      profileId: normalizedProfileId,
      deviceNumber: normalizedDeviceNumber,
      ...(this.lastUserScope != null ? { scope: this.lastUserScope } : {}),
    });
  }

  async clearLastProfileSelection(): Promise<void> {
    await this.setLastProfileState(null);
  }

  async listProfileAuthenticators(profileId: string): Promise<ProfileAuthenticatorRecord[]> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return [];
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.profileAuthenticatorStore, 'readonly');
    const rows = await tx.store.index('profileId').getAll(normalizedProfileId);
    await tx.done;
    return (rows as ProfileAuthenticatorRecord[]) || [];
  }

  async updatePreferences(args: {
    profileId: string;
    preferences: Partial<UserPreferences>;
    eventAccountId?: AccountId | null;
  }): Promise<void> {
    const profileId = toTrimmedString(args.profileId || '');
    if (!profileId) return;

    const profile = await this.getProfile(profileId).catch(() => null);
    if (!profile) return;
    const updatedPreferences = {
      ...(profile.preferences || {}),
      ...args.preferences,
    } as UserPreferences;

    await this.upsertProfile({
      profileId: profile.profileId,
      defaultDeviceNumber: profile.defaultDeviceNumber,
      preferences: updatedPreferences,
    });

    const accountId = toTrimmedString(args.eventAccountId || '');
    if (accountId) {
      this.emitEvent({
        type: 'preferences-updated',
        accountId: accountId as AccountId,
        data: { preferences: updatedPreferences },
      });
    }
  }

  async deleteProfileData(
    profileId: string,
    args?: { eventAccountId?: AccountId | null },
  ): Promise<void> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return;
    await this.clearLastProfileStateIfMatchesProfile(normalizedProfileId);
    await this.deleteProfileDataForProfile(normalizedProfileId);
    const accountId = toTrimmedString(args?.eventAccountId || '');
    if (accountId) {
      this.emitEvent({ type: 'user-deleted', accountId: accountId as AccountId });
    }
  }

  async upsertProfileAuthenticator(record: ProfileAuthenticatorRecord): Promise<void> {
    const profileId = toTrimmedString(record.profileId || '');
    const credentialId = toTrimmedString(record.credentialId || '');
    if (!profileId || !credentialId) {
      throw new Error(
        'PasskeyClientDB: profileId and credentialId are required for profileAuthenticators',
      );
    }
    const db = await this.getDB();
    await db.put(DB_CONFIG.profileAuthenticatorStore, {
      ...record,
      profileId,
      credentialId,
    } satisfies ProfileAuthenticatorRecord);
  }

  async getProfileAuthenticatorByCredentialId(
    profileId: string,
    credentialId: string,
  ): Promise<ProfileAuthenticatorRecord | null> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedCredentialId = toTrimmedString(credentialId || '');
    if (!normalizedProfileId || !normalizedCredentialId) return null;
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.profileAuthenticatorStore, 'readonly');
    const row = (await tx.store
      .index('profileId_credentialId')
      .get([normalizedProfileId, normalizedCredentialId])) as
      | ProfileAuthenticatorRecord
      | undefined;
    await tx.done;
    return row || null;
  }

  async clearProfileAuthenticators(profileId: string): Promise<void> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return;
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.profileAuthenticatorStore, 'readwrite');
    const profileStore = tx.store;
    let cursor = await profileStore
      .index('profileId')
      .openCursor(IDBKeyRange.only(normalizedProfileId));
    while (cursor) {
      await profileStore.delete(cursor.primaryKey);
      cursor = await cursor.continue();
    }
    await tx.done;
  }

  async upsertRecoveryEmails(
    profileId: string,
    entries: Array<{ hashHex: string; email: string }>,
  ): Promise<void> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId || !entries?.length) return;
    const db = await this.getDB();
    const now = Date.now();
    for (const entry of entries) {
      const hashHex = toTrimmedString(entry?.hashHex || '');
      const email = toTrimmedString(entry?.email || '');
      if (!hashHex) continue;
      await db.put(DB_CONFIG.recoveryEmailStore, {
        profileId: normalizedProfileId,
        hashHex,
        email: email || hashHex,
        addedAt: now,
      } satisfies ProfileRecoveryEmailRecord);
    }
  }

  async listRecoveryEmails(profileId: string): Promise<ProfileRecoveryEmailRecord[]> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return [];
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.recoveryEmailStore, 'readonly');
    const rows = (await tx.store
      .index('profileId')
      .getAll(normalizedProfileId)) as ProfileRecoveryEmailRecord[];
    await tx.done;
    return rows || [];
  }

  async selectProfileAuthenticatorsForPrompt(args: {
    profileId: string;
    authenticators: ProfileAuthenticatorRecord[];
    selectedCredentialRawId?: string;
    accountLabel?: string;
  }): Promise<{
    authenticatorsForPrompt: ProfileAuthenticatorRecord[];
    wrongPasskeyError?: string;
  }> {
    const profileId = toTrimmedString(args.profileId || '');
    const authenticators = Array.isArray(args.authenticators) ? args.authenticators : [];
    if (!profileId || authenticators.length <= 1) {
      return { authenticatorsForPrompt: authenticators };
    }

    const lastProfileState = await this.getLastProfileState().catch(() => null);
    if (!lastProfileState || lastProfileState.profileId !== profileId) {
      return { authenticatorsForPrompt: authenticators };
    }

    const expectedDeviceNumber = Number(lastProfileState.deviceNumber);
    const byDeviceNumber = authenticators.filter((a) => a.deviceNumber === expectedDeviceNumber);
    const expectedCredentialId = String(
      byDeviceNumber[0]?.credentialId || authenticators[0]?.credentialId || '',
    ).trim();
    const byCredentialId = expectedCredentialId
      ? authenticators.filter((a) => a.credentialId === expectedCredentialId)
      : [];
    const authenticatorsForPrompt =
      byCredentialId.length > 0
        ? byCredentialId
        : byDeviceNumber.length > 0
          ? byDeviceNumber
          : authenticators;

    const selectedCredentialRawId = toTrimmedString(args.selectedCredentialRawId || '');
    const accountLabel = String(args.accountLabel || profileId).trim();
    const wrongPasskeyError =
      selectedCredentialRawId &&
      expectedCredentialId &&
      selectedCredentialRawId !== expectedCredentialId
        ? `You have multiple passkeys (deviceNumbers) for account ${accountLabel}, ` +
          'but used a different passkey than the most recently logged-in one. ' +
          'Please use the passkey for the most recently logged-in device.'
        : undefined;

    return { authenticatorsForPrompt, wrongPasskeyError };
  }

  private createSignerOperationId(prefix: string): string {
    return createSignerOperationIdValue(prefix);
  }

  private async upsertAccountSignerDirect(
    input: UpsertAccountSignerInput,
  ): Promise<AccountSignerRecord> {
    const profileId = toTrimmedString(input.profileId || '');
    const chainIdKey = normalizeChainIdKey(input.chainIdKey);
    const accountAddress = normalizeAccountAddress(input.accountAddress);
    const signerId = toTrimmedString(input.signerId || '');
    if (!profileId || !chainIdKey || !accountAddress || !signerId) {
      throw new Error(
        'PasskeyClientDB: profileId, chainIdKey, accountAddress, and signerId are required',
      );
    }
    if (!Number.isSafeInteger(input.signerSlot) || input.signerSlot < 1) {
      throw new Error('PasskeyClientDB: signerSlot must be an integer >= 1');
    }
    const db = await this.getDB();
    const chainAccount = (await db.get(DB_CONFIG.chainAccountsStore, [
      profileId,
      chainIdKey,
      accountAddress,
    ])) as ChainAccountRecord | undefined;
    if (!chainAccount) {
      throw new DBConstraintError(
        'MISSING_CHAIN_ACCOUNT',
        `Cannot upsert signer without chain account row: ${profileId}/${chainIdKey}/${accountAddress}`,
        { profileId, chainIdKey, accountAddress, signerId },
      );
    }
    if (chainAccount.profileId !== profileId) {
      throw new DBConstraintError(
        'CHAIN_ACCOUNT_PROFILE_MISMATCH',
        `Chain account profile mismatch for ${chainIdKey}/${accountAddress}`,
        {
          expectedProfileId: profileId,
          chainAccountProfileId: chainAccount.profileId,
          chainIdKey,
          accountAddress,
          signerId,
        },
      );
    }
    this.assertSignerTypeCapability(input.signerType, chainAccount.accountModel, {
      chainIdKey,
      accountAddress,
    });

    const tx = db.transaction(DB_CONFIG.accountSignersStore, 'readwrite');
    const store = tx.store;
    const now = Date.now();
    const existing = (await store.get([chainIdKey, accountAddress, signerId])) as
      | AccountSignerRecord
      | undefined;
    if (existing && existing.profileId !== profileId) {
      throw new DBConstraintError(
        'CHAIN_ACCOUNT_PROFILE_MISMATCH',
        `Signer row belongs to a different profile for ${chainIdKey}/${accountAddress}/${signerId}`,
        {
          expectedProfileId: profileId,
          existingProfileId: existing.profileId,
          chainIdKey,
          accountAddress,
          signerId,
        },
      );
    }
    const removedAt = this.ensureRevokedSignerHasRemovedAt({
      status: input.status,
      removedAt: input.removedAt ?? existing?.removedAt,
      chainIdKey,
      accountAddress,
      signerId,
    });
    const next: AccountSignerRecord = {
      profileId,
      chainIdKey,
      accountAddress,
      signerId,
      signerSlot: input.signerSlot,
      signerType: input.signerType,
      status: input.status,
      addedAt: existing?.addedAt ?? now,
      updatedAt: now,
      ...(removedAt != null ? { removedAt } : {}),
      ...(input.metadata != null
        ? { metadata: input.metadata }
        : existing?.metadata != null
          ? { metadata: existing.metadata }
          : {}),
    };
    await this.assertSignerWriteInvariants(store, {
      next,
      accountModel: chainAccount.accountModel,
      existingSignerId: existing?.signerId,
      existingStatus: existing?.status,
    });
    await store.put(next);
    await tx.done;
    return next;
  }

  async upsertAccountSigner(input: UpsertAccountSignerInput): Promise<AccountSignerRecord> {
    const next = await this.upsertAccountSignerDirect(input);
    const routeThroughOutbox = input.mutation?.routeThroughOutbox ?? true;
    if (!routeThroughOutbox) return next;
    const opId =
      toTrimmedString(input.mutation?.opId || '') || this.createSignerOperationId('add-signer');
    const idempotencyKey =
      toTrimmedString(input.mutation?.idempotencyKey || '') ||
      `add-signer:${next.chainIdKey}:${next.accountAddress}:${next.signerId}:${next.signerSlot}`;
    await this.enqueueSignerOperation({
      opId,
      idempotencyKey,
      opType: 'add-signer',
      chainIdKey: next.chainIdKey,
      accountAddress: next.accountAddress,
      signerId: next.signerId,
      payload: {
        profileId: next.profileId,
        signerSlot: next.signerSlot,
        signerType: next.signerType,
        ...(next.metadata ? { signerMetadata: next.metadata } : {}),
        ...(input.mutation?.outboxPayload ? input.mutation.outboxPayload : {}),
      },
      status: input.mutation?.outboxStatus || 'queued',
    });
    return next;
  }

  async listAccountSigners(args: {
    chainIdKey: string;
    accountAddress: string;
    status?: AccountSignerStatus;
  }): Promise<AccountSignerRecord[]> {
    const chainIdKey = normalizeChainIdKey(args.chainIdKey);
    const accountAddress = normalizeAccountAddress(args.accountAddress);
    if (!chainIdKey || !accountAddress) return [];
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.accountSignersStore, 'readonly');
    const store = tx.store;
    if (args.status) {
      const idx = store.index('chainIdKey_accountAddress_status');
      const rows = await idx.getAll([chainIdKey, accountAddress, args.status]);
      return (rows as AccountSignerRecord[]) || [];
    }
    const idx = store.index('chainIdKey_accountAddress');
    const rows = await idx.getAll([chainIdKey, accountAddress]);
    return (rows as AccountSignerRecord[]) || [];
  }

  async getAccountSigner(args: {
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
  }): Promise<AccountSignerRecord | null> {
    const chainIdKey = normalizeChainIdKey(args.chainIdKey);
    const accountAddress = normalizeAccountAddress(args.accountAddress);
    const signerId = toTrimmedString(args.signerId || '');
    if (!chainIdKey || !accountAddress || !signerId) return null;
    const db = await this.getDB();
    const row = (await db.get(DB_CONFIG.accountSignersStore, [
      chainIdKey,
      accountAddress,
      signerId,
    ])) as AccountSignerRecord | undefined;
    return row || null;
  }

  private async setAccountSignerStatusDirect(args: {
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
    status: AccountSignerStatus;
    removedAt?: number;
  }): Promise<AccountSignerRecord | null> {
    const chainIdKey = normalizeChainIdKey(args.chainIdKey);
    const accountAddress = normalizeAccountAddress(args.accountAddress);
    const signerId = toTrimmedString(args.signerId || '');
    if (!chainIdKey || !accountAddress || !signerId) return null;
    const db = await this.getDB();
    const existing = (await db.get(DB_CONFIG.accountSignersStore, [
      chainIdKey,
      accountAddress,
      signerId,
    ])) as AccountSignerRecord | undefined;
    if (!existing) return null;
    const chainAccount = (await db.get(DB_CONFIG.chainAccountsStore, [
      existing.profileId,
      chainIdKey,
      accountAddress,
    ])) as ChainAccountRecord | undefined;
    if (!chainAccount) {
      throw new DBConstraintError(
        'MISSING_CHAIN_ACCOUNT',
        `Cannot update signer status without chain account row: ${existing.profileId}/${chainIdKey}/${accountAddress}`,
        {
          profileId: existing.profileId,
          chainIdKey,
          accountAddress,
          signerId,
        },
      );
    }

    const removedAt = this.ensureRevokedSignerHasRemovedAt({
      status: args.status,
      removedAt: args.removedAt ?? existing.removedAt,
      chainIdKey,
      accountAddress,
      signerId,
    });

    const tx = db.transaction(DB_CONFIG.accountSignersStore, 'readwrite');
    const store = tx.store;
    const latest = (await store.get([chainIdKey, accountAddress, signerId])) as
      | AccountSignerRecord
      | undefined;
    if (!latest) {
      await tx.done;
      return null;
    }

    const updated: AccountSignerRecord = {
      ...latest,
      status: args.status,
      updatedAt: Date.now(),
      ...(removedAt != null ? { removedAt } : {}),
    };
    await this.assertSignerWriteInvariants(store, {
      next: updated,
      accountModel: chainAccount.accountModel,
      existingSignerId: latest.signerId,
      existingStatus: latest.status,
    });
    await store.put(updated);
    await tx.done;
    return updated;
  }

  async setAccountSignerStatus(args: {
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
    status: AccountSignerStatus;
    removedAt?: number;
    mutation?: SignerMutationOptions;
  }): Promise<AccountSignerRecord | null> {
    const updated = await this.setAccountSignerStatusDirect(args);
    if (!updated) return null;

    const routeThroughOutbox = args.mutation?.routeThroughOutbox ?? true;
    if (!routeThroughOutbox) return updated;

    const opType: SignerOperationType = args.status === 'revoked' ? 'revoke-signer' : 'add-signer';
    const opId = toTrimmedString(args.mutation?.opId || '') || this.createSignerOperationId(opType);
    const idempotencyKey =
      toTrimmedString(args.mutation?.idempotencyKey || '') ||
      `signer-status:${args.status}:${updated.chainIdKey}:${updated.accountAddress}:${updated.signerId}`;
    await this.enqueueSignerOperation({
      opId,
      idempotencyKey,
      opType,
      chainIdKey: updated.chainIdKey,
      accountAddress: updated.accountAddress,
      signerId: updated.signerId,
      payload: {
        profileId: updated.profileId,
        signerSlot: updated.signerSlot,
        status: updated.status,
        ...(updated.removedAt != null ? { removedAt: updated.removedAt } : {}),
        ...(args.mutation?.outboxPayload ? args.mutation.outboxPayload : {}),
      },
      status: args.mutation?.outboxStatus || 'queued',
    });
    return updated;
  }

  async enqueueSignerOperation(input: EnqueueSignerOperationInput): Promise<SignerOpOutboxRecord> {
    const db = await this.getDB();
    return enqueueSignerOperationRecord(db, DB_CONFIG.signerOpsOutboxStore, input);
  }

  async listSignerOperations(args?: {
    statuses?: SignerOperationStatus[];
    dueBefore?: number;
    limit?: number;
  }): Promise<SignerOpOutboxRecord[]> {
    const db = await this.getDB();
    return listSignerOperationRecords(db, DB_CONFIG.signerOpsOutboxStore, args);
  }

  async setSignerOperationStatus(args: {
    opId: string;
    status: SignerOperationStatus;
    attemptDelta?: number;
    nextAttemptAt?: number;
    lastError?: string | null;
    txHash?: string | null;
  }): Promise<SignerOpOutboxRecord | null> {
    const db = await this.getDB();
    return setSignerOperationRecordStatus(db, DB_CONFIG.signerOpsOutboxStore, args);
  }

  /**
   * Set the scoping key used for last-user selection in wallet-iframe mode.
   *
   * When set, last-user pointers are stored in a namespaced app-state key:
   * `lastProfileState::<scope>`.
   *
   * This is intended for the wallet-origin host to call with the embedding app origin
   * (e.g., from the CONNECT handshake `MessageEvent.origin`).
   */
  setLastUserScope(scope: string | null): void {
    this.lastUserScope = normalizeLastUserScope(scope);
  }

  getLastUserScope(): string | null {
    return this.lastUserScope;
  }

  private getScopedLastProfileStateAppStateKey(
    scope: string | null = this.lastUserScope,
  ): string | null {
    return makeScopedAppStateKey(LAST_PROFILE_STATE_APP_STATE_KEY, scope);
  }

  private async assertLastProfileStateInvariant(state: LastProfileState): Promise<void> {
    const db = await this.getDB();
    const profile = (await db.get(DB_CONFIG.profilesStore, state.profileId)) as
      | ProfileRecord
      | undefined;
    if (!profile) {
      throw new DBConstraintError(
        'INVALID_LAST_PROFILE_STATE',
        `lastProfileState profile does not exist: ${state.profileId}`,
        {
          profileId: state.profileId,
          deviceNumber: state.deviceNumber,
        },
      );
    }

    const signerTx = db.transaction(DB_CONFIG.accountSignersStore, 'readonly');
    const signerRows = (await signerTx.store
      .index('profileId')
      .getAll(state.profileId)) as AccountSignerRecord[];
    await signerTx.done;
    if (!signerRows.length) return;
    const hasMatchingSignerSlot = signerRows.some(
      (row) => row.signerSlot === state.deviceNumber && row.status !== 'revoked',
    );
    if (!hasMatchingSignerSlot) {
      throw new DBConstraintError(
        'INVALID_LAST_PROFILE_STATE',
        `lastProfileState signer slot ${state.deviceNumber} was not found for profile ${state.profileId}`,
        {
          profileId: state.profileId,
          deviceNumber: state.deviceNumber,
        },
      );
    }
  }

  async getLastProfileState(): Promise<LastProfileState | null> {
    const scopedKey = this.getScopedLastProfileStateAppStateKey();
    if (scopedKey) {
      const scopedRaw = await this.getAppState<unknown>(scopedKey).catch(() => undefined);
      return parseLastProfileState(scopedRaw);
    }
    const unscopedRaw = await this.getAppState<unknown>(LAST_PROFILE_STATE_APP_STATE_KEY).catch(
      () => undefined,
    );
    return parseLastProfileState(unscopedRaw);
  }

  async setLastProfileState(state: LastProfileState | null): Promise<void> {
    if (state) {
      await this.assertLastProfileStateInvariant(state);
    }
    const scopedKey = this.getScopedLastProfileStateAppStateKey();
    if (scopedKey) {
      await this.setAppState(scopedKey, state);
      return;
    }
    await this.setAppState(LAST_PROFILE_STATE_APP_STATE_KEY, state);
  }

  private async clearLastProfileStateIfMatchesProfile(profileId: string): Promise<void> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return;
    try {
      const unscopedProfile = parseLastProfileState(
        await this.getAppState<unknown>(LAST_PROFILE_STATE_APP_STATE_KEY),
      );
      if (unscopedProfile && unscopedProfile.profileId === normalizedProfileId) {
        await this.setAppState(LAST_PROFILE_STATE_APP_STATE_KEY, null);
      }
    } catch {}

    const scopedProfileKey = this.getScopedLastProfileStateAppStateKey();
    if (scopedProfileKey) {
      try {
        const scopedProfile = parseLastProfileState(
          await this.getAppState<unknown>(scopedProfileKey),
        );
        if (scopedProfile && scopedProfile.profileId === normalizedProfileId) {
          await this.setAppState(scopedProfileKey, null);
        }
      } catch {}
    }
  }

  private async deleteProfileDataForProfile(profileId: string): Promise<void> {
    const db = await this.getDB();
    await deleteProfileDataValue({
      db,
      profileId,
      stores: {
        profilesStore: DB_CONFIG.profilesStore,
        chainAccountsStore: DB_CONFIG.chainAccountsStore,
        accountSignersStore: DB_CONFIG.accountSignersStore,
        recoveryEmailStore: DB_CONFIG.recoveryEmailStore,
        profileAuthenticatorStore: DB_CONFIG.profileAuthenticatorStore,
      },
    });
  }

  async clearAllAppState(): Promise<void> {
    const db = await this.getDB();
    await db.clear(DB_CONFIG.appStateStore);
  }

  /**
   * Atomic operation wrapper for multiple IndexedDB operations
   * Either all operations succeed or all are rolled back
   */
  async atomicOperation<T>(operation: (db: IDBPDatabase) => Promise<T>): Promise<T> {
    const db = await this.getDB();
    try {
      const result = await operation(db);
      return result;
    } catch (error) {
      console.error('Atomic operation failed:', error);
      throw error;
    }
  }
}
