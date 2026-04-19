import { openDB, type IDBPDatabase } from 'idb';
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
  SignerAuthMethod,
  SignerKind,
  SignerMutationOptions,
  SignerOperationStatus,
  SignerOperationType,
  SignerOpOutboxRecord,
  SignerSource,
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
import {
  ALLOWED_SIGNER_STATUS_TRANSITIONS,
  createAccountSignerRepository,
  type AccountSignerRepository,
} from './accountSignerRepository';
import {
  createChainAccountRepository,
  type ChainAccountRepository,
} from './chainAccountRepository';
import { parseLastProfileState } from '../lastProfileState';
import {
  createLastProfileStateRepository,
  type LastProfileStateRepository,
} from './lastProfileStateRepository';
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
  createProfileAuthenticatorRepository,
  type ProfileAuthenticatorRepository,
} from './profileAuthenticatorRepository';
import { createProfileRepository, type ProfileRepository } from './profileRepository';
import {
  normalizeIndexedDbAccountAddress as normalizeAccountAddress,
  normalizeIndexedDbAccountModel as normalizeAccountModel,
  normalizeIndexedDbChainIdKey as normalizeChainIdKey,
  normalizeLastUserScope,
} from '../normalization';
import {
  planAccountSignerActivation,
  type ActivateAccountSignerInput,
  type ActivateAccountSignerResult,
  type StageAccountSignerInput,
  type StageAccountSignerResult,
} from '../accountSignerLifecycle';

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
export type {
  ActivateAccountSignerInput,
  ActivateAccountSignerResult,
  AccountSignerActivationPlan,
  SignerActivationPolicy,
  SignerAuthMethod,
  SignerKind,
  SignerSource,
  StageAccountSignerInput,
  StageAccountSignerResult,
} from '../accountSignerLifecycle';

interface AppStateEntry<T = unknown> {
  key: string;
  value: T;
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

export class PasskeyClientDBManager {
  private config: PasskeyClientDBConfig;
  private accountSignerRepository: AccountSignerRepository;
  private db: IDBPDatabase | null = null;
  private disabled = false;
  private chainAccountRepository: ChainAccountRepository;
  private eventListeners: Set<(event: IndexedDBEvent) => void> = new Set();
  private lastProfileStateRepository: LastProfileStateRepository;
  private lastUserScope: string | null = null;
  private profileAuthenticatorRepository: ProfileAuthenticatorRepository;
  private profileRepository: ProfileRepository;

  constructor(config: PasskeyClientDBConfig = DB_CONFIG) {
    this.config = config;
    this.accountSignerRepository = createAccountSignerRepository({
      getDB: () => this.getDB(),
      accountSignersStore: DB_CONFIG.accountSignersStore,
      chainAccountsStore: DB_CONFIG.chainAccountsStore,
      createConstraintError: (code, message, details) =>
        new DBConstraintError(code, message, details),
    });
    this.chainAccountRepository = createChainAccountRepository({
      getDB: () => this.getDB(),
      chainAccountsStore: DB_CONFIG.chainAccountsStore,
      accountSignersStore: DB_CONFIG.accountSignersStore,
      profilesStore: DB_CONFIG.profilesStore,
      signerOpsOutboxStore: DB_CONFIG.signerOpsOutboxStore,
      createConstraintError: (code, message, details) =>
        new DBConstraintError(code, message, details),
    });
    this.lastProfileStateRepository = createLastProfileStateRepository({
      getDB: () => this.getDB(),
      appStateStore: DB_CONFIG.appStateStore,
      accountSignersStore: DB_CONFIG.accountSignersStore,
      profilesStore: DB_CONFIG.profilesStore,
      lastProfileStateAppStateKey: LAST_PROFILE_STATE_APP_STATE_KEY,
      createConstraintError: (code, message, details) =>
        new DBConstraintError(code, message, details),
    });
    this.profileAuthenticatorRepository = createProfileAuthenticatorRepository({
      getDB: () => this.getDB(),
      profileAuthenticatorStore: DB_CONFIG.profileAuthenticatorStore,
    });
    this.profileRepository = createProfileRepository({
      getDB: () => this.getDB(),
      profilesStore: DB_CONFIG.profilesStore,
    });
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
    return this.profileRepository.getProfile(profileId);
  }

  async listProfiles(args?: { limit?: number }): Promise<ProfileRecord[]> {
    return this.profileRepository.listProfiles(args);
  }

  async upsertProfile(input: UpsertProfileInput): Promise<ProfileRecord> {
    return this.profileRepository.upsertProfile(input);
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
      await this.accountSignerRepository.putPreparedAccountSignerInTransaction({
        store: signerStore,
        next: promoted,
        accountModel: args.next.accountModel,
        existingSignerId: signer.signerId,
        existingStatus: signer.status,
      });
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
    return this.chainAccountRepository.upsertChainAccount(input, {
      reconcilePendingSignerStateOnDeployment: (args) =>
        this.reconcilePendingSignerStateOnDeployment(args),
    });
  }

  async listChainAccountsByProfile(profileId: string): Promise<ChainAccountRecord[]> {
    return this.chainAccountRepository.listChainAccountsByProfile(profileId);
  }

  async listChainAccountsByProfileAndChain(
    profileId: string,
    chainIdKey: string,
  ): Promise<ChainAccountRecord[]> {
    return this.chainAccountRepository.listChainAccountsByProfileAndChain(profileId, chainIdKey);
  }

  async listAccountSignersByProfile(args: {
    profileId: string;
    status?: AccountSignerStatus;
  }): Promise<AccountSignerRecord[]> {
    return this.accountSignerRepository.listAccountSignersByProfile(args);
  }

  async getChainAccount(args: {
    profileId: string;
    chainIdKey: string;
    accountAddress: string;
  }): Promise<ChainAccountRecord | null> {
    return this.chainAccountRepository.getChainAccount(args);
  }

  async resolveProfileAccountContext(
    accountRef: AccountRef,
  ): Promise<{ profileId: string; accountRef: AccountRef } | null> {
    return this.chainAccountRepository.resolveProfileAccountContext(accountRef);
  }

  async listChainAccountsByChain(chainIdKey: string): Promise<ChainAccountRecord[]> {
    return this.chainAccountRepository.listChainAccountsByChain(chainIdKey);
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

  async setLastProfileStateForProfile(profileId: string, activeSignerSlot: number): Promise<void> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedActiveSignerSlot = Number(activeSignerSlot);
    if (!normalizedProfileId) {
      throw new Error('PasskeyClientDB: profileId is required');
    }
    if (!Number.isSafeInteger(normalizedActiveSignerSlot) || normalizedActiveSignerSlot < 1) {
      throw new Error('PasskeyClientDB: activeSignerSlot must be an integer >= 1');
    }
    await this.setLastProfileState({
      profileId: normalizedProfileId,
      activeSignerSlot: normalizedActiveSignerSlot,
      ...(this.lastUserScope != null ? { scope: this.lastUserScope } : {}),
    });
  }

  async clearLastProfileSelection(): Promise<void> {
    await this.setLastProfileState(null);
  }

  async listProfileAuthenticators(profileId: string): Promise<ProfileAuthenticatorRecord[]> {
    return this.profileAuthenticatorRepository.listProfileAuthenticators(profileId);
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
      defaultSignerSlot: profile.defaultSignerSlot,
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
    await this.lastProfileStateRepository.clearLastProfileStateIfMatchesProfile(
      normalizedProfileId,
      this.lastUserScope,
    );
    await this.deleteProfileDataForProfile(normalizedProfileId);
    const accountId = toTrimmedString(args?.eventAccountId || '');
    if (accountId) {
      this.emitEvent({ type: 'user-deleted', accountId: accountId as AccountId });
    }
  }

  async upsertProfileAuthenticator(record: ProfileAuthenticatorRecord): Promise<void> {
    return this.profileAuthenticatorRepository.upsertProfileAuthenticator(record);
  }

  async getProfileAuthenticatorByCredentialId(
    profileId: string,
    credentialId: string,
  ): Promise<ProfileAuthenticatorRecord | null> {
    return this.profileAuthenticatorRepository.getProfileAuthenticatorByCredentialId(
      profileId,
      credentialId,
    );
  }

  async clearProfileAuthenticators(profileId: string): Promise<void> {
    return this.profileAuthenticatorRepository.clearProfileAuthenticators(profileId);
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

    const expectedSignerSlot = Number(lastProfileState.activeSignerSlot);
    const bySignerSlot = authenticators.filter((a) => a.signerSlot === expectedSignerSlot);
    const expectedCredentialId = String(
      bySignerSlot[0]?.credentialId || authenticators[0]?.credentialId || '',
    ).trim();
    const byCredentialId = expectedCredentialId
      ? authenticators.filter((a) => a.credentialId === expectedCredentialId)
      : [];
    const authenticatorsForPrompt =
      byCredentialId.length > 0
        ? byCredentialId
        : bySignerSlot.length > 0
          ? bySignerSlot
          : authenticators;

    const selectedCredentialRawId = toTrimmedString(args.selectedCredentialRawId || '');
    const accountLabel = String(args.accountLabel || profileId).trim();
    const wrongPasskeyError =
      selectedCredentialRawId &&
      expectedCredentialId &&
      selectedCredentialRawId !== expectedCredentialId
        ? `You have multiple passkeys for account ${accountLabel}, ` +
          'but used a different passkey than the most recently logged-in one. ' +
          'Please use the passkey for the most recently active signer.'
        : undefined;

    return { authenticatorsForPrompt, wrongPasskeyError };
  }

  private createSignerOperationId(prefix: string): string {
    return createSignerOperationIdValue(prefix);
  }

  private async enqueueSignerOperationInTransaction(
    store: any,
    input: EnqueueSignerOperationInput,
  ): Promise<SignerOpOutboxRecord> {
    const opId = toTrimmedString(input.opId || '');
    const idempotencyKey = toTrimmedString(input.idempotencyKey || '');
    const chainIdKey = normalizeChainIdKey(input.chainIdKey);
    const accountAddress = normalizeAccountAddress(input.accountAddress);
    const signerId = toTrimmedString(input.signerId || '');
    if (!opId || !idempotencyKey || !chainIdKey || !accountAddress || !signerId) {
      throw new Error(
        'PasskeyClientDB: opId, idempotencyKey, chainIdKey, accountAddress, and signerId are required',
      );
    }

    const now = Date.now();
    const existing = (await store.get(opId)) as SignerOpOutboxRecord | undefined;
    if (!existing) {
      const byIdempotency = (await store.index('idempotencyKey').get(idempotencyKey)) as
        | SignerOpOutboxRecord
        | undefined;
      if (byIdempotency) return byIdempotency;
    }

    const next: SignerOpOutboxRecord = {
      opId,
      idempotencyKey,
      opType: input.opType,
      chainIdKey,
      accountAddress,
      signerId,
      payload: input.payload ?? existing?.payload,
      status: input.status ?? existing?.status ?? 'queued',
      attemptCount: input.attemptCount ?? existing?.attemptCount ?? 0,
      nextAttemptAt: input.nextAttemptAt ?? existing?.nextAttemptAt ?? now,
      lastError: input.lastError ?? existing?.lastError,
      txHash: input.txHash ?? existing?.txHash,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    await store.put(next);
    return next;
  }

  async upsertAccountSigner(input: UpsertAccountSignerInput): Promise<AccountSignerRecord> {
    const next = await this.accountSignerRepository.upsertAccountSignerDirect(input);
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
        ...(next.signerKind ? { signerKind: next.signerKind } : {}),
        ...(next.signerAuthMethod ? { signerAuthMethod: next.signerAuthMethod } : {}),
        ...(next.signerSource ? { signerSource: next.signerSource } : {}),
        ...(next.metadata ? { signerMetadata: next.metadata } : {}),
        ...(input.mutation?.outboxPayload ? input.mutation.outboxPayload : {}),
      },
      status: input.mutation?.outboxStatus || 'queued',
    });
    return next;
  }

  async activateAccountSigner(
    input: ActivateAccountSignerInput,
  ): Promise<ActivateAccountSignerResult> {
    const profileId = toTrimmedString(input.account.profileId || '');
    const chainIdKey = normalizeChainIdKey(input.account.chainIdKey);
    const accountAddress = normalizeAccountAddress(input.account.accountAddress);
    const accountModel = normalizeAccountModel(input.account.accountModel);
    const signerId = toTrimmedString(input.signer.signerId || '');
    const signerKind = toTrimmedString(input.signer.signerKind || '') as SignerKind;
    const signerAuthMethod = toTrimmedString(
      input.signer.signerAuthMethod || '',
    ) as SignerAuthMethod;
    const signerSource = toTrimmedString(input.signer.signerSource || '') as SignerSource;
    if (
      !profileId ||
      !chainIdKey ||
      !accountAddress ||
      !accountModel ||
      !signerId ||
      !signerKind ||
      !signerAuthMethod ||
      !signerSource
    ) {
      throw new Error(
        'PasskeyClientDB: profileId, chainIdKey, accountAddress, accountModel, signerId, signerKind, signerAuthMethod, and signerSource are required',
      );
    }

    const db = await this.getDB();
    const tx = db.transaction(
      [
        DB_CONFIG.profilesStore,
        DB_CONFIG.chainAccountsStore,
        DB_CONFIG.accountSignersStore,
        DB_CONFIG.appStateStore,
        DB_CONFIG.signerOpsOutboxStore,
      ],
      'readwrite',
    );
    const now = Date.now();
    const chainAccount = await this.chainAccountRepository.putChainAccountForSignerLifecycle({
      tx,
      profileId,
      chainIdKey,
      accountAddress,
      accountModel,
      now,
    });
    const signerStore = tx.objectStore(DB_CONFIG.accountSignersStore);
    const activeSigners = (await signerStore
      .index('chainIdKey_accountAddress_status')
      .getAll([chainIdKey, accountAddress, 'active'])) as AccountSignerRecord[];
    const plan = planAccountSignerActivation({
      activeSigners,
      signer: { signerId, signerKind, signerAuthMethod, signerSource },
      activationPolicy: input.activationPolicy,
      ...(input.preferredSlot != null ? { preferredSlot: input.preferredSlot } : {}),
    });

    const existingSigner = (await signerStore.get([chainIdKey, accountAddress, signerId])) as
      | AccountSignerRecord
      | undefined;
    if (existingSigner && existingSigner.profileId !== profileId) {
      throw new DBConstraintError(
        'CHAIN_ACCOUNT_PROFILE_MISMATCH',
        `Signer row belongs to a different profile for ${chainIdKey}/${accountAddress}/${signerId}`,
        {
          expectedProfileId: profileId,
          existingProfileId: existingSigner.profileId,
          chainIdKey,
          accountAddress,
          signerId,
        },
      );
    }

    const signer = this.accountSignerRepository.buildAccountSignerRecord({
      profileId,
      chainIdKey,
      accountAddress,
      signerId,
      signerSlot: plan.signerSlot,
      signerType: input.signer.signerType as AccountSignerType,
      signerKind,
      signerAuthMethod,
      signerSource,
      status: 'active',
      existing: existingSigner,
      now,
      ...(input.signer.metadata ? { metadata: input.signer.metadata } : {}),
    });
    await this.accountSignerRepository.putPreparedAccountSignerInTransaction({
      store: signerStore,
      next: signer,
      accountModel: chainAccount.accountModel,
      existingSignerId: existingSigner?.signerId,
      existingStatus: existingSigner?.status,
    });

    const selectAsActive = input.selectAsActive ?? true;
    if (selectAsActive) {
      const lastProfileState: LastProfileState = {
        profileId,
        activeSignerSlot: plan.signerSlot,
        ...(this.lastUserScope != null ? { scope: this.lastUserScope } : {}),
      };
      const signerRows = (await signerStore.index('profileId').getAll(profileId)) as
        | AccountSignerRecord[]
        | undefined;
      const hasMatchingSignerSlot = (signerRows || []).some(
        (row) => row.signerSlot === lastProfileState.activeSignerSlot && row.status !== 'revoked',
      );
      if (!hasMatchingSignerSlot) {
        throw new DBConstraintError(
          'INVALID_LAST_PROFILE_STATE',
          `lastProfileState signer slot ${lastProfileState.activeSignerSlot} was not found for profile ${profileId}`,
          {
            profileId,
            activeSignerSlot: lastProfileState.activeSignerSlot,
          },
        );
      }
      await this.lastProfileStateRepository.setLastProfileStateInTransaction({
        tx,
        state: lastProfileState,
        scope: this.lastUserScope,
      });
    }

    const routeThroughOutbox = input.mutation?.routeThroughOutbox ?? false;
    if (routeThroughOutbox) {
      const opId =
        toTrimmedString(input.mutation?.opId || '') || this.createSignerOperationId('add-signer');
      const idempotencyKey =
        toTrimmedString(input.mutation?.idempotencyKey || '') ||
        `add-signer:${signer.chainIdKey}:${signer.accountAddress}:${signer.signerId}:${signer.signerSlot}`;
      await this.enqueueSignerOperationInTransaction(
        tx.objectStore(DB_CONFIG.signerOpsOutboxStore),
        {
          opId,
          idempotencyKey,
          opType: 'add-signer',
          chainIdKey: signer.chainIdKey,
          accountAddress: signer.accountAddress,
          signerId: signer.signerId,
          payload: {
            profileId: signer.profileId,
            signerSlot: signer.signerSlot,
            signerType: signer.signerType,
            ...(signer.signerKind ? { signerKind: signer.signerKind } : {}),
            ...(signer.signerAuthMethod ? { signerAuthMethod: signer.signerAuthMethod } : {}),
            ...(signer.signerSource ? { signerSource: signer.signerSource } : {}),
            ...(signer.metadata ? { signerMetadata: signer.metadata } : {}),
            ...(input.mutation?.outboxPayload ? input.mutation.outboxPayload : {}),
          },
          status: input.mutation?.outboxStatus || 'queued',
        },
      );
    }
    await tx.done;

    return {
      signer,
      signerSlot: plan.signerSlot,
    };
  }

  async stageAccountSigner(input: StageAccountSignerInput): Promise<StageAccountSignerResult> {
    const profileId = toTrimmedString(input.account.profileId || '');
    const chainIdKey = normalizeChainIdKey(input.account.chainIdKey);
    const accountAddress = normalizeAccountAddress(input.account.accountAddress);
    const accountModel = normalizeAccountModel(input.account.accountModel);
    const signerId = toTrimmedString(input.signer.signerId || '');
    const signerKind = toTrimmedString(input.signer.signerKind || '') as SignerKind;
    const signerAuthMethod = toTrimmedString(
      input.signer.signerAuthMethod || '',
    ) as SignerAuthMethod;
    const signerSource = toTrimmedString(input.signer.signerSource || '') as SignerSource;
    const signerSlot = Number(input.signer.signerSlot);
    if (
      !profileId ||
      !chainIdKey ||
      !accountAddress ||
      !accountModel ||
      !signerId ||
      !signerKind ||
      !signerAuthMethod ||
      !signerSource
    ) {
      throw new Error(
        'PasskeyClientDB: profileId, chainIdKey, accountAddress, accountModel, signerId, signerKind, signerAuthMethod, and signerSource are required',
      );
    }
    if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
      throw new Error('PasskeyClientDB: signerSlot must be an integer >= 1');
    }

    const db = await this.getDB();
    const tx = db.transaction(
      [
        DB_CONFIG.profilesStore,
        DB_CONFIG.chainAccountsStore,
        DB_CONFIG.accountSignersStore,
        DB_CONFIG.signerOpsOutboxStore,
      ],
      'readwrite',
    );
    const now = Date.now();
    const chainAccount = await this.chainAccountRepository.putChainAccountForSignerLifecycle({
      tx,
      profileId,
      chainIdKey,
      accountAddress,
      accountModel,
      now,
    });
    const signerStore = tx.objectStore(DB_CONFIG.accountSignersStore);
    const existingSigner = (await signerStore.get([chainIdKey, accountAddress, signerId])) as
      | AccountSignerRecord
      | undefined;
    if (existingSigner && existingSigner.profileId !== profileId) {
      throw new DBConstraintError(
        'CHAIN_ACCOUNT_PROFILE_MISMATCH',
        `Signer row belongs to a different profile for ${chainIdKey}/${accountAddress}/${signerId}`,
        {
          expectedProfileId: profileId,
          existingProfileId: existingSigner.profileId,
          chainIdKey,
          accountAddress,
          signerId,
        },
      );
    }

    const signer = this.accountSignerRepository.buildAccountSignerRecord({
      profileId,
      chainIdKey,
      accountAddress,
      signerId,
      signerSlot,
      signerType: input.signer.signerType as AccountSignerType,
      signerKind,
      signerAuthMethod,
      signerSource,
      status: 'pending',
      existing: existingSigner,
      now,
      ...(input.signer.metadata ? { metadata: input.signer.metadata } : {}),
    });
    await this.accountSignerRepository.putPreparedAccountSignerInTransaction({
      store: signerStore,
      next: signer,
      accountModel: chainAccount.accountModel,
      existingSignerId: existingSigner?.signerId,
      existingStatus: existingSigner?.status,
    });

    const routeThroughOutbox = input.mutation?.routeThroughOutbox ?? false;
    if (routeThroughOutbox) {
      const opId =
        toTrimmedString(input.mutation?.opId || '') || this.createSignerOperationId('add-signer');
      const idempotencyKey =
        toTrimmedString(input.mutation?.idempotencyKey || '') ||
        `add-signer:${signer.chainIdKey}:${signer.accountAddress}:${signer.signerId}:${signer.signerSlot}`;
      await this.enqueueSignerOperationInTransaction(
        tx.objectStore(DB_CONFIG.signerOpsOutboxStore),
        {
          opId,
          idempotencyKey,
          opType: 'add-signer',
          chainIdKey: signer.chainIdKey,
          accountAddress: signer.accountAddress,
          signerId: signer.signerId,
          payload: {
            profileId: signer.profileId,
            signerSlot: signer.signerSlot,
            signerType: signer.signerType,
            ...(signer.signerKind ? { signerKind: signer.signerKind } : {}),
            ...(signer.signerAuthMethod ? { signerAuthMethod: signer.signerAuthMethod } : {}),
            ...(signer.signerSource ? { signerSource: signer.signerSource } : {}),
            ...(signer.metadata ? { signerMetadata: signer.metadata } : {}),
            ...(input.mutation?.outboxPayload ? input.mutation.outboxPayload : {}),
          },
          status: input.mutation?.outboxStatus || 'queued',
        },
      );
    }
    await tx.done;

    return {
      signer,
      signerSlot,
    };
  }

  async listAccountSigners(args: {
    chainIdKey: string;
    accountAddress: string;
    status?: AccountSignerStatus;
  }): Promise<AccountSignerRecord[]> {
    return this.accountSignerRepository.listAccountSigners(args);
  }

  async getAccountSigner(args: {
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
  }): Promise<AccountSignerRecord | null> {
    return this.accountSignerRepository.getAccountSigner(args);
  }

  async setAccountSignerStatus(args: {
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
    status: AccountSignerStatus;
    removedAt?: number;
    revocationReason?: string;
    mutation?: SignerMutationOptions;
  }): Promise<AccountSignerRecord | null> {
    const updated = await this.accountSignerRepository.setAccountSignerStatusDirect({
      chainIdKey: args.chainIdKey,
      accountAddress: args.accountAddress,
      signerId: args.signerId,
      status: args.status,
      ...(args.removedAt != null ? { removedAt: args.removedAt } : {}),
      ...(args.revocationReason ? { revocationReason: args.revocationReason } : {}),
    });
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
        ...(updated.revocationReason ? { revocationReason: updated.revocationReason } : {}),
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

  async getLastProfileState(): Promise<LastProfileState | null> {
    return this.lastProfileStateRepository.getLastProfileState(this.lastUserScope);
  }

  async setLastProfileState(state: LastProfileState | null): Promise<void> {
    await this.lastProfileStateRepository.setLastProfileState(state, this.lastUserScope);
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
