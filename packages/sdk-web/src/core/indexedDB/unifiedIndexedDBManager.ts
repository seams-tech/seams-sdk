import { SIGNER_KINDS } from '@shared/utils/signerDomain';
import { toTrimmedString } from '@shared/utils/validation';
import type { AccountId } from '../types/accountIds';
import { normalizeLastUserScope } from './normalization';
import type {
  AccountRef,
  AccountSignerRecord,
  AccountSignerStatus,
  ChainAccountRecord,
  EnqueueSignerOperationInput,
  IndexedDBEvent,
  LastProfileState,
  LocalWalletAuthMethodRecord,
  NonceLaneLeaseStoreRecord,
  ProfileAuthenticatorRecord,
  ProfileContinuitySnapshot,
  ProfileRecoveryEmailRecord,
  ProfileRecord,
  SignerMutationOptions,
  SignerOperationStatus,
  SignerOpOutboxRecord,
  UpsertChainAccountInput,
  UpsertProfileInput,
  UserPreferences,
  WalletSignerLookup,
} from './passkeyClientDB.types';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ActivateAccountSignerInput as AccountSignerLifecycleInput,
  ActivateAccountSignerResult as AccountSignerLifecycleResult,
  StageAccountSignerInput,
  StageAccountSignerResult,
} from './accountSignerLifecycle';
import { type KeyMaterialKind, type KeyMaterialRecord } from './keyMaterial.types';
import { seamsWalletDB } from './singletons';
import type { SeamsWalletDBManager } from './seamsWalletDB/manager';
import {
  SeamsWalletRepositories,
  type StoreWalletSignerFinalizeBatchResult,
  type StoreWalletSignerFinalizeBatchInput,
  type StoreWalletSignerFinalizeRollbackReceipt,
  type StoreWalletRegistrationFinalizeBatchInput,
  type StoreWalletRegistrationFinalizeBatchResult,
} from './seamsWalletDB/repositories';

export interface UnifiedIndexedDBManagerDeps {
  seamsWalletDB: SeamsWalletDBManager;
}

export type LocalSignerReconciliationIssueCode =
  | 'duplicate_active_signer_slot'
  | 'active_signer_missing_key_material'
  | 'key_material_without_active_signer'
  | 'stale_pending_signer';

export type LocalSignerReconciliationIssue = {
  code: LocalSignerReconciliationIssueCode;
  profileId: string;
  chainIdKey?: string;
  accountAddress?: string;
  signerId?: string;
  signerSlot?: number;
  keyKind?: string;
  message: string;
};

export type LocalSignerReconciliationSummary = {
  scannedProfiles: number;
  scannedSigners: number;
  scannedKeyMaterials: number;
  issues: LocalSignerReconciliationIssue[];
  repairs: string[];
};

const DEFAULT_STALE_PENDING_SIGNER_MS = 24 * 60 * 60_000;
const KEY_MATERIAL_SIGNER_KINDS = new Set<string>(Object.values(SIGNER_KINDS));

export class UnifiedIndexedDBManager {
  public readonly seamsWalletDB: SeamsWalletDBManager;
  private readonly seamsWalletRepositories: SeamsWalletRepositories;
  private readonly eventListeners: Set<(event: IndexedDBEvent) => void> = new Set();
  private _initialized = false;
  private lastUserScope: string | null = null;

  constructor(deps?: Partial<UnifiedIndexedDBManagerDeps>) {
    this.seamsWalletDB = deps?.seamsWalletDB || seamsWalletDB;
    this.seamsWalletRepositories = new SeamsWalletRepositories(this.seamsWalletDB);
  }

  async initialize(): Promise<void> {
    if (this._initialized) {
      return;
    }

    try {
      if (this.seamsWalletDB.isDisabled()) {
        this._initialized = true;
        return;
      }
      // Initialize all active persistence managers.
      await this.seamsWalletRepositories.getAppState('_init_check');

      try {
        await this.repairSignerMutationSagas({ limit: 64 });
      } catch (error) {
        console.warn('IndexedDB saga repair failed during initialize:', error);
      }
      try {
        await this.reconcileLocalSignerState({ limitProfiles: 64, logIssues: true });
      } catch (error) {
        console.warn('IndexedDB local signer reconciliation failed during initialize:', error);
      }

      this._initialized = true;
    } catch (error) {
      console.warn('Failed to initialize IndexedDB databases:', error);
      // Don't throw - allow the SDK to continue working, databases will be initialized on first use
    }
  }

  /**
   * Check if databases have been initialized
   */
  get isInitialized(): boolean {
    return this._initialized;
  }

  isDisabled(): boolean {
    return this.seamsWalletDB.isDisabled();
  }

  onChange(callback: (event: IndexedDBEvent) => void): () => void {
    this.eventListeners.add(callback);
    return () => {
      this.eventListeners.delete(callback);
    };
  }

  private emitEvent(event: IndexedDBEvent): void {
    for (const listener of this.eventListeners) {
      try {
        listener(event);
      } catch (error) {
        console.warn('[UnifiedIndexedDBManager]: Error in event listener:', error);
      }
    }
  }

  async getAppState<T = unknown>(key: string): Promise<T | undefined> {
    return this.seamsWalletRepositories.getAppState<T>(key);
  }

  async setAppState<T = unknown>(key: string, value: T): Promise<void> {
    return this.seamsWalletRepositories.setAppState(key, value);
  }

  async upsertRecoveryEmails(
    walletId: string,
    entries: Array<{ hashHex: string; email: string }>,
  ): Promise<void> {
    return this.seamsWalletRepositories.upsertRecoveryEmails(walletId, entries);
  }

  async listRecoveryEmails(profileId: string): Promise<ProfileRecoveryEmailRecord[]> {
    return this.seamsWalletRepositories.listRecoveryEmails(profileId);
  }

  setLastUserScope(scope: string | null): void {
    this.lastUserScope = normalizeLastUserScope(scope);
  }

  getLastUserScope(): string | null {
    return this.lastUserScope;
  }

  async getLastProfileState(): Promise<LastProfileState | null> {
    return this.seamsWalletRepositories.getLastProfileState(this.lastUserScope);
  }

  async setLastProfileState(state: LastProfileState | null): Promise<void> {
    return this.seamsWalletRepositories.setLastProfileState(state, this.lastUserScope);
  }

  async setLastProfileStateForProfile(profileId: string, activeSignerSlot: number): Promise<void> {
    return this.seamsWalletRepositories.setLastProfileStateForProfile(
      profileId,
      activeSignerSlot,
      this.lastUserScope,
    );
  }

  async clearLastProfileSelection(): Promise<void> {
    return this.seamsWalletRepositories.clearLastProfileSelection(this.lastUserScope);
  }

  async readNonceLaneLeaseRecords(laneKey: string): Promise<NonceLaneLeaseStoreRecord[]> {
    return this.seamsWalletRepositories.readNonceLaneLeaseRecords(laneKey);
  }

  async listNonceLaneLeaseRecords(args?: {
    walletId?: string;
  }): Promise<NonceLaneLeaseStoreRecord[]> {
    return this.seamsWalletRepositories.listNonceLaneLeaseRecords(args);
  }

  async upsertNonceLaneLeaseRecord(record: NonceLaneLeaseStoreRecord): Promise<void> {
    return this.seamsWalletRepositories.upsertNonceLaneLeaseRecord(record);
  }

  async removeNonceLaneLeaseRecord(input: { leaseId: string }): Promise<void> {
    return this.seamsWalletRepositories.removeNonceLaneLeaseRecord(input);
  }

  async clearNonceLaneLeaseRecordsForWallet(walletId: string): Promise<void> {
    return this.seamsWalletRepositories.clearNonceLaneLeaseRecordsForWallet(walletId);
  }

  async clearAllNonceLaneLeaseRecords(): Promise<void> {
    return this.seamsWalletRepositories.clearAllNonceLaneLeaseRecords();
  }

  async pruneExpiredNonceLaneLeaseRecords(nowMs: number): Promise<void> {
    return this.seamsWalletRepositories.pruneExpiredNonceLaneLeaseRecords(nowMs);
  }

  async withNonceLaneCoordinationLock<T>(
    input: {
      lockKey: string;
      ownerId: string;
      ttlMs?: number;
      waitTimeoutMs?: number;
    },
    task: () => Promise<T>,
  ): Promise<T> {
    return this.seamsWalletRepositories.withNonceLaneCoordinationLock(input, task);
  }

  // === profile/account/signer convenience ===
  async getProfile(profileId: string): Promise<ProfileRecord | null> {
    return this.seamsWalletRepositories.getProfile(profileId);
  }

  async getWalletPreferences(walletId: string): Promise<Partial<UserPreferences>> {
    return await this.seamsWalletRepositories.getWalletPreferences(walletId);
  }

  async listProfiles(args?: { limit?: number }): Promise<ProfileRecord[]> {
    return this.seamsWalletRepositories.listProfiles(args);
  }

  async upsertProfile(input: UpsertProfileInput): Promise<ProfileRecord> {
    return this.seamsWalletRepositories.upsertProfile(input);
  }

  async upsertChainAccount(input: UpsertChainAccountInput): Promise<ChainAccountRecord> {
    return this.seamsWalletRepositories.upsertChainAccount(input);
  }

  async listChainAccountsByProfile(profileId: string): Promise<ChainAccountRecord[]> {
    return this.seamsWalletRepositories.listChainAccountsByProfile(profileId);
  }

  async listChainAccountsByProfileAndChain(
    profileId: string,
    chainIdKey: string,
  ): Promise<ChainAccountRecord[]> {
    return this.seamsWalletRepositories.listChainAccountsByProfileAndChain(profileId, chainIdKey);
  }

  async listChainAccountsByChain(chainIdKey: string): Promise<ChainAccountRecord[]> {
    return this.seamsWalletRepositories.listChainAccountsByChain(chainIdKey);
  }

  async getChainAccount(args: {
    profileId: string;
    chainIdKey: string;
    accountAddress: string;
  }): Promise<ChainAccountRecord | null> {
    return this.seamsWalletRepositories.getChainAccount(args);
  }

  async resolveProfileAccountContext(
    accountRef: AccountRef,
  ): Promise<{ profileId: string; accountRef: AccountRef } | null> {
    return this.seamsWalletRepositories.resolveProfileAccountContext(accountRef);
  }

  async getProfileContinuitySnapshot(profileId: string): Promise<ProfileContinuitySnapshot | null> {
    return this.seamsWalletRepositories.getProfileContinuitySnapshot(profileId);
  }

  async activateAccountSigner(
    input: AccountSignerLifecycleInput,
  ): Promise<AccountSignerLifecycleResult> {
    return this.seamsWalletRepositories.activateAccountSigner(input);
  }

  async stageAccountSigner(input: StageAccountSignerInput): Promise<StageAccountSignerResult> {
    return this.seamsWalletRepositories.stageAccountSigner(input);
  }

  async listAccountSigners(args: {
    chainIdKey: string;
    accountAddress: string;
    status?: AccountSignerStatus;
  }): Promise<AccountSignerRecord[]> {
    return this.seamsWalletRepositories.listAccountSigners(args);
  }

  async listAccountSignersByProfile(args: {
    profileId: string;
    status?: AccountSignerStatus;
  }): Promise<AccountSignerRecord[]> {
    return this.seamsWalletRepositories.listAccountSignersByProfile(args);
  }

  async listActiveWalletSigners(args: {
    walletId: string;
    signerFamily: WalletSignerLookup['signerFamily'];
  }): Promise<AccountSignerRecord[]> {
    return this.seamsWalletRepositories.listActiveWalletSigners(args);
  }

  async getActiveWalletSignerForChainTarget(args: {
    walletId: string;
    chainTarget: ThresholdEcdsaChainTarget;
  }): Promise<AccountSignerRecord | null> {
    return this.seamsWalletRepositories.getActiveWalletSignerForChainTarget(args);
  }

  async getAccountSigner(args: {
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
  }): Promise<AccountSignerRecord | null> {
    return this.seamsWalletRepositories.getAccountSigner(args);
  }

  async setAccountSignerStatus(args: {
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
    status: AccountSignerStatus;
    removedAt?: number;
    mutation?: SignerMutationOptions;
  }): Promise<AccountSignerRecord | null> {
    return this.seamsWalletRepositories.setAccountSignerStatus(args);
  }

  async enqueueSignerOperation(input: EnqueueSignerOperationInput): Promise<SignerOpOutboxRecord> {
    return this.seamsWalletRepositories.enqueueSignerOperation(input);
  }

  async listSignerOperations(args?: {
    statuses?: SignerOperationStatus[];
    dueBefore?: number;
    limit?: number;
  }): Promise<SignerOpOutboxRecord[]> {
    return this.seamsWalletRepositories.listSignerOperations(args);
  }

  async setSignerOperationStatus(args: {
    opId: string;
    status: SignerOperationStatus;
    attemptDelta?: number;
    nextAttemptAt?: number;
    lastError?: string | null;
    txHash?: string | null;
  }): Promise<SignerOpOutboxRecord | null> {
    return this.seamsWalletRepositories.setSignerOperationStatus(args);
  }

  async listProfileAuthenticators(profileId: string): Promise<ProfileAuthenticatorRecord[]> {
    return this.seamsWalletRepositories.listProfileAuthenticators(profileId);
  }

  async listWalletPasskeyAuthenticators(walletId: string): Promise<ProfileAuthenticatorRecord[]> {
    return this.seamsWalletRepositories.listWalletPasskeyAuthenticators(walletId);
  }

  async upsertProfileAuthenticator(record: ProfileAuthenticatorRecord): Promise<void> {
    return this.seamsWalletRepositories.upsertProfileAuthenticator(record);
  }

  async getProfileAuthenticatorByCredentialId(
    profileId: string,
    credentialId: string,
  ): Promise<ProfileAuthenticatorRecord | null> {
    return this.seamsWalletRepositories.getProfileAuthenticatorByCredentialId(
      profileId,
      credentialId,
    );
  }

  async getWalletPasskeyAuthenticator(args: {
    walletId: string;
    credentialId: string;
  }): Promise<ProfileAuthenticatorRecord | null> {
    return this.seamsWalletRepositories.getWalletPasskeyAuthenticator(args);
  }

  async upsertWalletAuthMethod(
    record: LocalWalletAuthMethodRecord,
  ): Promise<LocalWalletAuthMethodRecord> {
    return this.seamsWalletRepositories.upsertWalletAuthMethod(record);
  }

  async listWalletAuthMethodsForWallet(walletId: string): Promise<LocalWalletAuthMethodRecord[]> {
    return this.seamsWalletRepositories.listWalletAuthMethodsForWallet(walletId);
  }

  async persistWalletRegistrationFinalize(
    input: StoreWalletRegistrationFinalizeBatchInput,
  ): Promise<StoreWalletRegistrationFinalizeBatchResult> {
    return this.seamsWalletRepositories.persistWalletRegistrationFinalize(input);
  }

  async persistWalletSignerFinalize(
    input: StoreWalletSignerFinalizeBatchInput,
  ): Promise<StoreWalletSignerFinalizeBatchResult> {
    return this.seamsWalletRepositories.persistWalletSignerFinalize(input);
  }

  async rollbackWalletSignerFinalize(
    receipt: StoreWalletSignerFinalizeRollbackReceipt,
  ): Promise<void> {
    return this.seamsWalletRepositories.rollbackWalletSignerFinalize(receipt);
  }

  async clearProfileAuthenticators(profileId: string): Promise<void> {
    return this.seamsWalletRepositories.clearProfileAuthenticators(profileId);
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
    return this.seamsWalletRepositories.selectProfileAuthenticatorsForPrompt(args);
  }

  async updatePreferences(args: {
    profileId: string;
    preferences: Partial<UserPreferences>;
    eventAccountId?: string | null;
  }): Promise<void> {
    const updatedPreferences = await this.seamsWalletRepositories.updatePreferences(args);
    const accountId = toTrimmedString(args.eventAccountId || '');
    if (updatedPreferences && accountId) {
      this.emitEvent({
        type: 'preferences-updated',
        accountId: accountId as AccountId,
        data: { preferences: updatedPreferences },
      });
    }
  }

  async updateWalletPreferences(args: {
    walletId: string;
    preferences: Partial<UserPreferences>;
  }): Promise<void> {
    const updatedPreferences = await this.seamsWalletRepositories.updateWalletPreferences(args);
    if (updatedPreferences) {
      this.emitEvent({
        type: 'preferences-updated',
        accountId: args.walletId as AccountId,
        data: { preferences: updatedPreferences },
      });
    }
  }

  async deleteProfileData(
    profileId: string,
    args?: { eventAccountId?: AccountId | null },
  ): Promise<void> {
    await this.seamsWalletRepositories.deleteProfileData(profileId, this.lastUserScope);
    const accountId = toTrimmedString(args?.eventAccountId || '');
    if (accountId) {
      this.emitEvent({ type: 'user-deleted', accountId: accountId as AccountId });
    }
  }

  // === key material convenience ===
  async storeKeyMaterial(input: KeyMaterialRecord): Promise<void> {
    return this.seamsWalletRepositories.storeKeyMaterial(input);
  }

  async getKeyMaterial(
    profileId: string,
    signerSlot: number,
    chainIdKey: string,
    keyKind: KeyMaterialKind,
  ): Promise<KeyMaterialRecord | null> {
    return this.seamsWalletRepositories.getKeyMaterial(profileId, signerSlot, chainIdKey, keyKind);
  }

  async deleteKeyMaterial(
    profileId: string,
    signerSlot: number,
    chainIdKey: string,
    keyKind: KeyMaterialKind,
  ): Promise<void> {
    return this.seamsWalletRepositories.deleteKeyMaterial(
      profileId,
      signerSlot,
      chainIdKey,
      keyKind,
    );
  }

  async listKeyMaterialByProfile(
    profileId: string,
    chainIdKey?: string,
  ): Promise<KeyMaterialRecord[]> {
    return this.seamsWalletRepositories.listKeyMaterialByProfile(profileId, chainIdKey);
  }

  async reconcileLocalSignerState(args?: {
    profileId?: string;
    limitProfiles?: number;
    stalePendingSignerMs?: number;
    now?: number;
    logIssues?: boolean;
  }): Promise<LocalSignerReconciliationSummary> {
    const now = typeof args?.now === 'number' ? args.now : Date.now();
    const stalePendingSignerMs =
      Number.isSafeInteger(args?.stalePendingSignerMs) && Number(args?.stalePendingSignerMs) > 0
        ? Number(args?.stalePendingSignerMs)
        : DEFAULT_STALE_PENDING_SIGNER_MS;
    const profileId = toTrimmedString(args?.profileId || '');
    const profiles = profileId
      ? await this.getProfile(profileId).then((profile) => (profile ? [profile] : []))
      : await this.listProfiles({ limit: args?.limitProfiles });
    const summary: LocalSignerReconciliationSummary = {
      scannedProfiles: 0,
      scannedSigners: 0,
      scannedKeyMaterials: 0,
      issues: [],
      repairs: [],
    };

    const pushIssue = (issue: LocalSignerReconciliationIssue): void => {
      summary.issues.push(issue);
    };

    for (const profile of profiles) {
      summary.scannedProfiles += 1;
      const signers = await this.listAccountSignersByProfile({
        profileId: profile.profileId,
      });
      const keyMaterials = await this.seamsWalletRepositories.listKeyMaterialByProfile(
        profile.profileId,
      );
      summary.scannedSigners += signers.length;
      summary.scannedKeyMaterials += keyMaterials.length;

      const activeByAccountSlot = new Map<string, AccountSignerRecord[]>();
      const activeSlotKeys = new Set<string>();
      for (const signer of signers) {
        if (signer.status !== 'active') continue;
        const slotKey = [signer.chainIdKey, signer.accountAddress, String(signer.signerSlot)].join(
          '\0',
        );
        activeSlotKeys.add(slotKey);
        const existing = activeByAccountSlot.get(slotKey) || [];
        existing.push(signer);
        activeByAccountSlot.set(slotKey, existing);
      }

      for (const [slotKey, slotSigners] of activeByAccountSlot.entries()) {
        if (slotSigners.length <= 1) continue;
        const [chainIdKey, accountAddress, signerSlotRaw] = slotKey.split('\0');
        pushIssue({
          code: 'duplicate_active_signer_slot',
          profileId: profile.profileId,
          chainIdKey,
          accountAddress,
          signerSlot: Number(signerSlotRaw),
          message: `Multiple active signers share slot ${signerSlotRaw} for ${chainIdKey}/${accountAddress}`,
        });
      }

      for (const signer of signers) {
        if (
          signer.status === 'pending' &&
          now - Number(signer.addedAt || 0) > stalePendingSignerMs
        ) {
          pushIssue({
            code: 'stale_pending_signer',
            profileId: profile.profileId,
            chainIdKey: signer.chainIdKey,
            accountAddress: signer.accountAddress,
            signerId: signer.signerId,
            signerSlot: signer.signerSlot,
            message: `Pending signer ${signer.signerId} has been pending longer than ${stalePendingSignerMs}ms`,
          });
        }

        if (
          signer.status === 'active' &&
          KEY_MATERIAL_SIGNER_KINDS.has(String(signer.signerKind || ''))
        ) {
          const matchingKeys = keyMaterials.filter(
            (key) =>
              key.chainIdKey === signer.chainIdKey &&
              key.signerSlot === signer.signerSlot &&
              key.keyKind === 'threshold_share_v1',
          );
          if (matchingKeys.length === 0) {
            pushIssue({
              code: 'active_signer_missing_key_material',
              profileId: profile.profileId,
              chainIdKey: signer.chainIdKey,
              accountAddress: signer.accountAddress,
              signerId: signer.signerId,
              signerSlot: signer.signerSlot,
              message: `Active ${signer.signerKind} signer ${signer.signerId} has no threshold key material`,
            });
          }
        }
      }

      for (const keyMaterial of keyMaterials) {
        const slotKey = [
          keyMaterial.chainIdKey,
          keyMaterial.payloadEnvelope?.aad?.accountAddress || '',
          String(keyMaterial.signerSlot),
        ].join('\0');
        const hasActiveSignerAtSameSlot =
          activeSlotKeys.has(slotKey) ||
          signers.some(
            (signer) =>
              signer.status === 'active' &&
              signer.chainIdKey === keyMaterial.chainIdKey &&
              signer.signerSlot === keyMaterial.signerSlot,
          );
        if (!hasActiveSignerAtSameSlot) {
          pushIssue({
            code: 'key_material_without_active_signer',
            profileId: profile.profileId,
            chainIdKey: keyMaterial.chainIdKey,
            signerSlot: keyMaterial.signerSlot,
            keyKind: keyMaterial.keyKind,
            message: `Key material ${keyMaterial.keyKind} at slot ${keyMaterial.signerSlot} has no active signer`,
          });
        }
      }
    }

    if (args?.logIssues && summary.issues.length > 0) {
      console.warn('[IndexedDB] local signer reconciliation found issues', {
        issueCount: summary.issues.length,
        issues: summary.issues.slice(0, 20),
      });
    }

    return summary;
  }

  private computeSignerOpRetryDelayMs(nextAttemptCount: number): number {
    const bounded = Math.max(1, Math.min(nextAttemptCount, 8));
    return Math.min(5 * 60_000, 5_000 * Math.pow(2, bounded - 1));
  }

  async repairSignerMutationSagas(args?: { limit?: number; now?: number }): Promise<{
    scanned: number;
    confirmed: number;
    failed: number;
    deadLettered: number;
  }> {
    return await this.repairSignerMutationSagasWithRuntime(args);
  }

  async repairSignerMutationSagasWithRuntime(args?: { limit?: number; now?: number }): Promise<{
    scanned: number;
    confirmed: number;
    failed: number;
    deadLettered: number;
  }> {
    const now = typeof args?.now === 'number' ? args.now : Date.now();
    const limit =
      Number.isSafeInteger(args?.limit) && Number(args?.limit) > 0 ? Number(args?.limit) : 100;
    const summary = {
      scanned: 0,
      confirmed: 0,
      failed: 0,
      deadLettered: 0,
    };

    const ops = await this.listSignerOperations({
      statuses: ['queued', 'submitted', 'failed'],
      dueBefore: now,
      limit,
    });

    for (const op of ops) {
      summary.scanned += 1;
      const payload = (op.payload || {}) as Record<string, unknown>;
      const signer = await this.getAccountSigner({
        chainIdKey: op.chainIdKey,
        accountAddress: op.accountAddress,
        signerId: op.signerId,
      });
      const profileIdRaw = toTrimmedString(signer?.profileId || payload.profileId || '');
      const signerSlotRaw = Number(payload.signerSlot ?? signer?.signerSlot);
      const signerSlot =
        Number.isSafeInteger(signerSlotRaw) && signerSlotRaw >= 1 ? signerSlotRaw : null;

      const markFailed = async (reason: string): Promise<void> => {
        const nextAttemptCount = (op.attemptCount || 0) + 1;
        await this.setSignerOperationStatus({
          opId: op.opId,
          status: 'failed',
          attemptDelta: 1,
          lastError: reason,
          nextAttemptAt: now + this.computeSignerOpRetryDelayMs(nextAttemptCount),
        });
        summary.failed += 1;
      };

      const markDeadLetter = async (reason: string): Promise<void> => {
        await this.setSignerOperationStatus({
          opId: op.opId,
          status: 'dead-letter',
          lastError: reason,
          nextAttemptAt: now,
        });
        summary.deadLettered += 1;
      };

      const markConfirmed = async (): Promise<void> => {
        await this.setSignerOperationStatus({
          opId: op.opId,
          status: 'confirmed',
          lastError: null,
          nextAttemptAt: now,
        });
        summary.confirmed += 1;
      };

      try {
        if (op.opType === 'add-signer' || op.opType === 'activate-recovery-signer') {
          if (!signer) {
            await markDeadLetter('Missing signer row for add-signer operation');
            continue;
          }
          if (signer.status === 'revoked') {
            await markDeadLetter('Cannot activate a revoked signer; create a new signer record');
            continue;
          }
          if (!profileIdRaw || signerSlot == null) {
            await markDeadLetter('Missing profileId/signerSlot metadata for add-signer operation');
            continue;
          }
          const chainAccount = await this.getChainAccount({
            profileId: signer.profileId,
            chainIdKey: op.chainIdKey,
            accountAddress: op.accountAddress,
          });
          if (!chainAccount) {
            await markDeadLetter('Missing chain account row for add-signer operation');
            continue;
          }
          const keys = await this.seamsWalletRepositories.listKeyMaterialByProfileAndSignerSlot(
            profileIdRaw,
            signerSlot,
            op.chainIdKey,
          );
          if (keys.length === 0) {
            await markFailed('Missing key material for signer operation');
            continue;
          }
          await markConfirmed();
          continue;
        }

        if (op.opType === 'revoke-signer') {
          if (signer) {
            if (signer.status !== 'revoked') {
              await this.setAccountSignerStatus({
                chainIdKey: op.chainIdKey,
                accountAddress: op.accountAddress,
                signerId: op.signerId,
                status: 'revoked',
                removedAt: now,
                mutation: { routeThroughOutbox: false },
              });
            }
            if (profileIdRaw && signerSlot != null) {
              const keys = await this.seamsWalletRepositories.listKeyMaterialByProfileAndSignerSlot(
                profileIdRaw,
                signerSlot,
                op.chainIdKey,
              );
              for (const key of keys) {
                await this.seamsWalletRepositories.deleteKeyMaterial(
                  key.profileId,
                  key.signerSlot,
                  key.chainIdKey,
                  key.keyKind,
                );
              }
            }
          }
          await markConfirmed();
          continue;
        }

        await markDeadLetter(`Unsupported signer operation type: ${String(op.opType || '')}`);
      } catch (error: any) {
        await markFailed(String(error?.message || error || 'Unknown saga repair error'));
      }
    }

    return summary;
  }
}
