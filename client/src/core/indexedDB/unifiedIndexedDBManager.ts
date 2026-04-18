import type { AccountId } from '../types/accountIds';
import { SIGNER_KINDS } from '@shared/utils/signerDomain';
import { toTrimmedString } from '@shared/utils/validation';
import type { PasskeyClientDBManager } from './passkeyClientDB/manager';
import type {
  AccountSignerRecord,
  AccountSignerStatus,
  ChainAccountRecord,
  EnqueueSignerOperationInput,
  LastProfileState,
  ProfileRecord,
  SignerMutationOptions,
  SignerOperationStatus,
  SignerOpOutboxRecord,
  UpsertChainAccountInput,
  UpsertProfileInput,
} from './passkeyClientDB.types';
import type {
  ActivateAccountSignerInput as AccountSignerLifecycleInput,
  ActivateAccountSignerResult as AccountSignerLifecycleResult,
  StageAccountSignerInput,
  StageAccountSignerResult,
} from './accountSignerLifecycle';
import type { AccountKeyMaterialDBManager } from './accountKeyMaterialDB/manager';
import { type KeyMaterialKind, type KeyMaterialRecord } from './accountKeyMaterialDB.types';
import { passkeyClientDB, accountKeyMaterialDB } from './singletons';

export interface UnifiedIndexedDBManagerDeps {
  clientDB: PasskeyClientDBManager;
  accountKeyMaterialDB: AccountKeyMaterialDBManager;
}

type DeployedSignerMutationRuntime = {
  resolveOwnerAccountId: (args: {
    profileId: string;
    op: SignerOpOutboxRecord;
    signer: AccountSignerRecord;
    chainAccount: ChainAccountRecord;
  }) => Promise<AccountId | null>;
  executeDeployedAddSigner: (args: {
    ownerAccountId: AccountId;
    op: SignerOpOutboxRecord;
    signer: AccountSignerRecord;
    chainAccount: ChainAccountRecord;
    now: number;
  }) => Promise<{ txHash?: string | null }>;
  executeDeployedRemoveSigner?: (args: {
    ownerAccountId: AccountId;
    op: SignerOpOutboxRecord;
    signer: AccountSignerRecord;
    chainAccount: ChainAccountRecord;
    now: number;
  }) => Promise<{ txHash?: string | null }>;
};

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

/**
 * Unified IndexedDB interface providing access to both databases
 * This allows centralized access while maintaining separation of concerns
 */
export class UnifiedIndexedDBManager {
  public readonly clientDB: PasskeyClientDBManager;
  public readonly accountKeyMaterialDB: AccountKeyMaterialDBManager;
  private _initialized = false;

  constructor(deps?: Partial<UnifiedIndexedDBManagerDeps>) {
    this.clientDB = deps?.clientDB || passkeyClientDB;
    this.accountKeyMaterialDB = deps?.accountKeyMaterialDB || accountKeyMaterialDB;
  }

  /**
   * Initialize both databases proactively
   * This ensures both databases are created and ready for use
   */
  async initialize(): Promise<void> {
    if (this._initialized) {
      return;
    }

    try {
      if (this.clientDB.isDisabled() || this.accountKeyMaterialDB.isDisabled()) {
        this._initialized = true;
        return;
      }
      // Initialize both databases by calling a simple operation
      // This will trigger the getDB() method in both managers and ensure databases are created
      await Promise.all([
        this.clientDB.getAppState('_init_check'),
        this.accountKeyMaterialDB.getKeyMaterial('_init_check', 1, 'init:check', 'init_check'),
      ]);

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

  async getLastProfileState(): Promise<LastProfileState | null> {
    return this.clientDB.getLastProfileState();
  }

  async setLastProfileState(state: LastProfileState | null): Promise<void> {
    return this.clientDB.setLastProfileState(state);
  }

  // === profile/account/signer convenience ===
  async getProfile(profileId: string): Promise<ProfileRecord | null> {
    return this.clientDB.getProfile(profileId);
  }

  async listProfiles(args?: { limit?: number }): Promise<ProfileRecord[]> {
    return this.clientDB.listProfiles(args);
  }

  async upsertProfile(input: UpsertProfileInput): Promise<ProfileRecord> {
    return this.clientDB.upsertProfile(input);
  }

  async upsertChainAccount(input: UpsertChainAccountInput): Promise<ChainAccountRecord> {
    return this.clientDB.upsertChainAccount(input);
  }

  async getChainAccount(args: {
    profileId: string;
    chainIdKey: string;
    accountAddress: string;
  }): Promise<ChainAccountRecord | null> {
    return this.clientDB.getChainAccount(args);
  }

  async activateAccountSigner(
    input: AccountSignerLifecycleInput,
  ): Promise<AccountSignerLifecycleResult> {
    return this.clientDB.activateAccountSigner(input);
  }

  async stageAccountSigner(input: StageAccountSignerInput): Promise<StageAccountSignerResult> {
    return this.clientDB.stageAccountSigner(input);
  }

  async listAccountSigners(args: {
    chainIdKey: string;
    accountAddress: string;
    status?: AccountSignerStatus;
  }): Promise<AccountSignerRecord[]> {
    return this.clientDB.listAccountSigners(args);
  }

  async getAccountSigner(args: {
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
  }): Promise<AccountSignerRecord | null> {
    return this.clientDB.getAccountSigner(args);
  }

  async setAccountSignerStatus(args: {
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
    status: AccountSignerStatus;
    removedAt?: number;
    mutation?: SignerMutationOptions;
  }): Promise<AccountSignerRecord | null> {
    return this.clientDB.setAccountSignerStatus(args);
  }

  async enqueueSignerOperation(input: EnqueueSignerOperationInput): Promise<SignerOpOutboxRecord> {
    return this.clientDB.enqueueSignerOperation(input);
  }

  async listSignerOperations(args?: {
    statuses?: SignerOperationStatus[];
    dueBefore?: number;
    limit?: number;
  }): Promise<SignerOpOutboxRecord[]> {
    return this.clientDB.listSignerOperations(args);
  }

  async setSignerOperationStatus(args: {
    opId: string;
    status: SignerOperationStatus;
    attemptDelta?: number;
    nextAttemptAt?: number;
    lastError?: string | null;
    txHash?: string | null;
  }): Promise<SignerOpOutboxRecord | null> {
    return this.clientDB.setSignerOperationStatus(args);
  }

  // === key material convenience ===
  async storeKeyMaterial(input: KeyMaterialRecord): Promise<void> {
    return this.accountKeyMaterialDB.storeKeyMaterial(input);
  }

  async getKeyMaterial(
    profileId: string,
    signerSlot: number,
    chainIdKey: string,
    keyKind: KeyMaterialKind,
  ): Promise<KeyMaterialRecord | null> {
    return this.accountKeyMaterialDB.getKeyMaterial(profileId, signerSlot, chainIdKey, keyKind);
  }

  async listKeyMaterialByProfile(
    profileId: string,
    chainIdKey?: string,
  ): Promise<KeyMaterialRecord[]> {
    return this.accountKeyMaterialDB.listKeyMaterialByProfile(profileId, chainIdKey);
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
      ? (await this.clientDB.getProfile(profileId).then((profile) => (profile ? [profile] : [])))
      : await this.clientDB.listProfiles({ limit: args?.limitProfiles });
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
      const signers = await this.clientDB.listAccountSignersByProfile({
        profileId: profile.profileId,
      });
      const keyMaterials = await this.accountKeyMaterialDB.listKeyMaterialByProfile(
        profile.profileId,
      );
      summary.scannedSigners += signers.length;
      summary.scannedKeyMaterials += keyMaterials.length;

      const activeByAccountSlot = new Map<string, AccountSignerRecord[]>();
      const activeSlotKeys = new Set<string>();
      for (const signer of signers) {
        if (signer.status !== 'active') continue;
        const slotKey = [
          signer.chainIdKey,
          signer.accountAddress,
          String(signer.signerSlot),
        ].join('\0');
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
        if (signer.status === 'pending' && now - Number(signer.addedAt || 0) > stalePendingSignerMs) {
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

  async repairSignerMutationSagasWithRuntime(args?: {
    limit?: number;
    now?: number;
    runtime?: DeployedSignerMutationRuntime;
  }): Promise<{
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

    const ops = await this.clientDB.listSignerOperations({
      statuses: ['queued', 'submitted', 'failed'],
      dueBefore: now,
      limit,
    });

    for (const op of ops) {
      summary.scanned += 1;
      const payload = (op.payload || {}) as Record<string, unknown>;
      const signer = await this.clientDB.getAccountSigner({
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
        await this.clientDB.setSignerOperationStatus({
          opId: op.opId,
          status: 'failed',
          attemptDelta: 1,
          lastError: reason,
          nextAttemptAt: now + this.computeSignerOpRetryDelayMs(nextAttemptCount),
        });
        summary.failed += 1;
      };

      const markDeadLetter = async (reason: string): Promise<void> => {
        await this.clientDB.setSignerOperationStatus({
          opId: op.opId,
          status: 'dead-letter',
          lastError: reason,
          nextAttemptAt: now,
        });
        summary.deadLettered += 1;
      };

      const markConfirmed = async (): Promise<void> => {
        await this.clientDB.setSignerOperationStatus({
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
          const chainAccount = await this.clientDB.getChainAccount({
            profileId: signer.profileId,
            chainIdKey: op.chainIdKey,
            accountAddress: op.accountAddress,
          });
          if (!chainAccount) {
            await markDeadLetter('Missing chain account row for add-signer operation');
            continue;
          }
          const keys = await this.accountKeyMaterialDB.listKeyMaterialByProfileAndSignerSlot(
            profileIdRaw,
            signerSlot,
            op.chainIdKey,
          );
          if (keys.length === 0) {
            await markFailed('Missing key material for signer operation');
            continue;
          }
          if (chainAccount.deployed === true) {
            if (signer.status === 'active') {
              await markConfirmed();
              continue;
            }
            if (!args?.runtime?.resolveOwnerAccountId) {
              await markFailed(
                'Deployed smart-account signer mutation requires an owner-account resolver',
              );
              continue;
            }
            const ownerAccountId = await args.runtime.resolveOwnerAccountId({
              profileId: profileIdRaw,
              op,
              signer,
              chainAccount,
            });
            if (!ownerAccountId) {
              await markDeadLetter('Missing owner account row for deployed signer operation');
              continue;
            }
            if (!args?.runtime?.executeDeployedAddSigner) {
              await markFailed(
                'Deployed smart-account signer mutation requires the owner-management executor',
              );
              continue;
            }
            const executed = await args.runtime.executeDeployedAddSigner({
              ownerAccountId,
              op,
              signer,
              chainAccount,
              now,
            });
            await this.clientDB.setAccountSignerStatus({
              chainIdKey: op.chainIdKey,
              accountAddress: op.accountAddress,
              signerId: op.signerId,
              status: 'active',
              mutation: { routeThroughOutbox: false },
            });
            await this.clientDB.setSignerOperationStatus({
              opId: op.opId,
              status: 'confirmed',
              lastError: null,
              nextAttemptAt: now,
              ...(executed?.txHash ? { txHash: executed.txHash } : {}),
            });
            summary.confirmed += 1;
            continue;
          }
          await markConfirmed();
          continue;
        }

        if (op.opType === 'revoke-signer') {
          const chainAccount =
            signer && signer.profileId
              ? await this.clientDB.getChainAccount({
                  profileId: signer.profileId,
                  chainIdKey: op.chainIdKey,
                  accountAddress: op.accountAddress,
                })
              : null;
          if (signer && chainAccount?.deployed === true) {
            if (!args?.runtime?.resolveOwnerAccountId) {
              await markFailed(
                'Deployed smart-account signer mutation requires an owner-account resolver',
              );
              continue;
            }
            const ownerAccountId = await args.runtime.resolveOwnerAccountId({
              profileId: signer.profileId,
              op,
              signer,
              chainAccount,
            });
            if (!ownerAccountId) {
              await markDeadLetter('Missing owner account row for deployed signer operation');
              continue;
            }
            if (!args?.runtime?.executeDeployedRemoveSigner) {
              await markFailed(
                'Deployed smart-account signer mutation requires the owner-management executor',
              );
              continue;
            }
            const executed = await args.runtime.executeDeployedRemoveSigner({
              ownerAccountId,
              op,
              signer,
              chainAccount,
              now,
            });
            if (signer.status !== 'revoked') {
              await this.clientDB.setAccountSignerStatus({
                chainIdKey: op.chainIdKey,
                accountAddress: op.accountAddress,
                signerId: op.signerId,
                status: 'revoked',
                removedAt: now,
                mutation: { routeThroughOutbox: false },
              });
            }
            if (profileIdRaw && signerSlot != null) {
              const keys = await this.accountKeyMaterialDB.listKeyMaterialByProfileAndSignerSlot(
                profileIdRaw,
                signerSlot,
                op.chainIdKey,
              );
              for (const key of keys) {
                await this.accountKeyMaterialDB.deleteKeyMaterial(
                  key.profileId,
                  key.signerSlot,
                  key.chainIdKey,
                  key.keyKind,
                );
              }
            }
            await this.clientDB.setSignerOperationStatus({
              opId: op.opId,
              status: 'confirmed',
              lastError: null,
              nextAttemptAt: now,
              ...(executed?.txHash ? { txHash: executed.txHash } : {}),
            });
            summary.confirmed += 1;
            continue;
          }
          if (signer) {
            if (signer.status !== 'revoked') {
              await this.clientDB.setAccountSignerStatus({
                chainIdKey: op.chainIdKey,
                accountAddress: op.accountAddress,
                signerId: op.signerId,
                status: 'revoked',
                removedAt: now,
                mutation: { routeThroughOutbox: false },
              });
            }
            if (profileIdRaw && signerSlot != null) {
              const keys = await this.accountKeyMaterialDB.listKeyMaterialByProfileAndSignerSlot(
                profileIdRaw,
                signerSlot,
                op.chainIdKey,
              );
              for (const key of keys) {
                await this.accountKeyMaterialDB.deleteKeyMaterial(
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
