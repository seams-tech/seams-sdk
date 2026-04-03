import type { AccountId } from '../types/accountIds';
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
  UpsertAccountSignerInput,
  UpsertChainAccountInput,
  UpsertProfileInput,
} from './passkeyClientDB.types';
import type { AccountKeyMaterialDBManager } from './accountKeyMaterialDB/manager';
import {
  type KeyMaterialKind,
  type KeyMaterialRecord,
} from './accountKeyMaterialDB.types';
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

  async upsertAccountSigner(input: UpsertAccountSignerInput): Promise<AccountSignerRecord> {
    return this.clientDB.upsertAccountSigner(input);
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
    deviceNumber: number,
    chainIdKey: string,
    keyKind: KeyMaterialKind,
  ): Promise<KeyMaterialRecord | null> {
    return this.accountKeyMaterialDB.getKeyMaterial(profileId, deviceNumber, chainIdKey, keyKind);
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
      const signerSlotRaw = Number(
        payload.signerSlot ?? payload.deviceNumber ?? signer?.signerSlot,
      );
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
          const keys = await this.accountKeyMaterialDB.listKeyMaterialByProfileAndDevice(
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
              const keys = await this.accountKeyMaterialDB.listKeyMaterialByProfileAndDevice(
                profileIdRaw,
                signerSlot,
                op.chainIdKey,
              );
              for (const key of keys) {
                await this.accountKeyMaterialDB.deleteKeyMaterial(
                  key.profileId,
                  key.deviceNumber,
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
              const keys = await this.accountKeyMaterialDB.listKeyMaterialByProfileAndDevice(
                profileIdRaw,
                signerSlot,
                op.chainIdKey,
              );
              for (const key of keys) {
                await this.accountKeyMaterialDB.deleteKeyMaterial(
                  key.profileId,
                  key.deviceNumber,
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
