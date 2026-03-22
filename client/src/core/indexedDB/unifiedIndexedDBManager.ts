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
import type { PasskeyNearKeysDBManager } from './passkeyNearKeysDB/manager';
import {
  type LocalNearSkV3Material,
  type PasskeyChainIdKeyKind,
  type PasskeyChainIdKeyMaterial,
  type ThresholdEd25519_2p_V1Material,
} from './passkeyNearKeysDB.types';
import {
  getNearLocalKeyMaterial as getNearLocalKeyMaterialValue,
  getNearThresholdKeyMaterial as getNearThresholdKeyMaterialValue,
  storeNearLocalKeyMaterial as storeNearLocalKeyMaterialValue,
  storeNearThresholdKeyMaterial as storeNearThresholdKeyMaterialValue,
  type NearKeyMaterialDeps,
  type StoreNearLocalKeyMaterialInput,
  type StoreNearThresholdKeyMaterialInput,
} from './near/keyMaterial';
import { passkeyClientDB, passkeyNearKeysDB } from './singletons';

export interface UnifiedIndexedDBManagerDeps {
  clientDB: PasskeyClientDBManager;
  nearKeysDB: PasskeyNearKeysDBManager;
}

type DeployedSignerMutationRuntime = {
  executeDeployedAddSigner: (args: {
    nearAccountId: AccountId;
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
  public readonly nearKeysDB: PasskeyNearKeysDBManager;
  private _initialized = false;

  constructor(deps?: Partial<UnifiedIndexedDBManagerDeps>) {
    this.clientDB = deps?.clientDB || passkeyClientDB;
    this.nearKeysDB = deps?.nearKeysDB || passkeyNearKeysDB;
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
      if (this.clientDB.isDisabled() || this.nearKeysDB.isDisabled()) {
        this._initialized = true;
        return;
      }
      // Initialize both databases by calling a simple operation
      // This will trigger the getDB() method in both managers and ensure databases are created
      await Promise.all([
        this.clientDB.getAppState('_init_check'),
        this.nearKeysDB.getKeyMaterial('_init_check', 1, 'near:testnet', 'local_sk_encrypted_v1'),
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

  private getNearKeyMaterialDeps(): NearKeyMaterialDeps {
    return {
      clientDB: this.clientDB,
      nearKeysDB: this.nearKeysDB,
    };
  }

  async getNearLocalKeyMaterial(
    nearAccountId: AccountId,
    deviceNumber: number,
  ): Promise<LocalNearSkV3Material | null> {
    return getNearLocalKeyMaterialValue(this.getNearKeyMaterialDeps(), nearAccountId, deviceNumber);
  }

  async getNearThresholdKeyMaterial(
    nearAccountId: AccountId,
    deviceNumber: number,
  ): Promise<ThresholdEd25519_2p_V1Material | null> {
    return getNearThresholdKeyMaterialValue(
      this.getNearKeyMaterialDeps(),
      nearAccountId,
      deviceNumber,
    );
  }

  async storeNearLocalKeyMaterial(input: StoreNearLocalKeyMaterialInput): Promise<void> {
    return storeNearLocalKeyMaterialValue(this.getNearKeyMaterialDeps(), input);
  }

  async storeNearThresholdKeyMaterial(input: StoreNearThresholdKeyMaterialInput): Promise<void> {
    return storeNearThresholdKeyMaterialValue(this.getNearKeyMaterialDeps(), input);
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

  async getProfileByAccount(
    chainIdKey: string,
    accountAddress: string,
  ): Promise<ProfileRecord | null> {
    return this.clientDB.getProfileByAccount(chainIdKey, accountAddress);
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
  async storeKeyMaterial(input: PasskeyChainIdKeyMaterial): Promise<void> {
    return this.nearKeysDB.storeKeyMaterial(input);
  }

  async getKeyMaterial(
    profileId: string,
    deviceNumber: number,
    chainIdKey: string,
    keyKind: PasskeyChainIdKeyKind,
  ): Promise<PasskeyChainIdKeyMaterial | null> {
    return this.nearKeysDB.getKeyMaterial(profileId, deviceNumber, chainIdKey, keyKind);
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
          const nearAccountId = await this.clientDB.getNearAccountIdForProfile(profileIdRaw);
          if (!nearAccountId) {
            await markDeadLetter('Missing NEAR account row for deployed signer operation');
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
          const keys = await this.nearKeysDB.listKeyMaterialByProfileAndDevice(
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
            if (!args?.runtime?.executeDeployedAddSigner) {
              await markFailed(
                'Deployed smart-account signer mutation requires the owner-management executor',
              );
              continue;
            }
            const executed = await args.runtime.executeDeployedAddSigner({
              nearAccountId,
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
              const keys = await this.nearKeysDB.listKeyMaterialByProfileAndDevice(
                profileIdRaw,
                signerSlot,
                op.chainIdKey,
              );
              for (const key of keys) {
                await this.nearKeysDB.deleteKeyMaterial(
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
