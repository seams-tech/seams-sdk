import type { IDBPDatabase } from 'idb';
import { normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import type { UndeployedSmartAccountSignerSet } from '@shared/utils';
import { toTrimmedString } from '@shared/utils/validation';
import type {
  AccountModel,
  AccountRef,
  ChainAccountRecord,
  DBConstraintErrorCode,
  ProfileRecord,
  UpsertChainAccountInput,
} from '../passkeyClientDB.types';
import {
  normalizeIndexedDbAccountAddress as normalizeAccountAddress,
  normalizeIndexedDbAccountModel as normalizeAccountModel,
  normalizeIndexedDbChainIdKey as normalizeChainIdKey,
} from '../normalization';

type CreateConstraintError = (
  code: DBConstraintErrorCode,
  message: string,
  details?: Record<string, unknown>,
) => Error;

type ReconcilePendingSignerStateOnDeployment = (args: {
  tx: any;
  previous?: ChainAccountRecord;
  next: ChainAccountRecord;
  now: number;
}) => Promise<void>;

export type ChainAccountRepository = {
  upsertChainAccount(
    input: UpsertChainAccountInput,
    options?: {
      reconcilePendingSignerStateOnDeployment?: ReconcilePendingSignerStateOnDeployment;
    },
  ): Promise<ChainAccountRecord>;
  listChainAccountsByProfile(profileId: string): Promise<ChainAccountRecord[]>;
  listChainAccountsByProfileAndChain(
    profileId: string,
    chainIdKey: string,
  ): Promise<ChainAccountRecord[]>;
  getChainAccount(args: {
    profileId: string;
    chainIdKey: string;
    accountAddress: string;
  }): Promise<ChainAccountRecord | null>;
  resolveProfileAccountContext(
    accountRef: AccountRef,
  ): Promise<{ profileId: string; accountRef: AccountRef } | null>;
  listChainAccountsByChain(chainIdKey: string): Promise<ChainAccountRecord[]>;
  putChainAccountForSignerLifecycle(args: {
    tx: any;
    profileId: string;
    chainIdKey: string;
    accountAddress: string;
    accountModel: AccountModel;
    now: number;
  }): Promise<ChainAccountRecord>;
};

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
          const signerSlotRaw = Number(candidate.signerSlot);
          const participantIds = Array.isArray(candidate.participantIds)
            ? candidate.participantIds
                .map((candidateValue) => Math.floor(Number(candidateValue)))
                .filter((candidateValue) => Number.isFinite(candidateValue) && candidateValue > 0)
            : [];
          return {
            signerId,
            signerType,
            status,
            ...(Number.isFinite(signerSlotRaw) && signerSlotRaw > 0
              ? { signerSlot: Math.floor(signerSlotRaw) }
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
            ...(normalizeOptionalNonEmptyString(candidate.credentialIdB64u)
              ? { credentialIdB64u: normalizeOptionalNonEmptyString(candidate.credentialIdB64u)! }
              : {}),
            ...(normalizeOptionalNonEmptyString(candidate.rpId)
              ? { rpId: normalizeOptionalNonEmptyString(candidate.rpId)! }
              : {}),
            ...(participantIds.length ? { participantIds } : {}),
          };
        })
        .filter((entry) => !!entry)
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

export function createChainAccountRepository(args: {
  getDB: () => Promise<IDBPDatabase>;
  chainAccountsStore: string;
  accountSignersStore: string;
  profilesStore: string;
  signerOpsOutboxStore: string;
  createConstraintError: CreateConstraintError;
}): ChainAccountRepository {
  return {
    async upsertChainAccount(
      input: UpsertChainAccountInput,
      options?: {
        reconcilePendingSignerStateOnDeployment?: ReconcilePendingSignerStateOnDeployment;
      },
    ): Promise<ChainAccountRecord> {
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
      const db = await args.getDB();
      const now = Date.now();
      const profile = (await db.get(args.profilesStore, profileId)) as ProfileRecord | undefined;
      if (!profile) {
        throw args.createConstraintError(
          'MISSING_PROFILE',
          `Cannot upsert chain account for unknown profile: ${profileId}`,
          { profileId, chainIdKey, accountAddress },
        );
      }
      const tx = db.transaction(
        [args.chainAccountsStore, args.accountSignersStore, args.signerOpsOutboxStore],
        'readwrite',
      );
      const store = tx.objectStore(args.chainAccountsStore);
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
      await options?.reconcilePendingSignerStateOnDeployment?.({
        tx,
        previous: existing,
        next,
        now,
      });
      await tx.done;
      return next;
    },

    async listChainAccountsByProfile(profileId: string): Promise<ChainAccountRecord[]> {
      const normalizedProfileId = toTrimmedString(profileId || '');
      if (!normalizedProfileId) return [];
      const db = await args.getDB();
      const tx = db.transaction(args.chainAccountsStore, 'readonly');
      const rows = await tx.store.index('profileId').getAll(normalizedProfileId);
      await tx.done;
      return (rows as ChainAccountRecord[]) || [];
    },

    async listChainAccountsByProfileAndChain(
      profileId: string,
      chainIdKey: string,
    ): Promise<ChainAccountRecord[]> {
      const normalizedProfileId = toTrimmedString(profileId || '');
      const normalizedChainIdKey = normalizeChainIdKey(chainIdKey);
      if (!normalizedProfileId || !normalizedChainIdKey) return [];
      const db = await args.getDB();
      const tx = db.transaction(args.chainAccountsStore, 'readonly');
      const rows = await tx.store
        .index('profileId_chainIdKey')
        .getAll([normalizedProfileId, normalizedChainIdKey]);
      await tx.done;
      return (rows as ChainAccountRecord[]) || [];
    },

    async getChainAccount(input: {
      profileId: string;
      chainIdKey: string;
      accountAddress: string;
    }): Promise<ChainAccountRecord | null> {
      const profileId = toTrimmedString(input.profileId || '');
      const chainIdKey = normalizeChainIdKey(input.chainIdKey);
      const accountAddress = normalizeAccountAddress(input.accountAddress);
      if (!profileId || !chainIdKey || !accountAddress) return null;
      const db = await args.getDB();
      const row = (await db.get(args.chainAccountsStore, [
        profileId,
        chainIdKey,
        accountAddress,
      ])) as ChainAccountRecord | undefined;
      return row || null;
    },

    async resolveProfileAccountContext(
      accountRef: AccountRef,
    ): Promise<{ profileId: string; accountRef: AccountRef } | null> {
      const chainIdKey = normalizeChainIdKey(accountRef.chainIdKey);
      const accountAddress = normalizeAccountAddress(accountRef.accountAddress);
      if (!chainIdKey || !accountAddress) return null;

      const db = await args.getDB();
      const tx = db.transaction(args.chainAccountsStore, 'readonly');
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
    },

    async listChainAccountsByChain(chainIdKey: string): Promise<ChainAccountRecord[]> {
      const normalizedChainIdKey = normalizeChainIdKey(chainIdKey);
      if (!normalizedChainIdKey) return [];
      const db = await args.getDB();
      const tx = db.transaction(args.chainAccountsStore, 'readonly');
      const rows = (await tx.store.index('chainIdKey').getAll(normalizedChainIdKey)) as
        | ChainAccountRecord[]
        | undefined;
      await tx.done;
      return rows || [];
    },

    async putChainAccountForSignerLifecycle(input: {
      tx: any;
      profileId: string;
      chainIdKey: string;
      accountAddress: string;
      accountModel: AccountModel;
      now: number;
    }): Promise<ChainAccountRecord> {
      const profile = (await input.tx.objectStore(args.profilesStore).get(input.profileId)) as
        | ProfileRecord
        | undefined;
      if (!profile) {
        throw args.createConstraintError(
          'MISSING_PROFILE',
          `Cannot upsert chain account for unknown profile: ${input.profileId}`,
          {
            profileId: input.profileId,
            chainIdKey: input.chainIdKey,
            accountAddress: input.accountAddress,
          },
        );
      }

      const store = input.tx.objectStore(args.chainAccountsStore);
      const existing = (await store.get([
        input.profileId,
        input.chainIdKey,
        input.accountAddress,
      ])) as ChainAccountRecord | undefined;
      const next: ChainAccountRecord = {
        ...existing,
        profileId: input.profileId,
        chainIdKey: input.chainIdKey,
        accountAddress: input.accountAddress,
        accountModel: input.accountModel,
        isPrimary: true,
        createdAt: existing?.createdAt ?? input.now,
        updatedAt: input.now,
      };

      const idx = store.index('profileId_chainIdKey');
      let cursor = await idx.openCursor([input.profileId, input.chainIdKey]);
      while (cursor) {
        const row = cursor.value as ChainAccountRecord;
        if (row.isPrimary && normalizeAccountAddress(row.accountAddress) !== input.accountAddress) {
          await cursor.update({
            ...row,
            isPrimary: false,
            updatedAt: input.now,
          });
        }
        cursor = await cursor.continue();
      }

      await store.put(next);
      return next;
    },
  };
}
