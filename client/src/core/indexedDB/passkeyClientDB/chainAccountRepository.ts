import type { IDBPDatabase } from 'idb';
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

export type ChainAccountRepository = {
  upsertChainAccount(input: UpsertChainAccountInput): Promise<ChainAccountRecord>;
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

export function createChainAccountRepository(args: {
  getDB: () => Promise<IDBPDatabase>;
  chainAccountsStore: string;
  profilesStore: string;
  createConstraintError: CreateConstraintError;
}): ChainAccountRepository {
  return {
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
      const tx = db.transaction(args.chainAccountsStore, 'readwrite');
      const store = tx.objectStore(args.chainAccountsStore);
      const existing = (await store.get([profileId, chainIdKey, accountAddress])) as
        | ChainAccountRecord
        | undefined;
      const next: ChainAccountRecord = {
        profileId,
        chainIdKey,
        accountAddress,
        accountModel,
        isPrimary: input.isPrimary ?? existing?.isPrimary ?? false,
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
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
