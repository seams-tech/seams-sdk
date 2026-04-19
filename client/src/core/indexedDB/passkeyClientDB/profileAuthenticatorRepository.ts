import type { IDBPDatabase } from 'idb';
import { toTrimmedString } from '@shared/utils/validation';
import type { ProfileAuthenticatorRecord } from '../passkeyClientDB.types';

export type ProfileAuthenticatorRepository = {
  listProfileAuthenticators(profileId: string): Promise<ProfileAuthenticatorRecord[]>;
  upsertProfileAuthenticator(record: ProfileAuthenticatorRecord): Promise<void>;
  getProfileAuthenticatorByCredentialId(
    profileId: string,
    credentialId: string,
  ): Promise<ProfileAuthenticatorRecord | null>;
  clearProfileAuthenticators(profileId: string): Promise<void>;
};

export function createProfileAuthenticatorRepository(args: {
  getDB: () => Promise<IDBPDatabase>;
  profileAuthenticatorStore: string;
}): ProfileAuthenticatorRepository {
  return {
    async listProfileAuthenticators(profileId: string): Promise<ProfileAuthenticatorRecord[]> {
      const normalizedProfileId = toTrimmedString(profileId || '');
      if (!normalizedProfileId) return [];
      const db = await args.getDB();
      const tx = db.transaction(args.profileAuthenticatorStore, 'readonly');
      const rows = await tx.store.index('profileId').getAll(normalizedProfileId);
      await tx.done;
      return (rows as ProfileAuthenticatorRecord[]) || [];
    },

    async upsertProfileAuthenticator(record: ProfileAuthenticatorRecord): Promise<void> {
      const profileId = toTrimmedString(record.profileId || '');
      const credentialId = toTrimmedString(record.credentialId || '');
      const signerSlot = Number(record.signerSlot);
      if (!profileId || !credentialId) {
        throw new Error(
          'PasskeyClientDB: profileId and credentialId are required for profileAuthenticators',
        );
      }
      if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
        throw new Error('PasskeyClientDB: signerSlot must be an integer >= 1');
      }
      const db = await args.getDB();
      await db.put(args.profileAuthenticatorStore, {
        ...record,
        profileId,
        signerSlot,
        credentialId,
      } satisfies ProfileAuthenticatorRecord);
    },

    async getProfileAuthenticatorByCredentialId(
      profileId: string,
      credentialId: string,
    ): Promise<ProfileAuthenticatorRecord | null> {
      const normalizedProfileId = toTrimmedString(profileId || '');
      const normalizedCredentialId = toTrimmedString(credentialId || '');
      if (!normalizedProfileId || !normalizedCredentialId) return null;
      const db = await args.getDB();
      const tx = db.transaction(args.profileAuthenticatorStore, 'readonly');
      const row = (await tx.store
        .index('profileId_credentialId')
        .get([normalizedProfileId, normalizedCredentialId])) as
        | ProfileAuthenticatorRecord
        | undefined;
      await tx.done;
      return row || null;
    },

    async clearProfileAuthenticators(profileId: string): Promise<void> {
      const normalizedProfileId = toTrimmedString(profileId || '');
      if (!normalizedProfileId) return;
      const db = await args.getDB();
      const tx = db.transaction(args.profileAuthenticatorStore, 'readwrite');
      const profileStore = tx.store;
      let cursor = await profileStore
        .index('profileId')
        .openCursor(IDBKeyRange.only(normalizedProfileId));
      while (cursor) {
        await profileStore.delete(cursor.primaryKey);
        cursor = await cursor.continue();
      }
      await tx.done;
    },
  };
}
