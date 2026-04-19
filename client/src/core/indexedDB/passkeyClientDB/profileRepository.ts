import type { IDBPDatabase } from 'idb';
import { toTrimmedString } from '@shared/utils/validation';
import type { ProfileRecord, UpsertProfileInput } from '../passkeyClientDB.types';

export type ProfileRepository = {
  getProfile(profileId: string): Promise<ProfileRecord | null>;
  listProfiles(args?: { limit?: number }): Promise<ProfileRecord[]>;
  upsertProfile(input: UpsertProfileInput): Promise<ProfileRecord>;
};

export function createProfileRepository(args: {
  getDB: () => Promise<IDBPDatabase>;
  profilesStore: string;
}): ProfileRepository {
  return {
    async getProfile(profileId: string): Promise<ProfileRecord | null> {
      const normalized = toTrimmedString(profileId || '');
      if (!normalized) return null;
      const db = await args.getDB();
      const rec = await db.get(args.profilesStore, normalized);
      return (rec as ProfileRecord) || null;
    },

    async listProfiles(input?: { limit?: number }): Promise<ProfileRecord[]> {
      const db = await args.getDB();
      const limit =
        Number.isSafeInteger(input?.limit) && Number(input?.limit) > 0
          ? Number(input?.limit)
          : undefined;
      const rows = limit
        ? await db.getAll(args.profilesStore, undefined, limit)
        : await db.getAll(args.profilesStore);
      return (rows as ProfileRecord[]) || [];
    },

    async upsertProfile(input: UpsertProfileInput): Promise<ProfileRecord> {
      const profileId = toTrimmedString(input.profileId || '');
      if (!profileId) throw new Error('PasskeyClientDB: profileId is required');
      const db = await args.getDB();
      const now = Date.now();
      const existing = (await db.get(args.profilesStore, profileId)) as ProfileRecord | undefined;
      const passkeyCredential = input.passkeyCredential?.rawId
        ? input.passkeyCredential
        : existing?.passkeyCredential;
      const next: ProfileRecord = {
        profileId,
        defaultSignerSlot: input.defaultSignerSlot ?? existing?.defaultSignerSlot ?? 1,
        ...(passkeyCredential ? { passkeyCredential } : {}),
        preferences: input.preferences ?? existing?.preferences,
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
      };
      await db.put(args.profilesStore, next);
      return next;
    },
  };
}
