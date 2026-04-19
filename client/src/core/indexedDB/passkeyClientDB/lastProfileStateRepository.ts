import type { IDBPDatabase } from 'idb';
import { toTrimmedString } from '@shared/utils/validation';
import type {
  AccountSignerRecord,
  DBConstraintErrorCode,
  LastProfileState,
  ProfileRecord,
} from '../passkeyClientDB.types';
import { parseLastProfileState } from '../lastProfileState';
import { normalizeLastUserScope } from '../normalization';

type AppStateEntry<T = unknown> = {
  key: string;
  value: T;
};

type CreateConstraintError = (
  code: DBConstraintErrorCode,
  message: string,
  details?: Record<string, unknown>,
) => Error;

export type LastProfileStateRepository = {
  getScopedLastProfileStateAppStateKey(scope?: string | null): string | null;
  getLastProfileState(scope?: string | null): Promise<LastProfileState | null>;
  setLastProfileState(state: LastProfileState | null, scope?: string | null): Promise<void>;
  setLastProfileStateInTransaction(args: {
    tx: any;
    state: LastProfileState | null;
    scope?: string | null;
  }): Promise<void>;
  clearLastProfileStateIfMatchesProfile(profileId: string, scope?: string | null): Promise<void>;
};

function makeScopedAppStateKey(baseKey: string, scope: unknown): string | null {
  const normalized = normalizeLastUserScope(scope);
  if (!normalized) return null;
  return `${baseKey}::${normalized}`;
}

export function createLastProfileStateRepository(args: {
  getDB: () => Promise<IDBPDatabase>;
  appStateStore: string;
  accountSignersStore: string;
  profilesStore: string;
  lastProfileStateAppStateKey: string;
  createConstraintError: CreateConstraintError;
}): LastProfileStateRepository {
  async function getAppState<T = unknown>(key: string): Promise<T | undefined> {
    const db = await args.getDB();
    const result = await db.get(args.appStateStore, key);
    return result?.value as T | undefined;
  }

  async function setAppState<T = unknown>(key: string, value: T): Promise<void> {
    const db = await args.getDB();
    await db.put(args.appStateStore, { key, value } satisfies AppStateEntry<T>);
  }

  async function assertLastProfileStateInvariant(state: LastProfileState): Promise<void> {
    const db = await args.getDB();
    const profile = (await db.get(args.profilesStore, state.profileId)) as
      | ProfileRecord
      | undefined;
    if (!profile) {
      throw args.createConstraintError(
        'INVALID_LAST_PROFILE_STATE',
        `lastProfileState profile does not exist: ${state.profileId}`,
        {
          profileId: state.profileId,
          activeSignerSlot: state.activeSignerSlot,
        },
      );
    }

    const signerTx = db.transaction(args.accountSignersStore, 'readonly');
    const signerRows = (await signerTx.store
      .index('profileId')
      .getAll(state.profileId)) as AccountSignerRecord[];
    await signerTx.done;
    if (!signerRows.length) return;
    const hasMatchingSignerSlot = signerRows.some(
      (row) => row.signerSlot === state.activeSignerSlot && row.status !== 'revoked',
    );
    if (!hasMatchingSignerSlot) {
      throw args.createConstraintError(
        'INVALID_LAST_PROFILE_STATE',
        `lastProfileState signer slot ${state.activeSignerSlot} was not found for profile ${state.profileId}`,
        {
          profileId: state.profileId,
          activeSignerSlot: state.activeSignerSlot,
        },
      );
    }
  }

  return {
    getScopedLastProfileStateAppStateKey(scope?: string | null): string | null {
      return makeScopedAppStateKey(args.lastProfileStateAppStateKey, scope);
    },

    async getLastProfileState(scope?: string | null): Promise<LastProfileState | null> {
      const scopedKey = this.getScopedLastProfileStateAppStateKey(scope);
      if (scopedKey) {
        const scopedRaw = await getAppState<unknown>(scopedKey).catch(() => undefined);
        return parseLastProfileState(scopedRaw);
      }
      const unscopedRaw = await getAppState<unknown>(args.lastProfileStateAppStateKey).catch(
        () => undefined,
      );
      return parseLastProfileState(unscopedRaw);
    },

    async setLastProfileState(
      state: LastProfileState | null,
      scope?: string | null,
    ): Promise<void> {
      if (state) {
        await assertLastProfileStateInvariant(state);
      }
      const scopedKey = this.getScopedLastProfileStateAppStateKey(scope);
      await setAppState(scopedKey || args.lastProfileStateAppStateKey, state);
    },

    async setLastProfileStateInTransaction(input: {
      tx: any;
      state: LastProfileState | null;
      scope?: string | null;
    }): Promise<void> {
      const scopedKey = this.getScopedLastProfileStateAppStateKey(input.scope);
      await input.tx.objectStore(args.appStateStore).put({
        key: scopedKey || args.lastProfileStateAppStateKey,
        value: input.state,
      } satisfies AppStateEntry<LastProfileState | null>);
    },

    async clearLastProfileStateIfMatchesProfile(
      profileId: string,
      scope?: string | null,
    ): Promise<void> {
      const normalizedProfileId = toTrimmedString(profileId || '');
      if (!normalizedProfileId) return;
      try {
        const unscopedProfile = parseLastProfileState(
          await getAppState<unknown>(args.lastProfileStateAppStateKey),
        );
        if (unscopedProfile && unscopedProfile.profileId === normalizedProfileId) {
          await setAppState(args.lastProfileStateAppStateKey, null);
        }
      } catch {}

      const scopedProfileKey = this.getScopedLastProfileStateAppStateKey(scope);
      if (scopedProfileKey) {
        try {
          const scopedProfile = parseLastProfileState(await getAppState<unknown>(scopedProfileKey));
          if (scopedProfile && scopedProfile.profileId === normalizedProfileId) {
            await setAppState(scopedProfileKey, null);
          }
        } catch {}
      }
    },
  };
}
