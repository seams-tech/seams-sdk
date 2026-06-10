import type { AccountKeyMaterialStorePort } from '@/core/indexedDB/accountKeyMaterial';
import type { LastProfileState } from '@/core/indexedDB/passkeyClientDB.types';
import type { ProfileAccountContextPort } from '@/core/indexedDB/profileAccountProjection';

export type RecoveryNearKeyMaterialStorePort = ProfileAccountContextPort &
  AccountKeyMaterialStorePort & {
    getLastProfileState: () => Promise<LastProfileState | null>;
  };
