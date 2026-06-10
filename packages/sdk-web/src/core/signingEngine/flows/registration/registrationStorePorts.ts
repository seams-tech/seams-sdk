import type { AccountId } from '@/core/types/accountIds';
import type { NearAccountClientDbPort } from '@/core/accountData/near/accountProjection';
import type {
  AccountSignerRecord,
  LastProfileState,
  ProfileAuthenticatorRecord,
  ProfileRecord,
  UpsertProfileInput,
} from '@/core/indexedDB';
import type { AccountKeyMaterialStorePort } from '@/core/indexedDB/accountKeyMaterial';
import type {
  ActivateAccountSignerInput,
  ActivateAccountSignerResult,
} from '@/core/indexedDB/accountSignerLifecycle';
import type {
  ProfileAccountProjectionPort,
  ProfileLastSelectionPort,
} from '@/core/indexedDB/profileAccountProjection';
import type {
  StoreWalletRegistrationFinalizeBatchInput,
  StoreWalletRegistrationFinalizeBatchResult,
  StoreWalletSignerFinalizeBatchInput,
} from '@/core/indexedDB/seamsWalletDB/repositories';

export type RegistrationAccountStorePort = ProfileAccountProjectionPort &
  ProfileLastSelectionPort &
  NearAccountClientDbPort &
  AccountKeyMaterialStorePort & {
    upsertProfile: (input: UpsertProfileInput) => Promise<ProfileRecord>;
    activateAccountSigner: (
      input: ActivateAccountSignerInput,
    ) => Promise<ActivateAccountSignerResult>;
    setLastProfileStateForProfile: (
      profileId: string,
      activeSignerSlot: number,
      scope?: LastProfileState['scope'],
    ) => Promise<void>;
    listProfileAuthenticators: (profileId: string) => Promise<ProfileAuthenticatorRecord[]>;
    upsertProfileAuthenticator: (record: ProfileAuthenticatorRecord) => Promise<void>;
    deleteProfileData: (
      profileId: string,
      args?: { eventAccountId?: AccountId | null },
    ) => Promise<void>;
    persistWalletRegistrationFinalize: (
      input: StoreWalletRegistrationFinalizeBatchInput,
    ) => Promise<StoreWalletRegistrationFinalizeBatchResult>;
    persistWalletSignerFinalize: (
      input: StoreWalletSignerFinalizeBatchInput,
    ) => Promise<StoreWalletRegistrationFinalizeBatchResult>;
    listAccountSigners: (args: {
      chainIdKey: string;
      accountAddress: string;
      status?: AccountSignerRecord['status'];
    }) => Promise<AccountSignerRecord[]>;
  };
