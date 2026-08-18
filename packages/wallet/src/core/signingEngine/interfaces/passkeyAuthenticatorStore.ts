import type { ProfileAuthenticatorRecord } from '@/core/indexedDB/passkeyClientDB.types';

export type EvmFamilyPasskeyAuthenticatorStorePort = {
  listWalletPasskeyAuthenticators: (walletId: string) => Promise<ProfileAuthenticatorRecord[]>;
  selectProfileAuthenticatorsForPrompt: (args: {
    profileId: string;
    authenticators: ProfileAuthenticatorRecord[];
    selectedCredentialRawId?: string;
    accountLabel?: string;
  }) => Promise<{
    authenticatorsForPrompt: ProfileAuthenticatorRecord[];
    wrongPasskeyError?: string;
  }>;
};
