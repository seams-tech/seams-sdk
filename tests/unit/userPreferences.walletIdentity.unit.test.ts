import { expect, test } from '@playwright/test';
import { UserPreferencesManager } from '../../packages/sdk-web/src/core/signingEngine/session/userPreferences';
import type {
  AccountSignerRecord,
  ChainAccountRecord,
  IndexedDBEvent,
  LastProfileState,
  UserPreferences,
} from '../../packages/sdk-web/src/core/indexedDB';
import type { WalletId } from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';

function activeNearSigner(profileId: string, walletId: string): AccountSignerRecord {
  return {
    profileId,
    chainIdKey: 'near:testnet',
    accountAddress: 'refresh-profile.testnet',
    signerId: 'ed25519-public-key',
    signerSlot: 1,
    signerType: 'threshold',
    signerKind: 'threshold-ed25519',
    signerAuthMethod: 'passkey',
    signerSource: 'passkey_registration',
    status: 'active',
    addedAt: 1,
    updatedAt: 1,
    metadata: {
      walletId,
      nearAccountId: 'refresh-profile.testnet',
      nearEd25519SigningKeyId: 'near-key-1',
    },
  };
}

test.describe('UserPreferences wallet identity boundary', () => {
  test('loads current wallet preferences from wallet-bound metadata for last NEAR profile', async () => {
    const requestedPreferenceWalletIds: string[] = [];
    const nearProfileId = 'near-profile:refresh-profile.testnet';
    const walletId = 'refresh-wallet-id';
    const manager = new UserPreferencesManager({
      store: {
        isDisabled: () => false,
        onChange: (_callback: (event: IndexedDBEvent) => void) => () => undefined,
        getLastProfileState: async (): Promise<LastProfileState> => ({
          profileId: nearProfileId,
          activeSignerSlot: 1,
        }),
        listChainAccountsByProfile: async (profileId: string): Promise<ChainAccountRecord[]> => [
          {
            profileId,
            chainIdKey: 'near:testnet',
            accountAddress: 'refresh-profile.testnet',
            accountModel: 'near-native',
            isPrimary: true,
            createdAt: 1,
            updatedAt: 1,
          },
        ],
        listAccountSignersByProfile: async (args: {
          profileId: string;
          status?: AccountSignerRecord['status'];
        }): Promise<AccountSignerRecord[]> =>
          args.profileId === nearProfileId && args.status === 'active'
            ? [activeNearSigner(nearProfileId, walletId)]
            : [],
        getWalletPreferences: async (
          requestedWalletId: WalletId,
        ): Promise<Partial<UserPreferences>> => {
          requestedPreferenceWalletIds.push(String(requestedWalletId));
          return {
            confirmationConfig: {
              behavior: 'skipClick',
              uiMode: 'drawer',
              autoProceedDelay: 7,
            },
          };
        },
        updateWalletPreferences: async () => undefined,
      },
    });

    await manager.loadUserSettings();

    expect(String(manager.getCurrentWalletId() || '')).toBe(walletId);
    expect(requestedPreferenceWalletIds).toEqual([walletId]);
    expect(manager.getConfirmationConfig()).toEqual({
      behavior: 'skipClick',
      uiMode: 'drawer',
      autoProceedDelay: 7,
    });
  });
});
