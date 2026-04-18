import { PasskeyClientDBManager } from '../../client/src/core/indexedDB/passkeyClientDB/manager.ts';
import {
  getNearAccountIdForProfile,
  resolveNearAccountProfileContinuity,
} from '../../client/src/core/accountData/near/accountProjection.ts';

const chainAccounts = [
  {
    profileId: 'profile-alice',
    chainIdKey: 'near:testnet',
    accountAddress: 'alice.testnet',
    accountModel: 'near-native',
    isPrimary: true,
  },
  {
    profileId: 'profile-alice',
    chainIdKey: 'evm:11155111',
    accountAddress: `0x${'11'.repeat(20)}`,
    accountModel: 'erc4337',
    isPrimary: true,
    counterfactualAddress: `0x${'22'.repeat(20)}`,
    deployed: false,
  },
];

const accountSigners = [
  {
    profileId: 'profile-alice',
    chainIdKey: 'near:testnet',
    accountAddress: 'alice.testnet',
    signerId: 'near-passkey-1',
    signerSlot: 1,
    signerType: 'threshold',
    signerKind: 'threshold-ed25519',
    signerAuthMethod: 'passkey',
    signerSource: 'passkey_registration',
    status: 'active',
  },
  {
    profileId: 'profile-alice',
    chainIdKey: 'evm:11155111',
    accountAddress: `0x${'11'.repeat(20)}`,
    signerId: `0x${'aa'.repeat(20)}`,
    signerSlot: 1,
    signerType: 'threshold',
    signerKind: 'threshold-ecdsa',
    signerAuthMethod: 'passkey',
    signerSource: 'passkey_registration',
    status: 'active',
  },
  {
    profileId: 'profile-alice',
    chainIdKey: 'evm:11155111',
    accountAddress: `0x${'11'.repeat(20)}`,
    signerId: `0x${'bb'.repeat(20)}`,
    signerSlot: 2,
    signerType: 'threshold',
    signerKind: 'threshold-ecdsa',
    signerAuthMethod: 'passkey',
    signerSource: 'passkey_registration',
    status: 'pending',
  },
];

const fakeManager = {
  async getProfile(profileId: string) {
    if (profileId !== 'profile-alice') return null;
    return {
      profileId,
      defaultSignerSlot: 1,
      passkeyCredential: { id: 'cred-alice', rawId: 'raw-alice' },
      createdAt: 1,
      updatedAt: 2,
    };
  },
  async listChainAccountsByProfile(profileId: string) {
    return profileId === 'profile-alice' ? chainAccounts : [];
  },
  async listAccountSignersByProfile(args: { profileId: string; status?: string }) {
    if (args.profileId !== 'profile-alice') return [];
    if (!args.status) return accountSigners;
    return accountSigners.filter((row) => row.status === args.status);
  },
  async resolveProfileAccountContext(args: { chainIdKey: string; accountAddress: string }) {
    const chainIdKey = String(args.chainIdKey || '').trim();
    const accountAddress = String(args.accountAddress || '')
      .trim()
      .toLowerCase();
    if (chainIdKey !== 'near:testnet' || accountAddress !== 'alice.testnet') return null;
    return {
      profileId: 'profile-alice',
      accountRef: {
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
      },
    };
  },
  async getProfileContinuitySnapshot(profileId: string) {
    return PasskeyClientDBManager.prototype.getProfileContinuitySnapshot.call(
      this as unknown as PasskeyClientDBManager,
      profileId,
    );
  },
};

const snapshot = await PasskeyClientDBManager.prototype.getProfileContinuitySnapshot.call(
  fakeManager as unknown as PasskeyClientDBManager,
  'profile-alice',
);
const nearAccountId = await getNearAccountIdForProfile(
  fakeManager as unknown as PasskeyClientDBManager,
  'profile-alice',
);
const resolvedSnapshot = await resolveNearAccountProfileContinuity(
  fakeManager as unknown as PasskeyClientDBManager,
  'alice.testnet',
);
const activeSigners = await fakeManager.listAccountSignersByProfile({
  profileId: 'profile-alice',
  status: 'active',
});

console.log(
  'RESULT:' +
    JSON.stringify({
      profileId: snapshot?.profile.profileId || null,
      nearAccountId,
      resolvedProfileId: resolvedSnapshot?.profile.profileId || null,
      chainAccounts:
        resolvedSnapshot?.chainAccounts.map((row) => ({
          chainIdKey: row.chainIdKey,
          accountAddress: row.accountAddress,
          accountModel: row.accountModel,
          isPrimary: !!row.isPrimary,
        })) || [],
      accountSigners:
        resolvedSnapshot?.accountSigners.map((row) => ({
          chainIdKey: row.chainIdKey,
          signerId: row.signerId,
          signerSlot: row.signerSlot,
          status: row.status,
        })) || [],
      activeSignerIds: activeSigners.map((row) => row.signerId),
    }),
);
