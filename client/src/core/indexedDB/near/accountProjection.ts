import type { AccountId } from '../../types/accountIds';
import { toAccountId } from '../../types/accountIds';
import type { IDBPDatabase } from 'idb';
import { toTrimmedString } from '@shared/utils/validation';
import type {
  AccountSignerRecord,
  ChainAccountRecord,
  ClientAuthenticatorData,
  ClientUserData,
  LastProfileState,
  ProfileAuthenticatorRecord,
  ProfileRecord,
  UpsertAccountSignerInput,
  UpsertChainAccountInput,
  UpsertProfileInput,
  UserPreferences,
} from '../passkeyClientDB.types';
import { NEAR_PROFILE_PREFIX } from '../passkeyClientDB/schema';
import {
  normalizeIndexedDbAccountAddress as normalizeAccountAddress,
  normalizeLastUserScope,
} from '../normalization';

export function buildNearProfileId(accountId: AccountId): string {
  return `${NEAR_PROFILE_PREFIX}:${String(accountId)}`;
}

export function parseLastProfileState(raw: unknown): LastProfileState | null {
  if (raw == null || typeof raw !== 'object') return null;

  const profileId =
    typeof (raw as any).profileId === 'string' ? String((raw as any).profileId).trim() : '';
  if (!profileId) return null;

  const deviceNumberRaw = (raw as any).deviceNumber;
  const deviceNumber = Number(deviceNumberRaw);
  if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) return null;

  const scope = normalizeLastUserScope((raw as any).scope);
  return scope != null ? { profileId, deviceNumber, scope } : { profileId, deviceNumber };
}

export function inferNearChainIdKey(
  nearAccountId: AccountId,
  networkHint?: UserPreferences['useNetwork'],
): string {
  if (networkHint === 'mainnet') return 'near:mainnet';
  if (networkHint === 'testnet') return 'near:testnet';
  return String(nearAccountId).endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
}

export function getNearChainCandidates(accountId: AccountId): string[] {
  const preferred = inferNearChainIdKey(accountId);
  return preferred === 'near:testnet'
    ? ['near:testnet', 'near:mainnet']
    : ['near:mainnet', 'near:testnet'];
}

export function mapProfileAuthenticatorToClient(
  profileAuthenticator: ProfileAuthenticatorRecord,
  nearAccountId: AccountId,
): ClientAuthenticatorData {
  return {
    nearAccountId,
    deviceNumber: profileAuthenticator.deviceNumber,
    credentialId: profileAuthenticator.credentialId,
    credentialPublicKey: profileAuthenticator.credentialPublicKey,
    transports: profileAuthenticator.transports,
    name: profileAuthenticator.name,
    registered: profileAuthenticator.registered,
    syncedAt: profileAuthenticator.syncedAt,
  };
}

export interface UpsertNearProjectionOperations {
  upsertProfile: (input: UpsertProfileInput) => Promise<unknown>;
  upsertChainAccount: (input: UpsertChainAccountInput) => Promise<unknown>;
  getAccountSigner: (args: {
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
  }) => Promise<AccountSignerRecord | null>;
  upsertAccountSigner: (input: UpsertAccountSignerInput) => Promise<unknown>;
}

export async function upsertNearAccountProjectionRecords(args: {
  userData: ClientUserData;
  ops: UpsertNearProjectionOperations;
}): Promise<void> {
  const { userData, ops } = args;
  const accountId = toAccountId(userData.nearAccountId);
  const deviceNumber = Number(userData.deviceNumber);
  if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) {
    throw new Error('PasskeyClientDB: deviceNumber must be an integer >= 1');
  }

  const profileId = buildNearProfileId(accountId);
  const chainIdKey = inferNearChainIdKey(accountId, userData.preferences?.useNetwork);
  const accountAddress = normalizeAccountAddress(accountId);
  const signerId =
    toTrimmedString(userData.passkeyCredential?.rawId || '') || `device-${deviceNumber}`;

  await ops.upsertProfile({
    profileId,
    defaultDeviceNumber: deviceNumber,
    passkeyCredential: userData.passkeyCredential,
    ...(userData.preferences ? { preferences: userData.preferences } : {}),
  });

  await ops.upsertChainAccount({
    profileId,
    chainIdKey,
    accountAddress,
    accountModel: 'near-native',
    isPrimary: true,
  });

  const existingSigner = await ops
    .getAccountSigner({
      chainIdKey,
      accountAddress,
      signerId,
    })
    .catch(() => null);
  await ops.upsertAccountSigner({
    profileId,
    chainIdKey,
    accountAddress,
    signerId,
    signerSlot: deviceNumber,
    signerType: 'passkey',
    status: 'active',
    metadata: {
      ...(existingSigner?.metadata || {}),
      operationalPublicKey: userData.operationalPublicKey,
      passkeyCredentialId: userData.passkeyCredential?.id,
      passkeyCredentialRawId: userData.passkeyCredential?.rawId,
    },
    mutation: { routeThroughOutbox: false },
  });
}

export async function buildNearAccountProjection(args: {
  db: IDBPDatabase;
  nearAccountId: AccountId;
  deviceNumber?: number;
  stores: {
    chainAccountsStore: string;
    profilesStore: string;
    accountSignersStore: string;
  };
}): Promise<ClientUserData | null> {
  const { db, nearAccountId, deviceNumber, stores } = args;
  const accountId = toAccountId(nearAccountId);
  const accountAddress = normalizeAccountAddress(accountId);

  for (const chainIdKey of getNearChainCandidates(accountId)) {
    const tx = db.transaction(stores.chainAccountsStore, 'readonly');
    const idx = tx.store.index('chainIdKey_accountAddress');
    const chainAccount = (await idx.get([chainIdKey, accountAddress])) as
      | ChainAccountRecord
      | undefined;
    if (!chainAccount?.profileId) continue;

    const profile = (await db.get(stores.profilesStore, chainAccount.profileId)) as
      | ProfileRecord
      | undefined;
    if (!profile) continue;

    const signerTx = db.transaction(stores.accountSignersStore, 'readonly');
    const signerStore = signerTx.store;
    const activeSigners = (await signerStore
      .index('chainIdKey_accountAddress_status')
      .getAll([chainIdKey, accountAddress, 'active'])) as AccountSignerRecord[];
    if (!activeSigners.length) continue;

    const selectedSigner = (() => {
      if (typeof deviceNumber === 'number') {
        return activeSigners.find((row) => row.signerSlot === deviceNumber);
      }
      const preferredSlot = Number.isSafeInteger(profile.defaultDeviceNumber)
        ? profile.defaultDeviceNumber
        : 1;
      return (
        activeSigners.find((row) => row.signerSlot === preferredSlot) ||
        activeSigners.slice().sort((a, b) => a.signerSlot - b.signerSlot)[0]
      );
    })();
    if (!selectedSigner) continue;

    const metadata = selectedSigner.metadata || {};
    const passkeyCredentialRawId =
      typeof metadata.passkeyCredentialRawId === 'string'
        ? metadata.passkeyCredentialRawId
        : selectedSigner.signerId;
    const passkeyCredentialId =
      typeof metadata.passkeyCredentialId === 'string'
        ? metadata.passkeyCredentialId
        : profile.passkeyCredential?.id || passkeyCredentialRawId;
    const operationalPublicKey =
      typeof metadata.operationalPublicKey === 'string' ? metadata.operationalPublicKey : '';

    return {
      nearAccountId: accountId,
      deviceNumber: selectedSigner.signerSlot,
      version: 2,
      registeredAt: profile.createdAt,
      lastLogin: profile.updatedAt,
      lastUpdated: profile.updatedAt,
      operationalPublicKey,
      passkeyCredential: {
        id: passkeyCredentialId,
        rawId: passkeyCredentialRawId,
      },
      preferences: profile.preferences,
    };
  }

  return null;
}
