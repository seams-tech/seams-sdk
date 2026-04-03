import type { AccountId } from '../../types/accountIds';
import { toAccountId } from '../../types/accountIds';
import { toTrimmedString } from '@shared/utils/validation';
import { DEFAULT_CONFIRMATION_CONFIG } from '../../types/signer-worker';
import type { ClientUserData, StoreUserDataInput } from './types';
import {
  getLastSelectedProfileAccountByChain,
  getPrimaryProfileAccountByChain,
  resolveProfileAccountProjection,
  resolveProfileAccountContextFromCandidates,
  selectAccountSigner,
} from '../../indexedDB/profileAccountProjection';
import type {
  AccountSignerRecord,
  ChainAccountRecord,
  ProfileContinuitySnapshot,
  ProfileAuthenticatorRecord,
  ProfileRecord,
  UpsertAccountSignerInput,
  UpsertChainAccountInput,
  UpsertProfileInput,
  UserPreferences,
} from '../../indexedDB/passkeyClientDB.types';
import type { PasskeyClientDBManager } from '../../indexedDB/passkeyClientDB/manager';
import { getNearChainCandidates, inferNearChainIdKey } from './accountRefs';
import { buildNearProfileId } from './profileId';
import {
  normalizeIndexedDbAccountAddress as normalizeAccountAddress,
} from '../../indexedDB/normalization';

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

type NearAccountContext = {
  profileId: string;
  sourceChainIdKey: string;
  sourceAccountAddress: string;
};

type NearAccountClientDbPort = Pick<
  PasskeyClientDBManager,
  | 'resolveProfileAccountContext'
  | 'getProfile'
  | 'getLastProfileState'
  | 'setLastProfileStateForProfile'
  | 'listChainAccountsByProfile'
  | 'listChainAccountsByChain'
  | 'listAccountSigners'
  | 'getProfileContinuitySnapshot'
  | 'upsertProfile'
  | 'upsertChainAccount'
  | 'getAccountSigner'
  | 'upsertAccountSigner'
  | 'updatePreferences'
>;

export async function resolveNearAccountContext(
  clientDB: Pick<PasskeyClientDBManager, 'resolveProfileAccountContext'>,
  nearAccountId: AccountId,
): Promise<NearAccountContext | null> {
  const accountId = toAccountId(nearAccountId);
  const sourceAccountAddress = normalizeAccountAddress(accountId);
  if (!sourceAccountAddress) return null;

  const context = await resolveProfileAccountContextFromCandidates(
    clientDB,
    getNearChainCandidates(accountId).map((sourceChainIdKey) => ({
      chainIdKey: sourceChainIdKey,
      accountAddress: sourceAccountAddress,
    })),
  );
  if (context?.profileId) {
    return {
      profileId: context.profileId,
      sourceChainIdKey: context.accountRef.chainIdKey,
      sourceAccountAddress: context.accountRef.accountAddress,
    };
  }

  return null;
}

export async function getNearAccountIdForProfile(
  clientDB: Pick<PasskeyClientDBManager, 'listChainAccountsByProfile'>,
  profileId: string,
): Promise<AccountId | null> {
  const normalizedProfileId = toTrimmedString(profileId || '');
  if (!normalizedProfileId) return null;

  const selected = await getPrimaryProfileAccountByChain(clientDB, {
    profileId: normalizedProfileId,
    chainIdKeys: ['near:testnet', 'near:mainnet'],
  });
  const candidate = toTrimmedString(selected?.accountAddress || '');
  if (!candidate) return null;
  try {
    return toAccountId(candidate);
  } catch {
    return null;
  }
}

export async function resolveNearAccountProfileContinuity(
  clientDB: Pick<
    PasskeyClientDBManager,
    'resolveProfileAccountContext' | 'getProfileContinuitySnapshot'
  >,
  nearAccountId: AccountId,
): Promise<ProfileContinuitySnapshot | null> {
  const context = await resolveNearAccountContext(clientDB, nearAccountId);
  if (!context?.profileId) return null;
  return clientDB.getProfileContinuitySnapshot(context.profileId);
}

export async function getNearAccountProjection(
  clientDB: NearAccountClientDbPort,
  nearAccountId: AccountId,
  deviceNumber?: number,
): Promise<ClientUserData | null> {
  const accountId = toAccountId(nearAccountId);
  const accountAddress = normalizeAccountAddress(accountId);
  if (!accountAddress) return null;
  const projection = await resolveProfileAccountProjection(clientDB, {
    accountRefs: getNearChainCandidates(accountId).map((chainIdKey) => ({
      chainIdKey,
      accountAddress,
    })),
    deviceNumber,
  });
  if (!projection) return null;

  const metadata = projection.selectedSigner.metadata || {};
  const passkeyCredentialRawId =
    typeof metadata.passkeyCredentialRawId === 'string'
      ? metadata.passkeyCredentialRawId
      : projection.selectedSigner.signerId;
  const passkeyCredentialId =
    typeof metadata.passkeyCredentialId === 'string'
      ? metadata.passkeyCredentialId
      : projection.profile.passkeyCredential?.id || passkeyCredentialRawId;
  const operationalPublicKey =
    typeof metadata.operationalPublicKey === 'string' ? metadata.operationalPublicKey : '';

  return {
    nearAccountId: accountId,
    deviceNumber: projection.selectedSigner.signerSlot,
    version: 2,
    registeredAt: projection.profile.createdAt,
    lastLogin: projection.profile.updatedAt,
    lastUpdated: projection.profile.updatedAt,
    operationalPublicKey,
    passkeyCredential: {
      id: passkeyCredentialId,
      rawId: passkeyCredentialRawId,
    },
    preferences: projection.profile.preferences,
  };
}

export async function getLastSelectedNearAccount(
  clientDB: Pick<
    PasskeyClientDBManager,
    'getLastProfileState' | 'listChainAccountsByProfile'
  >,
): Promise<{ nearAccountId: AccountId; profileId: string; deviceNumber: number } | null> {
  const last = await getLastSelectedProfileAccountByChain(clientDB, {
    chainIdKeys: ['near:testnet', 'near:mainnet'],
  });
  if (!last?.chainAccount?.accountAddress) return null;
  let nearAccountId: AccountId;
  try {
    nearAccountId = toAccountId(last.chainAccount.accountAddress);
  } catch {
    return null;
  }
  return {
    nearAccountId,
    profileId: last.profileId,
    deviceNumber: last.deviceNumber,
  };
}

export async function getLastSelectedNearAccountProjection(
  clientDB: NearAccountClientDbPort,
): Promise<ClientUserData | null> {
  const last = await getLastSelectedNearAccount(clientDB).catch(() => null);
  if (!last) return null;
  return getNearAccountProjection(clientDB, last.nearAccountId, last.deviceNumber);
}

export async function listNearAccountProjections(
  clientDB: Pick<PasskeyClientDBManager, 'listChainAccountsByChain'> & NearAccountClientDbPort,
): Promise<ClientUserData[]> {
  const [nearTestnetRows, nearMainnetRows] = await Promise.all([
    clientDB.listChainAccountsByChain('near:testnet'),
    clientDB.listChainAccountsByChain('near:mainnet'),
  ]);

  const accountCandidates = new Set<AccountId>();
  for (const row of [...nearTestnetRows, ...nearMainnetRows]) {
    const candidate = toTrimmedString(row.accountAddress || '');
    if (!candidate) continue;
    try {
      accountCandidates.add(toAccountId(candidate));
    } catch {}
  }

  const users: ClientUserData[] = [];
  for (const accountId of accountCandidates) {
    const projected = await getNearAccountProjection(clientDB, accountId).catch(() => null);
    if (projected) users.push(projected);
  }
  return users;
}

export async function setLastProfileStateForNearAccount(
  clientDB: Pick<
    PasskeyClientDBManager,
    'resolveProfileAccountContext' | 'setLastProfileStateForProfile'
  >,
  nearAccountId: AccountId,
  deviceNumber: number,
): Promise<void> {
  const normalizedDeviceNumber = Number(deviceNumber);
  if (!Number.isSafeInteger(normalizedDeviceNumber) || normalizedDeviceNumber < 1) {
    throw new Error('PasskeyClientDB: deviceNumber must be an integer >= 1');
  }
  const context = await resolveNearAccountContext(clientDB, nearAccountId);
  if (!context?.profileId) {
    throw new Error(
      `PasskeyClientDB: Missing profile/account mapping for NEAR account ${String(nearAccountId)}`,
    );
  }
  await clientDB.setLastProfileStateForProfile(context.profileId, normalizedDeviceNumber);
}

export async function upsertNearAccountProjection(
  clientDB: NearAccountClientDbPort,
  input: StoreUserDataInput,
): Promise<ClientUserData> {
  const accountId = toAccountId(input.nearAccountId);
  const now = Date.now();
  const deviceNumber = Number(input.deviceNumber);
  const normalizedDeviceNumber =
    Number.isSafeInteger(deviceNumber) && deviceNumber >= 1 ? deviceNumber : 1;
  const userData: ClientUserData = {
    nearAccountId: accountId,
    deviceNumber: normalizedDeviceNumber,
    version: input.version || 2,
    registeredAt: now,
    lastLogin: now,
    lastUpdated: input.lastUpdated ?? now,
    operationalPublicKey: input.operationalPublicKey,
    passkeyCredential: input.passkeyCredential,
    preferences: input.preferences ?? {
      useRelayer: false,
      useNetwork: inferNearChainIdKey(accountId).endsWith('mainnet') ? 'mainnet' : 'testnet',
      confirmationConfig: DEFAULT_CONFIRMATION_CONFIG,
    },
  };

  await upsertNearAccountProjectionRecords({
    userData,
    ops: {
      upsertProfile: (record) => clientDB.upsertProfile(record),
      upsertChainAccount: (record) => clientDB.upsertChainAccount(record),
      getAccountSigner: (args) => clientDB.getAccountSigner(args),
      upsertAccountSigner: (record) => clientDB.upsertAccountSigner(record),
    },
  });
  await setLastProfileStateForNearAccount(clientDB, accountId, normalizedDeviceNumber);
  return (await getNearAccountProjection(clientDB, accountId, normalizedDeviceNumber)) || userData;
}

export async function touchLastLoginForNearAccount(
  clientDB: Pick<
    PasskeyClientDBManager,
    'resolveProfileAccountContext' | 'getLastProfileState' | 'getProfile' | 'setLastProfileStateForProfile'
  >,
  nearAccountId: AccountId,
): Promise<void> {
  const context = await resolveNearAccountContext(clientDB, nearAccountId).catch(() => null);
  if (!context?.profileId) return;
  const [lastProfileState, profile] = await Promise.all([
    clientDB.getLastProfileState().catch(() => null),
    clientDB.getProfile(context.profileId).catch(() => null),
  ]);
  const defaultDeviceNumber = Number(profile?.defaultDeviceNumber);
  const deviceNumber =
    lastProfileState?.profileId === context.profileId
      ? lastProfileState.deviceNumber
      : Number.isSafeInteger(defaultDeviceNumber) && defaultDeviceNumber >= 1
        ? defaultDeviceNumber
        : 1;
  await clientDB.setLastProfileStateForProfile(context.profileId, deviceNumber);
}

export async function updateNearAccountPreferences(
  clientDB: Pick<
    PasskeyClientDBManager,
    'resolveProfileAccountContext' | 'updatePreferences'
  >,
  nearAccountId: AccountId,
  preferences: Partial<UserPreferences>,
): Promise<void> {
  const accountId = toAccountId(nearAccountId);
  const context = await resolveNearAccountContext(clientDB, accountId).catch(() => null);
  if (!context?.profileId) return;
  await clientDB.updatePreferences({
    profileId: context.profileId,
    preferences,
    eventAccountId: accountId,
  });
}
