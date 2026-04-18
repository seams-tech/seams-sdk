import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { SIGNER_AUTH_METHODS, SIGNER_KINDS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { NonceManager } from '@/core/rpcClients/near/nonceManager';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { WebAuthnRegistrationCredential } from '@/core/types';
import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import type { ClientUserData, StoreUserDataInput } from '@/core/accountData/near/types';
import {
  resolveProfileAccountContextFromCandidates,
  resolveProfileAccountProjection,
} from '@/core/indexedDB/profileAccountProjection';
import { normalizeIndexedDbAccountAddress } from '@/core/indexedDB/normalization';
import { inferNearChainIdKey } from '@/core/accountData/near/accountRefs';
import { buildNearProfileId } from '@/core/accountData/near/profileId';
import { getLastLoggedInSignerSlot } from '../../signers/webauthn/device/signerSlot';
import type { UserPreferencesManager } from '../userPreferences';
import type { IDBPDatabase } from 'idb';

export type RegistrationAccountLifecycleDeps = {
  indexedDB: UnifiedIndexedDBManager;
  userPreferencesManager: Pick<UserPreferencesManager, 'setCurrentUser' | 'reloadUserSettings'>;
  nonceManager: Pick<NonceManager, 'initializeUser' | 'prefetchBlockheight'>;
  extractCosePublicKey: (attestationObjectBase64url: string) => Promise<Uint8Array>;
};

export type StoreAuthenticatorInput = {
  credentialId: string;
  credentialPublicKey: Uint8Array;
  transports?: string[];
  name?: string;
  nearAccountId: AccountId;
  registered: string;
  syncedAt: string;
  signerSlot?: number;
};

async function resolveNearProfileContext(
  deps: RegistrationAccountLifecycleDeps,
  nearAccountId: AccountId,
): Promise<{ profileId: string; chainIdKey: string; accountAddress: string } | null> {
  const accountId = toAccountId(nearAccountId);
  const context = await resolveProfileAccountContextFromCandidates(
    deps.indexedDB.clientDB,
    buildNearAccountRefs(accountId),
  ).catch(() => null);
  if (!context?.profileId) return null;
  return {
    profileId: context.profileId,
    chainIdKey: context.accountRef.chainIdKey,
    accountAddress: context.accountRef.accountAddress,
  };
}

async function readNearUserData(
  deps: RegistrationAccountLifecycleDeps,
  nearAccountId: AccountId,
  signerSlot?: number,
): Promise<ClientUserData | null> {
  const accountId = toAccountId(nearAccountId);
  const projection = await resolveProfileAccountProjection(deps.indexedDB.clientDB, {
    accountRefs: buildNearAccountRefs(accountId),
    ...(typeof signerSlot === 'number' ? { signerSlot } : {}),
  }).catch(() => null);
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
    signerSlot: projection.selectedSigner.signerSlot,
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

export async function storeUserData(
  deps: RegistrationAccountLifecycleDeps,
  userData: StoreUserDataInput,
): Promise<{ signerSlot: number }> {
  const nearAccountId = toAccountId(userData.nearAccountId);
  const signerSlot = Number(userData.signerSlot);
  const normalizedSignerSlot =
    Number.isSafeInteger(signerSlot) && signerSlot >= 1 ? signerSlot : 1;
  const profileId = buildNearProfileId(nearAccountId);
  const chainIdKey = inferNearChainIdKey(nearAccountId, userData.preferences?.useNetwork);
  const accountAddress = normalizeIndexedDbAccountAddress(nearAccountId);
  const signerId =
    String(userData.passkeyCredential?.rawId || '').trim() || `signer-${normalizedSignerSlot}`;

  await deps.indexedDB.clientDB.upsertProfile({
    profileId,
    defaultSignerSlot: normalizedSignerSlot,
    passkeyCredential: userData.passkeyCredential,
    ...(userData.preferences ? { preferences: userData.preferences } : {}),
  });
  const existingSigner = await deps.indexedDB.clientDB
    .getAccountSigner({
      chainIdKey,
      accountAddress,
      signerId,
    })
    .catch(() => null);
  const activation = await deps.indexedDB.clientDB.activateAccountSigner({
    account: {
      profileId,
      chainIdKey,
      accountAddress,
      accountModel: 'near-native',
    },
    signer: {
      signerId,
      signerType: 'threshold',
      signerKind: SIGNER_KINDS.thresholdEd25519,
      signerAuthMethod: SIGNER_AUTH_METHODS.passkey,
      signerSource: SIGNER_SOURCES.passkeyRegistration,
      metadata: {
        ...(existingSigner?.metadata || {}),
        operationalPublicKey: userData.operationalPublicKey,
        passkeyCredentialId: userData.passkeyCredential?.id,
        passkeyCredentialRawId: userData.passkeyCredential?.rawId,
      },
    },
    activationPolicy: { mode: 'allocate_next_free' },
    preferredSlot: normalizedSignerSlot,
    mutation: { routeThroughOutbox: false },
  });

  if (activation.signerSlot !== normalizedSignerSlot) {
    await deps.indexedDB.clientDB.upsertProfile({
      profileId,
      defaultSignerSlot: activation.signerSlot,
      passkeyCredential: userData.passkeyCredential,
      ...(userData.preferences ? { preferences: userData.preferences } : {}),
    });
  }

  return { signerSlot: activation.signerSlot };
}

export async function initializeCurrentUser(
  deps: RegistrationAccountLifecycleDeps,
  args: { nearAccountId: AccountId; nearClient?: NearClient },
): Promise<void> {
  const accountId = toAccountId(args.nearAccountId);

  // Set as last profile/signer slot for future sessions, preferring the existing pointer.
  let signerSlotToUse = await getLastLoggedInSignerSlot(
    accountId,
    deps.indexedDB.clientDB,
  ).catch(() => null as number | null);
  if (signerSlotToUse === null) {
    const context = await resolveNearProfileContext(deps, accountId);
    const profile = context?.profileId
      ? await deps.indexedDB.clientDB.getProfile(context.profileId).catch(() => null)
      : null;
    const defaultSignerSlot = Number(profile?.defaultSignerSlot);
    signerSlotToUse =
      Number.isSafeInteger(defaultSignerSlot) && defaultSignerSlot >= 1 ? defaultSignerSlot : 1;
  }
  const context = await resolveNearProfileContext(deps, accountId);
  if (context?.profileId) {
    await deps.indexedDB.clientDB.setLastProfileStateForProfile(
      context.profileId,
      signerSlotToUse,
    );
  }

  // Set as current user for immediate use
  deps.userPreferencesManager.setCurrentUser(accountId);
  // Ensure confirmation preferences are loaded before callers read them (best-effort)
  await deps.userPreferencesManager.reloadUserSettings().catch(() => undefined);

  // Initialize NonceManager with the selected operational NEAR key (best-effort)
  const userData = await readNearUserData(deps, accountId, signerSlotToUse);
  if (userData && userData.operationalPublicKey) {
    deps.nonceManager.initializeUser(accountId, userData.operationalPublicKey);
  }

  // Prefetch block height for better UX (non-fatal if it fails and nearClient is provided)
  if (args.nearClient) {
    await deps.nonceManager
      .prefetchBlockheight(args.nearClient)
      .catch((prefetchErr) =>
        console.debug(
          'Nonce prefetch after authentication state initialization failed (non-fatal):',
          prefetchErr,
        ),
      );
  }
}

export async function registerUser(
  deps: RegistrationAccountLifecycleDeps,
  storeUserDataInput: StoreUserDataInput,
): Promise<ClientUserData> {
  const activation = await storeUserData(deps, storeUserDataInput);
  const stored = await readNearUserData(
    deps,
    storeUserDataInput.nearAccountId,
    activation.signerSlot,
  );
  if (!stored) {
    throw new Error(
      `PasskeyClientDB: Failed to resolve stored NEAR account projection for ${String(storeUserDataInput.nearAccountId || '').trim()}`,
    );
  }
  return stored;
}

export async function storeAuthenticator(
  deps: RegistrationAccountLifecycleDeps,
  authenticatorData: StoreAuthenticatorInput,
): Promise<void> {
  const signerSlot = Number(authenticatorData.signerSlot);
  const normalizedSignerSlot =
    Number.isSafeInteger(signerSlot) && signerSlot >= 1 ? signerSlot : 1;
  const authData = {
    ...authenticatorData,
    nearAccountId: toAccountId(authenticatorData.nearAccountId),
    signerSlot: normalizedSignerSlot,
  };
  const context = await resolveNearProfileContext(deps, authData.nearAccountId);
  if (!context?.profileId) {
    throw new Error(
      `PasskeyClientDB: Missing profile/account mapping for NEAR account ${authData.nearAccountId}`,
    );
  }
  await deps.indexedDB.clientDB.upsertProfileAuthenticator({
    profileId: context.profileId,
    signerSlot: authData.signerSlot,
    credentialId: authData.credentialId,
    credentialPublicKey: authData.credentialPublicKey,
    transports: authData.transports,
    name: authData.name,
    registered: authData.registered,
    syncedAt: authData.syncedAt,
  });
}

export function extractUsername(nearAccountId: AccountId): string {
  return String(nearAccountId).split('.')[0] || '';
}

export async function atomicOperation<T>(
  deps: RegistrationAccountLifecycleDeps,
  callback: (db: IDBPDatabase) => Promise<T>,
): Promise<T> {
  return await deps.indexedDB.clientDB.atomicOperation(callback);
}

export async function rollbackUserRegistration(
  deps: RegistrationAccountLifecycleDeps,
  nearAccountId: AccountId,
): Promise<void> {
  const accountId = toAccountId(nearAccountId);
  const context = await resolveNearProfileContext(deps, accountId);
  if (!context?.profileId) return;
  await deps.indexedDB.clientDB.deleteProfileData(context.profileId, { eventAccountId: accountId });
}

export async function hasPasskeyCredential(
  deps: RegistrationAccountLifecycleDeps,
  nearAccountId: AccountId,
): Promise<boolean> {
  const accountId = toAccountId(nearAccountId);
  const context = await resolveNearProfileContext(deps, accountId);
  if (!context?.profileId) return false;
  const authenticators = await deps.indexedDB.clientDB.listProfileAuthenticators(context.profileId);
  if (authenticators.length > 0) return !!authenticators[0]?.credentialId;
  const profile = await deps.indexedDB.clientDB.getProfile(context.profileId).catch(() => null);
  return !!profile?.passkeyCredential?.rawId;
}

export async function atomicStoreRegistrationData(
  deps: RegistrationAccountLifecycleDeps,
  args: {
    nearAccountId: AccountId;
    credential: WebAuthnRegistrationCredential;
    operationalPublicKey: string;
  },
): Promise<void> {
  await atomicOperation(deps, async () => {
    // Store credential for authentication
    const credentialId: string = args.credential.rawId;
    const attestationB64u: string = args.credential.response.attestationObject;
    const transports: string[] = args.credential.response?.transports;
    const credentialPublicKey = await deps.extractCosePublicKey(attestationB64u);

    // Persist profile/account mapping first.
    await storeUserData(deps, {
      nearAccountId: args.nearAccountId,
      signerSlot: 1,
      operationalPublicKey: args.operationalPublicKey,
      lastUpdated: Date.now(),
      passkeyCredential: {
        id: args.credential.id,
        rawId: credentialId,
      },
      version: 2,
    });

    await storeAuthenticator(deps, {
      nearAccountId: args.nearAccountId,
      credentialId: credentialId,
      credentialPublicKey,
      transports,
      name: `Passkey for ${extractUsername(args.nearAccountId)}`,
      registered: new Date().toISOString(),
      syncedAt: new Date().toISOString(),
    });

    return true;
  });
}
