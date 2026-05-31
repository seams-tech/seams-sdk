import { SIGNER_AUTH_METHODS, SIGNER_KINDS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import type { WalletId } from '@shared/utils/registrationIntent';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types';
import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import {
  getLastSelectedNearAccountProjection,
  getNearAccountProjection,
  listNearAccountProjections,
} from '@/core/accountData/near/accountProjection';
import type {
  ClientAuthenticatorData,
  ClientUserData,
  StoreUserDataInput,
} from '@/core/accountData/near/types';
import {
  resolveProfileAccountContextFromCandidates,
  resolveProfileAccountProjection,
} from '@/core/indexedDB/profileAccountProjection';
import {
  normalizeIndexedDbAccountAddress,
  toIndexedDbChainTargetKey,
} from '@/core/indexedDB/normalization';
import { inferNearChainIdKey } from '@/core/accountData/near/accountRefs';
import { buildNearProfileId } from '@/core/accountData/near/profileId';
import { getLastLoggedInSignerSlot } from '../../webauthnAuth/device/signerSlot';
import type {
  ActivateAccountSignerInput,
  AccountSignerRecord,
  KeyMaterialRecord,
  LocalWalletAuthMethodRecord,
  ProfileAuthenticatorRecord,
} from '@/core/indexedDB';
import type { RegistrationAccountLifecycleDeps } from '../../interfaces/operationDeps';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '../../interfaces/ecdsaChainTarget';
import { bytesToHex } from '../../chains/evm/bytes';

export type StoreAuthenticatorInput = {
  credentialId: string;
  credentialPublicKey: Uint8Array;
  transports?: string[];
  name?: string;
  nearAccountId: AccountId;
  registered: string;
  syncedAt: string;
  signerSlot: number;
};

export type StoredRegistrationData = {
  signerSlot: number;
};

export type StoreWalletEd25519RegistrationInput = {
  walletId: WalletId;
  nearAccountId: AccountId;
  credential: WebAuthnRegistrationCredential;
  signerSlot: number;
  operationalPublicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  participantIds?: number[];
  clientParticipantId?: number;
  relayerParticipantId?: number;
};

export type StoreWalletEmailOtpEd25519RegistrationInput = Omit<
  StoreWalletEd25519RegistrationInput,
  'credential'
> & {
  email: string;
  challengeId: string;
};

export type StoreWalletEd25519SignerRecordInput = {
  walletId: WalletId;
  nearAccountId: AccountId;
  credential: WebAuthnAuthenticationCredential;
  signerSlot: number;
  operationalPublicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  participantIds?: number[];
  clientParticipantId?: number;
  relayerParticipantId?: number;
};

export type StoreWalletEcdsaWalletKey = {
  keyScope: 'evm-family';
  chainTarget: ThresholdEcdsaChainTarget;
  walletId: string;
  rpId: string;
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  thresholdEcdsaPublicKeyB64u: string;
  thresholdOwnerAddress: string;
  relayerKeyId: string;
  relayerVerifyingShareB64u: string;
  participantIds: readonly number[];
};

export type StoreWalletEcdsaSignerRecordsInput = {
  walletId: WalletId;
  walletKeys: readonly StoreWalletEcdsaWalletKey[];
};

export type StoreWalletEcdsaRegistrationInput = StoreWalletEcdsaSignerRecordsInput & {
  credential: WebAuthnRegistrationCredential;
};

export type StoreWalletEmailOtpEcdsaRegistrationInput = StoreWalletEcdsaSignerRecordsInput & {
  email: string;
  challengeId: string;
};

export type StoredWalletEcdsaSignerRecord = {
  chainTarget: ThresholdEcdsaChainTarget;
  targetKey: string;
  signerSlot: number;
  signerId: string;
};

export type StoreWalletEcdsaSignerRecordsResult = {
  storedSigners: StoredWalletEcdsaSignerRecord[];
};

const WALLET_SUBJECT_CHAIN_ID_KEY = 'wallet';
const WALLET_SUBJECT_ACCOUNT_MODEL = 'wallet';
const THRESHOLD_ECDSA_ACCOUNT_MODEL = 'threshold-ecdsa';
const LOCAL_WALLET_AUTH_RP_ID = 'local';

async function resolveNearProfileContext(
  deps: RegistrationAccountLifecycleDeps,
  nearAccountId: AccountId,
): Promise<{ profileId: string; chainIdKey: string; accountAddress: string } | null> {
  const accountId = toAccountId(nearAccountId);
  const context = await resolveProfileAccountContextFromCandidates(
    deps.indexedDB,
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
  const projection = await resolveProfileAccountProjection(deps.indexedDB, {
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

  await deps.indexedDB.upsertProfile({
    profileId,
    defaultSignerSlot: normalizedSignerSlot,
    passkeyCredential: userData.passkeyCredential,
    ...(userData.preferences ? { preferences: userData.preferences } : {}),
  });
  const existingSigner = await deps.indexedDB
    .getAccountSigner({
      chainIdKey,
      accountAddress,
      signerId,
    })
    .catch(() => null);
  const activation = await deps.indexedDB.activateAccountSigner({
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
    await deps.indexedDB.upsertProfile({
      profileId,
      defaultSignerSlot: activation.signerSlot,
      passkeyCredential: userData.passkeyCredential,
      ...(userData.preferences ? { preferences: userData.preferences } : {}),
    });
  }
  await deps.indexedDB.setLastProfileStateForProfile(profileId, activation.signerSlot);

  return { signerSlot: activation.signerSlot };
}

export function getAllUsers(
  deps: RegistrationAccountLifecycleDeps,
): Promise<ClientUserData[]> {
  return listNearAccountProjections(deps.indexedDB);
}

export function getUserBySignerSlot(
  deps: RegistrationAccountLifecycleDeps,
  nearAccountId: AccountId,
  signerSlot: number,
): Promise<ClientUserData | null> {
  return getNearAccountProjection(deps.indexedDB, nearAccountId, signerSlot);
}

export function getLastUser(
  deps: RegistrationAccountLifecycleDeps,
): Promise<ClientUserData | null> {
  return getLastSelectedNearAccountProjection(deps.indexedDB);
}

function mapProfileAuthenticatorToClient(
  profileAuthenticator: ProfileAuthenticatorRecord,
  nearAccountId: AccountId,
  signerSlotOverride?: number,
): ClientAuthenticatorData {
  return {
    nearAccountId,
    signerSlot: signerSlotOverride ?? profileAuthenticator.signerSlot,
    credentialId: profileAuthenticator.credentialId,
    credentialPublicKey: profileAuthenticator.credentialPublicKey,
    transports: profileAuthenticator.transports,
    name: profileAuthenticator.name,
    registered: profileAuthenticator.registered,
    syncedAt: profileAuthenticator.syncedAt,
  };
}

type PasskeySignerAuthenticatorBinding = {
  walletId: string;
  credentialId: string;
  signerSlot: number;
};

function passkeySignerAuthenticatorBinding(
  signer: AccountSignerRecord,
): PasskeySignerAuthenticatorBinding | null {
  if (signer.signerAuthMethod !== SIGNER_AUTH_METHODS.passkey) return null;
  const walletId = String(signer.metadata?.walletId || '').trim();
  const credentialId = String(signer.metadata?.passkeyCredentialRawId || '').trim();
  if (!walletId || !credentialId) return null;
  return { walletId, credentialId, signerSlot: signer.signerSlot };
}

async function listCanonicalPasskeyAuthenticatorsForNearAccount(
  deps: RegistrationAccountLifecycleDeps,
  args: {
    nearAccountId: AccountId;
    chainIdKey: string;
    accountAddress: string;
  },
): Promise<ClientAuthenticatorData[]> {
  const activeSigners = await deps.indexedDB.listAccountSigners({
    chainIdKey: args.chainIdKey,
    accountAddress: args.accountAddress,
    status: 'active',
  });
  const bindings = activeSigners
    .map(passkeySignerAuthenticatorBinding)
    .filter((binding): binding is PasskeySignerAuthenticatorBinding => binding !== null);
  const byWalletId = new Map<string, PasskeySignerAuthenticatorBinding[]>();
  for (const binding of bindings) {
    const existing = byWalletId.get(binding.walletId);
    if (existing) {
      existing.push(binding);
    } else {
      byWalletId.set(binding.walletId, [binding]);
    }
  }

  const authenticators: ClientAuthenticatorData[] = [];
  for (const [walletId, walletBindings] of byWalletId.entries()) {
    const walletAuthenticators = await deps.indexedDB.listProfileAuthenticators(walletId);
    for (const binding of walletBindings) {
      const matched = walletAuthenticators.find(
        (authenticator) => authenticator.credentialId === binding.credentialId,
      );
      if (!matched) continue;
      authenticators.push(
        mapProfileAuthenticatorToClient(matched, args.nearAccountId, binding.signerSlot),
      );
    }
  }
  return authenticators;
}

export async function nearAuthenticatorsByAccount(
  deps: RegistrationAccountLifecycleDeps,
  nearAccountId: AccountId,
): Promise<ClientAuthenticatorData[]> {
  const accountId = toAccountId(nearAccountId);
  const context = await resolveProfileAccountContextFromCandidates(
    deps.indexedDB,
    buildNearAccountRefs(accountId),
  ).catch(() => null);
  if (!context?.accountRef) return [];
  return await listCanonicalPasskeyAuthenticatorsForNearAccount(deps, {
    nearAccountId: accountId,
    chainIdKey: context.accountRef.chainIdKey,
    accountAddress: context.accountRef.accountAddress,
  });
}

export async function updateLastLogin(
  deps: RegistrationAccountLifecycleDeps,
  nearAccountId: AccountId,
): Promise<void> {
  const accountId = toAccountId(nearAccountId);
  const context = await resolveProfileAccountContextFromCandidates(
    deps.indexedDB,
    buildNearAccountRefs(accountId),
  ).catch(() => null);
  if (!context?.profileId) return;
  const [lastProfileState, profile] = await Promise.all([
    deps.indexedDB.getLastProfileState().catch(() => null),
    deps.indexedDB.getProfile(context.profileId).catch(() => null),
  ]);
  const defaultSignerSlot = Number(profile?.defaultSignerSlot);
  const signerSlot =
    lastProfileState?.profileId === context.profileId
      ? lastProfileState.activeSignerSlot
      : Number.isSafeInteger(defaultSignerSlot) && defaultSignerSlot >= 1
        ? defaultSignerSlot
        : 1;
  await deps.indexedDB.setLastProfileStateForProfile(context.profileId, signerSlot);
}

export async function setLastUser(
  deps: RegistrationAccountLifecycleDeps,
  nearAccountId: AccountId,
  signerSlot: number = 1,
): Promise<void> {
  const normalizedSignerSlot = Number(signerSlot);
  if (!Number.isSafeInteger(normalizedSignerSlot) || normalizedSignerSlot < 1) {
    throw new Error('SeamsWalletDB: signerSlot must be an integer >= 1');
  }
  const accountId = toAccountId(nearAccountId);
  const context = await resolveProfileAccountContextFromCandidates(
    deps.indexedDB,
    buildNearAccountRefs(accountId),
  ).catch(() => null);
  if (!context?.profileId) {
    throw new Error(
      `SeamsWalletDB: Missing profile/account mapping for NEAR account ${String(accountId)}`,
    );
  }
  await deps.indexedDB.setLastProfileStateForProfile(context.profileId, normalizedSignerSlot);
}

export async function initializeCurrentUser(
  deps: RegistrationAccountLifecycleDeps,
  args: { nearAccountId: AccountId; nearClient?: NearClient },
): Promise<void> {
  const accountId = toAccountId(args.nearAccountId);

  // Set as last profile/signer slot for future sessions, preferring the existing pointer.
  let signerSlotToUse = await getLastLoggedInSignerSlot(
    accountId,
    deps.indexedDB,
  ).catch(() => null as number | null);
  if (signerSlotToUse === null) {
    const context = await resolveNearProfileContext(deps, accountId);
    const profile = context?.profileId
      ? await deps.indexedDB.getProfile(context.profileId).catch(() => null)
      : null;
    const defaultSignerSlot = Number(profile?.defaultSignerSlot);
    signerSlotToUse =
      Number.isSafeInteger(defaultSignerSlot) && defaultSignerSlot >= 1 ? defaultSignerSlot : 1;
  }
  const context = await resolveNearProfileContext(deps, accountId);
  if (context?.profileId) {
    await deps.indexedDB.setLastProfileStateForProfile(context.profileId, signerSlotToUse);
  }

  // Set as current user for immediate use
  deps.userPreferencesManager.setCurrentWallet(toWalletId(accountId));
  // Ensure confirmation preferences are loaded before callers read them (best-effort)
  await deps.userPreferencesManager.reloadUserSettings().catch(() => undefined);

  // Initialize the coordinator's NEAR access-key lane with the selected operational key.
  const userData = await readNearUserData(deps, accountId, signerSlotToUse);
  if (userData && userData.operationalPublicKey) {
    deps.nonceCoordinator.initializeNearAccessKey({
      accountId,
      publicKey: userData.operationalPublicKey,
    });
  }

  // Prefetch block height for better UX (non-fatal if it fails and nearClient is provided)
  if (args.nearClient) {
    await deps.nonceCoordinator
      .prefetchNearContext({ nearClient: args.nearClient })
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
      `SeamsWalletDB: Failed to resolve stored NEAR account projection for ${String(storeUserDataInput.nearAccountId || '').trim()}`,
    );
  }
  return stored;
}

export async function storeAuthenticator(
  deps: RegistrationAccountLifecycleDeps,
  authenticatorData: StoreAuthenticatorInput,
): Promise<void> {
  const signerSlot = Number(authenticatorData.signerSlot);
  if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
    throw new Error('SeamsWalletDB: authenticator signerSlot must be an integer >= 1');
  }
  const authData = {
    ...authenticatorData,
    nearAccountId: toAccountId(authenticatorData.nearAccountId),
    signerSlot,
  };
  const context = await resolveNearProfileContext(deps, authData.nearAccountId);
  if (!context?.profileId) {
    throw new Error(
      `SeamsWalletDB: Missing profile/account mapping for NEAR account ${authData.nearAccountId}`,
    );
  }
  await deps.indexedDB.upsertProfileAuthenticator({
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

function passkeyAuthMethod(args: {
  walletId: WalletId;
  credentialId: string;
  credentialPublicKey: Uint8Array;
}): LocalWalletAuthMethodRecord {
  const nowMs = Date.now();
  return {
    version: 'wallet_auth_method_v1',
    kind: 'passkey',
    status: 'active',
    localStatus: 'synced',
    walletId: args.walletId,
    rpId: LOCAL_WALLET_AUTH_RP_ID,
    credentialIdB64u: args.credentialId,
    credentialPublicKeyB64u: base64UrlEncode(args.credentialPublicKey),
    counter: 0,
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  };
}

async function emailOtpAuthMethod(args: {
  walletId: WalletId;
  email: string;
  challengeId: string;
}): Promise<LocalWalletAuthMethodRecord> {
  const walletId = String(args.walletId || '').trim();
  const email = String(args.email || '').trim().toLowerCase();
  const challengeId = String(args.challengeId || '').trim();
  if (!walletId || !email || !challengeId) {
    throw new Error('SeamsWalletDB: Email OTP auth method requires walletId, email, and challengeId');
  }
  const nowMs = Date.now();
  return {
    version: 'wallet_auth_method_v1',
    kind: 'email_otp',
    status: 'active',
    localStatus: 'synced',
    walletId: args.walletId,
    rpId: LOCAL_WALLET_AUTH_RP_ID,
    emailHashHex: bytesToHex(await sha256BytesUtf8(email)),
    challengeId,
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  };
}

export async function rollbackUserRegistration(
  deps: RegistrationAccountLifecycleDeps,
  nearAccountId: AccountId,
): Promise<void> {
  const accountId = toAccountId(nearAccountId);
  const context = await resolveNearProfileContext(deps, accountId);
  if (!context?.profileId) return;
  await deps.indexedDB.deleteProfileData(context.profileId, { eventAccountId: accountId });
}

export async function hasPasskeyCredential(
  deps: RegistrationAccountLifecycleDeps,
  nearAccountId: AccountId,
): Promise<boolean> {
  const accountId = toAccountId(nearAccountId);
  const authenticators = await nearAuthenticatorsByAccount(deps, accountId);
  return authenticators.length > 0;
}

export async function atomicStoreRegistrationData(
  deps: RegistrationAccountLifecycleDeps,
  args: {
    nearAccountId: AccountId;
    credential: WebAuthnRegistrationCredential;
    operationalPublicKey: string;
  },
): Promise<StoredRegistrationData> {
  const credentialId: string = args.credential.rawId;
  const attestationB64u: string = args.credential.response.attestationObject;
  const transports: string[] = args.credential.response?.transports;
  const credentialPublicKey = await deps.extractCosePublicKey(attestationB64u);

  const activation = await storeUserData(deps, {
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
    signerSlot: activation.signerSlot,
  });

  return { signerSlot: activation.signerSlot };
}

function keyMaterialForSignerActivation(args: {
  activation: ActivateAccountSignerInput;
  signerSlot: number;
  timestamp: number;
}): KeyMaterialRecord {
  const metadata = args.activation.signer.metadata || {};
  const signerKind = args.activation.signer.signerKind;
  const publicKey = signerKind === SIGNER_KINDS.thresholdEcdsa
    ? requireStoreWalletString(
        metadata.thresholdEcdsaPublicKeyB64u,
        'ECDSA key material publicKey',
      )
    : requireStoreWalletString(
        metadata.operationalPublicKey,
        'Ed25519 key material publicKey',
      );
  const record: KeyMaterialRecord = {
    profileId: requireStoreWalletString(args.activation.account.profileId, 'profileId'),
    signerSlot: args.signerSlot,
    chainIdKey: requireStoreWalletString(args.activation.account.chainIdKey, 'chainIdKey'),
    accountAddress: requireStoreWalletString(
      args.activation.account.accountAddress,
      'accountAddress',
    ),
    signerId: requireStoreWalletString(args.activation.signer.signerId, 'signerId'),
    keyKind: 'threshold_share_v1',
    algorithm: signerKind === SIGNER_KINDS.thresholdEcdsa ? 'secp256k1' : 'ed25519',
    publicKey,
    timestamp: args.timestamp,
    schemaVersion: 1,
  };
  if (signerKind === SIGNER_KINDS.thresholdEd25519) {
    record.payload = {
      relayerKeyId: requireStoreWalletString(metadata.relayerKeyId, 'relayerKeyId'),
      keyVersion: requireStoreWalletString(metadata.keyVersion, 'keyVersion'),
    };
  }
  return record;
}

export async function storeWalletEd25519RegistrationData(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletEd25519RegistrationInput,
): Promise<StoredRegistrationData> {
  const credentialId = String(args.credential.rawId || '').trim();
  if (!credentialId) {
    throw new Error('SeamsWalletDB: registration credential rawId is required');
  }
  const signerSlot = Number(args.signerSlot);
  if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
    throw new Error('SeamsWalletDB: wallet signerSlot must be an integer >= 1');
  }
  const walletId = String(args.walletId || '').trim();
  if (!walletId) {
    throw new Error('SeamsWalletDB: walletId is required');
  }
  const nearAccountId = toAccountId(args.nearAccountId);
  const credentialPublicKey = await deps.extractCosePublicKey(args.credential.response.attestationObject);
  const passkeyCredential = {
    id: args.credential.id,
    rawId: credentialId,
  };
  const nowIso = new Date().toISOString();
  const signerMetadata = {
    walletId,
    nearAccountId: String(nearAccountId),
    operationalPublicKey: args.operationalPublicKey,
    relayerKeyId: args.relayerKeyId,
    keyVersion: args.keyVersion,
    passkeyCredentialId: args.credential.id,
    passkeyCredentialRawId: credentialId,
    ...(args.participantIds ? { participantIds: args.participantIds } : {}),
    ...(args.clientParticipantId != null ? { clientParticipantId: args.clientParticipantId } : {}),
    ...(args.relayerParticipantId != null ? { relayerParticipantId: args.relayerParticipantId } : {}),
  };

  const nearProfileId = buildNearProfileId(nearAccountId);
  const chainIdKey = inferNearChainIdKey(nearAccountId);
  const accountAddress = normalizeIndexedDbAccountAddress(nearAccountId);
  const ed25519SignerId = requireStoreWalletString(
    args.operationalPublicKey,
    'Ed25519 signerId',
  );
  const walletActivation: ActivateAccountSignerInput = {
    account: {
      profileId: walletId,
      chainIdKey: WALLET_SUBJECT_CHAIN_ID_KEY,
      accountAddress: walletId,
      accountModel: WALLET_SUBJECT_ACCOUNT_MODEL,
    },
    signer: {
      signerId: ed25519SignerId,
      signerType: 'threshold',
      signerKind: SIGNER_KINDS.thresholdEd25519,
      signerAuthMethod: SIGNER_AUTH_METHODS.passkey,
      signerSource: SIGNER_SOURCES.passkeyRegistration,
      metadata: signerMetadata,
    },
    activationPolicy: { mode: 'fail_if_occupied', signerSlot },
    preferredSlot: signerSlot,
    mutation: { routeThroughOutbox: false },
  };
  const nearActivation: ActivateAccountSignerInput = {
    account: {
      profileId: nearProfileId,
      chainIdKey,
      accountAddress,
      accountModel: 'near-native',
    },
    signer: {
      signerId: ed25519SignerId,
      signerType: 'threshold',
      signerKind: SIGNER_KINDS.thresholdEd25519,
      signerAuthMethod: SIGNER_AUTH_METHODS.passkey,
      signerSource: SIGNER_SOURCES.passkeyRegistration,
      metadata: signerMetadata,
    },
    activationPolicy: { mode: 'fail_if_occupied', signerSlot },
    preferredSlot: signerSlot,
    mutation: { routeThroughOutbox: false },
  };
  const keyMaterialTimestamp = Date.now();
  const result = await deps.indexedDB.persistWalletRegistrationFinalize({
    profiles: [
      {
        profileId: walletId,
        defaultSignerSlot: signerSlot,
        passkeyCredential,
      },
      {
        profileId: nearProfileId,
        defaultSignerSlot: signerSlot,
        passkeyCredential,
      },
    ],
    initialAuthMethod: passkeyAuthMethod({
      walletId: args.walletId,
      credentialId,
      credentialPublicKey,
    }),
    authenticators: [
      {
        profileId: walletId,
        signerSlot,
        credentialId,
        credentialPublicKey,
        transports: args.credential.response?.transports,
        name: `Passkey for ${extractUsername(nearAccountId)}`,
        registered: nowIso,
        syncedAt: nowIso,
      },
      {
        profileId: nearProfileId,
        signerSlot,
        credentialId,
        credentialPublicKey,
        transports: args.credential.response?.transports,
        name: `Passkey for ${extractUsername(nearAccountId)}`,
        registered: nowIso,
        syncedAt: nowIso,
      },
    ],
    signerActivations: [walletActivation, nearActivation],
    keyMaterials: [
      keyMaterialForSignerActivation({
        activation: walletActivation,
        signerSlot,
        timestamp: keyMaterialTimestamp,
      }),
      keyMaterialForSignerActivation({
        activation: nearActivation,
        signerSlot,
        timestamp: keyMaterialTimestamp,
      }),
    ],
    lastProfileState: { profileId: nearProfileId, activeSignerSlot: signerSlot },
  });
  const storedNearActivation = result.signerActivations[1];
  if (!storedNearActivation) {
    throw new Error('SeamsWalletDB: wallet Ed25519 registration batch did not complete');
  }
  return { signerSlot: storedNearActivation.signerSlot };
}

export async function storeWalletEmailOtpEd25519RegistrationData(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletEmailOtpEd25519RegistrationInput,
): Promise<StoredRegistrationData> {
  const signerSlot = Number(args.signerSlot);
  if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
    throw new Error('SeamsWalletDB: wallet signerSlot must be an integer >= 1');
  }
  const walletId = String(args.walletId || '').trim();
  if (!walletId) {
    throw new Error('SeamsWalletDB: walletId is required');
  }
  const nearAccountId = toAccountId(args.nearAccountId);
  const signerMetadata = {
    walletId,
    nearAccountId: String(nearAccountId),
    operationalPublicKey: args.operationalPublicKey,
    relayerKeyId: args.relayerKeyId,
    keyVersion: args.keyVersion,
    email: String(args.email || '').trim().toLowerCase(),
    challengeId: String(args.challengeId || '').trim(),
    ...(args.participantIds ? { participantIds: args.participantIds } : {}),
    ...(args.clientParticipantId != null ? { clientParticipantId: args.clientParticipantId } : {}),
    ...(args.relayerParticipantId != null ? { relayerParticipantId: args.relayerParticipantId } : {}),
  };

  const nearProfileId = buildNearProfileId(nearAccountId);
  const chainIdKey = inferNearChainIdKey(nearAccountId);
  const accountAddress = normalizeIndexedDbAccountAddress(nearAccountId);
  const ed25519SignerId = requireStoreWalletString(
    args.operationalPublicKey,
    'Ed25519 signerId',
  );
  const walletActivation: ActivateAccountSignerInput = {
    account: {
      profileId: walletId,
      chainIdKey: WALLET_SUBJECT_CHAIN_ID_KEY,
      accountAddress: walletId,
      accountModel: WALLET_SUBJECT_ACCOUNT_MODEL,
    },
    signer: {
      signerId: ed25519SignerId,
      signerType: 'threshold',
      signerKind: SIGNER_KINDS.thresholdEd25519,
      signerAuthMethod: SIGNER_AUTH_METHODS.emailOtp,
      signerSource: SIGNER_SOURCES.emailOtpRegistration,
      metadata: signerMetadata,
    },
    activationPolicy: { mode: 'fail_if_occupied', signerSlot },
    preferredSlot: signerSlot,
    mutation: { routeThroughOutbox: false },
  };
  const nearActivation: ActivateAccountSignerInput = {
    account: {
      profileId: nearProfileId,
      chainIdKey,
      accountAddress,
      accountModel: 'near-native',
    },
    signer: {
      signerId: ed25519SignerId,
      signerType: 'threshold',
      signerKind: SIGNER_KINDS.thresholdEd25519,
      signerAuthMethod: SIGNER_AUTH_METHODS.emailOtp,
      signerSource: SIGNER_SOURCES.emailOtpRegistration,
      metadata: signerMetadata,
    },
    activationPolicy: { mode: 'fail_if_occupied', signerSlot },
    preferredSlot: signerSlot,
    mutation: { routeThroughOutbox: false },
  };
  const keyMaterialTimestamp = Date.now();
  const result = await deps.indexedDB.persistWalletRegistrationFinalize({
    profiles: [
      {
        profileId: walletId,
        defaultSignerSlot: signerSlot,
      },
      {
        profileId: nearProfileId,
        defaultSignerSlot: signerSlot,
      },
    ],
    initialAuthMethod: await emailOtpAuthMethod({
      walletId: args.walletId,
      email: args.email,
      challengeId: args.challengeId,
    }),
    authenticators: [],
    signerActivations: [walletActivation, nearActivation],
    keyMaterials: [
      keyMaterialForSignerActivation({
        activation: walletActivation,
        signerSlot,
        timestamp: keyMaterialTimestamp,
      }),
      keyMaterialForSignerActivation({
        activation: nearActivation,
        signerSlot,
        timestamp: keyMaterialTimestamp,
      }),
    ],
    lastProfileState: { profileId: nearProfileId, activeSignerSlot: signerSlot },
  });
  const storedNearActivation = result.signerActivations[1];
  if (!storedNearActivation) {
    throw new Error('SeamsWalletDB: wallet Email OTP Ed25519 registration batch did not complete');
  }
  return { signerSlot: storedNearActivation.signerSlot };
}

export async function storeWalletEd25519SignerRecord(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletEd25519SignerRecordInput,
): Promise<StoredRegistrationData> {
  const credentialId = String(args.credential.rawId || args.credential.id || '').trim();
  if (!credentialId) {
    throw new Error('SeamsWalletDB: add-signer credential id is required');
  }
  const signerSlot = Number(args.signerSlot);
  if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
    throw new Error('SeamsWalletDB: wallet signerSlot must be an integer >= 1');
  }
  const walletId = String(args.walletId || '').trim();
  if (!walletId) {
    throw new Error('SeamsWalletDB: walletId is required');
  }
  const nearAccountId = toAccountId(args.nearAccountId);
  const passkeyCredential = {
    id: args.credential.id,
    rawId: credentialId,
  };
  const signerMetadata = {
    walletId,
    nearAccountId: String(nearAccountId),
    operationalPublicKey: args.operationalPublicKey,
    relayerKeyId: args.relayerKeyId,
    keyVersion: args.keyVersion,
    passkeyCredentialId: args.credential.id,
    passkeyCredentialRawId: credentialId,
    ...(args.participantIds ? { participantIds: args.participantIds } : {}),
    ...(args.clientParticipantId != null ? { clientParticipantId: args.clientParticipantId } : {}),
    ...(args.relayerParticipantId != null ? { relayerParticipantId: args.relayerParticipantId } : {}),
  };

  const nearProfileId = buildNearProfileId(nearAccountId);
  const chainIdKey = inferNearChainIdKey(nearAccountId);
  const accountAddress = normalizeIndexedDbAccountAddress(nearAccountId);
  const ed25519SignerId = requireStoreWalletString(
    args.operationalPublicKey,
    'Ed25519 signerId',
  );
  const walletActivation = {
    account: {
      profileId: walletId,
      chainIdKey: WALLET_SUBJECT_CHAIN_ID_KEY,
      accountAddress: walletId,
      accountModel: WALLET_SUBJECT_ACCOUNT_MODEL,
    },
    signer: {
      signerId: ed25519SignerId,
      signerType: 'threshold',
      signerKind: SIGNER_KINDS.thresholdEd25519,
      signerAuthMethod: SIGNER_AUTH_METHODS.passkey,
      signerSource: SIGNER_SOURCES.passkeyRegistration,
      metadata: signerMetadata,
    },
    activationPolicy: { mode: 'fail_if_occupied', signerSlot },
    preferredSlot: signerSlot,
    mutation: { routeThroughOutbox: false },
  } satisfies ActivateAccountSignerInput;
  const nearActivation = {
    account: {
      profileId: nearProfileId,
      chainIdKey,
      accountAddress,
      accountModel: 'near-native',
    },
    signer: {
      signerId: ed25519SignerId,
      signerType: 'threshold',
      signerKind: SIGNER_KINDS.thresholdEd25519,
      signerAuthMethod: SIGNER_AUTH_METHODS.passkey,
      signerSource: SIGNER_SOURCES.passkeyRegistration,
      metadata: signerMetadata,
    },
    activationPolicy: { mode: 'fail_if_occupied', signerSlot },
    preferredSlot: signerSlot,
    mutation: { routeThroughOutbox: false },
  } satisfies ActivateAccountSignerInput;
  const keyMaterialTimestamp = Date.now();
  const result = await deps.indexedDB.persistWalletSignerFinalize({
    profiles: [
      {
        profileId: walletId,
        defaultSignerSlot: signerSlot,
        passkeyCredential,
      },
      {
        profileId: nearProfileId,
        defaultSignerSlot: signerSlot,
        passkeyCredential,
      },
    ],
    signerActivations: [
      walletActivation,
      nearActivation,
    ],
    keyMaterials: [
      keyMaterialForSignerActivation({
        activation: walletActivation,
        signerSlot,
        timestamp: keyMaterialTimestamp,
      }),
      keyMaterialForSignerActivation({
        activation: nearActivation,
        signerSlot,
        timestamp: keyMaterialTimestamp,
      }),
    ],
    lastProfileState: { profileId: nearProfileId, activeSignerSlot: signerSlot },
  });
  const storedNearActivation = result.signerActivations[1];
  if (!storedNearActivation) {
    throw new Error('SeamsWalletDB: wallet Ed25519 signer batch did not complete');
  }
  return { signerSlot: storedNearActivation.signerSlot };
}

function requireStoreWalletString(value: unknown, field: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`SeamsWalletDB: ${field} is required`);
  }
  return normalized;
}

function normalizeStoreWalletParticipantIds(value: readonly number[]): number[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error('SeamsWalletDB: threshold ECDSA participantIds are required');
  }
  return value.map((participantId) => {
    const normalized = Number(participantId);
    if (!Number.isSafeInteger(normalized) || normalized <= 0) {
      throw new Error('SeamsWalletDB: threshold ECDSA participantIds must be positive integers');
    }
    return normalized;
  });
}

type PreparedWalletEcdsaSignerActivation = {
  chainTarget: ThresholdEcdsaChainTarget;
  targetKey: string;
  signerId: string;
  signerSlot: number;
  input: ActivateAccountSignerInput;
};

function prepareWalletEcdsaSignerActivations(
  args: StoreWalletEcdsaSignerRecordsInput,
  source: {
    signerAuthMethod: (typeof SIGNER_AUTH_METHODS)[keyof typeof SIGNER_AUTH_METHODS];
    signerSource: (typeof SIGNER_SOURCES)[keyof typeof SIGNER_SOURCES];
  } = {
    signerAuthMethod: SIGNER_AUTH_METHODS.passkey,
    signerSource: SIGNER_SOURCES.passkeyRegistration,
  },
): {
  walletId: string;
  signerActivations: PreparedWalletEcdsaSignerActivation[];
} {
  const expectedWalletId = requireStoreWalletString(
    args.walletId,
    'walletId',
  );
  if (!Array.isArray(args.walletKeys) || args.walletKeys.length === 0) {
    throw new Error('SeamsWalletDB: threshold ECDSA walletKeys are required');
  }

  const signerActivations: PreparedWalletEcdsaSignerActivation[] = [];
  for (const walletKey of args.walletKeys) {
    if (walletKey.keyScope !== 'evm-family') {
      throw new Error('SeamsWalletDB: threshold ECDSA wallet keyScope must be evm-family');
    }
    const walletId = requireStoreWalletString(walletKey.walletId, 'wallet key walletId');
    if (walletId !== expectedWalletId) {
      throw new Error('SeamsWalletDB: threshold ECDSA wallet key walletId mismatch');
    }
    const keyHandle = requireStoreWalletString(walletKey.keyHandle, 'wallet key keyHandle');
    const ecdsaThresholdKeyId = requireStoreWalletString(
      walletKey.ecdsaThresholdKeyId,
      'wallet key ecdsaThresholdKeyId',
    );
    const signingRootId = requireStoreWalletString(
      walletKey.signingRootId,
      'wallet key signingRootId',
    );
    const signingRootVersion = requireStoreWalletString(
      walletKey.signingRootVersion,
      'wallet key signingRootVersion',
    );
    const rpId = requireStoreWalletString(walletKey.rpId, 'wallet key rpId');
    const relayerKeyId = requireStoreWalletString(
      walletKey.relayerKeyId,
      'wallet key relayerKeyId',
    );
    const thresholdEcdsaPublicKeyB64u = requireStoreWalletString(
      walletKey.thresholdEcdsaPublicKeyB64u,
      'wallet key thresholdEcdsaPublicKeyB64u',
    );
    const participantIds = normalizeStoreWalletParticipantIds(walletKey.participantIds);
    const thresholdOwnerAddress = normalizeIndexedDbAccountAddress(
      walletKey.thresholdOwnerAddress,
    );
    if (!thresholdOwnerAddress) {
      throw new Error('SeamsWalletDB: wallet key thresholdOwnerAddress is required');
    }
    const chainIdKey = toIndexedDbChainTargetKey(walletKey.chainTarget);
    const targetKey = thresholdEcdsaChainTargetKey(walletKey.chainTarget);

    signerActivations.push({
      chainTarget: walletKey.chainTarget,
      targetKey,
      signerId: thresholdOwnerAddress,
      signerSlot: 1,
      input: {
        account: {
          profileId: walletId,
          chainIdKey,
          accountAddress: thresholdOwnerAddress,
          accountModel: THRESHOLD_ECDSA_ACCOUNT_MODEL,
        },
        signer: {
          signerId: thresholdOwnerAddress,
          signerType: 'threshold',
          signerKind: SIGNER_KINDS.thresholdEcdsa,
          signerAuthMethod: source.signerAuthMethod,
          signerSource: source.signerSource,
          metadata: {
            accountModel: THRESHOLD_ECDSA_ACCOUNT_MODEL,
            accountAddress: thresholdOwnerAddress,
            ownerAddress: thresholdOwnerAddress,
            thresholdOwnerAddress,
            keyScope: walletKey.keyScope,
            keyHandle,
            walletId: walletId,
            rpId,
            ecdsaThresholdKeyId,
            signingRootId,
            signingRootVersion,
            relayerKeyId,
            relayerVerifyingShareB64u: requireStoreWalletString(
              walletKey.relayerVerifyingShareB64u,
              'wallet key relayerVerifyingShareB64u',
            ),
            thresholdEcdsaPublicKeyB64u,
            participantIds,
            chainTarget: walletKey.chainTarget,
            targetMembership: {
              targetKey,
              chainTarget: walletKey.chainTarget,
            },
            sharedEvmFamilyKey: {
              walletId: walletId,
              rpId,
              keyScope: walletKey.keyScope,
              keyHandle,
              ecdsaThresholdKeyId,
              signingRootId,
              signingRootVersion,
              participantIds,
              thresholdOwnerAddress,
              thresholdEcdsaPublicKeyB64u,
            },
            chainId: walletKey.chainTarget.chainId,
          },
        },
        activationPolicy: { mode: 'allocate_next_free' },
        preferredSlot: 1,
        mutation: { routeThroughOutbox: false },
      },
    });
  }
  return { walletId: expectedWalletId, signerActivations };
}

export async function storeWalletEcdsaSignerRecords(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletEcdsaSignerRecordsInput,
): Promise<StoreWalletEcdsaSignerRecordsResult> {
  const { walletId, signerActivations } =
    prepareWalletEcdsaSignerActivations(args);
  const keyMaterialTimestamp = Date.now();
  const batch = await deps.indexedDB.persistWalletSignerFinalize({
    profiles: [{ profileId: walletId }],
    signerActivations: signerActivations.map((activation) => activation.input),
    keyMaterials: signerActivations.map((activation) =>
      keyMaterialForSignerActivation({
        activation: activation.input,
        signerSlot: activation.signerSlot,
        timestamp: keyMaterialTimestamp,
      }),
    ),
  });
  return {
    storedSigners: signerActivations.map((activation, index) => {
      const result = batch.signerActivations[index];
      if (!result) {
        throw new Error('SeamsWalletDB: wallet ECDSA signer batch did not complete');
      }
      return {
        chainTarget: activation.chainTarget,
        targetKey: activation.targetKey,
        signerSlot: result.signerSlot,
        signerId: activation.signerId,
      };
    }),
  };
}

export async function storeWalletEmailOtpEcdsaSignerRecords(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletEcdsaSignerRecordsInput,
): Promise<StoreWalletEcdsaSignerRecordsResult> {
  const { walletId, signerActivations } = prepareWalletEcdsaSignerActivations(args, {
    signerAuthMethod: SIGNER_AUTH_METHODS.emailOtp,
    signerSource: SIGNER_SOURCES.emailOtpRegistration,
  });
  const keyMaterialTimestamp = Date.now();
  const batch = await deps.indexedDB.persistWalletSignerFinalize({
    profiles: [{ profileId: walletId }],
    signerActivations: signerActivations.map((activation) => activation.input),
    keyMaterials: signerActivations.map((activation) =>
      keyMaterialForSignerActivation({
        activation: activation.input,
        signerSlot: activation.signerSlot,
        timestamp: keyMaterialTimestamp,
      }),
    ),
  });
  return {
    storedSigners: signerActivations.map((activation, index) => {
      const result = batch.signerActivations[index];
      if (!result) {
        throw new Error('SeamsWalletDB: wallet Email OTP ECDSA signer batch did not complete');
      }
      return {
        chainTarget: activation.chainTarget,
        targetKey: activation.targetKey,
        signerSlot: result.signerSlot,
        signerId: activation.signerId,
      };
    }),
  };
}

export async function storeWalletEcdsaRegistrationData(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletEcdsaRegistrationInput,
): Promise<StoreWalletEcdsaSignerRecordsResult> {
  const walletId = requireStoreWalletString(
    args.walletId,
    'walletId',
  );
  const credentialId = String(args.credential.rawId || '').trim();
  if (!credentialId) {
    throw new Error('SeamsWalletDB: registration credential rawId is required');
  }
  const credentialPublicKey = await deps.extractCosePublicKey(
    args.credential.response.attestationObject,
  );
  const passkeyCredential = {
    id: args.credential.id,
    rawId: credentialId,
  };
  const nowIso = new Date().toISOString();
  const preparedEcdsa = prepareWalletEcdsaSignerActivations({
    walletId: args.walletId,
    walletKeys: args.walletKeys,
  });
  const keyMaterialTimestamp = Date.now();

  const batch = await deps.indexedDB.persistWalletRegistrationFinalize({
    profiles: [
      {
        profileId: walletId,
        defaultSignerSlot: 1,
        passkeyCredential,
      },
    ],
    initialAuthMethod: passkeyAuthMethod({
      walletId: args.walletId,
      credentialId,
      credentialPublicKey,
    }),
    authenticators: [
      {
        profileId: walletId,
        signerSlot: 1,
        credentialId,
        credentialPublicKey,
        transports: args.credential.response?.transports,
        name: 'Passkey for wallet',
        registered: nowIso,
        syncedAt: nowIso,
      },
    ],
    signerActivations: preparedEcdsa.signerActivations.map((activation) => activation.input),
    keyMaterials: preparedEcdsa.signerActivations.map((activation) =>
      keyMaterialForSignerActivation({
        activation: activation.input,
        signerSlot: activation.signerSlot,
        timestamp: keyMaterialTimestamp,
      }),
    ),
  });

  return {
    storedSigners: preparedEcdsa.signerActivations.map((activation, index) => {
      const result = batch.signerActivations[index];
      if (!result) {
        throw new Error('SeamsWalletDB: wallet ECDSA registration batch did not complete');
      }
      return {
        chainTarget: activation.chainTarget,
        targetKey: activation.targetKey,
        signerSlot: result.signerSlot,
        signerId: activation.signerId,
      };
    }),
  };
}

export async function storeWalletEmailOtpEcdsaRegistrationData(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletEmailOtpEcdsaRegistrationInput,
): Promise<StoreWalletEcdsaSignerRecordsResult> {
  const walletId = requireStoreWalletString(
    args.walletId,
    'walletId',
  );
  const preparedEcdsa = prepareWalletEcdsaSignerActivations(
    {
      walletId: args.walletId,
      walletKeys: args.walletKeys,
    },
    {
      signerAuthMethod: SIGNER_AUTH_METHODS.emailOtp,
      signerSource: SIGNER_SOURCES.emailOtpRegistration,
    },
  );
  const keyMaterialTimestamp = Date.now();

  const batch = await deps.indexedDB.persistWalletRegistrationFinalize({
    profiles: [
      {
        profileId: walletId,
        defaultSignerSlot: 1,
      },
    ],
    initialAuthMethod: await emailOtpAuthMethod({
      walletId: args.walletId,
      email: args.email,
      challengeId: args.challengeId,
    }),
    authenticators: [],
    signerActivations: preparedEcdsa.signerActivations.map((activation) => activation.input),
    keyMaterials: preparedEcdsa.signerActivations.map((activation) =>
      keyMaterialForSignerActivation({
        activation: activation.input,
        signerSlot: activation.signerSlot,
        timestamp: keyMaterialTimestamp,
      }),
    ),
  });

  return {
    storedSigners: preparedEcdsa.signerActivations.map((activation, index) => {
      const result = batch.signerActivations[index];
      if (!result) {
        throw new Error(
          'SeamsWalletDB: wallet Email OTP ECDSA registration batch did not complete',
        );
      }
      return {
        chainTarget: activation.chainTarget,
        targetKey: activation.targetKey,
        signerSlot: result.signerSlot,
        signerId: activation.signerId,
      };
    }),
  };
}
