import {
  SIGNER_AUTH_METHODS,
  SIGNER_KINDS,
  SIGNER_SOURCES,
  type WalletAuthMethod,
} from '@shared/utils/signerDomain';
import {
  nearEd25519SigningKeyIdFromString,
  type NearEd25519SigningKeyId,
  type WalletId,
} from '@shared/utils/registrationIntent';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import { compactImplicitNearAccountId } from '@shared/utils/near';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { sha256HexUtf8 } from '@shared/utils/digests';
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
} from '@/core/accountData/near/nearAccountData.types';
import {
  resolveProfileAccountContextFromCandidates,
  resolveProfileAccountProjection,
} from '@/core/indexedDB/profileAccountProjection';
import {
  normalizeIndexedDbAccountAddress,
  toIndexedDbChainTargetKey,
} from '@/core/indexedDB/normalization';
import { inferNearChainIdKey } from '@/core/accountData/near/accountRefs';
import {
  buildNearProfileId,
  parseNearAccountProjectionProfileId,
  type NearAccountProjectionProfileId,
} from '@/core/accountData/near/profileId';
import { parseSignerSlot } from '@shared/utils/signerSlot';
import type {
  ActivateAccountSignerInput,
  AccountSignerRecord,
  KeyMaterialRecord,
  LocalWalletAuthMethodRecord,
  ProfileAuthenticatorRecord,
  SignerActivationPolicy,
} from '@/core/indexedDB';
import type { StoreWalletSignerFinalizeRollbackReceipt } from '@/core/indexedDB/seamsWalletDB/repositories';
import type { RegistrationAccountLifecycleDeps } from '../../interfaces/operationDeps';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '../../interfaces/ecdsaChainTarget';

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

export type StoredWalletEd25519SignerRegistration = StoredRegistrationData & {
  rollbackReceipt: StoreWalletSignerFinalizeRollbackReceipt;
};

export type StoreWalletEd25519RegistrationInput = {
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: string;
  credential: WebAuthnRegistrationCredential;
  credentialPublicKeyB64u: string;
  signerSlot: number;
  operationalPublicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  participantIds?: number[];
  clientParticipantId?: number;
  relayerParticipantId?: number;
};

type StoreWalletEd25519RegistrationMode =
  | { kind: 'fresh_registration' }
  | { kind: 'email_recovery_replacement' };

type StoreWalletEcdsaSignerRecordsMode =
  | { kind: 'fresh_registration' }
  | { kind: 'email_recovery_replacement' };

export type StoreWalletEmailOtpEd25519RegistrationInput = Omit<
  StoreWalletEd25519RegistrationInput,
  'credential' | 'credentialPublicKeyB64u'
> & {
  email: string;
  registrationAuthorityId: string;
};

export type StoreWalletEd25519SignerRecordInput = {
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: string;
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
  evmFamilySigningKeySlotId: string;
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
  credentialPublicKeyB64u: string;
};

export type StoreWalletEmailOtpEcdsaRegistrationInput = StoreWalletEcdsaSignerRecordsInput & {
  email: string;
  registrationAuthorityId: string;
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

export type StoreWalletMixedRegistrationInput = StoreWalletEd25519RegistrationInput & {
  walletKeys: readonly StoreWalletEcdsaWalletKey[];
};

export type StoreWalletMixedRegistrationResult = StoredRegistrationData &
  StoreWalletEcdsaSignerRecordsResult;

export type StoreWalletEmailOtpMixedRegistrationInput =
  StoreWalletEmailOtpEd25519RegistrationInput & {
    walletKeys: readonly StoreWalletEcdsaWalletKey[];
    credential?: never;
    credentialPublicKeyB64u?: never;
  };

export type StoreWalletEmailOtpMixedRegistrationResult = StoredRegistrationData &
  StoreWalletEcdsaSignerRecordsResult;

type StoreWalletRegistrationComposition =
  | {
      kind: 'near_ed25519_only';
      walletKeys?: never;
    }
  | {
      kind: 'near_ed25519_and_evm_family_ecdsa';
      walletKeys: readonly StoreWalletEcdsaWalletKey[];
    };

const WALLET_SUBJECT_CHAIN_ID_KEY = 'wallet';
const WALLET_SUBJECT_ACCOUNT_MODEL = 'wallet';
const THRESHOLD_ECDSA_ACCOUNT_MODEL = 'threshold-ecdsa';
const LOCAL_WALLET_AUTH_RP_ID = 'local';

function requireWebAuthnRpId(value: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function toWalletAuthMethod(authMethod: unknown): WalletAuthMethod | null {
  if (authMethod === SIGNER_AUTH_METHODS.emailOtp) return SIGNER_AUTH_METHODS.emailOtp;
  if (authMethod === SIGNER_AUTH_METHODS.passkey) return SIGNER_AUTH_METHODS.passkey;
  return null;
}

function signerLoginDisplayName(args: {
  walletId: string;
  authMethod: WalletAuthMethod | null;
  metadata: Record<string, unknown>;
}): string {
  if (args.authMethod === SIGNER_AUTH_METHODS.emailOtp) {
    const email = String(args.metadata.email || '').trim();
    if (email) return email;
  }
  return args.walletId;
}

function verifiedCredentialPublicKeyBytes(value: string, field: string): Uint8Array {
  const credentialPublicKeyB64u = String(value || '').trim();
  if (!credentialPublicKeyB64u) {
    throw new Error(`SeamsWalletDB: ${field} is required`);
  }
  const credentialPublicKey = base64UrlDecode(credentialPublicKeyB64u);
  if (credentialPublicKey.length === 0) {
    throw new Error(`SeamsWalletDB: ${field} decoded to empty credential public key`);
  }
  return credentialPublicKey;
}

async function resolveNearProfileContext(
  deps: RegistrationAccountLifecycleDeps,
  nearAccountId: AccountId,
): Promise<{
  profileId: NearAccountProjectionProfileId;
  chainIdKey: string;
  accountAddress: string;
} | null> {
  const accountId = toAccountId(nearAccountId);
  const context = await resolveProfileAccountContextFromCandidates(
    deps.accountStore,
    buildNearAccountRefs(accountId),
  ).catch(() => null);
  if (!context?.profileId) return null;
  const profileId = parseNearAccountProjectionProfileId(context.profileId);
  if (!profileId.ok) return null;
  return {
    profileId: profileId.value,
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
  const projection = await resolveProfileAccountProjection(deps.accountStore, {
    accountRefs: buildNearAccountRefs(accountId),
    ...(typeof signerSlot === 'number' ? { signerSlot } : {}),
  }).catch(() => null);
  if (!projection) return null;

  const metadata = projection.selectedSigner.metadata || {};
  const walletId = String(metadata.walletId || '').trim();
  if (!walletId) return null;
  const authMethod = toWalletAuthMethod(projection.selectedSigner.signerAuthMethod);
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
    walletId,
    nearAccountId: accountId,
    loginDisplayName: signerLoginDisplayName({
      walletId,
      authMethod,
      metadata,
    }),
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
    authMethod,
    preferences: projection.profile.preferences,
  };
}

export async function storeUserData(
  deps: RegistrationAccountLifecycleDeps,
  userData: StoreUserDataInput,
): Promise<{ signerSlot: number }> {
  const nearAccountId = toAccountId(userData.nearAccountId);
  const signerSlot = Number(userData.signerSlot);
  if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
    throw new Error('SeamsWalletDB: storeUserData requires an exact signerSlot');
  }
  const normalizedSignerSlot = signerSlot;
  const profileId = toWalletId(userData.walletId);
  const chainIdKey = inferNearChainIdKey(nearAccountId, userData.preferences?.useNetwork);
  const accountAddress = normalizeIndexedDbAccountAddress(nearAccountId);
  const signerId =
    String(userData.passkeyCredential?.rawId || '').trim() || `signer-${normalizedSignerSlot}`;

  await deps.accountStore.upsertProfile({
    profileId,
    defaultSignerSlot: normalizedSignerSlot,
    passkeyCredential: userData.passkeyCredential,
    ...(userData.preferences ? { preferences: userData.preferences } : {}),
  });
  const existingSigner = await deps.accountStore
    .getAccountSigner({
      chainIdKey,
      accountAddress,
      signerId,
    })
    .catch(() => null);
  const activation = await deps.accountStore.activateAccountSigner({
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
    await deps.accountStore.upsertProfile({
      profileId,
      defaultSignerSlot: activation.signerSlot,
      passkeyCredential: userData.passkeyCredential,
      ...(userData.preferences ? { preferences: userData.preferences } : {}),
    });
  }
  await deps.accountStore.setLastProfileStateForProfile(profileId, activation.signerSlot);

  return { signerSlot: activation.signerSlot };
}

export function getAllUsers(deps: RegistrationAccountLifecycleDeps): Promise<ClientUserData[]> {
  return listNearAccountProjections(deps.accountStore);
}

export function getUserBySignerSlot(
  deps: RegistrationAccountLifecycleDeps,
  nearAccountId: AccountId,
  signerSlot: number,
): Promise<ClientUserData | null> {
  return getNearAccountProjection(deps.accountStore, nearAccountId, signerSlot);
}

export function getLastUser(
  deps: RegistrationAccountLifecycleDeps,
): Promise<ClientUserData | null> {
  return getLastSelectedNearAccountProjection(deps.accountStore);
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
  const activeSigners = await deps.accountStore.listAccountSigners({
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
    const walletAuthenticators = await deps.accountStore.listProfileAuthenticators(walletId);
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
    deps.accountStore,
    buildNearAccountRefs(accountId),
  ).catch(() => null);
  if (!context?.accountRef) return [];
  return await listCanonicalPasskeyAuthenticatorsForNearAccount(deps, {
    nearAccountId: accountId,
    chainIdKey: context.accountRef.chainIdKey,
    accountAddress: context.accountRef.accountAddress,
  });
}

export async function setLastUser(
  deps: RegistrationAccountLifecycleDeps,
  walletId: WalletId,
  signerSlot: number,
): Promise<void> {
  const normalizedSignerSlot = Number(signerSlot);
  if (!Number.isSafeInteger(normalizedSignerSlot) || normalizedSignerSlot < 1) {
    throw new Error('SeamsWalletDB: signerSlot must be an integer >= 1');
  }
  const selectedId = String(walletId || '').trim();
  if (!selectedId) {
    throw new Error('SeamsWalletDB: selected wallet id is required');
  }
  const selectedProfile = await deps.accountStore.getProfile(selectedId).catch(() => null);
  if (!selectedProfile?.profileId) {
    throw new Error(`SeamsWalletDB: Missing profile for wallet ${selectedId}`);
  }
  await deps.accountStore.setLastProfileStateForProfile(
    selectedProfile.profileId,
    normalizedSignerSlot,
  );
}

type AuthenticatedWalletProfileBinding = Readonly<{
  kind: 'authenticated_near_ed25519_wallet_profile_binding';
  walletId: WalletId;
  nearProjectionProfileId: NearAccountProjectionProfileId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
  operationalPublicKey: string;
}>;

type AuthenticatedWalletActivationDeps = {
  accountStore: Pick<
    RegistrationAccountLifecycleDeps['accountStore'],
    | 'resolveProfileAccountContext'
    | 'getProfile'
    | 'listAccountSigners'
    | 'setLastProfileStateForProfile'
  >;
  userPreferencesManager: RegistrationAccountLifecycleDeps['userPreferencesManager'];
  nonceCoordinator: RegistrationAccountLifecycleDeps['nonceCoordinator'];
};

function storedSignerWalletId(value: unknown): WalletId | null {
  try {
    return toWalletId(value);
  } catch {
    return null;
  }
}

function storedSignerNearAccountId(value: unknown): AccountId | null {
  if (typeof value !== 'string') return null;
  try {
    return toAccountId(value);
  } catch {
    return null;
  }
}

function storedSignerNearEd25519SigningKeyId(value: unknown): NearEd25519SigningKeyId | null {
  if (typeof value !== 'string' || !value.trim()) return null;
  try {
    return nearEd25519SigningKeyIdFromString(value);
  } catch {
    return null;
  }
}

async function resolveAuthenticatedWalletProfileBinding(
  deps: AuthenticatedWalletActivationDeps,
  args: {
    walletId: WalletId;
    nearAccountId: AccountId;
    signerSlot: number;
  },
): Promise<AuthenticatedWalletProfileBinding> {
  let projection: Awaited<ReturnType<typeof resolveProfileAccountProjection>> = null;
  try {
    projection = await resolveProfileAccountProjection(deps.accountStore, {
      accountRefs: buildNearAccountRefs(args.nearAccountId),
      signerSlot: args.signerSlot,
    });
  } catch {
    projection = null;
  }
  if (!projection) {
    throw new Error('Authenticated wallet activation requires an exact NEAR signer projection');
  }
  const nearProjectionProfileId = parseNearAccountProjectionProfileId(projection.context.profileId);
  if (!nearProjectionProfileId.ok) {
    throw new Error(nearProjectionProfileId.message);
  }
  const selectedSigner = projection.selectedSigner;
  const metadata = selectedSigner.metadata || {};
  const storedWalletId = storedSignerWalletId(metadata.walletId);
  const storedNearAccountId = storedSignerNearAccountId(metadata.nearAccountId);
  const nearEd25519SigningKeyId = storedSignerNearEd25519SigningKeyId(
    metadata.nearEd25519SigningKeyId,
  );
  const operationalPublicKey =
    typeof metadata.operationalPublicKey === 'string' ? metadata.operationalPublicKey.trim() : '';
  if (
    selectedSigner.signerKind !== SIGNER_KINDS.thresholdEd25519 ||
    selectedSigner.signerSlot !== args.signerSlot ||
    storedWalletId !== args.walletId ||
    storedNearAccountId !== args.nearAccountId ||
    !nearEd25519SigningKeyId ||
    !operationalPublicKey
  ) {
    throw new Error('Authenticated wallet activation requires an exact wallet signer binding');
  }
  return {
    kind: 'authenticated_near_ed25519_wallet_profile_binding',
    walletId: storedWalletId,
    nearProjectionProfileId: nearProjectionProfileId.value,
    nearAccountId: storedNearAccountId,
    nearEd25519SigningKeyId,
    signerSlot: selectedSigner.signerSlot,
    operationalPublicKey,
  };
}

export async function activateAuthenticatedWalletState(
  deps: AuthenticatedWalletActivationDeps,
  args: {
    walletId: WalletId;
    nearAccountId: AccountId;
    signerSlot: number;
    nearClient?: NearClient;
  },
): Promise<void> {
  const accountId = toAccountId(args.nearAccountId);
  const walletId = toWalletId(args.walletId);
  const signerSlot = parseSignerSlot(args.signerSlot);
  if (!signerSlot) {
    throw new Error('Authenticated wallet activation requires an exact signerSlot');
  }
  const binding = await resolveAuthenticatedWalletProfileBinding(deps, {
    walletId,
    nearAccountId: accountId,
    signerSlot,
  });
  await deps.accountStore.setLastProfileStateForProfile(
    binding.nearProjectionProfileId,
    binding.signerSlot,
  );

  // Set as current user for immediate use
  deps.userPreferencesManager.setCurrentWallet(binding.walletId);
  // Ensure confirmation preferences are loaded before callers read them (best-effort)
  await deps.userPreferencesManager.reloadUserSettings().catch(() => undefined);

  // Initialize the coordinator's NEAR access-key lane with the selected operational key.
  deps.nonceCoordinator.initializeNearAccessKey({
    walletId: binding.walletId,
    nearAccountId: binding.nearAccountId,
    publicKey: binding.operationalPublicKey,
  });

  // Prefetch block height for better UX (non-fatal if it fails and nearClient is provided)
  if (args.nearClient) {
    await deps.nonceCoordinator
      .prefetchNearContext({ kind: 'initialized_state', nearClient: args.nearClient })
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
  await deps.accountStore.upsertProfileAuthenticator({
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
  const normalized = String(nearAccountId).trim();
  const compactImplicit = compactImplicitNearAccountId(normalized);
  if (compactImplicit) return compactImplicit;
  return normalized.split('.')[0] || '';
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
    rpId: requireWebAuthnRpId(LOCAL_WALLET_AUTH_RP_ID),
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
  registrationAuthorityId: string;
}): Promise<LocalWalletAuthMethodRecord> {
  const walletId = String(args.walletId || '').trim();
  const email = String(args.email || '')
    .trim()
    .toLowerCase();
  const registrationAuthorityId = String(args.registrationAuthorityId || '').trim();
  if (!walletId || !email || !registrationAuthorityId) {
    throw new Error(
      'SeamsWalletDB: Email OTP auth method requires walletId, email, and registrationAuthorityId',
    );
  }
  const nowMs = Date.now();
  return {
    version: 'wallet_auth_method_v1',
    kind: 'email_otp',
    status: 'active',
    localStatus: 'synced',
    walletId: args.walletId,
    emailHashHex: await sha256HexUtf8(email),
    registrationAuthorityId,
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
  await deps.accountStore.deleteProfileData(context.profileId, { eventAccountId: accountId });
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
    walletId: WalletId;
    nearAccountId: AccountId;
    credential: WebAuthnRegistrationCredential;
    credentialPublicKeyB64u: string;
    operationalPublicKey: string;
  },
): Promise<StoredRegistrationData> {
  const credentialId: string = args.credential.rawId;
  const transports: string[] = args.credential.response?.transports;
  const credentialPublicKey = verifiedCredentialPublicKeyBytes(
    args.credentialPublicKeyB64u,
    'credentialPublicKeyB64u',
  );

  const activation = await storeUserData(deps, {
    walletId: args.walletId,
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
  const publicKey =
    signerKind === SIGNER_KINDS.thresholdEcdsa
      ? requireStoreWalletString(
          metadata.thresholdEcdsaPublicKeyB64u,
          'ECDSA key material publicKey',
        )
      : requireStoreWalletString(metadata.operationalPublicKey, 'Ed25519 key material publicKey');
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
      walletId: requireStoreWalletString(metadata.walletId, 'walletId'),
      nearAccountId: requireStoreWalletString(metadata.nearAccountId, 'nearAccountId'),
      nearEd25519SigningKeyId: requireStoreWalletString(
        metadata.nearEd25519SigningKeyId,
        'nearEd25519SigningKeyId',
      ),
      relayerKeyId: requireStoreWalletString(metadata.relayerKeyId, 'relayerKeyId'),
      keyVersion: requireStoreWalletString(metadata.keyVersion, 'keyVersion'),
    };
  }
  return record;
}

function walletEd25519RegistrationActivationPolicy(args: {
  mode: StoreWalletEd25519RegistrationMode;
  signerSlot: number;
}): SignerActivationPolicy {
  switch (args.mode.kind) {
    case 'fresh_registration':
      return { mode: 'fail_if_occupied', signerSlot: args.signerSlot };
    case 'email_recovery_replacement':
      return {
        mode: 'replace_slot',
        signerSlot: args.signerSlot,
        replacedSignerKind: SIGNER_KINDS.thresholdEd25519,
        revocationReason: 'email_recovery_replacement',
      };
  }
}

function walletEcdsaSignerActivationPolicy(args: {
  mode: StoreWalletEcdsaSignerRecordsMode;
  signerSlot: number;
}): SignerActivationPolicy {
  switch (args.mode.kind) {
    case 'fresh_registration':
      return { mode: 'allocate_next_free' };
    case 'email_recovery_replacement':
      return {
        mode: 'replace_profile_chain_kind',
        signerSlot: args.signerSlot,
        replacedSignerKind: SIGNER_KINDS.thresholdEcdsa,
        revocationReason: 'email_recovery_replacement',
      };
  }
}

async function storeWalletEd25519RegistrationDataWithMode(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletEd25519RegistrationInput,
  mode: StoreWalletEd25519RegistrationMode,
  composition: StoreWalletRegistrationComposition,
): Promise<StoreWalletMixedRegistrationResult> {
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
  const nearEd25519SigningKeyId = String(args.nearEd25519SigningKeyId || '').trim();
  if (!nearEd25519SigningKeyId) {
    throw new Error('SeamsWalletDB: nearEd25519SigningKeyId is required');
  }
  const credentialPublicKey = verifiedCredentialPublicKeyBytes(
    args.credentialPublicKeyB64u,
    'credentialPublicKeyB64u',
  );
  const passkeyCredential = {
    id: args.credential.id,
    rawId: credentialId,
  };
  const nowIso = new Date().toISOString();
  const signerMetadata = {
    walletId,
    nearAccountId: String(nearAccountId),
    nearEd25519SigningKeyId,
    operationalPublicKey: args.operationalPublicKey,
    relayerKeyId: args.relayerKeyId,
    keyVersion: args.keyVersion,
    passkeyCredentialId: args.credential.id,
    passkeyCredentialRawId: credentialId,
    ...(args.participantIds ? { participantIds: args.participantIds } : {}),
    ...(args.clientParticipantId != null ? { clientParticipantId: args.clientParticipantId } : {}),
    ...(args.relayerParticipantId != null
      ? { relayerParticipantId: args.relayerParticipantId }
      : {}),
  };

  const nearProfileId = buildNearProfileId(nearAccountId);
  const chainIdKey = inferNearChainIdKey(nearAccountId);
  const accountAddress = normalizeIndexedDbAccountAddress(nearAccountId);
  const ed25519SignerId = requireStoreWalletString(args.operationalPublicKey, 'Ed25519 signerId');
  const activationPolicy = walletEd25519RegistrationActivationPolicy({
    mode,
    signerSlot,
  });
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
    activationPolicy,
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
    activationPolicy,
    preferredSlot: signerSlot,
    mutation: { routeThroughOutbox: false },
  };
  const preparedEcdsa =
    composition.kind === 'near_ed25519_and_evm_family_ecdsa'
      ? prepareWalletEcdsaSignerActivations({
          walletId: args.walletId,
          walletKeys: composition.walletKeys,
        })
      : null;
  const signerActivations: ActivateAccountSignerInput[] = [walletActivation, nearActivation];
  if (preparedEcdsa) {
    for (const activation of preparedEcdsa.signerActivations) {
      signerActivations.push(activation.input);
    }
  }
  const keyMaterialTimestamp = Date.now();
  const keyMaterials: KeyMaterialRecord[] = [];
  keyMaterials.push(
    keyMaterialForSignerActivation({
      activation: walletActivation,
      signerSlot,
      timestamp: keyMaterialTimestamp,
    }),
  );
  keyMaterials.push(
    keyMaterialForSignerActivation({
      activation: nearActivation,
      signerSlot,
      timestamp: keyMaterialTimestamp,
    }),
  );
  if (preparedEcdsa) {
    for (const activation of preparedEcdsa.signerActivations) {
      keyMaterials.push(
        keyMaterialForSignerActivation({
          activation: activation.input,
          signerSlot: activation.signerSlot,
          timestamp: keyMaterialTimestamp,
        }),
      );
    }
  }
  const result = await deps.accountStore.persistWalletRegistrationFinalize({
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
    signerActivations,
    keyMaterials,
    lastProfileState: { profileId: walletId, activeSignerSlot: signerSlot },
  });
  const storedNearActivation = result.signerActivations[1];
  if (!storedNearActivation) {
    throw new Error('SeamsWalletDB: wallet Ed25519 registration batch did not complete');
  }
  const storedSigners: StoredWalletEcdsaSignerRecord[] = [];
  if (preparedEcdsa) {
    for (let index = 0; index < preparedEcdsa.signerActivations.length; index += 1) {
      const activation = preparedEcdsa.signerActivations[index];
      const stored = result.signerActivations[index + 2];
      if (!activation || !stored) {
        throw new Error('SeamsWalletDB: mixed wallet ECDSA registration batch did not complete');
      }
      storedSigners.push({
        chainTarget: activation.chainTarget,
        targetKey: activation.targetKey,
        signerSlot: stored.signerSlot,
        signerId: activation.signerId,
      });
    }
  }
  return { signerSlot: storedNearActivation.signerSlot, storedSigners };
}

export async function storeWalletEd25519RegistrationData(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletEd25519RegistrationInput,
): Promise<StoredRegistrationData> {
  const stored = await storeWalletEd25519RegistrationDataWithMode(
    deps,
    args,
    { kind: 'fresh_registration' },
    { kind: 'near_ed25519_only' },
  );
  return { signerSlot: stored.signerSlot };
}

export async function storeWalletMixedRegistrationData(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletMixedRegistrationInput,
): Promise<StoreWalletMixedRegistrationResult> {
  return await storeWalletEd25519RegistrationDataWithMode(
    deps,
    args,
    { kind: 'fresh_registration' },
    {
      kind: 'near_ed25519_and_evm_family_ecdsa',
      walletKeys: args.walletKeys,
    },
  );
}

export async function storeWalletEd25519RecoveryRegistrationData(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletEd25519RegistrationInput,
): Promise<StoredRegistrationData> {
  const stored = await storeWalletEd25519RegistrationDataWithMode(
    deps,
    args,
    { kind: 'email_recovery_replacement' },
    { kind: 'near_ed25519_only' },
  );
  return { signerSlot: stored.signerSlot };
}

async function storeWalletEmailOtpEd25519RegistrationDataWithComposition(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletEmailOtpEd25519RegistrationInput,
  composition: StoreWalletRegistrationComposition,
): Promise<StoreWalletEmailOtpMixedRegistrationResult> {
  const signerSlot = Number(args.signerSlot);
  if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
    throw new Error('SeamsWalletDB: wallet signerSlot must be an integer >= 1');
  }
  const walletId = String(args.walletId || '').trim();
  if (!walletId) {
    throw new Error('SeamsWalletDB: walletId is required');
  }
  const nearAccountId = toAccountId(args.nearAccountId);
  const nearEd25519SigningKeyId = String(args.nearEd25519SigningKeyId || '').trim();
  if (!nearEd25519SigningKeyId) {
    throw new Error('SeamsWalletDB: nearEd25519SigningKeyId is required');
  }
  const signerMetadata = {
    walletId,
    nearAccountId: String(nearAccountId),
    nearEd25519SigningKeyId,
    operationalPublicKey: args.operationalPublicKey,
    relayerKeyId: args.relayerKeyId,
    keyVersion: args.keyVersion,
    email: String(args.email || '')
      .trim()
      .toLowerCase(),
    registrationAuthorityId: String(args.registrationAuthorityId || '').trim(),
    ...(args.participantIds ? { participantIds: args.participantIds } : {}),
    ...(args.clientParticipantId != null ? { clientParticipantId: args.clientParticipantId } : {}),
    ...(args.relayerParticipantId != null
      ? { relayerParticipantId: args.relayerParticipantId }
      : {}),
  };

  const nearProfileId = buildNearProfileId(nearAccountId);
  const chainIdKey = inferNearChainIdKey(nearAccountId);
  const accountAddress = normalizeIndexedDbAccountAddress(nearAccountId);
  const ed25519SignerId = requireStoreWalletString(args.operationalPublicKey, 'Ed25519 signerId');
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
  const preparedEcdsa =
    composition.kind === 'near_ed25519_and_evm_family_ecdsa'
      ? prepareWalletEcdsaSignerActivations(
          {
            walletId: args.walletId,
            walletKeys: composition.walletKeys,
          },
          {
            signerAuthMethod: SIGNER_AUTH_METHODS.emailOtp,
            signerSource: SIGNER_SOURCES.emailOtpRegistration,
          },
        )
      : null;
  const signerActivations: ActivateAccountSignerInput[] = [walletActivation, nearActivation];
  if (preparedEcdsa) {
    for (const activation of preparedEcdsa.signerActivations) {
      signerActivations.push(activation.input);
    }
  }
  const keyMaterialTimestamp = Date.now();
  const keyMaterials = [
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
  ];
  if (preparedEcdsa) {
    for (const activation of preparedEcdsa.signerActivations) {
      keyMaterials.push(
        keyMaterialForSignerActivation({
          activation: activation.input,
          signerSlot: activation.signerSlot,
          timestamp: keyMaterialTimestamp,
        }),
      );
    }
  }
  const result = await deps.accountStore.persistWalletRegistrationFinalize({
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
      registrationAuthorityId: args.registrationAuthorityId,
    }),
    authenticators: [],
    signerActivations,
    keyMaterials,
    lastProfileState: { profileId: walletId, activeSignerSlot: signerSlot },
  });
  const storedNearActivation = result.signerActivations[1];
  if (!storedNearActivation) {
    throw new Error('SeamsWalletDB: wallet Email OTP Ed25519 registration batch did not complete');
  }
  const storedSigners: StoredWalletEcdsaSignerRecord[] = [];
  if (preparedEcdsa) {
    for (let index = 0; index < preparedEcdsa.signerActivations.length; index += 1) {
      const activation = preparedEcdsa.signerActivations[index];
      const stored = result.signerActivations[index + 2];
      if (!activation || !stored) {
        throw new Error(
          'SeamsWalletDB: mixed wallet Email OTP ECDSA registration batch did not complete',
        );
      }
      storedSigners.push({
        chainTarget: activation.chainTarget,
        targetKey: activation.targetKey,
        signerSlot: stored.signerSlot,
        signerId: activation.signerId,
      });
    }
  }
  return { signerSlot: storedNearActivation.signerSlot, storedSigners };
}

export async function storeWalletEmailOtpEd25519RegistrationData(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletEmailOtpEd25519RegistrationInput,
): Promise<StoredRegistrationData> {
  const stored = await storeWalletEmailOtpEd25519RegistrationDataWithComposition(deps, args, {
    kind: 'near_ed25519_only',
  });
  return { signerSlot: stored.signerSlot };
}

export async function storeWalletEmailOtpMixedRegistrationData(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletEmailOtpMixedRegistrationInput,
): Promise<StoreWalletEmailOtpMixedRegistrationResult> {
  return storeWalletEmailOtpEd25519RegistrationDataWithComposition(deps, args, {
    kind: 'near_ed25519_and_evm_family_ecdsa',
    walletKeys: args.walletKeys,
  });
}

export async function finalizeWalletEd25519SignerRegistration(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletEd25519SignerRecordInput,
): Promise<StoredWalletEd25519SignerRegistration> {
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
  const nearEd25519SigningKeyId = String(args.nearEd25519SigningKeyId || '').trim();
  if (!nearEd25519SigningKeyId) {
    throw new Error('SeamsWalletDB: nearEd25519SigningKeyId is required');
  }
  const passkeyCredential = {
    id: args.credential.id,
    rawId: credentialId,
  };
  const signerMetadata = {
    walletId,
    nearAccountId: String(nearAccountId),
    nearEd25519SigningKeyId,
    operationalPublicKey: args.operationalPublicKey,
    relayerKeyId: args.relayerKeyId,
    keyVersion: args.keyVersion,
    passkeyCredentialId: args.credential.id,
    passkeyCredentialRawId: credentialId,
    ...(args.participantIds ? { participantIds: args.participantIds } : {}),
    ...(args.clientParticipantId != null ? { clientParticipantId: args.clientParticipantId } : {}),
    ...(args.relayerParticipantId != null
      ? { relayerParticipantId: args.relayerParticipantId }
      : {}),
  };

  const nearProfileId = buildNearProfileId(nearAccountId);
  const chainIdKey = inferNearChainIdKey(nearAccountId);
  const accountAddress = normalizeIndexedDbAccountAddress(nearAccountId);
  const ed25519SignerId = requireStoreWalletString(args.operationalPublicKey, 'Ed25519 signerId');
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
  const result = await deps.accountStore.persistWalletSignerFinalize({
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
    lastProfileState: { profileId: walletId, activeSignerSlot: signerSlot },
  });
  const storedNearActivation = result.signerActivations[1];
  if (!storedNearActivation) {
    throw new Error('SeamsWalletDB: wallet Ed25519 signer batch did not complete');
  }
  return {
    signerSlot: storedNearActivation.signerSlot,
    rollbackReceipt: result.rollbackReceipt,
  };
}

export async function rollbackWalletEd25519SignerRegistration(
  deps: RegistrationAccountLifecycleDeps,
  receipt: StoreWalletSignerFinalizeRollbackReceipt,
): Promise<void> {
  await deps.accountStore.rollbackWalletSignerFinalize(receipt);
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
  mode: StoreWalletEcdsaSignerRecordsMode = { kind: 'fresh_registration' },
): {
  walletId: string;
  signerActivations: PreparedWalletEcdsaSignerActivation[];
} {
  const expectedWalletId = requireStoreWalletString(args.walletId, 'walletId');
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
    const evmFamilySigningKeySlotId = requireStoreWalletString(
      walletKey.evmFamilySigningKeySlotId,
      'wallet key evmFamilySigningKeySlotId',
    );
    const relayerKeyId = requireStoreWalletString(
      walletKey.relayerKeyId,
      'wallet key relayerKeyId',
    );
    const thresholdEcdsaPublicKeyB64u = requireStoreWalletString(
      walletKey.thresholdEcdsaPublicKeyB64u,
      'wallet key thresholdEcdsaPublicKeyB64u',
    );
    const participantIds = normalizeStoreWalletParticipantIds(walletKey.participantIds);
    const thresholdOwnerAddress = normalizeIndexedDbAccountAddress(walletKey.thresholdOwnerAddress);
    if (!thresholdOwnerAddress) {
      throw new Error('SeamsWalletDB: wallet key thresholdOwnerAddress is required');
    }
    const chainIdKey = toIndexedDbChainTargetKey(walletKey.chainTarget);
    const targetKey = thresholdEcdsaChainTargetKey(walletKey.chainTarget);
    const signerSlot = 1;

    signerActivations.push({
      chainTarget: walletKey.chainTarget,
      targetKey,
      signerId: thresholdOwnerAddress,
      signerSlot,
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
            evmFamilySigningKeySlotId,
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
              evmFamilySigningKeySlotId,
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
        activationPolicy: walletEcdsaSignerActivationPolicy({ mode, signerSlot }),
        preferredSlot: signerSlot,
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
  const { walletId, signerActivations } = prepareWalletEcdsaSignerActivations(args);
  const keyMaterialTimestamp = Date.now();
  const batch = await deps.accountStore.persistWalletSignerFinalize({
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

export async function storeWalletEcdsaRecoverySignerRecords(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletEcdsaSignerRecordsInput,
): Promise<StoreWalletEcdsaSignerRecordsResult> {
  const { walletId, signerActivations } = prepareWalletEcdsaSignerActivations(
    args,
    {
      signerAuthMethod: SIGNER_AUTH_METHODS.passkey,
      signerSource: SIGNER_SOURCES.passkeyRegistration,
    },
    { kind: 'email_recovery_replacement' },
  );
  const keyMaterialTimestamp = Date.now();
  const batch = await deps.accountStore.persistWalletSignerFinalize({
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
        throw new Error('SeamsWalletDB: wallet recovery ECDSA signer batch did not complete');
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
  const batch = await deps.accountStore.persistWalletSignerFinalize({
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

export async function finalizeWalletEcdsaRegistration(
  deps: RegistrationAccountLifecycleDeps,
  args: StoreWalletEcdsaRegistrationInput,
): Promise<StoreWalletEcdsaSignerRecordsResult> {
  const walletId = requireStoreWalletString(args.walletId, 'walletId');
  const credentialId = String(args.credential.rawId || '').trim();
  if (!credentialId) {
    throw new Error('SeamsWalletDB: registration credential rawId is required');
  }
  const credentialPublicKey = verifiedCredentialPublicKeyBytes(
    args.credentialPublicKeyB64u,
    'credentialPublicKeyB64u',
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

  const batch = await deps.accountStore.persistWalletRegistrationFinalize({
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
  const walletId = requireStoreWalletString(args.walletId, 'walletId');
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

  const batch = await deps.accountStore.persistWalletRegistrationFinalize({
    profiles: [
      {
        profileId: walletId,
        defaultSignerSlot: 1,
      },
    ],
    initialAuthMethod: await emailOtpAuthMethod({
      walletId: args.walletId,
      email: args.email,
      registrationAuthorityId: args.registrationAuthorityId,
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
