import type {
  ClientAuthenticatorData,
  ClientUserData,
  StoreUserDataInput,
} from '@/core/accountData/near/types';
import type { AccountId } from '@/core/types/accountIds';
import type { WebAuthnAuthenticationCredential, WebAuthnRegistrationCredential } from '@/core/types';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { RegistrationCredentialConfirmationPayload } from '../../workerManager/validation';
import type { WebAuthnAllowCredential } from '../../webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type {
  RegistrationAccountLifecycleDeps,
  RegistrationSessionDeps,
} from '../../interfaces/operationDeps';
import type { NearSigningKeyOps } from '../../interfaces/nearKeyOps';
import {
  atomicStoreRegistrationData as atomicStoreRegistrationDataValue,
  getAllUsers as getAllUsersValue,
  getAuthenticatorsByUser as getAuthenticatorsByUserValue,
  getLastUser as getLastUserValue,
  getUserBySignerSlot as getUserBySignerSlotValue,
  hasPasskeyCredential as hasPasskeyCredentialValue,
  initializeCurrentUser as initializeCurrentUserValue,
  rollbackUserRegistration as rollbackUserRegistrationValue,
  setLastUser as setLastUserValue,
  storeWalletSubjectEd25519SignerRecord as storeWalletSubjectEd25519SignerRecordValue,
  storeWalletSubjectEd25519RegistrationData as storeWalletSubjectEd25519RegistrationDataValue,
  storeWalletSubjectEcdsaRegistrationData as storeWalletSubjectEcdsaRegistrationDataValue,
  storeWalletSubjectEcdsaSignerRecords as storeWalletSubjectEcdsaSignerRecordsValue,
  storeAuthenticator as storeAuthenticatorValue,
  storeUserData as storeUserDataValue,
  updateLastLogin as updateLastLoginValue,
  type StoredRegistrationData,
  type StoreWalletSubjectEcdsaSignerRecordsInput,
  type StoreWalletSubjectEcdsaRegistrationInput,
  type StoreWalletSubjectEcdsaSignerRecordsResult,
  type StoreWalletSubjectEd25519RegistrationInput,
  type StoreWalletSubjectEd25519SignerRecordInput,
  type StoreAuthenticatorInput,
} from './accountLifecycle';
import {
  getAuthenticationCredentialsSerialized as getAuthenticationCredentialsSerializedValue,
  requestRegistrationSessionCredentialConfirmation as requestRegistrationCredentialConfirmationValue,
} from './session';

export type { StoreAuthenticatorInput };
export type { StoredRegistrationData };
export type {
  StoreWalletSubjectEcdsaSignerRecordsInput,
  StoreWalletSubjectEcdsaRegistrationInput,
  StoreWalletSubjectEcdsaSignerRecordsResult,
};

export type RegistrationPublicDeps = {
  accountLifecycle: RegistrationAccountLifecycleDeps;
  session: RegistrationSessionDeps;
  signingKeyOps: Pick<NearSigningKeyOps, 'extractCosePublicKey'>;
};

export function storeUserData(
  deps: RegistrationPublicDeps,
  userData: StoreUserDataInput,
): Promise<void> {
  return storeUserDataValue(deps.accountLifecycle, userData).then(() => undefined);
}

export function getAllUsers(deps: RegistrationPublicDeps): Promise<ClientUserData[]> {
  return getAllUsersValue(deps.accountLifecycle);
}

export function getUserBySignerSlot(
  deps: RegistrationPublicDeps,
  nearAccountId: AccountId,
  signerSlot: number,
): Promise<ClientUserData | null> {
  return getUserBySignerSlotValue(deps.accountLifecycle, nearAccountId, signerSlot);
}

export function getLastUser(deps: RegistrationPublicDeps): Promise<ClientUserData | null> {
  return getLastUserValue(deps.accountLifecycle);
}

export function getAuthenticatorsByUser(
  deps: RegistrationPublicDeps,
  nearAccountId: AccountId,
): Promise<ClientAuthenticatorData[]> {
  return getAuthenticatorsByUserValue(deps.accountLifecycle, nearAccountId);
}

export function updateLastLogin(
  deps: RegistrationPublicDeps,
  nearAccountId: AccountId,
): Promise<void> {
  return updateLastLoginValue(deps.accountLifecycle, nearAccountId);
}

export function setLastUser(
  deps: RegistrationPublicDeps,
  nearAccountId: AccountId,
  signerSlot: number = 1,
): Promise<void> {
  return setLastUserValue(deps.accountLifecycle, nearAccountId, signerSlot);
}

export function initializeCurrentUser(
  deps: RegistrationPublicDeps,
  args: {
    nearAccountId: AccountId;
    nearClient?: NearClient;
  },
): Promise<void> {
  return initializeCurrentUserValue(deps.accountLifecycle, args);
}

export function storeAuthenticator(
  deps: RegistrationPublicDeps,
  authenticatorData: StoreAuthenticatorInput,
): Promise<void> {
  return storeAuthenticatorValue(deps.accountLifecycle, authenticatorData);
}

export function rollbackUserRegistration(
  deps: RegistrationPublicDeps,
  nearAccountId: AccountId,
): Promise<void> {
  return rollbackUserRegistrationValue(deps.accountLifecycle, nearAccountId);
}

export function hasPasskeyCredential(
  deps: RegistrationPublicDeps,
  nearAccountId: AccountId,
): Promise<boolean> {
  return hasPasskeyCredentialValue(deps.accountLifecycle, nearAccountId);
}

export function atomicStoreRegistrationData(
  deps: RegistrationPublicDeps,
  args: {
    nearAccountId: AccountId;
    credential: WebAuthnRegistrationCredential;
    operationalPublicKey: string;
  },
): Promise<StoredRegistrationData> {
  return atomicStoreRegistrationDataValue(deps.accountLifecycle, args);
}

export function storeWalletSubjectEd25519RegistrationData(
  deps: RegistrationPublicDeps,
  args: StoreWalletSubjectEd25519RegistrationInput,
): Promise<StoredRegistrationData> {
  return storeWalletSubjectEd25519RegistrationDataValue(deps.accountLifecycle, args);
}

export function storeWalletSubjectEd25519SignerRecord(
  deps: RegistrationPublicDeps,
  args: StoreWalletSubjectEd25519SignerRecordInput,
): Promise<StoredRegistrationData> {
  return storeWalletSubjectEd25519SignerRecordValue(deps.accountLifecycle, args);
}

export function storeWalletSubjectEcdsaSignerRecords(
  deps: RegistrationPublicDeps,
  args: StoreWalletSubjectEcdsaSignerRecordsInput,
): Promise<StoreWalletSubjectEcdsaSignerRecordsResult> {
  return storeWalletSubjectEcdsaSignerRecordsValue(deps.accountLifecycle, args);
}

export function storeWalletSubjectEcdsaRegistrationData(
  deps: RegistrationPublicDeps,
  args: StoreWalletSubjectEcdsaRegistrationInput,
): Promise<StoreWalletSubjectEcdsaSignerRecordsResult> {
  return storeWalletSubjectEcdsaRegistrationDataValue(deps.accountLifecycle, args);
}

export function requestRegistrationCredentialConfirmation(
  deps: RegistrationPublicDeps,
  params: {
    nearAccountId: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    challengeB64u?: string;
  },
): Promise<RegistrationCredentialConfirmationPayload> {
  return requestRegistrationCredentialConfirmationValue(deps.session, params);
}

export function getAuthenticationCredentialsSerialized(
  deps: RegistrationPublicDeps,
  args: {
    nearAccountId: AccountId;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  },
): Promise<WebAuthnAuthenticationCredential> {
  return getAuthenticationCredentialsSerializedValue(deps.session, args);
}

export function extractCosePublicKey(
  deps: RegistrationPublicDeps,
  attestationObjectBase64url: string,
): Promise<Uint8Array> {
  return deps.signingKeyOps.extractCosePublicKey(attestationObjectBase64url);
}

export function createRegistrationPublicApi(deps: RegistrationPublicDeps) {
  return {
    storeUserData: (userData: StoreUserDataInput) => storeUserData(deps, userData),
    getAllUsers: () => getAllUsers(deps),
    getUserBySignerSlot: (nearAccountId: AccountId, signerSlot: number) =>
      getUserBySignerSlot(deps, nearAccountId, signerSlot),
    getLastUser: () => getLastUser(deps),
    getAuthenticatorsByUser: (nearAccountId: AccountId) =>
      getAuthenticatorsByUser(deps, nearAccountId),
    updateLastLogin: (nearAccountId: AccountId) => updateLastLogin(deps, nearAccountId),
    setLastUser: (nearAccountId: AccountId, signerSlot: number = 1) =>
      setLastUser(deps, nearAccountId, signerSlot),
    initializeCurrentUser: (args: { nearAccountId: AccountId; nearClient?: NearClient }) =>
      initializeCurrentUser(deps, args),
    storeAuthenticator: (authenticatorData: StoreAuthenticatorInput) =>
      storeAuthenticator(deps, authenticatorData),
    rollbackUserRegistration: (nearAccountId: AccountId) =>
      rollbackUserRegistration(deps, nearAccountId),
    hasPasskeyCredential: (nearAccountId: AccountId) => hasPasskeyCredential(deps, nearAccountId),
    atomicStoreRegistrationData: (args: {
      nearAccountId: AccountId;
      credential: WebAuthnRegistrationCredential;
      operationalPublicKey: string;
    }) => atomicStoreRegistrationData(deps, args),
    storeWalletSubjectEd25519RegistrationData: (
      args: StoreWalletSubjectEd25519RegistrationInput,
    ) => storeWalletSubjectEd25519RegistrationData(deps, args),
    storeWalletSubjectEd25519SignerRecord: (
      args: StoreWalletSubjectEd25519SignerRecordInput,
    ) => storeWalletSubjectEd25519SignerRecord(deps, args),
    storeWalletSubjectEcdsaSignerRecords: (
      args: StoreWalletSubjectEcdsaSignerRecordsInput,
    ) => storeWalletSubjectEcdsaSignerRecords(deps, args),
    storeWalletSubjectEcdsaRegistrationData: (
      args: StoreWalletSubjectEcdsaRegistrationInput,
    ) => storeWalletSubjectEcdsaRegistrationData(deps, args),
    requestRegistrationCredentialConfirmation: (params: {
    nearAccountId: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    challengeB64u?: string;
  }) => requestRegistrationCredentialConfirmation(deps, params),
    getAuthenticationCredentialsSerialized: (args: {
      nearAccountId: AccountId;
      challengeB64u: string;
      allowCredentials: WebAuthnAllowCredential[];
      includeSecondPrfOutput?: boolean;
    }) => getAuthenticationCredentialsSerialized(deps, args),
    extractCosePublicKey: (attestationObjectBase64url: string) =>
      extractCosePublicKey(deps, attestationObjectBase64url),
  };
}

export type RegistrationPublicApi = ReturnType<typeof createRegistrationPublicApi>;
