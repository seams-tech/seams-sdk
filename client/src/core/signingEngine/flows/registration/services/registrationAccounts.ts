import type {
  ClientAuthenticatorData,
  ClientUserData,
  StoreUserDataInput,
} from '@/core/accountData/near/types';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { AccountId } from '@/core/types/accountIds';
import type { RegistrationAccountLifecycleDeps } from '@/core/signingEngine/interfaces/operationDeps';
import {
  getAllUsers,
  getLastUser,
  getUserBySignerSlot,
  hasPasskeyCredential,
  initializeCurrentUser,
  nearAuthenticatorsByAccount,
  rollbackUserRegistration,
  setLastUser,
  storeAuthenticator,
  storeUserData,
  storeWalletEd25519RegistrationData,
  storeWalletEd25519SignerRecord,
  storeWalletEmailOtpEd25519RegistrationData,
  updateLastLogin,
  type StoredRegistrationData,
  type StoreAuthenticatorInput,
  type StoreWalletEd25519RegistrationInput,
  type StoreWalletEd25519SignerRecordInput,
  type StoreWalletEmailOtpEd25519RegistrationInput,
} from '@/core/signingEngine/flows/registration/accountLifecycle';

export type InitializeCurrentUserInput = {
  nearAccountId: AccountId;
  nearClient?: NearClient;
};

export type RegistrationAccountsService = {
  storeUserData(userData: StoreUserDataInput): Promise<void>;
  getAllUsers(): Promise<ClientUserData[]>;
  getUserBySignerSlot(
    nearAccountId: AccountId,
    signerSlot: number,
  ): Promise<ClientUserData | null>;
  getLastUser(): Promise<ClientUserData | null>;
  nearAuthenticatorsByAccount(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]>;
  updateLastLogin(nearAccountId: AccountId): Promise<void>;
  setLastUser(nearAccountId: AccountId, signerSlot: number): Promise<void>;
  initializeCurrentUser(input: InitializeCurrentUserInput): Promise<void>;
  storeAuthenticator(authenticatorData: StoreAuthenticatorInput): Promise<void>;
  rollbackUserRegistration(nearAccountId: AccountId): Promise<void>;
  hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean>;
  storeWalletEd25519RegistrationData(
    input: StoreWalletEd25519RegistrationInput,
  ): Promise<StoredRegistrationData>;
  storeWalletEmailOtpEd25519RegistrationData(
    input: StoreWalletEmailOtpEd25519RegistrationInput,
  ): Promise<StoredRegistrationData>;
  storeWalletEd25519SignerRecord(
    input: StoreWalletEd25519SignerRecordInput,
  ): Promise<StoredRegistrationData>;
};

export function createRegistrationAccountsService(
  accountLifecycle: RegistrationAccountLifecycleDeps,
): RegistrationAccountsService {
  return {
    storeUserData: async (userData) => {
      await storeUserData(accountLifecycle, userData);
    },
    getAllUsers: () => getAllUsers(accountLifecycle),
    getUserBySignerSlot: (nearAccountId, signerSlot) =>
      getUserBySignerSlot(accountLifecycle, nearAccountId, signerSlot),
    getLastUser: () => getLastUser(accountLifecycle),
    nearAuthenticatorsByAccount: (nearAccountId) =>
      nearAuthenticatorsByAccount(accountLifecycle, nearAccountId),
    updateLastLogin: (nearAccountId) => updateLastLogin(accountLifecycle, nearAccountId),
    setLastUser: (nearAccountId, signerSlot) =>
      setLastUser(accountLifecycle, nearAccountId, signerSlot),
    initializeCurrentUser: (input) => initializeCurrentUser(accountLifecycle, input),
    storeAuthenticator: (authenticatorData) =>
      storeAuthenticator(accountLifecycle, authenticatorData),
    rollbackUserRegistration: (nearAccountId) =>
      rollbackUserRegistration(accountLifecycle, nearAccountId),
    hasPasskeyCredential: (nearAccountId) =>
      hasPasskeyCredential(accountLifecycle, nearAccountId),
    storeWalletEd25519RegistrationData: (input) =>
      storeWalletEd25519RegistrationData(accountLifecycle, input),
    storeWalletEmailOtpEd25519RegistrationData: (input) =>
      storeWalletEmailOtpEd25519RegistrationData(accountLifecycle, input),
    storeWalletEd25519SignerRecord: (input) =>
      storeWalletEd25519SignerRecord(accountLifecycle, input),
  };
}
