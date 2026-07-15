import type {
  ClientAuthenticatorData,
  ClientUserData,
  StoreUserDataInput,
} from '@/core/accountData/near/nearAccountData.types';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { AccountId } from '@/core/types/accountIds';
import type { WalletId } from '@shared/utils/registrationIntent';
import type { RegistrationAccountLifecycleDeps } from '@/core/signingEngine/interfaces/operationDeps';
import {
  getAllUsers,
  getLastUser,
  getUserBySignerSlot,
  hasPasskeyCredential,
  activateAuthenticatedWalletState,
  nearAuthenticatorsByAccount,
  rollbackUserRegistration,
  setLastUser,
  storeAuthenticator,
  storeUserData,
  storeWalletEd25519RegistrationData,
  storeWalletEd25519RecoveryRegistrationData,
  finalizeWalletEd25519SignerRegistration,
  rollbackWalletEd25519SignerRegistration,
  storeWalletEmailOtpEd25519RegistrationData,
  storeWalletEmailOtpMixedRegistrationData,
  type StoredRegistrationData,
  type StoredWalletEd25519SignerRegistration,
  type StoreAuthenticatorInput,
  type StoreWalletEd25519RegistrationInput,
  type StoreWalletEd25519SignerRecordInput,
  type StoreWalletEmailOtpEd25519RegistrationInput,
  type StoreWalletEmailOtpMixedRegistrationInput,
  type StoreWalletEmailOtpMixedRegistrationResult,
} from '@/core/signingEngine/flows/registration/accountLifecycle';
import type { StoreWalletSignerFinalizeRollbackReceipt } from '@/core/indexedDB/seamsWalletDB/repositories';

export type ActivateAuthenticatedWalletStateInput = {
  walletId: WalletId;
  nearAccountId: AccountId;
  signerSlot: number;
  nearClient?: NearClient;
};

export type RegistrationAccountsService = {
  storeUserData(userData: StoreUserDataInput): Promise<void>;
  getAllUsers(): Promise<ClientUserData[]>;
  getUserBySignerSlot(nearAccountId: AccountId, signerSlot: number): Promise<ClientUserData | null>;
  getLastUser(): Promise<ClientUserData | null>;
  nearAuthenticatorsByAccount(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]>;
  setLastUser(walletId: WalletId, signerSlot: number): Promise<void>;
  activateAuthenticatedWalletState(input: ActivateAuthenticatedWalletStateInput): Promise<void>;
  storeAuthenticator(authenticatorData: StoreAuthenticatorInput): Promise<void>;
  rollbackUserRegistration(nearAccountId: AccountId): Promise<void>;
  hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean>;
  storeWalletEd25519RegistrationData(
    input: StoreWalletEd25519RegistrationInput,
  ): Promise<StoredRegistrationData>;
  storeWalletEd25519RecoveryRegistrationData(
    input: StoreWalletEd25519RegistrationInput,
  ): Promise<StoredRegistrationData>;
  storeWalletEmailOtpEd25519RegistrationData(
    input: StoreWalletEmailOtpEd25519RegistrationInput,
  ): Promise<StoredRegistrationData>;
  storeWalletEmailOtpMixedRegistrationData(
    input: StoreWalletEmailOtpMixedRegistrationInput,
  ): Promise<StoreWalletEmailOtpMixedRegistrationResult>;
  finalizeWalletEd25519SignerRegistration(
    input: StoreWalletEd25519SignerRecordInput,
  ): Promise<StoredWalletEd25519SignerRegistration>;
  rollbackWalletEd25519SignerRegistration(
    receipt: StoreWalletSignerFinalizeRollbackReceipt,
  ): Promise<void>;
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
    setLastUser: (walletId, signerSlot) => setLastUser(accountLifecycle, walletId, signerSlot),
    activateAuthenticatedWalletState: (input) =>
      activateAuthenticatedWalletState(accountLifecycle, input),
    storeAuthenticator: (authenticatorData) =>
      storeAuthenticator(accountLifecycle, authenticatorData),
    rollbackUserRegistration: (nearAccountId) =>
      rollbackUserRegistration(accountLifecycle, nearAccountId),
    hasPasskeyCredential: (nearAccountId) => hasPasskeyCredential(accountLifecycle, nearAccountId),
    storeWalletEd25519RegistrationData: (input) =>
      storeWalletEd25519RegistrationData(accountLifecycle, input),
    storeWalletEd25519RecoveryRegistrationData: (input) =>
      storeWalletEd25519RecoveryRegistrationData(accountLifecycle, input),
    storeWalletEmailOtpEd25519RegistrationData: (input) =>
      storeWalletEmailOtpEd25519RegistrationData(accountLifecycle, input),
    storeWalletEmailOtpMixedRegistrationData: (input) =>
      storeWalletEmailOtpMixedRegistrationData(accountLifecycle, input),
    finalizeWalletEd25519SignerRegistration: (input) =>
      finalizeWalletEd25519SignerRegistration(accountLifecycle, input),
    rollbackWalletEd25519SignerRegistration: (receipt) =>
      rollbackWalletEd25519SignerRegistration(accountLifecycle, receipt),
  };
}
