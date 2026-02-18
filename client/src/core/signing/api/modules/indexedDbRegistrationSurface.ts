import type {
  ChainAccountRecord,
  AccountSignerRecord,
  SignerOpOutboxRecord,
  ProfileRecord,
  ClientUserData,
  ClientAuthenticatorData,
  AccountSignerStatus,
  UpsertProfileInput,
  UpsertChainAccountInput,
  UpsertAccountSignerInput,
  EnqueueSignerOperationInput,
} from '../../../IndexedDBManager';
import type { StoreUserDataInput } from '../../../IndexedDBManager/passkeyClientDB';
import type { NearClient } from '../../../near/NearClient';
import type { AccountId } from '../../../types/accountIds';
import type { WebAuthnRegistrationCredential } from '../../../types';
import {
  enqueueSignerOperation as enqueueSignerOperationValue,
  getAllUsers as getAllUsersValue,
  getAuthenticatorsByUser as getAuthenticatorsByUserValue,
  getLastUser as getLastUserValue,
  getProfile as getProfileValue,
  getProfileByAccount as getProfileByAccountValue,
  getUserByDevice as getUserByDeviceValue,
  listAccountSigners as listAccountSignersValue,
  setAccountSignerStatus as setAccountSignerStatusValue,
  setLastUser as setLastUserValue,
  updateLastLogin as updateLastLoginValue,
  upsertAccountSigner as upsertAccountSignerValue,
  upsertChainAccount as upsertChainAccountValue,
  upsertProfile as upsertProfileValue,
  type IndexedDbFacadeDeps,
} from '../indexedDbFacade';
import {
  atomicOperation as atomicOperationValue,
  atomicStoreRegistrationData as atomicStoreRegistrationDataValue,
  extractUsername as extractUsernameValue,
  hasPasskeyCredential as hasPasskeyCredentialValue,
  initializeCurrentUser as initializeCurrentUserValue,
  registerUser as registerUserValue,
  rollbackUserRegistration as rollbackUserRegistrationValue,
  storeAuthenticator as storeAuthenticatorValue,
  storeUserData as storeUserDataValue,
  type RegistrationAccountLifecycleDeps,
  type StoreAuthenticatorInput,
} from '../registrationAccountLifecycle';

export type IndexedDbRegistrationSurfaceDeps = {
  indexedDbFacadeDeps: IndexedDbFacadeDeps;
  registrationAccountLifecycleDeps: RegistrationAccountLifecycleDeps;
};

export type IndexedDbRegistrationSurface = {
  storeUserData(userData: StoreUserDataInput): Promise<void>;
  getProfile(profileId: string): Promise<ProfileRecord | null>;
  upsertProfile(input: UpsertProfileInput): Promise<ProfileRecord>;
  upsertChainAccount(input: UpsertChainAccountInput): Promise<ChainAccountRecord>;
  getProfileByAccount(chainId: string, accountAddress: string): Promise<ProfileRecord | null>;
  upsertAccountSigner(input: UpsertAccountSignerInput): Promise<AccountSignerRecord>;
  listAccountSigners(args: {
    chainId: string;
    accountAddress: string;
    status?: AccountSignerStatus;
  }): Promise<AccountSignerRecord[]>;
  setAccountSignerStatus(args: {
    chainId: string;
    accountAddress: string;
    signerId: string;
    status: AccountSignerStatus;
    removedAt?: number;
  }): Promise<AccountSignerRecord | null>;
  enqueueSignerOperation(input: EnqueueSignerOperationInput): Promise<SignerOpOutboxRecord>;
  getAllUsers(): Promise<ClientUserData[]>;
  getUserByDevice(nearAccountId: AccountId, deviceNumber: number): Promise<ClientUserData | null>;
  getLastUser(): Promise<ClientUserData | null>;
  getAuthenticatorsByUser(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]>;
  updateLastLogin(nearAccountId: AccountId): Promise<void>;
  setLastUser(nearAccountId: AccountId, deviceNumber?: number): Promise<void>;
  initializeCurrentUser(nearAccountId: AccountId, nearClient?: NearClient): Promise<void>;
  registerUser(storeUserData: StoreUserDataInput): Promise<ClientUserData>;
  storeAuthenticator(authenticatorData: StoreAuthenticatorInput): Promise<void>;
  extractUsername(nearAccountId: AccountId): string;
  atomicOperation<T>(callback: (db: any) => Promise<T>): Promise<T>;
  rollbackUserRegistration(nearAccountId: AccountId): Promise<void>;
  hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean>;
  atomicStoreRegistrationData(args: {
    nearAccountId: AccountId;
    credential: WebAuthnRegistrationCredential;
    publicKey: string;
  }): Promise<void>;
};

export function createIndexedDbRegistrationSurface(
  deps: IndexedDbRegistrationSurfaceDeps,
): IndexedDbRegistrationSurface {
  return {
    async storeUserData(userData: StoreUserDataInput): Promise<void> {
      await storeUserDataValue(deps.registrationAccountLifecycleDeps, userData);
    },
    async getProfile(profileId: string): Promise<ProfileRecord | null> {
      return await getProfileValue(deps.indexedDbFacadeDeps, profileId);
    },
    async upsertProfile(input: UpsertProfileInput): Promise<ProfileRecord> {
      return await upsertProfileValue(deps.indexedDbFacadeDeps, input);
    },
    async upsertChainAccount(input: UpsertChainAccountInput): Promise<ChainAccountRecord> {
      return await upsertChainAccountValue(deps.indexedDbFacadeDeps, input);
    },
    async getProfileByAccount(
      chainId: string,
      accountAddress: string,
    ): Promise<ProfileRecord | null> {
      return await getProfileByAccountValue(deps.indexedDbFacadeDeps, chainId, accountAddress);
    },
    async upsertAccountSigner(input: UpsertAccountSignerInput): Promise<AccountSignerRecord> {
      return await upsertAccountSignerValue(deps.indexedDbFacadeDeps, input);
    },
    async listAccountSigners(args: {
      chainId: string;
      accountAddress: string;
      status?: AccountSignerStatus;
    }): Promise<AccountSignerRecord[]> {
      return await listAccountSignersValue(deps.indexedDbFacadeDeps, args);
    },
    async setAccountSignerStatus(args: {
      chainId: string;
      accountAddress: string;
      signerId: string;
      status: AccountSignerStatus;
      removedAt?: number;
    }): Promise<AccountSignerRecord | null> {
      return await setAccountSignerStatusValue(deps.indexedDbFacadeDeps, args);
    },
    async enqueueSignerOperation(
      input: EnqueueSignerOperationInput,
    ): Promise<SignerOpOutboxRecord> {
      return await enqueueSignerOperationValue(deps.indexedDbFacadeDeps, input);
    },
    async getAllUsers(): Promise<ClientUserData[]> {
      return await getAllUsersValue(deps.indexedDbFacadeDeps);
    },
    async getUserByDevice(
      nearAccountId: AccountId,
      deviceNumber: number,
    ): Promise<ClientUserData | null> {
      return await getUserByDeviceValue(
        deps.indexedDbFacadeDeps,
        nearAccountId,
        deviceNumber,
      );
    },
    async getLastUser(): Promise<ClientUserData | null> {
      return await getLastUserValue(deps.indexedDbFacadeDeps);
    },
    async getAuthenticatorsByUser(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]> {
      return await getAuthenticatorsByUserValue(deps.indexedDbFacadeDeps, nearAccountId);
    },
    async updateLastLogin(nearAccountId: AccountId): Promise<void> {
      await updateLastLoginValue(deps.indexedDbFacadeDeps, nearAccountId);
    },
    async setLastUser(nearAccountId: AccountId, deviceNumber: number = 1): Promise<void> {
      await setLastUserValue(deps.indexedDbFacadeDeps, nearAccountId, deviceNumber);
    },
    async initializeCurrentUser(
      nearAccountId: AccountId,
      nearClient?: NearClient,
    ): Promise<void> {
      await initializeCurrentUserValue(deps.registrationAccountLifecycleDeps, {
        nearAccountId,
        nearClient,
      });
    },
    async registerUser(storeUserData: StoreUserDataInput): Promise<ClientUserData> {
      return await registerUserValue(deps.registrationAccountLifecycleDeps, storeUserData);
    },
    async storeAuthenticator(authenticatorData: StoreAuthenticatorInput): Promise<void> {
      await storeAuthenticatorValue(deps.registrationAccountLifecycleDeps, authenticatorData);
    },
    extractUsername(nearAccountId: AccountId): string {
      return extractUsernameValue(nearAccountId);
    },
    async atomicOperation<T>(callback: (db: any) => Promise<T>): Promise<T> {
      return await atomicOperationValue(deps.registrationAccountLifecycleDeps, callback);
    },
    async rollbackUserRegistration(nearAccountId: AccountId): Promise<void> {
      await rollbackUserRegistrationValue(deps.registrationAccountLifecycleDeps, nearAccountId);
    },
    async hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean> {
      return await hasPasskeyCredentialValue(deps.registrationAccountLifecycleDeps, nearAccountId);
    },
    async atomicStoreRegistrationData(args: {
      nearAccountId: AccountId;
      credential: WebAuthnRegistrationCredential;
      publicKey: string;
    }): Promise<void> {
      await atomicStoreRegistrationDataValue(deps.registrationAccountLifecycleDeps, args);
    },
  };
}

export type { StoreAuthenticatorInput } from '../registrationAccountLifecycle';
