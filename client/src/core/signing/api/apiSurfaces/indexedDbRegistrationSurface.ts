import type {
  ClientAuthenticatorData,
  ClientUserData,
  UnifiedIndexedDBManager,
} from '@/core/IndexedDBManager';
import type { StoreUserDataInput } from '@/core/IndexedDBManager/passkeyClientDB.types';
import type { NearClient } from '@/core/near/NearClient';
import type { AccountId } from '@/core/types/accountIds';
import type { WebAuthnRegistrationCredential } from '@/core/types';
import {
  atomicStoreRegistrationData as atomicStoreRegistrationDataValue,
  hasPasskeyCredential as hasPasskeyCredentialValue,
  initializeCurrentUser as initializeCurrentUserValue,
  rollbackUserRegistration as rollbackUserRegistrationValue,
  storeAuthenticator as storeAuthenticatorValue,
  storeUserData as storeUserDataValue,
  type RegistrationAccountLifecycleDeps,
  type StoreAuthenticatorInput,
} from '../registration/registrationAccountLifecycle';

export type IndexedDbRegistrationSurfaceDeps = {
  indexedDB: UnifiedIndexedDBManager;
  registrationAccountLifecycleDeps: RegistrationAccountLifecycleDeps;
};

export type IndexedDbRegistrationSurface = {
  storeUserData(userData: StoreUserDataInput): Promise<void>;
  getAllUsers(): Promise<ClientUserData[]>;
  getUserByDevice(nearAccountId: AccountId, deviceNumber: number): Promise<ClientUserData | null>;
  getLastUser(): Promise<ClientUserData | null>;
  getAuthenticatorsByUser(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]>;
  updateLastLogin(nearAccountId: AccountId): Promise<void>;
  setLastUser(nearAccountId: AccountId, deviceNumber?: number): Promise<void>;
  initializeCurrentUser(nearAccountId: AccountId, nearClient?: NearClient): Promise<void>;
  storeAuthenticator(authenticatorData: StoreAuthenticatorInput): Promise<void>;
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
    storeUserData: (userData: StoreUserDataInput): Promise<void> =>
      storeUserDataValue(deps.registrationAccountLifecycleDeps, userData),
    getAllUsers: (): Promise<ClientUserData[]> =>
      deps.indexedDB.clientDB.listNearAccountProjections(),
    getUserByDevice: (
      nearAccountId: AccountId,
      deviceNumber: number,
    ): Promise<ClientUserData | null> =>
      deps.indexedDB.clientDB.getNearAccountProjection(nearAccountId, deviceNumber),
    getLastUser: (): Promise<ClientUserData | null> =>
      deps.indexedDB.clientDB.getLastSelectedNearAccountProjection(),
    getAuthenticatorsByUser: (nearAccountId: AccountId): Promise<ClientAuthenticatorData[]> =>
      deps.indexedDB.clientDB.listNearAuthenticators(nearAccountId),
    updateLastLogin: (nearAccountId: AccountId): Promise<void> =>
      deps.indexedDB.clientDB.touchLastLoginForNearAccount(nearAccountId),
    setLastUser: (nearAccountId: AccountId, deviceNumber: number = 1): Promise<void> =>
      deps.indexedDB.clientDB.setLastProfileStateForNearAccount(nearAccountId, deviceNumber),
    initializeCurrentUser: (
      nearAccountId: AccountId,
      nearClient?: NearClient,
    ): Promise<void> =>
      initializeCurrentUserValue(deps.registrationAccountLifecycleDeps, {
        nearAccountId,
        nearClient,
      }),
    storeAuthenticator: (authenticatorData: StoreAuthenticatorInput): Promise<void> =>
      storeAuthenticatorValue(deps.registrationAccountLifecycleDeps, authenticatorData),
    rollbackUserRegistration: (nearAccountId: AccountId): Promise<void> =>
      rollbackUserRegistrationValue(deps.registrationAccountLifecycleDeps, nearAccountId),
    hasPasskeyCredential: (nearAccountId: AccountId): Promise<boolean> =>
      hasPasskeyCredentialValue(deps.registrationAccountLifecycleDeps, nearAccountId),
    atomicStoreRegistrationData: (args: {
      nearAccountId: AccountId;
      credential: WebAuthnRegistrationCredential;
      publicKey: string;
    }): Promise<void> =>
      atomicStoreRegistrationDataValue(deps.registrationAccountLifecycleDeps, args),
  };
}

export type { StoreAuthenticatorInput } from '../registration/registrationAccountLifecycle';
