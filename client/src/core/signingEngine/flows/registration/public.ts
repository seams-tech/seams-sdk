import type {
  ClientAuthenticatorData,
  ClientUserData,
  StoreUserDataInput,
} from '@/core/accountData/near/types';
import type { AccountId } from '@/core/types/accountIds';
import type { WebAuthnAuthenticationCredential, WebAuthnRegistrationCredential } from '@/core/types';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { RegistrationCredentialConfirmationPayload } from '../../workerManager/validation';
import type { WebAuthnAllowCredential } from '../../walletAuth/webauthn/credentials/collectAuthenticationCredentialForChallengeB64u';
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
  storeAuthenticator as storeAuthenticatorValue,
  storeUserData as storeUserDataValue,
  updateLastLogin as updateLastLoginValue,
  type StoreAuthenticatorInput,
} from './accountLifecycle';
import {
  getAuthenticationCredentialsSerialized as getAuthenticationCredentialsSerializedValue,
  requestRegistrationSessionCredentialConfirmation as requestRegistrationCredentialConfirmationValue,
} from './session';

export type { StoreAuthenticatorInput };

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
): Promise<void> {
  return atomicStoreRegistrationDataValue(deps.accountLifecycle, args);
}

export function requestRegistrationCredentialConfirmation(
  deps: RegistrationPublicDeps,
  params: {
    nearAccountId: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
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
