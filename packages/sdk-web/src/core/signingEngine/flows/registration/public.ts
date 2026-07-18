import type {
  ClientAuthenticatorData,
  ClientUserData,
  StoreUserDataInput,
} from '@/core/accountData/near/nearAccountData.types';
import type { AccountId } from '@/core/types/accountIds';
import type { WalletId } from '@shared/utils/registrationIntent';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { RegistrationCredentialConfirmationPayload } from '../../workerManager/validation';
import type { WebAuthnAllowCredential } from '../../webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type {
  RegistrationAccountLifecycleDeps,
  RegistrationSessionDeps,
} from '../../interfaces/operationDeps';
import {
  atomicStoreRegistrationData as atomicStoreRegistrationDataValue,
  getAllUsers as getAllUsersValue,
  getLastUser as getLastUserValue,
  getUserBySignerSlot as getUserBySignerSlotValue,
  hasPasskeyCredential as hasPasskeyCredentialValue,
  activateAuthenticatedWalletState as activateAuthenticatedWalletStateValue,
  nearAuthenticatorsByAccount as nearAuthenticatorsByAccountValue,
  rollbackUserRegistration as rollbackUserRegistrationValue,
  setLastUser as setLastUserValue,
  finalizeWalletEd25519SignerRegistration as finalizeWalletEd25519SignerRegistrationValue,
  rollbackWalletEd25519SignerRegistration as rollbackWalletEd25519SignerRegistrationValue,
  storeWalletEd25519RegistrationData as storeWalletEd25519RegistrationDataValue,
  storeWalletMixedRegistrationData as storeWalletMixedRegistrationDataValue,
  storeWalletEd25519RecoveryRegistrationData as storeWalletEd25519RecoveryRegistrationDataValue,
  storeWalletEmailOtpEd25519RegistrationData as storeWalletEmailOtpEd25519RegistrationDataValue,
  storeWalletEmailOtpMixedRegistrationData as storeWalletEmailOtpMixedRegistrationDataValue,
  storeWalletEmailOtpEcdsaRegistrationData as storeWalletEmailOtpEcdsaRegistrationDataValue,
  storeWalletEmailOtpEcdsaSignerRecords as storeWalletEmailOtpEcdsaSignerRecordsValue,
  storeWalletEcdsaRecoverySignerRecords as storeWalletEcdsaRecoverySignerRecordsValue,
  finalizeWalletEcdsaRegistration as finalizeWalletEcdsaRegistrationValue,
  storeWalletEcdsaSignerRecords as storeWalletEcdsaSignerRecordsValue,
  storeAuthenticator as storeAuthenticatorValue,
  storeUserData as storeUserDataValue,
  type StoredRegistrationData,
  type StoredWalletEd25519SignerRegistration,
  type StoreWalletEcdsaSignerRecordsInput,
  type StoreWalletEcdsaRegistrationInput,
  type StoreWalletEcdsaSignerRecordsResult,
  type StoreWalletEmailOtpEd25519RegistrationInput,
  type StoreWalletEmailOtpMixedRegistrationInput,
  type StoreWalletEmailOtpMixedRegistrationResult,
  type StoreWalletEmailOtpEcdsaRegistrationInput,
  type StoreWalletEd25519RegistrationInput,
  type StoreWalletEd25519SignerRecordInput,
  type StoreWalletMixedRegistrationInput,
  type StoreWalletMixedRegistrationResult,
  type StoreAuthenticatorInput,
} from './accountLifecycle';
import type { StoreWalletSignerFinalizeRollbackReceipt } from '@/core/indexedDB/seamsWalletDB/repositories';
import {
  getAuthenticationCredentialsSerialized as getAuthenticationCredentialsSerializedValue,
  requestRegistrationSessionCredentialConfirmation as requestRegistrationCredentialConfirmationValue,
} from './session';

export type { StoreAuthenticatorInput };
export type { StoredRegistrationData };
export type {
  StoreWalletEcdsaSignerRecordsInput,
  StoreWalletEcdsaRegistrationInput,
  StoreWalletEcdsaSignerRecordsResult,
  StoreWalletEmailOtpEd25519RegistrationInput,
  StoreWalletEmailOtpMixedRegistrationInput,
  StoreWalletEmailOtpMixedRegistrationResult,
  StoreWalletEmailOtpEcdsaRegistrationInput,
  StoreWalletEd25519RegistrationInput,
  StoreWalletEd25519SignerRecordInput,
  StoreWalletMixedRegistrationInput,
  StoreWalletMixedRegistrationResult,
};

export type RegistrationPublicDeps = {
  accountLifecycle: RegistrationAccountLifecycleDeps;
  session: RegistrationSessionDeps;
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

export function nearAuthenticatorsByAccount(
  deps: RegistrationPublicDeps,
  nearAccountId: AccountId,
): Promise<ClientAuthenticatorData[]> {
  return nearAuthenticatorsByAccountValue(deps.accountLifecycle, nearAccountId);
}

export function setLastUser(
  deps: RegistrationPublicDeps,
  walletId: WalletId,
  signerSlot: number,
): Promise<void> {
  return setLastUserValue(deps.accountLifecycle, walletId, signerSlot);
}

export function activateAuthenticatedWalletState(
  deps: RegistrationPublicDeps,
  args: {
    walletId: WalletId;
    nearAccountId: AccountId;
    signerSlot: number;
    nearClient?: NearClient;
  },
): Promise<void> {
  return activateAuthenticatedWalletStateValue(deps.accountLifecycle, args);
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
    walletId: WalletId;
    nearAccountId: AccountId;
    credential: WebAuthnRegistrationCredential;
    credentialPublicKeyB64u: string;
    operationalPublicKey: string;
  },
): Promise<StoredRegistrationData> {
  return atomicStoreRegistrationDataValue(deps.accountLifecycle, args);
}

export function storeWalletEd25519RegistrationData(
  deps: RegistrationPublicDeps,
  args: StoreWalletEd25519RegistrationInput,
): Promise<StoredRegistrationData> {
  return storeWalletEd25519RegistrationDataValue(deps.accountLifecycle, args);
}

export function storeWalletMixedRegistrationData(
  deps: RegistrationPublicDeps,
  args: StoreWalletMixedRegistrationInput,
): Promise<StoreWalletMixedRegistrationResult> {
  return storeWalletMixedRegistrationDataValue(deps.accountLifecycle, args);
}

export function storeWalletEd25519RecoveryRegistrationData(
  deps: RegistrationPublicDeps,
  args: StoreWalletEd25519RegistrationInput,
): Promise<StoredRegistrationData> {
  return storeWalletEd25519RecoveryRegistrationDataValue(deps.accountLifecycle, args);
}

export function storeWalletEmailOtpEd25519RegistrationData(
  deps: RegistrationPublicDeps,
  args: StoreWalletEmailOtpEd25519RegistrationInput,
): Promise<StoredRegistrationData> {
  return storeWalletEmailOtpEd25519RegistrationDataValue(deps.accountLifecycle, args);
}

export function storeWalletEmailOtpMixedRegistrationData(
  deps: RegistrationPublicDeps,
  args: StoreWalletEmailOtpMixedRegistrationInput,
): Promise<StoreWalletEmailOtpMixedRegistrationResult> {
  return storeWalletEmailOtpMixedRegistrationDataValue(deps.accountLifecycle, args);
}

export function finalizeWalletEd25519SignerRegistration(
  deps: RegistrationPublicDeps,
  args: StoreWalletEd25519SignerRecordInput,
): Promise<StoredWalletEd25519SignerRegistration> {
  return finalizeWalletEd25519SignerRegistrationValue(deps.accountLifecycle, args);
}

export function rollbackWalletEd25519SignerRegistration(
  deps: RegistrationPublicDeps,
  receipt: StoreWalletSignerFinalizeRollbackReceipt,
): Promise<void> {
  return rollbackWalletEd25519SignerRegistrationValue(deps.accountLifecycle, receipt);
}

export function storeWalletEcdsaSignerRecords(
  deps: RegistrationPublicDeps,
  args: StoreWalletEcdsaSignerRecordsInput,
): Promise<StoreWalletEcdsaSignerRecordsResult> {
  return storeWalletEcdsaSignerRecordsValue(deps.accountLifecycle, args);
}

export function storeWalletEcdsaRecoverySignerRecords(
  deps: RegistrationPublicDeps,
  args: StoreWalletEcdsaSignerRecordsInput,
): Promise<StoreWalletEcdsaSignerRecordsResult> {
  return storeWalletEcdsaRecoverySignerRecordsValue(deps.accountLifecycle, args);
}

export function storeWalletEmailOtpEcdsaSignerRecords(
  deps: RegistrationPublicDeps,
  args: StoreWalletEcdsaSignerRecordsInput,
): Promise<StoreWalletEcdsaSignerRecordsResult> {
  return storeWalletEmailOtpEcdsaSignerRecordsValue(deps.accountLifecycle, args);
}

export function finalizeWalletEcdsaRegistration(
  deps: RegistrationPublicDeps,
  args: StoreWalletEcdsaRegistrationInput,
): Promise<StoreWalletEcdsaSignerRecordsResult> {
  return finalizeWalletEcdsaRegistrationValue(deps.accountLifecycle, args);
}

export function storeWalletEmailOtpEcdsaRegistrationData(
  deps: RegistrationPublicDeps,
  args: StoreWalletEmailOtpEcdsaRegistrationInput,
): Promise<StoreWalletEcdsaSignerRecordsResult> {
  return storeWalletEmailOtpEcdsaRegistrationDataValue(deps.accountLifecycle, args);
}

export function requestRegistrationCredentialConfirmation(
  deps: RegistrationPublicDeps,
  params: {
    walletId: string;
    nearAccountId?: string;
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
    subjectId: string;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  },
): Promise<WebAuthnAuthenticationCredential> {
  return getAuthenticationCredentialsSerializedValue(deps.session, args);
}
