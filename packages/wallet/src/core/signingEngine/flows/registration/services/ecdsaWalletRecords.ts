import type { RegistrationAccountLifecycleDeps } from '@/core/signingEngine/interfaces/operationDeps';
import {
  storeWalletEmailOtpEcdsaRegistrationData,
  storeWalletEmailOtpEcdsaSignerRecords,
  storeWalletEcdsaRecoverySignerRecords,
  finalizeWalletEcdsaRegistration,
  storeWalletEcdsaSignerRecords,
  type StoreWalletEcdsaRegistrationInput,
  type StoreWalletEcdsaSignerRecordsInput,
  type StoreWalletEcdsaSignerRecordsResult,
  type StoreWalletEmailOtpEcdsaRegistrationInput,
} from '@/core/signingEngine/flows/registration/accountLifecycle';

export type EcdsaWalletRecordsService = {
  storeWalletEcdsaSignerRecords(
    input: StoreWalletEcdsaSignerRecordsInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult>;
  storeWalletEmailOtpEcdsaSignerRecords(
    input: StoreWalletEcdsaSignerRecordsInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult>;
  storeWalletEcdsaRecoverySignerRecords(
    input: StoreWalletEcdsaSignerRecordsInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult>;
  finalizeWalletEcdsaRegistration(
    input: StoreWalletEcdsaRegistrationInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult>;
  storeWalletEmailOtpEcdsaRegistrationData(
    input: StoreWalletEmailOtpEcdsaRegistrationInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult>;
};

export function createEcdsaWalletRecordsService(deps: {
  accountLifecycle: RegistrationAccountLifecycleDeps;
}): EcdsaWalletRecordsService {
  return {
    storeWalletEcdsaSignerRecords: (input) =>
      storeWalletEcdsaSignerRecords(deps.accountLifecycle, input),
    storeWalletEmailOtpEcdsaSignerRecords: (input) =>
      storeWalletEmailOtpEcdsaSignerRecords(deps.accountLifecycle, input),
    storeWalletEcdsaRecoverySignerRecords: (input) =>
      storeWalletEcdsaRecoverySignerRecords(deps.accountLifecycle, input),
    finalizeWalletEcdsaRegistration: (input) =>
      finalizeWalletEcdsaRegistration(deps.accountLifecycle, input),
    storeWalletEmailOtpEcdsaRegistrationData: (input) =>
      storeWalletEmailOtpEcdsaRegistrationData(deps.accountLifecycle, input),
  };
}
