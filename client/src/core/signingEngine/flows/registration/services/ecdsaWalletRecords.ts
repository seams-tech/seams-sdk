import type {
  RegistrationAccountLifecycleDeps,
} from '@/core/signingEngine/interfaces/operationDeps';
import {
  storeWalletEmailOtpEcdsaRegistrationData,
  storeWalletEmailOtpEcdsaSignerRecords,
  storeWalletEcdsaRegistrationData,
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
  storeWalletEcdsaRegistrationData(
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
    storeWalletEcdsaRegistrationData: (input) =>
      storeWalletEcdsaRegistrationData(deps.accountLifecycle, input),
    storeWalletEmailOtpEcdsaRegistrationData: (input) =>
      storeWalletEmailOtpEcdsaRegistrationData(deps.accountLifecycle, input),
  };
}
