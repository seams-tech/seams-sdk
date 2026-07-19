import type {
  StoreWalletEcdsaWalletKey,
  StoreWalletEmailOtpEd25519RegistrationInput,
  StoreWalletEmailOtpMixedRegistrationInput,
  StoreWalletEmailOtpMixedRegistrationResult,
  StoreWalletMixedRegistrationResult,
} from './accountLifecycle';
import type { ActivateAuthenticatedWalletStateInput } from './services/registrationAccounts';
import type { StoreUserDataInput } from '@/core/accountData/near/nearAccountData.types';

declare const emailOtpEd25519Input: StoreWalletEmailOtpEd25519RegistrationInput;
declare const walletKeys: readonly StoreWalletEcdsaWalletKey[];
declare const walletKey: StoreWalletEcdsaWalletKey;

const validEmailOtpMixedInput = {
  ...emailOtpEd25519Input,
  walletKeys,
} satisfies StoreWalletEmailOtpMixedRegistrationInput;

void validEmailOtpMixedInput;

const walletKeyWithoutPublicCapability = {
  keyScope: walletKey.keyScope,
  chainTarget: walletKey.chainTarget,
  walletId: walletKey.walletId,
  evmFamilySigningKeySlotId: walletKey.evmFamilySigningKeySlotId,
  keyHandle: walletKey.keyHandle,
  ecdsaThresholdKeyId: walletKey.ecdsaThresholdKeyId,
  signingRootId: walletKey.signingRootId,
  signingRootVersion: walletKey.signingRootVersion,
  thresholdEcdsaPublicKeyB64u: walletKey.thresholdEcdsaPublicKeyB64u,
  thresholdOwnerAddress: walletKey.thresholdOwnerAddress,
  relayerKeyId: walletKey.relayerKeyId,
  relayerVerifyingShareB64u: walletKey.relayerVerifyingShareB64u,
  participantIds: walletKey.participantIds,
};
// @ts-expect-error Persisted ECDSA signer metadata requires its public capability.
walletKeyWithoutPublicCapability satisfies StoreWalletEcdsaWalletKey;

const missingWalletKeys = { ...emailOtpEd25519Input };
// @ts-expect-error mixed registration requires the ECDSA wallet-key inventory.
missingWalletKeys satisfies StoreWalletEmailOtpMixedRegistrationInput;

const passkeyCredentialLeak = {
  ...validEmailOtpMixedInput,
  credential: { id: 'passkey-credential' },
};
// @ts-expect-error Email OTP mixed persistence rejects passkey registration state after broad spreads.
passkeyCredentialLeak satisfies StoreWalletEmailOtpMixedRegistrationInput;

declare const emailOtpMixedResult: StoreWalletEmailOtpMixedRegistrationResult;
const sharedMixedResultShape: StoreWalletMixedRegistrationResult = emailOtpMixedResult;
void sharedMixedResultShape;

declare const authenticatedWalletActivation: ActivateAuthenticatedWalletStateInput;
const activationWithoutSignerSlot = {
  walletId: authenticatedWalletActivation.walletId,
  nearAccountId: authenticatedWalletActivation.nearAccountId,
};
// @ts-expect-error authenticated wallet activation requires the backend-validated signer slot.
activationWithoutSignerSlot satisfies ActivateAuthenticatedWalletStateInput;

declare const storedUserInput: StoreUserDataInput;
const storedUserWithoutSignerSlot = {
  walletId: storedUserInput.walletId,
  nearAccountId: storedUserInput.nearAccountId,
  operationalPublicKey: storedUserInput.operationalPublicKey,
  passkeyCredential: storedUserInput.passkeyCredential,
};
// @ts-expect-error local signer projections require the server-assigned signer slot.
storedUserWithoutSignerSlot satisfies StoreUserDataInput;
