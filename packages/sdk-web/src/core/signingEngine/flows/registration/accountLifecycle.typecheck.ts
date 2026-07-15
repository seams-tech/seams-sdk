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

const validEmailOtpMixedInput = {
  ...emailOtpEd25519Input,
  walletKeys,
} satisfies StoreWalletEmailOtpMixedRegistrationInput;

void validEmailOtpMixedInput;

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
