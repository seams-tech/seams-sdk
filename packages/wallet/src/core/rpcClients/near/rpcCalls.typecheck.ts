import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';
import type { RouterAbEcdsaPostRegistrationSessionActivationPolicyV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type {
  PasskeyWalletUnlockEd25519Session,
  PasskeyWalletUnlockInputWithCombinedActivation,
  PasskeyWalletUnlockInputWithEcdsaActivation,
  PasskeyWalletUnlockInputWithEcdsaOnlyActivation,
  WalletUnlockSuccessWithCombinedActivation,
  WalletUnlockSuccessWithEcdsaOnlyActivation,
} from './rpcCalls';
import { verifyPasskeyWalletUnlock } from './rpcCalls';

declare const credential: WebAuthnAuthenticationCredential;
declare const activationPolicy: RouterAbEcdsaPostRegistrationSessionActivationPolicyV1;
declare const ed25519Session: PasskeyWalletUnlockEd25519Session;

if (ed25519Session.sessionKind === 'issued_exact_wallet_session') {
  ed25519Session.operationCredential.token satisfies string;
} else {
  ed25519Session.operationCredential.token satisfies string;
}

const ecdsaOnlyInput: PasskeyWalletUnlockInputWithEcdsaOnlyActivation = {
  type: 'passkey_assertion',
  challengeId: 'challenge-1',
  webauthn_authentication: credential,
  ed25519SessionRequest: { kind: 'not_requested' },
  ecdsaSessionPolicy: activationPolicy,
  walletId: 'wallet.testnet',
};

const ecdsaOnlyUnlock = verifyPasskeyWalletUnlock('https://relay.example', ecdsaOnlyInput);

void ecdsaOnlyUnlock.then((result) => {
  if (result.success) {
    result.ecdsaSession.session.operation_credential.token satisfies string;
    result.ed25519Session satisfies null;
  }
});

const combinedInput: PasskeyWalletUnlockInputWithCombinedActivation = {
  type: 'passkey_assertion',
  challengeId: 'challenge-1',
  webauthn_authentication: credential,
  ed25519SessionRequest: { kind: 'requested', remainingUses: 8 },
  ecdsaSessionPolicy: activationPolicy,
  walletId: 'wallet.testnet',
};

const combinedUnlock = verifyPasskeyWalletUnlock('https://relay.example', combinedInput);

void combinedUnlock.then((result) => {
  if (result.success) {
    result.ecdsaSession.authorization.operationCredential.token satisfies string;
    result.ed25519Session.operationCredential.token satisfies string;
  }
});

declare const combinedSuccess: WalletUnlockSuccessWithCombinedActivation;
declare const ecdsaOnlySuccess: WalletUnlockSuccessWithEcdsaOnlyActivation;

const invalidCombinedWithoutEd25519: WalletUnlockSuccessWithCombinedActivation = {
  ...combinedSuccess,
  // @ts-expect-error Combined activation requires an Ed25519 session.
  ed25519Session: null,
};

const invalidCombinedDirectActivation: WalletUnlockSuccessWithCombinedActivation = {
  ...combinedSuccess,
  // @ts-expect-error Combined activation requires credential-free ECDSA authorization.
  ecdsaSession: ecdsaOnlySuccess.ecdsaSession,
};

const invalidEcdsaOnlyWithEd25519: WalletUnlockSuccessWithEcdsaOnlyActivation = {
  ...ecdsaOnlySuccess,
  // @ts-expect-error ECDSA-only activation cannot carry an Ed25519 session.
  ed25519Session: combinedSuccess.ed25519Session,
};

const invalidEcdsaOnlyCredentialFree: WalletUnlockSuccessWithEcdsaOnlyActivation = {
  ...ecdsaOnlySuccess,
  // @ts-expect-error ECDSA-only activation requires the direct response branch.
  ecdsaSession: combinedSuccess.ecdsaSession,
};

// @ts-expect-error Combined input requires an Ed25519 session request.
const invalidCombinedInput: PasskeyWalletUnlockInputWithCombinedActivation = {
  ...ecdsaOnlyInput,
};

// @ts-expect-error ECDSA-only input cannot request an Ed25519 session.
const invalidEcdsaOnlyInput: PasskeyWalletUnlockInputWithEcdsaOnlyActivation = {
  ...combinedInput,
};

const activatedInput: PasskeyWalletUnlockInputWithEcdsaActivation = combinedInput;
void activatedInput;
void invalidCombinedWithoutEd25519;
void invalidCombinedDirectActivation;
void invalidEcdsaOnlyWithEd25519;
void invalidEcdsaOnlyCredentialFree;
void invalidCombinedInput;
void invalidEcdsaOnlyInput;
