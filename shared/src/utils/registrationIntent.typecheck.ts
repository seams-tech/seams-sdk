import {
  walletSubjectIdFromString,
  type RegistrationAuthMethodInput,
  type RegistrationIntentV1,
  type RegistrationSignerSelection,
  type WalletAuthMethodBinding,
} from './registrationIntent';

const passkeyAuthMethod = {
  kind: 'passkey',
} satisfies RegistrationAuthMethodInput;

const emailOtpAuthMethod = {
  kind: 'email_otp',
  email: 'alice@example.test',
  challengeId: 'challenge',
} satisfies RegistrationAuthMethodInput;

const ecdsaOnlySelection = {
  mode: 'ecdsa_only',
  ecdsa: {
    chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
    participantIds: [1, 2],
  },
} satisfies RegistrationSignerSelection;

const ed25519OnlySelection = {
  mode: 'ed25519_only',
  ed25519: {
    nearAccountId: 'alice.testnet',
    signerSlot: 1,
    participantIds: [1, 2],
    keyPurpose: 'near_tx',
    keyVersion: 'threshold-ed25519-hss-v1',
    derivationVersion: 1,
    createNearAccount: true,
  },
} satisfies RegistrationSignerSelection;

void ({
  version: 'registration_intent_v1',
  walletSubjectId: walletSubjectIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  authMethod: emailOtpAuthMethod,
  signerSelection: ecdsaOnlySelection,
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1);

void ({
  version: 'registration_intent_v1',
  walletSubjectId: walletSubjectIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  authMethod: passkeyAuthMethod,
  signerSelection: ed25519OnlySelection,
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1);

// @ts-expect-error registration intents require explicit authMethod.
const missingAuthMethod: RegistrationIntentV1 = {
  version: 'registration_intent_v1',
  walletSubjectId: walletSubjectIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  signerSelection: ed25519OnlySelection,
  nonceB64u: 'nonce',
};
void missingAuthMethod;

// @ts-expect-error passkey registration auth cannot carry Email OTP fields.
const passkeyWithEmail: RegistrationAuthMethodInput = {
  kind: 'passkey',
  email: 'alice@example.test',
};
void passkeyWithEmail;

// @ts-expect-error Email OTP registration auth cannot carry passkey options.
const emailOtpWithAuthenticatorOptions: RegistrationAuthMethodInput = {
  kind: 'email_otp',
  email: 'alice@example.test',
  authenticatorOptions: {},
};
void emailOtpWithAuthenticatorOptions;

void ({
  version: 'wallet_auth_method_binding_v1',
  kind: 'passkey',
  status: 'active',
  walletSubjectId: walletSubjectIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  credentialIdB64u: 'credential',
  credentialPublicKeyB64u: 'public-key',
  counter: 0,
  createdAtMs: 1,
  updatedAtMs: 1,
} satisfies WalletAuthMethodBinding);

void ({
  version: 'wallet_auth_method_binding_v1',
  kind: 'email_otp',
  status: 'active',
  walletSubjectId: walletSubjectIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  emailHashHex: '00',
  challengeId: 'challenge',
  createdAtMs: 1,
  updatedAtMs: 1,
} satisfies WalletAuthMethodBinding);

export {};
