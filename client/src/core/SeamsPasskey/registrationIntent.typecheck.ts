import {
  walletSubjectIdFromString,
  type AddSignerIntentV1,
  type AddSignerSelection,
  type NearAccountOwnershipProofV1,
  type RegistrationIntentV1,
  type RegistrationSignerSelection,
  type ThresholdEcdsaAddSignerSpec,
  type ThresholdEcdsaRegistrationSpec,
  type ThresholdEd25519AddSignerSpec,
  type ThresholdEd25519RegistrationSpec,
} from '@shared/utils/registrationIntent';

const ed25519Spec = {
  nearAccountId: 'alice.testnet',
  signerSlot: 1,
  participantIds: [1, 2],
  keyPurpose: 'near_tx',
  keyVersion: 'threshold-ed25519-hss-v1',
  derivationVersion: 1,
  createNearAccount: true,
} satisfies ThresholdEd25519RegistrationSpec;

const ecdsaSpec = {
  chainTargets: [{ chain: 'tempo', chainId: 978 }],
  participantIds: [1, 2],
} satisfies ThresholdEcdsaRegistrationSpec;

const ed25519AddSignerSpec = {
  mode: 'create_near_account',
  nearAccountId: 'alice.testnet',
  signerSlot: 2,
  participantIds: [1, 2],
  keyPurpose: 'near_tx',
  keyVersion: 'threshold-ed25519-hss-v1',
  derivationVersion: 1,
} satisfies ThresholdEd25519AddSignerSpec;

const nearAccountOwnershipProof = {
  version: 'near_account_ownership_proof_v1',
  message: {
    version: 'near_account_ownership_proof_message_v1',
    walletSubjectId: walletSubjectIdFromString('wallet_alice'),
    rpId: 'wallet.example.test',
    nearAccountId: 'alice.testnet',
    publicKey: 'ed25519:public-key',
    nonceB64u: 'nonce',
    issuedAtMs: 1,
    expiresAtMs: 2,
  },
  signatureB64u: 'signature',
} satisfies NearAccountOwnershipProofV1;

const ecdsaAddSignerSpec = {
  chainTargets: [{ chain: 'tempo', chainId: 978 }],
  participantIds: [1, 2],
} satisfies ThresholdEcdsaAddSignerSpec;

void ({
  mode: 'ed25519_only',
  ed25519: ed25519Spec,
} satisfies RegistrationSignerSelection);

void ({
  mode: 'ecdsa_only',
  ecdsa: ecdsaSpec,
} satisfies RegistrationSignerSelection);

void ({
  mode: 'ed25519_and_ecdsa',
  ed25519: ed25519Spec,
  ecdsa: ecdsaSpec,
} satisfies RegistrationSignerSelection);

void ({
  mode: 'ed25519',
  ed25519: ed25519AddSignerSpec,
} satisfies AddSignerSelection);

void ({
  mode: 'ecdsa',
  ecdsa: ecdsaAddSignerSpec,
} satisfies AddSignerSelection);

void ({
  version: 'registration_intent_v1',
  walletSubjectId: walletSubjectIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  authMethod: { kind: 'passkey' },
  signerSelection: {
    mode: 'ed25519_only',
    ed25519: ed25519Spec,
  },
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1);

void ({
  version: 'add_signer_intent_v1',
  walletSubjectId: walletSubjectIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  signerSelection: {
    mode: 'ed25519',
    ed25519: ed25519AddSignerSpec,
  },
  nonceB64u: 'nonce',
} satisfies AddSignerIntentV1);

void ({
  mode: 'ed25519_only',
  ed25519: ed25519Spec,
  ecdsa: ecdsaSpec,
  // @ts-expect-error ed25519_only registration cannot carry ECDSA signer input
} satisfies RegistrationSignerSelection);

void ({
  mode: 'ecdsa_only',
  ecdsa: ecdsaSpec,
  ed25519: ed25519Spec,
  // @ts-expect-error ecdsa_only registration cannot carry Ed25519 signer input
} satisfies RegistrationSignerSelection);

void ({
  mode: 'ed25519',
  ed25519: ed25519AddSignerSpec,
  ecdsa: ecdsaAddSignerSpec,
  // @ts-expect-error Ed25519 add-signer cannot carry ECDSA signer input
} satisfies AddSignerSelection);

void ({
  mode: 'ecdsa',
  ecdsa: ecdsaAddSignerSpec,
  ed25519: ed25519AddSignerSpec,
  // @ts-expect-error ECDSA add-signer cannot carry Ed25519 signer input
} satisfies AddSignerSelection);

void ({
  mode: 'ed25519_and_ecdsa',
  ed25519: ed25519Spec,
  // @ts-expect-error combined registration requires an ECDSA signer spec
} satisfies RegistrationSignerSelection);

void ({
  nearAccountId: 'alice.testnet',
  participantIds: [1, 2],
  keyPurpose: 'near_tx',
  keyVersion: 'threshold-ed25519-hss-v1',
  derivationVersion: 1,
  createNearAccount: true,
  // @ts-expect-error Ed25519 registration requires explicit signerSlot
} satisfies ThresholdEd25519RegistrationSpec);

void ({
  mode: 'link_existing_near_account',
  nearAccountId: 'alice.testnet',
  signerSlot: 2,
  participantIds: [1, 2],
  keyPurpose: 'near_tx',
  keyVersion: 'threshold-ed25519-hss-v1',
  derivationVersion: 1,
  // @ts-expect-error existing-account add-signer requires account ownership proof
} satisfies ThresholdEd25519AddSignerSpec);

void ({
  mode: 'link_existing_near_account',
  nearAccountId: 'alice.testnet',
  signerSlot: 2,
  participantIds: [1, 2],
  keyPurpose: 'near_tx',
  keyVersion: 'threshold-ed25519-hss-v1',
  derivationVersion: 1,
  accountOwnershipProof: nearAccountOwnershipProof,
} satisfies ThresholdEd25519AddSignerSpec);

void ({
  version: 'registration_intent_v1',
  // @ts-expect-error registration intent requires a branded wallet subject id
  walletSubjectId: 'wallet_alice',
  rpId: 'wallet.example.test',
  authMethod: { kind: 'passkey' },
  signerSelection: {
    mode: 'ed25519_only',
    ed25519: ed25519Spec,
  },
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1);

void ({
  version: 'registration_intent_v1',
  walletSubjectId: walletSubjectIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  authMethod: { kind: 'passkey' },
  signerSelection: {
    mode: 'ed25519_only',
    ed25519: ed25519Spec,
  },
  // @ts-expect-error registration intent nonce is required
} satisfies RegistrationIntentV1);

void ({
  version: 'add_signer_intent_v1',
  // @ts-expect-error add-signer intent requires a branded wallet subject id
  walletSubjectId: 'wallet_alice',
  rpId: 'wallet.example.test',
  signerSelection: {
    mode: 'ecdsa',
    ecdsa: ecdsaAddSignerSpec,
  },
  nonceB64u: 'nonce',
} satisfies AddSignerIntentV1);

void ({
  version: 'add_signer_intent_v1',
  walletSubjectId: walletSubjectIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  signerSelection: {
    mode: 'ecdsa',
    ecdsa: ecdsaAddSignerSpec,
  },
  // @ts-expect-error add-signer intent nonce is required
} satisfies AddSignerIntentV1);

export {};
