import {
  implicitNearAccountProvisioning,
  walletIdFromString,
  type AddAuthMethodIntentV1,
  type AddSignerIntentV1,
  type AddSignerSelection,
  type NearAccountOwnershipProofMessageV1,
  type NearAccountOwnershipProofV1,
  type RegistrationIntentV1,
  type ThresholdEcdsaAddSignerSpec,
  type ThresholdEd25519AddSignerSpec,
  type ThresholdEd25519RegistrationSpec,
} from '@shared/utils/registrationIntent';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import type {
  RegistrationEvmFamilyEcdsaSignerRequest as PublicRegistrationEvmFamilyEcdsaSignerRequest,
  RegistrationNearEd25519SignerRequest as PublicRegistrationNearEd25519SignerRequest,
  RegistrationSignerRequest as PublicRegistrationSignerRequest,
  RegistrationSignerSetSelection as PublicRegistrationSignerSetSelection,
} from '../index';

function unwrapDomainId<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('invalid type fixture domain id');
  return result.value;
}

const rpId = unwrapDomainId(parseWebAuthnRpId('wallet.example.test'));

const ed25519Spec = {
  accountProvisioning: implicitNearAccountProvisioning(),
  signerSlot: 1,
  participantIds: [1, 2],
  keyPurpose: 'near_tx',
  keyVersion: 'threshold-ed25519-hss-v1',
  derivationVersion: 1,
} satisfies ThresholdEd25519RegistrationSpec;

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
    walletId: walletIdFromString('wallet_alice'),
    nearAccountId: 'alice.testnet',
    publicKey: 'ed25519:public-key',
    nonceB64u: 'nonce',
    issuedAtMs: 1,
    expiresAtMs: 2,
  },
  signatureB64u: 'signature',
} satisfies NearAccountOwnershipProofV1;

void ({
  version: 'near_account_ownership_proof_message_v1',
  walletId: walletIdFromString('wallet_alice'),
  nearAccountId: 'alice.testnet',
  publicKey: 'ed25519:public-key',
  nonceB64u: 'nonce',
  issuedAtMs: 1,
  expiresAtMs: 2,
  // @ts-expect-error NEAR ownership proof messages cannot carry WebAuthn RP scope
  rpId,
} satisfies NearAccountOwnershipProofMessageV1);

const ecdsaAddSignerSpec = {
  chainTargets: [{ chain: 'tempo', chainId: 978 }],
  participantIds: [1, 2],
} satisfies ThresholdEcdsaAddSignerSpec;

const publicNearEd25519SignerRequest = {
  kind: 'near_ed25519',
  accountProvisioning: implicitNearAccountProvisioning(),
  signerSlot: 1,
  participantIds: [1, 2],
  derivationVersion: 1,
} satisfies PublicRegistrationNearEd25519SignerRequest;

const publicEvmFamilyEcdsaSignerRequest = {
  kind: 'evm_family_ecdsa',
  chainTargets: [{ chain: 'tempo', chainId: 978 }],
  participantIds: [1, 2],
} satisfies PublicRegistrationEvmFamilyEcdsaSignerRequest;

void (publicNearEd25519SignerRequest satisfies PublicRegistrationSignerRequest);
void (publicEvmFamilyEcdsaSignerRequest satisfies PublicRegistrationSignerRequest);

void ({
  kind: 'signer_set',
  signers: [publicNearEd25519SignerRequest, publicEvmFamilyEcdsaSignerRequest],
} satisfies PublicRegistrationSignerSetSelection);

const publicRegistrationSignerSetSelection = {
  kind: 'signer_set',
  signers: [publicNearEd25519SignerRequest, publicEvmFamilyEcdsaSignerRequest],
} satisfies PublicRegistrationSignerSetSelection;

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
  walletId: walletIdFromString('wallet_alice'),
  authMethod: { kind: 'passkey', rpId },
  signerSelection: publicRegistrationSignerSetSelection,
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1);

void ({
  version: 'add_signer_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  signerSelection: {
    mode: 'ed25519',
    ed25519: ed25519AddSignerSpec,
  },
  nonceB64u: 'nonce',
} satisfies AddSignerIntentV1);

void ({
  version: 'add_auth_method_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  authMethod: { kind: 'passkey', rpId },
  nonceB64u: 'nonce',
} satisfies AddAuthMethodIntentV1);

void ({
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  // @ts-expect-error registration intent cannot carry a root rpId
  rpId,
  authMethod: { kind: 'passkey', rpId },
  signerSelection: publicRegistrationSignerSetSelection,
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1);

void ({
  version: 'add_signer_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  // @ts-expect-error add-signer intent cannot carry a root rpId
  rpId,
  signerSelection: {
    mode: 'ed25519',
    ed25519: ed25519AddSignerSpec,
  },
  nonceB64u: 'nonce',
} satisfies AddSignerIntentV1);

void ({
  version: 'add_auth_method_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  // @ts-expect-error add-auth-method intent cannot carry a root rpId
  rpId,
  authMethod: { kind: 'passkey', rpId },
  nonceB64u: 'nonce',
} satisfies AddAuthMethodIntentV1);

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
  accountProvisioning: implicitNearAccountProvisioning(),
  participantIds: [1, 2],
  keyPurpose: 'near_tx',
  keyVersion: 'threshold-ed25519-hss-v1',
  derivationVersion: 1,
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
  // @ts-expect-error registration intent requires a branded wallet id
  walletId: 'wallet_alice',
  authMethod: { kind: 'passkey', rpId },
  signerSelection: publicRegistrationSignerSetSelection,
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1);

void ({
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  authMethod: { kind: 'passkey', rpId },
  signerSelection: publicRegistrationSignerSetSelection,
  // @ts-expect-error registration intent nonce is required
} satisfies RegistrationIntentV1);

void ({
  version: 'add_signer_intent_v1',
  // @ts-expect-error add-signer intent requires a branded wallet id
  walletId: 'wallet_alice',
  signerSelection: {
    mode: 'ecdsa',
    ecdsa: ecdsaAddSignerSpec,
  },
  nonceB64u: 'nonce',
} satisfies AddSignerIntentV1);

void ({
  version: 'add_signer_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  signerSelection: {
    mode: 'ecdsa',
    ecdsa: ecdsaAddSignerSpec,
  },
  // @ts-expect-error add-signer intent nonce is required
} satisfies AddSignerIntentV1);

export {};
