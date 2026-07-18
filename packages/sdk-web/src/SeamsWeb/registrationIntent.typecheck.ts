import {
  implicitNearAccountProvisioning,
  walletIdFromString,
  type AddAuthMethodIntentV1,
  type AddSignerIntentV1,
  type AddSignerSelection,
  type RegistrationIntentV1,
  type ThresholdEcdsaAddSignerSpec,
  type ThresholdEd25519AddSignerSpec,
  type ThresholdEd25519RegistrationSpec,
} from '@shared/utils/registrationIntent';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import type {
  FinalizeWalletAddSignerArgs,
  WalletAddSignerFinalizeResponse,
  WalletAddSignerStartResponse,
} from '../core/rpcClients/relayer/walletRegistration';
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
  keyVersion: 'router-ab-ed25519-yao-v1',
  derivationVersion: 1,
} satisfies ThresholdEd25519RegistrationSpec;

const ed25519AddSignerSpec = {
  mode: 'create_implicit_near_account',
  signerSlot: 2,
  participantIds: [1, 2],
  keyPurpose: 'near_tx',
  keyVersion: 'router-ab-ed25519-yao-v1',
  derivationVersion: 1,
} satisfies ThresholdEd25519AddSignerSpec;

const ecdsaAddSignerSpec = {
  chainTargets: [{ chain: 'tempo', chainId: 978 }],
  participantIds: [1, 2],
} satisfies ThresholdEcdsaAddSignerSpec;

const addSignerWalletId = walletIdFromString('wallet_alice');
const addSignerIntentFixture = {
  version: 'add_signer_intent_v1',
  walletId: addSignerWalletId,
  signerSelection: {
    mode: 'ed25519',
    ed25519: ed25519AddSignerSpec,
  },
  nonceB64u: 'nonce',
} satisfies AddSignerIntentV1;
const addSignerAdmissionRequestFixture = {
  scope: {
    lifecycle_id: 'add-signer-ceremony-1',
    root_share_epoch: 'root-share-epoch-1',
    account_id: 'alice.testnet',
    wallet_session_id: 'wallet-session-1',
    signer_set_id: 'signer-set-1',
    signing_worker_id: 'signing-worker-1',
  },
  application_binding: {
    wallet_id: addSignerWalletId,
    near_ed25519_signing_key_id: 'alice.testnet',
    signing_root_id: 'project:dev',
    key_creation_signer_slot: 2,
  },
  participant_ids: [1, 2] as const,
};
const validEd25519AddSignerStart = {
  ok: true,
  addSignerCeremonyId: 'add-signer-ceremony-1',
  intent: addSignerIntentFixture,
  kind: 'near_ed25519',
  ed25519: { admissionRequest: addSignerAdmissionRequestFixture },
} satisfies WalletAddSignerStartResponse;
void validEd25519AddSignerStart;

// @ts-expect-error A near-Ed25519 start response requires its admission branch.
const missingEd25519AddSignerStartBranch: WalletAddSignerStartResponse = {
  ok: true,
  addSignerCeremonyId: 'add-signer-ceremony-1',
  intent: addSignerIntentFixture,
  kind: 'near_ed25519',
};
void missingEd25519AddSignerStartBranch;

void ({
  ...validEd25519AddSignerStart,
  ed25519: {
    // @ts-expect-error DERIVATION-era ceremony handles are not an Ed25519 Yao admission.
    ceremonyHandle: 'legacy-derivation-handle',
    preparedSession: {},
    clientOtOfferMessageB64u: 'legacy-client-ot-offer',
  },
} satisfies WalletAddSignerStartResponse);

const validEd25519AddSignerFinalize = {
  relayerUrl: 'https://relay.example.test',
  walletId: addSignerWalletId,
  addSignerCeremonyId: 'add-signer-ceremony-1',
  idempotencyKey: 'add-signer-finalize-1',
  kind: 'near_ed25519',
  ed25519: {
    activationReference: {
      kind: 'router_ab_ed25519_yao_activation_reference_v1',
      lifecycle_id: 'add-signer-ceremony-1',
      session_id: new Array<number>(32).fill(1),
    },
  },
} satisfies FinalizeWalletAddSignerArgs;
void validEd25519AddSignerFinalize;

void ({
  ...validEd25519AddSignerFinalize,
  ecdsa: { expectedKeyHandles: ['legacy-key-handle'] },
  // @ts-expect-error A near-Ed25519 finalize request cannot carry ECDSA work.
} satisfies FinalizeWalletAddSignerArgs);

// @ts-expect-error A near-Ed25519 finalize request requires an activation reference.
const missingEd25519AddSignerFinalizeBranch: FinalizeWalletAddSignerArgs = {
  relayerUrl: 'https://relay.example.test',
  walletId: addSignerWalletId,
  addSignerCeremonyId: 'add-signer-ceremony-1',
  idempotencyKey: 'add-signer-finalize-1',
  kind: 'near_ed25519',
};
void missingEd25519AddSignerFinalizeBranch;

void ({
  ...validEd25519AddSignerFinalize,
  ed25519: {
    // @ts-expect-error DERIVATION-era evaluation results cannot finalize a Yao add-signer.
    evaluationResult: { stagedEvaluatorArtifactB64u: 'legacy-artifact' },
  },
} satisfies FinalizeWalletAddSignerArgs);

void ({
  ok: true,
  walletId: addSignerWalletId,
  kind: 'evm_family_ecdsa',
  rpId: 'wallet.example.test',
  ecdsa: { walletKeys: [] },
} satisfies WalletAddSignerFinalizeResponse);

// @ts-expect-error Successful add-signer finalize responses require a branch discriminator.
const missingAddSignerFinalizeResponseKind: WalletAddSignerFinalizeResponse = {
  ok: true,
  walletId: addSignerWalletId,
  rpId: 'wallet.example.test',
  ecdsa: { walletKeys: [] },
};
void missingAddSignerFinalizeResponseKind;

void ({
  ok: true,
  walletId: addSignerWalletId,
  kind: 'near_ed25519',
  rpId: 'wallet.example.test',
  credentialIdB64u: 'credential-1',
  ed25519: {
    // @ts-expect-error DERIVATION-era server payloads are not Ed25519 Yao public results.
    serverEvalFinalizeOutputB64u: 'legacy-server-output',
  },
} satisfies WalletAddSignerFinalizeResponse);

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
  keyVersion: 'router-ab-ed25519-yao-v1',
  derivationVersion: 1,
  // @ts-expect-error Ed25519 registration requires explicit signerSlot
} satisfies ThresholdEd25519RegistrationSpec);

void ({
  // @ts-expect-error unverified existing-account linking is not an add-signer mode.
  mode: 'link_existing_near_account',
  signerSlot: 2,
  participantIds: [1, 2],
  keyPurpose: 'near_tx',
  keyVersion: 'router-ab-ed25519-yao-v1',
  derivationVersion: 1,
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
