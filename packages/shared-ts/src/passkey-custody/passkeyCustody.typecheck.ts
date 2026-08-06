import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '../signing-lanes/ids';
import type { EvmFamilySigningKeySlotId } from '../signing-lanes/evmFamilySigningKeySlotId';
import type {
  PasskeyEnvelopeId,
  ThresholdEcdsaSessionId,
  WalletId,
  WebAuthnCredentialIdB64u,
  WebAuthnRpId,
} from '../utils/domainIds';
import type { NearEd25519SigningKeyId } from '../utils/registrationIntent';
import type { DigestB64u } from '../utils/canonicalPrimitives';
import type {
  Ed25519PublicKeyB64u,
  EnvelopeCiphertextB64u,
  EnvelopeNonceB64u,
  EnvelopeRevision,
  KeyCreationSignerSlot,
  PasskeyCustodyEnvelopeLifecycle,
  PasskeyCustodyEnvelopeRecord,
  PasskeyCustodySecretBinding,
  Secp256k1CompressedPublicKeyB64u,
} from './index';

declare const walletId: WalletId;
declare const walletKeyId: WalletKeyId;
declare const laneId: SigningLaneId;
declare const laneShareEpoch: LaneShareEpoch;
declare const envelopeId: PasskeyEnvelopeId;
declare const rpId: WebAuthnRpId;
declare const credentialIdB64u: WebAuthnCredentialIdB64u;
declare const nearEd25519SigningKeyId: NearEd25519SigningKeyId;
declare const evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
declare const thresholdSessionId: ThresholdEcdsaSessionId;
declare const digest: DigestB64u;
declare const ed25519PublicKey: Ed25519PublicKeyB64u;
declare const secpPublicKey: Secp256k1CompressedPublicKeyB64u;
declare const keyCreationSignerSlot: KeyCreationSignerSlot;
declare const envelopeRevision: EnvelopeRevision;
declare const nonceB64u: EnvelopeNonceB64u;
declare const ciphertextB64u: EnvelopeCiphertextB64u;

// --- Valid custody-secret branches ---------------------------------------

const ed25519Root: PasskeyCustodySecretBinding = {
  kind: 'ed25519_yao_client_root_v1',
  walletKeyId,
  laneId,
  laneShareEpoch,
  nearEd25519SigningKeyId,
  keyCreationSignerSlot,
  stableContextDigestB64u: digest,
  participantBindingDigestB64u: digest,
};
void ed25519Root;

const ed25519LaneHolderShare: PasskeyCustodySecretBinding = {
  kind: 'ed25519_lane_holder_share_v1',
  walletKeyId,
  laneId,
  laneShareEpoch,
  nearEd25519SigningKeyId,
  registeredPublicKeyB64u: ed25519PublicKey,
  participantBindingDigestB64u: digest,
};
void ed25519LaneHolderShare;

const ecdsaRootShare: PasskeyCustodySecretBinding = {
  kind: 'ecdsa_client_root_share_v1',
  walletKeyId,
  laneId,
  laneShareEpoch,
  evmFamilySigningKeySlotId,
  applicationBindingDigestB64u: digest,
  clientRootPublicKey33B64u: secpPublicKey,
};
void ecdsaRootShare;

const ecdsaLaneHolderShare: PasskeyCustodySecretBinding = {
  kind: 'ecdsa_lane_holder_share_v1',
  walletKeyId,
  laneId,
  laneShareEpoch,
  evmFamilySigningKeySlotId,
  thresholdSessionId,
  thresholdPublicKey33B64u: secpPublicKey,
};
void ecdsaLaneHolderShare;

// --- An Ed25519 root envelope with ECDSA fields fails ---------------------

// @ts-expect-error An Ed25519 root binding cannot carry an EVM-family key slot.
const ed25519RootWithEcdsaFields: PasskeyCustodySecretBinding = {
  kind: 'ed25519_yao_client_root_v1',
  walletKeyId,
  laneId,
  laneShareEpoch,
  nearEd25519SigningKeyId,
  keyCreationSignerSlot,
  stableContextDigestB64u: digest,
  participantBindingDigestB64u: digest,
  evmFamilySigningKeySlotId,
};
void ed25519RootWithEcdsaFields;

// @ts-expect-error An Ed25519 root binding cannot carry an ECDSA threshold session.
const ed25519RootWithThresholdSession: PasskeyCustodySecretBinding = {
  kind: 'ed25519_yao_client_root_v1',
  walletKeyId,
  laneId,
  laneShareEpoch,
  nearEd25519SigningKeyId,
  keyCreationSignerSlot,
  stableContextDigestB64u: digest,
  participantBindingDigestB64u: digest,
  thresholdSessionId,
};
void ed25519RootWithThresholdSession;

// --- An ECDSA holder-share envelope without a threshold session fails -----

// @ts-expect-error An ECDSA lane holder share requires its threshold session binding.
const ecdsaHolderShareWithoutSession: PasskeyCustodySecretBinding = {
  kind: 'ecdsa_lane_holder_share_v1',
  walletKeyId,
  laneId,
  laneShareEpoch,
  evmFamilySigningKeySlotId,
  thresholdPublicKey33B64u: secpPublicKey,
};
void ecdsaHolderShareWithoutSession;

// --- A linked-device holder share with a key-creation root field fails ----

// @ts-expect-error A holder share cannot carry the client root's public key.
const ecdsaHolderShareWithRootField: PasskeyCustodySecretBinding = {
  kind: 'ecdsa_lane_holder_share_v1',
  walletKeyId,
  laneId,
  laneShareEpoch,
  evmFamilySigningKeySlotId,
  thresholdSessionId,
  thresholdPublicKey33B64u: secpPublicKey,
  clientRootPublicKey33B64u: secpPublicKey,
};
void ecdsaHolderShareWithRootField;

// @ts-expect-error A holder share cannot carry the key-creation signer slot.
const ed25519HolderShareWithRootField: PasskeyCustodySecretBinding = {
  kind: 'ed25519_lane_holder_share_v1',
  walletKeyId,
  laneId,
  laneShareEpoch,
  nearEd25519SigningKeyId,
  registeredPublicKeyB64u: ed25519PublicKey,
  participantBindingDigestB64u: digest,
  keyCreationSignerSlot,
};
void ed25519HolderShareWithRootField;

// --- Public identities cannot be swapped across curves --------------------

const ed25519HolderShareWithSecpKey: PasskeyCustodySecretBinding = {
  kind: 'ed25519_lane_holder_share_v1',
  walletKeyId,
  laneId,
  laneShareEpoch,
  nearEd25519SigningKeyId,
  // @ts-expect-error A registered Ed25519 key cannot be a compressed secp256k1 point.
  registeredPublicKeyB64u: secpPublicKey,
  participantBindingDigestB64u: digest,
};
void ed25519HolderShareWithSecpKey;

// --- Envelope lifecycle ---------------------------------------------------

const activeLifecycle: PasskeyCustodyEnvelopeLifecycle = {
  state: 'active',
  activatedAtMs: 1,
};
void activeLifecycle;

// @ts-expect-error An active envelope cannot carry a revoked timestamp.
const activeLifecycleWithRevocation: PasskeyCustodyEnvelopeLifecycle = {
  state: 'active',
  activatedAtMs: 1,
  revokedAtMs: 2,
};
void activeLifecycleWithRevocation;

// @ts-expect-error A revoked envelope cannot also be retired.
const revokedAndRetiredLifecycle: PasskeyCustodyEnvelopeLifecycle = {
  state: 'revoked',
  activatedAtMs: 1,
  revokedAtMs: 2,
  retiredAtMs: 3,
};
void revokedAndRetiredLifecycle;

// --- Envelope record ------------------------------------------------------

const envelope: PasskeyCustodyEnvelopeRecord = {
  kind: 'passkey_custody_envelope_v1',
  envelopeId,
  walletId,
  binding: ed25519Root,
  rpId,
  credentialIdB64u,
  passkeyEnvelopeVersion: 'passkey_custody_envelope_v1',
  passkeyKekVersion: 'passkey_prf_kek_hkdf_sha256_v1',
  envelopeRevision,
  nonceB64u,
  sealedCustodySecretB64u: ciphertextB64u,
  ciphertextDigestB64u: digest,
  aadHashB64u: digest,
  lifecycle: activeLifecycle,
  createdAtMs: 1,
  updatedAtMs: 1,
};
void envelope;

// --- An active envelope without credential, lane, key, or AAD identity fails

// @ts-expect-error An envelope requires its credential identity.
const envelopeWithoutCredential: PasskeyCustodyEnvelopeRecord = {
  kind: 'passkey_custody_envelope_v1',
  envelopeId,
  walletId,
  binding: ed25519Root,
  rpId,
  passkeyEnvelopeVersion: 'passkey_custody_envelope_v1',
  passkeyKekVersion: 'passkey_prf_kek_hkdf_sha256_v1',
  envelopeRevision,
  nonceB64u,
  sealedCustodySecretB64u: ciphertextB64u,
  ciphertextDigestB64u: digest,
  aadHashB64u: digest,
  lifecycle: activeLifecycle,
  createdAtMs: 1,
  updatedAtMs: 1,
};
void envelopeWithoutCredential;

// @ts-expect-error An envelope requires its AAD binding hash.
const envelopeWithoutAad: PasskeyCustodyEnvelopeRecord = {
  kind: 'passkey_custody_envelope_v1',
  envelopeId,
  walletId,
  binding: ed25519Root,
  rpId,
  credentialIdB64u,
  passkeyEnvelopeVersion: 'passkey_custody_envelope_v1',
  passkeyKekVersion: 'passkey_prf_kek_hkdf_sha256_v1',
  envelopeRevision,
  nonceB64u,
  sealedCustodySecretB64u: ciphertextB64u,
  ciphertextDigestB64u: digest,
  lifecycle: activeLifecycle,
  createdAtMs: 1,
  updatedAtMs: 1,
};
void envelopeWithoutAad;

// A lane-scoped binding is required, so an envelope cannot be wallet-scoped
// only: `binding` has no branch without walletKeyId, laneId, and laneShareEpoch.
// @ts-expect-error An envelope requires an exact custody-secret binding.
const envelopeWithoutBinding: PasskeyCustodyEnvelopeRecord = {
  kind: 'passkey_custody_envelope_v1',
  envelopeId,
  walletId,
  rpId,
  credentialIdB64u,
  passkeyEnvelopeVersion: 'passkey_custody_envelope_v1',
  passkeyKekVersion: 'passkey_prf_kek_hkdf_sha256_v1',
  envelopeRevision,
  nonceB64u,
  sealedCustodySecretB64u: ciphertextB64u,
  ciphertextDigestB64u: digest,
  aadHashB64u: digest,
  lifecycle: activeLifecycle,
  createdAtMs: 1,
  updatedAtMs: 1,
};
void envelopeWithoutBinding;

// --- Plaintext custody material can never appear in a persisted record ----

const envelopeWithPrfOutput: PasskeyCustodyEnvelopeRecord = {
  ...envelope,
  // @ts-expect-error Envelopes must not carry WebAuthn PRF output.
  passkeyPrfFirstB64u: 'prf',
};
void envelopeWithPrfOutput;

const envelopeWithKek: PasskeyCustodyEnvelopeRecord = {
  ...envelope,
  // @ts-expect-error Envelopes must not carry the derived KEK.
  passkeyKekB64u: 'kek',
};
void envelopeWithKek;

const envelopeWithClientRoot: PasskeyCustodyEnvelopeRecord = {
  ...envelope,
  // @ts-expect-error Envelopes must not carry a plaintext client root.
  clientRootB64u: 'root',
};
void envelopeWithClientRoot;

const envelopeWithHolderShare: PasskeyCustodyEnvelopeRecord = {
  ...envelope,
  // @ts-expect-error Envelopes must not carry a plaintext holder share.
  holderShareB64u: 'share',
};
void envelopeWithHolderShare;

const envelopeWithRecoveryCode: PasskeyCustodyEnvelopeRecord = {
  ...envelope,
  // @ts-expect-error Envelopes must not carry a plaintext recovery code.
  recoveryCodePlaintext: 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH',
};
void envelopeWithRecoveryCode;

// --- Envelopes carry no authorization identity ----------------------------

const envelopeWithGrant: PasskeyCustodyEnvelopeRecord = {
  ...envelope,
  // @ts-expect-error Authorization grants are resolved per operation, never stored in custody.
  authorizationGrantRef: 'grant',
};
void envelopeWithGrant;

const envelopeWithMaterialActivation: PasskeyCustodyEnvelopeRecord = {
  ...envelope,
  // @ts-expect-error Material activation is bound at the activation boundary, not in the envelope.
  mpcMaterialActivationRef: 'activation',
};
void envelopeWithMaterialActivation;

// --- Raw boundary shapes cannot reach core custody functions --------------

declare function openCustodyEnvelope(envelope: PasskeyCustodyEnvelopeRecord): void;
declare const rawServerRow: Record<string, unknown>;
declare const rawJson: unknown;

// @ts-expect-error A raw persistence row must be parsed at the boundary first.
openCustodyEnvelope(rawServerRow);
// @ts-expect-error A raw wire payload must be parsed at the boundary first.
openCustodyEnvelope(rawJson);

export {};
