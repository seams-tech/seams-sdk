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
import { resolveCrossDeviceCustodyReadiness } from './index';
import type {
  CrossDeviceCustodyReadiness,
  Ed25519PublicKeyB64u,
  EnvelopeCiphertextB64u,
  EnvelopeNonceB64u,
  EnvelopeRevision,
  PasskeyCredentialObservationRecord,
  PasskeyCustodyEnvelopeLifecycle,
  PasskeyCustodyEnvelopeRecord,
  PasskeyCustodySecretBinding,
  Secp256k1CompressedPublicKeyB64u,
  WalletCustodyEnvelopeFactor,
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
declare const envelopeRevision: EnvelopeRevision;
declare const nonceB64u: EnvelopeNonceB64u;
declare const ciphertextB64u: EnvelopeCiphertextB64u;

// --- Valid custody-secret branches ---------------------------------------

const walletSeed: PasskeyCustodySecretBinding = {
  kind: 'wallet_custody_seed_v1',
  derivationScheme: 'wallet_seed_parallel_hkdf_sha256_v1',
};
void walletSeed;

// The seed names no key set. Key sets are provisioned independently and each
// records its own manifest on its own registration state, so a seed that named
// them would have to be resealed every time one arrived.
const seedNamingAKeySet: PasskeyCustodySecretBinding = {
  kind: 'wallet_custody_seed_v1',
  derivationScheme: 'wallet_seed_parallel_hkdf_sha256_v1',
  // @ts-expect-error The seed does not name the key sets it can derive.
  keyManifestDigestB64u: digest,
};
void seedNamingAKeySet;

// @ts-expect-error A key set's identity belongs to its own manifest.
const seedNamingASigningKey: PasskeyCustodySecretBinding = {
  kind: 'wallet_custody_seed_v1',
  derivationScheme: 'wallet_seed_parallel_hkdf_sha256_v1',
  nearEd25519SigningKeyId,
};
void seedNamingASigningKey;

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

// --- The wallet seed is wallet-scoped, never lane-scoped ------------------

// @ts-expect-error Owner custody covers every key, so it cannot name one lane.
const seedWithLane: PasskeyCustodySecretBinding = {
  kind: 'wallet_custody_seed_v1',
  derivationScheme: 'wallet_seed_parallel_hkdf_sha256_v1',
  laneId,
};
void seedWithLane;

const laneShareWithManifest: PasskeyCustodySecretBinding = {
  kind: 'ed25519_lane_holder_share_v1',
  walletKeyId,
  laneId,
  laneShareEpoch,
  nearEd25519SigningKeyId,
  registeredPublicKeyB64u: ed25519PublicKey,
  participantBindingDigestB64u: digest,
  // @ts-expect-error A key manifest digest is not a custody binding field.
  keyManifestDigestB64u: digest,
};
void laneShareWithManifest;

const laneShareWithScheme: PasskeyCustodySecretBinding = {
  kind: 'ecdsa_lane_holder_share_v1',
  walletKeyId,
  laneId,
  laneShareEpoch,
  evmFamilySigningKeySlotId,
  thresholdSessionId,
  thresholdPublicKey33B64u: secpPublicKey,
  // @ts-expect-error Only owner custody declares a seed derivation scheme.
  derivationScheme: 'wallet_seed_parallel_hkdf_sha256_v1',
};
void laneShareWithScheme;

// --- Cross-branch fields still fail --------------------------------------

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

const ecdsaHolderShareWithRootField: PasskeyCustodySecretBinding = {
  kind: 'ecdsa_lane_holder_share_v1',
  walletKeyId,
  laneId,
  laneShareEpoch,
  evmFamilySigningKeySlotId,
  thresholdSessionId,
  thresholdPublicKey33B64u: secpPublicKey,
  // @ts-expect-error A holder share cannot carry the client root's public key.
  clientRootPublicKey33B64u: secpPublicKey,
};
void ecdsaHolderShareWithRootField;

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

// @ts-expect-error An owner root cannot carry lane-holder identity fields.
const retiredEd25519Root: PasskeyCustodySecretBinding = {
  kind: 'ed25519_yao_client_root_v1',
  walletKeyId,
  laneId,
  laneShareEpoch,
  nearEd25519SigningKeyId,
  participantBindingDigestB64u: digest,
};
void retiredEd25519Root;

// --- Factor branches ------------------------------------------------------

const passkeyFactor: WalletCustodyEnvelopeFactor = {
  kind: 'passkey',
  rpId,
  credentialIdB64u,
  kekVersion: 'passkey_prf_kek_hkdf_sha256_v1',
};
void passkeyFactor;

const emailOtpFactor: WalletCustodyEnvelopeFactor = {
  kind: 'email_otp',
  enrollmentId: 'enrollment-1',
  enrollmentSealKeyVersion: 'seal-v1',
  kekVersion: 'email_otp_factor_kek_hkdf_sha256_v1',
};
void emailOtpFactor;

// @ts-expect-error An Email OTP factor has no relying party or credential.
const emailOtpFactorWithCredential: WalletCustodyEnvelopeFactor = {
  kind: 'email_otp',
  enrollmentId: 'enrollment-1',
  enrollmentSealKeyVersion: 'seal-v1',
  kekVersion: 'email_otp_factor_kek_hkdf_sha256_v1',
  credentialIdB64u,
};
void emailOtpFactorWithCredential;

// @ts-expect-error A passkey factor has no Email OTP enrollment identity.
const passkeyFactorWithEnrollment: WalletCustodyEnvelopeFactor = {
  kind: 'passkey',
  rpId,
  credentialIdB64u,
  kekVersion: 'passkey_prf_kek_hkdf_sha256_v1',
  enrollmentId: 'enrollment-1',
};
void passkeyFactorWithEnrollment;

// @ts-expect-error Each factor kind pins its own KEK version.
const passkeyFactorWithOtpKek: WalletCustodyEnvelopeFactor = {
  kind: 'passkey',
  rpId,
  credentialIdB64u,
  kekVersion: 'email_otp_factor_kek_hkdf_sha256_v1',
};
void passkeyFactorWithOtpKek;

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
  kind: 'wallet_custody_envelope_v2',
  envelopeId,
  walletId,
  binding: walletSeed,
  factor: passkeyFactor,
  envelopeVersion: 'wallet_custody_envelope_v2',
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

// The same seed sealed under an Email OTP factor: interchangeable unwrap paths
// to identical signing material.
const emailOtpEnvelope: PasskeyCustodyEnvelopeRecord = {
  ...envelope,
  factor: emailOtpFactor,
};
void emailOtpEnvelope;

// @ts-expect-error An envelope requires its factor identity.
const envelopeWithoutFactor: PasskeyCustodyEnvelopeRecord = {
  kind: 'wallet_custody_envelope_v2',
  envelopeId,
  walletId,
  binding: walletSeed,
  envelopeVersion: 'wallet_custody_envelope_v2',
  envelopeRevision,
  nonceB64u,
  sealedCustodySecretB64u: ciphertextB64u,
  ciphertextDigestB64u: digest,
  aadHashB64u: digest,
  lifecycle: activeLifecycle,
  createdAtMs: 1,
  updatedAtMs: 1,
};
void envelopeWithoutFactor;

// @ts-expect-error An envelope requires its AAD binding hash.
const envelopeWithoutAad: PasskeyCustodyEnvelopeRecord = {
  kind: 'wallet_custody_envelope_v2',
  envelopeId,
  walletId,
  binding: walletSeed,
  factor: passkeyFactor,
  envelopeVersion: 'wallet_custody_envelope_v2',
  envelopeRevision,
  nonceB64u,
  sealedCustodySecretB64u: ciphertextB64u,
  ciphertextDigestB64u: digest,
  lifecycle: activeLifecycle,
  createdAtMs: 1,
  updatedAtMs: 1,
};
void envelopeWithoutAad;

// @ts-expect-error An envelope requires an exact custody-secret binding.
const envelopeWithoutBinding: PasskeyCustodyEnvelopeRecord = {
  kind: 'wallet_custody_envelope_v2',
  envelopeId,
  walletId,
  factor: passkeyFactor,
  envelopeVersion: 'wallet_custody_envelope_v2',
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

// Factor identity lives in the branch, never at the record's top level.
const envelopeWithTopLevelCredential: PasskeyCustodyEnvelopeRecord = {
  ...envelope,
  // @ts-expect-error Credential identity belongs to the passkey factor branch.
  credentialIdB64u,
};
void envelopeWithTopLevelCredential;

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

const envelopeWithSeedPlaintext: PasskeyCustodyEnvelopeRecord = {
  ...envelope,
  // @ts-expect-error Envelopes must not carry the plaintext custody seed.
  walletCustodySeedB64u: 'seed',
};
void envelopeWithSeedPlaintext;

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

// --- Backup flags can never establish cross-device custody readiness ------

declare const observation: PasskeyCredentialObservationRecord;

// Readiness takes PRF support and the sealed envelope; there is no parameter a
// backup flag could occupy, so "backed up therefore portable" cannot compile.
const readiness: CrossDeviceCustodyReadiness = resolveCrossDeviceCustodyReadiness({
  prfSupported: observation.prfSupported,
  activeSealedEnvelope: { envelopeId, envelopeRevision },
});
void readiness;

resolveCrossDeviceCustodyReadiness({
  prfSupported: observation.prfSupported,
  activeSealedEnvelope: null,
  // @ts-expect-error Backup eligibility is advisory and is not a readiness input.
  backupEligible: observation.backupEligible,
});

resolveCrossDeviceCustodyReadiness({
  prfSupported: observation.prfSupported,
  // @ts-expect-error A backup-state flag cannot stand in for a sealed envelope.
  activeSealedEnvelope: observation.backupState,
});

const observationWithSecret: PasskeyCredentialObservationRecord = {
  ...observation,
  // @ts-expect-error Observations must not carry WebAuthn PRF output.
  prfFirstB64u: 'prf',
};
void observationWithSecret;

export {};
