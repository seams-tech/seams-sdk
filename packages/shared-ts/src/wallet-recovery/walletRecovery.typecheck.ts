import type { WalletId } from '../utils/domainIds';
import type { DigestB64u } from '../utils/canonicalPrimitives';
import type { EnvelopeCiphertextB64u, EnvelopeNonceB64u } from '../passkey-custody';
import type { DerivedWalletRecoveryKeyId } from './recoveryCodes';
import type { RecoveryCodeLifecycleState } from './recoveryEnvelopes';
import type { RecoveryCodeReservationId } from './recoveryCodeReservation';
import type {
  WalletRecoveryEnvelopeEntry,
  WalletRecoveryEnvelopeSetRecord,
  WalletRecoveryManifestKekWrap,
} from './walletRecoveryEnvelopeSet';

declare const walletId: WalletId;
declare const recoveryKeyId: DerivedWalletRecoveryKeyId;
declare const digest: DigestB64u;
declare const nonceB64u: EnvelopeNonceB64u;
declare const ciphertextB64u: EnvelopeCiphertextB64u;
declare const reservationId: RecoveryCodeReservationId;

const activeRecoveryCode: RecoveryCodeLifecycleState = {
  state: 'active',
  issuedAtMs: 1,
};
void activeRecoveryCode;

// @ts-expect-error Active recovery codes cannot carry consumed timestamps.
const invalidActiveRecoveryCode: RecoveryCodeLifecycleState = {
  state: 'active',
  issuedAtMs: 1,
  consumedAtMs: 2,
};
void invalidActiveRecoveryCode;

// @ts-expect-error An active code cannot hold a reservation.
const activeCodeHoldingReservation: RecoveryCodeLifecycleState = {
  state: 'active',
  issuedAtMs: 1,
  reservationId,
};
void activeCodeHoldingReservation;

// @ts-expect-error A consumed code retains the recovery operation that spent it.
const consumedCodeWithoutCorrelation: RecoveryCodeLifecycleState = {
  state: 'consumed',
  issuedAtMs: 1,
  consumedAtMs: 2,
};
void consumedCodeWithoutCorrelation;

// The owner entry is wallet-scoped: one seed covering every owner key.
const seedEntry: WalletRecoveryEnvelopeEntry = {
  custodySecretKind: 'wallet_custody_seed_v1',
  nonceB64u,
  wrappedCustodySecretB64u: ciphertextB64u,
  aadHashB64u: digest,
};
void seedEntry;

// Lane holder shares are never recoverable: a linked device's share is sealed
// under that device's own factor and is reprovisioned, not restored.
const laneEntry: WalletRecoveryEnvelopeEntry = {
  // @ts-expect-error A recovery set carries the wallet custody seed only.
  custodySecretKind: 'ecdsa_lane_holder_share_v1',
  nonceB64u,
  wrappedCustodySecretB64u: ciphertextB64u,
  aadHashB64u: digest,
};
void laneEntry;

const entryWithUnknownKind: WalletRecoveryEnvelopeEntry = {
  // @ts-expect-error Entries name an exact custody-secret kind, not a generic holder share.
  custodySecretKind: 'holder_share_v1',
  nonceB64u,
  wrappedCustodySecretB64u: ciphertextB64u,
  aadHashB64u: digest,
};
void entryWithUnknownKind;

const entryWithRetiredKind: WalletRecoveryEnvelopeEntry = {
  // @ts-expect-error The retired per-curve owner root kinds no longer exist.
  custodySecretKind: 'ed25519_yao_client_root_v1',
  nonceB64u,
  wrappedCustodySecretB64u: ciphertextB64u,
  aadHashB64u: digest,
};
void entryWithRetiredKind;

const entryWithPlaintextSecret: WalletRecoveryEnvelopeEntry = {
  custodySecretKind: 'wallet_custody_seed_v1',
  nonceB64u,
  wrappedCustodySecretB64u: ciphertextB64u,
  aadHashB64u: digest,
  // @ts-expect-error Recovery entries must not carry plaintext custody material.
  custodySecretPlaintextB64u: 'secret',
};
void entryWithPlaintextSecret;

const manifestKekWrap: WalletRecoveryManifestKekWrap = {
  recoveryKeyId,
  nonceB64u,
  wrappedManifestKekB64u: ciphertextB64u,
  aadHashB64u: digest,
  lifecycle: activeRecoveryCode,
};
void manifestKekWrap;

const manifestKekWrapWithPlaintextKek: WalletRecoveryManifestKekWrap = {
  recoveryKeyId,
  nonceB64u,
  wrappedManifestKekB64u: ciphertextB64u,
  aadHashB64u: digest,
  lifecycle: activeRecoveryCode,
  // @ts-expect-error A manifest-KEK wrap must not carry the plaintext KEK.
  manifestKekB64u: 'kek',
};
void manifestKekWrapWithPlaintextKek;

const recoverySet: WalletRecoveryEnvelopeSetRecord = {
  kind: 'wallet_recovery_envelope_set_v1',
  walletId,
  manifestKekWraps: [manifestKekWrap],
  entries: [seedEntry],
  issuedAtMs: 1,
  updatedAtMs: 1,
};
void recoverySet;

// The set wraps the wallet's seed. Key sets carry their own manifests on their
// own registration state, so a set naming one would couple them again.
const recoverySetNamingAKeySet: WalletRecoveryEnvelopeSetRecord = {
  ...recoverySet,
  // @ts-expect-error A recovery set does not name a key manifest.
  keyManifestDigestB64u: digest,
};
void recoverySetNamingAKeySet;

const recoverySetWithPlaintextCode: WalletRecoveryEnvelopeSetRecord = {
  ...recoverySet,
  // @ts-expect-error Recovery sets must not contain plaintext recovery codes.
  recoveryCodePlaintext: 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH',
};
void recoverySetWithPlaintextCode;

const recoverySetWithGrant: WalletRecoveryEnvelopeSetRecord = {
  ...recoverySet,
  // @ts-expect-error A recovery code is a custody factor, never an authorization grant.
  authorizationGrantRef: 'grant',
};
void recoverySetWithGrant;

// @ts-expect-error A recovery set requires its manifest-KEK wraps.
const recoverySetWithoutKekWraps: WalletRecoveryEnvelopeSetRecord = {
  kind: 'wallet_recovery_envelope_set_v1',
  walletId,
  entries: [seedEntry],
  issuedAtMs: 1,
  updatedAtMs: 1,
};
void recoverySetWithoutKekWraps;

export {};
