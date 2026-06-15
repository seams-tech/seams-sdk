import type { WalletId } from '../utils/domainIds';
import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '../signing-lanes/ids';
import type { DerivedWalletRecoveryKeyId } from './recoveryCodes';
import type {
  RecoveryCodeLifecycleState,
  RecoveryWrappedHolderShareEnvelopeRecord,
} from './recoveryEnvelopes';

declare const walletId: WalletId;
declare const walletKeyId: WalletKeyId;
declare const laneId: SigningLaneId;
declare const laneShareEpoch: LaneShareEpoch;
declare const recoveryKeyId: DerivedWalletRecoveryKeyId;

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

const envelope: RecoveryWrappedHolderShareEnvelopeRecord = {
  kind: 'recovery_wrapped_holder_share_envelope_v1',
  walletId,
  walletKeyId,
  laneId,
  laneShareEpoch,
  recoveryKeyId,
  recoveryKeyStatus: activeRecoveryCode,
  recoveryEnvelopeVersion: 'v1',
  nonceB64u: 'nonce',
  wrappedHolderShareB64u: 'ciphertext',
  aadHashB64u: 'aad',
  issuedAtMs: 1,
  updatedAtMs: 1,
};
void envelope;

const invalidEnvelope: RecoveryWrappedHolderShareEnvelopeRecord = {
  kind: 'recovery_wrapped_holder_share_envelope_v1',
  walletId,
  walletKeyId,
  laneId,
  laneShareEpoch,
  recoveryKeyId,
  recoveryKeyStatus: activeRecoveryCode,
  recoveryEnvelopeVersion: 'v1',
  nonceB64u: 'nonce',
  wrappedHolderShareB64u: 'ciphertext',
  aadHashB64u: 'aad',
  issuedAtMs: 1,
  updatedAtMs: 1,
  // @ts-expect-error Recovery envelopes must not contain plaintext recovery codes.
  recoveryCodePlaintext: 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH',
};
void invalidEnvelope;

export {};
