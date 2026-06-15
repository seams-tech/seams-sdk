import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '../signing-lanes/ids';
import type { WalletId } from '../utils/domainIds';
import type { DerivedWalletRecoveryKeyId } from './recoveryCodes';

export type RecoveryCodeLifecycleState =
  | {
      state: 'active';
      issuedAtMs: number;
      consumedAtMs?: never;
      revokedAtMs?: never;
    }
  | {
      state: 'consumed';
      issuedAtMs: number;
      consumedAtMs: number;
      revokedAtMs?: never;
    }
  | {
      state: 'revoked';
      issuedAtMs: number;
      revokedAtMs: number;
      consumedAtMs?: never;
    };

export type RecoveryWrappedHolderShareEnvelopeRecord = {
  kind: 'recovery_wrapped_holder_share_envelope_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  recoveryKeyId: DerivedWalletRecoveryKeyId;
  recoveryKeyStatus: RecoveryCodeLifecycleState;
  recoveryEnvelopeVersion: string;
  nonceB64u: string;
  wrappedHolderShareB64u: string;
  aadHashB64u: string;
  issuedAtMs: number;
  updatedAtMs: number;
};
