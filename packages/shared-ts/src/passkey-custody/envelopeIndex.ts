import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '../signing-lanes/ids';
import type { PasskeyEnvelopeId, WalletId } from '../utils/domainIds';
import type {
  PasskeyCustodyEnvelopeLifecycle,
  WalletCustodyEnvelopeFactor,
} from './custodyEnvelope';
import type { PasskeyCustodySecretKind } from './custodySecretBinding';

/**
 * Public listing row for factor management: which factor protects which custody
 * secret, under which envelope. It holds no ciphertext, so listing a wallet's
 * enrolled factors never moves sealed custody material.
 *
 * Lane scope is optional because owner custody is wallet-scoped: a
 * `wallet_custody_seed_v1` row covers every owner key and carries no lane,
 * while a lane holder-share row names exactly one lane.
 */
export type PasskeyDeviceEnvelopeIndexRecord = {
  kind: 'wallet_custody_envelope_index_v2';
  walletId: WalletId;
  custodySecretKind: PasskeyCustodySecretKind;
  factor: WalletCustodyEnvelopeFactor;
  envelopeId: PasskeyEnvelopeId;
  /** Absent until the owner chooses a name for this credential. */
  deviceLabel?: string;
  lifecycle: PasskeyCustodyEnvelopeLifecycle;
  walletKeyId?: WalletKeyId;
  laneId?: SigningLaneId;
  laneShareEpoch?: LaneShareEpoch;
  createdAtMs: number;
  updatedAtMs: number;
};
