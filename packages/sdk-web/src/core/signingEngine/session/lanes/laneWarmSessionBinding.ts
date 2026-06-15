import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '@shared/signing-lanes';

export type LaneWarmSessionBinding = {
  kind: 'lane_warm_session_binding_v1';
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  walletSigningSessionId: string;
  thresholdSessionId: string;
};
