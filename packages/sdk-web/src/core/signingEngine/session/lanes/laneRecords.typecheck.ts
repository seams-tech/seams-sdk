import type { SigningLaneReference } from '@shared/signing-lanes';
import type { WalletId } from '@shared/utils/domainIds';
import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '@shared/signing-lanes';

declare const walletId: WalletId;
declare const walletKeyId: WalletKeyId;
declare const laneId: SigningLaneId;
declare const laneShareEpoch: LaneShareEpoch;

const lane: SigningLaneReference = {
  kind: 'signing_lane_reference_v1',
  walletId,
  walletKeyId,
  laneId,
  laneKind: 'linked_device',
  laneShareEpoch,
};
void lane;

const invalidLane: SigningLaneReference = {
  kind: 'signing_lane_reference_v1',
  walletId,
  walletKeyId,
  laneId,
  laneKind: 'linked_device',
  // @ts-expect-error Lane references require laneShareEpoch.
  thresholdSessionId: 'threshold-session',
};
void invalidLane;

export {};
