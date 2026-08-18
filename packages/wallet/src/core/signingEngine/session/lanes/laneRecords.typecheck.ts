import { parseLaneParticipantBindingDigestB64u, type SigningLaneReference } from '@shared/signing-lanes';
import type { WalletId } from '@shared/utils/domainIds';
import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '@shared/signing-lanes';

declare const walletId: WalletId;
declare const walletKeyId: WalletKeyId;
declare const laneId: SigningLaneId;
declare const laneShareEpoch: LaneShareEpoch;
const participantBindingDigestB64u = parseLaneParticipantBindingDigestB64u(
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
);
if (!participantBindingDigestB64u.ok) throw new Error(participantBindingDigestB64u.error.message);

const lane: SigningLaneReference = {
  kind: 'signing_lane_reference_v1',
  walletId,
  walletKeyId,
  laneId,
  laneKind: 'linked_device',
  laneShareEpoch,
  participantBindingDigestB64u: participantBindingDigestB64u.value,
};
void lane;

const invalidLane: SigningLaneReference = {
  kind: 'signing_lane_reference_v1',
  walletId,
  walletKeyId,
  laneId,
  laneKind: 'linked_device',
  participantBindingDigestB64u: participantBindingDigestB64u.value,
  // @ts-expect-error Lane references require laneShareEpoch.
  thresholdSessionId: 'threshold-session',
};
void invalidLane;

export {};
