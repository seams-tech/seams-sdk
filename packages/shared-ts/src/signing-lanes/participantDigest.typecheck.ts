import { computeLaneParticipantSetBindingDigestV1 } from './participantDigest';
import type {
  LaneHolderParticipantRecordV1,
  SigningWorkerParticipantRecordV1,
} from './participants';

declare const holderParticipant: LaneHolderParticipantRecordV1;
declare const signingWorkerParticipant: SigningWorkerParticipantRecordV1;

const aggregateDigest = computeLaneParticipantSetBindingDigestV1({
  holderParticipant,
  signingWorkerParticipant,
});
void aggregateDigest;

void computeLaneParticipantSetBindingDigestV1({
  // @ts-expect-error The fixed participant-set order rejects role substitution.
  holderParticipant: signingWorkerParticipant,
  // @ts-expect-error The fixed participant-set order rejects role substitution.
  signingWorkerParticipant: holderParticipant,
});

export {};
