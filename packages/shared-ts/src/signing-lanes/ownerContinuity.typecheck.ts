import type { MpcSigningWorkerRef } from '../utils/domainIds';
import type { DigestB64u } from '../utils/canonicalPrimitives';
import {
  buildOwnerLaneParticipantContinuityV1,
  computeOwnerLaneParticipantBindingDigestV1,
  parseOwnerLaneParticipantContinuityV1,
  type OwnerLaneParticipantContinuityV1,
  type WalletSignerId,
} from './ownerContinuity';

declare const signerId: WalletSignerId;
declare const signingWorkerId: MpcSigningWorkerRef;
declare const digest: DigestB64u;

const ownerContinuity: OwnerLaneParticipantContinuityV1 = buildOwnerLaneParticipantContinuityV1({
  signerId,
  participantIds: [1, 2],
  signingWorkerId,
  custodyKeyManifestDigestB64u: digest,
  sourceIdentityDigestB64u: digest,
});

const parsedOwnerContinuity: OwnerLaneParticipantContinuityV1 =
  parseOwnerLaneParticipantContinuityV1(ownerContinuity);
const ownerBindingDigest = computeOwnerLaneParticipantBindingDigestV1(parsedOwnerContinuity);
void ownerBindingDigest;

const invalidSignerId: OwnerLaneParticipantContinuityV1 = {
  ...ownerContinuity,
  // @ts-expect-error Owner continuity must retain the branded signer identity.
  signerId: 'wallet-signer:raw',
};
void invalidSignerId;

const invalidSigningWorkerId: OwnerLaneParticipantContinuityV1 = {
  ...ownerContinuity,
  // @ts-expect-error Owner continuity must retain the MPC signing-worker reference.
  signingWorkerId: 'signing-worker:raw',
};
void invalidSigningWorkerId;

const invalidParticipantTuple: OwnerLaneParticipantContinuityV1 = {
  ...ownerContinuity,
  // @ts-expect-error Owner continuity requires exactly two participant ids.
  participantIds: [1, 2, 3],
};
void invalidParticipantTuple;

const invalidMissingDigest: OwnerLaneParticipantContinuityV1 = {
  ...ownerContinuity,
  // @ts-expect-error Both continuity digests are required.
  sourceIdentityDigestB64u: undefined,
};
void invalidMissingDigest;

export {};
