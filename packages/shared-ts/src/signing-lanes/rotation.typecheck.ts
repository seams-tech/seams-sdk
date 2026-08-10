import type {
  EcdsaAdditiveLaneCreationJobV1,
  EcdsaAdditiveLaneJobV1,
  CompleteSigningLaneRevocationV1,
  Ed25519YaoLaneCreationJobV1,
  LaneServerRetirementReceiptV1,
  LaneCreationTargetV1,
  LaneHolderPackageWireV1,
  LaneProductEpochActiveV1,
  LaneProductEpochPendingVisibilityV1,
  LaneProductEpochRevocationPendingV1,
  LaneProductEpochRevokedV1,
  LaneRefreshTargetV1,
} from './rotation';
import type { MpcMaterialActivationRef } from '../utils/domainIds';

declare const activation: MpcMaterialActivationRef;
declare const creationTarget: LaneCreationTargetV1;
declare const refreshTarget: LaneRefreshTargetV1;
declare const ed25519CreationJob: Ed25519YaoLaneCreationJobV1;
declare const ecdsaCreationJob: EcdsaAdditiveLaneCreationJobV1;
declare const activeEpoch: LaneProductEpochActiveV1;
declare const pendingEpoch: LaneProductEpochPendingVisibilityV1;
declare const revocationPendingEpoch: LaneProductEpochRevocationPendingV1;
declare const revokedEpoch: LaneProductEpochRevokedV1;
declare const serverRetirementReceipt: LaneServerRetirementReceiptV1;
declare const digestOnlyRevocationCompletion: Omit<
  CompleteSigningLaneRevocationV1,
  'retirementReceipt'
> & { readonly retirementReceiptDigestB64u: string };

// Creation never carries a prior activation. Refresh always carries one.
const invalidCreationTarget: LaneCreationTargetV1 = {
  ...creationTarget,
  // @ts-expect-error creation target cannot carry a prior material activation
  priorMaterialActivation: activation,
};

const invalidRefreshTarget: LaneRefreshTargetV1 = {
  ...refreshTarget,
  // @ts-expect-error refresh target cannot omit its prior material activation
  priorMaterialActivation: undefined,
};

// Curve-specific jobs reject fields owned by the other curve.
// @ts-expect-error Ed25519 jobs cannot be assigned an ECDSA job
const invalidCurveJob: Ed25519YaoLaneCreationJobV1 = ecdsaCreationJob;

// ECDSA jobs cannot be assigned an Ed25519 job.
// @ts-expect-error ECDSA jobs cannot be assigned an Ed25519 job
const invalidReverseCurveJob: EcdsaAdditiveLaneCreationJobV1 = ed25519CreationJob;

// A visible product epoch always retains the exact material activation.
const invalidActiveEpoch: LaneProductEpochActiveV1 = {
  ...activeEpoch,
  // @ts-expect-error active product epochs cannot drop exact activation identity
  materialActivation: undefined,
};

const invalidActiveEpochParticipantSet: LaneProductEpochActiveV1 = {
  ...activeEpoch,
  // @ts-expect-error Product epochs require the complete holder participant.
  holderParticipant: undefined,
};

const invalidActiveEpochRevocationEpoch: LaneProductEpochActiveV1 = {
  ...activeEpoch,
  // @ts-expect-error Every product epoch state carries its revocation epoch.
  revocationEpoch: undefined,
};

// Pending visibility also carries the exact private activation reference; it is
// fenced from active/retired/revoked-only fields.
const invalidPendingEpoch: LaneProductEpochPendingVisibilityV1 = {
  ...pendingEpoch,
  // @ts-expect-error pending visibility cannot expose an activation timestamp
  activatedAtMs: 1,
};

const invalidRevocationPendingReceipt: LaneProductEpochRevocationPendingV1 = {
  ...revocationPendingEpoch,
  // @ts-expect-error pending revocation cannot claim a participant retirement receipt
  revocationReceiptDigestB64u: revokedEpoch.revocationReceiptDigestB64u,
};

// @ts-expect-error a fenced lane is not fully revoked until a participant receipt is committed
const invalidCompletedRevocation: LaneProductEpochRevokedV1 = revocationPendingEpoch;

// @ts-expect-error completion requires the exact participant-issued receipt
const invalidDigestOnlyCompletion: CompleteSigningLaneRevocationV1 = digestOnlyRevocationCompletion;

void invalidCreationTarget;
void invalidRefreshTarget;
void invalidCurveJob;
void invalidReverseCurveJob;
void invalidActiveEpoch;
void invalidActiveEpochParticipantSet;
void invalidActiveEpochRevocationEpoch;
void invalidPendingEpoch;
void invalidRevocationPendingReceipt;
void invalidCompletedRevocation;
void invalidDigestOnlyCompletion;
void serverRetirementReceipt;

// @ts-expect-error Ed25519 holder packages cannot carry ECDSA envelopes
const invalidEd25519HolderPackage: LaneHolderPackageWireV1 = {
  kind: 'ed25519_yao_lane_holder_package_set_v1',
  deriverAEncryptedPackageJson: '{}',
  deriverBEncryptedPackageJson: '{}',
  ecdsaEncryptedMaterialEnvelopeJson: '{}',
};

// @ts-expect-error ECDSA holder packages cannot carry Yao Deriver packages
const invalidEcdsaHolderPackage: LaneHolderPackageWireV1 = {
  kind: 'ecdsa_additive_lane_holder_package_v1',
  ecdsaEncryptedMaterialEnvelopeJson: '{}',
  deriverAEncryptedPackageJson: '{}',
};

void invalidEd25519HolderPackage;
void invalidEcdsaHolderPackage;
