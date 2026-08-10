import type {
  DiscardedLaneHolderRecipientV1,
  OpenLaneHolderRecipientV1,
  SealedLaneHolderRecipientV1,
} from './recipientPreparation';
import {
  buildLaneActivationEffectPlanV1,
  type LaneActivationChildInputV1,
  type LaneActivationEffectPlanV1,
} from './activationCoordinator';
import type {
  EcdsaAdditiveLaneJobV1,
  LaneHolderDeliveryReceiptV1,
  LaneProtocolCommitReceiptV1,
  LaneRefreshPredecessorRetirementV1,
  LaneServerActivationReceiptV1,
} from '@shared/signing-lanes';
import {
  buildLaneMaterialInvalidationPlanV1,
  type ExactLaneMaterialInvalidationTargetV1,
} from './laneMaterialInvalidation';

declare const open: OpenLaneHolderRecipientV1;
declare const sealed: SealedLaneHolderRecipientV1;
declare const discarded: DiscardedLaneHolderRecipientV1;
declare const target: ExactLaneMaterialInvalidationTargetV1;

function consumeOpen(value: OpenLaneHolderRecipientV1): void {
  value.recipientHandle;
}

function consumeSealed(value: SealedLaneHolderRecipientV1): void {
  value.sealedHolderMaterialB64u;
}

function consumeDiscarded(value: DiscardedLaneHolderRecipientV1): void {
  value.state;
}

consumeOpen(open);
consumeSealed(sealed);
consumeDiscarded(discarded);

// @ts-expect-error A sealed recipient cannot be reused as an open recipient.
consumeOpen(sealed);
// @ts-expect-error A discarded recipient cannot be reused as an open recipient.
consumeOpen(discarded);

declare const activationPlanInput: Parameters<typeof buildLaneActivationEffectPlanV1>[0];
declare const activationPlan: LaneActivationEffectPlanV1;
void buildLaneActivationEffectPlanV1(activationPlanInput);
void activationPlan.commitCommand;

declare const refreshJob: Extract<
  EcdsaAdditiveLaneJobV1,
  { target: { operation: 'refresh_lane' } }
>;
declare const protocolCommitReceipt: LaneProtocolCommitReceiptV1;
declare const holderDeliveryReceipt: LaneHolderDeliveryReceiptV1;
declare const serverActivationReceipt: LaneServerActivationReceiptV1;
declare const predecessorRetirement: LaneRefreshPredecessorRetirementV1;

const refreshActivationChild: LaneActivationChildInputV1 = {
  job: refreshJob,
  protocolCommitReceipt,
  holderDeliveryReceipt,
  serverActivationReceipt,
  predecessorRetirement,
};
void refreshActivationChild;

// @ts-expect-error A refresh target cannot reach activation without exact predecessor retirement.
const refreshWithoutRetirement: LaneActivationChildInputV1 = {
  job: refreshJob,
  protocolCommitReceipt,
  holderDeliveryReceipt,
  serverActivationReceipt,
};
void refreshWithoutRetirement;

const invalidationPlan = buildLaneMaterialInvalidationPlanV1({
  target,
  reason: 'refresh',
  keyFamily: 'ecdsa_secp256k1',
});
invalidationPlan.orderedEffects;
