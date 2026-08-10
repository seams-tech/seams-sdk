import type {
  DiscardedLaneHolderRecipientV1,
  OpenLaneHolderRecipientV1,
  SealedLaneHolderRecipientV1,
} from './recipientPreparation';
import {
  buildLaneActivationEffectPlanV1,
  type LaneActivationEffectPlanV1,
} from './activationCoordinator';
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

const invalidationPlan = buildLaneMaterialInvalidationPlanV1({
  target,
  reason: 'refresh',
  keyFamily: 'ecdsa_secp256k1',
});
invalidationPlan.orderedEffects;

