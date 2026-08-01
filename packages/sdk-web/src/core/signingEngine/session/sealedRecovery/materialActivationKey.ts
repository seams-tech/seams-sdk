import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';

export function materialActivationKey(activation: MpcMaterialActivationRef): string {
  return [
    activation.activationId,
    activation.capability,
    activation.materialOwner,
    activation.keyBinding,
    activation.lifecycleBinding,
    activation.signingWorker,
  ]
    .map((part) => encodeURIComponent(String(part)))
    .join(':');
}
