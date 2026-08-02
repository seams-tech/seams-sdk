import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { SigningSessionSealAuthMethod } from '@shared/utils/signingSessionSeal';

export type Ed25519DurableMaterialLocator = {
  readonly kind: 'ed25519_durable_material';
  readonly authMethod: SigningSessionSealAuthMethod;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly thresholdSessionId?: never;
};

export function ed25519DurableMaterialLocator(args: {
  authMethod: SigningSessionSealAuthMethod;
  materialActivation: MpcMaterialActivationRef;
}): Ed25519DurableMaterialLocator {
  return {
    kind: 'ed25519_durable_material',
    authMethod: args.authMethod,
    materialActivation: args.materialActivation,
  };
}

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
