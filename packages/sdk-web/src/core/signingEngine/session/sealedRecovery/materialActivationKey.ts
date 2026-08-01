import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';

export type Ed25519DurableMaterialLocator = {
  readonly kind: 'ed25519_durable_material';
  readonly authMethod: 'passkey' | 'email_otp';
  readonly materialActivation: MpcMaterialActivationRef;
  readonly thresholdSessionId?: never;
  readonly signingGrantId?: never;
};

export function ed25519DurableMaterialLocator(args: {
  authMethod: Ed25519DurableMaterialLocator['authMethod'];
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
