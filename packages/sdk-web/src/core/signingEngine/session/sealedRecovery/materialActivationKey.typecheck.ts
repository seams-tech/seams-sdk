import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import {
  ed25519DurableMaterialLocator,
  type Ed25519DurableMaterialLocator,
} from './materialActivationKey';

declare const materialActivation: MpcMaterialActivationRef;

const locator = ed25519DurableMaterialLocator({
  authMethod: 'passkey',
  materialActivation,
});
void locator;

const thresholdSessionLocator: Ed25519DurableMaterialLocator = {
  kind: 'ed25519_durable_material',
  authMethod: 'passkey',
  materialActivation,
  // @ts-expect-error Threshold session identity cannot locate durable Ed25519 material.
  thresholdSessionId: 'threshold-session-1',
};
void thresholdSessionLocator;

const signingGrantLocator: Ed25519DurableMaterialLocator = {
  kind: 'ed25519_durable_material',
  authMethod: 'email_otp',
  materialActivation,
  // @ts-expect-error Signing grant identity cannot locate durable Ed25519 material.
  signingGrantId: 'signing-grant-1',
};
void signingGrantLocator;

ed25519DurableMaterialLocator({
  authMethod: 'passkey',
  // @ts-expect-error Threshold session identity cannot replace the exact activation reference.
  thresholdSessionId: 'threshold-session-1',
});

ed25519DurableMaterialLocator({
  authMethod: 'email_otp',
  // @ts-expect-error Signing grant identity cannot replace the exact activation reference.
  signingGrantId: 'signing-grant-1',
});
