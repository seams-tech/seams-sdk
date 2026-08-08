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

ed25519DurableMaterialLocator({
  authMethod: 'passkey',
  // @ts-expect-error Threshold session identity cannot replace the exact activation reference.
  thresholdSessionId: 'threshold-session-1',
});
