import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type {
  WarmSessionLanePurpose,
  WarmSessionMaterialOperationTarget,
} from './sealedRuntimePurpose';

declare const materialActivation: MpcMaterialActivationRef;

const ed25519Purpose: WarmSessionLanePurpose = {
  curve: 'ed25519',
  materialActivation,
};

const ed25519Operation: WarmSessionMaterialOperationTarget = {
  purpose: ed25519Purpose,
  thresholdSessionId: 'threshold-ed25519-session',
};
void ed25519Operation;

// @ts-expect-error Ed25519 material selection requires its exact activation.
const missingActivation: WarmSessionLanePurpose = {
  curve: 'ed25519',
  thresholdSessionId: 'threshold-ed25519-session',
};
void missingActivation;

// @ts-expect-error Threshold session identity cannot select Ed25519 material.
const sessionKeyedPurpose: WarmSessionLanePurpose = {
  curve: 'ed25519',
  materialActivation,
  thresholdSessionId: 'threshold-ed25519-session',
};
void sessionKeyedPurpose;

// @ts-expect-error Ed25519 worker operations still require protocol session identity separately.
const missingProtocolSession: WarmSessionMaterialOperationTarget = {
  purpose: ed25519Purpose,
};
void missingProtocolSession;
