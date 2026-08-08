import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';

// A threshold-session id addresses runtime protocol state. Exact material
// selection uses the activation reference carried by the Ed25519 branch.

export type EmailOtpEcdsaSealedRuntimePurpose = {
  readonly thresholdSessionId: string;
  readonly chainTarget: ThresholdEcdsaChainTarget;
};

/** Discriminated warm-session lane purpose. */
export type WarmSessionLanePurpose =
  | ({
      readonly curve: 'ecdsa';
      readonly nearAccountId?: never;
    } & EmailOtpEcdsaSealedRuntimePurpose)
  | {
      readonly curve: 'ed25519';
      readonly materialActivation: MpcMaterialActivationRef;
      readonly thresholdSessionId?: never;
      readonly chainTarget?: never;
    };

export type WarmSessionMaterialOperationTarget =
  | {
      readonly purpose: Extract<WarmSessionLanePurpose, { curve: 'ecdsa' }>;
      readonly thresholdSessionId?: never;
    }
  | {
      readonly purpose: Extract<WarmSessionLanePurpose, { curve: 'ed25519' }>;
      readonly thresholdSessionId: string;
    };

export function warmSessionProtocolSessionId(
  target: WarmSessionMaterialOperationTarget,
): string {
  if (target.purpose.curve === 'ecdsa') return target.purpose.thresholdSessionId;
  if (target.thresholdSessionId === undefined) {
    throw new Error('Ed25519 warm material operation requires its protocol session id');
  }
  return target.thresholdSessionId;
}

export function ecdsaSealedRuntimePurpose(
  purpose: WarmSessionLanePurpose,
): EmailOtpEcdsaSealedRuntimePurpose | null {
  return purpose.curve === 'ecdsa'
    ? { thresholdSessionId: purpose.thresholdSessionId, chainTarget: purpose.chainTarget }
    : null;
}
