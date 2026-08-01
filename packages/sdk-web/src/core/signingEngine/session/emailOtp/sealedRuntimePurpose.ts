import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

// A threshold-session id indexes runtime state; it never selects material. To
// read the one sealed record a session refers to, the exact store API needs the
// lane it belongs to as well, so the id is only ever carried alongside its lane
// purpose. The lane policy that produced the session already owns that target.

export type EmailOtpEcdsaSealedRuntimePurpose = {
  readonly thresholdSessionId: string;
  readonly chainTarget: ThresholdEcdsaChainTarget;
};

/** Discriminated warm-session lane purpose. ECDSA cannot be expressed without a
 * chain target and Ed25519 cannot be expressed without its Near identity, so a
 * cross-curve combination does not compile. */
export type WarmSessionLanePurpose =
  | ({
      readonly curve: 'ecdsa';
      readonly nearAccountId?: never;
    } & EmailOtpEcdsaSealedRuntimePurpose)
  | {
      readonly curve: 'ed25519';
      readonly thresholdSessionId: string;
      readonly chainTarget?: never;
    };

export function ecdsaSealedRuntimePurpose(
  purpose: WarmSessionLanePurpose,
): EmailOtpEcdsaSealedRuntimePurpose | null {
  return purpose.curve === 'ecdsa'
    ? { thresholdSessionId: purpose.thresholdSessionId, chainTarget: purpose.chainTarget }
    : null;
}
