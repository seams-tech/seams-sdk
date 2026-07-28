import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { AccountId } from '@/core/types/accountIds';

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
      /** Present wherever the caller already holds it. Not every warm-session
       * claim site carries a Near identity today, and requiring one here would
       * force it through paths that have no other use for it. The invariant
       * this union exists to enforce -- ECDSA is inexpressible without its
       * chain target, and Ed25519 cannot carry one -- holds regardless. */
      readonly nearAccountId?: AccountId;
      readonly chainTarget?: never;
    };

export function ecdsaSealedRuntimePurpose(
  purpose: WarmSessionLanePurpose,
): EmailOtpEcdsaSealedRuntimePurpose | null {
  return purpose.curve === 'ecdsa'
    ? { thresholdSessionId: purpose.thresholdSessionId, chainTarget: purpose.chainTarget }
    : null;
}
