import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';

/**
 * Whether one custody envelope may be revoked.
 *
 * **The rule that needs a list, not a lookup.** Revoking an envelope removes
 * one factor's way into the wallet's custody seed. Doing that to the *last*
 * active envelope leaves a wallet whose seed no factor can open — recoverable
 * only by a recovery code, and only if the owner still has one. That is a
 * support incident, not an error the user sees at the time, because revocation
 * would appear to succeed.
 *
 * So the decision is a function of the wallet's whole envelope set, which is
 * why `listWalletEnvelopes` exists. A per-envelope lookup cannot answer it.
 *
 * Removing a synced passkey is the case this is written for: the same custody
 * secret is protected by another active envelope, so the lane stays open and
 * the removal is safe.
 */

export type EnvelopeRevocationAdmission =
  | { readonly kind: 'admitted' }
  | { readonly kind: 'refused'; readonly reason: string };

export function admitEnvelopeRevocation(input: {
  /** The wallet's envelopes, as stored. */
  readonly envelopes: readonly PasskeyCustodyEnvelopeRecord[];
  /** The envelope the caller wants revoked. */
  readonly envelopeId: string;
}): EnvelopeRevocationAdmission {
  const envelopeId = String(input.envelopeId || '').trim();
  if (!envelopeId) {
    return { kind: 'refused', reason: 'revocation names no envelope' };
  }

  const target = input.envelopes.find((envelope) => String(envelope.envelopeId) === envelopeId);
  if (!target) {
    return { kind: 'refused', reason: 'the wallet has no such envelope' };
  }
  if (target.lifecycle.state === 'revoked') {
    // Idempotent from the caller's side, but reported: a second revocation is
    // usually a client that lost track of the first, not a new intent.
    return { kind: 'refused', reason: 'envelope is already revoked' };
  }

  const remainingActive = input.envelopes.filter(
    (envelope) =>
      envelope.lifecycle.state === 'active' && String(envelope.envelopeId) !== envelopeId,
  );
  if (remainingActive.length === 0) {
    return {
      kind: 'refused',
      reason:
        'revoking the last active envelope would leave the wallet custody seed with no factor that can open it',
    };
  }
  return { kind: 'admitted' };
}
