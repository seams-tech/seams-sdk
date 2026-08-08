import type { WalletId } from '@shared/utils/domainIds';
import type { WalletCustodyEnvelopeFactor } from '@shared/passkey-custody';
import {
  commitWalletCustodyRegistration,
  type WalletCustodyCeremonyCommitPayload,
  type WalletCustodyRegistrationCommitOutcome,
} from './walletCustodyRegistrationCommit';
import type { CloudflareD1WalletCustodyCommitStore } from '../../cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';

/**
 * Admits one ceremony's custody commit against a registration this server has
 * already verified.
 *
 * The custody commit has no route of its own. It rides the registration's
 * activate/finalize leg, because what may establish custody for a wallet is
 * exactly what may create that wallet: the verified signed setup plus that
 * leg's own auth proof. A separate endpoint would be a second, weaker way in.
 *
 * This module is where that decision is enforced, and it is deliberately the
 * only path to `commitWalletCustodyRegistration` from a route. Two checks, both
 * cheap and both load-bearing:
 *
 * 1. **The payload names the wallet the registration named.** A ceremony
 *    payload is client-supplied; without this, a caller holding a valid
 *    registration for their own wallet could commit an envelope under someone
 *    else's `walletId`.
 * 2. **The factor comes from the credential this server just verified**, never
 *    from the payload. The factor is what the envelope's AAD binds the seed to,
 *    so a payload-supplied factor could address a wallet's custody to a
 *    credential its owner does not control.
 *
 * A joining run commits nothing here: its output is a manifest digest that
 * rides the key set's own registration state, so it is admitted and reported
 * without touching the custody store.
 */

export type WalletCustodyRegistrationAdmissionOutcome =
  | WalletCustodyRegistrationCommitOutcome
  /**
   * The run joined custody that already existed. Nothing to write — the wallet
   * already has its seed envelope and recovery set, and this key set's manifest
   * digest belongs on its registration state.
   */
  | { readonly kind: 'no_custody_records'; readonly keyManifestDigestB64u: string };

export type WalletCustodyRegistrationAdmissionInput = {
  /** What the ceremony produced. Client-supplied, therefore untrusted. */
  readonly payload: WalletCustodyCeremonyCommitPayload;
  /** The wallet this server verified the registration for. */
  readonly verifiedWalletId: WalletId;
  /**
   * Built from the credential the registration leg verified — the WebAuthn
   * credential just created, or the Email OTP enrollment just proved. Never
   * read off the payload.
   */
  readonly verifiedFactor: WalletCustodyEnvelopeFactor;
  readonly nowMs: number;
  readonly store: CloudflareD1WalletCustodyCommitStore;
};

export async function admitWalletCustodyRegistrationCommit(
  input: WalletCustodyRegistrationAdmissionInput,
): Promise<WalletCustodyRegistrationAdmissionOutcome> {
  const payloadWalletId = String(input.payload.walletId ?? '').trim();
  if (!payloadWalletId) {
    return { kind: 'rejected', reason: 'wallet custody commit payload names no wallet' };
  }
  if (payloadWalletId !== String(input.verifiedWalletId)) {
    // Refused before the store is touched, and without echoing the claimed id:
    // the caller learns their payload was refused, not which wallet exists.
    return {
      kind: 'rejected',
      reason: 'wallet custody commit payload does not name the registered wallet',
    };
  }

  const digest = String(input.payload.keyManifestDigestB64u ?? '').trim();
  if (!digest) {
    return { kind: 'rejected', reason: 'wallet custody commit payload carries no manifest digest' };
  }

  // A joining run writes no custody records. Reporting it here rather than
  // letting the adapter throw keeps "nothing to write" distinct from "this
  // payload is malformed" — the caller must be able to tell them apart.
  if (!input.payload.establishedCustody) {
    return { kind: 'no_custody_records', keyManifestDigestB64u: digest };
  }

  return await commitWalletCustodyRegistration({
    payload: input.payload,
    factor: input.verifiedFactor,
    nowMs: input.nowMs,
    store: input.store,
  });
}
