import type { WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { WalletId } from '@shared/utils/domainIds';
import {
  admitWalletCustodyRegistrationCommit,
  type WalletCustodyRegistrationAdmissionOutcome,
} from './walletCustodyRegistrationAdmission';
import type { WalletCustodyCeremonyCommitPayload } from './walletCustodyRegistrationCommit';
import {
  verifiedCustodyFactorFromAuthority,
  type VerifiedEmailOtpEnrollmentFacts,
} from './verifiedCustodyFactor';
import type { CloudflareD1WalletCustodyCommitStore } from '../../cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';

/**
 * What a registration leg reports back about the custody it was asked to
 * commit.
 *
 * This is the whole custody side-effect of activation, in one call: resolve the
 * factor from the authority the leg verified, then admit the payload against
 * the wallet the leg registered.
 *
 * **Activation never fails because of custody.** The wallet's registration is
 * already committed by the time this runs, and the seed exists only in the
 * client's worker — so the client is the one party that can retry, re-enter as
 * a join, or abandon the run. Failing activation here would leave the server
 * registered, the response an error, and the client with no instruction; the
 * client cannot be told what happened by an exception it never sees the body
 * of. So every outcome is reported, and the caller decides.
 *
 * That is a deliberate default, not a claim that a wallet without custody is
 * fine — it is not, and a client that sees anything but `committed` or
 * `not_requested` must act on it rather than treat registration as done.
 */
export type RegistrationCustodyOutcome =
  /** No custody payload rode this activation. Registration is unaffected. */
  | { readonly status: 'not_requested' }
  | { readonly status: 'committed' }
  /**
   * A joining run: this key set's manifest digest, with no custody records
   * written because the wallet already has its envelope and recovery set.
   */
  | { readonly status: 'joined'; readonly keyManifestDigestB64u: string }
  /**
   * Another ceremony established this wallet's custody first. The client must
   * discard its run's seed and re-enter as a join of the existing envelope.
   */
  | { readonly status: 'custody_already_established' }
  /** The payload was refused. Nothing was written. */
  | { readonly status: 'rejected'; readonly reason: string };

export async function commitRegistrationCustody(input: {
  /** Absent when the client did not run a custody ceremony for this leg. */
  readonly payload?: WalletCustodyCeremonyCommitPayload;
  readonly verifiedWalletId: WalletId;
  readonly verifiedAuthority: WalletAuthAuthority;
  /** Required when the verified authority is Email OTP. */
  readonly verifiedEmailOtpEnrollment?: VerifiedEmailOtpEnrollmentFacts;
  readonly nowMs: number;
  readonly store: CloudflareD1WalletCustodyCommitStore;
}): Promise<RegistrationCustodyOutcome> {
  if (!input.payload) return { status: 'not_requested' };

  const factor = verifiedCustodyFactorFromAuthority({
    authority: input.verifiedAuthority,
    ...(input.verifiedEmailOtpEnrollment
      ? { emailOtpEnrollment: input.verifiedEmailOtpEnrollment }
      : {}),
  });
  if (!factor.ok) return { status: 'rejected', reason: factor.reason };

  return toOutcome(
    await admitWalletCustodyRegistrationCommit({
      payload: input.payload,
      verifiedWalletId: input.verifiedWalletId,
      verifiedFactor: factor.factor,
      nowMs: input.nowMs,
      store: input.store,
    }),
  );
}

function toOutcome(
  admitted: WalletCustodyRegistrationAdmissionOutcome,
): RegistrationCustodyOutcome {
  switch (admitted.kind) {
    case 'committed':
      return { status: 'committed' };
    case 'no_custody_records':
      return { status: 'joined', keyManifestDigestB64u: admitted.keyManifestDigestB64u };
    case 'custody_already_established':
      return { status: 'custody_already_established' };
    case 'already_exists':
      // The same ceremony's records are already stored. Treated as committed
      // because it is exactly what a retried activation looks like, and the
      // client's next step is identical.
      return { status: 'committed' };
    case 'rejected':
      return { status: 'rejected', reason: admitted.reason };
  }
}
