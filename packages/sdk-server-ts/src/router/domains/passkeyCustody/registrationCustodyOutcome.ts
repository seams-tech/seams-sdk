import type { WalletCustodyRegistrationOutcome } from '@shared/passkey-custody';
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
 * The whole custody side-effect of one registration leg, in one call: resolve
 * the factor from the authority the leg verified, then admit the payload
 * against the wallet the leg registered.
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
 *
 * The outcome shape itself is the wire contract, and lives in shared beside the
 * payload it answers.
 */
export type RegistrationCustodyOutcome = WalletCustodyRegistrationOutcome;

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

  try {
    return toOutcome(
      await admitWalletCustodyRegistrationCommit({
        payload: input.payload,
        verifiedWalletId: input.verifiedWalletId,
        verifiedFactor: factor.factor,
        nowMs: input.nowMs,
        store: input.store,
      }),
    );
  } catch (error: unknown) {
    /* The store itself failed — D1 refused the write, or the batch threw. The
       payload parser already turns malformed input into `rejected`, so
       reaching here means infrastructure, and the policy above is exactly what
       must hold when infrastructure fails: the registration this leg already
       committed must not be reported as an error because custody could not be
       stored. The client is told, and retries. */
    return {
      status: 'rejected',
      reason: error instanceof Error ? error.message : 'wallet custody commit failed',
    };
  }
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
