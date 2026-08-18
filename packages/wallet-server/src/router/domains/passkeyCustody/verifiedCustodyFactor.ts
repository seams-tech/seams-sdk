import {
  buildEmailOtpEnvelopeFactor,
  buildPasskeyEnvelopeFactor,
  type WalletCustodyEnvelopeFactor,
} from '@shared/passkey-custody';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';

/**
 * The custody factor for an envelope, resolved from the authority the
 * registration leg actually verified.
 *
 * This exists so a route never reads the factor off the ceremony payload. The
 * factor is what the envelope's AAD binds the seed to, so a payload-supplied
 * one would let a caller address a wallet's custody to a credential its owner
 * does not control. Taking it from `WalletAuthAuthority` means the envelope can
 * only ever name the credential this server just proved.
 *
 * A passkey authority carries everything the factor needs. An Email OTP
 * authority does not: the custody factor names the *enrollment* — its id and
 * seal key version — which live on the enrollment material the same leg
 * finalizes, not on the authority. So the OTP arm takes them explicitly, and
 * the caller must pass the enrollment it verified rather than one it looked up.
 */

export type VerifiedCustodyFactorResult =
  | { readonly ok: true; readonly factor: WalletCustodyEnvelopeFactor }
  | { readonly ok: false; readonly reason: string };

export type VerifiedEmailOtpEnrollmentFacts = {
  readonly enrollmentId: string;
  readonly enrollmentSealKeyVersion: string;
};

export function verifiedCustodyFactorFromAuthority(input: {
  readonly authority: WalletAuthAuthority;
  /** Required exactly when the authority is Email OTP. */
  readonly emailOtpEnrollment?: VerifiedEmailOtpEnrollmentFacts;
}): VerifiedCustodyFactorResult {
  const { authority } = input;

  if (isPasskeyWalletAuthAuthority(authority)) {
    // `verifier.rpId` rather than anything client-supplied: the RP id is what
    // the WebAuthn verification was performed against.
    const rpId = String(authority.verifier.rpId ?? '').trim();
    const credentialIdB64u = String(authority.factor.credentialIdB64u ?? '').trim();
    if (!rpId || !credentialIdB64u) {
      return { ok: false, reason: 'verified passkey authority is missing its credential identity' };
    }
    return {
      ok: true,
      factor: buildPasskeyEnvelopeFactor({
        rpId: authority.verifier.rpId,
        credentialIdB64u: authority.factor.credentialIdB64u,
      }),
    };
  }

  if (isEmailOtpWalletAuthAuthority(authority)) {
    const enrollment = input.emailOtpEnrollment;
    const enrollmentId = String(enrollment?.enrollmentId ?? '').trim();
    const enrollmentSealKeyVersion = String(enrollment?.enrollmentSealKeyVersion ?? '').trim();
    if (!enrollmentId || !enrollmentSealKeyVersion) {
      // Refused rather than defaulted: an envelope sealed against a guessed
      // enrollment would not open, and the failure would surface much later as
      // a wallet that cannot unlock.
      return {
        ok: false,
        reason: 'Email OTP custody requires the verified enrollment id and seal key version',
      };
    }
    return {
      ok: true,
      factor: buildEmailOtpEnvelopeFactor({ enrollmentId, enrollmentSealKeyVersion }),
    };
  }

  return { ok: false, reason: 'unsupported wallet auth authority for custody' };
}
