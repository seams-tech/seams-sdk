/**
 * Refactor 103 Phase 8 — proving the approval's ceremony is the server's own.
 *
 * The approval digest makes the ceremony immutable *after* the approval is
 * accepted. It says nothing about where the ceremony came from: Device 1
 * assembles the approval body, so without this check a caller could name a
 * ceremony belonging to another wallet, or submit registration options that
 * never came from any ceremony, and the digest would faithfully seal the lie.
 *
 * So before an approval is recorded, the ceremony it carries is re-read from
 * the server's own records and compared field for field against what was
 * submitted. Provenance first, immutability second.
 *
 * The Email OTP branch has no add-auth-method ceremony. Its server-owned facts
 * are the wallet's one active verified base Email OTP factor and the masked
 * destination hint derived from it, so provenance for that branch means: the
 * factor the approval names is the factor the server resolves for that wallet,
 * and the hint is the server's own masking — never one Device 1 or Device 2
 * chose.
 */
import type { LinkedDeviceApprovalV1 } from '@shared/device-linking/contracts';
import type { WalletAddAuthMethodRegistrationOptions } from '@shared/utils/addAuthMethodRegistration';
import type { WalletAuthMethodId } from '@shared/utils/domainIds';
import type { WalletId } from '@shared/utils/domainIds';
import { alphabetizeStringify } from '@shared/utils/digests';
import type { StoredWalletAddAuthMethodCeremony } from '../RegistrationCeremonyStore';

export type LinkedOwnerEnrollmentProvenanceDeniedV1 =
  | 'ceremony_not_found'
  | 'ceremony_is_not_a_passkey_ceremony'
  | 'ceremony_belongs_to_another_wallet'
  | 'ceremony_relying_party_does_not_match'
  | 'ceremony_registration_options_do_not_match'
  | 'ceremony_expiry_does_not_match'
  | 'ceremony_expired'
  | 'email_otp_base_factor_unavailable'
  | 'email_otp_base_factor_does_not_match'
  | 'email_otp_masked_hint_does_not_match';

export type LinkedOwnerEnrollmentProvenanceResultV1 =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: LinkedOwnerEnrollmentProvenanceDeniedV1 };

/**
 * Reads back the ceremony an approval claims, by id alone.
 *
 * Deliberately the exact shape of `RegistrationCeremonyStore`'s own reader, so
 * the existing store satisfies it structurally and no adapter stands between
 * the check and the record it is checking against.
 */
export type LinkedOwnerEnrollmentCeremonyReaderV1 = {
  getAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null>;
};

/**
 * Resolves the one active verified base Email OTP factor for a wallet, along
 * with the server-derived masked destination hint. Returning `null` means no
 * eligible factor exists — which refuses the approval outright rather than
 * letting an enrollment proceed against a factor the wallet does not hold.
 */
export type LinkedOwnerEmailOtpBaseFactorReaderV1 = {
  readActiveEmailOtpBaseFactorV1(input: { readonly walletId: WalletId }): Promise<{
    readonly baseWalletAuthMethodId: WalletAuthMethodId;
    readonly maskedEmailHint: string;
  } | null>;
};

function sameRegistrationOptions(
  submitted: WalletAddAuthMethodRegistrationOptions,
  stored: WalletAddAuthMethodRegistrationOptions,
): boolean {
  // Both sides have already been through the one canonical parser, so their
  // field sets are identical and a canonical stringify is an exact comparison
  // rather than a structural approximation.
  return alphabetizeStringify(submitted) === alphabetizeStringify(stored);
}

export async function admitLinkedOwnerEnrollmentProvenanceV1(input: {
  readonly approval: LinkedDeviceApprovalV1;
  readonly ceremonies: LinkedOwnerEnrollmentCeremonyReaderV1;
  readonly emailOtpBaseFactors: LinkedOwnerEmailOtpBaseFactorReaderV1;
  readonly requestedAtMs: number;
}): Promise<LinkedOwnerEnrollmentProvenanceResultV1> {
  const claimed = input.approval.ownerEnrollment;
  switch (claimed.kind) {
    case 'linked_device_passkey_owner_enrollment_v1': {
      const stored = await input.ceremonies.getAddAuthMethodCeremony(
        claimed.addAuthMethodCeremonyId,
      );
      if (!stored) return { ok: false, reason: 'ceremony_not_found' };
      if (stored.kind !== 'passkey') {
        return { ok: false, reason: 'ceremony_is_not_a_passkey_ceremony' };
      }
      if (String(stored.intent.walletId) !== String(input.approval.walletId)) {
        return { ok: false, reason: 'ceremony_belongs_to_another_wallet' };
      }
      if (stored.passkeyRegistration.rpId !== String(claimed.registration.rpId)) {
        return { ok: false, reason: 'ceremony_relying_party_does_not_match' };
      }
      if (!sameRegistrationOptions(claimed.registration, stored.passkeyRegistration.options)) {
        return { ok: false, reason: 'ceremony_registration_options_do_not_match' };
      }
      // Carried rather than trusted: the expiry every downstream record clamps
      // to has to be the ceremony's own, not one the approval chose.
      if (stored.expiresAtMs !== claimed.expiresAtMs) {
        return { ok: false, reason: 'ceremony_expiry_does_not_match' };
      }
      if (stored.expiresAtMs <= input.requestedAtMs) {
        return { ok: false, reason: 'ceremony_expired' };
      }
      return { ok: true };
    }
    case 'linked_device_email_otp_owner_enrollment_v1': {
      const resolved = await input.emailOtpBaseFactors.readActiveEmailOtpBaseFactorV1({
        walletId: input.approval.walletId,
      });
      if (!resolved) return { ok: false, reason: 'email_otp_base_factor_unavailable' };
      if (resolved.baseWalletAuthMethodId !== claimed.baseWalletAuthMethodId) {
        return { ok: false, reason: 'email_otp_base_factor_does_not_match' };
      }
      if (resolved.maskedEmailHint !== claimed.maskedEmailHint) {
        return { ok: false, reason: 'email_otp_masked_hint_does_not_match' };
      }
      // The email branch has no independent ceremony clock: its deadline is
      // the approval expiry, restated so downstream records can clamp to one
      // number without re-deriving it.
      if (claimed.expiresAtMs !== input.approval.expiresAtMs) {
        return { ok: false, reason: 'ceremony_expiry_does_not_match' };
      }
      if (claimed.expiresAtMs <= input.requestedAtMs) {
        return { ok: false, reason: 'ceremony_expired' };
      }
      return { ok: true };
    }
  }
  claimed satisfies never;
  throw new Error('linked-device owner enrollment ceremony kind is unsupported');
}
