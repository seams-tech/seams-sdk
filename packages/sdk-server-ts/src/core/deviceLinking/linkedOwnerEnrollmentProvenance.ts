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
 * the ceremony store and compared field for field against what was submitted.
 * Provenance first, immutability second.
 */
import type { LinkedDeviceApprovalV1 } from '@shared/device-linking/contracts';
import type { WalletAddAuthMethodRegistrationOptions } from '@shared/utils/addAuthMethodRegistration';
import { alphabetizeStringify } from '@shared/utils/digests';
import type { StoredWalletAddAuthMethodCeremony } from '../RegistrationCeremonyStore';

export type LinkedOwnerEnrollmentProvenanceDeniedV1 =
  | 'ceremony_not_found'
  | 'ceremony_is_not_a_passkey_ceremony'
  | 'ceremony_belongs_to_another_wallet'
  | 'ceremony_relying_party_does_not_match'
  | 'ceremony_registration_options_do_not_match'
  | 'ceremony_expiry_does_not_match'
  | 'ceremony_expired';

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
  readonly requestedAtMs: number;
}): Promise<LinkedOwnerEnrollmentProvenanceResultV1> {
  const claimed = input.approval.ownerEnrollment;
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
  // Carried rather than trusted: the expiry every downstream record clamps to
  // has to be the ceremony's own, not one the approval chose.
  if (stored.expiresAtMs !== claimed.expiresAtMs) {
    return { ok: false, reason: 'ceremony_expiry_does_not_match' };
  }
  if (stored.expiresAtMs <= input.requestedAtMs) {
    return { ok: false, reason: 'ceremony_expired' };
  }
  return { ok: true };
}
