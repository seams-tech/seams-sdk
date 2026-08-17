/**
 * Refactor 103 Phase 8 — admitting a device-authenticated owner finalize.
 *
 * The canonical add-auth-method finalize is owner-authenticated. Device 2 has
 * no owner authority, so its finalize arrives authenticated only by the link
 * session. That is safe exactly once the server proves the named ceremony is
 * the one Device 1 started *for this enrollment* — otherwise a linked device
 * could finalize a ceremony it was never approved for and mint an owner
 * credential on someone else's wallet.
 *
 * This module is that proof. It takes the already-authenticated session, the
 * persisted target preparation, and the submitted ceremony id, and returns
 * either the exact enrollment facts the binding needs or a named reason.
 *
 * Ordering matters and is enforced here: the finalize is admitted only from a
 * session state that carries a verified key-manifest digest. The binding
 * records which key manifest the new owner credential is bound to, so
 * admitting one before the manifest exists would publish a claim nothing had
 * established.
 */
import type { LinkedDeviceTargetPreparationV1 } from '@shared/device-linking/contracts';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { LinkedDeviceEnrollmentId, LinkedDeviceId } from '@shared/signing-lanes/ids';
import type { WalletId } from '@shared/utils/domainIds';
import type { LinkedDeviceSessionRecordV1 } from './linkedDeviceSession';

export type LinkedOwnerEnrollmentAdmissionDeniedV1 =
  | 'session_not_claimed'
  | 'session_has_no_key_manifest'
  | 'ceremony_does_not_match_enrollment'
  | 'preparation_does_not_match_session'
  | 'preparation_expired';

/** The exact facts the owner-auth binding is written from. */
export type LinkedOwnerEnrollmentAdmissionV1 = {
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly keyManifestDigestB64u: DigestB64u;
  readonly addAuthMethodCeremonyId: string;
};

export type LinkedOwnerEnrollmentAdmissionResultV1 =
  | { readonly ok: true; readonly admission: LinkedOwnerEnrollmentAdmissionV1 }
  | { readonly ok: false; readonly reason: LinkedOwnerEnrollmentAdmissionDeniedV1 };

/**
 * The only session states a linked owner finalize may be admitted from.
 *
 * Both carry the verified key-manifest digest. `awaiting_target_passkey` does
 * not, which is why it is absent: at that point the R102 children have not
 * committed and there is no manifest for the credential to be bound to.
 */
type AdmissibleSessionStateV1 = Extract<
  LinkedDeviceSessionRecordV1['state'],
  { readonly state: 'provisioning' | 'committed_completion_required' }
>;

export function admitLinkedOwnerEnrollmentFinalizeV1(input: {
  readonly session: LinkedDeviceSessionRecordV1;
  readonly preparation: LinkedDeviceTargetPreparationV1;
  readonly addAuthMethodCeremonyId: string;
  readonly requestedAtMs: number;
}): LinkedOwnerEnrollmentAdmissionResultV1 {
  const claim = input.session.claimTranscript?.value;
  if (!claim) return { ok: false, reason: 'session_not_claimed' };

  const state = admissibleState(input.session.state);
  if (!state) return { ok: false, reason: 'session_has_no_key_manifest' };
  if (state.walletId !== claim.walletId || state.enrollmentId !== claim.enrollmentId) {
    return { ok: false, reason: 'session_not_claimed' };
  }

  const preparation = input.preparation;
  if (
    preparation.linkSessionId !== input.session.linkSessionId ||
    preparation.walletId !== claim.walletId ||
    preparation.enrollmentId !== claim.enrollmentId ||
    preparation.deviceId !== claim.deviceId
  ) {
    return { ok: false, reason: 'preparation_does_not_match_session' };
  }
  if (preparation.expiresAtMs <= input.requestedAtMs) {
    return { ok: false, reason: 'preparation_expired' };
  }

  // The whole point of this module: the submitted ceremony must be the one
  // Device 1 started for this exact enrollment, not merely a ceremony that
  // exists. A preparation always carries one — it is minted from the approval
  // that authorized it — so the only question left is whether it is this one.
  const ownerEnrollment = preparation.ownerEnrollment;
  if (ownerEnrollment.addAuthMethodCeremonyId !== input.addAuthMethodCeremonyId) {
    return { ok: false, reason: 'ceremony_does_not_match_enrollment' };
  }

  return {
    ok: true,
    admission: {
      walletId: claim.walletId,
      enrollmentId: claim.enrollmentId,
      deviceId: claim.deviceId,
      keyManifestDigestB64u: state.keyManifestDigestB64u,
      addAuthMethodCeremonyId: ownerEnrollment.addAuthMethodCeremonyId,
    },
  };
}

function admissibleState(
  state: LinkedDeviceSessionRecordV1['state'],
): AdmissibleSessionStateV1 | null {
  switch (state.state) {
    case 'provisioning':
    case 'committed_completion_required':
      return state;
    case 'displaying_qr':
    case 'claimed_by_owner':
    case 'awaiting_target_passkey':
    case 'active':
    case 'expired_unclaimed':
    case 'expired_claimed':
    case 'cancelled_unclaimed':
    case 'cancelled_claimed_precommit':
      return null;
  }
  state satisfies never;
  return null;
}
