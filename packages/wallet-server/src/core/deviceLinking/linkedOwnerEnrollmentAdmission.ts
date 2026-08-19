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
 * The binding records which key manifest the new owner credential is bound to.
 * That manifest arrives with the approval — read from the owner Wallet Session
 * that authorized it — so it exists from `awaiting_target_factor` onward and
 * the finalize no longer has to wait for a signing lane to commit one.
 */
import type { LinkedDeviceTargetPreparationV1 } from '@shared/device-linking/contracts';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { LinkedDeviceEnrollmentId, LinkedDeviceId } from '@shared/signing-lanes/ids';
import type { WalletId } from '@shared/utils/domainIds';
import type { LinkedDeviceSessionRecordV1 } from './linkedDeviceSession';

export type LinkedOwnerEnrollmentAdmissionDeniedV1 =
  | 'session_not_claimed'
  | 'session_not_approved'
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
 * The session states a linked owner finalize may be admitted from: every state
 * an approval has been recorded in. `awaiting_target_factor` is the state
 * Device 2 is actually in when it finalizes, and it is admissible because the
 * approval it already holds carries the manifest.
 */
type AdmissibleSessionStateV1 = Extract<
  LinkedDeviceSessionRecordV1['state'],
  {
    readonly state: 'awaiting_target_factor' | 'provisioning' | 'committed_completion_required';
  }
>;

export function admitLinkedOwnerEnrollmentFinalizeV1(input: {
  readonly session: LinkedDeviceSessionRecordV1;
  readonly preparation: LinkedDeviceTargetPreparationV1;
  readonly addAuthMethodCeremonyId: string;
  readonly requestedAtMs: number;
}): LinkedOwnerEnrollmentAdmissionResultV1 {
  const claim = input.session.claimTranscript?.value;
  if (!claim) return { ok: false, reason: 'session_not_claimed' };

  const approval = input.session.approvalTranscript;
  if (!approval) return { ok: false, reason: 'session_not_approved' };

  const state = admissibleState(input.session.state);
  if (!state) return { ok: false, reason: 'session_not_approved' };
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
      keyManifestDigestB64u: approval.sourceKeyManifestDigestB64u,
      addAuthMethodCeremonyId: ownerEnrollment.addAuthMethodCeremonyId,
    },
  };
}

function admissibleState(
  state: LinkedDeviceSessionRecordV1['state'],
): AdmissibleSessionStateV1 | null {
  switch (state.state) {
    case 'awaiting_target_factor':
    case 'provisioning':
    case 'committed_completion_required':
      return state;
    case 'displaying_qr':
    case 'claimed_by_owner':
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
