import { parseDeviceId, type DeviceId } from '@shared/authorization/capabilityKinds';
import {
  hasDelegatedWalletPermissionV1,
  sameDelegatedWalletAuthorityV1,
  validateDelegatedWalletAuthorityAttenuationV1,
  type DelegatedWalletAuthorityV1,
} from '@shared/authorization/delegatedAuthority';
import type {
  LinkPrecommitFailureV1,
  LinkSessionStateV1,
  LinkedDeviceApprovalV1,
  LinkedDeviceOwnerAuthorizationSourceV1,
  LinkedDeviceSessionClaimV1,
  LinkedDeviceTargetFactorV1,
  LinkDevicePublicKeyB64u,
  QrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking/contracts';
import { assertNeverLinkSessionStateV1 } from '@shared/device-linking/contracts';
import {
  computeLinkedDeviceApprovalDigestV1,
  computeLinkedDeviceSessionClaimDigestV1,
} from '@shared/device-linking/digests';
import {
  parseLinkedDeviceApprovalV1 as parseSharedLinkedDeviceApprovalV1,
  parseLinkedDeviceSessionClaimV1 as parseSharedLinkedDeviceSessionClaimV1,
  parseLinkDevicePublicKeyB64u,
  parseQrLinkedDeviceSessionPayloadV5 as parseSharedQrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking/parsers';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  hasWhitespaceOrControlCharacters,
  parseWalletAuthorityId,
  type DomainIdParseResult,
  type WalletAuthorityId,
  type WalletId,
} from '@shared/utils/domainIds';
import type {
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseAuthorizationEvidenceSetId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseLinkDeviceSessionId,
  type LinkedDeviceEnrollmentId,
  type LinkedDeviceId,
  type LinkDeviceSessionId,
} from '@shared/signing-lanes/ids';
import { alphabetizeStringify } from '@shared/utils/digests';
import { LINKED_DEVICE_CLOCK_SKEW_TOLERANCE_MS_V1 } from '@shared/device-linking/requestProof';

type LinkedDeviceClaimV1 = LinkedDeviceSessionClaimV1;

export type {
  LinkSessionStateV1,
  QrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking/contracts';

export type LinkedDeviceSessionListCursorV1 = {
  readonly updatedAtMs: number;
  readonly linkSessionId: LinkDeviceSessionId;
};

export type LinkedDeviceSessionListPageV1 = {
  readonly records: readonly LinkedDeviceSessionRecordV1[];
  readonly nextCursor: LinkedDeviceSessionListCursorV1 | null;
};

export type LinkedDeviceClaimTranscriptV1 = {
  readonly digestB64u: DigestB64u;
  readonly value: LinkedDeviceClaimV1;
};

export type LinkedDeviceApprovalTranscriptV1 = {
  readonly digestB64u: DigestB64u;
  readonly value: LinkedDeviceApprovalV1;
  readonly sourceKeyManifestDigestB64u: DigestB64u;
};

type LinkedDeviceEmailOtpChallengeV1 =
  | { readonly state: 'available'; readonly maskedEmailHint: string }
  | {
      readonly state: 'sent';
      readonly challengeId: string;
      readonly workerEphemeralPublicKey65B64u: string;
      readonly maskedEmailHint: string;
      readonly expiresAtMs: number;
      readonly resendAvailableAtMs: number;
    };

type LinkedDeviceTargetFactorRecordV1 =
  | {
      readonly targetFactor: { readonly kind: 'passkey_prf' };
      readonly emailOtpChallenge?: never;
    }
  | {
      readonly targetFactor: { readonly kind: 'email_otp' };
      readonly emailOtpChallenge: LinkedDeviceEmailOtpChallengeV1;
    };

type LinkedDeviceSessionRecordBaseV1 = {
  readonly version: 'linked_device_session_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly qrPayload: QrLinkedDeviceSessionPayloadV5;
  readonly revision: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

type LinkedDeviceSessionUnclaimedRecordV1 = LinkedDeviceSessionRecordBaseV1 & {
  readonly state: Extract<LinkSessionStateV1, { readonly state: 'displaying_qr' }>;
  readonly claimTranscript?: never;
  readonly approvalTranscript?: never;
  readonly targetFactor?: never;
  readonly emailOtpChallenge?: never;
  readonly authorityId?: never;
  readonly packageSetDigestB64u?: never;
};

type LinkedDeviceSessionClaimedRecordV1 = LinkedDeviceSessionRecordBaseV1 & {
  readonly state: Extract<LinkSessionStateV1, { readonly state: 'claimed' }>;
  readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript?: never;
  readonly targetFactor?: never;
  readonly emailOtpChallenge?: never;
  readonly authorityId?: never;
  readonly packageSetDigestB64u?: never;
};

type LinkedDeviceSessionApprovedRecordV1 = LinkedDeviceSessionRecordBaseV1 &
  LinkedDeviceTargetFactorRecordV1 & {
    readonly state: Extract<
      LinkSessionStateV1,
      { readonly state: 'awaiting_target_factor' | 'provisioning' }
    >;
    readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
    readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1;
    readonly authorityId?: never;
    readonly packageSetDigestB64u?: never;
  };

type LinkedDeviceSessionPendingRecordV1 = LinkedDeviceSessionRecordBaseV1 &
  LinkedDeviceTargetFactorRecordV1 & {
    readonly state: Extract<
      LinkSessionStateV1,
      { readonly state: 'authority_pending_local_install' }
    >;
    readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
    readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1;
    readonly authorityId: WalletAuthorityId;
    readonly packageSetDigestB64u: DigestB64u;
  };

type LinkedDeviceSessionActiveRecordV1 = LinkedDeviceSessionRecordBaseV1 &
  LinkedDeviceTargetFactorRecordV1 & {
    readonly state: Extract<LinkSessionStateV1, { readonly state: 'active' }>;
    readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
    readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1;
    readonly authorityId: WalletAuthorityId;
    readonly packageSetDigestB64u: DigestB64u;
  };

type LinkedDeviceSessionTerminalRecordV1 = LinkedDeviceSessionRecordBaseV1 & {
  readonly state: Extract<
    LinkSessionStateV1,
    { readonly state: 'failed_before_commit' | 'cancelled' | 'expired' }
  >;
  readonly claimTranscript?: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript?: LinkedDeviceApprovalTranscriptV1;
  readonly targetFactor?: LinkedDeviceTargetFactorV1;
  readonly emailOtpChallenge?: LinkedDeviceEmailOtpChallengeV1;
  readonly authorityId?: never;
  readonly packageSetDigestB64u?: never;
};

export type LinkedDeviceSessionRecordV1 =
  | LinkedDeviceSessionUnclaimedRecordV1
  | LinkedDeviceSessionClaimedRecordV1
  | LinkedDeviceSessionApprovedRecordV1
  | LinkedDeviceSessionPendingRecordV1
  | LinkedDeviceSessionActiveRecordV1
  | LinkedDeviceSessionTerminalRecordV1;

export type LinkedDeviceSessionClaimIdentityV1 = {
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly claimExpiresAtMs: number;
};

export type LinkedDeviceOwnerAuthorizationDeniedV1 = {
  readonly kind: 'denied';
  readonly code: 'unauthorized' | 'expired' | 'invalid';
  readonly message: string;
};

export type LinkedDeviceOwnerAuthorizationContextV1 = {
  readonly walletId: WalletId;
  readonly walletSessionId: WalletSessionId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly expiresAtMs: number;
  readonly permission: DelegatedWalletAuthorityV1;
  readonly curve: 'ed25519' | 'ecdsa';
  readonly keyManifestDigestB64u: DigestB64u;
};

export type LinkedDeviceEmailOtpBaseFactorReaderV1 = {
  readActiveEmailOtpBaseFactorV1(input: { readonly walletId: WalletId }): Promise<{
    readonly baseWalletAuthMethodId: import('@shared/utils/domainIds').WalletAuthMethodId;
  } | null>;
};

export type LinkedDeviceOwnerAuthorizationPortV1 = {
  authorizeOwnerClaimV1(input: {
    readonly payload: QrLinkedDeviceSessionPayloadV5;
    readonly requestedAtMs: number;
    readonly owner: LinkedDeviceOwnerAuthorizationContextV1;
  }): Promise<
    | { readonly kind: 'authorized'; readonly identity: LinkedDeviceSessionClaimIdentityV1 }
    | LinkedDeviceOwnerAuthorizationDeniedV1
  >;
  authorizeOwnerApprovalV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
    readonly owner: LinkedDeviceOwnerAuthorizationContextV1;
  }): Promise<{ readonly kind: 'authorized' } | LinkedDeviceOwnerAuthorizationDeniedV1>;
};

export type LinkedDeviceSessionStoreV1 = {
  createUnclaimedSessionV1(
    record: LinkedDeviceSessionRecordV1,
  ): Promise<LinkedDeviceSessionMutationResultV1>;
  getSessionV1(linkSessionId: LinkDeviceSessionId): Promise<LinkedDeviceSessionRecordV1 | null>;
  listSessionsForWalletV1(input: {
    readonly walletId: WalletId;
    readonly limit: number;
    readonly cursor: LinkedDeviceSessionListCursorV1 | null;
  }): Promise<LinkedDeviceSessionListPageV1>;
  claimSessionV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly claim: LinkedDeviceClaimV1;
    readonly claimDigestB64u: DigestB64u;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1>;
  recordOwnerApprovalV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly approval: LinkedDeviceApprovalV1;
    readonly approvalDigestB64u: DigestB64u;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1>;
  recordTargetCredentialV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1>;
  recordEmailOtpChallengeStateV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1>;
  markAuthorityPendingLocalInstallV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly authorityId: WalletAuthorityId;
    readonly packageSetDigestB64u: DigestB64u;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1>;
  activateSessionV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly authorityId: WalletAuthorityId;
    readonly packageSetDigestB64u: DigestB64u;
    readonly activatedAtMs: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1>;
  failBeforeCommitV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1>;
  cancelSessionV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1>;
  expireSessionV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1>;
  deleteActiveSessionV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly authorityId: WalletAuthorityId;
    readonly packageSetDigestB64u: DigestB64u;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1>;
};

export type LinkedDeviceSessionMutationResultV1 =
  | { readonly outcome: 'applied' | 'replayed'; readonly record: LinkedDeviceSessionRecordV1 }
  | {
      readonly outcome: 'conflict';
      readonly expectedRevision: number;
      readonly actualRevision: number | null;
      readonly record: LinkedDeviceSessionRecordV1 | null;
    }
  | { readonly outcome: 'expired'; readonly record: LinkedDeviceSessionRecordV1 }
  | { readonly outcome: 'deleted'; readonly record: null }
  | {
      readonly outcome: 'invalid_state';
      readonly state: LinkSessionStateV1['state'];
      readonly record: LinkedDeviceSessionRecordV1;
    }
  | {
      readonly outcome: 'integrity_error';
      readonly reason: 'authority_id_mismatch' | 'package_set_digest_mismatch';
      readonly record: LinkedDeviceSessionRecordV1;
    };

export type LinkedDeviceSessionServiceResultV1 =
  | LinkedDeviceSessionMutationResultV1
  | { readonly outcome: 'invalid_input'; readonly message: string }
  | { readonly outcome: 'unauthorized'; readonly code: string; readonly message: string };

export type LinkedDeviceTargetCredentialMutationResultV1 =
  | LinkedDeviceSessionMutationResultV1
  | { readonly outcome: 'invalid_input'; readonly message: string };

export type LinkedDeviceSessionCreateInputV1 = {
  readonly payload: QrLinkedDeviceSessionPayloadV5;
  readonly nowMs: number;
};

export type LinkedDeviceSessionClaimInputV1 = {
  readonly payload: QrLinkedDeviceSessionPayloadV5;
  readonly nowMs: number;
  readonly owner: LinkedDeviceOwnerAuthorizationContextV1;
};

export type LinkedDeviceSessionApprovalInputV1 = {
  readonly approval: LinkedDeviceApprovalV1;
  readonly nowMs: number;
  readonly owner: LinkedDeviceOwnerAuthorizationContextV1;
};

export type LinkedDeviceSessionCancelInputV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly nowMs: number;
};

export type LinkedDeviceSessionExpireInputV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly nowMs: number;
};

export type LinkedDeviceSessionDeleteInputV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly authorityId: WalletAuthorityId;
  readonly packageSetDigestB64u: DigestB64u;
  readonly nowMs: number;
};

export type LinkedDeviceSessionTargetCredentialInputV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly nowMs: number;
};

export type LinkedDeviceSessionEmailOtpChallengeInputV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly challenge: {
    readonly challengeId: string;
    readonly workerEphemeralPublicKey65B64u: string;
    readonly maskedEmailHint: string;
    readonly expiresAtMs: number;
    readonly resendAvailableAtMs: number;
  };
  readonly nowMs: number;
};

export type LinkedDeviceSessionCommitInputV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly authorityId: WalletAuthorityId;
  readonly packageSetDigestB64u: DigestB64u;
  readonly nowMs: number;
};

export type LinkedDeviceSessionActivationInputV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly authorityId: WalletAuthorityId;
  readonly packageSetDigestB64u: DigestB64u;
  readonly activatedAtMs: number;
  readonly nowMs: number;
};

const FAIL_CLOSED_EMAIL_OTP_BASE_FACTOR_READER_V1: LinkedDeviceEmailOtpBaseFactorReaderV1 = {
  readActiveEmailOtpBaseFactorV1: () => Promise.resolve(null),
};

export class LinkedDeviceSessionServiceV1 {
  private readonly store: LinkedDeviceSessionStoreV1;
  private readonly authorization: LinkedDeviceOwnerAuthorizationPortV1;
  private readonly emailOtpBaseFactors: LinkedDeviceEmailOtpBaseFactorReaderV1;

  constructor(input: {
    readonly store: LinkedDeviceSessionStoreV1;
    readonly authorization: LinkedDeviceOwnerAuthorizationPortV1;
    readonly emailOtpBaseFactors?: LinkedDeviceEmailOtpBaseFactorReaderV1;
  }) {
    this.store = input.store;
    this.authorization = input.authorization;
    this.emailOtpBaseFactors =
      input.emailOtpBaseFactors ?? FAIL_CLOSED_EMAIL_OTP_BASE_FACTOR_READER_V1;
  }

  async createUnclaimedSessionV1(
    input: LinkedDeviceSessionCreateInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      const payload = parseQrLinkedDeviceSessionPayloadV1(input.payload);
      const nowMs = requireTimestamp(input.nowMs, 'nowMs');
      if (payload.expiresAtMs <= nowMs) {
        return { outcome: 'invalid_input', message: 'link session expiry must be in the future' };
      }
      return await this.store.createUnclaimedSessionV1(
        buildUnclaimedSessionRecordV1(payload, nowMs),
      );
    } catch (error: unknown) {
      return invalidInputResult(error);
    }
  }

  async claimSessionV1(
    input: LinkedDeviceSessionClaimInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      const payload = parseQrLinkedDeviceSessionPayloadV1(input.payload);
      const nowMs = requireTimestamp(input.nowMs, 'nowMs');
      const existing = await this.store.getSessionV1(payload.linkSessionId);
      if (!existing) return conflictResult(0, null);
      if (!sameQrPayload(existing.qrPayload, payload))
        return conflictResult(existing.revision, existing);
      if (existing.state.state === 'displaying_qr' && nowMs >= payload.expiresAtMs) {
        return { outcome: 'expired', record: existing };
      }
      const requestedAuthorityError = validateLinkedDeviceRequestedAuthorityV1(
        input.owner.permission,
        payload.requestedPermission,
      );
      if (requestedAuthorityError)
        return unauthorizedResult('unauthorized', requestedAuthorityError);
      const authorization = await this.authorization.authorizeOwnerClaimV1({
        payload,
        requestedAtMs: nowMs,
        owner: input.owner,
      });
      if (authorization.kind === 'denied') {
        return unauthorizedResult(authorization.code, authorization.message);
      }
      const claim = buildClaimV1(payload, authorization.identity, nowMs);
      const claimDigestB64u = await digestTranscriptV1('claim', claim);
      if (sameClaim(existing, claimDigestB64u, claim))
        return { outcome: 'replayed', record: existing };
      if (existing.claimTranscript) return conflictResult(existing.revision, existing);
      const nextRecord = replaceSessionRecordV1(existing, {
        state: claimedStateV1(existing, claim),
        claimTranscript: { digestB64u: claimDigestB64u, value: claim },
        revision: existing.revision + 1,
        updatedAtMs: nowMs,
      });
      return await this.store.claimSessionV1({
        linkSessionId: payload.linkSessionId,
        expectedRevision: existing.revision,
        claim,
        claimDigestB64u,
        nextRecord,
        nowMs,
      });
    } catch (error: unknown) {
      return invalidInputResult(error);
    }
  }

  async recordOwnerApprovalV1(
    input: LinkedDeviceSessionApprovalInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      const approval = parseLinkedDeviceApprovalV1(input.approval);
      const nowMs = requireTimestamp(input.nowMs, 'nowMs');
      const existing = await this.store.getSessionV1(approval.linkSessionId);
      if (!existing) return conflictResult(0, null);
      const approvalDigestB64u = await digestTranscriptV1('approval', approval);
      if (sameApproval(existing, approvalDigestB64u, approval)) {
        return { outcome: 'replayed', record: existing };
      }
      if (existing.approvalTranscript) return conflictResult(existing.revision, existing);
      if (
        existing.state.state === 'claimed' &&
        existing.claimTranscript &&
        existing.claimTranscript.value.claimExpiresAtMs <= nowMs
      ) {
        return { outcome: 'expired', record: existing };
      }
      validateApprovalMatchesSession(existing, approval, nowMs);
      const requestedAuthorityError = validateLinkedDeviceRequestedAuthorityV1(
        input.owner.permission,
        approval.permission,
      );
      if (requestedAuthorityError)
        return unauthorizedResult('unauthorized', requestedAuthorityError);
      if (approval.ownerEnrollment.expiresAtMs <= nowMs) {
        return unauthorizedResult(
          'linked_device_owner_enrollment_expired',
          'linked-device owner enrollment has expired',
        );
      }
      if (approval.ownerEnrollment.targetFactor.kind !== approval.targetFactor.kind) {
        return unauthorizedResult(
          'linked_device_owner_enrollment_mismatch',
          'linked-device owner enrollment factor does not match the target factor',
        );
      }
      const authorization = await this.authorization.authorizeOwnerApprovalV1({
        session: existing,
        approval,
        requestedAtMs: nowMs,
        owner: input.owner,
      });
      if (authorization.kind === 'denied') {
        return unauthorizedResult(authorization.code, authorization.message);
      }
      const targetFactor = approval.targetFactor;
      const emailOtpChallenge = emailOtpChallengeForApproval(approval);
      const nextRecord = replaceSessionRecordV1(existing, {
        state: awaitingTargetFactorStateV1(existing),
        targetFactor,
        emailOtpChallenge,
        approvalTranscript: {
          digestB64u: approvalDigestB64u,
          value: approval,
          sourceKeyManifestDigestB64u: input.owner.keyManifestDigestB64u,
        },
        revision: existing.revision + 1,
        updatedAtMs: nowMs,
      });
      return await this.store.recordOwnerApprovalV1({
        linkSessionId: approval.linkSessionId,
        expectedRevision: existing.revision,
        approval,
        approvalDigestB64u,
        nextRecord,
        nowMs,
      });
    } catch (error: unknown) {
      return invalidInputResult(error);
    }
  }

  async recordTargetCredentialV1(
    input: LinkedDeviceSessionTargetCredentialInputV1,
  ): Promise<LinkedDeviceTargetCredentialMutationResultV1> {
    try {
      const nowMs = requireTimestamp(input.nowMs, 'nowMs');
      const existing = await this.requireSession(input.linkSessionId);
      if (existing.state.state === 'provisioning') return { outcome: 'replayed', record: existing };
      if (existing.state.state !== 'awaiting_target_factor') return invalidStateResult(existing);
      if (nowMs >= awaitingTargetDeadlineMsV1(existing))
        return { outcome: 'expired', record: existing };
      const nextRecord = replaceSessionRecordV1(existing, {
        state: provisioningStateV1(existing),
        revision: existing.revision + 1,
        updatedAtMs: nowMs,
      });
      return await this.store.recordTargetCredentialV1({
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        nextRecord,
        nowMs,
      });
    } catch (error: unknown) {
      return invalidInputResult(error);
    }
  }

  async recordEmailOtpChallengeStateV1(
    input: LinkedDeviceSessionEmailOtpChallengeInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      const nowMs = requireTimestamp(input.nowMs, 'nowMs');
      const existing = await this.requireSession(input.linkSessionId);
      if (
        existing.state.state !== 'awaiting_target_factor' ||
        existing.targetFactor?.kind !== 'email_otp'
      ) {
        return invalidStateResult(existing);
      }
      if (nowMs >= awaitingTargetDeadlineMsV1(existing))
        return { outcome: 'expired', record: existing };
      const challenge = parseEmailOtpChallengeV1(input.challenge);
      if (
        existing.emailOtpChallenge?.state === 'sent' &&
        alphabetizeStringify(existing.emailOtpChallenge) === alphabetizeStringify(challenge)
      ) {
        return { outcome: 'replayed', record: existing };
      }
      const nextRecord = replaceSessionRecordV1(existing, {
        emailOtpChallenge: challenge,
        revision: existing.revision + 1,
        updatedAtMs: nowMs,
      });
      return await this.store.recordEmailOtpChallengeStateV1({
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        nextRecord,
        nowMs,
      });
    } catch (error: unknown) {
      return invalidInputResult(error);
    }
  }

  async markAuthorityPendingLocalInstallV1(
    input: LinkedDeviceSessionCommitInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      const authorityId = parseId(input.authorityId, parseWalletAuthorityId, 'authorityId');
      const packageSetDigestB64u = requireDigest(
        input.packageSetDigestB64u,
        'packageSetDigestB64u',
      );
      const nowMs = requireTimestamp(input.nowMs, 'nowMs');
      const existing = await this.requireSession(input.linkSessionId);
      const retry = pendingRetryResult(existing, authorityId, packageSetDigestB64u);
      if (retry) return retry;
      if (existing.state.state !== 'provisioning') return invalidStateResult(existing);
      const nextRecord = replaceSessionRecordV1(existing, {
        state: authorityPendingStateV1(existing, authorityId, packageSetDigestB64u),
        authorityId,
        packageSetDigestB64u,
        revision: existing.revision + 1,
        updatedAtMs: nowMs,
      });
      return await this.store.markAuthorityPendingLocalInstallV1({
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        authorityId,
        packageSetDigestB64u,
        nextRecord,
        nowMs,
      });
    } catch (error: unknown) {
      return invalidInputResult(error);
    }
  }

  async activateSessionV1(
    input: LinkedDeviceSessionActivationInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      const authorityId = parseId(input.authorityId, parseWalletAuthorityId, 'authorityId');
      const packageSetDigestB64u = requireDigest(
        input.packageSetDigestB64u,
        'packageSetDigestB64u',
      );
      const activatedAtMs = requireTimestamp(input.activatedAtMs, 'activatedAtMs');
      const nowMs = requireTimestamp(input.nowMs, 'nowMs');
      if (activatedAtMs > nowMs) {
        return { outcome: 'invalid_input', message: 'activatedAtMs cannot be in the future' };
      }
      const existing = await this.requireSession(input.linkSessionId);
      const retry = activeRetryResult(existing, authorityId, packageSetDigestB64u);
      if (retry) return retry;
      if (existing.state.state !== 'authority_pending_local_install')
        return invalidStateResult(existing);
      if (
        existing.state.authorityId !== authorityId ||
        existing.state.packageSetDigestB64u !== packageSetDigestB64u
      ) {
        return integrityResult(existing, 'authority_id_mismatch');
      }
      const nextRecord = replaceSessionRecordV1(existing, {
        state: activeStateV1(existing, activatedAtMs),
        revision: existing.revision + 1,
        updatedAtMs: nowMs,
      });
      return await this.store.activateSessionV1({
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        authorityId,
        packageSetDigestB64u,
        activatedAtMs,
        nextRecord,
        nowMs,
      });
    } catch (error: unknown) {
      return invalidInputResult(error);
    }
  }

  async failBeforeCommitV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly error: LinkPrecommitFailureV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      const nowMs = requireTimestamp(input.nowMs, 'nowMs');
      const error = parseLinkPrecommitFailureV1(input.error);
      const existing = await this.requireSession(input.linkSessionId);
      if (existing.state.state === 'failed_before_commit') {
        return alphabetizeStringify(existing.state.error) === alphabetizeStringify(error)
          ? { outcome: 'replayed', record: existing }
          : conflictResult(existing.revision, existing);
      }
      if (!isPrecommitState(existing.state)) return invalidStateResult(existing);
      const nextRecord = replaceSessionRecordV1(existing, {
        state: { state: 'failed_before_commit', error },
        revision: existing.revision + 1,
        updatedAtMs: nowMs,
      });
      return await this.store.failBeforeCommitV1({
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        nextRecord,
        nowMs,
      });
    } catch (error: unknown) {
      return invalidInputResult(error);
    }
  }

  async cancelSessionV1(
    input: LinkedDeviceSessionCancelInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      const nowMs = requireTimestamp(input.nowMs, 'nowMs');
      const existing = await this.requireSession(input.linkSessionId);
      if (existing.state.state === 'cancelled') return { outcome: 'replayed', record: existing };
      if (!isPrecommitState(existing.state)) return invalidStateResult(existing);
      const nextRecord = replaceSessionRecordV1(existing, {
        state: { state: 'cancelled', cancelledAtMs: nowMs },
        revision: existing.revision + 1,
        updatedAtMs: nowMs,
      });
      return await this.store.cancelSessionV1({
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        nextRecord,
        nowMs,
      });
    } catch (error: unknown) {
      return invalidInputResult(error);
    }
  }

  async expireSessionV1(
    input: LinkedDeviceSessionExpireInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      const nowMs = requireTimestamp(input.nowMs, 'nowMs');
      const existing = await this.requireSession(input.linkSessionId);
      if (existing.state.state === 'expired') return { outcome: 'replayed', record: existing };
      if (!isPrecommitState(existing.state)) return invalidStateResult(existing);
      if (nowMs < sessionExpiryMsV1(existing)) {
        return { outcome: 'invalid_input', message: 'link session has not expired' };
      }
      const nextRecord = replaceSessionRecordV1(existing, {
        state: { state: 'expired', expiredAtMs: nowMs },
        revision: existing.revision + 1,
        updatedAtMs: nowMs,
      });
      return await this.store.expireSessionV1({
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        nextRecord,
        nowMs,
      });
    } catch (error: unknown) {
      return invalidInputResult(error);
    }
  }

  async deleteActiveSessionV1(
    input: LinkedDeviceSessionDeleteInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      const authorityId = parseId(input.authorityId, parseWalletAuthorityId, 'authorityId');
      const packageSetDigestB64u = requireDigest(
        input.packageSetDigestB64u,
        'packageSetDigestB64u',
      );
      const nowMs = requireTimestamp(input.nowMs, 'nowMs');
      const existing = await this.store.getSessionV1(input.linkSessionId);
      if (!existing) return { outcome: 'deleted', record: null };
      if (existing.state.state !== 'active') return invalidStateResult(existing);
      if (existing.state.authorityId !== authorityId)
        return integrityResult(existing, 'authority_id_mismatch');
      if (existing.packageSetDigestB64u !== packageSetDigestB64u) {
        return integrityResult(existing, 'package_set_digest_mismatch');
      }
      return await this.store.deleteActiveSessionV1({
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        authorityId,
        packageSetDigestB64u,
        nowMs,
      });
    } catch (error: unknown) {
      return invalidInputResult(error);
    }
  }

  async getSessionV1(
    input:
      | { readonly linkSessionId: LinkDeviceSessionId; readonly nowMs: number }
      | LinkDeviceSessionId,
  ): Promise<LinkedDeviceSessionRecordV1 | null> {
    const normalized = normalizeSessionReadInput(input);
    const existing = await this.store.getSessionV1(normalized.linkSessionId);
    if (!existing || !isPrecommitState(existing.state)) return existing;
    if (normalized.nowMs < sessionExpiryMsV1(existing)) return existing;
    const expired = await this.expireSessionV1({
      linkSessionId: existing.linkSessionId,
      expectedRevision: existing.revision,
      nowMs: normalized.nowMs,
    });
    return 'record' in expired ? expired.record : existing;
  }

  async listSessionsForWalletV1(input: {
    readonly walletId: WalletId;
    readonly nowMs: number;
    readonly limit: number;
    readonly cursor: LinkedDeviceSessionListCursorV1 | null;
  }): Promise<LinkedDeviceSessionListPageV1> {
    const page = await this.store.listSessionsForWalletV1({
      walletId: input.walletId,
      limit: input.limit,
      cursor: input.cursor,
    });
    const records: LinkedDeviceSessionRecordV1[] = [];
    for (const record of page.records) {
      if (!isPrecommitState(record.state) || input.nowMs < sessionExpiryMsV1(record)) {
        records.push(record);
        continue;
      }
      const expired = await this.expireSessionV1({
        linkSessionId: record.linkSessionId,
        expectedRevision: record.revision,
        nowMs: input.nowMs,
      });
      records.push('record' in expired ? (expired.record ?? record) : record);
    }
    return { records, nextCursor: page.nextCursor };
  }

  private async requireSession(
    linkSessionId: LinkDeviceSessionId,
  ): Promise<LinkedDeviceSessionRecordV1> {
    const existing = await this.store.getSessionV1(linkSessionId);
    if (!existing) throw new Error(`unknown link session: ${String(linkSessionId)}`);
    return existing;
  }
}

export function digestTranscriptV1(kind: 'claim', value: LinkedDeviceClaimV1): Promise<DigestB64u>;
export function digestTranscriptV1(
  kind: 'approval',
  value: LinkedDeviceApprovalV1,
): Promise<DigestB64u>;
export async function digestTranscriptV1(
  kind: 'claim' | 'approval',
  value: LinkedDeviceClaimV1 | LinkedDeviceApprovalV1,
): Promise<DigestB64u> {
  if (kind === 'claim') {
    if (!isLinkedDeviceClaimV1(value)) throw new Error('claim transcript value is invalid');
    return computeLinkedDeviceSessionClaimDigestV1(value);
  }
  if (!isLinkedDeviceApprovalV1(value)) throw new Error('approval transcript value is invalid');
  return computeLinkedDeviceApprovalDigestV1(value);
}

export function buildUnclaimedSessionRecordV1(
  payload: QrLinkedDeviceSessionPayloadV5,
  nowMs: number,
): LinkedDeviceSessionRecordV1 {
  const parsedPayload = parseQrLinkedDeviceSessionPayloadV1(payload);
  const createdAtMs = requireTimestamp(nowMs, 'nowMs');
  if (parsedPayload.issuedAtMs - createdAtMs > LINKED_DEVICE_CLOCK_SKEW_TOLERANCE_MS_V1) {
    throw new Error('link session issuedAtMs is in the future');
  }
  return buildSessionRecordV1({
    linkSessionId: parsedPayload.linkSessionId,
    qrPayload: parsedPayload,
    state: { state: 'displaying_qr' },
    revision: 1,
    createdAtMs,
    updatedAtMs: createdAtMs,
  });
}

export function parseLinkedDeviceSessionRecordV1(raw: unknown): LinkedDeviceSessionRecordV1 {
  const record = requireRecord(raw, 'linked device session record');
  requireAllowedKeys(record, [
    'version',
    'linkSessionId',
    'qrPayload',
    'state',
    'revision',
    'claimTranscript',
    'approvalTranscript',
    'targetFactor',
    'emailOtpChallenge',
    'authorityId',
    'packageSetDigestB64u',
    'createdAtMs',
    'updatedAtMs',
  ]);
  if (record.version !== 'linked_device_session_v1')
    throw new Error('linked device session version is invalid');
  const linkSessionId = parseId(record.linkSessionId, parseLinkDeviceSessionId, 'linkSessionId');
  const qrPayload = parseQrLinkedDeviceSessionPayloadV1(record.qrPayload);
  if (qrPayload.linkSessionId !== linkSessionId)
    throw new Error('linkSessionId does not match QR payload');
  const state = parseLinkSessionStateV1(record.state);
  const revision = requirePositiveInteger(record.revision, 'revision');
  const createdAtMs = requireTimestamp(record.createdAtMs, 'createdAtMs');
  const updatedAtMs = requireTimestamp(record.updatedAtMs, 'updatedAtMs');
  if (updatedAtMs < createdAtMs) throw new Error('updatedAtMs precedes createdAtMs');
  return buildSessionRecordV1({
    linkSessionId,
    qrPayload,
    state,
    revision,
    claimTranscript: parseOptionalClaimTranscript(record.claimTranscript),
    approvalTranscript: parseOptionalApprovalTranscript(record.approvalTranscript),
    targetFactor: parseOptionalTargetFactor(record.targetFactor),
    emailOtpChallenge: parseOptionalEmailOtpChallenge(record.emailOtpChallenge),
    authorityId: parseOptionalId(record.authorityId, parseWalletAuthorityId, 'authorityId'),
    packageSetDigestB64u: parseOptionalDigest(record.packageSetDigestB64u, 'packageSetDigestB64u'),
    createdAtMs,
    updatedAtMs,
  });
}

export function parseQrLinkedDeviceSessionPayloadV1(raw: unknown): QrLinkedDeviceSessionPayloadV5 {
  return parseSharedQrLinkedDeviceSessionPayloadV5(raw);
}

export function parseOwnerAuthorizationSourceV1(
  raw: unknown,
): LinkedDeviceOwnerAuthorizationSourceV1 {
  return parseOwnerAuthorizationV1(raw);
}

export function parseLinkedDeviceApprovalRecordV1(raw: unknown): LinkedDeviceApprovalV1 {
  return parseLinkedDeviceApprovalV1(raw);
}

export function parseLinkedDeviceClaimRecordV1(raw: unknown): LinkedDeviceClaimV1 {
  return parseLinkedDeviceClaimV1(raw);
}

export function parseLinkedDeviceSessionStateV1(raw: unknown): LinkSessionStateV1 {
  return parseLinkSessionStateV1(raw);
}

export function parseLinkedDevicePublicKeyV1(raw: unknown): LinkDevicePublicKeyB64u {
  return parseLinkDevicePublicKeyB64u(raw);
}

export function parseLinkedDeviceDigestV1(raw: unknown): DigestB64u {
  return requireDigest(raw, 'digest');
}

function buildSessionRecordV1(input: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly qrPayload: QrLinkedDeviceSessionPayloadV5;
  readonly state: LinkSessionStateV1;
  readonly revision: number;
  readonly claimTranscript?: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript?: LinkedDeviceApprovalTranscriptV1;
  readonly targetFactor?: LinkedDeviceTargetFactorV1;
  readonly emailOtpChallenge?: LinkedDeviceEmailOtpChallengeV1;
  readonly authorityId?: WalletAuthorityId;
  readonly packageSetDigestB64u?: DigestB64u;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): LinkedDeviceSessionRecordV1 {
  requireRecordIdentityFacts(input);
  switch (input.state.state) {
    case 'displaying_qr':
      requireNoRecordFacts(input, 'displaying_qr');
      return {
        version: 'linked_device_session_v1',
        linkSessionId: input.linkSessionId,
        qrPayload: input.qrPayload,
        state: input.state,
        revision: input.revision,
        createdAtMs: input.createdAtMs,
        updatedAtMs: input.updatedAtMs,
      };
    case 'claimed':
      requireClaimRecordFacts(input, 'claimed');
      return {
        version: 'linked_device_session_v1',
        linkSessionId: input.linkSessionId,
        qrPayload: input.qrPayload,
        state: input.state,
        claimTranscript: input.claimTranscript,
        revision: input.revision,
        createdAtMs: input.createdAtMs,
        updatedAtMs: input.updatedAtMs,
      };
    case 'awaiting_target_factor':
    case 'provisioning':
      return buildApprovedSessionRecordV1(input);
    case 'authority_pending_local_install':
      return buildPendingSessionRecordV1(input);
    case 'active':
      return buildActiveSessionRecordV1(input);
    case 'failed_before_commit':
    case 'cancelled':
    case 'expired':
      requireTerminalRecordFacts(input, input.state.state);
      return {
        version: 'linked_device_session_v1',
        linkSessionId: input.linkSessionId,
        qrPayload: input.qrPayload,
        state: input.state,
        ...(input.claimTranscript ? { claimTranscript: input.claimTranscript } : {}),
        ...(input.approvalTranscript ? { approvalTranscript: input.approvalTranscript } : {}),
        ...(input.targetFactor ? { targetFactor: input.targetFactor } : {}),
        ...(input.emailOtpChallenge ? { emailOtpChallenge: input.emailOtpChallenge } : {}),
        revision: input.revision,
        createdAtMs: input.createdAtMs,
        updatedAtMs: input.updatedAtMs,
      };
    default:
      return assertNeverLinkSessionStateV1(input.state);
  }
}

function buildApprovedSessionRecordV1(input: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly qrPayload: QrLinkedDeviceSessionPayloadV5;
  readonly state: LinkSessionStateV1;
  readonly revision: number;
  readonly claimTranscript?: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript?: LinkedDeviceApprovalTranscriptV1;
  readonly targetFactor?: LinkedDeviceTargetFactorV1;
  readonly emailOtpChallenge?: LinkedDeviceEmailOtpChallengeV1;
  readonly authorityId?: WalletAuthorityId;
  readonly packageSetDigestB64u?: DigestB64u;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): LinkedDeviceSessionApprovedRecordV1 {
  if (input.state.state !== 'awaiting_target_factor' && input.state.state !== 'provisioning') {
    throw new Error('approved session state is invalid');
  }
  requireApprovedRecordFacts(input, input.state.state);
  if (input.targetFactor.kind === 'passkey_prf') {
    return {
      version: 'linked_device_session_v1',
      linkSessionId: input.linkSessionId,
      qrPayload: input.qrPayload,
      state: input.state,
      claimTranscript: input.claimTranscript,
      approvalTranscript: input.approvalTranscript,
      targetFactor: input.targetFactor,
      revision: input.revision,
      createdAtMs: input.createdAtMs,
      updatedAtMs: input.updatedAtMs,
    };
  }
  if (!input.emailOtpChallenge)
    throw new Error(`${input.state.state} email session is missing challenge state`);
  return {
    version: 'linked_device_session_v1',
    linkSessionId: input.linkSessionId,
    qrPayload: input.qrPayload,
    state: input.state,
    claimTranscript: input.claimTranscript,
    approvalTranscript: input.approvalTranscript,
    targetFactor: input.targetFactor,
    emailOtpChallenge: input.emailOtpChallenge,
    revision: input.revision,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
}

function buildPendingSessionRecordV1(input: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly qrPayload: QrLinkedDeviceSessionPayloadV5;
  readonly state: LinkSessionStateV1;
  readonly revision: number;
  readonly claimTranscript?: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript?: LinkedDeviceApprovalTranscriptV1;
  readonly targetFactor?: LinkedDeviceTargetFactorV1;
  readonly emailOtpChallenge?: LinkedDeviceEmailOtpChallengeV1;
  readonly authorityId?: WalletAuthorityId;
  readonly packageSetDigestB64u?: DigestB64u;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): LinkedDeviceSessionPendingRecordV1 {
  if (input.state.state !== 'authority_pending_local_install') {
    throw new Error('pending session state is invalid');
  }
  requireCommittedRecordFacts(input, input.state.state);
  if (input.authorityId !== input.state.authorityId)
    throw new Error('pending authority facts do not match state');
  if (input.packageSetDigestB64u !== input.state.packageSetDigestB64u)
    throw new Error('pending package digest does not match state');
  if (input.targetFactor.kind === 'passkey_prf') {
    return {
      version: 'linked_device_session_v1',
      linkSessionId: input.linkSessionId,
      qrPayload: input.qrPayload,
      state: input.state,
      claimTranscript: input.claimTranscript,
      approvalTranscript: input.approvalTranscript,
      targetFactor: input.targetFactor,
      authorityId: input.authorityId,
      packageSetDigestB64u: input.packageSetDigestB64u,
      revision: input.revision,
      createdAtMs: input.createdAtMs,
      updatedAtMs: input.updatedAtMs,
    };
  }
  if (!input.emailOtpChallenge) throw new Error('pending email session is missing challenge state');
  return {
    version: 'linked_device_session_v1',
    linkSessionId: input.linkSessionId,
    qrPayload: input.qrPayload,
    state: input.state,
    claimTranscript: input.claimTranscript,
    approvalTranscript: input.approvalTranscript,
    targetFactor: input.targetFactor,
    emailOtpChallenge: input.emailOtpChallenge,
    authorityId: input.authorityId,
    packageSetDigestB64u: input.packageSetDigestB64u,
    revision: input.revision,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
}

function buildActiveSessionRecordV1(input: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly qrPayload: QrLinkedDeviceSessionPayloadV5;
  readonly state: LinkSessionStateV1;
  readonly revision: number;
  readonly claimTranscript?: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript?: LinkedDeviceApprovalTranscriptV1;
  readonly targetFactor?: LinkedDeviceTargetFactorV1;
  readonly emailOtpChallenge?: LinkedDeviceEmailOtpChallengeV1;
  readonly authorityId?: WalletAuthorityId;
  readonly packageSetDigestB64u?: DigestB64u;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): LinkedDeviceSessionActiveRecordV1 {
  if (input.state.state !== 'active') throw new Error('active session state is invalid');
  requireCommittedRecordFacts(input, 'active');
  if (input.authorityId !== input.state.authorityId)
    throw new Error('active authority facts do not match state');
  if (input.targetFactor.kind === 'passkey_prf') {
    return {
      version: 'linked_device_session_v1',
      linkSessionId: input.linkSessionId,
      qrPayload: input.qrPayload,
      state: input.state,
      claimTranscript: input.claimTranscript,
      approvalTranscript: input.approvalTranscript,
      targetFactor: input.targetFactor,
      authorityId: input.authorityId,
      packageSetDigestB64u: input.packageSetDigestB64u,
      revision: input.revision,
      createdAtMs: input.createdAtMs,
      updatedAtMs: input.updatedAtMs,
    };
  }
  if (!input.emailOtpChallenge) throw new Error('active email session is missing challenge state');
  return {
    version: 'linked_device_session_v1',
    linkSessionId: input.linkSessionId,
    qrPayload: input.qrPayload,
    state: input.state,
    claimTranscript: input.claimTranscript,
    approvalTranscript: input.approvalTranscript,
    targetFactor: input.targetFactor,
    emailOtpChallenge: input.emailOtpChallenge,
    authorityId: input.authorityId,
    packageSetDigestB64u: input.packageSetDigestB64u,
    revision: input.revision,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
}

function replaceSessionRecordV1(
  record: LinkedDeviceSessionRecordV1,
  patch: {
    readonly state?: LinkSessionStateV1;
    readonly claimTranscript?: LinkedDeviceClaimTranscriptV1;
    readonly approvalTranscript?: LinkedDeviceApprovalTranscriptV1;
    readonly targetFactor?: LinkedDeviceTargetFactorV1;
    readonly emailOtpChallenge?: LinkedDeviceEmailOtpChallengeV1;
    readonly authorityId?: WalletAuthorityId;
    readonly packageSetDigestB64u?: DigestB64u;
    readonly revision: number;
    readonly updatedAtMs: number;
  },
): LinkedDeviceSessionRecordV1 {
  return buildSessionRecordV1({
    linkSessionId: record.linkSessionId,
    qrPayload: record.qrPayload,
    state: patch.state ?? record.state,
    revision: patch.revision,
    claimTranscript: patch.claimTranscript ?? record.claimTranscript,
    approvalTranscript: patch.approvalTranscript ?? record.approvalTranscript,
    targetFactor: patch.targetFactor ?? record.targetFactor,
    emailOtpChallenge: patch.emailOtpChallenge ?? record.emailOtpChallenge,
    authorityId: patch.authorityId ?? record.authorityId,
    packageSetDigestB64u: patch.packageSetDigestB64u ?? record.packageSetDigestB64u,
    createdAtMs: record.createdAtMs,
    updatedAtMs: patch.updatedAtMs,
  });
}

/** Builds the next linear session record for the authority commit transaction. */
export function buildAuthorityPendingLocalInstallSessionRecordV1(input: {
  readonly record: LinkedDeviceSessionRecordV1;
  readonly authorityId: WalletAuthorityId;
  readonly packageSetDigestB64u: DigestB64u;
  readonly nowMs: number;
}): LinkedDeviceSessionRecordV1 {
  const nowMs = requireTimestamp(input.nowMs, 'nowMs');
  if (input.record.state.state !== 'provisioning') {
    throw new Error('linked-device session is not ready for authority commit');
  }
  return replaceSessionRecordV1(input.record, {
    state: authorityPendingStateV1(input.record, input.authorityId, input.packageSetDigestB64u),
    authorityId: input.authorityId,
    packageSetDigestB64u: input.packageSetDigestB64u,
    revision: input.record.revision + 1,
    updatedAtMs: nowMs,
  });
}

/** Builds the next linear session record for the authority activation transaction. */
export function buildAuthorityActiveSessionRecordV1(input: {
  readonly record: LinkedDeviceSessionRecordV1;
  readonly activatedAtMs: number;
  readonly nowMs: number;
}): LinkedDeviceSessionRecordV1 {
  const nowMs = requireTimestamp(input.nowMs, 'nowMs');
  const activatedAtMs = requireTimestamp(input.activatedAtMs, 'activatedAtMs');
  if (activatedAtMs > nowMs) throw new Error('activatedAtMs cannot be in the future');
  if (input.record.state.state !== 'authority_pending_local_install') {
    throw new Error('linked-device session has no pending authority installation');
  }
  return replaceSessionRecordV1(input.record, {
    state: activeStateV1(input.record, activatedAtMs),
    revision: input.record.revision + 1,
    updatedAtMs: nowMs,
  });
}

function claimedStateV1(
  record: LinkedDeviceSessionRecordV1,
  claim: LinkedDeviceClaimV1,
): Extract<LinkSessionStateV1, { readonly state: 'claimed' }> {
  if (record.state.state !== 'displaying_qr') throw new Error('link session is not claimable');
  return { state: 'claimed', deviceId: parseDeviceIdValue(claim.deviceId) };
}

function awaitingTargetFactorStateV1(
  record: LinkedDeviceSessionRecordV1,
): Extract<LinkSessionStateV1, { readonly state: 'awaiting_target_factor' }> {
  if (record.state.state !== 'claimed')
    throw new Error('link session is not awaiting owner approval');
  return { state: 'awaiting_target_factor', deviceId: record.state.deviceId };
}

function provisioningStateV1(
  record: LinkedDeviceSessionRecordV1,
): Extract<LinkSessionStateV1, { readonly state: 'provisioning' }> {
  if (record.state.state !== 'awaiting_target_factor')
    throw new Error('link session is not awaiting target credential');
  return { state: 'provisioning', deviceId: record.state.deviceId };
}

function authorityPendingStateV1(
  record: LinkedDeviceSessionRecordV1,
  authorityId: WalletAuthorityId,
  packageSetDigestB64u: DigestB64u,
): Extract<LinkSessionStateV1, { readonly state: 'authority_pending_local_install' }> {
  if (record.state.state !== 'provisioning')
    throw new Error('link session has no pending authority installation');
  return {
    state: 'authority_pending_local_install',
    deviceId: record.state.deviceId,
    authorityId,
    packageSetDigestB64u,
  };
}

function activeStateV1(
  record: LinkedDeviceSessionRecordV1,
  activatedAtMs: number,
): Extract<LinkSessionStateV1, { readonly state: 'active' }> {
  if (record.state.state !== 'authority_pending_local_install')
    throw new Error('link session has no pending authority installation');
  return {
    state: 'active',
    deviceId: record.state.deviceId,
    authorityId: record.state.authorityId,
    activatedAtMs,
  };
}

function validateApprovalMatchesSession(
  record: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
  nowMs: number,
): void {
  if (record.state.state !== 'claimed' || !record.claimTranscript)
    throw new Error('link session is not awaiting owner approval');
  const claim = record.claimTranscript.value;
  if (
    claim.walletId !== approval.walletId ||
    claim.enrollmentId !== approval.enrollmentId ||
    claim.deviceId !== approval.deviceId ||
    claim.devicePublicKeyB64u !== approval.devicePublicKeyB64u ||
    approval.linkPublicKeyB64u !== record.qrPayload.linkPublicKeyB64u ||
    approval.devicePublicKeyB64u !== record.qrPayload.devicePublicKeyB64u
  )
    throw new Error('approval identity does not match the claimed session');
  if (!sameDelegatedWalletAuthorityV1(approval.permission, record.qrPayload.requestedPermission))
    throw new Error('approval permission does not match QR payload');
  if (
    approval.targetFactor.kind !== record.qrPayload.targetFactor.kind ||
    approval.targetFactor.kind !== approval.ownerEnrollment.targetFactor.kind
  )
    throw new Error('approval target factor does not match the QR session');
  if (approval.expiresAtMs <= nowMs || approval.expiresAtMs > claim.claimExpiresAtMs)
    throw new Error('approval expiry is outside the claim lifetime');
  if (approval.approvedAtMs > nowMs) throw new Error('approval is from the future');
  if (approval.orderedKeyBindings.length === 0 || approval.protocolVersions.length === 0)
    throw new Error('approval manifest is empty');
}

function validateLinkedDeviceRequestedAuthorityV1(
  sourceAuthority: DelegatedWalletAuthorityV1,
  authority: DelegatedWalletAuthorityV1,
): string | null {
  if (!hasDelegatedWalletPermissionV1(sourceAuthority, 'link_devices'))
    return 'linking authority does not contain link_devices';
  const attenuation = validateDelegatedWalletAuthorityAttenuationV1({
    parent: sourceAuthority,
    child: authority,
  });
  return attenuation.ok ? null : attenuation.error.message;
}

function pendingRetryResult(
  record: LinkedDeviceSessionRecordV1,
  authorityId: WalletAuthorityId,
  packageSetDigestB64u: DigestB64u,
): LinkedDeviceSessionMutationResultV1 | null {
  if (record.state.state !== 'authority_pending_local_install' && record.state.state !== 'active')
    return null;
  if (record.state.authorityId !== authorityId)
    return integrityResult(record, 'authority_id_mismatch');
  if (record.packageSetDigestB64u !== packageSetDigestB64u)
    return integrityResult(record, 'package_set_digest_mismatch');
  return { outcome: 'replayed', record };
}

function activeRetryResult(
  record: LinkedDeviceSessionRecordV1,
  authorityId: WalletAuthorityId,
  packageSetDigestB64u: DigestB64u,
): LinkedDeviceSessionMutationResultV1 | null {
  if (record.state.state === 'authority_pending_local_install') {
    if (record.state.authorityId !== authorityId)
      return integrityResult(record, 'authority_id_mismatch');
    if (record.state.packageSetDigestB64u !== packageSetDigestB64u)
      return integrityResult(record, 'package_set_digest_mismatch');
    return null;
  }
  if (record.state.state !== 'active') return null;
  if (record.state.authorityId !== authorityId)
    return integrityResult(record, 'authority_id_mismatch');
  if (record.packageSetDigestB64u !== packageSetDigestB64u)
    return integrityResult(record, 'package_set_digest_mismatch');
  return { outcome: 'replayed', record };
}

function isPrecommitState(
  state: LinkSessionStateV1,
): state is Extract<
  LinkSessionStateV1,
  { readonly state: 'displaying_qr' | 'claimed' | 'awaiting_target_factor' | 'provisioning' }
> {
  switch (state.state) {
    case 'displaying_qr':
    case 'claimed':
    case 'awaiting_target_factor':
    case 'provisioning':
      return true;
    case 'authority_pending_local_install':
    case 'active':
    case 'failed_before_commit':
    case 'cancelled':
    case 'expired':
      return false;
    default:
      return assertNeverLinkSessionStateV1(state);
  }
}

function sessionExpiryMsV1(record: LinkedDeviceSessionRecordV1): number {
  switch (record.state.state) {
    case 'displaying_qr':
      return record.qrPayload.expiresAtMs;
    case 'claimed':
      return record.claimTranscript?.value.claimExpiresAtMs ?? record.qrPayload.expiresAtMs;
    case 'awaiting_target_factor':
    case 'provisioning':
      return record.approvalTranscript?.value.expiresAtMs ?? record.qrPayload.expiresAtMs;
    case 'authority_pending_local_install':
    case 'active':
    case 'failed_before_commit':
    case 'cancelled':
    case 'expired':
      return Number.POSITIVE_INFINITY;
    default:
      return assertNeverLinkSessionStateV1(record.state);
  }
}

function awaitingTargetDeadlineMsV1(record: LinkedDeviceSessionRecordV1): number {
  if (record.state.state !== 'awaiting_target_factor')
    throw new Error('link session is not awaiting target factor');
  return record.approvalTranscript?.value.expiresAtMs ?? record.qrPayload.expiresAtMs;
}

function sameQrPayload(
  left: QrLinkedDeviceSessionPayloadV5,
  right: QrLinkedDeviceSessionPayloadV5,
): boolean {
  return alphabetizeStringify(left) === alphabetizeStringify(right);
}

function sameClaim(
  record: LinkedDeviceSessionRecordV1,
  digest: DigestB64u,
  value: unknown,
): boolean {
  return Boolean(
    record.claimTranscript &&
    record.claimTranscript.digestB64u === digest &&
    alphabetizeStringify(record.claimTranscript.value) === alphabetizeStringify(value),
  );
}

function sameApproval(
  record: LinkedDeviceSessionRecordV1,
  digest: DigestB64u,
  value: unknown,
): boolean {
  return Boolean(
    record.approvalTranscript &&
    record.approvalTranscript.digestB64u === digest &&
    alphabetizeStringify(record.approvalTranscript.value) === alphabetizeStringify(value),
  );
}

function isLinkedDeviceClaimV1(
  value: LinkedDeviceClaimV1 | LinkedDeviceApprovalV1,
): value is LinkedDeviceClaimV1 {
  return value.kind === 'linked_device_session_claim_v1';
}

function isLinkedDeviceApprovalV1(
  value: LinkedDeviceClaimV1 | LinkedDeviceApprovalV1,
): value is LinkedDeviceApprovalV1 {
  return value.kind === 'linked_device_approval_v1';
}

function parseLinkedDeviceApprovalV1(raw: unknown): LinkedDeviceApprovalV1 {
  return parseSharedLinkedDeviceApprovalV1(raw);
}

function parseLinkedDeviceClaimV1(raw: unknown): LinkedDeviceClaimV1 {
  return parseSharedLinkedDeviceSessionClaimV1(raw);
}

function parseLinkSessionStateV1(raw: unknown): LinkSessionStateV1 {
  const record = requireRecord(raw, 'session state');
  const state = parseIdentityString(record.state, 'state');
  switch (state) {
    case 'displaying_qr':
      requireExactKeys(record, ['state']);
      return { state };
    case 'claimed':
    case 'awaiting_target_factor':
    case 'provisioning':
      requireExactKeys(record, ['state', 'deviceId']);
      return { state, deviceId: parseDeviceIdValue(record.deviceId) };
    case 'authority_pending_local_install':
      requireExactKeys(record, ['state', 'deviceId', 'authorityId', 'packageSetDigestB64u']);
      return {
        state,
        deviceId: parseDeviceIdValue(record.deviceId),
        authorityId: parseId(record.authorityId, parseWalletAuthorityId, 'state.authorityId'),
        packageSetDigestB64u: requireDigest(
          record.packageSetDigestB64u,
          'state.packageSetDigestB64u',
        ),
      };
    case 'active':
      requireExactKeys(record, ['state', 'deviceId', 'authorityId', 'activatedAtMs']);
      return {
        state,
        deviceId: parseDeviceIdValue(record.deviceId),
        authorityId: parseId(record.authorityId, parseWalletAuthorityId, 'state.authorityId'),
        activatedAtMs: requireTimestamp(record.activatedAtMs, 'state.activatedAtMs'),
      };
    case 'failed_before_commit':
      requireExactKeys(record, ['state', 'error']);
      return { state, error: parseLinkPrecommitFailureV1(record.error) };
    case 'cancelled':
      requireExactKeys(record, ['state', 'cancelledAtMs']);
      return {
        state,
        cancelledAtMs: requireTimestamp(record.cancelledAtMs, 'state.cancelledAtMs'),
      };
    case 'expired':
      requireExactKeys(record, ['state', 'expiredAtMs']);
      return { state, expiredAtMs: requireTimestamp(record.expiredAtMs, 'state.expiredAtMs') };
    default:
      throw new Error('state is invalid');
  }
}

function parseLinkPrecommitFailureV1(raw: unknown): LinkPrecommitFailureV1 {
  const record = requireRecord(raw, 'state.error');
  requireExactKeys(record, ['kind', 'reason']);
  const kind = parseIdentityString(record.kind, 'state.error.kind');
  const reason = parseIdentityString(record.reason, 'state.error.reason');
  switch (kind) {
    case 'invalid_input':
    case 'unauthorized_source':
    case 'revoked_source':
    case 'permission_attenuation_failed':
    case 'target_factor_failed':
    case 'expired_session':
    case 'cancelled_session':
    case 'claim_conflict':
    case 'package_preparation_failed':
      return { kind, reason };
    default:
      throw new Error('state.error.kind is invalid');
  }
}

function parseOptionalClaimTranscript(raw: unknown): LinkedDeviceClaimTranscriptV1 | undefined {
  if (raw === undefined) return undefined;
  const record = requireRecord(raw, 'claimTranscript');
  requireExactKeys(record, ['digestB64u', 'value']);
  return {
    digestB64u: requireDigest(record.digestB64u, 'claimTranscript.digestB64u'),
    value: parseLinkedDeviceClaimV1(record.value),
  };
}

function parseOptionalApprovalTranscript(
  raw: unknown,
): LinkedDeviceApprovalTranscriptV1 | undefined {
  if (raw === undefined) return undefined;
  const record = requireRecord(raw, 'approvalTranscript');
  requireExactKeys(record, ['digestB64u', 'value', 'sourceKeyManifestDigestB64u']);
  return {
    digestB64u: requireDigest(record.digestB64u, 'approvalTranscript.digestB64u'),
    value: parseLinkedDeviceApprovalV1(record.value),
    sourceKeyManifestDigestB64u: requireDigest(
      record.sourceKeyManifestDigestB64u,
      'approvalTranscript.sourceKeyManifestDigestB64u',
    ),
  };
}

function parseOptionalTargetFactor(raw: unknown): LinkedDeviceTargetFactorV1 | undefined {
  if (raw === undefined) return undefined;
  const record = requireRecord(raw, 'targetFactor');
  requireExactKeys(record, ['kind']);
  if (record.kind === 'passkey_prf' || record.kind === 'email_otp') return { kind: record.kind };
  throw new Error('targetFactor.kind is invalid');
}

function parseOptionalEmailOtpChallenge(raw: unknown): LinkedDeviceEmailOtpChallengeV1 | undefined {
  if (raw === undefined) return undefined;
  const record = requireRecord(raw, 'emailOtpChallenge');
  const state = parseIdentityString(record.state, 'emailOtpChallenge.state');
  if (state === 'available') {
    requireExactKeys(record, ['state', 'maskedEmailHint']);
    return {
      state,
      maskedEmailHint: parseIdentityString(
        record.maskedEmailHint,
        'emailOtpChallenge.maskedEmailHint',
      ),
    };
  }
  if (state === 'sent') {
    requireExactKeys(record, [
      'state',
      'challengeId',
      'workerEphemeralPublicKey65B64u',
      'maskedEmailHint',
      'expiresAtMs',
      'resendAvailableAtMs',
    ]);
    return {
      state,
      challengeId: parseIdentityString(record.challengeId, 'emailOtpChallenge.challengeId'),
      workerEphemeralPublicKey65B64u: parseIdentityString(
        record.workerEphemeralPublicKey65B64u,
        'emailOtpChallenge.workerEphemeralPublicKey65B64u',
      ),
      maskedEmailHint: parseIdentityString(
        record.maskedEmailHint,
        'emailOtpChallenge.maskedEmailHint',
      ),
      expiresAtMs: requireTimestamp(record.expiresAtMs, 'emailOtpChallenge.expiresAtMs'),
      resendAvailableAtMs: requireTimestamp(
        record.resendAvailableAtMs,
        'emailOtpChallenge.resendAvailableAtMs',
      ),
    };
  }
  throw new Error('emailOtpChallenge.state is invalid');
}

function parseEmailOtpChallengeV1(raw: unknown): LinkedDeviceEmailOtpChallengeV1 {
  const record = requireRecord(raw, 'challenge');
  requireExactKeys(record, [
    'challengeId',
    'workerEphemeralPublicKey65B64u',
    'maskedEmailHint',
    'expiresAtMs',
    'resendAvailableAtMs',
  ]);
  return {
    state: 'sent',
    challengeId: parseIdentityString(record.challengeId, 'challenge.challengeId'),
    workerEphemeralPublicKey65B64u: parseIdentityString(
      record.workerEphemeralPublicKey65B64u,
      'challenge.workerEphemeralPublicKey65B64u',
    ),
    maskedEmailHint: parseIdentityString(record.maskedEmailHint, 'challenge.maskedEmailHint'),
    expiresAtMs: requireTimestamp(record.expiresAtMs, 'challenge.expiresAtMs'),
    resendAvailableAtMs: requireTimestamp(
      record.resendAvailableAtMs,
      'challenge.resendAvailableAtMs',
    ),
  };
}

function emailOtpChallengeForApproval(
  approval: LinkedDeviceApprovalV1,
): LinkedDeviceEmailOtpChallengeV1 | undefined {
  if (approval.targetFactor.kind !== 'email_otp') return undefined;
  if (approval.ownerEnrollment.kind !== 'linked_device_email_otp_owner_enrollment_v1')
    throw new Error('email OTP approval requires an email owner enrollment ceremony');
  return { state: 'available', maskedEmailHint: approval.ownerEnrollment.maskedEmailHint };
}

function parseOwnerAuthorizationV1(raw: unknown): LinkedDeviceOwnerAuthorizationSourceV1 {
  const record = requireRecord(raw, 'ownerAuthorization');
  const kind = parseIdentityString(record.kind, 'ownerAuthorization.kind');
  switch (kind) {
    case 'wallet_session':
      requireExactKeys(record, ['kind', 'walletSessionId', 'authorizationId']);
      return {
        kind,
        walletSessionId: parseAuthorizationId(
          record.walletSessionId,
          parseWalletSessionId,
          'walletSessionId',
        ),
        authorizationId: parseAuthorizationId(
          record.authorizationId,
          parseWalletSessionAuthorizationId,
          'authorizationId',
        ),
      };
    case 'step_up':
      requireExactKeys(record, ['kind', 'evidenceSetId']);
      return {
        kind,
        evidenceSetId: parseAuthorizationId(
          record.evidenceSetId,
          parseAuthorizationEvidenceSetId,
          'evidenceSetId',
        ),
      };
    default:
      throw new Error('ownerAuthorization.kind is invalid');
  }
}

function requireNoRecordFacts(
  input: {
    readonly claimTranscript?: LinkedDeviceClaimTranscriptV1;
    readonly approvalTranscript?: LinkedDeviceApprovalTranscriptV1;
    readonly targetFactor?: LinkedDeviceTargetFactorV1;
    readonly emailOtpChallenge?: LinkedDeviceEmailOtpChallengeV1;
    readonly authorityId?: WalletAuthorityId;
    readonly packageSetDigestB64u?: DigestB64u;
  },
  state: string,
): void {
  if (
    input.claimTranscript ||
    input.approvalTranscript ||
    input.targetFactor ||
    input.emailOtpChallenge ||
    input.authorityId ||
    input.packageSetDigestB64u
  )
    throw new Error(`${state} session carries invalid durable facts`);
}

function requireClaimRecordFacts(
  input: {
    readonly claimTranscript?: LinkedDeviceClaimTranscriptV1;
    readonly approvalTranscript?: LinkedDeviceApprovalTranscriptV1;
    readonly targetFactor?: LinkedDeviceTargetFactorV1;
    readonly emailOtpChallenge?: LinkedDeviceEmailOtpChallengeV1;
    readonly authorityId?: WalletAuthorityId;
    readonly packageSetDigestB64u?: DigestB64u;
  },
  state: string,
): asserts input is typeof input & { readonly claimTranscript: LinkedDeviceClaimTranscriptV1 } {
  if (
    !input.claimTranscript ||
    input.approvalTranscript ||
    input.targetFactor ||
    input.emailOtpChallenge ||
    input.authorityId ||
    input.packageSetDigestB64u
  )
    throw new Error(`${state} session facts are invalid`);
}

function requireApprovedRecordFacts(
  input: {
    readonly claimTranscript?: LinkedDeviceClaimTranscriptV1;
    readonly approvalTranscript?: LinkedDeviceApprovalTranscriptV1;
    readonly targetFactor?: LinkedDeviceTargetFactorV1;
    readonly emailOtpChallenge?: LinkedDeviceEmailOtpChallengeV1;
    readonly authorityId?: WalletAuthorityId;
    readonly packageSetDigestB64u?: DigestB64u;
  },
  state: string,
): asserts input is typeof input & {
  readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1;
  readonly targetFactor: LinkedDeviceTargetFactorV1;
} {
  if (!input.claimTranscript || !input.approvalTranscript || !input.targetFactor)
    throw new Error(`${state} session facts are incomplete`);
  if (input.authorityId || input.packageSetDigestB64u)
    throw new Error(`${state} session contains committed facts`);
  if (input.targetFactor.kind === 'email_otp' && !input.emailOtpChallenge)
    throw new Error(`${state} email session is missing challenge state`);
  if (input.targetFactor.kind === 'passkey_prf' && input.emailOtpChallenge)
    throw new Error(`${state} passkey session contains email challenge state`);
}

function requireCommittedRecordFacts(
  input: {
    readonly claimTranscript?: LinkedDeviceClaimTranscriptV1;
    readonly approvalTranscript?: LinkedDeviceApprovalTranscriptV1;
    readonly targetFactor?: LinkedDeviceTargetFactorV1;
    readonly emailOtpChallenge?: LinkedDeviceEmailOtpChallengeV1;
    readonly authorityId?: WalletAuthorityId;
    readonly packageSetDigestB64u?: DigestB64u;
  },
  state: string,
): asserts input is typeof input & {
  readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1;
  readonly targetFactor: LinkedDeviceTargetFactorV1;
  readonly authorityId: WalletAuthorityId;
  readonly packageSetDigestB64u: DigestB64u;
} {
  if (
    !input.claimTranscript ||
    !input.approvalTranscript ||
    !input.targetFactor ||
    !input.authorityId ||
    !input.packageSetDigestB64u
  )
    throw new Error(`${state} session facts are incomplete`);
  if (input.targetFactor.kind === 'email_otp' && !input.emailOtpChallenge)
    throw new Error(`${state} email session is missing challenge state`);
  if (input.targetFactor.kind === 'passkey_prf' && input.emailOtpChallenge)
    throw new Error(`${state} passkey session contains email challenge state`);
}

function requireNoCommittedFacts(
  input: { readonly authorityId?: WalletAuthorityId; readonly packageSetDigestB64u?: DigestB64u },
  state: string,
): void {
  if (input.authorityId || input.packageSetDigestB64u)
    throw new Error(`${state} session contains committed facts`);
}

function requireRecordIdentityFacts(input: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly qrPayload: QrLinkedDeviceSessionPayloadV5;
  readonly state: LinkSessionStateV1;
  readonly claimTranscript?: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript?: LinkedDeviceApprovalTranscriptV1;
  readonly targetFactor?: LinkedDeviceTargetFactorV1;
}): void {
  if (input.targetFactor && input.targetFactor.kind !== input.qrPayload.targetFactor.kind) {
    throw new Error('target factor does not match QR payload');
  }
  const claim = input.claimTranscript?.value;
  if (claim) {
    if (
      claim.linkSessionId !== input.linkSessionId ||
      claim.devicePublicKeyB64u !== input.qrPayload.devicePublicKeyB64u ||
      claim.targetFactor.kind !== input.qrPayload.targetFactor.kind
    ) {
      throw new Error('claim transcript identity does not match QR payload');
    }
  }
  const approval = input.approvalTranscript?.value;
  if (approval) {
    if (
      approval.linkSessionId !== input.linkSessionId ||
      approval.linkPublicKeyB64u !== input.qrPayload.linkPublicKeyB64u ||
      approval.devicePublicKeyB64u !== input.qrPayload.devicePublicKeyB64u ||
      approval.targetFactor.kind !== input.qrPayload.targetFactor.kind
    ) {
      throw new Error('approval transcript identity does not match QR payload');
    }
  }
  if (
    claim &&
    approval &&
    parseDeviceIdValue(claim.deviceId) !== parseDeviceIdValue(approval.deviceId)
  ) {
    throw new Error('approval transcript device identity does not match claim transcript');
  }
  switch (input.state.state) {
    case 'displaying_qr':
    case 'failed_before_commit':
    case 'cancelled':
    case 'expired':
      return;
    case 'claimed':
    case 'awaiting_target_factor':
    case 'provisioning':
      if (!claim || input.state.deviceId !== parseDeviceIdValue(claim.deviceId)) {
        throw new Error(`${input.state.state} device identity does not match claim transcript`);
      }
      return;
    case 'authority_pending_local_install':
    case 'active':
      if (
        !claim ||
        !approval ||
        input.state.deviceId !== parseDeviceIdValue(claim.deviceId) ||
        input.state.deviceId !== parseDeviceIdValue(approval.deviceId)
      ) {
        throw new Error(`${input.state.state} device identity does not match transcripts`);
      }
      return;
    default:
      return assertNeverLinkSessionStateV1(input.state);
  }
}

function requireTerminalRecordFacts(
  input: {
    readonly claimTranscript?: LinkedDeviceClaimTranscriptV1;
    readonly approvalTranscript?: LinkedDeviceApprovalTranscriptV1;
    readonly targetFactor?: LinkedDeviceTargetFactorV1;
    readonly emailOtpChallenge?: LinkedDeviceEmailOtpChallengeV1;
    readonly authorityId?: WalletAuthorityId;
    readonly packageSetDigestB64u?: DigestB64u;
  },
  state: string,
): void {
  requireNoCommittedFacts(input, state);
  if (
    !input.claimTranscript &&
    (input.approvalTranscript || input.targetFactor || input.emailOtpChallenge)
  ) {
    throw new Error(`${state} session facts are incomplete`);
  }
  if (!input.approvalTranscript && input.emailOtpChallenge) {
    throw new Error(`${state} session email challenge has no approval`);
  }
  if (input.approvalTranscript && !input.targetFactor) {
    throw new Error(`${state} session approval has no target factor`);
  }
  if (input.targetFactor?.kind === 'email_otp' && !input.emailOtpChallenge) {
    throw new Error(`${state} email session is missing challenge state`);
  }
  if (input.targetFactor?.kind === 'passkey_prf' && input.emailOtpChallenge) {
    throw new Error(`${state} passkey session contains email challenge state`);
  }
}

function buildClaimV1(
  payload: QrLinkedDeviceSessionPayloadV5,
  identity: LinkedDeviceSessionClaimIdentityV1,
  claimedAtMs: number,
): LinkedDeviceClaimV1 {
  if (identity.claimExpiresAtMs <= claimedAtMs || identity.claimExpiresAtMs > payload.expiresAtMs)
    throw new Error('claim expiry is outside the link session lifetime');
  return {
    kind: 'linked_device_session_claim_v1',
    linkSessionId: payload.linkSessionId,
    walletId: identity.walletId,
    enrollmentId: identity.enrollmentId,
    deviceId: identity.deviceId,
    devicePublicKeyB64u: payload.devicePublicKeyB64u,
    targetFactor: payload.targetFactor,
    claimedAtMs,
    claimExpiresAtMs: identity.claimExpiresAtMs,
  };
}

function parseDeviceIdValue(raw: unknown): DeviceId {
  const parsed = parseDeviceId(raw);
  if (!parsed.ok) throw new Error(`deviceId: ${parsed.error.message}`);
  return parsed.value;
}

function parseId<T>(
  raw: unknown,
  parser: (value: unknown) => DomainIdParseResult<T>,
  field: string,
): T {
  const parsed = parser(raw);
  if (!parsed.ok) throw new Error(`${field}: ${parsed.error.message}`);
  return parsed.value;
}

function parseOptionalId<T>(
  raw: unknown,
  parser: (value: unknown) => DomainIdParseResult<T>,
  field: string,
): T | undefined {
  return raw === undefined ? undefined : parseId(raw, parser, field);
}

function parseAuthorizationId<T>(
  raw: unknown,
  parser: (
    value: unknown,
  ) =>
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  field: string,
): T {
  const parsed = parser(raw);
  if (!parsed.ok) throw new Error(`${field}: ${parsed.error.message}`);
  return parsed.value;
}

function parseIdentityString(raw: unknown, field: string): string {
  if (
    typeof raw !== 'string' ||
    raw.length === 0 ||
    raw.trim() !== raw ||
    hasWhitespaceOrControlCharacters(raw)
  )
    throw new Error(`${field} is invalid`);
  return raw;
}

function requireDigest(raw: unknown, field: string): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch {
    throw new Error(`${field} is invalid`);
  }
}

function parseOptionalDigest(raw: unknown, field: string): DigestB64u | undefined {
  return raw === undefined ? undefined : requireDigest(raw, field);
}

function requireTimestamp(raw: unknown, field: string): number {
  if (!Number.isSafeInteger(raw) || Number(raw) <= 0)
    throw new Error(`${field} must be a positive safe integer`);
  return Number(raw);
}

function requirePositiveInteger(raw: unknown, field: string): number {
  return requireTimestamp(raw, field);
}

function requireRecord(raw: unknown, field: string): Record<string, unknown> {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw))
    throw new Error(`${field} must be an object`);
  return Object.fromEntries(Object.entries(raw));
}

function requireExactKeys(record: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(record).sort();
  const required = [...expected].sort();
  if (actual.length !== required.length || actual.some((key, index) => key !== required[index]))
    throw new Error('record contains invalid fields');
}

function requireAllowedKeys(record: Record<string, unknown>, allowed: readonly string[]): void {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(record))
    if (!allowedSet.has(key)) throw new Error('record contains invalid fields');
}

function normalizeSessionReadInput(
  input:
    | { readonly linkSessionId: LinkDeviceSessionId; readonly nowMs: number }
    | LinkDeviceSessionId,
): { readonly linkSessionId: LinkDeviceSessionId; readonly nowMs: number } {
  if (typeof input === 'string')
    return {
      linkSessionId: parseId(input, parseLinkDeviceSessionId, 'linkSessionId'),
      nowMs: Date.now(),
    };
  return {
    linkSessionId: parseId(input.linkSessionId, parseLinkDeviceSessionId, 'linkSessionId'),
    nowMs: requireTimestamp(input.nowMs, 'nowMs'),
  };
}

function invalidInputResult(error: unknown): {
  readonly outcome: 'invalid_input';
  readonly message: string;
} {
  return {
    outcome: 'invalid_input',
    message:
      error instanceof Error ? error.message : String(error || 'invalid linked-device input'),
  };
}

function unauthorizedResult(
  code: string,
  message: string,
): { readonly outcome: 'unauthorized'; readonly code: string; readonly message: string } {
  return { outcome: 'unauthorized', code, message };
}

function conflictResult(
  expectedRevision: number,
  record: LinkedDeviceSessionRecordV1 | null,
): LinkedDeviceSessionMutationResultV1 {
  return {
    outcome: 'conflict',
    expectedRevision,
    actualRevision: record?.revision ?? null,
    record,
  };
}

function invalidStateResult(
  record: LinkedDeviceSessionRecordV1,
): LinkedDeviceSessionMutationResultV1 {
  return { outcome: 'invalid_state', state: record.state.state, record };
}

function integrityResult(
  record: LinkedDeviceSessionRecordV1,
  reason: 'authority_id_mismatch' | 'package_set_digest_mismatch',
): LinkedDeviceSessionMutationResultV1 {
  return { outcome: 'integrity_error', reason, record };
}
