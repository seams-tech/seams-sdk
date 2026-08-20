import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { alphabetizeStringify } from '@shared/utils/digests';
import {
  computeLinkedDeviceApprovalDigestV1,
  computeLinkedDeviceSessionClaimDigestV1,
} from '@shared/device-linking/digests';
import {
  parseLaneOperationId,
  parseLaneOperationIdempotencyKey,
  parseLaneShareEpoch,
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseLinkDeviceSessionId,
  parseSigningLaneId,
  parseWalletKeyId,
  type LaneOperationId,
  type LaneOperationIdempotencyKey,
  type LaneShareEpoch,
  type LinkedDeviceEnrollmentId,
  type LinkedDeviceId,
  type LinkDeviceSessionId,
  type SigningLaneId,
  type WalletKeyId,
} from '@shared/signing-lanes/ids';
import {
  hasWhitespaceOrControlCharacters,
  parseMpcMaterialActivationRef,
  parseWalletId,
  type DomainIdParseResult,
  type MpcMaterialActivationRef,
  type WalletId,
} from '@shared/utils/domainIds';
import {
  LINKED_DEVICE_CLOCK_SKEW_TOLERANCE_MS_V1,
} from '@shared/device-linking/requestProof';
import type {
  AuthorizationEvidenceSetId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseAuthorizationEvidenceSetId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceSessionClaimV1,
  LinkedDeviceEnrollmentReceiptV1,
  LinkedDeviceEnrollmentChildReceiptV1,
  LinkedDeviceEnrollmentKeyBindingV1,
  LinkedDeviceReceiptAcknowledgementV1,
  LinkedDeviceOwnerAuthorizationSourceV1,
  LinkedDeviceSessionState,
  LinkedDeviceTargetFactorV1,
  LinkDevicePublicKeyB64u,
  QrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking/contracts';
import {
  parseLinkedDeviceApprovalV1 as parseSharedLinkedDeviceApprovalV1,
  parseLinkedDeviceReceiptAcknowledgementV1 as parseSharedLinkedDeviceReceiptAcknowledgementV1,
  parseQrLinkedDeviceSessionPayloadV5 as parseSharedQrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking/parsers';
import {
  buildFullOwnerDelegatedWalletAuthorityV1,
  hasDelegatedWalletPermissionV1,
  sameDelegatedWalletAuthorityV1,
  validateDelegatedWalletAuthorityAttenuationV1,
  type DelegatedWalletAuthorityV1,
} from '@shared/authorization/delegatedAuthority';
import {
  admitLinkedOwnerEnrollmentProvenanceV1,
  type LinkedOwnerEmailOtpBaseFactorReaderV1,
  type LinkedOwnerEnrollmentCeremonyReaderV1,
} from './linkedOwnerEnrollmentProvenance';
type LinkedDeviceClaimV1 = LinkedDeviceSessionClaimV1;

export type LinkedDeviceSessionListCursorV1 = {
  readonly updatedAtMs: number;
  readonly linkSessionId: LinkDeviceSessionId;
};

export type LinkedDeviceSessionListPageV1 = {
  readonly records: readonly LinkedDeviceSessionRecordV1[];
  readonly nextCursor: LinkedDeviceSessionListCursorV1 | null;
};

export type {
  LinkedDeviceSessionState,
  QrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking/contracts';

type LinkedDeviceSessionRecordBaseV1 = {
  readonly version: 'linked_device_session_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly qrPayload: QrLinkedDeviceSessionPayloadV5;
  readonly revision: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

type LinkedDeviceSessionUnclaimedRecordV1 = LinkedDeviceSessionRecordBaseV1 & {
  readonly state: Extract<
    LinkedDeviceSessionState,
    { readonly state: 'displaying_qr' | 'expired_unclaimed' | 'cancelled_unclaimed' }
  >;
  readonly claimTranscript?: never;
  readonly approvalTranscript?: never;
  readonly aggregateReceipt?: never;
};

type LinkedDeviceSessionClaimedRecordV1 = LinkedDeviceSessionRecordBaseV1 & {
  readonly state: Extract<LinkedDeviceSessionState, { readonly state: 'claimed_by_owner' }>;
  readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript?: never;
  readonly aggregateReceipt?: never;
};

type LinkedDeviceSessionApprovedRecordV1 = LinkedDeviceSessionRecordBaseV1 & {
  readonly state: Extract<
    LinkedDeviceSessionState,
    {
      readonly state: 'awaiting_target_factor' | 'provisioning';
    }
  >;
  readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1;
  readonly aggregateReceipt?: never;
};

type LinkedDeviceSessionCommittedRecordV1 = LinkedDeviceSessionRecordBaseV1 & {
  readonly state: Extract<
    LinkedDeviceSessionState,
    { readonly state: 'committed_completion_required' }
  >;
  readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1;
  readonly aggregateReceipt?: never;
};

type LinkedDeviceSessionActiveRecordV1 = LinkedDeviceSessionRecordBaseV1 & {
  readonly state: Extract<LinkedDeviceSessionState, { readonly state: 'active' }>;
  readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1;
  readonly aggregateReceipt: LinkedDeviceEnrollmentReceiptV1;
};

type LinkedDeviceSessionExpiredClaimedRecordV1 =
  | (LinkedDeviceSessionRecordBaseV1 & {
      readonly state: Extract<LinkedDeviceSessionState, { readonly state: 'expired_claimed' }>;
      readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
      readonly approvalTranscript?: never;
      readonly aggregateReceipt?: never;
    })
  | (LinkedDeviceSessionRecordBaseV1 & {
      readonly state: Extract<LinkedDeviceSessionState, { readonly state: 'expired_claimed' }>;
      readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
      readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1;
      readonly aggregateReceipt?: never;
    });

type LinkedDeviceSessionCancelledClaimedRecordV1 =
  | (LinkedDeviceSessionRecordBaseV1 & {
      readonly state: Extract<
        LinkedDeviceSessionState,
        { readonly state: 'cancelled_claimed_precommit' }
      >;
      readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
      readonly approvalTranscript?: never;
      readonly aggregateReceipt?: never;
    })
  | (LinkedDeviceSessionRecordBaseV1 & {
      readonly state: Extract<
        LinkedDeviceSessionState,
        { readonly state: 'cancelled_claimed_precommit' }
      >;
      readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
      readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1;
      readonly aggregateReceipt?: never;
    });

export type LinkedDeviceSessionRecordV1 =
  | LinkedDeviceSessionUnclaimedRecordV1
  | LinkedDeviceSessionClaimedRecordV1
  | LinkedDeviceSessionApprovedRecordV1
  | LinkedDeviceSessionCommittedRecordV1
  | LinkedDeviceSessionActiveRecordV1
  | LinkedDeviceSessionExpiredClaimedRecordV1
  | LinkedDeviceSessionCancelledClaimedRecordV1;

export type LinkedDeviceClaimTranscriptV1 = {
  readonly digestB64u: DigestB64u;
  readonly value: LinkedDeviceClaimV1;
};

export type LinkedDeviceApprovalTranscriptV1 = {
  readonly digestB64u: DigestB64u;
  readonly value: LinkedDeviceApprovalV1;
  /**
   * Taken from the owner Wallet Session that authorized this approval, never
   * from the approval body. The digest seals what Device 1 sent; only the
   * session says which key set that device actually holds.
   */
  readonly sourceKeyManifestDigestB64u: DigestB64u;
};

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

/** Request-scoped owner Wallet Session context carried into claim/approval. */
export type LinkedDeviceOwnerAuthorizationContextV1 = {
  readonly walletId: WalletId;
  readonly walletSessionId: WalletSessionId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly expiresAtMs: number;
  readonly permission: DelegatedWalletAuthorityV1;
  readonly curve: 'ed25519' | 'ecdsa';
  /**
   * The manifest the source device's key set for this curve was registered
   * against. This is one key set's manifest, not a wallet-wide one — a wallet
   * may hold several, each established by its own registration.
   */
  readonly keyManifestDigestB64u: DigestB64u;
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

export type LinkedDeviceAggregateActivationVerifierV1 = {
  verifyAggregateActivationV1(input: {
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly walletId: WalletId;
    readonly deviceId: LinkedDeviceId;
    readonly manifestDigestB64u: DigestB64u;
    readonly orderedChildReceipts: readonly LinkedDeviceEnrollmentChildReceiptV1[];
  }): Promise<
    { readonly kind: 'verified' } | { readonly kind: 'rejected'; readonly message: string }
  >;
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
    readonly claimDigestB64u: string;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1>;
  recordOwnerApprovalV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly approval: LinkedDeviceApprovalV1;
    readonly approvalDigestB64u: string;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1>;
  recordTargetCredentialV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly keyManifestDigestB64u: DigestB64u;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1>;
  recordEmailOtpChallengeStateV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1>;
  markCommittedCompletionRequiredV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly transcriptSetDigestB64u: DigestB64u;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1>;
  recordAggregateActivationV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly receipt: LinkedDeviceEnrollmentReceiptV1;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceMutationResultWithReceiptV1>;
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
  | {
      readonly outcome: 'invalid_state';
      readonly state: LinkedDeviceSessionState['state'];
      readonly record: LinkedDeviceSessionRecordV1;
    };

export type LinkedDeviceMutationResultWithReceiptV1 =
  | Extract<LinkedDeviceSessionMutationResultV1, { readonly outcome: 'applied' | 'replayed' }>
  | Extract<LinkedDeviceSessionMutationResultV1, { readonly outcome: 'conflict' }>
  | Extract<LinkedDeviceSessionMutationResultV1, { readonly outcome: 'expired' }>
  | Extract<LinkedDeviceSessionMutationResultV1, { readonly outcome: 'invalid_state' }>;

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

export type LinkedDeviceSessionCommitInputV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly transcriptSetDigestB64u: DigestB64u;
  readonly nowMs: number;
};

export type LinkedDeviceSessionTargetCredentialInputV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly keyManifestDigestB64u: DigestB64u;
  readonly nowMs: number;
};

/** Server-issued public challenge state for an approved `email_otp` session. */
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

/** Reserves the current session revision for the owner-credential commit. */
export type LinkedOwnerEnrollmentCompletionInputV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly nowMs: number;
};

export type LinkedOwnerEnrollmentCompletionResultV1 =
  | LinkedDeviceSessionMutationResultV1
  | { readonly outcome: 'invalid_input'; readonly message: string };

/**
 * A completion that has passed its preconditions but has not been written.
 *
 * Device 2's owner finalize commits a credential it cannot take back, so the
 * session reservation has to share that commit rather than follow it. This is the
 * half a transport-agnostic service can produce: the validated next record and
 * the revision it must still be at. Turning it into a write belongs to the
 * store, which is the only layer that knows what a batch is.
 */
export type LinkedOwnerEnrollmentCompletionPlanV1 =
  | {
      readonly outcome: 'prepared';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly expectedRevision: number;
      readonly nextRecord: LinkedDeviceSessionRecordV1;
      readonly nowMs: number;
    }
  | LinkedOwnerEnrollmentCompletionRefusalV1;

/**
 * Why a completion cannot be written. Spelled out rather than subtracted from
 * the mutation result, because a plan can only ever be refused for a reason a
 * reader could see — it never reports `applied`, having written nothing.
 */
export type LinkedOwnerEnrollmentCompletionRefusalV1 =
  | {
      readonly outcome: 'conflict';
      readonly expectedRevision: number;
      readonly actualRevision: number | null;
      readonly record: LinkedDeviceSessionRecordV1 | null;
    }
  | {
      readonly outcome: 'invalid_state';
      readonly state: LinkedDeviceSessionState['state'];
      readonly record: LinkedDeviceSessionRecordV1;
    }
  | { readonly outcome: 'expired'; readonly record: LinkedDeviceSessionRecordV1 }
  | { readonly outcome: 'invalid_input'; readonly message: string };

export type LinkedDeviceSessionAggregateActivationInputV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly acknowledgement: LinkedDeviceReceiptAcknowledgementV1;
  readonly nowMs: number;
};

/**
 * The default when no base-factor reader is wired: every Email OTP approval is
 * refused as `email_otp_base_factor_unavailable`. Fail-closed by construction —
 * a composition that forgets the reader cannot admit an email enrollment, and
 * Passkey approvals never consult it.
 */
const FAIL_CLOSED_EMAIL_OTP_BASE_FACTOR_READER_V1: LinkedOwnerEmailOtpBaseFactorReaderV1 = {
  readActiveEmailOtpBaseFactorV1: () => Promise.resolve(null),
};

export class LinkedDeviceSessionServiceV1 {
  private readonly store: LinkedDeviceSessionStoreV1;
  private readonly authorization: LinkedDeviceOwnerAuthorizationPortV1;
  private readonly aggregateActivationVerifier: LinkedDeviceAggregateActivationVerifierV1;
  private readonly ownerEnrollmentCeremonies: LinkedOwnerEnrollmentCeremonyReaderV1;
  private readonly emailOtpBaseFactors: LinkedOwnerEmailOtpBaseFactorReaderV1;

  constructor(input: {
    readonly store: LinkedDeviceSessionStoreV1;
    readonly authorization: LinkedDeviceOwnerAuthorizationPortV1;
    readonly aggregateActivationVerifier: LinkedDeviceAggregateActivationVerifierV1;
    readonly ownerEnrollmentCeremonies: LinkedOwnerEnrollmentCeremonyReaderV1;
    readonly emailOtpBaseFactors?: LinkedOwnerEmailOtpBaseFactorReaderV1;
  }) {
    this.store = input.store;
    this.authorization = input.authorization;
    this.aggregateActivationVerifier = input.aggregateActivationVerifier;
    this.ownerEnrollmentCeremonies = input.ownerEnrollmentCeremonies;
    this.emailOtpBaseFactors =
      input.emailOtpBaseFactors ?? FAIL_CLOSED_EMAIL_OTP_BASE_FACTOR_READER_V1;
  }

  async createUnclaimedSessionV1(
    input: LinkedDeviceSessionCreateInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      const payload = parseQrLinkedDeviceSessionPayloadV1(input.payload);
      requireTimestamp(input.nowMs, 'nowMs');
      if (payload.expiresAtMs <= input.nowMs) {
        return { outcome: 'invalid_input', message: 'link session expiry must be in the future' };
      }
      const record = buildUnclaimedSessionRecordV1(payload, input.nowMs);
      return await this.store.createUnclaimedSessionV1(record);
    } catch (error: unknown) {
      return { outcome: 'invalid_input', message: errorMessage(error) };
    }
  }

  async claimSessionV1(
    input: LinkedDeviceSessionClaimInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      const payload = parseQrLinkedDeviceSessionPayloadV1(input.payload);
      requireTimestamp(input.nowMs, 'nowMs');
      const existing = await this.store.getSessionV1(payload.linkSessionId);
      if (!existing) {
        return { outcome: 'conflict', expectedRevision: 0, actualRevision: null, record: null };
      }
      if (!sameQrPayload(existing.qrPayload, payload)) {
        return {
          outcome: 'conflict',
          expectedRevision: existing.revision,
          actualRevision: existing.revision,
          record: existing,
        };
      }
      if (
        existing.state.state === 'displaying_qr' &&
        input.nowMs >= existing.qrPayload.expiresAtMs
      ) {
        return { outcome: 'expired', record: existing };
      }
      const requestedAuthorityError = validateLinkedDeviceRequestedAuthorityV1(
        payload.requestedPermission,
      );
      if (requestedAuthorityError) {
        return {
          outcome: 'unauthorized',
          code: 'unauthorized',
          message: requestedAuthorityError,
        };
      }
      const authorization = await this.authorization.authorizeOwnerClaimV1({
        payload,
        requestedAtMs: input.nowMs,
        owner: input.owner,
      });
      if (authorization.kind === 'denied') {
        return {
          outcome: 'unauthorized',
          code: authorization.code,
          message: authorization.message,
        };
      }
      const claim = buildClaimV1(payload, authorization.identity, input.nowMs);
      const claimDigestB64u = await digestTranscriptV1('claim', claim);
      if (
        existing.claimTranscript?.digestB64u === claimDigestB64u &&
        alphabetizeStringify(existing.claimTranscript.value) === alphabetizeStringify(claim)
      ) {
        return { outcome: 'replayed', record: existing };
      }
      if (existing.claimTranscript) {
        return {
          outcome: 'conflict',
          expectedRevision: existing.revision,
          actualRevision: existing.revision,
          record: existing,
        };
      }
      const nextState = claimedByOwnerStateV1(existing, claim);
      const nextRecord = replaceSessionRecordV1(existing, {
        state: nextState,
        revision: existing.revision + 1,
        claimTranscript: { digestB64u: claimDigestB64u, value: claim },
        updatedAtMs: input.nowMs,
      });
      return await this.store.claimSessionV1({
        linkSessionId: payload.linkSessionId,
        expectedRevision: existing.revision,
        claim,
        claimDigestB64u,
        nextRecord,
        nowMs: input.nowMs,
      });
    } catch (error: unknown) {
      return { outcome: 'invalid_input', message: errorMessage(error) };
    }
  }

  async recordOwnerApprovalV1(
    input: LinkedDeviceSessionApprovalInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      const approval = parseLinkedDeviceApprovalV1(input.approval);
      requireTimestamp(input.nowMs, 'nowMs');
      const existing = await this.store.getSessionV1(approval.linkSessionId);
      if (!existing) {
        return { outcome: 'conflict', expectedRevision: 0, actualRevision: null, record: null };
      }
      const approvalDigestB64u = await digestTranscriptV1('approval', approval);
      if (
        existing.approvalTranscript?.digestB64u === approvalDigestB64u &&
        alphabetizeStringify(existing.approvalTranscript.value) === alphabetizeStringify(approval)
      ) {
        return { outcome: 'replayed', record: existing };
      }
      if (existing.approvalTranscript) {
        return {
          outcome: 'conflict',
          expectedRevision: existing.revision,
          actualRevision: existing.revision,
          record: existing,
        };
      }
      if (
        existing.state.state === 'claimed_by_owner' &&
        input.nowMs >= existing.state.claimExpiresAtMs
      ) {
        return { outcome: 'expired', record: existing };
      }
      validateApprovalMatchesSession(existing, approval, input.nowMs);
      const requestedAuthorityError = validateLinkedDeviceRequestedAuthorityV1(
        approval.permission,
      );
      if (requestedAuthorityError) {
        return {
          outcome: 'unauthorized',
          code: 'unauthorized',
          message: requestedAuthorityError,
        };
      }
      // Provenance before immutability: the approval digest would otherwise
      // seal whatever ceremony the caller named, including one belonging to
      // another wallet.
      const provenance = await admitLinkedOwnerEnrollmentProvenanceV1({
        approval,
        ceremonies: this.ownerEnrollmentCeremonies,
        emailOtpBaseFactors: this.emailOtpBaseFactors,
        requestedAtMs: input.nowMs,
      });
      if (!provenance.ok) {
        return {
          outcome: 'unauthorized',
          code: 'linked_device_owner_enrollment_rejected',
          message: `linked-device owner enrollment ceremony rejected: ${provenance.reason}`,
        };
      }
      const authorization = await this.authorization.authorizeOwnerApprovalV1({
        session: existing,
        approval,
        requestedAtMs: input.nowMs,
        owner: input.owner,
      });
      if (authorization.kind === 'denied') {
        return {
          outcome: 'unauthorized',
          code: authorization.code,
          message: authorization.message,
        };
      }
      const nextState = awaitingTargetFactorStateV1(existing, approval);
      const nextRecord = replaceSessionRecordV1(existing, {
        state: nextState,
        revision: existing.revision + 1,
        approvalTranscript: {
          digestB64u: approvalDigestB64u,
          value: approval,
          sourceKeyManifestDigestB64u: input.owner.keyManifestDigestB64u,
        },
        updatedAtMs: input.nowMs,
      });
      return await this.store.recordOwnerApprovalV1({
        linkSessionId: approval.linkSessionId,
        expectedRevision: existing.revision,
        approval,
        approvalDigestB64u,
        nextRecord,
        nowMs: input.nowMs,
      });
    } catch (error: unknown) {
      return { outcome: 'invalid_input', message: errorMessage(error) };
    }
  }

  async markCommittedCompletionRequiredV1(
    input: LinkedDeviceSessionCommitInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      requireTimestamp(input.nowMs, 'nowMs');
      const digestB64u = requireDigest(input.transcriptSetDigestB64u, 'transcriptSetDigestB64u');
      const existing = await this.requireSession(input.linkSessionId);
      if (
        existing.state.state === 'committed_completion_required' &&
        existing.state.transcriptSetDigestB64u === digestB64u
      ) {
        return { outcome: 'replayed', record: existing };
      }
      if (existing.state.state !== 'provisioning') {
        return invalidStateResult(existing);
      }
      const nextState = committedCompletionRequiredStateV1(existing, digestB64u);
      const nextRecord = replaceSessionRecordV1(existing, {
        state: nextState,
        revision: existing.revision + 1,
        updatedAtMs: input.nowMs,
      });
      return await this.store.markCommittedCompletionRequiredV1({
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        transcriptSetDigestB64u: digestB64u,
        nextRecord,
        nowMs: input.nowMs,
      });
    } catch (error: unknown) {
      return { outcome: 'invalid_input', message: errorMessage(error) };
    }
  }

  async recordTargetCredentialV1(
    input: LinkedDeviceSessionTargetCredentialInputV1,
  ): Promise<LinkedDeviceTargetCredentialMutationResultV1> {
    try {
      requireTimestamp(input.nowMs, 'nowMs');
      const keyManifestDigestB64u = requireDigest(
        input.keyManifestDigestB64u,
        'keyManifestDigestB64u',
      );
      const existing = await this.requireSession(input.linkSessionId);
      if (
        existing.state.state === 'provisioning' &&
        existing.state.keyManifestDigestB64u === keyManifestDigestB64u
      ) {
        return { outcome: 'replayed', record: existing };
      }
      if (existing.state.state !== 'awaiting_target_factor') {
        return invalidStateResult(existing);
      }
      if (input.nowMs >= awaitingTargetDeadlineMsV1(existing)) {
        return { outcome: 'expired', record: existing };
      }
      const nextRecord = replaceSessionRecordV1(existing, {
        state: provisioningStateV1(existing, keyManifestDigestB64u),
        revision: existing.revision + 1,
        updatedAtMs: input.nowMs,
      });
      return await this.store.recordTargetCredentialV1({
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        keyManifestDigestB64u,
        nextRecord,
        nowMs: input.nowMs,
      });
    } catch (error: unknown) {
      return { outcome: 'invalid_input', message: errorMessage(error) };
    }
  }

  /**
   * Records the public state of the one outstanding Email OTP challenge for an
   * approved `email_otp` session. Only server-issued public facts enter the
   * record — the OTP code and destination address never do. Re-recording the
   * identical challenge replays; a different challenge id supersedes the
   * previous one (a resend after expiry), which is why this is a revision-
   * guarded state write rather than an append.
   */
  async recordEmailOtpChallengeStateV1(
    input: LinkedDeviceSessionEmailOtpChallengeInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      requireTimestamp(input.nowMs, 'nowMs');
      requireTimestamp(input.challenge.expiresAtMs, 'challenge.expiresAtMs');
      requireTimestamp(input.challenge.resendAvailableAtMs, 'challenge.resendAvailableAtMs');
      if (!input.challenge.challengeId) throw new Error('challenge.challengeId is required');
      const existing = await this.requireSession(input.linkSessionId);
      if (
        existing.state.state !== 'awaiting_target_factor' ||
        existing.state.targetFactor.kind !== 'email_otp'
      ) {
        return invalidStateResult(existing);
      }
      if (input.nowMs >= awaitingTargetDeadlineMsV1(existing)) {
        return { outcome: 'expired', record: existing };
      }
      const currentChallenge = existing.state.emailOtpChallenge;
      if (!currentChallenge) return invalidStateResult(existing);
      const nextChallenge = {
        state: 'sent' as const,
        challengeId: input.challenge.challengeId,
        workerEphemeralPublicKey65B64u: input.challenge.workerEphemeralPublicKey65B64u,
        maskedEmailHint: currentChallenge.maskedEmailHint,
        expiresAtMs: input.challenge.expiresAtMs,
        resendAvailableAtMs: input.challenge.resendAvailableAtMs,
      };
      if (
        currentChallenge.state === 'sent' &&
        alphabetizeStringify(currentChallenge) === alphabetizeStringify(nextChallenge)
      ) {
        return { outcome: 'replayed', record: existing };
      }
      const nextRecord = replaceSessionRecordV1(existing, {
        state: {
          state: 'awaiting_target_factor',
          linkSessionId: existing.linkSessionId,
          walletId: existing.state.walletId,
          enrollmentId: existing.state.enrollmentId,
          targetFactor: { kind: 'email_otp' },
          emailOtpChallenge: nextChallenge,
        },
        revision: existing.revision + 1,
        updatedAtMs: input.nowMs,
      });
      return await this.store.recordEmailOtpChallengeStateV1({
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        nextRecord,
        nowMs: input.nowMs,
      });
    } catch (error: unknown) {
      return { outcome: 'invalid_input', message: errorMessage(error) };
    }
  }

  /**
   * Validates the completion and returns it as a plan, without writing.
   *
   * Same preconditions as `recordTargetCredentialV1` — that is the point, since
   * both describe the one legal transition out of `awaiting_target_factor` —
   * but stopping short of the store leaves the write available to a caller that
   * has to make it atomic with something else.
   */
  async prepareLinkedOwnerEnrollmentCompletionV1(
    input: LinkedOwnerEnrollmentCompletionInputV1,
  ): Promise<LinkedOwnerEnrollmentCompletionPlanV1> {
    try {
      requireTimestamp(input.nowMs, 'nowMs');
      const existing = await this.requireSession(input.linkSessionId);
      if (existing.state.state !== 'awaiting_target_factor') {
        return { outcome: 'invalid_state', state: existing.state.state, record: existing };
      }
      if (input.nowMs >= awaitingTargetDeadlineMsV1(existing)) {
        return { outcome: 'expired', record: existing };
      }
      return {
        outcome: 'prepared',
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        nextRecord: replaceSessionRecordV1(existing, {
          state: existing.state,
          revision: existing.revision + 1,
          updatedAtMs: input.nowMs,
        }),
        nowMs: input.nowMs,
      };
    } catch (error: unknown) {
      return { outcome: 'invalid_input', message: errorMessage(error) };
    }
  }

  async recordAggregateActivationV1(
    input: LinkedDeviceSessionAggregateActivationInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      requireTimestamp(input.nowMs, 'nowMs');
      const acknowledgement = parseSharedLinkedDeviceReceiptAcknowledgementV1(
        input.acknowledgement,
      );
      const receipt = parseAggregateReceiptV1(acknowledgement.receipt);
      const existing = await this.requireSession(input.linkSessionId);
      if (
        existing.state.state === 'active' &&
        existing.aggregateReceipt &&
        alphabetizeStringify(existing.aggregateReceipt) === alphabetizeStringify(receipt)
      ) {
        return { outcome: 'replayed', record: existing };
      }
      if (existing.state.state !== 'committed_completion_required') {
        return invalidStateResult(existing);
      }
      if (
        acknowledgement.linkSessionId !== existing.linkSessionId ||
        acknowledgement.enrollmentId !== existing.state.enrollmentId ||
        acknowledgement.deviceId !== deviceIdFromRecord(existing)
      ) {
        return {
          outcome: 'invalid_input',
          message: 'aggregate receipt acknowledgement identity does not match session',
        };
      }
      if (acknowledgement.acknowledgedAtMs < receipt.activatedAtMs) {
        return {
          outcome: 'invalid_input',
          message: 'aggregate receipt acknowledgement precedes activation',
        };
      }
      if (
        receipt.enrollmentId !== existing.state.enrollmentId ||
        receipt.walletId !== existing.state.walletId ||
        receipt.deviceId !== deviceIdFromRecord(existing)
      ) {
        return {
          outcome: 'invalid_input',
          message: 'aggregate receipt identity does not match session',
        };
      }
      validateAggregateReceiptMatchesApproval(existing, receipt);
      const verification = await this.aggregateActivationVerifier.verifyAggregateActivationV1({
        enrollmentId: existing.state.enrollmentId,
        walletId: existing.state.walletId,
        deviceId: deviceIdFromRecord(existing),
        manifestDigestB64u: receipt.manifestDigestB64u,
        orderedChildReceipts: receipt.orderedChildReceipts,
      });
      if (verification.kind === 'rejected') {
        return { outcome: 'invalid_input', message: verification.message };
      }
      const nextState: LinkedDeviceSessionState = {
        state: 'active',
        linkSessionId: existing.linkSessionId,
        walletId: existing.state.walletId,
        enrollmentId: existing.state.enrollmentId,
        activatedAtMs: receipt.activatedAtMs,
      };
      const nextRecord = replaceSessionRecordV1(existing, {
        state: nextState,
        aggregateReceipt: receipt,
        revision: existing.revision + 1,
        updatedAtMs: input.nowMs,
      });
      return await this.store.recordAggregateActivationV1({
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        receipt,
        nextRecord,
        nowMs: input.nowMs,
      });
    } catch (error: unknown) {
      return { outcome: 'invalid_input', message: errorMessage(error) };
    }
  }

  async cancelSessionV1(
    input: LinkedDeviceSessionCancelInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      requireTimestamp(input.nowMs, 'nowMs');
      const existing = await this.requireSession(input.linkSessionId);
      if (
        (existing.state.state === 'cancelled_unclaimed' ||
          existing.state.state === 'cancelled_claimed_precommit') &&
        existing.state.cancelledAtMs === input.nowMs
      ) {
        return { outcome: 'replayed', record: existing };
      }
      const nextState = cancellationStateV1(existing, input.nowMs);
      if (!nextState) return invalidStateResult(existing);
      const nextRecord = replaceSessionRecordV1(existing, {
        state: nextState,
        revision: existing.revision + 1,
        updatedAtMs: input.nowMs,
      });
      return await this.store.cancelSessionV1({
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        nextRecord,
        nowMs: input.nowMs,
      });
    } catch (error: unknown) {
      return { outcome: 'invalid_input', message: errorMessage(error) };
    }
  }

  async expireSessionV1(
    input: LinkedDeviceSessionExpireInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      requireTimestamp(input.nowMs, 'nowMs');
      const existing = await this.requireSession(input.linkSessionId);
      if (
        existing.state.state === 'expired_unclaimed' ||
        existing.state.state === 'expired_claimed'
      ) {
        return { outcome: 'replayed', record: existing };
      }
      const expiryMs = sessionExpiryMsV1(existing);
      if (input.nowMs < expiryMs) {
        return { outcome: 'invalid_input', message: 'link session has not expired' };
      }
      const nextState = expiryStateV1(existing, input.nowMs);
      if (!nextState) return invalidStateResult(existing);
      const nextRecord = replaceSessionRecordV1(existing, {
        state: nextState,
        revision: existing.revision + 1,
        updatedAtMs: input.nowMs,
      });
      return await this.store.expireSessionV1({
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        nextRecord,
        nowMs: input.nowMs,
      });
    } catch (error: unknown) {
      return { outcome: 'invalid_input', message: errorMessage(error) };
    }
  }

  async getSessionV1(
    input:
      | { readonly linkSessionId: LinkDeviceSessionId; readonly nowMs: number }
      | LinkDeviceSessionId,
  ): Promise<LinkedDeviceSessionRecordV1 | null> {
    const normalized = normalizeSessionReadInput(input);
    const existing = await this.store.getSessionV1(normalized.linkSessionId);
    if (!existing) return null;
    const expiryMs = sessionExpiryMsV1(existing);
    if (normalized.nowMs < expiryMs || isTerminalState(existing.state)) return existing;
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
    const projected: LinkedDeviceSessionRecordV1[] = [];
    for (const record of page.records) {
      const expiryMs = sessionExpiryMsV1(record);
      if (input.nowMs < expiryMs || isTerminalState(record.state)) {
        projected.push(record);
        continue;
      }
      const expired = await this.expireSessionV1({
        linkSessionId: record.linkSessionId,
        expectedRevision: record.revision,
        nowMs: input.nowMs,
      });
      projected.push(
        expired.outcome === 'applied' ||
          expired.outcome === 'replayed' ||
          expired.outcome === 'expired' ||
          expired.outcome === 'invalid_state'
          ? expired.record
          : record,
      );
    }
    return { records: projected, nextCursor: page.nextCursor };
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

export function buildUnclaimedSessionRecordV1(
  payload: QrLinkedDeviceSessionPayloadV5,
  nowMs: number,
): LinkedDeviceSessionRecordV1 {
  const parsedPayload = parseQrLinkedDeviceSessionPayloadV1(payload);
  requireTimestamp(nowMs, 'nowMs');
  if (parsedPayload.issuedAtMs - nowMs > LINKED_DEVICE_CLOCK_SKEW_TOLERANCE_MS_V1) {
    throw new Error('link session issuedAtMs is in the future');
  }
  return {
    version: 'linked_device_session_v1',
    linkSessionId: parsedPayload.linkSessionId,
    qrPayload: parsedPayload,
    state: {
      state: 'displaying_qr',
      linkSessionId: parsedPayload.linkSessionId,
      expiresAtMs: parsedPayload.expiresAtMs,
    },
    revision: 1,
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  };
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
    'aggregateReceipt',
    'createdAtMs',
    'updatedAtMs',
  ]);
  if (record.version !== 'linked_device_session_v1')
    throw new Error('linked device session version is invalid');
  const linkSessionId = parseId(record.linkSessionId, parseLinkDeviceSessionId, 'linkSessionId');
  const qrPayload = parseQrLinkedDeviceSessionPayloadV1(record.qrPayload);
  if (qrPayload.linkSessionId !== linkSessionId)
    throw new Error('linkSessionId does not match QR payload');
  const state = parseSessionStateV1(record.state);
  if (state.linkSessionId !== linkSessionId)
    throw new Error('state linkSessionId does not match record');
  const revision = requirePositiveInteger(record.revision, 'revision');
  const createdAtMs = requireTimestamp(record.createdAtMs, 'createdAtMs');
  const updatedAtMs = requireTimestamp(record.updatedAtMs, 'updatedAtMs');
  if (updatedAtMs < createdAtMs) throw new Error('updatedAtMs precedes createdAtMs');
  const claimTranscript =
    record.claimTranscript === undefined
      ? undefined
      : parseClaimTranscriptV1(record.claimTranscript);
  const approvalTranscript =
    record.approvalTranscript === undefined
      ? undefined
      : parseApprovalTranscriptV1(record.approvalTranscript);
  const aggregateReceipt =
    record.aggregateReceipt === undefined
      ? undefined
      : parseAggregateReceiptV1(record.aggregateReceipt);
  validateRecordTranscriptState(state, claimTranscript, approvalTranscript, aggregateReceipt);
  return buildSessionRecordV1({
    linkSessionId,
    qrPayload,
    state,
    revision,
    claimTranscript,
    approvalTranscript,
    aggregateReceipt,
    createdAtMs,
    updatedAtMs,
  });
}

export function parseQrLinkedDeviceSessionPayloadV1(raw: unknown): QrLinkedDeviceSessionPayloadV5 {
  return parseSharedQrLinkedDeviceSessionPayloadV5(raw);
}

function parseTargetFactorV1(raw: unknown): LinkedDeviceTargetFactorV1 {
  const record = requireRecord(raw, 'targetFactor');
  requireExactKeys(record, ['kind']);
  if (record.kind === 'passkey_prf') return { kind: 'passkey_prf' };
  if (record.kind === 'email_otp') return { kind: 'email_otp' };
  throw new Error('targetFactor kind is invalid');
}

type LinkedDeviceEmailOtpChallengeStateV1 = Extract<
  LinkedDeviceSessionState,
  {
    readonly state: 'awaiting_target_factor';
    readonly targetFactor: { readonly kind: 'email_otp' };
  }
>['emailOtpChallenge'];

function parseEmailOtpChallengeStateV1(raw: unknown): LinkedDeviceEmailOtpChallengeStateV1 {
  const record = requireRecord(raw, 'emailOtpChallenge');
  switch (record.state) {
    case 'available':
      requireExactKeys(record, ['state', 'maskedEmailHint']);
      return {
        state: 'available',
        maskedEmailHint: parseIdentityString(
          record.maskedEmailHint,
          'emailOtpChallenge.maskedEmailHint',
        ),
      };
    case 'sent': {
      requireExactKeys(record, [
        'state',
        'challengeId',
        'workerEphemeralPublicKey65B64u',
        'maskedEmailHint',
        'expiresAtMs',
        'resendAvailableAtMs',
      ]);
      return {
        state: 'sent',
        challengeId: parseIdentityString(record.challengeId, 'emailOtpChallenge.challengeId'),
        workerEphemeralPublicKey65B64u: parseFixedBase64UrlBytes(
          record.workerEphemeralPublicKey65B64u,
          65,
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
    default:
      throw new Error('emailOtpChallenge.state is unsupported');
  }
}

function buildClaimV1(
  payload: QrLinkedDeviceSessionPayloadV5,
  identity: LinkedDeviceSessionClaimIdentityV1,
  claimedAtMs: number,
): LinkedDeviceClaimV1 {
  if (identity.claimExpiresAtMs <= claimedAtMs || identity.claimExpiresAtMs > payload.expiresAtMs) {
    throw new Error('claim expiry is outside the link session lifetime');
  }
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

function claimedByOwnerStateV1(
  record: LinkedDeviceSessionRecordV1,
  claim: LinkedDeviceClaimV1,
): Extract<LinkedDeviceSessionState, { readonly state: 'claimed_by_owner' }> {
  if (record.state.state !== 'displaying_qr') throw new Error('link session is not claimable');
  return {
    state: 'claimed_by_owner',
    linkSessionId: record.linkSessionId,
    walletId: claim.walletId,
    enrollmentId: claim.enrollmentId,
    claimExpiresAtMs: claim.claimExpiresAtMs,
  };
}

function awaitingTargetFactorStateV1(
  record: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
): Extract<LinkedDeviceSessionState, { readonly state: 'awaiting_target_factor' }> {
  if (record.state.state !== 'claimed_by_owner')
    throw new Error('link session is not awaiting owner approval');
  switch (approval.targetFactor.kind) {
    case 'passkey_prf':
      return {
        state: 'awaiting_target_factor',
        linkSessionId: record.linkSessionId,
        walletId: record.state.walletId,
        enrollmentId: record.state.enrollmentId,
        targetFactor: { kind: 'passkey_prf' },
        credentialDeadlineMs: approval.expiresAtMs,
      };
    case 'email_otp': {
      if (approval.ownerEnrollment.kind !== 'linked_device_email_otp_owner_enrollment_v1') {
        throw new Error('email OTP approval requires the email owner enrollment ceremony');
      }
      return {
        state: 'awaiting_target_factor',
        linkSessionId: record.linkSessionId,
        walletId: record.state.walletId,
        enrollmentId: record.state.enrollmentId,
        targetFactor: { kind: 'email_otp' },
        emailOtpChallenge: {
          state: 'available',
          maskedEmailHint: approval.ownerEnrollment.maskedEmailHint,
        },
      };
    }
  }
  approval.targetFactor satisfies never;
  throw new Error('approval targetFactor kind is unsupported');
}

/**
 * The one deadline that gates leaving `awaiting_target_factor`. The Passkey
 * branch carries its credential deadline in the state; the Email OTP branch
 * deliberately does not carry a second clock — its deadline is the approval
 * expiry the challenge and grant TTLs must fit inside.
 */
function awaitingTargetDeadlineMsV1(record: LinkedDeviceSessionRecordV1): number {
  if (record.state.state !== 'awaiting_target_factor') {
    throw new Error('link session is not awaiting its target factor');
  }
  if (record.state.targetFactor.kind === 'passkey_prf') {
    const credentialDeadlineMs = record.state.credentialDeadlineMs;
    if (credentialDeadlineMs === undefined) {
      throw new Error('passkey awaiting state is missing its credential deadline');
    }
    return credentialDeadlineMs;
  }
  const approval = record.approvalTranscript?.value;
  if (!approval) throw new Error('awaiting session is missing owner approval');
  return approval.expiresAtMs;
}

function provisioningStateV1(
  record: LinkedDeviceSessionRecordV1,
  keyManifestDigestB64u: DigestB64u,
): Extract<LinkedDeviceSessionState, { readonly state: 'provisioning' }> {
  if (record.state.state !== 'awaiting_target_factor') {
    throw new Error('link session is not awaiting its target credential');
  }
  return {
    state: 'provisioning',
    linkSessionId: record.linkSessionId,
    walletId: record.state.walletId,
    enrollmentId: record.state.enrollmentId,
    keyManifestDigestB64u,
  };
}

function committedCompletionRequiredStateV1(
  record: LinkedDeviceSessionRecordV1,
  transcriptSetDigestB64u: DigestB64u,
): Extract<LinkedDeviceSessionState, { readonly state: 'committed_completion_required' }> {
  if (record.state.state !== 'provisioning') {
    throw new Error('link session has no committed provisioning output');
  }
  return {
    state: 'committed_completion_required',
    linkSessionId: record.linkSessionId,
    walletId: record.state.walletId,
    enrollmentId: record.state.enrollmentId,
    keyManifestDigestB64u: record.state.keyManifestDigestB64u,
    transcriptSetDigestB64u,
  };
}

export function buildCommittedCompletionRequiredLinkedDeviceSessionRecordV1(input: {
  readonly record: LinkedDeviceSessionRecordV1;
  readonly transcriptSetDigestB64u: DigestB64u;
  readonly committedAtMs: number;
}): LinkedDeviceSessionRecordV1 {
  const transcriptSetDigestB64u = requireDigest(
    input.transcriptSetDigestB64u,
    'transcriptSetDigestB64u',
  );
  const committedAtMs = requireTimestamp(input.committedAtMs, 'committedAtMs');
  return replaceSessionRecordV1(input.record, {
    state: committedCompletionRequiredStateV1(input.record, transcriptSetDigestB64u),
    revision: input.record.revision + 1,
    updatedAtMs: Math.max(input.record.updatedAtMs, committedAtMs),
  });
}

function cancellationStateV1(
  record: LinkedDeviceSessionRecordV1,
  cancelledAtMs: number,
): LinkedDeviceSessionState | null {
  switch (record.state.state) {
    case 'displaying_qr':
      return { state: 'cancelled_unclaimed', linkSessionId: record.linkSessionId, cancelledAtMs };
    case 'claimed_by_owner':
    case 'awaiting_target_factor':
    case 'provisioning':
      return {
        state: 'cancelled_claimed_precommit',
        linkSessionId: record.linkSessionId,
        walletId: record.state.walletId,
        enrollmentId: record.state.enrollmentId,
        cancelledAtMs,
      };
    case 'cancelled_unclaimed':
    case 'cancelled_claimed_precommit':
    case 'expired_unclaimed':
    case 'expired_claimed':
    case 'active':
    case 'committed_completion_required':
      return null;
    default:
      return assertNeverSessionState(record.state);
  }
}

function expiryStateV1(
  record: LinkedDeviceSessionRecordV1,
  expiredAtMs: number,
): LinkedDeviceSessionState | null {
  switch (record.state.state) {
    case 'displaying_qr':
      return { state: 'expired_unclaimed', linkSessionId: record.linkSessionId, expiredAtMs };
    case 'claimed_by_owner':
    case 'awaiting_target_factor':
    case 'provisioning':
      return {
        state: 'expired_claimed',
        linkSessionId: record.linkSessionId,
        walletId: record.state.walletId,
        enrollmentId: record.state.enrollmentId,
        expiredAtMs,
      };
    case 'expired_unclaimed':
    case 'expired_claimed':
    case 'cancelled_unclaimed':
    case 'cancelled_claimed_precommit':
    case 'active':
    case 'committed_completion_required':
      return null;
    default:
      return assertNeverSessionState(record.state);
  }
}

function sessionExpiryMsV1(record: LinkedDeviceSessionRecordV1): number {
  switch (record.state.state) {
    case 'displaying_qr':
      return record.state.expiresAtMs;
    case 'claimed_by_owner':
      return record.state.claimExpiresAtMs;
    case 'awaiting_target_factor':
      return awaitingTargetDeadlineMsV1(record);
    case 'provisioning':
      return record.qrPayload.expiresAtMs;
    case 'active':
    case 'expired_unclaimed':
    case 'expired_claimed':
    case 'cancelled_unclaimed':
    case 'cancelled_claimed_precommit':
    case 'committed_completion_required':
      return Number.POSITIVE_INFINITY;
    default:
      return assertNeverSessionState(record.state);
  }
}

function isTerminalState(state: LinkedDeviceSessionState): boolean {
  switch (state.state) {
    case 'active':
    case 'expired_unclaimed':
    case 'expired_claimed':
    case 'cancelled_unclaimed':
    case 'cancelled_claimed_precommit':
    case 'committed_completion_required':
      return true;
    case 'displaying_qr':
    case 'claimed_by_owner':
    case 'awaiting_target_factor':
    case 'provisioning':
      return false;
    default:
      return assertNeverSessionState(state);
  }
}

function replaceSessionRecordV1(
  record: LinkedDeviceSessionRecordV1,
  patch: {
    readonly state: LinkedDeviceSessionState;
    readonly revision: number;
    readonly updatedAtMs: number;
    readonly claimTranscript?: LinkedDeviceClaimTranscriptV1;
    readonly approvalTranscript?: LinkedDeviceApprovalTranscriptV1;
    readonly aggregateReceipt?: LinkedDeviceEnrollmentReceiptV1;
  },
): LinkedDeviceSessionRecordV1 {
  return buildSessionRecordV1({
    linkSessionId: record.linkSessionId,
    qrPayload: record.qrPayload,
    state: patch.state,
    revision: patch.revision,
    claimTranscript: patch.claimTranscript || record.claimTranscript,
    approvalTranscript: patch.approvalTranscript || record.approvalTranscript,
    aggregateReceipt: patch.aggregateReceipt || record.aggregateReceipt,
    createdAtMs: record.createdAtMs,
    updatedAtMs: patch.updatedAtMs,
  });
}

function buildSessionRecordV1(input: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly qrPayload: QrLinkedDeviceSessionPayloadV5;
  readonly state: LinkedDeviceSessionState;
  readonly revision: number;
  readonly claimTranscript: LinkedDeviceClaimTranscriptV1 | undefined;
  readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1 | undefined;
  readonly aggregateReceipt: LinkedDeviceEnrollmentReceiptV1 | undefined;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): LinkedDeviceSessionRecordV1 {
  const base = {
    version: 'linked_device_session_v1' as const,
    linkSessionId: input.linkSessionId,
    qrPayload: input.qrPayload,
    revision: input.revision,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
  switch (input.state.state) {
    case 'displaying_qr':
    case 'expired_unclaimed':
    case 'cancelled_unclaimed':
      if (input.claimTranscript || input.approvalTranscript || input.aggregateReceipt) {
        throw new Error('unclaimed session cannot carry transcript facts');
      }
      return { ...base, state: input.state };
    case 'claimed_by_owner':
      if (!input.claimTranscript || input.approvalTranscript || input.aggregateReceipt) {
        throw new Error('claimed session transcript facts are invalid');
      }
      return { ...base, state: input.state, claimTranscript: input.claimTranscript };
    case 'awaiting_target_factor':
    case 'provisioning':
      if (!input.claimTranscript || !input.approvalTranscript || input.aggregateReceipt) {
        throw new Error('approved session transcript facts are invalid');
      }
      return {
        ...base,
        state: input.state,
        claimTranscript: input.claimTranscript,
        approvalTranscript: input.approvalTranscript,
      };
    case 'committed_completion_required':
      if (!input.claimTranscript || !input.approvalTranscript || input.aggregateReceipt) {
        throw new Error('approved session transcript facts are invalid');
      }
      return {
        ...base,
        state: input.state,
        claimTranscript: input.claimTranscript,
        approvalTranscript: input.approvalTranscript,
      };
    case 'active':
      if (!input.claimTranscript || !input.approvalTranscript || !input.aggregateReceipt) {
        throw new Error('active session transcript facts are incomplete');
      }
      return {
        ...base,
        state: input.state,
        claimTranscript: input.claimTranscript,
        approvalTranscript: input.approvalTranscript,
        aggregateReceipt: input.aggregateReceipt,
      };
    case 'expired_claimed':
      if (!input.claimTranscript || input.aggregateReceipt) {
        throw new Error('claimed terminal session transcript facts are incomplete');
      }
      return input.approvalTranscript
        ? {
            ...base,
            state: input.state,
            claimTranscript: input.claimTranscript,
            approvalTranscript: input.approvalTranscript,
          }
        : { ...base, state: input.state, claimTranscript: input.claimTranscript };
    case 'cancelled_claimed_precommit':
      if (!input.claimTranscript || input.aggregateReceipt) {
        throw new Error('claimed terminal session transcript facts are incomplete');
      }
      return input.approvalTranscript
        ? {
            ...base,
            state: input.state,
            claimTranscript: input.claimTranscript,
            approvalTranscript: input.approvalTranscript,
          }
        : { ...base, state: input.state, claimTranscript: input.claimTranscript };
    default:
      return assertNeverSessionState(input.state);
  }
}

function validateApprovalMatchesSession(
  record: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
  nowMs: number,
): void {
  if (record.state.state !== 'claimed_by_owner')
    throw new Error('link session is not awaiting owner approval');
  if (
    record.state.walletId !== approval.walletId ||
    record.state.enrollmentId !== approval.enrollmentId
  ) {
    throw new Error('approval wallet or enrollment does not match claim');
  }
  const claim = record.claimTranscript?.value;
  if (
    !claim ||
    claim.deviceId !== approval.deviceId ||
    claim.devicePublicKeyB64u !== approval.devicePublicKeyB64u
  ) {
    throw new Error('approval device identity does not match claim');
  }
  if (approval.linkPublicKeyB64u !== record.qrPayload.linkPublicKeyB64u) {
    throw new Error('approval link public key does not match QR payload');
  }
  if (approval.devicePublicKeyB64u !== record.qrPayload.devicePublicKeyB64u) {
    throw new Error('approval device public key does not match QR payload');
  }
  if (!sameDelegatedWalletAuthorityV1(approval.permission, record.qrPayload.requestedPermission)) {
    throw new Error('approval permission does not match QR payload');
  }
  // The factor branch is chosen once, in the QR, and every artifact after it
  // must repeat that exact choice. Approval is the last owner-authenticated
  // step, so a cross-branch approval fails here — before any credential,
  // challenge, or lane exists.
  if (
    approval.targetFactor.kind !== record.qrPayload.targetFactor.kind ||
    approval.targetFactor.kind !== claim.targetFactor.kind
  ) {
    throw new Error('approval target factor does not match the QR session');
  }
  if (approval.targetFactor.kind !== approval.ownerEnrollment.targetFactor.kind) {
    throw new Error('approval owner enrollment ceremony does not match its target factor');
  }
  if (approval.expiresAtMs <= nowMs || approval.expiresAtMs > record.state.claimExpiresAtMs) {
    throw new Error('approval expiry is outside the claim lifetime');
  }
  if (approval.approvedAtMs > nowMs) throw new Error('approval is from the future');
  if (approval.orderedKeyBindings.length === 0 || approval.protocolVersions.length === 0) {
    throw new Error('approval manifest is empty');
  }
}

function validateLinkedDeviceRequestedAuthorityV1(
  authority: DelegatedWalletAuthorityV1,
): string | null {
  const parent = buildFullOwnerDelegatedWalletAuthorityV1();
  if (!hasDelegatedWalletPermissionV1(parent, 'link_devices')) {
    return 'linking authority does not contain link_devices';
  }
  const attenuation = validateDelegatedWalletAuthorityAttenuationV1({
    parent,
    child: authority,
  });
  return attenuation.ok ? null : attenuation.error.message;
}

function parseLinkedDeviceApprovalV1(raw: unknown): LinkedDeviceApprovalV1 {
  return parseSharedLinkedDeviceApprovalV1(raw);
}

function parseClaimTranscriptV1(raw: unknown): LinkedDeviceClaimTranscriptV1 {
  const record = requireRecord(raw, 'claim transcript');
  requireExactKeys(record, ['digestB64u', 'value']);
  return {
    digestB64u: requireDigest(record.digestB64u, 'claim transcript digest'),
    value: parseClaimV1(record.value),
  };
}

function parseApprovalTranscriptV1(raw: unknown): LinkedDeviceApprovalTranscriptV1 {
  const record = requireRecord(raw, 'approval transcript');
  requireExactKeys(record, ['digestB64u', 'value', 'sourceKeyManifestDigestB64u']);
  return {
    digestB64u: requireDigest(record.digestB64u, 'approval transcript digest'),
    value: parseLinkedDeviceApprovalV1(record.value),
    sourceKeyManifestDigestB64u: requireDigest(
      record.sourceKeyManifestDigestB64u,
      'approval transcript source key manifest digest',
    ),
  };
}

function parseClaimV1(raw: unknown): LinkedDeviceClaimV1 {
  const record = requireRecord(raw, 'claim');
  requireExactKeys(record, [
    'kind',
    'linkSessionId',
    'walletId',
    'enrollmentId',
    'deviceId',
    'devicePublicKeyB64u',
    'targetFactor',
    'claimedAtMs',
    'claimExpiresAtMs',
  ]);
  if (record.kind !== 'linked_device_session_claim_v1') throw new Error('claim kind is invalid');
  return {
    kind: 'linked_device_session_claim_v1',
    linkSessionId: parseId(record.linkSessionId, parseLinkDeviceSessionId, 'claim.linkSessionId'),
    walletId: parseId(record.walletId, parseWalletId, 'claim.walletId'),
    enrollmentId: parseId(record.enrollmentId, parseLinkedDeviceEnrollmentId, 'claim.enrollmentId'),
    deviceId: parseId(record.deviceId, parseLinkedDeviceId, 'claim.deviceId'),
    devicePublicKeyB64u: parsePublicKeyB64u(
      record.devicePublicKeyB64u,
      'claim.devicePublicKeyB64u',
    ),
    targetFactor: parseTargetFactorV1(record.targetFactor),
    claimedAtMs: requireTimestamp(record.claimedAtMs, 'claim.claimedAtMs'),
    claimExpiresAtMs: requireTimestamp(record.claimExpiresAtMs, 'claim.claimExpiresAtMs'),
  };
}

function parseOwnerAuthorizationV1(raw: unknown): LinkedDeviceOwnerAuthorizationSourceV1 {
  const record = requireRecord(raw, 'ownerAuthorization');
  switch (record.kind) {
    case 'wallet_session': {
      requireExactKeys(record, ['kind', 'walletSessionId', 'authorizationId']);
      return {
        kind: 'wallet_session',
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
    }
    case 'step_up': {
      requireExactKeys(record, ['kind', 'evidenceSetId']);
      return {
        kind: 'step_up',
        evidenceSetId: parseAuthorizationId(
          record.evidenceSetId,
          parseAuthorizationEvidenceSetId,
          'evidenceSetId',
        ),
      };
    }
    default:
      throw new Error('ownerAuthorization.kind is invalid');
  }
}

function parseAggregateReceiptV1(raw: unknown): LinkedDeviceEnrollmentReceiptV1 {
  const record = requireRecord(raw, 'aggregate receipt');
  requireExactKeys(record, [
    'kind',
    'enrollmentId',
    'walletId',
    'deviceId',
    'targetFactor',
    'manifestDigestB64u',
    'aggregateReceiptDigestB64u',
    'orderedChildReceipts',
    'activatedAtMs',
  ]);
  if (record.kind !== 'linked_device_enrollment_receipt_v1')
    throw new Error('aggregate receipt kind is invalid');
  if (!Array.isArray(record.orderedChildReceipts) || record.orderedChildReceipts.length === 0)
    throw new Error('aggregate receipt child set is empty');
  const orderedChildReceipts = parseChildReceiptsV1(record.orderedChildReceipts);
  const enrollmentId = parseId(
    record.enrollmentId,
    parseLinkedDeviceEnrollmentId,
    'aggregate.enrollmentId',
  );
  const walletId = parseId(record.walletId, parseWalletId, 'aggregate.walletId');
  for (const child of orderedChildReceipts) {
    if (child.enrollmentId !== enrollmentId || child.walletId !== walletId) {
      throw new Error('aggregate receipt child identity does not match parent');
    }
  }
  return {
    kind: 'linked_device_enrollment_receipt_v1',
    enrollmentId,
    walletId,
    deviceId: parseId(record.deviceId, parseLinkedDeviceId, 'aggregate.deviceId'),
    targetFactor: parseTargetFactorV1(record.targetFactor),
    manifestDigestB64u: requireDigest(record.manifestDigestB64u, 'aggregate.manifestDigestB64u'),
    aggregateReceiptDigestB64u: requireDigest(
      record.aggregateReceiptDigestB64u,
      'aggregate.aggregateReceiptDigestB64u',
    ),
    orderedChildReceipts,
    activatedAtMs: requireTimestamp(record.activatedAtMs, 'aggregate.activatedAtMs'),
  };
}

function parseChildReceiptsV1(
  raw: unknown,
): readonly [LinkedDeviceEnrollmentChildReceiptV1, ...LinkedDeviceEnrollmentChildReceiptV1[]] {
  const values = (raw as unknown[]).map(parseChildReceiptV1);
  return values as unknown as readonly [
    LinkedDeviceEnrollmentChildReceiptV1,
    ...LinkedDeviceEnrollmentChildReceiptV1[],
  ];
}

function parseChildReceiptV1(raw: unknown): LinkedDeviceEnrollmentChildReceiptV1 {
  const record = requireRecord(raw, 'child receipt');
  const baseKeys = [
    'kind',
    'enrollmentId',
    'walletId',
    'walletKeyId',
    'keyFamily',
    'targetLaneId',
    'targetLaneShareEpoch',
    'materialActivation',
    'receiptDigestB64u',
    'transcriptHashB64u',
    'deliveredAtMs',
  ];
  requireExactKeys(record, baseKeys);
  if (record.kind !== 'linked_device_enrollment_child_receipt_v1')
    throw new Error('child receipt kind is invalid');
  if (record.keyFamily !== 'ed25519' && record.keyFamily !== 'ecdsa_secp256k1')
    throw new Error('child receipt family is invalid');
  const result = {
    kind: 'linked_device_enrollment_child_receipt_v1' as const,
    keyFamily: record.keyFamily,
    enrollmentId: parseId(record.enrollmentId, parseLinkedDeviceEnrollmentId, 'child.enrollmentId'),
    walletId: parseId(record.walletId, parseWalletId, 'child.walletId'),
    walletKeyId: parseId(record.walletKeyId, parseWalletKeyId, 'child.walletKeyId'),
    targetLaneId: parseId(record.targetLaneId, parseSigningLaneId, 'child.targetLaneId'),
    targetLaneShareEpoch: parseId(
      record.targetLaneShareEpoch,
      parseLaneShareEpoch,
      'child.targetLaneShareEpoch',
    ),
    materialActivation: parseMpcActivation(record.materialActivation),
    receiptDigestB64u: requireDigest(record.receiptDigestB64u, 'child.receiptDigestB64u'),
    transcriptHashB64u: requireDigest(record.transcriptHashB64u, 'child.transcriptHashB64u'),
    deliveredAtMs: requireTimestamp(record.deliveredAtMs, 'child.deliveredAtMs'),
  };
  return result as LinkedDeviceEnrollmentChildReceiptV1;
}

function parseMpcActivation(raw: unknown): MpcMaterialActivationRef {
  const parsed = parseMpcMaterialActivationRef(raw);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function parseSessionStateV1(raw: unknown): LinkedDeviceSessionState {
  const record = requireRecord(raw, 'session state');
  const state = parseSessionStateKind(record.state);
  const linkSessionId = parseId(
    record.linkSessionId,
    parseLinkDeviceSessionId,
    'state.linkSessionId',
  );
  switch (state) {
    case 'displaying_qr':
      requireExactKeys(record, ['state', 'linkSessionId', 'expiresAtMs']);
      return {
        state,
        linkSessionId,
        expiresAtMs: requireTimestamp(record.expiresAtMs, 'state.expiresAtMs'),
      };
    case 'claimed_by_owner':
      requireExactKeys(record, [
        'state',
        'linkSessionId',
        'walletId',
        'enrollmentId',
        'claimExpiresAtMs',
      ]);
      return {
        state,
        linkSessionId,
        walletId: parseId(record.walletId, parseWalletId, 'state.walletId'),
        enrollmentId: parseId(
          record.enrollmentId,
          parseLinkedDeviceEnrollmentId,
          'state.enrollmentId',
        ),
        claimExpiresAtMs: requireTimestamp(record.claimExpiresAtMs, 'state.claimExpiresAtMs'),
      };
    case 'awaiting_target_factor': {
      const targetFactor = parseTargetFactorV1(record.targetFactor);
      const walletId = parseId(record.walletId, parseWalletId, 'state.walletId');
      const enrollmentId = parseId(
        record.enrollmentId,
        parseLinkedDeviceEnrollmentId,
        'state.enrollmentId',
      );
      if (targetFactor.kind === 'passkey_prf') {
        requireExactKeys(record, [
          'state',
          'linkSessionId',
          'walletId',
          'enrollmentId',
          'targetFactor',
          'credentialDeadlineMs',
        ]);
        return {
          state,
          linkSessionId,
          walletId,
          enrollmentId,
          targetFactor: { kind: 'passkey_prf' },
          credentialDeadlineMs: requireTimestamp(
            record.credentialDeadlineMs,
            'state.credentialDeadlineMs',
          ),
        };
      }
      requireExactKeys(record, [
        'state',
        'linkSessionId',
        'walletId',
        'enrollmentId',
        'targetFactor',
        'emailOtpChallenge',
      ]);
      return {
        state,
        linkSessionId,
        walletId,
        enrollmentId,
        targetFactor: { kind: 'email_otp' },
        emailOtpChallenge: parseEmailOtpChallengeStateV1(record.emailOtpChallenge),
      };
    }
    case 'provisioning':
      requireExactKeys(record, [
        'state',
        'linkSessionId',
        'walletId',
        'enrollmentId',
        'keyManifestDigestB64u',
      ]);
      return {
        state,
        linkSessionId,
        walletId: parseId(record.walletId, parseWalletId, 'state.walletId'),
        enrollmentId: parseId(
          record.enrollmentId,
          parseLinkedDeviceEnrollmentId,
          'state.enrollmentId',
        ),
        keyManifestDigestB64u: requireDigest(
          record.keyManifestDigestB64u,
          'state.keyManifestDigestB64u',
        ),
      };
    case 'active':
      requireExactKeys(record, [
        'state',
        'linkSessionId',
        'walletId',
        'enrollmentId',
        'activatedAtMs',
      ]);
      return {
        state,
        linkSessionId,
        walletId: parseId(record.walletId, parseWalletId, 'state.walletId'),
        enrollmentId: parseId(
          record.enrollmentId,
          parseLinkedDeviceEnrollmentId,
          'state.enrollmentId',
        ),
        activatedAtMs: requireTimestamp(record.activatedAtMs, 'state.activatedAtMs'),
      };
    case 'expired_unclaimed':
    case 'cancelled_unclaimed':
      requireExactKeys(record, [
        'state',
        'linkSessionId',
        state === 'expired_unclaimed' ? 'expiredAtMs' : 'cancelledAtMs',
      ]);
      return state === 'expired_unclaimed'
        ? {
            state,
            linkSessionId,
            expiredAtMs: requireTimestamp(record.expiredAtMs, 'state.expiredAtMs'),
          }
        : {
            state,
            linkSessionId,
            cancelledAtMs: requireTimestamp(record.cancelledAtMs, 'state.cancelledAtMs'),
          };
    case 'expired_claimed':
      requireExactKeys(record, [
        'state',
        'linkSessionId',
        'walletId',
        'enrollmentId',
        'expiredAtMs',
      ]);
      return {
        state,
        linkSessionId,
        walletId: parseId(record.walletId, parseWalletId, 'state.walletId'),
        enrollmentId: parseId(
          record.enrollmentId,
          parseLinkedDeviceEnrollmentId,
          'state.enrollmentId',
        ),
        expiredAtMs: requireTimestamp(record.expiredAtMs, 'state.expiredAtMs'),
      };
    case 'cancelled_claimed_precommit':
      requireExactKeys(record, [
        'state',
        'linkSessionId',
        'walletId',
        'enrollmentId',
        'cancelledAtMs',
      ]);
      return {
        state,
        linkSessionId,
        walletId: parseId(record.walletId, parseWalletId, 'state.walletId'),
        enrollmentId: parseId(
          record.enrollmentId,
          parseLinkedDeviceEnrollmentId,
          'state.enrollmentId',
        ),
        cancelledAtMs: requireTimestamp(record.cancelledAtMs, 'state.cancelledAtMs'),
      };
    case 'committed_completion_required':
      requireExactKeys(record, [
        'state',
        'linkSessionId',
        'walletId',
        'enrollmentId',
        'keyManifestDigestB64u',
        'transcriptSetDigestB64u',
      ]);
      return {
        state,
        linkSessionId,
        walletId: parseId(record.walletId, parseWalletId, 'state.walletId'),
        enrollmentId: parseId(
          record.enrollmentId,
          parseLinkedDeviceEnrollmentId,
          'state.enrollmentId',
        ),
        keyManifestDigestB64u: requireDigest(
          record.keyManifestDigestB64u,
          'state.keyManifestDigestB64u',
        ),
        transcriptSetDigestB64u: requireDigest(
          record.transcriptSetDigestB64u,
          'state.transcriptSetDigestB64u',
        ),
      };
    default:
      throw new Error(`unsupported linked-device state: ${state}`);
  }
}

type LinkedDeviceSessionStateKind = LinkedDeviceSessionState['state'];

function parseSessionStateKind(raw: unknown): LinkedDeviceSessionStateKind {
  const value = parseIdentityString(raw, 'state');
  switch (value) {
    case 'displaying_qr':
    case 'claimed_by_owner':
    case 'awaiting_target_factor':
    case 'provisioning':
    case 'active':
    case 'expired_unclaimed':
    case 'expired_claimed':
    case 'cancelled_unclaimed':
    case 'cancelled_claimed_precommit':
    case 'committed_completion_required':
      return value;
    default:
      throw new Error('state is invalid');
  }
}

function validateRecordTranscriptState(
  state: LinkedDeviceSessionState,
  claimTranscript: LinkedDeviceClaimTranscriptV1 | undefined,
  approvalTranscript: LinkedDeviceApprovalTranscriptV1 | undefined,
  aggregateReceipt: LinkedDeviceEnrollmentReceiptV1 | undefined,
): void {
  const unclaimed =
    state.state === 'displaying_qr' ||
    state.state === 'expired_unclaimed' ||
    state.state === 'cancelled_unclaimed';
  if (unclaimed && (claimTranscript || approvalTranscript || aggregateReceipt))
    throw new Error('unclaimed session carries private transcript');
  if (!unclaimed && !claimTranscript)
    throw new Error('claimed session is missing claim transcript');
  if (
    (state.state === 'awaiting_target_factor' ||
      state.state === 'provisioning' ||
      state.state === 'active' ||
      state.state === 'committed_completion_required') &&
    !approvalTranscript
  )
    throw new Error('approved session is missing approval transcript');
  if (state.state === 'active' && !aggregateReceipt)
    throw new Error('active session is missing aggregate receipt');
  if (aggregateReceipt && state.state !== 'active')
    throw new Error('aggregate receipt is only valid for active session');
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

function sameQrPayload(
  left: QrLinkedDeviceSessionPayloadV5,
  right: QrLinkedDeviceSessionPayloadV5,
): boolean {
  return alphabetizeStringify(left) === alphabetizeStringify(right);
}

function deviceIdFromRecord(record: LinkedDeviceSessionRecordV1): LinkedDeviceId {
  const value = record.claimTranscript?.value.deviceId;
  if (!value) throw new Error('session claim transcript is missing device id');
  return value;
}

function validateAggregateReceiptMatchesApproval(
  record: LinkedDeviceSessionRecordV1,
  receipt: LinkedDeviceEnrollmentReceiptV1,
): void {
  if (record.state.state !== 'committed_completion_required') {
    throw new Error('aggregate receipt validation requires a committed session');
  }
  const approval = record.approvalTranscript?.value;
  if (!approval) throw new Error('aggregate receipt session is missing owner approval');
  if (receipt.targetFactor.kind !== approval.targetFactor.kind) {
    throw new Error('aggregate receipt target factor differs from the approved target factor');
  }
  if (receipt.manifestDigestB64u !== record.state.keyManifestDigestB64u) {
    throw new Error('aggregate receipt manifest digest differs from the approved manifest');
  }

  const approvedCoverage = new Set<string>();
  for (const binding of approval.orderedKeyBindings) {
    const key = aggregateChildCoverageKey({
      walletKeyId: binding.walletKeyId,
      keyFamily: binding.keyFamily,
      targetLaneId: binding.targetLaneId,
      targetLaneShareEpoch: binding.targetLaneShareEpoch,
    });
    if (approvedCoverage.has(key)) {
      throw new Error('approved linked-device manifest contains duplicate child coverage');
    }
    approvedCoverage.add(key);
  }

  const receiptCoverage = new Set<string>();
  const materialActivationIds = new Set<string>();
  for (const child of receipt.orderedChildReceipts) {
    const key = aggregateChildCoverageKey(child);
    if (receiptCoverage.has(key)) {
      throw new Error('aggregate receipt contains duplicate child coverage');
    }
    receiptCoverage.add(key);
    const activationId = String(child.materialActivation.activationId);
    if (materialActivationIds.has(activationId)) {
      throw new Error('aggregate receipt contains duplicate material activation');
    }
    materialActivationIds.add(activationId);
  }

  if (receipt.orderedChildReceipts.length !== approval.orderedKeyBindings.length) {
    throw new Error('aggregate receipt child count differs from the approved manifest');
  }
  for (let index = 0; index < approval.orderedKeyBindings.length; index += 1) {
    const binding = approval.orderedKeyBindings[index];
    const child = receipt.orderedChildReceipts[index];
    if (!binding || !child) throw new Error('aggregate receipt child order is invalid');
    if (
      child.walletKeyId !== binding.walletKeyId ||
      child.keyFamily !== binding.keyFamily ||
      child.targetLaneId !== binding.targetLaneId ||
      child.targetLaneShareEpoch !== binding.targetLaneShareEpoch
    ) {
      throw new Error('aggregate receipt child differs from the approved manifest');
    }
  }
}

function aggregateChildCoverageKey(input: {
  readonly walletKeyId: WalletKeyId;
  readonly keyFamily: LinkedDeviceEnrollmentKeyBindingV1['keyFamily'];
  readonly targetLaneId: SigningLaneId;
  readonly targetLaneShareEpoch: LaneShareEpoch;
}): string {
  return [
    String(input.walletKeyId),
    input.keyFamily,
    String(input.targetLaneId),
    String(input.targetLaneShareEpoch),
  ].join('\u0000');
}

function invalidStateResult(
  record: LinkedDeviceSessionRecordV1,
): LinkedDeviceSessionMutationResultV1 {
  return { outcome: 'invalid_state', state: record.state.state, record };
}

function assertNeverSessionState(value: never): never {
  throw new Error(`unsupported linked-device session state: ${String(value)}`);
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

function parsePublicKeyB64u(raw: unknown, field: string): LinkDevicePublicKeyB64u {
  if (typeof raw !== 'string' || !/^[A-Za-z0-9_-]+$/.test(raw))
    throw new Error(`${field} is invalid`);
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(raw);
  } catch {
    throw new Error(`${field} is invalid`);
  }
  if (bytes.length === 0 || base64UrlEncode(bytes) !== raw)
    throw new Error(`${field} is not canonical base64url`);
  return raw as LinkDevicePublicKeyB64u;
}

function parseFixedBase64UrlBytes(raw: unknown, byteLength: number, field: string): string {
  if (typeof raw !== 'string' || !/^[A-Za-z0-9_-]+$/.test(raw)) {
    throw new Error(`${field} is invalid`);
  }
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(raw);
  } catch {
    throw new Error(`${field} is invalid`);
  }
  if (bytes.length !== byteLength || base64UrlEncode(bytes) !== raw) {
    throw new Error(`${field} must be canonical base64url for ${byteLength} bytes`);
  }
  return raw;
}

function requireDigest(raw: unknown, field: string): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch (error: unknown) {
    throw new Error(`${field} is invalid: ${errorMessage(error)}`);
  }
}

function requireTimestamp(raw: unknown, field: string): number {
  if (!Number.isSafeInteger(raw) || Number(raw) <= 0)
    throw new Error(`${field} must be a positive safe integer`);
  return Number(raw);
}

function requirePositiveInteger(raw: unknown, field: string): number {
  const value = requireTimestamp(raw, field);
  if (value < 1) throw new Error(`${field} must be positive`);
  return value;
}

function requireNonNegativeInteger(raw: unknown, field: string): number {
  if (!Number.isSafeInteger(raw) || Number(raw) < 0)
    throw new Error(`${field} must be a non-negative safe integer`);
  return Number(raw);
}

function requireRecord(raw: unknown, field: string): Record<string, unknown> {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw))
    throw new Error(`${field} must be an object`);
  return raw as Record<string, unknown>;
}

function requireExactKeys(record: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(record).sort();
  const required = [...expected].sort();
  if (actual.length !== required.length || actual.some((key, index) => key !== required[index])) {
    throw new Error('record contains invalid fields');
  }
}

function requireAllowedKeys(record: Record<string, unknown>, allowed: readonly string[]): void {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(record)) {
    if (!allowedSet.has(key)) throw new Error('record contains invalid fields');
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || 'invalid linked-device input');
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
  return parseClaimV1(raw);
}

export function parseLinkedDeviceAggregateReceiptV1(raw: unknown): LinkedDeviceEnrollmentReceiptV1 {
  return parseAggregateReceiptV1(raw);
}

export function parseLinkedDeviceSessionStateV1(raw: unknown): LinkedDeviceSessionState {
  return parseSessionStateV1(raw);
}

export function parseLinkedDevicePublicKeyV1(raw: unknown): LinkDevicePublicKeyB64u {
  return parsePublicKeyB64u(raw, 'public key');
}

export function parseLinkedDeviceDigestV1(raw: unknown): string {
  return requireDigest(raw, 'digest');
}
