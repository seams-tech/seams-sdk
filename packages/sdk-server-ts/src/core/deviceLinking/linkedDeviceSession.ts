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
  parseMpcMaterialActivationRef,
  parseWalletId,
  type DomainIdParseResult,
  type MpcMaterialActivationRef,
  type WalletId,
} from '@shared/utils/domainIds';
import {
  computeLinkedDevicePublicKeyDigestV1,
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
  LaneHolderParticipantId,
  SigningWorkerParticipantId,
} from '@shared/signing-lanes/participants';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceSessionClaimV1,
  LinkedDeviceEnrollmentReceiptV1,
  LinkedDeviceEnrollmentChildReceiptV1,
  LinkedDeviceEnrollmentKeyBindingV1,
  LinkedDeviceOwnerEnrollmentKeyBindingV1,
  LinkedDeviceProvisionedEnrollmentKeyBindingV1,
  LinkedDeviceOwnerAuthorizationSourceV1,
  LinkedDeviceProtocolVersionV1,
  LinkedDeviceSessionState,
  LinkDevicePublicKeyB64u,
  QrLinkedDevicePermissionRequest,
  QrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking/contracts';
import { parseOwnerLaneParticipantContinuityV1 } from '@shared/signing-lanes/ownerContinuity';
import type { SigningLaneKind } from '@shared/signing-lanes/records';

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
  QrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking/contracts';

type LinkedDeviceSessionRecordBaseV1 = {
  readonly version: 'linked_device_session_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly qrPayload: QrLinkedDeviceSessionPayloadV4;
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
  readonly recovery?: never;
};

type LinkedDeviceSessionClaimedRecordV1 = LinkedDeviceSessionRecordBaseV1 & {
  readonly state: Extract<LinkedDeviceSessionState, { readonly state: 'claimed_by_owner' }>;
  readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript?: never;
  readonly aggregateReceipt?: never;
  readonly recovery?: never;
};

type LinkedDeviceSessionApprovedRecordV1 = LinkedDeviceSessionRecordBaseV1 & {
  readonly state: Extract<
    LinkedDeviceSessionState,
    {
      readonly state: 'awaiting_target_passkey' | 'provisioning';
    }
  >;
  readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1;
  readonly aggregateReceipt?: never;
  readonly recovery?: never;
};

type LinkedDeviceSessionCommittedRecordV1 = LinkedDeviceSessionRecordBaseV1 & {
  readonly state: Extract<
    LinkedDeviceSessionState,
    { readonly state: 'committed_completion_required' }
  >;
  readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1;
  readonly aggregateReceipt?: never;
  readonly recovery: LinkedDeviceRecoveryBindingV1;
};

type LinkedDeviceSessionActiveRecordV1 = LinkedDeviceSessionRecordBaseV1 & {
  readonly state: Extract<LinkedDeviceSessionState, { readonly state: 'active' }>;
  readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
  readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1;
  readonly aggregateReceipt: LinkedDeviceEnrollmentReceiptV1;
  readonly recovery: LinkedDeviceRecoveryBindingV1;
};

type LinkedDeviceSessionExpiredClaimedRecordV1 =
  | (LinkedDeviceSessionRecordBaseV1 & {
      readonly state: Extract<LinkedDeviceSessionState, { readonly state: 'expired_claimed' }>;
      readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
      readonly approvalTranscript?: never;
      readonly aggregateReceipt?: never;
      readonly recovery?: never;
    })
  | (LinkedDeviceSessionRecordBaseV1 & {
      readonly state: Extract<LinkedDeviceSessionState, { readonly state: 'expired_claimed' }>;
      readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
      readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1;
      readonly aggregateReceipt?: never;
      readonly recovery?: never;
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
      readonly recovery?: never;
    })
  | (LinkedDeviceSessionRecordBaseV1 & {
      readonly state: Extract<
        LinkedDeviceSessionState,
        { readonly state: 'cancelled_claimed_precommit' }
      >;
      readonly claimTranscript: LinkedDeviceClaimTranscriptV1;
      readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1;
      readonly aggregateReceipt?: never;
      readonly recovery?: never;
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
};

export type LinkedDeviceRecoveryContinuationV1 = {
  readonly kind: 'linked_device_recovery_continuation_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly devicePublicKeyB64u: string;
  readonly devicePublicKeyDigestB64u: DigestB64u;
  readonly boundAtMs: number;
};

export type LinkedDeviceRecoveryBindingV1 =
  | { readonly kind: 'unbound' }
  | {
      readonly kind: 'bound';
      readonly continuation: LinkedDeviceRecoveryContinuationV1;
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
  readonly curve: 'ed25519' | 'ecdsa';
};

export type LinkedDeviceOwnerAuthorizationPortV1 = {
  authorizeOwnerClaimV1(input: {
    readonly payload: QrLinkedDeviceSessionPayloadV4;
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
  markCommittedCompletionRequiredV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly transcriptSetDigestB64u: DigestB64u;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1>;
  bindRecoveryContinuationV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly continuation: LinkedDeviceRecoveryContinuationV1;
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
  readonly payload: QrLinkedDeviceSessionPayloadV4;
  readonly nowMs: number;
};

export type LinkedDeviceSessionClaimInputV1 = {
  readonly payload: QrLinkedDeviceSessionPayloadV4;
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

export type LinkedDeviceSessionRecoveryRebindInputV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly continuation: LinkedDeviceRecoveryContinuationV1;
  readonly nowMs: number;
};

export type LinkedDeviceSessionTargetCredentialInputV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly keyManifestDigestB64u: DigestB64u;
  readonly nowMs: number;
};

export type LinkedDeviceSessionAggregateActivationInputV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly receipt: LinkedDeviceEnrollmentReceiptV1;
  readonly nowMs: number;
};

export class LinkedDeviceSessionServiceV1 {
  private readonly store: LinkedDeviceSessionStoreV1;
  private readonly authorization: LinkedDeviceOwnerAuthorizationPortV1;
  private readonly aggregateActivationVerifier: LinkedDeviceAggregateActivationVerifierV1;

  constructor(input: {
    readonly store: LinkedDeviceSessionStoreV1;
    readonly authorization: LinkedDeviceOwnerAuthorizationPortV1;
    readonly aggregateActivationVerifier: LinkedDeviceAggregateActivationVerifierV1;
  }) {
    this.store = input.store;
    this.authorization = input.authorization;
    this.aggregateActivationVerifier = input.aggregateActivationVerifier;
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
      const nextState = awaitingTargetPasskeyStateV1(existing, approval);
      const nextRecord = replaceSessionRecordV1(existing, {
        state: nextState,
        revision: existing.revision + 1,
        approvalTranscript: { digestB64u: approvalDigestB64u, value: approval },
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

  async bindRecoveryContinuationV1(
    input: LinkedDeviceSessionRecoveryRebindInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      requireTimestamp(input.nowMs, 'nowMs');
      const continuation = input.continuation;
      if (continuation.linkSessionId !== input.linkSessionId) {
        return {
          outcome: 'invalid_input',
          message: 'recovery continuation session does not match',
        };
      }
      requireTimestamp(continuation.boundAtMs, 'recovery continuation boundAtMs');
      if (continuation.boundAtMs > input.nowMs) {
        return { outcome: 'invalid_input', message: 'recovery continuation is from the future' };
      }
      const devicePublicKeyDigestB64u = requireDigest(
        continuation.devicePublicKeyDigestB64u,
        'recovery continuation devicePublicKeyDigestB64u',
      );
      const computedDigestB64u = await computeLinkedDevicePublicKeyDigestV1(
        continuation.devicePublicKeyB64u,
      );
      if (computedDigestB64u !== devicePublicKeyDigestB64u) {
        return {
          outcome: 'invalid_input',
          message: 'recovery continuation key digest does not match public key',
        };
      }
      const existing = await this.requireSession(input.linkSessionId);
      if (existing.state.state !== 'committed_completion_required') {
        return invalidStateResult(existing);
      }
      const recovery = existing.recovery;
      if (!recovery) {
        return {
          outcome: 'invalid_input',
          message: 'committed session is missing recovery binding',
        };
      }
      const approval = existing.approvalTranscript?.value;
      const deviceId = deviceIdFromRecord(existing);
      if (
        !approval ||
        continuation.enrollmentId !== existing.state.enrollmentId ||
        continuation.enrollmentId !== approval.enrollmentId ||
        continuation.deviceId !== deviceId ||
        continuation.devicePublicKeyB64u === approval.devicePublicKeyB64u
      ) {
        return {
          outcome: 'invalid_input',
          message: 'recovery continuation identity or freshness does not match session',
        };
      }
      if (recovery.kind === 'bound') {
        return alphabetizeStringify(recovery.continuation) === alphabetizeStringify(continuation)
          ? { outcome: 'replayed', record: existing }
          : {
              outcome: 'conflict',
              expectedRevision: existing.revision,
              actualRevision: existing.revision,
              record: existing,
            };
      }
      const nextRecord = replaceSessionRecordV1(existing, {
        state: existing.state,
        revision: existing.revision + 1,
        recovery: { kind: 'bound', continuation },
        updatedAtMs: input.nowMs,
      });
      return await this.store.bindRecoveryContinuationV1({
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        continuation,
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
      if (existing.state.state !== 'awaiting_target_passkey') {
        return invalidStateResult(existing);
      }
      if (input.nowMs >= existing.state.credentialDeadlineMs) {
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

  async recordAggregateActivationV1(
    input: LinkedDeviceSessionAggregateActivationInputV1,
  ): Promise<LinkedDeviceSessionServiceResultV1> {
    try {
      requireTimestamp(input.nowMs, 'nowMs');
      const receipt = parseAggregateReceiptV1(input.receipt);
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
  payload: QrLinkedDeviceSessionPayloadV4,
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
    'recovery',
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
  const parsedRecovery = parseRecoveryBindingV1(record.recovery);
  const recovery =
    state.state === 'committed_completion_required' || state.state === 'active'
      ? parsedRecovery
      : undefined;
  if (
    state.state !== 'committed_completion_required' &&
    state.state !== 'active' &&
    record.recovery
  ) {
    throw new Error('recovery binding is only valid for committed or active sessions');
  }
  validateRecordTranscriptState(state, claimTranscript, approvalTranscript, aggregateReceipt);
  return buildSessionRecordV1({
    linkSessionId,
    qrPayload,
    state,
    revision,
    claimTranscript,
    approvalTranscript,
    aggregateReceipt,
    recovery,
    createdAtMs,
    updatedAtMs,
  });
}

export function parseQrLinkedDeviceSessionPayloadV1(raw: unknown): QrLinkedDeviceSessionPayloadV4 {
  const record = requireRecord(raw, 'QR payload');
  requireExactKeys(record, [
    'version',
    'purpose',
    'linkSessionId',
    'linkPublicKeyB64u',
    'devicePublicKeyB64u',
    'requestedPermission',
    'issuedAtMs',
    'expiresAtMs',
  ]);
  if (record.version !== 'v4') throw new Error('QR payload version is invalid');
  if (record.purpose !== 'linked_device_lane_creation')
    throw new Error('QR payload purpose is invalid');
  const linkSessionId = parseId(record.linkSessionId, parseLinkDeviceSessionId, 'linkSessionId');
  const linkPublicKeyB64u = parsePublicKeyB64u(record.linkPublicKeyB64u, 'linkPublicKeyB64u');
  const devicePublicKeyB64u = parsePublicKeyB64u(record.devicePublicKeyB64u, 'devicePublicKeyB64u');
  const requestedPermission = parsePermissionV1(record.requestedPermission);
  const issuedAtMs = requireTimestamp(record.issuedAtMs, 'issuedAtMs');
  const expiresAtMs = requireTimestamp(record.expiresAtMs, 'expiresAtMs');
  if (expiresAtMs <= issuedAtMs) throw new Error('QR payload expiresAtMs must be after issuedAtMs');
  return {
    version: 'v4',
    purpose: 'linked_device_lane_creation',
    linkSessionId,
    linkPublicKeyB64u,
    devicePublicKeyB64u,
    requestedPermission,
    issuedAtMs,
    expiresAtMs,
  };
}

function buildClaimV1(
  payload: QrLinkedDeviceSessionPayloadV4,
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

function awaitingTargetPasskeyStateV1(
  record: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
): Extract<LinkedDeviceSessionState, { readonly state: 'awaiting_target_passkey' }> {
  if (record.state.state !== 'claimed_by_owner')
    throw new Error('link session is not awaiting owner approval');
  return {
    state: 'awaiting_target_passkey',
    linkSessionId: record.linkSessionId,
    walletId: record.state.walletId,
    enrollmentId: record.state.enrollmentId,
    credentialDeadlineMs: approval.expiresAtMs,
  };
}

function provisioningStateV1(
  record: LinkedDeviceSessionRecordV1,
  keyManifestDigestB64u: DigestB64u,
): Extract<LinkedDeviceSessionState, { readonly state: 'provisioning' }> {
  if (record.state.state !== 'awaiting_target_passkey') {
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
    case 'awaiting_target_passkey':
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
    case 'awaiting_target_passkey':
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
    case 'awaiting_target_passkey':
      return record.state.credentialDeadlineMs;
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
    case 'awaiting_target_passkey':
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
    readonly recovery?: LinkedDeviceRecoveryBindingV1;
  },
): LinkedDeviceSessionRecordV1 {
  const existingRecovery =
    record.state.state === 'committed_completion_required' || record.state.state === 'active'
      ? record.recovery
      : undefined;
  const nextRecovery =
    patch.recovery ??
    existingRecovery ??
    (patch.state.state === 'committed_completion_required' || patch.state.state === 'active'
      ? { kind: 'unbound' as const }
      : undefined);
  return buildSessionRecordV1({
    linkSessionId: record.linkSessionId,
    qrPayload: record.qrPayload,
    state: patch.state,
    revision: patch.revision,
    claimTranscript: patch.claimTranscript || record.claimTranscript,
    approvalTranscript: patch.approvalTranscript || record.approvalTranscript,
    aggregateReceipt: patch.aggregateReceipt || record.aggregateReceipt,
    recovery: nextRecovery,
    createdAtMs: record.createdAtMs,
    updatedAtMs: patch.updatedAtMs,
  });
}

function buildSessionRecordV1(input: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly qrPayload: QrLinkedDeviceSessionPayloadV4;
  readonly state: LinkedDeviceSessionState;
  readonly revision: number;
  readonly claimTranscript: LinkedDeviceClaimTranscriptV1 | undefined;
  readonly approvalTranscript: LinkedDeviceApprovalTranscriptV1 | undefined;
  readonly aggregateReceipt: LinkedDeviceEnrollmentReceiptV1 | undefined;
  readonly recovery: LinkedDeviceRecoveryBindingV1 | undefined;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): LinkedDeviceSessionRecordV1 {
  if (
    input.recovery &&
    input.state.state !== 'committed_completion_required' &&
    input.state.state !== 'active'
  ) {
    throw new Error('recovery continuation requires committed or active state');
  }
  if (
    !input.recovery &&
    (input.state.state === 'committed_completion_required' || input.state.state === 'active')
  ) {
    throw new Error('committed or active session is missing recovery binding');
  }
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
    case 'awaiting_target_passkey':
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
      if (!input.recovery) throw new Error('committed session is missing recovery binding');
      return {
        ...base,
        state: input.state,
        claimTranscript: input.claimTranscript,
        approvalTranscript: input.approvalTranscript,
        recovery: input.recovery,
      };
    case 'active':
      if (!input.claimTranscript || !input.approvalTranscript || !input.aggregateReceipt) {
        throw new Error('active session transcript facts are incomplete');
      }
      if (!input.recovery) throw new Error('active session is missing recovery binding');
      return {
        ...base,
        state: input.state,
        claimTranscript: input.claimTranscript,
        approvalTranscript: input.approvalTranscript,
        aggregateReceipt: input.aggregateReceipt,
        recovery: input.recovery,
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
  if (approval.expiresAtMs <= nowMs || approval.expiresAtMs > record.state.claimExpiresAtMs) {
    throw new Error('approval expiry is outside the claim lifetime');
  }
  if (approval.approvedAtMs > nowMs) throw new Error('approval is from the future');
  if (approval.orderedKeyBindings.length === 0 || approval.protocolVersions.length === 0) {
    throw new Error('approval manifest is empty');
  }
}

function parseLinkedDeviceApprovalV1(raw: unknown): LinkedDeviceApprovalV1 {
  const record = requireRecord(raw, 'approval transcript');
  requireExactKeys(record, [
    'kind',
    'linkSessionId',
    'walletId',
    'enrollmentId',
    'deviceId',
    'linkPublicKeyB64u',
    'devicePublicKeyB64u',
    'permission',
    'ownerAuthorization',
    'policyDigestB64u',
    'operationId',
    'idempotencyKey',
    'orderedKeyBindings',
    'protocolVersions',
    'approvedAtMs',
    'expiresAtMs',
  ]);
  if (record.kind !== 'linked_device_approval_v1') throw new Error('approval kind is invalid');
  const orderedKeyBindings = parseKeyBindingsV1(record.orderedKeyBindings);
  const protocolVersions = parseProtocolVersionsV1(record.protocolVersions);
  return {
    kind: 'linked_device_approval_v1',
    linkSessionId: parseId(
      record.linkSessionId,
      parseLinkDeviceSessionId,
      'approval.linkSessionId',
    ),
    walletId: parseId(record.walletId, parseWalletId, 'approval.walletId'),
    enrollmentId: parseId(
      record.enrollmentId,
      parseLinkedDeviceEnrollmentId,
      'approval.enrollmentId',
    ),
    deviceId: parseId(record.deviceId, parseLinkedDeviceId, 'approval.deviceId'),
    linkPublicKeyB64u: parsePublicKeyB64u(record.linkPublicKeyB64u, 'approval.linkPublicKeyB64u'),
    devicePublicKeyB64u: parsePublicKeyB64u(
      record.devicePublicKeyB64u,
      'approval.devicePublicKeyB64u',
    ),
    permission: parsePermissionV1(record.permission),
    ownerAuthorization: parseOwnerAuthorizationV1(record.ownerAuthorization),
    policyDigestB64u: requireDigest(record.policyDigestB64u, 'approval.policyDigestB64u'),
    operationId: parseId(record.operationId, parseLaneOperationId, 'approval.operationId'),
    idempotencyKey: parseId(
      record.idempotencyKey,
      parseLaneOperationIdempotencyKey,
      'approval.idempotencyKey',
    ),
    orderedKeyBindings,
    protocolVersions,
    approvedAtMs: requireTimestamp(record.approvedAtMs, 'approval.approvedAtMs'),
    expiresAtMs: requireTimestamp(record.expiresAtMs, 'approval.expiresAtMs'),
  };
}

function parseRecoveryContinuationV1(raw: unknown): LinkedDeviceRecoveryContinuationV1 {
  const record = requireRecord(raw, 'recovery continuation');
  requireExactKeys(record, [
    'kind',
    'linkSessionId',
    'enrollmentId',
    'deviceId',
    'devicePublicKeyB64u',
    'devicePublicKeyDigestB64u',
    'boundAtMs',
  ]);
  if (record.kind !== 'linked_device_recovery_continuation_v1') {
    throw new Error('recovery continuation kind is invalid');
  }
  return {
    kind: 'linked_device_recovery_continuation_v1',
    linkSessionId: parseId(
      record.linkSessionId,
      parseLinkDeviceSessionId,
      'recovery continuation.linkSessionId',
    ),
    enrollmentId: parseId(
      record.enrollmentId,
      parseLinkedDeviceEnrollmentId,
      'recovery continuation.enrollmentId',
    ),
    deviceId: parseId(record.deviceId, parseLinkedDeviceId, 'recovery continuation.deviceId'),
    devicePublicKeyB64u: parsePublicKeyB64u(
      record.devicePublicKeyB64u,
      'recovery continuation.devicePublicKeyB64u',
    ),
    devicePublicKeyDigestB64u: requireDigest(
      record.devicePublicKeyDigestB64u,
      'recovery continuation.devicePublicKeyDigestB64u',
    ),
    boundAtMs: requireTimestamp(record.boundAtMs, 'recovery continuation.boundAtMs'),
  };
}

function parseRecoveryBindingV1(rawBinding: unknown): LinkedDeviceRecoveryBindingV1 {
  if (rawBinding === undefined) {
    return { kind: 'unbound' };
  }
  const record = requireRecord(rawBinding, 'recovery binding');
  if (record.kind === 'unbound') {
    requireExactKeys(record, ['kind']);
    return { kind: 'unbound' };
  }
  requireExactKeys(record, ['kind', 'continuation']);
  if (record.kind !== 'bound') throw new Error('recovery binding kind is invalid');
  return { kind: 'bound', continuation: parseRecoveryContinuationV1(record.continuation) };
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
  requireExactKeys(record, ['digestB64u', 'value']);
  return {
    digestB64u: requireDigest(record.digestB64u, 'approval transcript digest'),
    value: parseLinkedDeviceApprovalV1(record.value),
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
    claimedAtMs: requireTimestamp(record.claimedAtMs, 'claim.claimedAtMs'),
    claimExpiresAtMs: requireTimestamp(record.claimExpiresAtMs, 'claim.claimExpiresAtMs'),
  };
}

function parsePermissionV1(raw: unknown): QrLinkedDevicePermissionRequest {
  const record = requireRecord(raw, 'permission');
  requireExactKeys(record, ['kind', 'administrationScope', 'localUserPresence']);
  if (
    record.kind !== 'owner_equivalent_signing' ||
    record.administrationScope !== 'signing_only' ||
    record.localUserPresence !== 'required'
  ) {
    throw new Error('linked-device permission is not supported');
  }
  return {
    kind: 'owner_equivalent_signing',
    administrationScope: 'signing_only',
    localUserPresence: 'required',
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

function parseKeyBindingsV1(
  raw: unknown,
): readonly [LinkedDeviceEnrollmentKeyBindingV1, ...LinkedDeviceEnrollmentKeyBindingV1[]] {
  if (!Array.isArray(raw) || raw.length === 0)
    throw new Error('orderedKeyBindings must be nonempty');
  const values = raw.map(parseKeyBindingV1);
  return values as unknown as readonly [
    LinkedDeviceEnrollmentKeyBindingV1,
    ...LinkedDeviceEnrollmentKeyBindingV1[],
  ];
}

function parseKeyBindingV1(raw: unknown): LinkedDeviceEnrollmentKeyBindingV1 {
  const record = requireRecord(raw, 'key binding');
  if (record.keyFamily !== 'ed25519' && record.keyFamily !== 'ecdsa_secp256k1')
    throw new Error('key binding family is invalid');
  const keyFamily: 'ed25519' | 'ecdsa_secp256k1' = record.keyFamily;
  const sourceLaneKind = parseSigningLaneKindV1(record.sourceLaneKind);
  const sourceKind = parseSourceKindV1(record.sourceKind);
  const common = {
    walletKeyId: parseId(record.walletKeyId, parseWalletKeyId, 'key binding.walletKeyId'),
    keyFamily,
    sourceLaneId: parseId(record.sourceLaneId, parseSigningLaneId, 'key binding.sourceLaneId'),
    sourceLaneKind,
    sourceKind,
    sourceLaneShareEpoch: parseId(
      record.sourceLaneShareEpoch,
      parseLaneShareEpoch,
      'key binding.sourceLaneShareEpoch',
    ),
    sourceRevocationEpoch: requireNonNegativeInteger(
      record.sourceRevocationEpoch,
      'key binding.sourceRevocationEpoch',
    ),
    targetLaneId: parseId(record.targetLaneId, parseSigningLaneId, 'key binding.targetLaneId'),
    targetLaneShareEpoch: parseId(
      record.targetLaneShareEpoch,
      parseLaneShareEpoch,
      'key binding.targetLaneShareEpoch',
    ),
  };
  if (sourceKind === 'owner_registration') {
    if (sourceLaneKind !== 'owner_passkey' && sourceLaneKind !== 'owner_email_otp')
      throw new Error('key binding source lane kind must be owner');
    requireExactKeys(record, [
      'walletKeyId',
      'keyFamily',
      'sourceLaneId',
      'sourceLaneKind',
      'sourceKind',
      'sourceLaneShareEpoch',
      'sourceRevocationEpoch',
      'ownerParticipantContinuity',
      'targetLaneId',
      'targetLaneShareEpoch',
    ]);
    const ownerBinding = {
      ...common,
      sourceKind: 'owner_registration',
      sourceLaneKind,
      ownerParticipantContinuity: parseOwnerLaneParticipantContinuityV1(
        record.ownerParticipantContinuity,
        'key binding.ownerParticipantContinuity',
      ),
    } satisfies LinkedDeviceOwnerEnrollmentKeyBindingV1;
    return ownerBinding;
  }
  if (sourceLaneKind === 'owner_passkey' || sourceLaneKind === 'owner_email_otp')
    throw new Error('key binding source lane kind must be provisioned');
  requireExactKeys(record, [
    'walletKeyId',
    'keyFamily',
    'sourceLaneId',
    'sourceLaneKind',
    'sourceKind',
    'sourceLaneShareEpoch',
    'sourceRevocationEpoch',
    'sourceHolderParticipantId',
    'sourceSigningWorkerParticipantId',
    'targetLaneId',
    'targetLaneShareEpoch',
  ]);
  const provisionedBinding = {
    ...common,
    sourceKind: 'provisioned_lane',
    sourceLaneKind,
    sourceHolderParticipantId: parseIdentityString(
      record.sourceHolderParticipantId,
      'key binding.sourceHolderParticipantId',
    ) as LaneHolderParticipantId,
    sourceSigningWorkerParticipantId: parseIdentityString(
      record.sourceSigningWorkerParticipantId,
      'key binding.sourceSigningWorkerParticipantId',
    ) as SigningWorkerParticipantId,
  } satisfies LinkedDeviceProvisionedEnrollmentKeyBindingV1;
  return provisionedBinding;
}

function parseSigningLaneKindV1(raw: unknown): SigningLaneKind {
  switch (raw) {
    case 'owner_passkey':
    case 'owner_email_otp':
    case 'linked_device':
    case 'delegated_execution':
    case 'recovery':
    case 'break_glass':
      return raw;
    default:
      throw new Error('key binding source lane kind is invalid');
  }
}

function parseSourceKindV1(raw: unknown): 'owner_registration' | 'provisioned_lane' {
  if (raw === 'owner_registration' || raw === 'provisioned_lane') return raw;
  throw new Error('key binding source kind is invalid');
}

function parseProtocolVersionsV1(
  raw: unknown,
): readonly [LinkedDeviceProtocolVersionV1, ...LinkedDeviceProtocolVersionV1[]] {
  if (!Array.isArray(raw) || raw.length === 0) throw new Error('protocolVersions must be nonempty');
  const values = raw.map((item) => {
    const record = requireRecord(item, 'protocol version');
    requireExactKeys(record, ['keyFamily', 'version']);
    if (record.keyFamily !== 'ed25519' && record.keyFamily !== 'ecdsa_secp256k1')
      throw new Error('protocol version family is invalid');
    const version = parseIdentityString(record.version, 'protocol version.version');
    if (version !== 'rotatable_signing_lane_protocol_v1')
      throw new Error('protocol version is invalid');
    return { keyFamily: record.keyFamily, version };
  });
  return values as unknown as readonly [
    LinkedDeviceProtocolVersionV1,
    ...LinkedDeviceProtocolVersionV1[],
  ];
}

function parseAggregateReceiptV1(raw: unknown): LinkedDeviceEnrollmentReceiptV1 {
  const record = requireRecord(raw, 'aggregate receipt');
  requireExactKeys(record, [
    'kind',
    'enrollmentId',
    'walletId',
    'deviceId',
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
    case 'awaiting_target_passkey':
      requireExactKeys(record, [
        'state',
        'linkSessionId',
        'walletId',
        'enrollmentId',
        'credentialDeadlineMs',
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
        credentialDeadlineMs: requireTimestamp(
          record.credentialDeadlineMs,
          'state.credentialDeadlineMs',
        ),
      };
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
    case 'awaiting_target_passkey':
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
    (state.state === 'awaiting_target_passkey' ||
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
  left: QrLinkedDeviceSessionPayloadV4,
  right: QrLinkedDeviceSessionPayloadV4,
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
    /[\s\u0000-\u001f\u007f]/.test(raw)
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
