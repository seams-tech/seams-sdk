import type {
  AggregateLaneActivationReceiptV1,
  AggregateLaneRevocationReceiptV1,
  LaneEnrollmentLifecycleV1,
  LaneProductEpochActiveV1,
  LaneProductEpochPendingVisibilityV1,
  LaneProductEpochRevocationPendingV1,
  LaneProductEpochRecordV1,
  LaneProductEpochRetiredV1,
  LaneProductEpochRevokedV1,
  LaneProtocolLifecycle,
} from './rotation';
import type { LaneOperationId } from './ids';

function requireForwardTime(previous: number, next: number, label: string): void {
  if (!Number.isSafeInteger(next) || next < previous) {
    throw new Error(`${label} must be a safe timestamp at or after ${previous}`);
  }
}

function requireSafeTimestamp(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe timestamp`);
  }
}

export type LaneProtocolLifecycleTransitionV1 =
  | { action: 'await_protocol_commitment'; atMs: number }
  | {
      action: 'record_commit';
      committedAtMs: number;
      transcriptHashB64u: string;
      protocolCommitReceiptDigestB64u: string;
    }
  | {
      action: 'record_holder_delivery';
      holderReceiptAtMs: number;
      holderDeliveryReceiptDigestB64u: string;
    }
  | {
      action: 'record_server_activation';
      serverActivatedAtMs: number;
      serverActivationReceiptDigestB64u: string;
    }
  | {
      action: 'activate';
      activatedAtMs: number;
      aggregateActivationReceiptDigestB64u: string;
    }
  | {
      action: 'abort_precommit';
      abortedAtMs: number;
      abortReason: 'cancelled' | 'expired' | 'revoked_before_commit';
    }
  | {
      action: 'require_completion';
      recoveryReason: 'exact_redelivery_required' | 'recovery_required';
    }
  | { action: 'resume_completion'; atMs: number };

export function transitionLaneProtocolLifecycleV1(
  current: LaneProtocolLifecycle,
  transition: LaneProtocolLifecycleTransitionV1,
): LaneProtocolLifecycle {
  switch (current.state) {
    case 'preparing':
      if (transition.action === 'await_protocol_commitment') {
        requireForwardTime(current.startedAtMs, transition.atMs, 'await_protocol_commitment.atMs');
        return { state: 'awaiting_protocol_commitment', startedAtMs: current.startedAtMs };
      }
      if (transition.action === 'abort_precommit') {
        requireForwardTime(
          current.startedAtMs,
          transition.abortedAtMs,
          'abort_precommit.abortedAtMs',
        );
        return {
          state: 'aborted_precommit',
          startedAtMs: current.startedAtMs,
          abortedAtMs: transition.abortedAtMs,
          abortReason: transition.abortReason,
        };
      }
      break;
    case 'awaiting_protocol_commitment':
      if (transition.action === 'record_commit') {
        requireForwardTime(
          current.startedAtMs,
          transition.committedAtMs,
          'record_commit.committedAtMs',
        );
        return {
          state: 'committed_awaiting_holder_delivery',
          startedAtMs: current.startedAtMs,
          committedAtMs: transition.committedAtMs,
          transcriptHashB64u: transition.transcriptHashB64u,
          protocolCommitReceiptDigestB64u: transition.protocolCommitReceiptDigestB64u,
        };
      }
      if (transition.action === 'abort_precommit') {
        requireForwardTime(
          current.startedAtMs,
          transition.abortedAtMs,
          'abort_precommit.abortedAtMs',
        );
        return {
          state: 'aborted_precommit',
          startedAtMs: current.startedAtMs,
          abortedAtMs: transition.abortedAtMs,
          abortReason: transition.abortReason,
        };
      }
      break;
    case 'committed_awaiting_holder_delivery':
      if (transition.action === 'record_holder_delivery') {
        requireForwardTime(
          current.committedAtMs,
          transition.holderReceiptAtMs,
          'record_holder_delivery.holderReceiptAtMs',
        );
        return {
          state: 'awaiting_server_activation',
          startedAtMs: current.startedAtMs,
          committedAtMs: current.committedAtMs,
          transcriptHashB64u: current.transcriptHashB64u,
          protocolCommitReceiptDigestB64u: current.protocolCommitReceiptDigestB64u,
          holderDeliveryReceiptDigestB64u: transition.holderDeliveryReceiptDigestB64u,
          holderReceiptAtMs: transition.holderReceiptAtMs,
        };
      }
      if (transition.action === 'require_completion') {
        return {
          state: 'committed_completion_required',
          startedAtMs: current.startedAtMs,
          committedAtMs: current.committedAtMs,
          transcriptHashB64u: current.transcriptHashB64u,
          protocolCommitReceiptDigestB64u: current.protocolCommitReceiptDigestB64u,
          recoveryReason: transition.recoveryReason,
        };
      }
      break;
    case 'awaiting_server_activation':
      if (transition.action === 'record_server_activation') {
        requireForwardTime(
          current.holderReceiptAtMs,
          transition.serverActivatedAtMs,
          'record_server_activation.serverActivatedAtMs',
        );
        return {
          state: 'ready_for_parent_visibility',
          startedAtMs: current.startedAtMs,
          committedAtMs: current.committedAtMs,
          transcriptHashB64u: current.transcriptHashB64u,
          protocolCommitReceiptDigestB64u: current.protocolCommitReceiptDigestB64u,
          holderDeliveryReceiptDigestB64u: current.holderDeliveryReceiptDigestB64u,
          holderReceiptAtMs: current.holderReceiptAtMs,
          serverActivationReceiptDigestB64u: transition.serverActivationReceiptDigestB64u,
          serverActivatedAtMs: transition.serverActivatedAtMs,
        };
      }
      break;
    case 'ready_for_parent_visibility':
      if (transition.action === 'activate') {
        requireForwardTime(
          current.serverActivatedAtMs,
          transition.activatedAtMs,
          'activate.activatedAtMs',
        );
        return {
          state: 'active',
          transcriptHashB64u: current.transcriptHashB64u,
          protocolCommitReceiptDigestB64u: current.protocolCommitReceiptDigestB64u,
          holderDeliveryReceiptDigestB64u: current.holderDeliveryReceiptDigestB64u,
          serverActivationReceiptDigestB64u: current.serverActivationReceiptDigestB64u,
          aggregateActivationReceiptDigestB64u: transition.aggregateActivationReceiptDigestB64u,
          activatedAtMs: transition.activatedAtMs,
        };
      }
      break;
    case 'committed_completion_required':
      if (transition.action === 'resume_completion') {
        requireForwardTime(current.committedAtMs, transition.atMs, 'resume_completion.atMs');
        return {
          state: 'committed_awaiting_holder_delivery',
          startedAtMs: current.startedAtMs,
          committedAtMs: current.committedAtMs,
          transcriptHashB64u: current.transcriptHashB64u,
          protocolCommitReceiptDigestB64u: current.protocolCommitReceiptDigestB64u,
        };
      }
      break;
    case 'active':
    case 'aborted_precommit':
      break;
  }
  throw new Error(
    `invalid lane protocol lifecycle transition: ${current.state} -> ${transition.action}`,
  );
}

export function beginLaneProtocolLifecycleV1(
  startedAtMs: number,
): Extract<LaneProtocolLifecycle, { state: 'preparing' }> {
  requireSafeTimestamp(startedAtMs, 'startedAtMs');
  return { state: 'preparing', startedAtMs };
}

export function markLaneProtocolCompletionRequiredV1(
  current: Extract<LaneProtocolLifecycle, { state: 'committed_awaiting_holder_delivery' }>,
  recoveryReason: 'exact_redelivery_required' | 'recovery_required',
): Extract<LaneProtocolLifecycle, { state: 'committed_completion_required' }> {
  const next = transitionLaneProtocolLifecycleV1(current, {
    action: 'require_completion',
    recoveryReason,
  });
  if (next.state !== 'committed_completion_required')
    throw new Error('completion transition did not produce completion state');
  return next;
}

export function resumeLaneProtocolCompletionV1(
  current: Extract<LaneProtocolLifecycle, { state: 'committed_completion_required' }>,
  atMs: number,
): Extract<LaneProtocolLifecycle, { state: 'committed_awaiting_holder_delivery' }> {
  const next = transitionLaneProtocolLifecycleV1(current, { action: 'resume_completion', atMs });
  if (next.state !== 'committed_awaiting_holder_delivery')
    throw new Error('resume transition did not produce committed state');
  return next;
}

export type LaneEnrollmentLifecycleTransitionV1 =
  | {
      action: 'mark_committed_completion_required';
      committedChildOperationIds: readonly [LaneOperationId, ...LaneOperationId[]];
      markedAtMs: number;
    }
  | { action: 'mark_ready_for_visibility'; aggregateReceiptDigestB64u: string; readyAtMs: number }
  | { action: 'activate'; activatedAtMs: number }
  | { action: 'cancel_precommit'; cancelledAtMs: number }
  | {
      action: 'begin_revocation';
      reason: 'cancelled_after_commit' | 'expired_after_commit' | 'revoked_during_activation';
      markedAtMs: number;
    }
  | { action: 'revoke'; aggregateRevocationReceiptDigestB64u: string; revokedAtMs: number };

export function transitionLaneEnrollmentLifecycleV1(
  current: LaneEnrollmentLifecycleV1,
  transition: LaneEnrollmentLifecycleTransitionV1,
): LaneEnrollmentLifecycleV1 {
  switch (current.state) {
    case 'preparing':
      if (transition.action === 'mark_committed_completion_required') {
        requireForwardTime(current.startedAtMs, transition.markedAtMs, 'markedAtMs');
        if (transition.committedChildOperationIds.length === 0)
          throw new Error('committed children must be non-empty');
        return {
          state: 'committed_completion_required',
          manifestDigestB64u: current.manifestDigestB64u,
          committedChildOperationIds: transition.committedChildOperationIds,
          markedAtMs: transition.markedAtMs,
        };
      }
      if (transition.action === 'cancel_precommit') {
        requireForwardTime(current.startedAtMs, transition.cancelledAtMs, 'cancelledAtMs');
        return { state: 'cancelled_precommit', cancelledAtMs: transition.cancelledAtMs };
      }
      break;
    case 'committed_completion_required':
      if (transition.action === 'mark_ready_for_visibility') {
        requireForwardTime(current.markedAtMs, transition.readyAtMs, 'readyAtMs');
        return {
          state: 'ready_for_visibility',
          manifestDigestB64u: current.manifestDigestB64u,
          aggregateReceiptDigestB64u: transition.aggregateReceiptDigestB64u,
          readyAtMs: transition.readyAtMs,
        };
      }
      if (transition.action === 'begin_revocation') {
        requireForwardTime(current.markedAtMs, transition.markedAtMs, 'markedAtMs');
        return {
          state: 'revoking_committed_targets',
          manifestDigestB64u: current.manifestDigestB64u,
          reason: transition.reason,
          markedAtMs: transition.markedAtMs,
        };
      }
      break;
    case 'ready_for_visibility':
      if (transition.action === 'activate') {
        requireForwardTime(current.readyAtMs, transition.activatedAtMs, 'activatedAtMs');
        return {
          state: 'active',
          manifestDigestB64u: current.manifestDigestB64u,
          aggregateReceiptDigestB64u: current.aggregateReceiptDigestB64u,
          activatedAtMs: transition.activatedAtMs,
        };
      }
      if (transition.action === 'begin_revocation') {
        requireForwardTime(current.readyAtMs, transition.markedAtMs, 'markedAtMs');
        return {
          state: 'revoking_committed_targets',
          manifestDigestB64u: current.manifestDigestB64u,
          reason: transition.reason,
          markedAtMs: transition.markedAtMs,
        };
      }
      break;
    case 'active':
      if (transition.action === 'begin_revocation') {
        requireForwardTime(current.activatedAtMs, transition.markedAtMs, 'markedAtMs');
        return {
          state: 'revoking_committed_targets',
          manifestDigestB64u: current.manifestDigestB64u,
          reason: transition.reason,
          markedAtMs: transition.markedAtMs,
        };
      }
      break;
    case 'revoking_committed_targets':
      if (transition.action === 'revoke') {
        requireForwardTime(current.markedAtMs, transition.revokedAtMs, 'revokedAtMs');
        return {
          state: 'revoked',
          manifestDigestB64u: current.manifestDigestB64u,
          aggregateRevocationReceiptDigestB64u: transition.aggregateRevocationReceiptDigestB64u,
          revokedAtMs: transition.revokedAtMs,
        };
      }
      break;
    case 'cancelled_precommit':
    case 'revoked':
      break;
  }
  throw new Error(
    `invalid enrollment lifecycle transition: ${current.state} -> ${transition.action}`,
  );
}

export function activateLaneProductEpochV1(
  current: LaneProductEpochPendingVisibilityV1,
  args: { readonly aggregateActivationReceiptDigestB64u: string; readonly activatedAtMs: number },
): LaneProductEpochActiveV1 {
  requireForwardTime(current.pendingSinceMs, args.activatedAtMs, 'activatedAtMs');
  return {
    kind: 'lane_product_epoch_record_v1',
    state: 'active',
    walletId: current.walletId,
    walletKeyId: current.walletKeyId,
    laneId: current.laneId,
    laneKind: current.laneKind,
    laneShareEpoch: current.laneShareEpoch,
    keyFamily: current.keyFamily,
    enrollmentId: current.enrollmentId,
    operationId: current.operationId,
    targetMaterialActivationId: current.targetMaterialActivationId,
    materialActivation: current.materialActivation,
    publicIdentityDigestB64u: current.publicIdentityDigestB64u,
    holderParticipant: current.holderParticipant,
    signingWorkerParticipant: current.signingWorkerParticipant,
    participantSetBindingDigestB64u: current.participantSetBindingDigestB64u,
    revocationEpoch: current.revocationEpoch,
    createdAtMs: current.createdAtMs,
    aggregateManifestDigestB64u: current.aggregateManifestDigestB64u,
    aggregateActivationReceiptDigestB64u: args.aggregateActivationReceiptDigestB64u,
    activatedAtMs: args.activatedAtMs,
  };
}

export function retireLaneProductEpochV1(
  current: LaneProductEpochActiveV1,
  args: {
    readonly retirementReason: LaneProductEpochRetiredV1['retirementReason'];
    readonly retirementReceiptDigestB64u: string;
    readonly retiredAtMs: number;
  },
): LaneProductEpochRetiredV1 {
  requireForwardTime(current.activatedAtMs, args.retiredAtMs, 'retiredAtMs');
  return {
    kind: 'lane_product_epoch_record_v1',
    state: 'retired',
    walletId: current.walletId,
    walletKeyId: current.walletKeyId,
    laneId: current.laneId,
    laneKind: current.laneKind,
    laneShareEpoch: current.laneShareEpoch,
    keyFamily: current.keyFamily,
    enrollmentId: current.enrollmentId,
    operationId: current.operationId,
    targetMaterialActivationId: current.targetMaterialActivationId,
    materialActivation: current.materialActivation,
    publicIdentityDigestB64u: current.publicIdentityDigestB64u,
    holderParticipant: current.holderParticipant,
    signingWorkerParticipant: current.signingWorkerParticipant,
    participantSetBindingDigestB64u: current.participantSetBindingDigestB64u,
    revocationEpoch: current.revocationEpoch,
    createdAtMs: current.createdAtMs,
    retirementReason: args.retirementReason,
    retirementReceiptDigestB64u: args.retirementReceiptDigestB64u,
    retiredAtMs: args.retiredAtMs,
  };
}

export function beginLaneProductEpochRevocationV1(
  current: LaneProductEpochPendingVisibilityV1 | LaneProductEpochActiveV1,
  args: {
    readonly revocationEpoch: number;
    readonly revocationReason: LaneProductEpochRevokedV1['revocationReason'];
    readonly retirementEffectBindingDigestB64u: string;
    readonly revocationRequestedAtMs: number;
  },
): LaneProductEpochRevocationPendingV1 {
  const previousAt =
    current.state === 'pending_visibility' ? current.pendingSinceMs : current.activatedAtMs;
  requireForwardTime(previousAt, args.revocationRequestedAtMs, 'revocationRequestedAtMs');
  if (!Number.isSafeInteger(args.revocationEpoch) || args.revocationEpoch < 0)
    throw new Error('revocationEpoch must be a non-negative safe integer');
  return {
    kind: 'lane_product_epoch_record_v1',
    state: 'revocation_pending',
    walletId: current.walletId,
    walletKeyId: current.walletKeyId,
    laneId: current.laneId,
    laneKind: current.laneKind,
    laneShareEpoch: current.laneShareEpoch,
    keyFamily: current.keyFamily,
    enrollmentId: current.enrollmentId,
    operationId: current.operationId,
    targetMaterialActivationId: current.targetMaterialActivationId,
    materialActivation: current.materialActivation,
    publicIdentityDigestB64u: current.publicIdentityDigestB64u,
    holderParticipant: current.holderParticipant,
    signingWorkerParticipant: current.signingWorkerParticipant,
    participantSetBindingDigestB64u: current.participantSetBindingDigestB64u,
    createdAtMs: current.createdAtMs,
    revocationEpoch: args.revocationEpoch,
    revocationReason: args.revocationReason,
    retirementEffectBindingDigestB64u: args.retirementEffectBindingDigestB64u,
    revocationRequestedAtMs: args.revocationRequestedAtMs,
  };
}

export function completeLaneProductEpochRevocationV1(
  current: LaneProductEpochRevocationPendingV1,
  args: {
    readonly revocationReceiptDigestB64u: string;
    readonly revokedAtMs: number;
  },
): LaneProductEpochRevokedV1 {
  requireForwardTime(current.revocationRequestedAtMs, args.revokedAtMs, 'revokedAtMs');
  return {
    kind: 'lane_product_epoch_record_v1',
    state: 'revoked',
    walletId: current.walletId,
    walletKeyId: current.walletKeyId,
    laneId: current.laneId,
    laneKind: current.laneKind,
    laneShareEpoch: current.laneShareEpoch,
    keyFamily: current.keyFamily,
    enrollmentId: current.enrollmentId,
    operationId: current.operationId,
    targetMaterialActivationId: current.targetMaterialActivationId,
    materialActivation: current.materialActivation,
    publicIdentityDigestB64u: current.publicIdentityDigestB64u,
    holderParticipant: current.holderParticipant,
    signingWorkerParticipant: current.signingWorkerParticipant,
    participantSetBindingDigestB64u: current.participantSetBindingDigestB64u,
    createdAtMs: current.createdAtMs,
    revocationEpoch: current.revocationEpoch,
    revocationReason: current.revocationReason,
    retirementEffectBindingDigestB64u: current.retirementEffectBindingDigestB64u,
    revocationReceiptDigestB64u: args.revocationReceiptDigestB64u,
    revokedAtMs: args.revokedAtMs,
  };
}

export function assertForwardOnlyLaneProductEpochV1(value: LaneProductEpochRecordV1): void {
  switch (value.state) {
    case 'pending_visibility':
    case 'active':
    case 'retired':
    case 'revocation_pending':
    case 'revoked':
      requireSafeTimestamp(value.createdAtMs, 'createdAtMs');
      break;
  }
}

export type LaneActivationReceiptInputV1 = {
  readonly aggregateReceipt: AggregateLaneActivationReceiptV1;
  readonly manifestDigestB64u: string;
};

export type LaneRevocationReceiptInputV1 = {
  readonly aggregateReceipt: AggregateLaneRevocationReceiptV1;
  readonly manifestDigestB64u: string;
};
