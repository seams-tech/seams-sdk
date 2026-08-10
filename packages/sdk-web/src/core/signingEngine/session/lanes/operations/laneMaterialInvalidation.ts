import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '@shared/signing-lanes/ids';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type {
  LaneEnrollmentActivationResultV1,
  LaneHolderRecipientWorkerV1,
  LaneSigningLaneRevocationResultV1,
} from '@shared/signing-lanes/rotation';
import type { LaneActivationEffectPlanV1 } from './activationCoordinator';

export type ExactLaneMaterialInvalidationTargetV1 = {
  readonly walletKeyId: WalletKeyId;
  readonly laneId: SigningLaneId;
  readonly laneShareEpoch: LaneShareEpoch;
  readonly materialActivation: MpcMaterialActivationRef;
};

export type LaneMaterialInvalidationReasonV1 = 'refresh' | 'revoke';

export type LaneMaterialInvalidationPlanV1 = {
  readonly kind: 'lane_material_invalidation_plan_v1';
  readonly target: ExactLaneMaterialInvalidationTargetV1;
  readonly reason: LaneMaterialInvalidationReasonV1;
  readonly keyFamily: 'ecdsa_secp256k1' | 'ed25519';
  readonly effect: 'worker_lane_material_and_curve_state';
};

export type LaneMaterialInvalidationExecutionV1 =
  | {
      readonly kind: 'lane_material_invalidation_execution_v1';
      readonly outcome: 'completed';
      readonly plan: LaneMaterialInvalidationPlanV1;
    }
  | {
      readonly kind: 'lane_material_invalidation_execution_v1';
      readonly outcome: 'deferred_offline';
      readonly plan: LaneMaterialInvalidationPlanV1;
    };

export type LaneMaterialInvalidationWorkerV1 =
  | {
      readonly state: 'available';
      readonly worker: Pick<LaneHolderRecipientWorkerV1, 'invalidateLaneMaterialV1'>;
    }
  | {
      readonly state: 'offline';
      readonly worker?: never;
    };

function exactTarget(
  target: ExactLaneMaterialInvalidationTargetV1,
): ExactLaneMaterialInvalidationTargetV1 {
  if (!String(target.walletKeyId).trim()) throw new Error('walletKeyId is required');
  if (!String(target.laneId).trim()) throw new Error('laneId is required');
  if (!String(target.laneShareEpoch).trim()) throw new Error('laneShareEpoch is required');
  if (!String(target.materialActivation.activationId).trim()) {
    throw new Error('materialActivation.activationId is required');
  }
  return target;
}

export function buildLaneMaterialInvalidationPlanV1(args: {
  readonly target: ExactLaneMaterialInvalidationTargetV1;
  readonly reason: LaneMaterialInvalidationReasonV1;
  readonly keyFamily: 'ecdsa_secp256k1' | 'ed25519';
}): LaneMaterialInvalidationPlanV1 {
  const target = exactTarget(args.target);
  return {
    kind: 'lane_material_invalidation_plan_v1',
    target,
    reason: args.reason,
    keyFamily: args.keyFamily,
    effect: 'worker_lane_material_and_curve_state',
  };
}

export async function executeLaneMaterialInvalidationPlanV1(args: {
  readonly plan: LaneMaterialInvalidationPlanV1;
  readonly worker: LaneMaterialInvalidationWorkerV1;
}): Promise<LaneMaterialInvalidationExecutionV1> {
  if (args.worker.state === 'offline') {
    return {
      kind: 'lane_material_invalidation_execution_v1',
      outcome: 'deferred_offline',
      plan: args.plan,
    };
  }
  await args.worker.worker.invalidateLaneMaterialV1(args.plan.target);
  return {
    kind: 'lane_material_invalidation_execution_v1',
    outcome: 'completed',
    plan: args.plan,
  };
}

export async function invalidateRefreshPredecessorsAfterActivationV1(args: {
  readonly activation: Extract<
    LaneEnrollmentActivationResultV1,
    { outcome: 'applied' | 'replayed' }
  >;
  readonly plan: LaneActivationEffectPlanV1;
  readonly worker: LaneMaterialInvalidationWorkerV1;
}): Promise<readonly LaneMaterialInvalidationExecutionV1[]> {
  if (
    args.activation.lifecycle.state !== 'active' ||
    args.activation.enrollmentId !== args.plan.commitCommand.enrollmentId ||
    args.activation.lifecycle.aggregateReceiptDigestB64u !==
      args.plan.aggregateActivationReceiptDigestB64u
  ) {
    throw new Error('refresh predecessor invalidation requires durable active visibility');
  }
  const executions: LaneMaterialInvalidationExecutionV1[] = [];
  for (const plan of args.plan.orderedPostCommitInvalidations) {
    if (plan.reason !== 'refresh')
      throw new Error('refresh predecessor invalidation plan reason changed');
    executions.push(await executeLaneMaterialInvalidationPlanV1({ plan, worker: args.worker }));
  }
  return executions;
}

export async function invalidateRevokedLaneAfterCompletionV1(args: {
  readonly revocation: Extract<
    LaneSigningLaneRevocationResultV1,
    { outcome: 'applied' | 'replayed' }
  >;
  readonly worker: LaneMaterialInvalidationWorkerV1;
}): Promise<LaneMaterialInvalidationExecutionV1> {
  const product = args.revocation.productEpoch;
  if (product.state !== 'revoked')
    throw new Error('lane invalidation requires a durably revoked product epoch');
  return await executeLaneMaterialInvalidationPlanV1({
    plan: buildLaneMaterialInvalidationPlanV1({
      target: {
        walletKeyId: product.walletKeyId,
        laneId: product.laneId,
        laneShareEpoch: product.laneShareEpoch,
        materialActivation: product.materialActivation,
      },
      reason: 'revoke',
      keyFamily: product.keyFamily,
    }),
    worker: args.worker,
  });
}

export const planLaneMaterialInvalidationV1 = buildLaneMaterialInvalidationPlanV1;
