import {
  buildLinkedDeviceEnrollmentChildReceiptV1,
  buildLinkedDeviceEnrollmentReceiptV1,
} from '@shared/device-linking/parsers';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceProvisioningCommandV1,
  LinkedDeviceProvisioningDeliveriesV1,
} from '@shared/device-linking/contracts';
import type { LaneEnrollmentGatewayV1 } from '@shared/signing-lanes';
import { computeAggregateLaneActivationReceiptDigestV1 } from '@shared/signing-lanes/rotationDigests';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type { LinkedDeviceSessionRecordV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type { LaneLifecycleApplicationService } from '../../../../core/signingLanes/LaneLifecycleApplicationService';
import type { LaneLifecycleStore } from '../../../../core/signingLanes/LaneLifecycleStore';
import type { LinkedDeviceR102ProvisioningExecutionPortV1 } from './d1LinkedDeviceProvisioningProvider';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';

export type LinkedDeviceR102SourcePreparationPortV1 = {
  prepareProvisioningDeliveriesV1(input: {
    readonly command: LinkedDeviceProvisioningCommandV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceProvisioningDeliveriesV1>;
};

/** Completes the authoritative R102 lifecycle after Device 2 returns holder receipts. */
export function createLinkedDeviceR102ProvisioningExecutionV1(input: {
  readonly sourcePreparation: LinkedDeviceR102SourcePreparationPortV1;
  readonly gateway: Pick<
    LaneEnrollmentGatewayV1,
    'recordLaneHolderDeliveryV1' | 'commitLaneEnrollmentActivationV1'
  >;
  readonly lifecycle: Pick<LaneLifecycleApplicationService, 'activateLaneServerMaterialV1'>;
  readonly products: Pick<LaneLifecycleStore, 'getProductEpoch'>;
}): LinkedDeviceR102ProvisioningExecutionPortV1 {
  return {
    prepareProvisioningDeliveriesV1: input.sourcePreparation.prepareProvisioningDeliveriesV1.bind(
      input.sourcePreparation,
    ),
    async recordHolderDeliveriesAndActivateV1(request) {
      if (
        request.acknowledgement.orderedHolderDeliveryReceipts.length !==
        request.deliveries.orderedChildren.length
      ) {
        throw new Error('linked-device holder receipt coverage is incomplete');
      }
      const aggregateChildren = [];
      const linkedChildren = [];
      let activatedAtMs = request.requestedAtMs;
      for (let index = 0; index < request.deliveries.orderedChildren.length; index += 1) {
        const delivery = request.deliveries.orderedChildren[index];
        const holderReceipt = request.acknowledgement.orderedHolderDeliveryReceipts[index];
        if (!delivery || !holderReceipt) {
          throw new Error('linked-device holder receipt order is incomplete');
        }
        const holder = await input.gateway.recordLaneHolderDeliveryV1({
          receipt: holderReceipt,
          expectedVersion: delivery.expectedVersion,
        });
        if (holder.outcome === 'conflict') {
          throw new Error(`R102 holder delivery conflicted for ${delivery.job.operationId}`);
        }
        const activation = await activateServerMaterialV1({
          lifecycle: input.lifecycle,
          delivery,
          holderReceipt,
          expectedVersion: holder.version,
        });
        if (activation.outcome === 'conflict') {
          throw new Error(`R102 server activation conflicted for ${delivery.job.operationId}`);
        }
        const lifecycle = activation.record.lifecycle;
        if (lifecycle.state !== 'ready_for_parent_visibility' && lifecycle.state !== 'active') {
          throw new Error('R102 server activation did not become ready for visibility');
        }
        activatedAtMs = Math.max(
          activatedAtMs,
          lifecycle.state === 'active' ? lifecycle.activatedAtMs : lifecycle.serverActivatedAtMs,
        );
        const pendingProduct = await input.products.getProductEpoch({
          walletId: delivery.job.walletId,
          walletKeyId: delivery.job.walletKeyId,
          laneId: delivery.job.target.laneId,
          laneShareEpoch: delivery.job.target.laneShareEpoch,
        });
        if (
          !pendingProduct ||
          pendingProduct.operationId !== delivery.job.operationId ||
          pendingProduct.enrollmentId !== delivery.job.enrollmentId ||
          pendingProduct.targetMaterialActivationId !== delivery.job.targetMaterialActivationId
        ) {
          throw new Error('R102 server activation did not persist its exact target product');
        }
        aggregateChildren.push({
          operationId: delivery.job.operationId,
          walletKeyId: delivery.job.walletKeyId,
          targetLaneId: delivery.job.target.laneId,
          targetLaneShareEpoch: delivery.job.target.laneShareEpoch,
          targetMaterialActivation: pendingProduct.materialActivation,
          protocolCommitReceiptDigestB64u: lifecycle.protocolCommitReceiptDigestB64u,
          holderDeliveryReceiptDigestB64u: lifecycle.holderDeliveryReceiptDigestB64u,
          serverActivationReceiptDigestB64u: lifecycle.serverActivationReceiptDigestB64u,
        });
        linkedChildren.push({
          delivery,
          lifecycle,
          materialActivation: pendingProduct.materialActivation,
        });
      }
      const firstAggregate = aggregateChildren[0];
      if (!firstAggregate) throw new Error('linked-device provisioning has no R102 children');
      const manifestDigestB64u = sessionManifestDigest(request.session);
      const committed = await input.gateway.commitLaneEnrollmentActivationV1({
        kind: 'commit_lane_enrollment_activation_v1',
        enrollmentId: request.deliveries.orderedChildren[0].job.enrollmentId,
        walletId: request.approval.walletId,
        manifestDigestB64u,
        orderedChildReceipts: [firstAggregate, ...aggregateChildren.slice(1)],
        orderedPredecessorRetirements: [],
        activatedAtMs,
      });
      if (committed.outcome === 'conflict') {
        throw new Error('R102 linked-device aggregate activation conflicted');
      }
      const aggregateReceiptDigestB64u = parseDigestB64u(
        await computeAggregateLaneActivationReceiptDigestV1(committed.receipt),
      );
      const productsByOperation = new Map(
        committed.productEpochs.map((product) => [String(product.operationId), product]),
      );
      const projectedChildren = linkedChildren.map(
        ({ delivery, lifecycle, materialActivation }) => {
          const product = productsByOperation.get(String(delivery.job.operationId));
          if (
            !product ||
            !mpcMaterialActivationRefsEqual(product.materialActivation, materialActivation)
          ) {
            throw new Error('R102 active product is missing after aggregate commit');
          }
          return buildLinkedDeviceEnrollmentChildReceiptV1({
            enrollmentId: request.approval.enrollmentId,
            walletId: request.approval.walletId,
            walletKeyId: delivery.job.walletKeyId,
            keyFamily: delivery.job.keyFamily,
            targetLaneId: delivery.job.target.laneId,
            targetLaneShareEpoch: delivery.job.target.laneShareEpoch,
            materialActivation,
            receiptDigestB64u: parseDigestB64u(lifecycle.serverActivationReceiptDigestB64u),
            transcriptHashB64u: parseDigestB64u(lifecycle.transcriptHashB64u),
            deliveredAtMs: committed.receipt.activatedAtMs,
          });
        },
      );
      const firstProjected = projectedChildren[0];
      if (!firstProjected) throw new Error('linked-device activation projected no children');
      return buildLinkedDeviceEnrollmentReceiptV1({
        enrollmentId: request.approval.enrollmentId,
        walletId: request.approval.walletId,
        deviceId: request.approval.deviceId,
        targetFactor: request.approval.targetFactor,
        manifestDigestB64u: parseDigestB64u(committed.receipt.manifestDigestB64u),
        aggregateReceiptDigestB64u,
        orderedChildReceipts: [firstProjected, ...projectedChildren.slice(1)],
        activatedAtMs: committed.receipt.activatedAtMs,
      });
    },
  };
}

async function activateServerMaterialV1(input: {
  readonly lifecycle: Pick<LaneLifecycleApplicationService, 'activateLaneServerMaterialV1'>;
  readonly delivery: LinkedDeviceProvisioningDeliveriesV1['orderedChildren'][number];
  readonly holderReceipt: Parameters<
    LaneEnrollmentGatewayV1['recordLaneHolderDeliveryV1']
  >[0]['receipt'];
  readonly expectedVersion: number;
}) {
  return input.delivery.job.keyFamily === 'ed25519'
    ? await input.lifecycle.activateLaneServerMaterialV1({
        curve: 'ed25519_yao',
        job: input.delivery.job,
        protocolCommitReceipt: input.delivery.protocolCommitReceipt,
        holderDeliveryReceipt: input.holderReceipt,
        expectedVersion: input.expectedVersion,
      })
    : await input.lifecycle.activateLaneServerMaterialV1({
        curve: 'ecdsa_additive',
        job: input.delivery.job,
        protocolCommitReceipt: input.delivery.protocolCommitReceipt,
        holderDeliveryReceipt: input.holderReceipt,
        expectedVersion: input.expectedVersion,
      });
}

function sessionManifestDigest(session: LinkedDeviceSessionRecordV1): string {
  if (session.state.state !== 'committed_completion_required') {
    throw new Error('linked-device session has no R102 manifest for first activation');
  }
  return session.state.keyManifestDigestB64u;
}
