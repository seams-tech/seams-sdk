import type {
  EcdsaAdditiveLaneHolderRoundV1,
  EcdsaAdditiveLaneJobV1,
  Ed25519YaoLaneJobV1,
  LaneHolderDeliveryReceiptV1,
  LaneProtocolCommitReceiptV1,
  LaneServerActivationReceiptV1,
  RevokeSigningLaneV1,
} from '@shared/signing-lanes';
import {
  parseLaneProtocolCommitReceiptV1,
  parseLaneServerActivationReceiptV1,
  parseRevokeSigningLaneV1,
} from '@shared/signing-lanes/rotationParsers';
import type {
  LaneLifecycleCurveExecutionPortsV1,
  LaneLifecycleRetirementExecutionV1,
} from '../../../core/signingLanes/LaneLifecycleApplicationService';
import type { CloudflareEd25519LaneProtocolTransportV1 } from './cloudflareLaneProtocolCommitter';

type LaneMaterialMutationOutcomeV1 = 'applied' | 'replayed';

export type SigningWorkerLaneProtocolCommitProjectionV1 = {
  readonly kind: 'signing_worker_lane_protocol_commit_projection_v1';
  readonly outcome: LaneMaterialMutationOutcomeV1;
  readonly receipt: LaneProtocolCommitReceiptV1;
};

export type SigningWorkerLaneServerActivationProjectionV1 = {
  readonly kind: 'signing_worker_lane_server_activation_projection_v1';
  readonly outcome: LaneMaterialMutationOutcomeV1;
  readonly receipt: LaneServerActivationReceiptV1;
};

export type SigningWorkerLaneRetirementProjectionV1 = {
  readonly kind: 'signing_worker_lane_retirement_projection_v1';
  readonly outcome: LaneMaterialMutationOutcomeV1;
  readonly command: RevokeSigningLaneV1;
  readonly retirementReceiptDigestB64u: string;
};

/**
 * Receipt-only projection of the private SigningWorker material journal. The
 * encrypted active record and all plaintext material are intentionally absent.
 */
export interface SigningWorkerLaneMaterialReceiptPortV1 {
  commitEcdsaProtocolV1(input: {
    readonly job: EcdsaAdditiveLaneJobV1;
    readonly holderRound: EcdsaAdditiveLaneHolderRoundV1;
    readonly encryptedDeltaPackageJson: string;
  }): Promise<SigningWorkerLaneProtocolCommitProjectionV1>;
  activateServerMaterialV1(
    input:
      | {
          readonly curve: 'ed25519_yao';
          readonly job: Ed25519YaoLaneJobV1;
          readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
          readonly holderDeliveryReceipt: LaneHolderDeliveryReceiptV1;
        }
      | {
          readonly curve: 'ecdsa_additive';
          readonly job: EcdsaAdditiveLaneJobV1;
          readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
          readonly holderDeliveryReceipt: LaneHolderDeliveryReceiptV1;
        },
  ): Promise<SigningWorkerLaneServerActivationProjectionV1>;
  retireServerMaterialV1(input: {
    readonly curve: 'ed25519_yao' | 'ecdsa_additive';
    readonly command: RevokeSigningLaneV1;
  }): Promise<SigningWorkerLaneRetirementProjectionV1>;
}

export type CloudflareLaneCurveExecutionOptionsV1 = {
  readonly ed25519Transport: CloudflareEd25519LaneProtocolTransportV1;
  readonly signingWorker: SigningWorkerLaneMaterialReceiptPortV1;
};

export function createCloudflareLaneCurveExecutionPortsV1(
  options: CloudflareLaneCurveExecutionOptionsV1,
): LaneLifecycleCurveExecutionPortsV1 {
  return {
    ed25519: {
      async executeProtocolCommitV1(input) {
        const execution = await options.ed25519Transport.executeProtocolCommitV1(input);
        return parseLaneProtocolCommitReceiptV1(execution.receipt);
      },
      async executeServerActivationV1(input) {
        const projection = await options.signingWorker.activateServerMaterialV1({
          curve: 'ed25519_yao',
          ...input,
        });
        requireProjection(
          projection,
          'signing_worker_lane_server_activation_projection_v1',
        );
        return parseLaneServerActivationReceiptV1(projection.receipt);
      },
      async executeServerRetirementV1(input) {
        return retirementExecution(
          await options.signingWorker.retireServerMaterialV1({
            curve: 'ed25519_yao',
            command: input.command,
          }),
        );
      },
    },
    ecdsa: {
      async executeProtocolCommitV1(input) {
        const projection = await options.signingWorker.commitEcdsaProtocolV1(input);
        requireProjection(projection, 'signing_worker_lane_protocol_commit_projection_v1');
        return parseLaneProtocolCommitReceiptV1(projection.receipt);
      },
      async executeServerActivationV1(input) {
        const projection = await options.signingWorker.activateServerMaterialV1({
          curve: 'ecdsa_additive',
          ...input,
        });
        requireProjection(
          projection,
          'signing_worker_lane_server_activation_projection_v1',
        );
        return parseLaneServerActivationReceiptV1(projection.receipt);
      },
      async executeServerRetirementV1(input) {
        return retirementExecution(
          await options.signingWorker.retireServerMaterialV1({
            curve: 'ecdsa_additive',
            command: input.command,
          }),
        );
      },
    },
  };
}

function retirementExecution(
  projection: SigningWorkerLaneRetirementProjectionV1,
): LaneLifecycleRetirementExecutionV1 {
  requireProjection(projection, 'signing_worker_lane_retirement_projection_v1');
  const command = parseRevokeSigningLaneV1(projection.command);
  if (
    typeof projection.retirementReceiptDigestB64u !== 'string' ||
    projection.retirementReceiptDigestB64u.length === 0
  ) {
    throw new Error('SigningWorker lane retirement receipt digest is invalid');
  }
  return {
    kind: 'lane_lifecycle_retirement_execution_v1',
    command,
    retirementReceiptDigestB64u: projection.retirementReceiptDigestB64u,
  };
}

function requireProjection(
  projection: {
    readonly kind: string;
    readonly outcome: string;
  },
  expectedKind:
    | 'signing_worker_lane_protocol_commit_projection_v1'
    | 'signing_worker_lane_server_activation_projection_v1'
    | 'signing_worker_lane_retirement_projection_v1',
): void {
  if (projection.kind !== expectedKind) {
    throw new Error('SigningWorker lane material projection kind is invalid');
  }
  if (projection.outcome !== 'applied' && projection.outcome !== 'replayed') {
    throw new Error('SigningWorker lane material projection outcome is invalid');
  }
}
