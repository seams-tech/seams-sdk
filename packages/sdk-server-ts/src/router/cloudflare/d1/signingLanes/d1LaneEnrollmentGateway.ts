import type { LaneEnrollmentGatewayV1 } from '@shared/signing-lanes';
import { LaneEnrollmentActivation } from '../../../../core/signingLanes/LaneEnrollmentActivation';
import { LaneEnrollmentRevocation } from '../../../../core/signingLanes/LaneEnrollmentRevocation';
import type { LaneLifecycleStore } from '../../../../core/signingLanes/LaneLifecycleStore';

export type CloudflareD1LaneEnrollmentGatewayOptions = {
  readonly lifecycleStore: LaneLifecycleStore;
};

/** D1 gateway composition. Participant network calls are injected by callers. */
export class CloudflareD1LaneEnrollmentGateway implements LaneEnrollmentGatewayV1 {
  private readonly activation: LaneEnrollmentActivation;
  private readonly revocation: LaneEnrollmentRevocation;

  constructor(options: CloudflareD1LaneEnrollmentGatewayOptions) {
    this.activation = new LaneEnrollmentActivation(options.lifecycleStore);
    this.revocation = new LaneEnrollmentRevocation(options.lifecycleStore);
  }

  async prepareLaneEnrollmentV1(
    ...args: Parameters<LaneEnrollmentGatewayV1['prepareLaneEnrollmentV1']>
  ): ReturnType<LaneEnrollmentGatewayV1['prepareLaneEnrollmentV1']> {
    return await this.activation.prepareLaneEnrollmentV1(...args);
  }

  async resumeLaneProtocolOperationV1(
    ...args: Parameters<LaneEnrollmentGatewayV1['resumeLaneProtocolOperationV1']>
  ): ReturnType<LaneEnrollmentGatewayV1['resumeLaneProtocolOperationV1']> {
    return await this.activation.resumeLaneProtocolOperationV1(...args);
  }

  async recordLaneProtocolCommitV1(
    ...args: Parameters<LaneEnrollmentGatewayV1['recordLaneProtocolCommitV1']>
  ): ReturnType<LaneEnrollmentGatewayV1['recordLaneProtocolCommitV1']> {
    return await this.activation.recordLaneProtocolCommitV1(...args);
  }

  async recordLaneHolderDeliveryV1(
    ...args: Parameters<LaneEnrollmentGatewayV1['recordLaneHolderDeliveryV1']>
  ): ReturnType<LaneEnrollmentGatewayV1['recordLaneHolderDeliveryV1']> {
    return await this.activation.recordLaneHolderDeliveryV1(...args);
  }

  async activateLaneServerMaterialV1(
    ...args: Parameters<LaneEnrollmentGatewayV1['activateLaneServerMaterialV1']>
  ): ReturnType<LaneEnrollmentGatewayV1['activateLaneServerMaterialV1']> {
    return await this.activation.activateLaneServerMaterialV1(...args);
  }

  async commitLaneEnrollmentActivationV1(
    ...args: Parameters<LaneEnrollmentGatewayV1['commitLaneEnrollmentActivationV1']>
  ): ReturnType<LaneEnrollmentGatewayV1['commitLaneEnrollmentActivationV1']> {
    return await this.activation.commitLaneEnrollmentActivationV1(...args);
  }

  async fenceSigningLaneRevocationV1(
    ...args: Parameters<LaneEnrollmentGatewayV1['fenceSigningLaneRevocationV1']>
  ): ReturnType<LaneEnrollmentGatewayV1['fenceSigningLaneRevocationV1']> {
    return await this.revocation.fenceSigningLaneRevocationV1(...args);
  }

  async completeSigningLaneRevocationV1(
    ...args: Parameters<LaneEnrollmentGatewayV1['completeSigningLaneRevocationV1']>
  ): ReturnType<LaneEnrollmentGatewayV1['completeSigningLaneRevocationV1']> {
    return await this.revocation.completeSigningLaneRevocationV1(...args);
  }

  async revokeLaneEnrollmentV1(
    ...args: Parameters<LaneEnrollmentGatewayV1['revokeLaneEnrollmentV1']>
  ): ReturnType<LaneEnrollmentGatewayV1['revokeLaneEnrollmentV1']> {
    return await this.revocation.revokeLaneEnrollmentV1(...args);
  }
}
