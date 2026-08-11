import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceHolderDeliveryAcknowledgementV1,
  LinkedDeviceProvisioningDeliveriesV1,
} from '@shared/device-linking/contracts';
import type {
  LaneEnrollmentManifestChildV1,
  LaneEnrollmentManifestV1,
  LaneProtocolLifecycle,
  RotatableSigningLaneJobV1,
} from '@shared/signing-lanes';
import { parseLaneEnrollmentId } from '@shared/signing-lanes/ids';
import { encodeLaneProtocolCommitReceiptV1 } from '@shared/signing-lanes/rotationDigests';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256Bytes } from '@shared/utils/digests';
import type { LaneLifecycleStore } from '../../../../core/signingLanes/LaneLifecycleStore';
import type { DeviceLinkingProvisioningVerifierV1 } from '../../../../router/transport/fetch/routes/deviceLinking';
import { equalLaneRecords } from '../signingLanes/d1LaneRecords';

export type D1LinkedDeviceProvisioningVerifierOptionsV1 = {
  readonly lifecycleStore: Pick<LaneLifecycleStore, 'getEnrollment' | 'getProtocol'>;
};

export class D1LinkedDeviceProvisioningVerifierV1 implements DeviceLinkingProvisioningVerifierV1 {
  private readonly lifecycleStore: D1LinkedDeviceProvisioningVerifierOptionsV1['lifecycleStore'];

  constructor(options: D1LinkedDeviceProvisioningVerifierOptionsV1) {
    this.lifecycleStore = options.lifecycleStore;
  }

  async verifyProvisioningDeliveriesV1(input: {
    readonly deliveries: LinkedDeviceProvisioningDeliveriesV1;
    readonly approval: LinkedDeviceApprovalV1;
  }): Promise<void> {
    const manifest = await this.requirePersistedManifest(input.approval);
    if (
      String(input.deliveries.enrollmentId) !== String(manifest.enrollmentId) ||
      input.deliveries.orderedChildren.length !== manifest.orderedChildren.length
    ) {
      throw new Error('R102 provisioning delivery coverage differs from its persisted manifest');
    }
    for (let index = 0; index < manifest.orderedChildren.length; index += 1) {
      const manifestChild = manifest.orderedChildren[index];
      const approvedChild = input.approval.orderedKeyBindings[index];
      const approvedProtocol = input.approval.protocolVersions[index];
      const delivery = input.deliveries.orderedChildren[index];
      if (!manifestChild || !approvedChild || !approvedProtocol || !delivery) {
        throw new Error('R102 provisioning delivery order is incomplete');
      }
      assertManifestChildMatchesApproval(manifestChild, approvedChild);
      const protocol = await this.lifecycleStore.getProtocol(manifestChild.operationId);
      if (!protocol || !isCommittedProtocolLifecycle(protocol.value.lifecycle)) {
        throw new Error('R102 provisioning child has no committed protocol');
      }
      assertJobMatchesManifest(
        protocol.value.job,
        manifestChild,
        manifest,
        approvedChild,
        approvedProtocol,
      );
      if (
        delivery.expectedVersion !== protocol.version ||
        !equalLaneRecords(protocol.value.job, delivery.job)
      ) {
        throw new Error('R102 provisioning delivery job differs from its persisted job');
      }
      const receiptDigestB64u = base64UrlEncode(
        await sha256Bytes(encodeLaneProtocolCommitReceiptV1(delivery.protocolCommitReceipt)),
      );
      if (receiptDigestB64u !== protocol.value.lifecycle.protocolCommitReceiptDigestB64u) {
        throw new Error('R102 provisioning receipt differs from its committed receipt digest');
      }
    }
  }

  async verifyHolderDeliveriesV1(input: {
    readonly acknowledgement: LinkedDeviceHolderDeliveryAcknowledgementV1;
    readonly approval: LinkedDeviceApprovalV1;
  }): Promise<void> {
    const manifest = await this.requirePersistedManifest(input.approval);
    if (
      input.acknowledgement.orderedHolderDeliveryReceipts.length !== manifest.orderedChildren.length
    ) {
      throw new Error('R102 holder receipt coverage differs from its persisted manifest');
    }
    for (let index = 0; index < manifest.orderedChildren.length; index += 1) {
      const manifestChild = manifest.orderedChildren[index];
      const approvedChild = input.approval.orderedKeyBindings[index];
      const approvedProtocol = input.approval.protocolVersions[index];
      const receipt = input.acknowledgement.orderedHolderDeliveryReceipts[index];
      if (!manifestChild || !approvedChild || !approvedProtocol || !receipt) {
        throw new Error('R102 holder receipt order is incomplete');
      }
      assertManifestChildMatchesApproval(manifestChild, approvedChild);
      const protocol = await this.lifecycleStore.getProtocol(manifestChild.operationId);
      if (!protocol || !isCommittedProtocolLifecycle(protocol.value.lifecycle)) {
        throw new Error('R102 holder receipt has no committed protocol');
      }
      assertJobMatchesManifest(
        protocol.value.job,
        manifestChild,
        manifest,
        approvedChild,
        approvedProtocol,
      );
      if (
        receipt.operationId !== manifestChild.operationId ||
        receipt.enrollmentId !== manifest.enrollmentId ||
        receipt.targetLaneId !== manifestChild.targetLaneId ||
        receipt.targetLaneShareEpoch !== manifestChild.targetLaneShareEpoch ||
        receipt.targetMaterialActivationId !== manifestChild.targetMaterialActivationId ||
        receipt.holderParticipantBindingDigestB64u !==
          manifestChild.holderParticipantBindingDigestB64u ||
        receipt.holderRecipientKeyDigestB64u !==
          protocol.value.job.targetHolder.hpkePublicKeyDigestB64u ||
        receipt.transcriptHashB64u !== protocol.value.lifecycle.transcriptHashB64u
      ) {
        throw new Error('R102 holder receipt differs from its persisted child operation');
      }
    }
  }

  private async requirePersistedManifest(
    approval: LinkedDeviceApprovalV1,
  ): Promise<LaneEnrollmentManifestV1> {
    const enrollmentId = parseLaneEnrollmentId(String(approval.enrollmentId));
    if (!enrollmentId.ok) throw new Error('R102 linked-device enrollment id is invalid');
    const enrollment = await this.lifecycleStore.getEnrollment(enrollmentId.value);
    if (!enrollment) throw new Error('R102 linked-device enrollment is not persisted');
    const { manifest, lifecycle } = enrollment.value;
    if (
      manifest.enrollmentId !== enrollmentId.value ||
      manifest.walletId !== approval.walletId ||
      manifest.authorization.kind !== 'linked_device_enrollment' ||
      manifest.authorization.linkedDeviceEnrollmentId !== approval.enrollmentId ||
      manifest.authorization.linkedDevicePermissionDigestB64u !== approval.policyDigestB64u ||
      manifest.orderedChildren.length !== approval.orderedKeyBindings.length ||
      lifecycle.state === 'cancelled_precommit' ||
      lifecycle.state === 'revoking_committed_targets' ||
      lifecycle.state === 'revoked'
    ) {
      throw new Error('R102 linked-device enrollment differs from its persisted approval');
    }
    return manifest;
  }
}

function assertManifestChildMatchesApproval(
  manifestChild: LaneEnrollmentManifestChildV1,
  approvedChild: LinkedDeviceApprovalV1['orderedKeyBindings'][number],
): void {
  if (
    manifestChild.walletKeyId !== approvedChild.walletKeyId ||
    manifestChild.keyFamily !== approvedChild.keyFamily ||
    manifestChild.sourceLaneId !== approvedChild.sourceLaneId ||
    manifestChild.sourceLaneShareEpoch !== approvedChild.sourceLaneShareEpoch ||
    manifestChild.sourceRevocationEpoch !== approvedChild.sourceRevocationEpoch ||
    manifestChild.targetLaneId !== approvedChild.targetLaneId ||
    manifestChild.targetLaneShareEpoch !== approvedChild.targetLaneShareEpoch
  ) {
    throw new Error('R102 manifest child differs from its approved key binding');
  }
}

function assertJobMatchesManifest(
  job: RotatableSigningLaneJobV1,
  manifestChild: LaneEnrollmentManifestChildV1,
  manifest: LaneEnrollmentManifestV1,
  approvedChild: LinkedDeviceApprovalV1['orderedKeyBindings'][number],
  approvedProtocol: LinkedDeviceApprovalV1['protocolVersions'][number],
): void {
  if (
    job.operationId !== manifestChild.operationId ||
    job.enrollmentId !== manifest.enrollmentId ||
    job.walletId !== manifest.walletId ||
    job.walletKeyId !== manifestChild.walletKeyId ||
    job.keyFamily !== manifestChild.keyFamily ||
    job.keyFamily !== approvedProtocol.keyFamily ||
    job.protocolVersion !== approvedProtocol.version ||
    job.source.laneId !== manifestChild.sourceLaneId ||
    job.source.laneShareEpoch !== manifestChild.sourceLaneShareEpoch ||
    job.source.revocationEpoch !== manifestChild.sourceRevocationEpoch ||
    job.source.holderParticipantId !== approvedChild.sourceHolderParticipantId ||
    job.source.signingWorkerParticipantId !== approvedChild.sourceSigningWorkerParticipantId ||
    !equalLaneRecords(job.source.materialActivation, manifestChild.sourceMaterialActivation) ||
    job.target.operation !== 'create_lane' ||
    job.target.laneKind !== 'linked_device' ||
    job.target.laneId !== manifestChild.targetLaneId ||
    job.target.laneShareEpoch !== manifestChild.targetLaneShareEpoch ||
    job.targetMaterialActivationId !== manifestChild.targetMaterialActivationId ||
    job.targetHolder.participantBindingDigestB64u !==
      manifestChild.holderParticipantBindingDigestB64u ||
    job.targetSigningWorker.participantBindingDigestB64u !==
      manifestChild.signingWorkerParticipantBindingDigestB64u ||
    job.authorization.kind !== 'linked_device_enrollment' ||
    manifest.authorization.kind !== 'linked_device_enrollment' ||
    job.authorization.linkedDeviceEnrollmentId !==
      manifest.authorization.linkedDeviceEnrollmentId ||
    job.authorization.linkedDevicePermissionDigestB64u !==
      manifest.authorization.linkedDevicePermissionDigestB64u
  ) {
    throw new Error('R102 persisted job differs from its manifest child');
  }
}

function isCommittedProtocolLifecycle(
  lifecycle: LaneProtocolLifecycle,
): lifecycle is Exclude<
  LaneProtocolLifecycle,
  { readonly state: 'preparing' | 'awaiting_protocol_commitment' | 'aborted_precommit' }
> {
  return (
    lifecycle.state === 'committed_awaiting_holder_delivery' ||
    lifecycle.state === 'awaiting_server_activation' ||
    lifecycle.state === 'ready_for_parent_visibility' ||
    lifecycle.state === 'active' ||
    lifecycle.state === 'committed_completion_required'
  );
}
