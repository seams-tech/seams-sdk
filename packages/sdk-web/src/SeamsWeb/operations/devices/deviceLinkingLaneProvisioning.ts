import { buildLinkedDeviceHolderDeliveryAcknowledgementV1 } from '@shared/device-linking';
import { parseLaneHolderDeliveryReceiptV1 } from '@shared/signing-lanes/rotationParsers';
import type { LinkedDeviceProvisioningChildV1 } from '@shared/device-linking';
import type { LaneHolderDeliveryReceiptV1 } from '@shared/signing-lanes/rotation';
import type {
  LaneSealedHolderMaterialRepositoryV1,
  LaneSealedHolderRecordV1,
} from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import type {
  DeviceLinkingKeyMaterialPortV1,
  DeviceLinkingLaneProvisioningPortV1,
} from './deviceLinkingPorts';

function lookupForDelivery(delivery: LinkedDeviceProvisioningChildV1) {
  return {
    operationId: delivery.job.operationId,
    enrollmentId: delivery.job.enrollmentId,
    targetLaneId: delivery.job.target.laneId,
    targetLaneShareEpoch: delivery.job.target.laneShareEpoch,
    targetMaterialActivationId: delivery.job.targetMaterialActivationId,
  };
}

function receiptFromRecord(record: LaneSealedHolderRecordV1): LaneHolderDeliveryReceiptV1 {
  return parseLaneHolderDeliveryReceiptV1({
    kind: 'lane_holder_delivery_receipt_v1',
    operationId: record.operationId,
    enrollmentId: record.enrollmentId,
    targetLaneId: record.laneId,
    targetLaneShareEpoch: record.laneShareEpoch,
    targetMaterialActivationId: record.targetMaterialActivationId,
    holderParticipantBindingDigestB64u: record.holderParticipantBindingDigestB64u,
    holderRecipientKeyDigestB64u: record.holderRecipientKeyDigestB64u,
    holderCiphertextDigestSetB64u: record.holderCiphertextDigestSetB64u,
    sealedHolderRecordDigestB64u: record.sealedHolderRecordDigestB64u,
    transcriptHashB64u: record.transcriptHashB64u,
    acknowledgedAtMs: record.acknowledgedAtMs,
  });
}

function assertRecordMatchesDelivery(
  record: LaneSealedHolderRecordV1,
  delivery: LinkedDeviceProvisioningChildV1,
): void {
  const job = delivery.job;
  const commit = delivery.protocolCommitReceipt;
  if (
    record.operationId !== job.operationId ||
    record.enrollmentId !== job.enrollmentId ||
    record.walletId !== job.walletId ||
    record.walletKeyId !== job.walletKeyId ||
    record.laneId !== job.target.laneId ||
    record.laneShareEpoch !== job.target.laneShareEpoch ||
    record.targetMaterialActivationId !== job.targetMaterialActivationId ||
    record.holderParticipantBindingDigestB64u !== job.targetHolder.participantBindingDigestB64u ||
    record.custodyBindingId !== job.targetHolder.custodyBindingId ||
    record.holderRecipientKeyDigestB64u !== job.targetHolder.hpkePublicKeyDigestB64u ||
    record.holderCiphertextDigestSetB64u !== commit.targetHolderCiphertextDigestSetB64u ||
    record.transcriptHashB64u !== commit.transcriptHashB64u
  ) {
    throw new Error('stored linked-device holder material does not match its exact delivery');
  }
}

async function sealDelivery(input: {
  readonly delivery: LinkedDeviceProvisioningChildV1;
  readonly keyMaterial: Parameters<
    DeviceLinkingKeyMaterialPortV1['openAndSealTargetHolderDeliveryV1']
  >[0]['handle'];
  readonly worker: DeviceLinkingKeyMaterialPortV1;
  readonly repository: LaneSealedHolderMaterialRepositoryV1;
  readonly nowMs: () => number;
}): Promise<LaneHolderDeliveryReceiptV1> {
  const existing = await input.repository.get(lookupForDelivery(input.delivery));
  if (existing) {
    assertRecordMatchesDelivery(existing, input.delivery);
    return receiptFromRecord(existing);
  }
  const sealed = await input.worker.openAndSealTargetHolderDeliveryV1({
    handle: input.keyMaterial,
    delivery: input.delivery,
  });
  const job = input.delivery.job;
  const commit = input.delivery.protocolCommitReceipt;
  const acknowledgedAtMs = input.nowMs();
  if (!Number.isSafeInteger(acknowledgedAtMs) || acknowledgedAtMs < 0) {
    throw new Error('linked-device holder acknowledgement time is invalid');
  }
  const record: LaneSealedHolderRecordV1 = {
    kind: 'lane_sealed_holder_record_v1',
    operationId: job.operationId,
    enrollmentId: job.enrollmentId,
    walletId: job.walletId,
    walletKeyId: job.walletKeyId,
    laneId: job.target.laneId,
    laneShareEpoch: job.target.laneShareEpoch,
    targetMaterialActivationId: job.targetMaterialActivationId,
    holderParticipantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
    custodyBindingId: job.targetHolder.custodyBindingId,
    holderRecipientKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
    holderCiphertextDigestSetB64u: sealed.verifiedHolderCiphertextDigestSetB64u,
    sealedHolderRecordDigestB64u: sealed.sealedHolderRecordDigestB64u,
    transcriptHashB64u: commit.transcriptHashB64u,
    sealedHolderMaterialB64u: sealed.sealedHolderMaterialB64u,
    acknowledgedAtMs,
    storedAtMs: acknowledgedAtMs,
  };
  assertRecordMatchesDelivery(record, input.delivery);
  await input.repository.put(record);
  return receiptFromRecord(record);
}

export function createDeviceLinkingLaneProvisioningPortV1(args: {
  readonly worker: DeviceLinkingKeyMaterialPortV1;
  readonly repository: LaneSealedHolderMaterialRepositoryV1;
  readonly resumeCommittedDeliveryV1: DeviceLinkingLaneProvisioningPortV1['resumeCommittedDeliveryV1'];
  readonly nowMs?: () => number;
}): DeviceLinkingLaneProvisioningPortV1 {
  const nowMs = args.nowMs ?? Date.now;
  return {
    async prepareLinkedDeviceLanesV1(input) {
      if (
        input.approval.linkSessionId !== input.deliveries.linkSessionId ||
        input.approval.enrollmentId !== input.deliveries.enrollmentId ||
        input.approval.deviceId !== input.deliveries.deviceId
      ) {
        throw new Error('linked-device deliveries do not match their owner approval');
      }
      const receipts: LaneHolderDeliveryReceiptV1[] = [];
      for (const delivery of input.deliveries.orderedChildren) {
        receipts.push(
          await sealDelivery({
            delivery,
            keyMaterial: input.keyMaterial,
            worker: args.worker,
            repository: args.repository,
            nowMs,
          }),
        );
      }
      const first = receipts[0];
      if (!first) throw new Error('linked-device deliveries are empty');
      return await input.acknowledgeHolderDeliveriesV1(
        buildLinkedDeviceHolderDeliveryAcknowledgementV1({
          linkSessionId: input.deliveries.linkSessionId,
          enrollmentId: input.deliveries.enrollmentId,
          deviceId: input.deliveries.deviceId,
          orderedHolderDeliveryReceipts: [first, ...receipts.slice(1)],
          acknowledgedAtMs: nowMs(),
        }),
      );
    },
    resumeCommittedDeliveryV1: args.resumeCommittedDeliveryV1,
  };
}
