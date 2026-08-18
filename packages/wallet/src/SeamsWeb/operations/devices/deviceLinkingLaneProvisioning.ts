import { buildLinkedDeviceHolderDeliveryAcknowledgementV1 } from '@shared/device-linking';
import { linkedDeviceEnrollmentBindingMatchesSourceV1 } from '@shared/device-linking/contracts';
import { parseLaneHolderDeliveryReceiptV1 } from '@shared/signing-lanes/rotationParsers';
import { parseLaneEnrollmentId, type LaneEnrollmentId } from '@shared/signing-lanes/ids';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceEnrollmentReceiptV1,
  LinkedDeviceHolderDeliveryAcknowledgementV1,
  LinkedDeviceProvisioningChildV1,
  LinkedDeviceProvisioningDeliveriesV1,
  LinkedDeviceSessionState,
} from '@shared/device-linking';
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

function assertApprovalMatchesCommittedDeliveryState(input: {
  readonly approval: LinkedDeviceApprovalV1;
  readonly state: Extract<
    LinkedDeviceSessionState,
    { readonly state: 'committed_completion_required' }
  >;
}): void {
  if (
    input.approval.linkSessionId !== input.state.linkSessionId ||
    input.approval.walletId !== input.state.walletId ||
    input.approval.enrollmentId !== input.state.enrollmentId
  ) {
    throw new Error('refetched linked-device approval does not match committed session state');
  }
}

function parseLaneEnrollmentIdForRecovery(value: string): LaneEnrollmentId {
  const parsed = parseLaneEnrollmentId(value);
  if (parsed.ok) return parsed.value;
  throw new Error(
    `linked-device enrollment id cannot address durable holder records: ${parsed.error.message}`,
  );
}

function protocolVersionForApproval(
  approval: LinkedDeviceApprovalV1,
  keyFamily: LinkedDeviceApprovalV1['orderedKeyBindings'][number]['keyFamily'],
): string {
  const matches = approval.protocolVersions.filter((entry) => entry.keyFamily === keyFamily);
  if (matches.length !== 1 || !matches[0]) {
    throw new Error('linked-device approval has no exact protocol version for its child');
  }
  return matches[0].version;
}

function assertDeliveryMatchesApproval(
  delivery: LinkedDeviceProvisioningChildV1,
  approval: LinkedDeviceApprovalV1,
  index: number,
): void {
  const binding = approval.orderedKeyBindings[index];
  if (!binding) throw new Error('linked-device delivery is missing an approved child');
  const job = delivery.job;
  if (
    String(job.enrollmentId) !== String(approval.enrollmentId) ||
    job.walletId !== approval.walletId ||
    job.walletKeyId !== binding.walletKeyId ||
    job.keyFamily !== binding.keyFamily ||
    job.protocolVersion !== protocolVersionForApproval(approval, binding.keyFamily) ||
    job.source.laneId !== binding.sourceLaneId ||
    job.source.laneShareEpoch !== binding.sourceLaneShareEpoch ||
    job.source.revocationEpoch !== binding.sourceRevocationEpoch ||
    !linkedDeviceEnrollmentBindingMatchesSourceV1(binding, job.source) ||
    job.target.operation !== 'create_lane' ||
    job.target.laneKind !== 'linked_device' ||
    job.target.laneId !== binding.targetLaneId ||
    job.target.laneShareEpoch !== binding.targetLaneShareEpoch ||
    job.authorization.kind !== 'linked_device_enrollment' ||
    String(job.authorization.linkedDeviceEnrollmentId) !== String(approval.enrollmentId) ||
    job.authorization.linkedDevicePermissionDigestB64u !== approval.policyDigestB64u
  ) {
    throw new Error('refetched linked-device delivery differs from its exact approval');
  }
}

function assertDeliveriesMatchApproval(input: {
  readonly deliveries: LinkedDeviceProvisioningDeliveriesV1;
  readonly approval: LinkedDeviceApprovalV1;
  readonly state: Extract<
    LinkedDeviceSessionState,
    { readonly state: 'committed_completion_required' }
  >;
}): void {
  if (
    input.deliveries.linkSessionId !== input.state.linkSessionId ||
    input.deliveries.linkSessionId !== input.approval.linkSessionId ||
    input.deliveries.enrollmentId !== input.state.enrollmentId ||
    input.deliveries.enrollmentId !== input.approval.enrollmentId ||
    input.deliveries.deviceId !== input.approval.deviceId ||
    input.deliveries.orderedChildren.length !== input.approval.orderedKeyBindings.length
  ) {
    throw new Error('refetched linked-device deliveries differ from their exact approval');
  }
  for (let index = 0; index < input.deliveries.orderedChildren.length; index += 1) {
    const delivery = input.deliveries.orderedChildren[index];
    if (!delivery) throw new Error('refetched linked-device deliveries are incomplete');
    assertDeliveryMatchesApproval(delivery, input.approval, index);
  }
}

function recordStoreKey(record: LaneSealedHolderRecordV1): string {
  return JSON.stringify([
    String(record.operationId),
    String(record.enrollmentId),
    String(record.laneId),
    String(record.laneShareEpoch),
    String(record.targetMaterialActivationId),
  ]);
}

function deliveryStoreKey(delivery: LinkedDeviceProvisioningChildV1): string {
  return JSON.stringify([
    String(delivery.job.operationId),
    String(delivery.job.enrollmentId),
    String(delivery.job.target.laneId),
    String(delivery.job.target.laneShareEpoch),
    String(delivery.job.targetMaterialActivationId),
  ]);
}

async function reconcileCommittedDelivery(input: {
  readonly state: Extract<
    LinkedDeviceSessionState,
    { readonly state: 'committed_completion_required' }
  >;
  readonly refetchApprovalV1: () => Promise<LinkedDeviceApprovalV1>;
  readonly refetchProvisioningDeliveriesV1: () => Promise<LinkedDeviceProvisioningDeliveriesV1>;
  readonly acknowledgeHolderDeliveriesV1: (
    acknowledgement: LinkedDeviceHolderDeliveryAcknowledgementV1,
  ) => Promise<LinkedDeviceEnrollmentReceiptV1>;
  readonly repository: LaneSealedHolderMaterialRepositoryV1;
  readonly nowMs: () => number;
}): Promise<LinkedDeviceEnrollmentReceiptV1> {
  const approval = await input.refetchApprovalV1();
  assertApprovalMatchesCommittedDeliveryState({ approval, state: input.state });
  const deliveries = await input.refetchProvisioningDeliveriesV1();
  assertDeliveriesMatchApproval({ deliveries, approval, state: input.state });

  const storedRecords = await input.repository.listForEnrollmentV1({
    enrollmentId: parseLaneEnrollmentIdForRecovery(String(input.state.enrollmentId)),
  });
  const recordsByKey = new Map<string, LaneSealedHolderRecordV1>();
  for (const record of storedRecords) {
    const key = recordStoreKey(record);
    if (recordsByKey.has(key)) {
      throw new Error('duplicate linked-device sealed holder record was persisted');
    }
    recordsByKey.set(key, record);
  }
  if (recordsByKey.size !== deliveries.orderedChildren.length) {
    throw new Error('committed linked-device delivery has incomplete durable holder records');
  }

  const receipts: LaneHolderDeliveryReceiptV1[] = [];
  const deliveryKeys = new Set<string>();
  for (const delivery of deliveries.orderedChildren) {
    const key = deliveryStoreKey(delivery);
    if (deliveryKeys.has(key))
      throw new Error('refetched linked-device deliveries contain a duplicate child');
    deliveryKeys.add(key);
    const enumeratedRecord = recordsByKey.get(key);
    if (!enumeratedRecord) {
      throw new Error('committed linked-device delivery is missing its exact sealed holder record');
    }
    const record = await input.repository.get(lookupForDelivery(delivery));
    if (!record) {
      throw new Error('committed linked-device delivery is missing its exact sealed holder record');
    }
    if (JSON.stringify(record) !== JSON.stringify(enumeratedRecord)) {
      throw new Error('durable linked-device holder record changed during recovery');
    }
    assertRecordMatchesDelivery(record, delivery);
    receipts.push(receiptFromRecord(record));
  }
  for (const key of recordsByKey.keys()) {
    if (!deliveryKeys.has(key)) {
      throw new Error('durable linked-device holder records contain an unapproved child');
    }
  }
  const first = receipts[0];
  if (!first) throw new Error('committed linked-device deliveries are empty');
  return await input.acknowledgeHolderDeliveriesV1(
    buildLinkedDeviceHolderDeliveryAcknowledgementV1({
      linkSessionId: deliveries.linkSessionId,
      enrollmentId: deliveries.enrollmentId,
      deviceId: deliveries.deviceId,
      orderedHolderDeliveryReceipts: [first, ...receipts.slice(1)],
      acknowledgedAtMs: input.nowMs(),
    }),
  );
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
    resumeCommittedDeliveryV1: async (input) =>
      await reconcileCommittedDelivery({
        ...input,
        repository: args.repository,
        nowMs,
      }),
  };
}
