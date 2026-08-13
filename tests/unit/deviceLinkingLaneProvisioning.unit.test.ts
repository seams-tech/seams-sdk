import { expect, test } from '@playwright/test';
import { createDeviceLinkingLaneProvisioningPortV1 } from '@/SeamsWeb/operations/devices/deviceLinkingLaneProvisioning';
import type { DeviceLinkingKeyMaterialPortV1 } from '@/SeamsWeb/operations/devices/deviceLinkingPorts';
import type {
  LaneSealedHolderMaterialRepositoryV1,
  LaneSealedHolderRecordLookupV1,
  LaneSealedHolderRecordV1,
} from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import { parseLinkedDeviceProvisioningDeliveriesV1 } from '../../packages/shared-ts/src/device-linking';
import { buildCommittedCompletionRequiredLinkedDeviceSessionState } from '../../packages/shared-ts/src/device-linking';
import type {
  LinkedDeviceHolderDeliveryAcknowledgementV1,
  LinkedDeviceProvisioningDeliveriesV1,
} from '../../packages/shared-ts/src/device-linking';
import {
  buildLaneEnrollmentManifestV1,
  parseRotatableSigningLaneJobV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import {
  buildR102LaneJob,
  buildR102ManifestChild,
  buildR102ProtocolCommitReceipt,
} from './helpers/r102LaneGateway.fixtures';

function manifestForJob(job: ReturnType<typeof buildR102LaneJob>) {
  return buildLaneEnrollmentManifestV1({
    enrollmentId: job.enrollmentId,
    walletId: job.walletId,
    authorization: job.authorization,
    orderedChildren: [buildR102ManifestChild(job)],
    createdAtMs: 1_000,
    expiresAtMs: job.expiresAtMs,
  });
}

class MemoryHolderRepository implements LaneSealedHolderMaterialRepositoryV1 {
  private readonly records = new Map<string, LaneSealedHolderRecordV1>();
  failNextPut = false;

  async put(record: LaneSealedHolderRecordV1): Promise<void> {
    if (this.failNextPut) {
      this.failNextPut = false;
      throw new Error('test persistence failure');
    }
    this.records.set(String(record.operationId), record);
  }

  async get(input: LaneSealedHolderRecordLookupV1): Promise<LaneSealedHolderRecordV1 | null> {
    return (
      [...this.records.values()].find(
        (record) =>
          String(record.operationId) === String(input.operationId) &&
          String(record.enrollmentId) === String(input.enrollmentId) &&
          String(record.laneId) === String(input.targetLaneId) &&
          String(record.laneShareEpoch) === String(input.targetLaneShareEpoch) &&
          String(record.targetMaterialActivationId) === String(input.targetMaterialActivationId),
      ) ?? null
    );
  }

  async listForEnrollmentV1(input: {
    readonly enrollmentId: LaneSealedHolderRecordV1['enrollmentId'];
  }): Promise<readonly LaneSealedHolderRecordV1[]> {
    return [...this.records.values()].filter(
      (record) => String(record.enrollmentId) === String(input.enrollmentId),
    );
  }

  async delete(input: LaneSealedHolderRecordLookupV1): Promise<void> {
    const record = await this.get(input);
    if (record) this.records.delete(String(record.operationId));
  }
}

test('seals exact linked-device deliveries once and replays the durable holder receipt', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const binding = fixture.approval.orderedKeyBindings[0];
  if (!binding) throw new Error('fixture is missing its approved child');
  const sourceJob = buildR102LaneJob('device-linking-provisioning');
  const job = parseRotatableSigningLaneJobV1({
    ...sourceJob,
    enrollmentId: String(fixture.approval.enrollmentId),
    walletId: String(fixture.approval.walletId),
    walletKeyId: String(binding.walletKeyId),
    source: {
      ...sourceJob.source,
      laneId: String(binding.sourceLaneId),
      laneShareEpoch: String(binding.sourceLaneShareEpoch),
      revocationEpoch: binding.sourceRevocationEpoch,
      holderParticipantId: String(binding.sourceHolderParticipantId),
      signingWorkerParticipantId: String(binding.sourceSigningWorkerParticipantId),
    },
    target: {
      ...sourceJob.target,
      laneId: String(binding.targetLaneId),
      laneShareEpoch: String(binding.targetLaneShareEpoch),
    },
    authorization: {
      kind: 'linked_device_enrollment',
      authorizedOperationId: String(sourceJob.authorization.authorizedOperationId),
      linkedDeviceEnrollmentId: String(fixture.approval.enrollmentId),
      linkedDevicePermissionDigestB64u: fixture.approval.policyDigestB64u,
    },
  });
  const protocolCommitReceipt = buildR102ProtocolCommitReceipt(job);
  const deliveries = parseLinkedDeviceProvisioningDeliveriesV1({
    kind: 'linked_device_provisioning_deliveries_v1',
    linkSessionId: fixture.payload.linkSessionId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    manifest: manifestForJob(job),
    orderedChildren: [
      {
        kind: 'linked_device_provisioning_child_v1',
        job,
        protocolCommitReceipt,
        holderPackage: {
          kind: 'ed25519_yao_lane_holder_package_set_v1',
          deriverAEncryptedPackageJson: '{}',
          deriverBEncryptedPackageJson: '{}',
        },
        expectedVersion: 0,
      },
    ],
  });
  let sealCalls = 0;
  const worker: DeviceLinkingKeyMaterialPortV1 = {
    async createBootstrapKeyMaterialV1() {
      throw new Error('bootstrap is outside this test');
    },
    async prepareTargetHolderRegistrationsV1() {
      throw new Error('target preparation is outside this test');
    },
    async openAndSealTargetHolderDeliveryV1() {
      sealCalls += 1;
      return {
        sealedHolderMaterialB64u: base64UrlEncode(new Uint8Array([1, 2, 3])),
        sealedHolderRecordDigestB64u: base64UrlEncode(new Uint8Array(32).fill(7)),
        verifiedHolderCiphertextDigestSetB64u:
          protocolCommitReceipt.targetHolderCiphertextDigestSetB64u,
      };
    },
    async discardKeyMaterialV1() {},
    async signDeviceSessionRequestV1() {
      throw new Error('request signing is outside this test');
    },
  };
  const repository = new MemoryHolderRepository();
  const port = createDeviceLinkingLaneProvisioningPortV1({
    worker,
    repository,
    nowMs: () => 5_000,
  });
  let holderReceiptCount = 0;
  const handoff = {
    kind: 'linked_device_lane_provisioning_handoff_v1' as const,
    approval: fixture.approval,
    deliveries,
    keyMaterial: {
      kind: 'device_linking_key_material_handle_v1' as const,
      handleId: 'device-linking-handle-1',
    },
    async acknowledgeHolderDeliveriesV1(
      acknowledgement: LinkedDeviceHolderDeliveryAcknowledgementV1,
    ) {
      holderReceiptCount = acknowledgement.orderedHolderDeliveryReceipts.length;
      return fixture.receipt;
    },
  };
  repository.failNextPut = true;
  await expect(port.prepareLinkedDeviceLanesV1(handoff)).rejects.toThrow(
    'test persistence failure',
  );
  await expect(port.prepareLinkedDeviceLanesV1(handoff)).resolves.toEqual(fixture.receipt);
  await expect(port.prepareLinkedDeviceLanesV1(handoff)).resolves.toEqual(fixture.receipt);
  expect(sealCalls).toBe(2);
  expect(holderReceiptCount).toBe(1);
});

test('reconciles committed delivery from refetched children and durable records idempotently', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const binding = fixture.approval.orderedKeyBindings[0];
  if (!binding) throw new Error('fixture is missing its approved child');
  const sourceJob = buildR102LaneJob('device-linking-recovery');
  const job = parseRotatableSigningLaneJobV1({
    ...sourceJob,
    enrollmentId: String(fixture.approval.enrollmentId),
    walletId: String(fixture.approval.walletId),
    walletKeyId: String(binding.walletKeyId),
    source: {
      ...sourceJob.source,
      laneId: String(binding.sourceLaneId),
      laneShareEpoch: String(binding.sourceLaneShareEpoch),
      revocationEpoch: binding.sourceRevocationEpoch,
      holderParticipantId: String(binding.sourceHolderParticipantId),
      signingWorkerParticipantId: String(binding.sourceSigningWorkerParticipantId),
    },
    target: {
      ...sourceJob.target,
      laneId: String(binding.targetLaneId),
      laneShareEpoch: String(binding.targetLaneShareEpoch),
    },
    authorization: {
      kind: 'linked_device_enrollment',
      authorizedOperationId: String(sourceJob.authorization.authorizedOperationId),
      linkedDeviceEnrollmentId: String(fixture.approval.enrollmentId),
      linkedDevicePermissionDigestB64u: fixture.approval.policyDigestB64u,
    },
  });
  const protocolCommitReceipt = buildR102ProtocolCommitReceipt(job);
  const deliveries = parseLinkedDeviceProvisioningDeliveriesV1({
    kind: 'linked_device_provisioning_deliveries_v1',
    linkSessionId: fixture.payload.linkSessionId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    manifest: manifestForJob(job),
    orderedChildren: [
      {
        kind: 'linked_device_provisioning_child_v1',
        job,
        protocolCommitReceipt,
        holderPackage: {
          kind: 'ed25519_yao_lane_holder_package_set_v1',
          deriverAEncryptedPackageJson: '{}',
          deriverBEncryptedPackageJson: '{}',
        },
        expectedVersion: 0,
      },
    ],
  });
  const repository = new MemoryHolderRepository();
  const worker: DeviceLinkingKeyMaterialPortV1 = {
    async createBootstrapKeyMaterialV1() {
      throw new Error('bootstrap is outside this test');
    },
    async prepareTargetHolderRegistrationsV1() {
      throw new Error('target preparation is outside this test');
    },
    async openAndSealTargetHolderDeliveryV1() {
      return {
        sealedHolderMaterialB64u: base64UrlEncode(new Uint8Array([1, 2, 3])),
        sealedHolderRecordDigestB64u: base64UrlEncode(new Uint8Array(32).fill(7)),
        verifiedHolderCiphertextDigestSetB64u:
          protocolCommitReceipt.targetHolderCiphertextDigestSetB64u,
      };
    },
    async discardKeyMaterialV1() {},
    async signDeviceSessionRequestV1() {
      throw new Error('request signing is outside this test');
    },
  };
  const port = createDeviceLinkingLaneProvisioningPortV1({
    worker,
    repository,
    nowMs: () => 6_000,
  });
  await port.prepareLinkedDeviceLanesV1({
    kind: 'linked_device_lane_provisioning_handoff_v1',
    approval: fixture.approval,
    deliveries,
    keyMaterial: {
      kind: 'device_linking_key_material_handle_v1',
      handleId: 'device-linking-recovery-handle',
    },
    async acknowledgeHolderDeliveriesV1() {
      return fixture.receipt;
    },
  });

  const state = buildCommittedCompletionRequiredLinkedDeviceSessionState({
    linkSessionId: fixture.approval.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    keyManifestDigestB64u: fixture.receipt.manifestDigestB64u,
    transcriptSetDigestB64u: fixture.receipt.manifestDigestB64u,
  });
  const acknowledgements: LinkedDeviceHolderDeliveryAcknowledgementV1[] = [];
  const recover = () =>
    port.resumeCommittedDeliveryV1({
      state,
      refetchApprovalV1: async () => fixture.approval,
      refetchProvisioningDeliveriesV1: async () => deliveries,
      acknowledgeHolderDeliveriesV1: async (acknowledgement) => {
        acknowledgements.push(acknowledgement);
        return fixture.receipt;
      },
    });

  await expect(recover()).resolves.toEqual(fixture.receipt);
  await expect(recover()).resolves.toEqual(fixture.receipt);
  expect(acknowledgements).toHaveLength(2);
  expect(acknowledgements[0]?.orderedHolderDeliveryReceipts).toHaveLength(1);
});

test('refuses committed recovery when a durable child is missing or substituted', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const binding = fixture.approval.orderedKeyBindings[0];
  if (!binding) throw new Error('fixture is missing its approved child');
  const sourceJob = buildR102LaneJob('device-linking-recovery-mismatch');
  const job = parseRotatableSigningLaneJobV1({
    ...sourceJob,
    enrollmentId: String(fixture.approval.enrollmentId),
    walletId: String(fixture.approval.walletId),
    walletKeyId: String(binding.walletKeyId),
    source: {
      ...sourceJob.source,
      laneId: String(binding.sourceLaneId),
      laneShareEpoch: String(binding.sourceLaneShareEpoch),
      revocationEpoch: binding.sourceRevocationEpoch,
      holderParticipantId: String(binding.sourceHolderParticipantId),
      signingWorkerParticipantId: String(binding.sourceSigningWorkerParticipantId),
    },
    target: {
      ...sourceJob.target,
      laneId: String(binding.targetLaneId),
      laneShareEpoch: String(binding.targetLaneShareEpoch),
    },
    authorization: {
      kind: 'linked_device_enrollment',
      authorizedOperationId: String(sourceJob.authorization.authorizedOperationId),
      linkedDeviceEnrollmentId: String(fixture.approval.enrollmentId),
      linkedDevicePermissionDigestB64u: fixture.approval.policyDigestB64u,
    },
  });
  const protocolCommitReceipt = buildR102ProtocolCommitReceipt(job);
  const deliveries: LinkedDeviceProvisioningDeliveriesV1 =
    parseLinkedDeviceProvisioningDeliveriesV1({
      kind: 'linked_device_provisioning_deliveries_v1',
      linkSessionId: fixture.payload.linkSessionId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
      manifest: manifestForJob(job),
      orderedChildren: [
        {
          kind: 'linked_device_provisioning_child_v1',
          job,
          protocolCommitReceipt,
          holderPackage: {
            kind: 'ed25519_yao_lane_holder_package_set_v1',
            deriverAEncryptedPackageJson: '{}',
            deriverBEncryptedPackageJson: '{}',
          },
          expectedVersion: 0,
        },
      ],
    });
  const worker: DeviceLinkingKeyMaterialPortV1 = {
    async createBootstrapKeyMaterialV1() {
      throw new Error('bootstrap is outside this test');
    },
    async prepareTargetHolderRegistrationsV1() {
      throw new Error('target preparation is outside this test');
    },
    async openAndSealTargetHolderDeliveryV1() {
      throw new Error('missing durable record must fail before sealing');
    },
    async discardKeyMaterialV1() {},
    async signDeviceSessionRequestV1() {
      throw new Error('request signing is outside this test');
    },
  };
  const port = createDeviceLinkingLaneProvisioningPortV1({
    worker,
    repository: new MemoryHolderRepository(),
    nowMs: () => 6_000,
  });
  const state = buildCommittedCompletionRequiredLinkedDeviceSessionState({
    linkSessionId: fixture.approval.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    keyManifestDigestB64u: fixture.receipt.manifestDigestB64u,
    transcriptSetDigestB64u: fixture.receipt.manifestDigestB64u,
  });
  await expect(
    port.resumeCommittedDeliveryV1({
      state,
      refetchApprovalV1: async () => fixture.approval,
      refetchProvisioningDeliveriesV1: async () => deliveries,
      acknowledgeHolderDeliveriesV1: async () => fixture.receipt,
    }),
  ).rejects.toThrow('incomplete durable holder records');
});
