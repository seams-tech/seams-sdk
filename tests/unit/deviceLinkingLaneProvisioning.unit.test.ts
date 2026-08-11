import { expect, test } from '@playwright/test';
import { createDeviceLinkingLaneProvisioningPortV1 } from '@/SeamsWeb/operations/devices/deviceLinkingLaneProvisioning';
import type { DeviceLinkingKeyMaterialPortV1 } from '@/SeamsWeb/operations/devices/deviceLinkingPorts';
import type {
  LaneSealedHolderMaterialRepositoryV1,
  LaneSealedHolderRecordLookupV1,
  LaneSealedHolderRecordV1,
} from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import { parseLinkedDeviceProvisioningDeliveriesV1 } from '../../packages/shared-ts/src/device-linking';
import type { LinkedDeviceHolderDeliveryAcknowledgementV1 } from '../../packages/shared-ts/src/device-linking';
import { parseRotatableSigningLaneJobV1 } from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import {
  buildR102LaneJob,
  buildR102ProtocolCommitReceipt,
} from './helpers/r102LaneGateway.fixtures';

class MemoryHolderRepository implements LaneSealedHolderMaterialRepositoryV1 {
  private record: LaneSealedHolderRecordV1 | null = null;
  failNextPut = false;

  async put(record: LaneSealedHolderRecordV1): Promise<void> {
    if (this.failNextPut) {
      this.failNextPut = false;
      throw new Error('test persistence failure');
    }
    this.record = record;
  }

  async get(_input: LaneSealedHolderRecordLookupV1): Promise<LaneSealedHolderRecordV1 | null> {
    return this.record;
  }

  async delete(_input: LaneSealedHolderRecordLookupV1): Promise<void> {
    this.record = null;
  }
}

test('seals exact linked-device deliveries once and replays the durable holder receipt', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const sourceJob = buildR102LaneJob('device-linking-provisioning');
  const job = parseRotatableSigningLaneJobV1({
    ...sourceJob,
    enrollmentId: String(fixture.approval.enrollmentId),
    walletId: String(fixture.approval.walletId),
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
    async resumeCommittedDeliveryV1() {
      return fixture.receipt;
    },
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
