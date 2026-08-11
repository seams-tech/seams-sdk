import { expect, test } from '@playwright/test';
import {
  buildActiveLinkedDeviceExecutionBundleV1,
  buildLinkedDeviceProvisionedExecutionEvidenceV1,
} from '../../packages/sdk-web/src/SeamsWeb/operations/devices/linkedDeviceExecutionBundle';
import { buildR103ActiveExecutionFixture } from './helpers/deviceLinkContracts.fixtures';

test('builds one exact active Device 2 execution projection from R102 evidence', async () => {
  const {
    deviceLink: fixture,
    targetCredential: target,
    provisioning,
    walletSession,
  } = await buildR103ActiveExecutionFixture();

  const bundle = await buildActiveLinkedDeviceExecutionBundleV1({
    approval: fixture.approval,
    targetPreparation: target.preparation,
    targetCredentialRegistration: target.registration,
    provisioningDeliveries: provisioning.deliveries,
    enrollmentReceipt: fixture.receipt,
    walletSessionDelivery: walletSession,
  });

  expect(bundle).toMatchObject({
    kind: 'active_linked_device_execution_bundle_v1',
    linkSessionId: fixture.approval.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    targetPreparation: target.preparation,
    targetCredentialRegistration: target.registration,
    manifest: provisioning.deliveries.manifest,
    keyManifestDigestB64u: fixture.receipt.manifestDigestB64u,
    aggregateReceiptDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
  });
  expect(bundle.orderedExecutions).toHaveLength(1);
  expect(bundle.orderedExecutions[0]).toMatchObject({
    kind: 'active_linked_device_ed25519_execution_v1',
    keyFamily: 'ed25519',
    walletKeyId: fixture.approval.orderedKeyBindings[0].walletKeyId,
    laneId: fixture.approval.orderedKeyBindings[0].targetLaneId,
    laneShareEpoch: fixture.approval.orderedKeyBindings[0].targetLaneShareEpoch,
    walletKey: { lifecycle: { state: 'active' } },
    lane: {
      laneKind: 'linked_device',
      linkedDeviceId: fixture.approval.deviceId,
      lifecycle: { state: 'active' },
    },
  });
});

test('rejects an enrollment receipt that is bound to a different R102 manifest', async () => {
  const {
    deviceLink: fixture,
    targetCredential: target,
    provisioning,
    walletSession,
  } = await buildR103ActiveExecutionFixture();

  await expect(
    buildActiveLinkedDeviceExecutionBundleV1({
      approval: fixture.approval,
      targetPreparation: target.preparation,
      targetCredentialRegistration: target.registration,
      provisioningDeliveries: provisioning.deliveries,
      enrollmentReceipt: {
        ...fixture.receipt,
        manifestDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      },
      walletSessionDelivery: walletSession,
    }),
  ).rejects.toThrow('linked-device R102 manifest digest does not match enrollment receipt');
});

test('rejects a provisioned job with a different approved replay identity', async () => {
  const {
    deviceLink: fixture,
    targetCredential: target,
    provisioning,
  } = await buildR103ActiveExecutionFixture();
  const child = provisioning.deliveries.orderedChildren[0];

  await expect(
    buildLinkedDeviceProvisionedExecutionEvidenceV1({
      approval: fixture.approval,
      targetPreparation: target.preparation,
      targetCredentialRegistration: target.registration,
      provisioningDeliveries: {
        ...provisioning.deliveries,
        orderedChildren: [
          {
            ...child,
            job: {
              ...child.job,
              idempotencyKey: 'idempotency:r103:substituted',
            },
          },
        ],
      },
      enrollmentReceipt: fixture.receipt,
    }),
  ).rejects.toThrow('linked-device provisioned execution child identity does not match');
});
