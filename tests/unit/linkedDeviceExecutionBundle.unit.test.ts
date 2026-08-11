import { expect, test } from '@playwright/test';
import { buildActiveLinkedDeviceExecutionBundleV1 } from '../../packages/sdk-web/src/SeamsWeb/operations/devices/linkedDeviceExecutionBundle';
import {
  buildR103DeviceLinkFixture,
  buildR103LinkedWalletSessionDeliveryFixture,
  buildR103ProvisioningFixture,
  buildR103TargetCredentialFixture,
} from './helpers/deviceLinkContracts.fixtures';

test('builds one exact active Device 2 execution projection from R102 evidence', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const target = await buildR103TargetCredentialFixture(fixture);
  const provisioning = buildR103ProvisioningFixture(fixture);
  const walletSession = buildR103LinkedWalletSessionDeliveryFixture(fixture);

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
    rpId: target.preparation.rpId,
    credentialIdB64u: target.registration.webauthnRegistration.credentialIdB64u,
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

test('rejects a Wallet Session that is bound to a different active manifest', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const target = await buildR103TargetCredentialFixture(fixture);
  const provisioning = buildR103ProvisioningFixture(fixture);
  const walletSession = buildR103LinkedWalletSessionDeliveryFixture(fixture);

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
  ).rejects.toThrow('linked-device active execution identity does not match');
});
