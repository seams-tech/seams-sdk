import { expect, test } from '@playwright/test';
import {
  buildActiveLinkedDeviceExecutionBundleV1,
  buildLinkedDeviceProvisionedExecutionEvidenceV1,
} from '../../packages/wallet/src/core/signingEngine/session/lanes/linkedDeviceExecutionBundle';
import { base64UrlDecode, base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
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

test('keeps the enrollment fence separate from each child lane epoch', async () => {
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
    // A parent revocation fence can advance independently of this child lane.
    walletSessionDelivery: { ...walletSession, revocationEpoch: 7 },
  });

  expect(bundle.revocationEpoch).toBe(7);
  expect(bundle.orderedExecutions[0]?.lane.lifecycle.revocationEpoch).toBe(
    walletSession.orderedTokens[0]?.revocationEpoch,
  );
  expect(bundle.orderedExecutions[0]?.lane.lifecycle.revocationEpoch).not.toBe(
    bundle.revocationEpoch,
  );
});

test('rejects using the enrollment fence as a child token epoch', async () => {
  const {
    deviceLink: fixture,
    targetCredential: target,
    provisioning,
    walletSession,
  } = await buildR103ActiveExecutionFixture();
  const token = walletSession.orderedTokens[0];
  if (!token) throw new Error('R103 wallet session fixture has no child token');
  const childFenceEpoch = 7;

  await expect(
    buildActiveLinkedDeviceExecutionBundleV1({
      approval: fixture.approval,
      targetPreparation: target.preparation,
      targetCredentialRegistration: target.registration,
      provisioningDeliveries: provisioning.deliveries,
      enrollmentReceipt: fixture.receipt,
      walletSessionDelivery: {
        ...walletSession,
        revocationEpoch: childFenceEpoch,
        orderedTokens: [
          {
            ...token,
            revocationEpoch: childFenceEpoch,
            walletSessionJwt: rewriteJwtRevocationEpoch(
              token.walletSessionJwt,
              childFenceEpoch,
            ),
          },
        ],
      },
    }),
  ).rejects.toThrow('active execution authorization does not match child');
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

function rewriteJwtRevocationEpoch(jwt: string, revocationEpoch: number): string {
  const segments = jwt.split('.');
  if (segments.length !== 3) throw new Error('R103 fixture JWT is malformed');
  const claims = JSON.parse(new TextDecoder().decode(base64UrlDecode(segments[1]))) as Record<
    string,
    unknown
  >;
  return `${segments[0]}.${base64UrlEncode(
    new TextEncoder().encode(JSON.stringify({ ...claims, revocationEpoch })),
  )}.${segments[2]}`;
}
