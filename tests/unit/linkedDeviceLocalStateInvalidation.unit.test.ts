import { expect, test } from '@playwright/test';
import { buildLinkedDeviceRevokeResultV1 } from '@shared/device-linking';
import { buildLinkedDeviceProvisionedExecutionEvidenceV1 } from '../../packages/sdk-web/src/core/signingEngine/session/lanes/linkedDeviceExecutionBundle';
import { createLinkedDeviceLocalStateInvalidationPortV1 } from '../../packages/sdk-web/src/SeamsWeb/operations/devices/linkedDeviceLocalStateInvalidation';
import { buildR103ActiveExecutionFixture } from './helpers/deviceLinkContracts.fixtures';
import { buildR103SealedHolderRecord } from './helpers/r102LaneGateway.fixtures';

test('clears exact linked-device browser state after durable revocation', async () => {
  const fixture = await buildR103ActiveExecutionFixture();
  const evidence = await buildLinkedDeviceProvisionedExecutionEvidenceV1({
    approval: fixture.deviceLink.approval,
    targetPreparation: fixture.targetCredential.preparation,
    targetCredentialRegistration: fixture.targetCredential.registration,
    provisioningDeliveries: fixture.provisioning.deliveries,
    enrollmentReceipt: fixture.deviceLink.receipt,
  });
  const child = fixture.provisioning.deliveries.orderedChildren[0];
  if (!child) throw new Error('R103 fixture has no provisioning child');
  const holderRecord = buildR103SealedHolderRecord(child.job, child.protocolCommitReceipt);
  const cleared: string[] = [];
  const invalidation = createLinkedDeviceLocalStateInvalidationPortV1({
    holderRepository: {
      listForEnrollmentV1: async () => [holderRecord],
      delete: async () => cleared.push('holder'),
    },
    walletSessionRepository: {
      readActiveForEnrollmentV1: async () => ({
        kind: 'found',
        delivery: fixture.walletSession,
      }),
      clearEnrollmentV1: async () => {
        cleared.push('wallet_session');
      },
    },
    executionEvidenceRepository: {
      readForEnrollmentV1: async () => ({ kind: 'found', evidence }),
      clearEnrollmentV1: async () => {
        cleared.push('evidence');
      },
    },
  });
  const result = buildLinkedDeviceRevokeResultV1({
    kind: 'revoked',
    enrollmentId: fixture.deviceLink.approval.enrollmentId,
    revocationEpoch: 1,
    aggregateReceiptDigestB64u: fixture.deviceLink.receipt.aggregateReceiptDigestB64u,
  });

  await invalidation.invalidateLinkedDeviceStateV1({
    walletId: fixture.deviceLink.approval.walletId,
    deviceId: fixture.deviceLink.approval.deviceId,
    requestedAtMs: fixture.walletSession.issuedAtMs,
    result,
  });

  expect(cleared).toEqual(['holder', 'wallet_session', 'evidence']);
});
