import { expect, test } from '@playwright/test';
import {
  buildActiveLinkedDeviceSessionState,
  buildAwaitingTargetPasskeyLinkedDeviceSessionState,
  buildLinkedDeviceSessionClaimV1,
  buildProvisioningLinkedDeviceSessionState,
  buildQrLinkedDeviceSessionPayloadV4,
} from '../../packages/shared-ts/src/device-linking';
import type {
  Device1LinkingFlowPortsV1,
  LinkSessionAuthenticationV1,
} from '../../packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingPorts';
import { scanAndLinkDevice } from '../../packages/wallet/src/SeamsWeb/operations/devices/scanDevice';
import {
  buildR103DeviceLinkFixture,
  buildR103OwnerEnrollmentCeremonyV1,
} from './helpers/deviceLinkContracts.fixtures';
import {
  buildLinkedDeviceCustodyTransferPackageFixtureV1,
  buildLinkedDeviceCustodyTransferRecipientFixtureV1,
  buildUnlockedCustodyCapabilityFixtureV1,
} from './helpers/linkedDeviceCustodyTransfer.fixtures';

test('seals once and replays the exact package after a lost first submission', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const now = Date.now();
  const payload = buildQrLinkedDeviceSessionPayloadV4({
    ...fixture.payload,
    issuedAtMs: now - 1_000,
    expiresAtMs: now + 60_000,
  });
  const authentication: LinkSessionAuthenticationV1 = {
    kind: 'link_session_authenticated_request_v1',
    source: fixture.approval.ownerAuthorization,
    proofDigestB64u: fixture.approval.policyDigestB64u,
  };
  const pendingState = buildAwaitingTargetPasskeyLinkedDeviceSessionState({
    linkSessionId: fixture.approval.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    credentialDeadlineMs: now + 30_000,
  });
  const activeState = buildActiveLinkedDeviceSessionState({
    linkSessionId: fixture.approval.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    activatedAtMs: now,
  });
  const claim = buildLinkedDeviceSessionClaimV1({
    linkSessionId: fixture.approval.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    devicePublicKeyB64u: payload.devicePublicKeyB64u,
    claimedAtMs: now,
    claimExpiresAtMs: now + 30_000,
  });
  const recipient = buildLinkedDeviceCustodyTransferRecipientFixtureV1({
    linkSessionId: String(fixture.approval.linkSessionId),
    walletId: String(fixture.approval.walletId),
    enrollmentId: String(fixture.approval.enrollmentId),
    deviceId: String(fixture.approval.deviceId),
  });
  const sealedPackage = buildLinkedDeviceCustodyTransferPackageFixtureV1({
    walletId: String(fixture.approval.walletId),
    enrollmentId: String(fixture.approval.enrollmentId),
    deviceId: String(fixture.approval.deviceId),
    recipientPublicKeyB64u: String(recipient.recipientPublicKeyB64u),
  });
  const submissions: Array<
    Parameters<
      Device1LinkingFlowPortsV1['transport']['submitCustodyTransferPackageV1']
    >[0]['submission']
  > = [];
  const workOrder: string[] = [];
  let sealCalls = 0;
  let submitAttempts = 0;
  const ports: Device1LinkingFlowPortsV1 = {
    ownerAuthorization: {
      authenticateOwnerForLinkingV1: async () => ({
        authentication,
        walletId: fixture.approval.walletId,
        ownerAuthorization: fixture.approval.ownerAuthorization,
        policyDigestB64u: fixture.approval.policyDigestB64u,
        operationId: fixture.approval.operationId,
        idempotencyKey: fixture.approval.idempotencyKey,
        orderedKeyBindings: fixture.approval.orderedKeyBindings,
        protocolVersions: fixture.approval.protocolVersions,
        expiresAtMs: now + 30_000,
        custodyTransferCapability: buildUnlockedCustodyCapabilityFixtureV1({
          walletId: String(fixture.approval.walletId),
          expiresAtMs: now + 30_000,
        }),
      }),
      startOwnerEnrollmentCeremonyV1: async () => ({
        ceremony: buildR103OwnerEnrollmentCeremonyV1({ expiresAtMs: now + 30_000 }),
      }),
    },
    transport: {
      claimSessionV1: async () => claim,
      recordOwnerApprovalV1: async () => ({ outcome: 'pending', state: pendingState }),
      getApprovalV1: async () => ({ outcome: 'pending', state: pendingState }),
      getTargetReadyV1: async () => {
        workOrder.push('source-handoff');
        return null;
      },
      submitPreparedProvisioningDeliveriesV1: async () => {
        throw new Error('source handoff is not part of this test');
      },
      getCustodyTransferRecipientV1: async () => {
        workOrder.push('custody-transfer');
        return recipient;
      },
      submitCustodyTransferPackageV1: async (input) => {
        submissions.push(input.submission);
        submitAttempts += 1;
        if (submitAttempts === 1) throw new Error('lost response');
      },
      subscribeApprovalV1: async (input) => {
        input.onResult({
          outcome: 'pending',
          state: buildProvisioningLinkedDeviceSessionState({
            linkSessionId: fixture.approval.linkSessionId,
            walletId: fixture.approval.walletId,
            enrollmentId: fixture.approval.enrollmentId,
            provisioningStartedAtMs: now,
          }),
        });
        setTimeout(() => {
          input.onResult({
            outcome: 'active',
            state: activeState,
            manifestDigestB64u: fixture.receipt.manifestDigestB64u,
            receipt: fixture.receipt,
          });
        }, 100);
        return { close: () => undefined };
      },
    },
    custodyTransfer: {
      createRecipientV1: async () => {
        throw new Error('recipient creation belongs to Device 2');
      },
      sealForLinkedDeviceV1: async () => {
        sealCalls += 1;
        return sealedPackage;
      },
      acceptTransferV1: async () => {
        throw new Error('transfer acceptance belongs to Device 2');
      },
      discardRecipientV1: async () => undefined,
    },
    sourcePreparation: {
      prepareTargetReadyDeliveriesV1: async () => {
        throw new Error('source handoff is not part of this test');
      },
    },
  };

  const result = await scanAndLinkDevice(undefined, payload, {}, ports);

  expect(result.success).toBe(true);
  expect(sealCalls).toBe(1);
  expect(submissions).toHaveLength(2);
  expect(submissions[0]?.package).toBe(sealedPackage);
  expect(submissions[1]?.package).toBe(sealedPackage);
  expect(submissions[1]).toEqual(submissions[0]);
  expect(workOrder.indexOf('custody-transfer')).toBeLessThan(workOrder.indexOf('source-handoff'));
});
