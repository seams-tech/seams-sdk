import { expect, test } from '@playwright/test';
import { scanAndLinkDevice } from '@/SeamsWeb/operations/devices/scanDevice';
import type { Device1LinkingFlowPortsV1 } from '@/SeamsWeb/operations/devices/deviceLinkingPorts';
import { buildLinkedDeviceSessionClaimV1 } from '@shared/device-linking/parsers';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';

test('does not submit owner approval after terminal Email OTP target resolution', async () => {
  const nowMs = Date.now();
  const fixture = buildR103DeviceLinkFixture({
    linkSessionId: 'link-session:first-email-terminal',
    targetFactor: { kind: 'email_otp' },
    issuedAtMs: nowMs - 1_000,
    expiresAtMs: nowMs + 60_000,
  });
  const authentication = {
    kind: 'link_session_authenticated_request_v1' as const,
    source: fixture.approval.ownerAuthorization,
    proofDigestB64u: fixture.packageSetDigestB64u,
  };
  const claim = buildLinkedDeviceSessionClaimV1({
    linkSessionId: fixture.payload.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
    targetFactor: fixture.payload.targetFactor,
    sessionRevision: 4,
    claimedAtMs: nowMs,
    claimExpiresAtMs: nowMs + 60_000,
  });
  let ownerApprovalCalls = 0;
  const ports = {
    ownerAuthorization: {
      authenticateOwnerForLinkingV1: async () => ({
        authentication,
        walletId: fixture.approval.walletId,
        ownerAuthorization: fixture.approval.ownerAuthorization,
        sourceSignerManifest: fixture.sourceSignerManifest,
        expiresAtMs: nowMs + 60_000,
        exportRootRequirement: 'not_required' as const,
      }),
    },
    transport: {
      claimSessionV1: async () => claim,
      resolveEmailOtpBaseFactorV1: async () => ({
        revision: 5,
        resolution: {
          kind: 'unavailable' as const,
          reason: 'no_active_email_otp_base_factor' as const,
        },
      }),
      recordOwnerApprovalV1: async () => {
        ownerApprovalCalls += 1;
        throw new Error('owner approval must not be submitted');
      },
      cancelClaimedSessionV1: async () => {
        throw new Error('session already reached its terminal state');
      },
    },
    sourceContribution: {},
    ed25519ExportRoot: {},
  } as unknown as Device1LinkingFlowPortsV1;

  await expect(scanAndLinkDevice(undefined, fixture.payload, {}, ports)).rejects.toThrow(
    'no_active_email_otp_base_factor',
  );
  expect(ownerApprovalCalls).toBe(0);
});

test('releases the wallet iframe foreground surface while device 1 waits', async () => {
  const nowMs = Date.now();
  const fixture = buildR103DeviceLinkFixture({
    linkSessionId: 'link-session:owner-progress-surface',
    targetFactor: { kind: 'email_otp' },
    issuedAtMs: nowMs - 1_000,
    expiresAtMs: nowMs + 60_000,
  });
  const events: Array<{ readonly interaction?: { readonly overlay: string } }> = [];

  await expect(
    scanAndLinkDevice(undefined, fixture.payload, { onEvent: (event) => events.push(event) }, {
      ownerAuthorization: {
        authenticateOwnerForLinkingV1: async () => {
          throw new Error('stop after the foreground surface is released');
        },
      },
    } as unknown as Device1LinkingFlowPortsV1),
  ).rejects.toThrow('stop after the foreground surface is released');

  expect(events[0]?.interaction?.overlay).toBe('hide');
});
