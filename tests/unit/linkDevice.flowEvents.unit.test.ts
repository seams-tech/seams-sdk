import { expect, test } from '@playwright/test';
import { LinkDeviceFlow } from '@/SeamsWeb/operations/devices/linkDevice';
import { scanAndLinkDevice } from '@/SeamsWeb/operations/devices/scanDevice';
import type {
  DeviceLinkingAuthenticatedTransportPortV1,
  LinkedDeviceApprovalResultV1,
  DeviceLinkingFlowPortsV1,
  LinkSessionAuthenticationV1,
  LinkSessionTransportPortV1,
} from '@/SeamsWeb/operations/devices/deviceLinkingPorts';
import { DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import {
  buildActiveLinkedDeviceSessionState,
  buildAwaitingTargetPasskeyLinkedDeviceSessionState,
  buildCommittedCompletionRequiredLinkedDeviceSessionState,
  buildDisplayingQrLinkedDeviceSessionState,
  buildQrLinkedDeviceSessionPayloadV4,
  parseQrLinkedDeviceSessionPayloadV4,
} from '../../packages/shared-ts/src/device-linking';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceReceiptAcknowledgementV1,
  LinkedDeviceSessionState,
  LinkedDeviceSessionTransportEventV1,
} from '../../packages/shared-ts/src/device-linking';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import { parseWebAuthnCredentialIdB64u } from '../../packages/shared-ts/src/utils/domainIds';

function createPorts(
  calls: string[],
  onApproval?: (approval: LinkedDeviceApprovalV1) => void,
  onTransportBind?: () => void,
  approvalResult?: (state: LinkedDeviceSessionState) => LinkedDeviceApprovalResultV1,
  onSessionEventHandler?: (handler: (event: LinkedDeviceSessionTransportEventV1) => void) => void,
  onReceiptAcknowledgement?: (acknowledgement: LinkedDeviceReceiptAcknowledgementV1) => void,
): DeviceLinkingFlowPortsV1 {
  const fixture = buildR103DeviceLinkFixture();
  const now = Date.now();
  const payload = buildQrLinkedDeviceSessionPayloadV4({
    linkSessionId: fixture.payload.linkSessionId,
    linkPublicKeyB64u: fixture.payload.linkPublicKeyB64u,
    devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
    issuedAtMs: now - 1_000,
    expiresAtMs: now + 60_000,
  });
  let state: LinkedDeviceSessionState = buildDisplayingQrLinkedDeviceSessionState({
    linkSessionId: payload.linkSessionId,
    expiresAtMs: payload.expiresAtMs,
  });
  const authentication: LinkSessionAuthenticationV1 = {
    kind: 'link_session_authenticated_request_v1',
    source: fixture.approval.ownerAuthorization,
    proofDigestB64u: fixture.approval.policyDigestB64u,
  };
  const credentialIdResult = parseWebAuthnCredentialIdB64u('credential:r103');
  if (!credentialIdResult.ok) throw new Error(credentialIdResult.error.message);
  const authenticatedTransport: DeviceLinkingAuthenticatedTransportPortV1 = {
    async createUnclaimedSessionV1() {
      calls.push('create');
    },
    async getSessionV1() {
      calls.push('get');
      if (
        state.state === 'displaying_qr' ||
        state.state === 'expired_unclaimed' ||
        state.state === 'cancelled_unclaimed'
      ) {
        return { state };
      }
      return { state, deviceId: fixture.approval.deviceId };
    },
    async getApprovalV1() {
      calls.push('get-approval');
      return fixture.approval;
    },
    async registerTargetCredentialV1() {
      calls.push('credential');
    },
    async acknowledgeReceiptV1(input) {
      calls.push('ack');
      onReceiptAcknowledgement?.(input.acknowledgement);
    },
    async retryCommittedDeliveryV1() {
      calls.push('retry');
    },
    async cancelSessionV1() {
      calls.push('cancel');
    },
    async subscribeSessionV1(input) {
      calls.push('subscribe');
      if (onSessionEventHandler) {
        onSessionEventHandler((event) => {
          state = event.state;
          input.onEvent(event);
        });
      } else {
        input.onEvent({
          kind: 'linked_device_session_event_v1',
          linkSessionId: payload.linkSessionId,
          state,
          emittedAtMs: now,
        });
      }
      return { close: () => undefined };
    },
  };
  const transport: LinkSessionTransportPortV1 = {
    async claimSessionV1() {
      calls.push('claim');
      state = {
        state: 'claimed_by_owner',
        linkSessionId: payload.linkSessionId,
        walletId: fixture.approval.walletId,
        enrollmentId: fixture.approval.enrollmentId,
        claimExpiresAtMs: now + 30_000,
      };
      return {
        kind: 'linked_device_session_claim_v1',
        linkSessionId: payload.linkSessionId,
        walletId: fixture.approval.walletId,
        enrollmentId: fixture.approval.enrollmentId,
        deviceId: fixture.approval.deviceId,
        devicePublicKeyB64u: payload.devicePublicKeyB64u,
        claimedAtMs: now,
        claimExpiresAtMs: now + 30_000,
      };
    },
    async recordOwnerApprovalV1(input) {
      calls.push('approve');
      onApproval?.(input.approval);
      state = buildActiveLinkedDeviceSessionState({
        linkSessionId: input.approval.linkSessionId,
        walletId: input.approval.walletId,
        enrollmentId: input.approval.enrollmentId,
        activatedAtMs: input.approval.approvedAtMs,
      });
      const result = approvalResult?.(state);
      if (result) return result;
      return {
        outcome: 'active',
        state,
        manifestDigestB64u: fixture.receipt.manifestDigestB64u,
        receipt: fixture.receipt,
      };
    },
    async getApprovalV1() {
      calls.push('get-approval-owner');
      return {
        outcome: 'active',
        state:
          state.state === 'active'
            ? state
            : buildActiveLinkedDeviceSessionState({
                linkSessionId: payload.linkSessionId,
                walletId: fixture.approval.walletId,
                enrollmentId: fixture.approval.enrollmentId,
                activatedAtMs: now,
              }),
        manifestDigestB64u: fixture.receipt.manifestDigestB64u,
        receipt: fixture.receipt,
      };
    },
    async subscribeApprovalV1(input) {
      calls.push('subscribe-approval');
      const subscribedResult = approvalResult?.(state);
      input.onResult(
        subscribedResult ?? {
          outcome: 'active',
          state: buildActiveLinkedDeviceSessionState({
            linkSessionId: payload.linkSessionId,
            walletId: fixture.approval.walletId,
            enrollmentId: fixture.approval.enrollmentId,
            activatedAtMs: now,
          }),
          manifestDigestB64u: fixture.receipt.manifestDigestB64u,
          receipt: fixture.receipt,
        },
      );
      return { close: () => undefined };
    },
    createAuthenticatedSessionTransportV1() {
      calls.push('bind-transport');
      onTransportBind?.();
      return authenticatedTransport;
    },
  };
  return {
    transport,
    keyMaterial: {
      async createBootstrapKeyMaterialV1() {
        calls.push('keygen');
        return {
          handle: { kind: 'device_linking_key_material_handle_v1', handleId: 'test-key-material' },
          linkPublicKeyB64u: payload.linkPublicKeyB64u,
          devicePublicKeyB64u: payload.devicePublicKeyB64u,
        };
      },
      async discardKeyMaterialV1() {
        calls.push('key-discard');
      },
      async signDeviceSessionRequestV1() {
        return { signatureB64u: 'test-signature' };
      },
    },
    ownerAuthorization: {
      async authenticateOwnerForLinkingV1() {
        calls.push('authenticate');
        return {
          authentication,
          walletId: fixture.approval.walletId,
          ownerAuthorization: fixture.approval.ownerAuthorization,
          policyDigestB64u: fixture.approval.policyDigestB64u,
          operationId: fixture.approval.operationId,
          idempotencyKey: fixture.approval.idempotencyKey,
          orderedKeyBindings: fixture.approval.orderedKeyBindings,
          protocolVersions: fixture.approval.protocolVersions,
          expiresAtMs: now + 30_000,
        };
      },
    },
    targetCredential: {
      async createTargetCredentialV1() {
        calls.push('target-passkey');
        return { credentialIdB64u: credentialIdResult.value };
      },
    },
    laneProvisioning: {
      async installAuthorizedLaneHolderWorkerV1() {
        calls.push('worker-install');
      },
      async prepareLinkedDeviceLanesV1() {
        calls.push('prepare-lanes');
        return fixture.receipt;
      },
      async resumeCommittedDeliveryV1() {
        calls.push('resume-delivery');
        return fixture.receipt;
      },
    },
  };
}

test.describe('linked-device browser orchestration', () => {
  test('Device 2 generates public-only QR material before registering the session', async () => {
    const calls: string[] = [];
    const events: string[] = [];
    let transportBound = false;
    const ports = createPorts(calls, undefined, () => {
      transportBound = true;
    });
    const flow = new LinkDeviceFlow(
      undefined,
      {
        options: { onEvent: (event) => events.push(event.status) },
      },
      ports,
    );

    const result = await flow.generateQR();
    expect(parseQrLinkedDeviceSessionPayloadV4(result.qrData)).toEqual(result.qrData);
    expect(result.qrData).not.toHaveProperty('walletId');
    expect(calls.slice(0, 4)).toEqual(['keygen', 'bind-transport', 'create', 'subscribe']);
    expect(transportBound).toBe(true);
    expect(events).toContain('succeeded');
    expect(String(result.qrData.linkSessionId)).toMatch(/^link-session-/);
  });

  test('Device 2 routes cancellation through the bound authenticated transport', async () => {
    const calls: string[] = [];
    const ports = createPorts(calls);
    const flow = new LinkDeviceFlow(undefined, {}, ports);

    await flow.generateQR();
    await flow.cancel();

    expect(calls).toEqual([
      'keygen',
      'bind-transport',
      'create',
      'subscribe',
      'cancel',
      'key-discard',
    ]);
  });

  test('Device 1 authenticates once, claims, and approves the exact manifest', async () => {
    const calls: string[] = [];
    const events: string[] = [];
    const fixture = buildR103DeviceLinkFixture();
    let recordedApproval: LinkedDeviceApprovalV1 | undefined;
    const ports = createPorts(calls, (approval) => {
      recordedApproval = approval;
    });
    const qrData = buildQrLinkedDeviceSessionPayloadV4({
      linkSessionId: fixture.payload.linkSessionId,
      linkPublicKeyB64u: fixture.payload.linkPublicKeyB64u,
      devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
      issuedAtMs: Date.now() - 1_000,
      expiresAtMs: Date.now() + 60_000,
    });

    const result = await scanAndLinkDevice(
      undefined,
      qrData,
      {
        onEvent: (event) => events.push(event.status),
      },
      ports,
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('expected successful link approval');
    expect(result.enrollmentId).toBe(fixture.approval.enrollmentId);
    expect(result.manifestDigestB64u).toBe(fixture.receipt.manifestDigestB64u);
    expect(calls).toEqual(['authenticate', 'claim', 'approve']);
    expect(events).toEqual(['started', 'succeeded']);
    expect(calls).not.toContain('keygen');
    expect(recordedApproval?.ownerAuthorization).toEqual(fixture.approval.ownerAuthorization);
  });

  test('Device 1 waits for pending approval through authenticated subscribe and poll', async () => {
    const calls: string[] = [];
    const fixture = buildR103DeviceLinkFixture();
    const pendingState = buildAwaitingTargetPasskeyLinkedDeviceSessionState({
      linkSessionId: fixture.approval.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      credentialDeadlineMs: Date.now() + 30_000,
    });
    const ports = createPorts(calls, undefined, undefined, () => ({
      outcome: 'pending',
      state: pendingState,
    }));
    const qrData = buildQrLinkedDeviceSessionPayloadV4({
      linkSessionId: fixture.payload.linkSessionId,
      linkPublicKeyB64u: fixture.payload.linkPublicKeyB64u,
      devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
      issuedAtMs: Date.now() - 1_000,
      expiresAtMs: Date.now() + 60_000,
    });

    const result = await scanAndLinkDevice(undefined, qrData, {}, ports);

    expect(result.success).toBe(true);
    expect(calls).toEqual([
      'authenticate',
      'claim',
      'approve',
      'subscribe-approval',
      'get-approval-owner',
    ]);
  });

  test('Device 1 accepts a committed approval replay only with its receipt', async () => {
    const calls: string[] = [];
    const fixture = buildR103DeviceLinkFixture();
    const ports = createPorts(calls, undefined, undefined, (state) => ({
      outcome: 'replayed',
      replay: {
        state: 'active',
        session:
          state.state === 'active'
            ? state
            : buildActiveLinkedDeviceSessionState({
                linkSessionId: fixture.approval.linkSessionId,
                walletId: fixture.approval.walletId,
                enrollmentId: fixture.approval.enrollmentId,
                activatedAtMs: fixture.approval.approvedAtMs,
              }),
        manifestDigestB64u: fixture.receipt.manifestDigestB64u,
        receipt: fixture.receipt,
      },
    }));
    const qrData = buildQrLinkedDeviceSessionPayloadV4({
      linkSessionId: fixture.payload.linkSessionId,
      linkPublicKeyB64u: fixture.payload.linkPublicKeyB64u,
      devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
      issuedAtMs: Date.now() - 1_000,
      expiresAtMs: Date.now() + 60_000,
    });

    const result = await scanAndLinkDevice(undefined, qrData, {}, ports);

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('expected replayed approval success');
    expect(result.receipt).toEqual(fixture.receipt);
  });

  test('Device 2 retries committed delivery before acknowledging the full receipt', async () => {
    const calls: string[] = [];
    const fixture = buildR103DeviceLinkFixture();
    let emitSessionEvent: ((event: LinkedDeviceSessionTransportEventV1) => void) | undefined;
    let acknowledgement: LinkedDeviceReceiptAcknowledgementV1 | undefined;
    const ports = createPorts(
      calls,
      undefined,
      undefined,
      undefined,
      (handler) => {
        emitSessionEvent = handler;
      },
      (value) => {
        acknowledgement = value;
      },
    );
    const flow = new LinkDeviceFlow(undefined, {}, ports);
    const generated = await flow.generateQR();
    emitSessionEvent?.({
      kind: 'linked_device_session_event_v1',
      linkSessionId: generated.qrData.linkSessionId,
      state: buildCommittedCompletionRequiredLinkedDeviceSessionState({
        linkSessionId: generated.qrData.linkSessionId,
        walletId: fixture.approval.walletId,
        enrollmentId: fixture.approval.enrollmentId,
        transcriptSetDigestB64u: fixture.receipt.manifestDigestB64u,
      }),
      emittedAtMs: Date.now(),
    });
    await expect
      .poll(() => calls.slice(-3), { timeout: 5_000 })
      .toEqual(['retry', 'resume-delivery', 'ack']);
    expect(acknowledgement?.receipt).toEqual(fixture.receipt);
  });

  test('strict QR validation rejects the superseded shape', () => {
    expect(() =>
      parseQrLinkedDeviceSessionPayloadV4({
        sessionId: 'legacy-session',
        timestamp: Date.now(),
        version: 'v3',
      }),
    ).toThrow();
    expect(DeviceLinkingErrorCode.UNSUPPORTED).toBe('UNSUPPORTED');
  });
});
