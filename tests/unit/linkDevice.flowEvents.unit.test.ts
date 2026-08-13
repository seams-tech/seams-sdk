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
  buildLinkedDeviceProvisionedExecutionEvidenceV1,
  type LinkedDeviceProvisionedExecutionEvidenceV1,
} from '@/core/signingEngine/session/lanes/linkedDeviceExecutionBundle';
import {
  buildActiveLinkedDeviceSessionState,
  buildAwaitingTargetPasskeyLinkedDeviceSessionState,
  buildProvisioningLinkedDeviceSessionState,
  buildLinkedDeviceHolderDeliveryAcknowledgementV1,
  buildCommittedCompletionRequiredLinkedDeviceSessionState,
  buildCancelledUnclaimedLinkedDeviceSessionState,
  buildDisplayingQrLinkedDeviceSessionState,
  buildExpiredUnclaimedLinkedDeviceSessionState,
  buildQrLinkedDeviceSessionPayloadV4,
  buildLinkedDeviceTargetPreparationV1,
  parseQrLinkedDeviceSessionPayloadV4,
} from '../../packages/shared-ts/src/device-linking';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceProvisioningDeliveriesSubmissionV1,
  LinkedDeviceTargetReadyR102InputV1,
  LinkedDeviceReceiptAcknowledgementV1,
  LinkedDeviceSessionState,
  LinkedDeviceSessionTransportEventV1,
} from '../../packages/shared-ts/src/device-linking';
import {
  buildR103DeviceLinkFixture,
  buildR103ActiveExecutionFixture,
  buildR103LinkedWalletSessionDeliveryFixture,
  buildR103ProvisioningFixture,
  buildR103TargetReadySourceFixture,
} from './helpers/deviceLinkContracts.fixtures';
import { parseWebAuthnCredentialIdB64u } from '../../packages/shared-ts/src/utils/domainIds';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { computeLaneEnrollmentManifestDigestV1 } from '../../packages/shared-ts/src/signing-lanes/rotationDigests';

function createPorts(
  calls: string[],
  onApproval?: (approval: LinkedDeviceApprovalV1) => void,
  onTransportBind?: (transport: DeviceLinkingAuthenticatedTransportPortV1) => void,
  approvalResult?: (state: LinkedDeviceSessionState) => LinkedDeviceApprovalResultV1,
  onSessionEventHandler?: (handler: (event: LinkedDeviceSessionTransportEventV1) => void) => void,
  onReceiptAcknowledgement?: (acknowledgement: LinkedDeviceReceiptAcknowledgementV1) => void,
  sourceHandoff?: {
    readonly targetReady: LinkedDeviceTargetReadyR102InputV1;
    readonly onSubmission: (submission: LinkedDeviceProvisioningDeliveriesSubmissionV1) => void;
  },
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
  let activeLinkSessionId = payload.linkSessionId;
  const authentication: LinkSessionAuthenticationV1 = {
    kind: 'link_session_authenticated_request_v1',
    source: fixture.approval.ownerAuthorization,
    proofDigestB64u: fixture.approval.policyDigestB64u,
  };
  const credentialIdResult = parseWebAuthnCredentialIdB64u(
    base64UrlEncode(new Uint8Array(32).fill(6)),
  );
  if (!credentialIdResult.ok) throw new Error(credentialIdResult.error.message);
  const targetBinding = fixture.approval.orderedKeyBindings[0];
  const targetHolder =
    buildR103ProvisioningFixture(fixture).deliveries.orderedChildren[0].job.targetHolder;
  let storedExecutionEvidence: LinkedDeviceProvisionedExecutionEvidenceV1 | null = null;
  const authenticatedTransport: DeviceLinkingAuthenticatedTransportPortV1 = {
    async createUnclaimedSessionV1(input) {
      calls.push('create');
      activeLinkSessionId = input.payload.linkSessionId;
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
      return buildR103DeviceLinkFixture({
        linkSessionId: String(activeLinkSessionId),
      }).approval;
    },
    async getWalletSessionDeliveryV1() {
      calls.push('get-wallet-session');
      return buildR103LinkedWalletSessionDeliveryFixture(
        buildR103DeviceLinkFixture({ linkSessionId: String(activeLinkSessionId) }),
      );
    },
    async getTargetPreparationV1() {
      calls.push('target-preparation');
      return buildLinkedDeviceTargetPreparationV1({
        linkSessionId: activeLinkSessionId,
        walletId: fixture.approval.walletId,
        enrollmentId: fixture.approval.enrollmentId,
        deviceId: fixture.approval.deviceId,
        rpId: 'wallet.example.test',
        userHandleB64u: fixture.payload.devicePublicKeyB64u,
        challengeB64u: fixture.approval.policyDigestB64u,
        orderedChildren: [
          {
            kind: 'linked_device_target_preparation_child_v1',
            operationId: fixture.approval.operationId,
            walletKeyId: targetBinding.walletKeyId,
            keyFamily: targetBinding.keyFamily,
            targetLaneId: targetBinding.targetLaneId,
            targetLaneShareEpoch: targetBinding.targetLaneShareEpoch,
            targetMaterialActivationId:
              fixture.receipt.orderedChildReceipts[0].materialActivation.activationId,
            targetHolderParticipantId: targetHolder.participantId,
          },
        ],
        issuedAtMs: now - 1_000,
        expiresAtMs: now + 30_000,
      });
    },
    async requestProvisioningDeliveriesV1() {
      throw new Error('provisioning delivery adapter is not configured for this test');
    },
    async acknowledgeHolderDeliveriesV1() {
      throw new Error('holder delivery adapter is not configured for this test');
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
      return {
        close: () => {
          calls.push('close');
        },
      };
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
    async getTargetReadyV1() {
      calls.push('get-target-ready');
      return sourceHandoff?.targetReady ?? null;
    },
    async submitPreparedProvisioningDeliveriesV1(input) {
      calls.push('submit-prepared-deliveries');
      sourceHandoff?.onSubmission(input.submission);
      return input.submission;
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
      onTransportBind?.(authenticatedTransport);
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
      async prepareTargetHolderRegistrationsV1() {
        throw new Error('target holder preparation is owned by the target credential fake');
      },
      async openAndSealTargetHolderDeliveryV1() {
        throw new Error('holder delivery is owned by the lane provisioning fake');
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
    sourcePreparation: {
      async prepareTargetReadyDeliveriesV1() {
        calls.push('prepare-source-deliveries');
        if (!sourceHandoff) throw new Error('source handoff is not configured for this test');
        return buildR103TargetReadySourceFixture(fixture).deliveries;
      },
    },
    targetCredential: {
      async createTargetCredentialV1(input) {
        calls.push('target-passkey');
        return {
          webauthnRegistration: {
            kind: 'linked_device_webauthn_registration_v1',
            credentialIdB64u: credentialIdResult.value,
            authenticatorAttachment: 'platform',
            clientDataJsonB64u: fixture.payload.devicePublicKeyB64u,
            attestationObjectB64u: fixture.payload.devicePublicKeyB64u,
            transports: ['internal'],
          },
          orderedHolderRegistrations: [
            {
              kind: 'linked_device_target_holder_registration_v1',
              operationId: input.preparation.orderedChildren[0].operationId,
              walletKeyId: input.preparation.orderedChildren[0].walletKeyId,
              keyFamily: input.preparation.orderedChildren[0].keyFamily,
              targetLaneId: input.preparation.orderedChildren[0].targetLaneId,
              targetLaneShareEpoch: input.preparation.orderedChildren[0].targetLaneShareEpoch,
              targetMaterialActivationId:
                input.preparation.orderedChildren[0].targetMaterialActivationId,
              holderParticipant: {
                kind: 'lane_holder_participant_v1',
                ...targetHolder,
              },
            },
          ],
        };
      },
    },
    laneProvisioning: {
      async prepareLinkedDeviceLanesV1() {
        calls.push('prepare-lanes');
        return fixture.receipt;
      },
      async resumeCommittedDeliveryV1(input) {
        calls.push('resume-delivery');
        await input.refetchApprovalV1();
        await input.refetchProvisioningDeliveriesV1();
        return fixture.receipt;
      },
    },
    walletSessions: {
      async putExactActiveDeliveryV1() {
        calls.push('persist-wallet-session');
      },
    },
    executionEvidence: {
      async putExactProvisionedEvidenceV1(evidence) {
        calls.push('persist-execution-evidence');
        storedExecutionEvidence = evidence;
        return evidence;
      },
      async readForEnrollmentV1() {
        calls.push('read-execution-evidence');
        return storedExecutionEvidence
          ? { kind: 'found', evidence: storedExecutionEvidence }
          : { kind: 'missing' };
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
      'close',
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

  test('Device 1 prepares and persists exact R102 deliveries once the target is ready', async () => {
    const calls: string[] = [];
    const fixture = buildR103DeviceLinkFixture();
    const source = buildR103TargetReadySourceFixture(fixture);
    let submitted: LinkedDeviceProvisioningDeliveriesSubmissionV1 | null = null;
    const ports = createPorts(
      calls,
      undefined,
      undefined,
      () => ({
        outcome: 'pending',
        state: buildProvisioningLinkedDeviceSessionState({
          linkSessionId: fixture.approval.linkSessionId,
          walletId: fixture.approval.walletId,
          enrollmentId: fixture.approval.enrollmentId,
          keyManifestDigestB64u: fixture.receipt.manifestDigestB64u,
        }),
      }),
      undefined,
      undefined,
      {
        targetReady: source.targetReady,
        onSubmission: (value) => {
          submitted = value;
        },
      },
    );
    const qrData = buildQrLinkedDeviceSessionPayloadV4({
      linkSessionId: fixture.payload.linkSessionId,
      linkPublicKeyB64u: fixture.payload.linkPublicKeyB64u,
      devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
      issuedAtMs: Date.now() - 1_000,
      expiresAtMs: Date.now() + 60_000,
    });

    await scanAndLinkDevice(undefined, qrData, {}, ports);

    expect(calls).toContain('get-target-ready');
    expect(calls).toContain('prepare-source-deliveries');
    expect(calls).toContain('submit-prepared-deliveries');
    expect(submitted?.deliveries).toEqual(source.deliveries);
    expect(submitted?.manifestDigestB64u).toBe(
      await computeLaneEnrollmentManifestDigestV1(source.targetReady.manifest),
    );
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
    let authenticatedTransport: DeviceLinkingAuthenticatedTransportPortV1 | undefined;
    const ports = createPorts(
      calls,
      undefined,
      (transport) => {
        authenticatedTransport = transport;
      },
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
    const active = await buildR103ActiveExecutionFixture({
      linkSessionId: String(generated.qrData.linkSessionId),
    });
    const evidence = await buildLinkedDeviceProvisionedExecutionEvidenceV1({
      approval: active.deviceLink.approval,
      targetPreparation: active.targetCredential.preparation,
      targetCredentialRegistration: active.targetCredential.registration,
      provisioningDeliveries: active.provisioning.deliveries,
      enrollmentReceipt: active.deviceLink.receipt,
    });
    if (!authenticatedTransport) throw new Error('authenticated transport was not bound');
    Object.assign(authenticatedTransport, {
      requestProvisioningDeliveriesV1: async () => {
        calls.push('provision-deliveries');
        return active.provisioning.deliveries;
      },
      getWalletSessionDeliveryV1: async () => {
        calls.push('get-wallet-session');
        return active.walletSession;
      },
    });
    Object.assign(ports.executionEvidence, {
      readForEnrollmentV1: async () => {
        calls.push('read-execution-evidence');
        return { kind: 'found', evidence } as const;
      },
    });
    Object.assign(ports.laneProvisioning, {
      resumeCommittedDeliveryV1: async (
        input: Parameters<typeof ports.laneProvisioning.resumeCommittedDeliveryV1>[0],
      ) => {
        calls.push('resume-delivery');
        await input.refetchApprovalV1();
        await input.refetchProvisioningDeliveriesV1();
        return active.deviceLink.receipt;
      },
    });
    emitSessionEvent?.({
      kind: 'linked_device_session_event_v1',
      linkSessionId: generated.qrData.linkSessionId,
      state: buildCommittedCompletionRequiredLinkedDeviceSessionState({
        linkSessionId: generated.qrData.linkSessionId,
        walletId: fixture.approval.walletId,
        enrollmentId: fixture.approval.enrollmentId,
        keyManifestDigestB64u: fixture.receipt.manifestDigestB64u,
        transcriptSetDigestB64u: fixture.receipt.manifestDigestB64u,
      }),
      emittedAtMs: Date.now(),
    });
    await expect
      .poll(() => calls.slice(-9), { timeout: 5_000 })
      .toEqual([
        'retry',
        'resume-delivery',
        'get-approval',
        'provision-deliveries',
        'read-execution-evidence',
        'persist-execution-evidence',
        'ack',
        'get-wallet-session',
        'persist-wallet-session',
      ]);
    expect(acknowledgement?.receipt).toEqual(active.deviceLink.receipt);
  });

  test('Device 2 processes exact encrypted deliveries before aggregate acknowledgement', async () => {
    const calls: string[] = [];
    const fixture = buildR103DeviceLinkFixture();
    const active = await buildR103ActiveExecutionFixture();
    let emitSessionEvent: ((event: LinkedDeviceSessionTransportEventV1) => void) | undefined;
    let authenticatedTransport: DeviceLinkingAuthenticatedTransportPortV1 | undefined;
    let aggregateAcknowledgement: LinkedDeviceReceiptAcknowledgementV1 | undefined;
    const ports = createPorts(
      calls,
      undefined,
      (transport) => {
        authenticatedTransport = transport;
      },
      undefined,
      (handler) => {
        emitSessionEvent = handler;
      },
      (value) => {
        aggregateAcknowledgement = value;
      },
    );
    const flow = new LinkDeviceFlow(undefined, {}, ports);
    const generated = await flow.generateQR();
    if (!authenticatedTransport) throw new Error('authenticated transport was not bound');
    Object.assign(authenticatedTransport, {
      requestProvisioningDeliveriesV1: async () => {
        calls.push('provision-deliveries');
        return active.provisioning.deliveries;
      },
      acknowledgeHolderDeliveriesV1: async () => {
        calls.push('holder-receipts');
        return active.deviceLink.receipt;
      },
      getWalletSessionDeliveryV1: async () => {
        calls.push('get-wallet-session');
        emitSessionEvent?.({
          kind: 'linked_device_session_event_v1',
          linkSessionId: generated.qrData.linkSessionId,
          state: buildActiveLinkedDeviceSessionState({
            linkSessionId: generated.qrData.linkSessionId,
            walletId: fixture.approval.walletId,
            enrollmentId: fixture.approval.enrollmentId,
            activatedAtMs: active.deviceLink.receipt.activatedAtMs,
          }),
          emittedAtMs: Date.now(),
        });
        return active.walletSession;
      },
    });
    Object.assign(ports.laneProvisioning, {
      prepareLinkedDeviceLanesV1: async (
        handoff: Parameters<typeof ports.laneProvisioning.prepareLinkedDeviceLanesV1>[0],
      ) => {
        calls.push('prepare-lanes');
        return await handoff.acknowledgeHolderDeliveriesV1(
          buildLinkedDeviceHolderDeliveryAcknowledgementV1({
            linkSessionId: handoff.approval.linkSessionId,
            enrollmentId: handoff.approval.enrollmentId,
            deviceId: handoff.approval.deviceId,
            orderedHolderDeliveryReceipts:
              active.provisioning.acknowledgement.orderedHolderDeliveryReceipts,
            acknowledgedAtMs: Date.now(),
          }),
        );
      },
    });
    emitSessionEvent?.({
      kind: 'linked_device_session_event_v1',
      linkSessionId: generated.qrData.linkSessionId,
      state: buildAwaitingTargetPasskeyLinkedDeviceSessionState({
        linkSessionId: generated.qrData.linkSessionId,
        walletId: fixture.approval.walletId,
        enrollmentId: fixture.approval.enrollmentId,
        credentialDeadlineMs: Date.now() + 30_000,
      }),
      emittedAtMs: Date.now(),
    });
    await expect
      .poll(() => calls.slice(-13), { timeout: 5_000 })
      .toEqual([
        'target-preparation',
        'target-passkey',
        'credential',
        'get-approval',
        'provision-deliveries',
        'prepare-lanes',
        'holder-receipts',
        'persist-execution-evidence',
        'ack',
        'get-wallet-session',
        'persist-wallet-session',
        'close',
        'key-discard',
      ]);
    expect(aggregateAcknowledgement?.receipt).toEqual(active.deviceLink.receipt);
  });

  test('Device 2 closes polling and discards its worker key for every terminal session', async () => {
    const fixture = buildR103DeviceLinkFixture();
    for (const terminalKind of ['expired', 'cancelled', 'active'] as const) {
      const calls: string[] = [];
      let emitSessionEvent: ((event: LinkedDeviceSessionTransportEventV1) => void) | undefined;
      const ports = createPorts(calls, undefined, undefined, undefined, (handler) => {
        emitSessionEvent = handler;
      });
      const flow = new LinkDeviceFlow(undefined, {}, ports);
      const generated = await flow.generateQR();
      const terminalState =
        terminalKind === 'expired'
          ? buildExpiredUnclaimedLinkedDeviceSessionState({
              linkSessionId: generated.qrData.linkSessionId,
              expiredAtMs: Date.now(),
            })
          : terminalKind === 'cancelled'
            ? buildCancelledUnclaimedLinkedDeviceSessionState({
                linkSessionId: generated.qrData.linkSessionId,
                cancelledAtMs: Date.now(),
              })
            : buildActiveLinkedDeviceSessionState({
                linkSessionId: generated.qrData.linkSessionId,
                walletId: fixture.approval.walletId,
                enrollmentId: fixture.approval.enrollmentId,
                activatedAtMs: Date.now(),
              });
      emitSessionEvent?.({
        kind: 'linked_device_session_event_v1',
        linkSessionId: generated.qrData.linkSessionId,
        state: terminalState,
        emittedAtMs: Date.now(),
      });
      await expect
        .poll(() => calls.filter((call) => call === 'close' || call === 'key-discard'))
        .toEqual(['close', 'key-discard']);
    }
  });

  test('Device 2 retries worker-key discard after a cleanup failure', async () => {
    const calls: string[] = [];
    const ports = createPorts(calls);
    let discardAttempts = 0;
    Object.assign(ports.keyMaterial, {
      discardKeyMaterialV1: async () => {
        discardAttempts += 1;
        calls.push('key-discard');
        if (discardAttempts === 1) throw new Error('worker unavailable');
      },
    });
    const flow = new LinkDeviceFlow(undefined, {}, ports);

    await flow.generateQR();
    await expect(flow.cancel()).rejects.toThrow('worker unavailable');
    await expect(flow.cancel()).resolves.toBeUndefined();

    expect(discardAttempts).toBe(2);
    expect(calls.filter((call) => call === 'close')).toHaveLength(1);
  });

  test('Device 2 cannot resurrect a cancelled flow after delayed key generation', async () => {
    const calls: string[] = [];
    const ports = createPorts(calls);
    const createKeyMaterial = ports.keyMaterial.createBootstrapKeyMaterialV1.bind(
      ports.keyMaterial,
    );
    let releaseKeyGeneration: (() => void) | undefined;
    const keyGenerationGate = new Promise<void>((resolve) => {
      releaseKeyGeneration = resolve;
    });
    Object.assign(ports.keyMaterial, {
      createBootstrapKeyMaterialV1: async () => {
        calls.push('keygen-delayed');
        await keyGenerationGate;
        return await createKeyMaterial();
      },
    });
    const flow = new LinkDeviceFlow(undefined, {}, ports);

    const generation = flow.generateQR();
    await expect.poll(() => calls).toContain('keygen-delayed');
    await flow.cancel();
    releaseKeyGeneration?.();
    await expect(generation).rejects.toThrow('cancelled or reset');

    expect(calls).not.toContain('bind-transport');
    expect(calls).not.toContain('create');
    expect(calls).not.toContain('subscribe');
    expect(calls.filter((call) => call === 'key-discard')).toHaveLength(1);
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
