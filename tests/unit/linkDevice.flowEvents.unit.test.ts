import { expect, test } from '@playwright/test';
import { DeviceLinkingDomain, LinkDeviceFlow } from '@/SeamsWeb/operations/devices/linkDevice';
import {
  scanAndLinkDevice,
  validateQrLinkedDeviceSessionPayloadV5,
} from '@/SeamsWeb/operations/devices/scanDevice';
import type {
  DeviceLinkingAuthenticatedTransportPortV1,
  DeviceLinkingSessionActivationPortV1,
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
  buildLinkedDeviceHolderDeliveryAcknowledgementV1,
  buildCancelledUnclaimedLinkedDeviceSessionState,
  buildDisplayingQrLinkedDeviceSessionState,
  buildExpiredUnclaimedLinkedDeviceSessionState,
  buildQrLinkedDeviceSessionPayloadV5,
  buildLinkedDeviceTargetPreparationV1,
  parseQrLinkedDeviceSessionPayloadV5,
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
  buildR103OwnerEnrollmentCeremonyV1,
  buildR103ProvisioningFixture,
  buildR103TargetReadySourceFixture,
} from './helpers/deviceLinkContracts.fixtures';
import {
  buildLinkedDeviceCustodyTransferPackageFixtureV1,
  buildLinkedDeviceCustodyTransferRecipientFixtureV1,
  buildUnlockedCustodyCapabilityFixtureV1,
} from './helpers/linkedDeviceCustodyTransfer.fixtures';
import { parseWebAuthnCredentialIdB64u } from '../../packages/shared-ts/src/utils/domainIds';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { computeLaneEnrollmentManifestDigestV1 } from '../../packages/shared-ts/src/signing-lanes/rotationDigests';
import { LINKED_DEVICE_CLOCK_SKEW_TOLERANCE_MS_V1 } from '../../packages/shared-ts/src/device-linking/requestProof';

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
  approvalSubscriptionResults?: readonly LinkedDeviceApprovalResultV1[],
  onSessionActivation?: (
    input: Parameters<
      DeviceLinkingSessionActivationPortV1['activateLinkedDeviceSigningSessionV1']
    >[0],
  ) => void,
): DeviceLinkingFlowPortsV1 {
  const fixture = buildR103DeviceLinkFixture();
  const now = Date.now();
  const payload = buildQrLinkedDeviceSessionPayloadV5({
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
  // Refactor 103 Phase 8: the owner add-auth-method ceremony Device 2 finalizes.
  // Device 1 starts it under its own owner authority and it travels to Device 2
  // inside the target preparation, so both sides read the same one here.
  const ownerEnrollmentCeremony = buildR103OwnerEnrollmentCeremonyV1({
    rpId: 'wallet.example.test',
    expiresAtMs: now + 30_000,
  });
  // Refactor 103 Phase 8: the wallet custody seed crosses to Device 2 inside the
  // link session, so both halves of the transfer are part of every flow here.
  const custodyRecipient = buildLinkedDeviceCustodyTransferRecipientFixtureV1({
    linkSessionId: String(payload.linkSessionId),
    walletId: String(fixture.approval.walletId),
    enrollmentId: String(fixture.approval.enrollmentId),
    deviceId: String(fixture.approval.deviceId),
  });
  const custodyPackage = buildLinkedDeviceCustodyTransferPackageFixtureV1({
    walletId: String(fixture.approval.walletId),
    enrollmentId: String(fixture.approval.enrollmentId),
    deviceId: String(fixture.approval.deviceId),
    recipientPublicKeyB64u: String(custodyRecipient.recipientPublicKeyB64u),
  });
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
        ownerEnrollment: ownerEnrollmentCeremony,
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
    async registerCustodyTransferRecipientV1() {
      calls.push('recipient-register');
    },
    async getCustodyTransferPackageV1() {
      calls.push('package');
      return custodyPackage;
    },
    async finalizeOwnerAuthMethodV1() {
      calls.push('finalize');
      return {
        localAccount: {
          kind: 'linked_device_local_account_projection_v1',
          walletId: fixture.approval.walletId,
          nearAccountId: 'linked-owner.testnet',
          signerSlot: 4,
        },
        response: {
          ok: true,
          walletId: fixture.approval.walletId,
          rpId: String(ownerEnrollmentCeremony.registration.rpId),
          authMethod: {
            kind: 'passkey',
            status: 'active',
            credentialIdB64u: String(credentialIdResult.value),
            credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(10)),
            counter: 0,
            device: {
              label: 'Chrome on macOS',
              browser: 'chrome',
              os: 'macos',
              synced: false,
              transports: ['internal'],
            },
          },
        },
      };
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
    async getCustodyTransferRecipientV1() {
      calls.push('get-custody-recipient');
      return custodyRecipient;
    },
    async submitCustodyTransferPackageV1() {
      calls.push('submit-custody-package');
    },
    async subscribeApprovalV1(input) {
      calls.push('subscribe-approval');
      const subscribedResults = approvalSubscriptionResults ?? [
        approvalResult?.(state) ?? {
          outcome: 'active' as const,
          state: buildActiveLinkedDeviceSessionState({
            linkSessionId: payload.linkSessionId,
            walletId: fixture.approval.walletId,
            enrollmentId: fixture.approval.enrollmentId,
            activatedAtMs: now,
          }),
          manifestDigestB64u: fixture.receipt.manifestDigestB64u,
          receipt: fixture.receipt,
        },
      ];
      for (const subscribedResult of subscribedResults) input.onResult(subscribedResult);
      if (
        !approvalSubscriptionResults &&
        sourceHandoff &&
        subscribedResults[0]?.outcome === 'pending'
      ) {
        setTimeout(() => {
          input.onResult({
            outcome: 'active',
            state: buildActiveLinkedDeviceSessionState({
              linkSessionId: payload.linkSessionId,
              walletId: fixture.approval.walletId,
              enrollmentId: fixture.approval.enrollmentId,
              activatedAtMs: now,
            }),
            manifestDigestB64u: fixture.receipt.manifestDigestB64u,
            receipt: fixture.receipt,
          });
        }, 0);
      }
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
      async startOwnerEnrollmentCeremonyV1() {
        calls.push('start-owner-ceremony');
        return { ceremony: ownerEnrollmentCeremony };
      },
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
          custodyTransferCapability: buildUnlockedCustodyCapabilityFixtureV1({
            walletId: String(fixture.approval.walletId),
            expiresAtMs: now + 30_000,
          }),
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
          factorSecret: new Uint8Array(32).fill(8),
        };
      },
    },
    custodyTransfer: {
      async createRecipientV1() {
        calls.push('recipient-create');
        return { recipientHandleId: 'test-recipient', registration: custodyRecipient };
      },
      async sealForLinkedDeviceV1() {
        calls.push('seal-custody');
        return custodyPackage;
      },
      async acceptTransferV1() {
        calls.push('accept-custody');
        return {
          nonceB64u: custodyPackage.nonceB64u,
          sealedCustodySecretB64u: custodyPackage.sealedCustodySecretB64u,
          aadHashB64u: custodyPackage.aadHashB64u,
          ciphertextDigestB64u: custodyPackage.ciphertextDigestB64u,
        };
      },
      async discardRecipientV1() {
        calls.push('recipient-discard');
      },
    },
    sessionActivation: {
      async activateLinkedDeviceSigningSessionV1(input) {
        onSessionActivation?.(input);
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
  test('rejects a second direct Device 2 flow while the first remains owned', async () => {
    const calls: string[] = [];
    const domain = new DeviceLinkingDomain({
      kind: 'direct',
      getContext: () => {
        throw new Error('Device 2 QR generation does not use the signing context');
      },
      walletIframe: {
        shouldUseWalletIframe: () => false,
        requireRouter: async () => {
          throw new Error('wallet iframe is disabled');
        },
      },
      ports: createPorts(calls),
    });

    const first = domain.startDevice2LinkingFlow();
    await expect(domain.startDevice2LinkingFlow()).rejects.toThrow(
      'Device-link QR flow is already running',
    );
    await first;
    await domain.cancelDeviceLinking();
    expect(calls.filter((call) => call === 'keygen')).toHaveLength(1);
    expect(calls.filter((call) => call === 'close')).toHaveLength(1);
    expect(calls.filter((call) => call === 'key-discard')).toHaveLength(1);
  });

  test('Device 2 generates public-only QR material before registering the session', async () => {
    const calls: string[] = [];
    const events: string[] = [];
    let transportBound = false;
    const ports = createPorts(calls, undefined, () => {
      transportBound = true;
    });
    const flow = new LinkDeviceFlow(
      {
        options: { onEvent: (event) => events.push(event.status) },
      },
      ports,
    );

    const result = await flow.generateQR();
    expect(parseQrLinkedDeviceSessionPayloadV5(result.qrData)).toEqual(result.qrData);
    expect(result.qrData).not.toHaveProperty('walletId');
    expect(calls.slice(0, 4)).toEqual(['keygen', 'bind-transport', 'create', 'subscribe']);
    expect(transportBound).toBe(true);
    expect(events).toContain('succeeded');
    expect(String(result.qrData.linkSessionId)).toMatch(/^link-session-/);
  });

  test('Device 2 routes cancellation through the bound authenticated transport', async () => {
    const calls: string[] = [];
    const ports = createPorts(calls);
    const flow = new LinkDeviceFlow({}, ports);

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

  test('Device 2 closes polling and discards its worker key for every terminal session', async () => {
    const fixture = buildR103DeviceLinkFixture();
    for (const terminalKind of ['expired', 'cancelled', 'active'] as const) {
      const calls: string[] = [];
      let emitSessionEvent: ((event: LinkedDeviceSessionTransportEventV1) => void) | undefined;
      const ports = createPorts(calls, undefined, undefined, undefined, (handler) => {
        emitSessionEvent = handler;
      });
      const flow = new LinkDeviceFlow({}, ports);
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
    const flow = new LinkDeviceFlow({}, ports);

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
    const flow = new LinkDeviceFlow({}, ports);

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
      parseQrLinkedDeviceSessionPayloadV5({
        sessionId: 'legacy-session',
        timestamp: Date.now(),
        version: 'v3',
      }),
    ).toThrow();
    expect(DeviceLinkingErrorCode.UNSUPPORTED).toBe('UNSUPPORTED');
  });

  test('uses the shared QR clock-skew boundary and keeps expiry strict', () => {
    const originalNow = Date.now;
    const now = 1_800_000_000_000;
    Date.now = () => now;
    try {
      const fixture = buildR103DeviceLinkFixture();
      const accepted = buildQrLinkedDeviceSessionPayloadV5({
        ...fixture.payload,
        issuedAtMs: now + LINKED_DEVICE_CLOCK_SKEW_TOLERANCE_MS_V1,
        expiresAtMs: now + LINKED_DEVICE_CLOCK_SKEW_TOLERANCE_MS_V1 + 60_000,
      });
      expect(validateQrLinkedDeviceSessionPayloadV5(accepted)).toEqual(accepted);

      const rejectedFuture = buildQrLinkedDeviceSessionPayloadV5({
        ...fixture.payload,
        issuedAtMs: now + LINKED_DEVICE_CLOCK_SKEW_TOLERANCE_MS_V1 + 1,
        expiresAtMs: now + LINKED_DEVICE_CLOCK_SKEW_TOLERANCE_MS_V1 + 60_001,
      });
      expect(() => validateQrLinkedDeviceSessionPayloadV5(rejectedFuture)).toThrow(
        'QR payload was issued in the future',
      );

      const expiredAtNow = buildQrLinkedDeviceSessionPayloadV5({
        ...fixture.payload,
        issuedAtMs: now - 60_000,
        expiresAtMs: now,
      });
      expect(() => validateQrLinkedDeviceSessionPayloadV5(expiredAtNow)).toThrow('QR code expired');
    } finally {
      Date.now = originalNow;
    }
  });
});
