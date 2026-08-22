import { expect, test } from '@playwright/test';
import { DeviceLinkingDomain, LinkDeviceFlow } from '@/SeamsWeb/operations/devices/linkDevice';
import { validateQrLinkedDeviceSessionPayloadV5 } from '@/SeamsWeb/operations/devices/scanDevice';
import type {
  DeviceLinkingAuthenticatedTransportPortV1,
  DeviceLinkingFlowPortsV1,
  LinkSessionTransportPortV1,
} from '@/SeamsWeb/operations/devices/deviceLinkingPorts';
import { DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import {
  buildQrLinkedDeviceSessionPayloadV5,
  parseLinkSessionStateV1,
  parseQrLinkedDeviceSessionPayloadV5,
} from '../../packages/shared-ts/src/device-linking';
import type {
  LinkSessionProjectionV1,
  LinkSessionStateV1,
  LinkSessionTransportEventV1,
} from '../../packages/shared-ts/src/device-linking';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { LINKED_DEVICE_CLOCK_SKEW_TOLERANCE_MS_V1 } from '../../packages/shared-ts/src/device-linking/requestProof';

function unsupportedPort(name: string): never {
  throw new Error(`${name} is outside this Device 2 QR orchestration test`);
}

function createPorts(
  calls: string[],
  onTransportBind?: (transport: DeviceLinkingAuthenticatedTransportPortV1) => void,
  onSessionEventHandler?: (handler: (event: LinkSessionTransportEventV1) => void) => void,
): DeviceLinkingFlowPortsV1 {
  const fixture = buildR103DeviceLinkFixture();
  let currentPayload = fixture.payload;
  let state: LinkSessionStateV1 = { state: 'displaying_qr' };
  const authenticatedTransport: DeviceLinkingAuthenticatedTransportPortV1 = {
    async createUnclaimedSessionV1(input) {
      calls.push('create');
      currentPayload = input.payload;
      state = input.state;
    },
    async getSessionV1(input): Promise<LinkSessionProjectionV1> {
      calls.push('get');
      return {
        kind: 'linked_device_session_projection_v1',
        linkSessionId: input.linkSessionId,
        qrPayload: currentPayload,
        revision: 0,
        createdAtMs: Date.now(),
        updatedAtMs: Date.now(),
        state,
      };
    },
    async getApprovalV1() {
      return unsupportedPort('getApprovalV1');
    },
    async getWalletSessionDeliveryV1() {
      return unsupportedPort('getWalletSessionDeliveryV1');
    },
    async getTargetPreparationV1() {
      return unsupportedPort('getTargetPreparationV1');
    },
    async startTargetEmailOtpChallengeV1() {
      return unsupportedPort('startTargetEmailOtpChallengeV1');
    },
    async resendTargetEmailOtpChallengeV1() {
      return unsupportedPort('resendTargetEmailOtpChallengeV1');
    },
    async verifyTargetEmailOtpChallengeV1() {
      return unsupportedPort('verifyTargetEmailOtpChallengeV1');
    },
    async requestProvisioningDeliveriesV1() {
      return unsupportedPort('requestProvisioningDeliveriesV1');
    },
    async acknowledgeHolderDeliveriesV1() {
      return unsupportedPort('acknowledgeHolderDeliveriesV1');
    },
    async registerTargetCredentialV1() {
      return unsupportedPort('registerTargetCredentialV1');
    },
    async registerEd25519ExportRootRecipientV1() {
      return unsupportedPort('registerEd25519ExportRootRecipientV1');
    },
    async getEd25519ExportRootPackageV1() {
      return null;
    },
    async finalizeOwnerAuthMethodV1() {
      return unsupportedPort('finalizeOwnerAuthMethodV1');
    },
    async receiveCommittedAuthorityPackagesV1() {
      return unsupportedPort('receiveCommittedAuthorityPackagesV1');
    },
    async activateInstalledAuthorityV1() {
      return unsupportedPort('activateInstalledAuthorityV1');
    },
    async acknowledgeLocalAuthorityActivationV1() {
      return unsupportedPort('acknowledgeLocalAuthorityActivationV1');
    },
    async acknowledgeReceiptV1() {
      return unsupportedPort('acknowledgeReceiptV1');
    },
    async retryCommittedDeliveryV1() {
      return unsupportedPort('retryCommittedDeliveryV1');
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
          linkSessionId: input.linkSessionId,
          state,
          emittedAtMs: Date.now(),
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
      return unsupportedPort('claimSessionV1');
    },
    async recordOwnerApprovalV1() {
      return unsupportedPort('recordOwnerApprovalV1');
    },
    async getApprovalV1() {
      return unsupportedPort('getApprovalV1');
    },
    async getTargetReadyV1() {
      return unsupportedPort('getTargetReadyV1');
    },
    async submitPreparedProvisioningDeliveriesV1() {
      return unsupportedPort('submitPreparedProvisioningDeliveriesV1');
    },
    async getEd25519ExportRootRecipientV1() {
      return null;
    },
    async submitEd25519ExportRootPackageV1() {
      return unsupportedPort('submitEd25519ExportRootPackageV1');
    },
    async subscribeApprovalV1() {
      return unsupportedPort('subscribeApprovalV1');
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
          linkPublicKeyB64u: fixture.payload.linkPublicKeyB64u,
          devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
          emailOtpReleasePublicKey65B64u: base64UrlEncode(new Uint8Array(65).fill(4)),
        };
      },
      async openEmailOtpFactorReleaseV1() {
        return unsupportedPort('openEmailOtpFactorReleaseV1');
      },
      async discardKeyMaterialV1() {
        calls.push('key-discard');
      },
      async signDeviceSessionRequestV1() {
        return { signatureB64u: 'test-signature' };
      },
      async createOrdinarySignerMaterialRecipientRequestsV1() {
        return unsupportedPort('createOrdinarySignerMaterialRecipientRequestsV1');
      },
      async prepareOrdinarySignerMaterialV1() {
        return unsupportedPort('prepareOrdinarySignerMaterialV1');
      },
      async sealCommittedAuthorityPackagesV1() {
        return unsupportedPort('sealCommittedAuthorityPackagesV1');
      },
    },
    ownerAuthorization: {
      async startOwnerEnrollmentCeremonyV1() {
        return unsupportedPort('startOwnerEnrollmentCeremonyV1');
      },
      async authenticateOwnerForLinkingV1() {
        return unsupportedPort('authenticateOwnerForLinkingV1');
      },
    },
    sourcePreparation: {
      async prepareTargetReadyDeliveriesV1() {
        return unsupportedPort('prepareTargetReadyDeliveriesV1');
      },
    },
    targetCredential: {
      async createTargetCredentialV1() {
        return unsupportedPort('createTargetCredentialV1');
      },
    },
    authorityInstallation: {
      async persistCommittedDeliveryResumeV1() {
        return unsupportedPort('persistCommittedDeliveryResumeV1');
      },
      async readCommittedDeliveryResumeV1() {
        return unsupportedPort('readCommittedDeliveryResumeV1');
      },
      async clearCommittedDeliveryResumeV1() {
        return unsupportedPort('clearCommittedDeliveryResumeV1');
      },
      async installLocalAuthorityV1() {
        return unsupportedPort('installLocalAuthorityV1');
      },
      async finalizeLocalAuthorityActivationV1() {
        return unsupportedPort('finalizeLocalAuthorityActivationV1');
      },
    },
    readExpectedLockGenerationV1: async () => 0,
    ed25519ExportRoot: {
      async createRecipientV1() {
        return unsupportedPort('createRecipientV1');
      },
      async sealForLinkedDeviceV1() {
        return unsupportedPort('sealForLinkedDeviceV1');
      },
      async acceptTransferV1() {
        return unsupportedPort('acceptTransferV1');
      },
      async discardRecipientV1() {
        calls.push('export-root-recipient-discard');
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

    const first = domain.startDevice2LinkingFlow({ targetFactor: { kind: 'passkey_prf' } });
    await expect.poll(() => calls).toContain('create');
    await expect(
      domain.startDevice2LinkingFlow({ targetFactor: { kind: 'passkey_prf' } }),
    ).rejects.toThrow('Device-link QR flow is already running');
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
    const ports = createPorts(calls, () => {
      transportBound = true;
    });
    const flow = new LinkDeviceFlow(
      {
        targetFactor: { kind: 'passkey_prf' },
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
    const flow = new LinkDeviceFlow({ targetFactor: { kind: 'passkey_prf' } }, ports);

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
    for (const terminalKind of ['expired', 'cancelled', 'failed_before_commit'] as const) {
      const calls: string[] = [];
      let emitSessionEvent: ((event: LinkSessionTransportEventV1) => void) | undefined;
      const ports = createPorts(calls, undefined, (handler) => {
        emitSessionEvent = handler;
      });
      const flow = new LinkDeviceFlow({ targetFactor: { kind: 'passkey_prf' } }, ports);
      const generated = await flow.generateQR();
      const terminalState =
        terminalKind === 'expired'
          ? parseLinkSessionStateV1({
              state: 'expired',
              expiredAtMs: Date.now(),
            })
          : terminalKind === 'cancelled'
            ? parseLinkSessionStateV1({
                state: 'cancelled',
                cancelledAtMs: Date.now(),
              })
            : parseLinkSessionStateV1({
                state: 'failed_before_commit',
                error: {
                  kind: 'package_preparation_failed',
                  reason: 'test-terminal-state',
                },
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
    const flow = new LinkDeviceFlow({ targetFactor: { kind: 'passkey_prf' } }, ports);

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
    const flow = new LinkDeviceFlow({ targetFactor: { kind: 'passkey_prf' } }, ports);

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
