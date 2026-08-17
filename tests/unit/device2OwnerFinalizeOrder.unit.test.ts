import { expect, test } from '@playwright/test';
import { LinkDeviceFlow } from '../../packages/sdk-web/src/SeamsWeb/operations/devices/linkDevice';
import type {
  DeviceLinkingAuthenticatedTransportPortV1,
  DeviceLinkingFlowPortsV1,
  DeviceLinkingKeyMaterialPortV1,
  DeviceLinkingTargetCredentialPortV1,
  LinkSessionTransportPortV1,
} from '../../packages/sdk-web/src/SeamsWeb/operations/devices/deviceLinkingPorts';
import type { DeviceLinkingCustodyTransferPortV1 } from '../../packages/sdk-web/src/SeamsWeb/operations/devices/deviceLinkingCustodyTransfer';
import { buildAwaitingTargetPasskeyLinkedDeviceSessionState } from '../../packages/shared-ts/src/device-linking';
import type { LinkedDeviceSessionTransportEventV1 } from '../../packages/shared-ts/src/device-linking';
import {
  LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1,
  parseLinkedDeviceCustodyTransferPackageV1,
  parseLinkedDeviceCustodyTransferRecipientV1,
} from '../../packages/shared-ts/src/device-linking/custodyTransfer';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import {
  ALT_DIGEST_B64U,
  CIPHERTEXT_B64U,
  CIPHERTEXT_DIGEST_B64U,
  NONCE_12_B64U,
} from './helpers/passkeyCustodyEnvelope.fixtures';
import {
  buildR103DeviceLinkFixture,
  buildR103TargetCredentialFixture,
} from './helpers/deviceLinkContracts.fixtures';

test('finalizes owner custody before registering the temporary target credential', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const target = await buildR103TargetCredentialFixture(fixture);
  const calls: string[] = [];
  const preparationRef: { current?: typeof target.preparation } = {};
  let sessionEventHandler: ((event: LinkedDeviceSessionTransportEventV1) => void) | undefined;
  let targetPasskeyActivation: { readonly createPasskey: () => Promise<void> } | undefined;

  const keyMaterial: DeviceLinkingKeyMaterialPortV1 = {
    async createBootstrapKeyMaterialV1() {
      return {
        handle: { kind: 'device_linking_key_material_handle_v1', handleId: 'test-key' },
        linkPublicKeyB64u: fixture.payload.linkPublicKeyB64u,
        devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
      };
    },
    async prepareTargetHolderRegistrationsV1() {
      throw new Error('target holder preparation is outside this test');
    },
    async openAndSealTargetHolderDeliveryV1() {
      throw new Error('holder delivery is outside this test');
    },
    async discardKeyMaterialV1() {
      calls.push('key-discard');
    },
    async signDeviceSessionRequestV1() {
      return { signatureB64u: base64UrlEncode(new Uint8Array(64).fill(3)) };
    },
  };

  const authenticatedTransport: DeviceLinkingAuthenticatedTransportPortV1 = {
    async createUnclaimedSessionV1() {
      calls.push('create');
    },
    async getSessionV1() {
      return {
        state: buildAwaitingTargetPasskeyLinkedDeviceSessionState({
          linkSessionId: preparationRef.current?.linkSessionId ?? fixture.payload.linkSessionId,
          walletId: fixture.approval.walletId,
          enrollmentId: fixture.approval.enrollmentId,
          credentialDeadlineMs: Date.now() + 30_000,
        }),
        deviceId: fixture.approval.deviceId,
      };
    },
    async getApprovalV1() {
      throw new Error('approval is outside this finalize-order test');
    },
    async getWalletSessionDeliveryV1() {
      throw new Error('wallet session delivery is outside this test');
    },
    async getTargetPreparationV1() {
      if (!preparationRef.current) throw new Error('target preparation is unavailable');
      return preparationRef.current;
    },
    async requestProvisioningDeliveriesV1() {
      throw new Error('provisioning is outside this finalize-order test');
    },
    async acknowledgeHolderDeliveriesV1() {
      throw new Error('holder delivery is outside this test');
    },
    async registerTargetCredentialV1() {
      calls.push('credential');
    },
    async finalizeOwnerAuthMethodV1() {
      calls.push('finalize');
      return {
        ok: true,
        walletId: fixture.approval.walletId,
        rpId: String(preparationRef.current?.ownerEnrollment.registration.rpId),
        authMethod: {
          kind: 'passkey' as const,
          status: 'active' as const,
          credentialIdB64u: base64UrlEncode(new Uint8Array(32).fill(9)),
          credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(10)),
          counter: 0,
          device: {
            label: 'Chrome on macOS',
            browser: 'chrome' as const,
            os: 'macos' as const,
            synced: false,
            transports: ['internal'],
          },
        },
      };
    },
    async registerCustodyTransferRecipientV1() {
      calls.push('recipient-register');
    },
    async getCustodyTransferPackageV1() {
      calls.push('package');
      return parseLinkedDeviceCustodyTransferPackageV1({
        kind: 'linked_device_custody_transfer_package_v1',
        walletId: String(fixture.approval.walletId),
        enrollmentId: String(fixture.approval.enrollmentId),
        deviceId: String(fixture.approval.deviceId),
        transferAlg: LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1,
        recipientPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(1)),
        ephemeralPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(2)),
        nonceB64u: NONCE_12_B64U,
        sealedCustodySecretB64u: CIPHERTEXT_B64U,
        aadHashB64u: ALT_DIGEST_B64U,
        ciphertextDigestB64u: CIPHERTEXT_DIGEST_B64U,
        sealedAtMs: Date.now(),
      });
    },
    async acknowledgeReceiptV1() {
      throw new Error('receipt acknowledgement is outside this test');
    },
    async retryCommittedDeliveryV1() {
      throw new Error('committed delivery is outside this test');
    },
    async cancelSessionV1() {
      calls.push('cancel');
    },
    async subscribeSessionV1(input) {
      sessionEventHandler = input.onEvent;
      return { close: () => undefined };
    },
  };

  const targetCredential: DeviceLinkingTargetCredentialPortV1 = {
    async createTargetCredentialV1() {
      calls.push('target-passkey');
      return {
        webauthnRegistration: target.registration.webauthnRegistration,
        orderedHolderRegistrations: target.registration.orderedHolderRegistrations,
        factorSecret: new Uint8Array(32).fill(7),
      };
    },
  };

  const recipientRegistration = parseLinkedDeviceCustodyTransferRecipientV1({
    kind: 'linked_device_custody_transfer_recipient_v1',
    linkSessionId: fixture.payload.linkSessionId,
    walletId: String(fixture.approval.walletId),
    enrollmentId: String(fixture.approval.enrollmentId),
    deviceId: String(fixture.approval.deviceId),
    transferAlg: LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1,
    recipientPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(1)),
    registeredAtMs: Date.now(),
  });
  const custodyTransfer: DeviceLinkingCustodyTransferPortV1 = {
    async createRecipientV1() {
      calls.push('recipient-create');
      return { recipientHandleId: 'test-recipient', registration: recipientRegistration };
    },
    async sealForLinkedDeviceV1() {
      throw new Error('source sealing is outside this test');
    },
    async acceptTransferV1() {
      calls.push('accept');
      return {
        nonceB64u: NONCE_12_B64U,
        sealedCustodySecretB64u: CIPHERTEXT_B64U,
        aadHashB64u: ALT_DIGEST_B64U,
        ciphertextDigestB64u: CIPHERTEXT_DIGEST_B64U,
      };
    },
    async discardRecipientV1() {
      calls.push('recipient-discard');
    },
  };

  const ports = {
    transport: {
      createAuthenticatedSessionTransportV1() {
        return authenticatedTransport;
      },
    } as never as LinkSessionTransportPortV1,
    keyMaterial,
    targetCredential,
    custodyTransfer,
    sessionActivation: {
      async activateLinkedDeviceSigningSessionV1() {
        throw new Error('session activation is outside this test');
      },
    },
    laneProvisioning: {
      async prepareLinkedDeviceLanesV1() {
        throw new Error('lane provisioning is outside this test');
      },
      async resumeCommittedDeliveryV1() {
        throw new Error('committed delivery is outside this test');
      },
    },
    walletSessions: {
      async putExactActiveDeliveryV1() {
        throw new Error('wallet session persistence is outside this test');
      },
    },
    executionEvidence: {
      async putExactProvisionedEvidenceV1() {
        throw new Error('execution evidence is outside this test');
      },
      async readForEnrollmentV1() {
        return { kind: 'missing' as const };
      },
    },
  } as never as DeviceLinkingFlowPortsV1;

  const flow = new LinkDeviceFlow(
    {
      options: {
        onTargetPasskeyRequired: (activation) => {
          targetPasskeyActivation = activation;
        },
      },
    },
    ports,
  );
  const generated = await flow.generateQR();
  preparationRef.current = {
    ...target.preparation,
    linkSessionId: generated.qrData.linkSessionId,
    issuedAtMs: Date.now() - 1_000,
    expiresAtMs: Date.now() + 30_000,
  };
  sessionEventHandler?.({
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
  await expect.poll(() => targetPasskeyActivation).toBeTruthy();
  if (!targetPasskeyActivation) throw new Error('target passkey activation was not published');

  await expect(targetPasskeyActivation.createPasskey()).rejects.toThrow(
    'linked-device owner finalize returned a mismatched auth method',
  );
  expect(calls).toContain('finalize');
  expect(calls).not.toContain('credential');
  expect(calls.indexOf('finalize')).toBeGreaterThan(calls.indexOf('accept'));
});
