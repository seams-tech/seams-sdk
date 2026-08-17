import { LinkDeviceFlow } from '@/SeamsWeb/operations/devices/linkDevice';
import type {
  DeviceLinkingAuthenticatedTransportPortV1,
  DeviceLinkingFlowPortsV1,
  DeviceLinkingKeyMaterialPortV1,
  DeviceLinkingTargetCredentialPortV1,
  LinkSessionTransportPortV1,
} from '@/SeamsWeb/operations/devices/deviceLinkingPorts';
import type { DeviceLinkingCustodyTransferPortV1 } from '@/SeamsWeb/operations/devices/deviceLinkingCustodyTransfer';
import { buildAwaitingTargetPasskeyLinkedDeviceSessionState } from '@shared/device-linking';
import type { LinkedDeviceSessionTransportEventV1 } from '@shared/device-linking';
import {
  LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1,
  parseLinkedDeviceCustodyTransferPackageV1,
  parseLinkedDeviceCustodyTransferRecipientV1,
} from '@shared/device-linking/custodyTransfer';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  ALT_DIGEST_B64U,
  CIPHERTEXT_B64U,
  CIPHERTEXT_DIGEST_B64U,
  NONCE_12_B64U,
} from './passkeyCustodyEnvelope.fixtures';
import {
  buildR103DeviceLinkFixture,
  buildR103TargetCredentialFixture,
} from './deviceLinkContracts.fixtures';
import { IndexedDBManager } from '@/core/indexedDB';

/** Every local write canonical unlock later reads, in the order they happened. */
export type CapturedLocalWritesV1 = {
  readonly profiles: Array<{ readonly profileId: string; readonly defaultSignerSlot?: number }>;
  readonly authenticators: Array<{
    readonly profileId: string;
    readonly signerSlot: number;
    readonly credentialId: string;
  }>;
  readonly authMethods: Array<{
    readonly walletId: string;
    readonly credentialIdB64u: string;
    readonly status: string;
  }>;
};

/**
 * Replaces the three local stores for one test and records what was written.
 *
 * All three together, never one at a time: they are a single recoverable unit,
 * and swapping only one would leave the others writing to real storage — which
 * both pollutes the environment and stops the test measuring the unit.
 *
 * `hooks` can throw to model a store that is failing.
 */
export async function withCapturedLocalWritesV1(
  hooks: {
    readonly onProfile?: () => void;
    readonly onAuthenticator?: () => void;
    readonly onAuthMethod?: (record: { readonly credentialIdB64u: string }) => void;
  },
  body: (captured: CapturedLocalWritesV1) => Promise<void>,
): Promise<CapturedLocalWritesV1> {
  const captured: CapturedLocalWritesV1 = { profiles: [], authenticators: [], authMethods: [] };
  const original = {
    profile: IndexedDBManager.upsertProfile,
    authenticator: IndexedDBManager.upsertProfileAuthenticator,
    authMethod: IndexedDBManager.upsertWalletAuthMethod,
  };
  IndexedDBManager.upsertProfile = (async (input: never) => {
    captured.profiles.push(input);
    hooks.onProfile?.();
    return input;
  }) as never;
  IndexedDBManager.upsertProfileAuthenticator = (async (record: never) => {
    captured.authenticators.push(record);
    hooks.onAuthenticator?.();
  }) as never;
  IndexedDBManager.upsertWalletAuthMethod = (async (record: never) => {
    captured.authMethods.push(record);
    hooks.onAuthMethod?.(record);
  }) as never;
  try {
    await body(captured);
  } finally {
    IndexedDBManager.upsertProfile = original.profile;
    IndexedDBManager.upsertProfileAuthenticator = original.authenticator;
    IndexedDBManager.upsertWalletAuthMethod = original.authMethod;
  }
  return captured;
}

/**
 * Device 2's linking flow, driven to the point where its user has clicked
 * through to the passkey prompt.
 *
 * The flow only reaches its interesting states through a subscription event and
 * a host-supplied activation callback, so every test of it needs the same
 * fifteen-port scaffold before it can assert anything. This owns that scaffold:
 * tests supply only the behaviour they are actually about, and the ports they
 * do not name throw rather than silently returning a plausible value.
 *
 * `calls` records the ordering-relevant steps. It is the seam most of these
 * tests assert on, because the invariants here are about what ran, how often,
 * and in which order.
 */
/**
 * The signer slot the harness's wallet key was created in.
 *
 * Not 1, so any test that reaches unlock proves the slot travelled from the
 * server rather than landing on the profile writer's default.
 */
export const LINKED_OWNER_SIGNER_SLOT_V1 = 4;

export type Device2LinkFlowHarnessV1 = {
  readonly flow: LinkDeviceFlow;
  /** Ordering-relevant steps, in the order they happened. */
  readonly calls: string[];
  /** Runs the flow up to the passkey prompt and returns its activation. */
  readonly reachTargetPasskeyPromptV1: () => Promise<{
    readonly createPasskey: () => Promise<void>;
  }>;
};

export type Device2LinkFlowOverridesV1 = {
  /** Replaces the default success; throw to model a rejected finalize. */
  readonly finalizeOwnerAuthMethodV1?: DeviceLinkingAuthenticatedTransportPortV1['finalizeOwnerAuthMethodV1'];
  readonly registerTargetCredentialV1?: DeviceLinkingAuthenticatedTransportPortV1['registerTargetCredentialV1'];
};

export async function buildDevice2LinkFlowHarnessV1(
  overrides: Device2LinkFlowOverridesV1 = {},
): Promise<Device2LinkFlowHarnessV1> {
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
      throw new Error('target holder preparation is outside this harness');
    },
    async openAndSealTargetHolderDeliveryV1() {
      throw new Error('holder delivery is outside this harness');
    },
    async discardKeyMaterialV1() {
      calls.push('key-discard');
    },
    async signDeviceSessionRequestV1() {
      return { signatureB64u: base64UrlEncode(new Uint8Array(64).fill(3)) };
    },
  };

  /**
   * A finalize that actually matches the credential the target port returns, so
   * the flow proceeds past its identity checks into the local writes.
   */
  const defaultFinalize: DeviceLinkingAuthenticatedTransportPortV1['finalizeOwnerAuthMethodV1'] =
    async () => {
      calls.push('finalize');
      return {
        localAccount: {
          kind: 'linked_device_local_account_projection_v1' as const,
          walletId: fixture.approval.walletId,
          nearAccountId: 'linked-owner.testnet',
          // Deliberately not 1. The profile writer defaults to slot 1 when none
          // is supplied, so a fixture using 1 would pass whether or not the real
          // slot is carried through.
          signerSlot: LINKED_OWNER_SIGNER_SLOT_V1,
        },
        response: {
          ok: true,
          walletId: fixture.approval.walletId,
          rpId: String(preparationRef.current?.ownerEnrollment.registration.rpId),
          authMethod: {
            kind: 'passkey' as const,
            status: 'active' as const,
            credentialIdB64u: String(target.registration.webauthnRegistration.credentialIdB64u),
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
        },
      };
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
      throw new Error('approval is outside this harness');
    },
    async getWalletSessionDeliveryV1() {
      throw new Error('wallet session delivery is outside this harness');
    },
    async getTargetPreparationV1() {
      if (!preparationRef.current) throw new Error('target preparation is unavailable');
      return preparationRef.current;
    },
    async requestProvisioningDeliveriesV1() {
      throw new Error('provisioning is outside this harness');
    },
    async acknowledgeHolderDeliveriesV1() {
      throw new Error('holder delivery is outside this harness');
    },
    registerTargetCredentialV1:
      overrides.registerTargetCredentialV1 ??
      (async () => {
        calls.push('credential');
      }),
    finalizeOwnerAuthMethodV1: overrides.finalizeOwnerAuthMethodV1 ?? defaultFinalize,
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
      throw new Error('receipt acknowledgement is outside this harness');
    },
    async retryCommittedDeliveryV1() {
      throw new Error('committed delivery is outside this harness');
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
      throw new Error('source sealing is outside this harness');
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
      // Recorded before throwing, so a test can assert the canonical route never
      // reaches it rather than relying on the throw to notice.
      async activateLinkedDeviceSigningSessionV1() {
        calls.push('session-activation');
        throw new Error('session activation is outside this harness');
      },
    },
    laneProvisioning: {
      async prepareLinkedDeviceLanesV1() {
        throw new Error('lane provisioning is outside this harness');
      },
      async resumeCommittedDeliveryV1() {
        throw new Error('committed delivery is outside this harness');
      },
    },
    walletSessions: {
      async putExactActiveDeliveryV1() {
        throw new Error('wallet session persistence is outside this harness');
      },
    },
    executionEvidence: {
      async putExactProvisionedEvidenceV1() {
        throw new Error('execution evidence is outside this harness');
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
    } as never,
    ports,
  );

  const emitAwaitingTargetPasskey = (linkSessionId: string): void => {
    sessionEventHandler?.({
      kind: 'linked_device_session_event_v1',
      linkSessionId,
      state: buildAwaitingTargetPasskeyLinkedDeviceSessionState({
        linkSessionId,
        walletId: fixture.approval.walletId,
        enrollmentId: fixture.approval.enrollmentId,
        credentialDeadlineMs: Date.now() + 30_000,
      }),
      emittedAtMs: Date.now(),
    } as never);
  };

  const awaitPublishedActivation = async (): Promise<{
    readonly createPasskey: () => Promise<void>;
  }> => {
    for (let attempt = 0; attempt < 200 && !targetPasskeyActivation; attempt += 1) {
      await new Promise<void>((resolve) => setTimeout(resolve, 5));
    }
    if (!targetPasskeyActivation) {
      throw new Error('target passkey activation was not published');
    }
    return targetPasskeyActivation;
  };

  let linkSessionIdRef = '';
  return {
    flow,
    calls,
    async reachTargetPasskeyPromptV1() {
      const generated = await flow.generateQR();
      linkSessionIdRef = String(generated.qrData.linkSessionId);
      preparationRef.current = {
        ...target.preparation,
        linkSessionId: generated.qrData.linkSessionId,
        issuedAtMs: Date.now() - 1_000,
        expiresAtMs: Date.now() + 30_000,
      };
      emitAwaitingTargetPasskey(linkSessionIdRef);
      return await awaitPublishedActivation();
    },
  };
}
