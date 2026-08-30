import { expect, test } from '@playwright/test';
import {
  activateLinkedAuthorityV1,
  replayPendingDeviceLinkingAcknowledgementsV1,
  type DeviceLinkingAuthorityActivationFlowInputV1,
} from '@/SeamsWeb/operations/devices/deviceLinkingAuthorityInstallation';
import {
  resumePendingDeviceLinkingAcknowledgementsV1,
  type DeviceLinkingAcknowledgementExactSessionReaderV1,
} from '@/SeamsWeb/operations/devices/deviceLinkingComposition';
import {
  buildDeviceLinkingCommittedResumeV1,
  compareDeviceLinkingCommittedResumeV1,
  type DeviceLinkingCommittedResumeV1,
} from '@/SeamsWeb/operations/devices/deviceLinkingResume';
import type {
  DeviceLinkingAuthorityActivationTransportPortV1,
  DeviceLinkingAuthorityInstallationPortV1,
  DeviceLinkingDeliveryResumePortV1,
  DeviceLinkingWalletSessionAcknowledgementReplayPortV1,
} from '@/SeamsWeb/operations/devices/deviceLinkingPorts';
import type { LocalAuthorityActivationFinalAckV1 } from '@shared/device-linking';
import {
  computeWalletSessionInstallationReceiptDigestB64u,
  computeWalletSessionOperationCredentialDigestB64u,
} from '@shared/device-linking/digests';
import {
  buildResumeFixture,
  type ResumeFixture,
} from './helpers/linkDeviceAuthorityResume.fixtures';
import { sdkEsmPath, setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  indexedDB: sdkEsmPath('core/indexedDB/index.js'),
  installation: sdkEsmPath('SeamsWeb/operations/devices/deviceLinkingAuthorityInstallation.js'),
} as const;

function activationInput(
  fixture: ResumeFixture,
  transport: DeviceLinkingAuthorityActivationTransportPortV1,
  installation: DeviceLinkingAuthorityInstallationPortV1,
): DeviceLinkingAuthorityActivationFlowInputV1 {
  return {
    ...fixture.inputBase,
    transport,
    installation,
    committed: fixture.committed,
    keyMaterialPort: {
      async createBootstrapKeyMaterialV1() {
        throw new Error('bootstrap key material is outside this continuation test');
      },
      async openWalletSessionCredentialDeliveryV1() {
        return fixture.operationCredential;
      },
      async discardKeyMaterialV1() {
        return undefined;
      },
      async signDeviceSessionRequestV1() {
        throw new Error('device-session signing is outside this continuation test');
      },
    },
    deliveryRecipientPublicKey65B64u:
      fixture.active.sealedDelivery.aad.recipientPublicKey65B64u,
  };
}

test.describe('linked-device committed delivery continuation', () => {
  test('projects the committed passkey into durable profile prerequisites before activation', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const fixture = await buildResumeFixture('profile-prerequisites');
    const browserFixture = {
      committed: fixture.committed,
      targetFactor: fixture.targetFactor,
      receipt: fixture.receipt,
      signerMaterials: fixture.signerMaterials,
      keyMaterial: fixture.inputBase.keyMaterial,
      expectedLockGeneration: fixture.inputBase.expectedLockGeneration,
    };
    const persisted = await page.evaluate(
      async ({ paths, fixture }) => {
        const { UnifiedIndexedDBManager } = await import(paths.indexedDB);
        const { createDeviceLinkingAuthorityInstallationPortV1 } = await import(
          paths.installation
        );
        const indexedDB = new UnifiedIndexedDBManager();
        indexedDB.getLocalAuthorityInstallationReceipt = async () => null;

        let profile: unknown = null;
        let authenticator: {
          readonly profileId: string;
          readonly signerSlot: number;
          readonly credentialId: string;
          readonly credentialPublicKey: number[];
          readonly registered: string;
          readonly syncedAt: string;
        } | null = null;
        indexedDB.installLocalAuthority = async (input) => {
          profile = input.profile;
          if (input.authenticator) {
            authenticator = {
              profileId: input.authenticator.profileId,
              signerSlot: input.authenticator.signerSlot,
              credentialId: input.authenticator.credentialId,
              credentialPublicKey: Array.from(input.authenticator.credentialPublicKey),
              registered: input.authenticator.registered,
              syncedAt: input.authenticator.syncedAt,
            };
          }
          return { kind: 'installed', receipt: fixture.receipt };
        };

        const installation = createDeviceLinkingAuthorityInstallationPortV1({
          indexedDB,
          sealing: {
            async sealCommittedAuthorityPackagesV1() {
              return {
                signerMaterials: fixture.signerMaterials,
                exportRoot: null,
                installedRecordSetDigestB64u: fixture.receipt.installedRecordSetDigestB64u,
              };
            },
          },
          nowMs: () => 500,
        });
        const result = await installation.installLocalAuthorityV1({
          committed: fixture.committed,
          targetFactor: fixture.targetFactor,
          keyMaterial: fixture.keyMaterial,
          resealedExportRoot: null,
          expectedLockGeneration: fixture.expectedLockGeneration,
        });
        return { result, profile, authenticator };
      },
      { paths: IMPORT_PATHS, fixture: browserFixture },
    );

    expect(persisted.result).toEqual(fixture.receipt);
    expect(persisted.profile).toEqual({
      profileId: String(fixture.committed.authority.walletId),
      defaultSignerSlot: 1,
      passkeyCredential: {
        id: fixture.committed.authMethod.credentialIdB64u,
        rawId: fixture.committed.authMethod.credentialIdB64u,
      },
    });
    expect(persisted.authenticator).toEqual({
      profileId: String(fixture.committed.authority.walletId),
      signerSlot: 1,
      credentialId: fixture.committed.authMethod.credentialIdB64u,
      credentialPublicKey: Array.from(new Uint8Array(32).fill(11)),
      registered: new Date(100).toISOString(),
      syncedAt: new Date(100).toISOString(),
    });
  });

  test('reuses the exact committed package state after an interrupted local install', async () => {
    const fixture = await buildResumeFixture('install-retry');
    let installAttempts = 0;
    let activationAttempts = 0;
    let persistedResume: DeviceLinkingCommittedResumeV1 | null = null;
    const installation: DeviceLinkingAuthorityInstallationPortV1 = {
      async persistCommittedDeliveryResumeV1(input) {
        persistedResume = buildDeviceLinkingCommittedResumeV1(input);
      },
      async readCommittedDeliveryResumeV1() {
        return persistedResume;
      },
      async clearCommittedDeliveryResumeV1() {
        persistedResume = null;
      },
      async persistPendingActivationAcknowledgementV1() {},
      async readPendingActivationAcknowledgementV1() {
        return null;
      },
      async clearPendingActivationAcknowledgementV1() {},
      async readLocalAuthorityInstallationReceiptV1() {
        return fixture.receipt;
      },
      async installLocalAuthorityV1(input) {
        expect(input.committed).toBe(fixture.committed);
        expect(input.keyMaterial).toBe(fixture.inputBase.keyMaterial);
        installAttempts += 1;
        if (installAttempts === 1) throw new Error('local install interrupted');
        return fixture.receipt;
      },
      async publishLocalAuthorityActivationV1() {},
      async finalizeLocalAuthorityActivationV1() {
        throw new Error('finalization should not run while activation is pending');
      },
    };
    const transport: DeviceLinkingAuthorityActivationTransportPortV1 = {
      async receiveCommittedAuthorityPackagesV1() {
        return fixture.committed;
      },
      async activateInstalledAuthorityV1(input) {
        expect(input.receipt).toBe(fixture.receipt);
        activationAttempts += 1;
        return {
          kind: 'pending_local_install',
          authorityId: fixture.committed.authority.authorityId,
          reason: { kind: 'server_worker_activation_pending' },
        };
      },
      async acknowledgeLocalAuthorityActivationV1() {
        throw new Error('acknowledgement should not run while activation is pending');
      },
    };
    const input = activationInput(fixture, transport, installation);

    await expect(activateLinkedAuthorityV1(input)).rejects.toThrow('local install interrupted');
    await expect(activateLinkedAuthorityV1(input)).resolves.toEqual({
      kind: 'pending_local_install',
      authorityId: fixture.committed.authority.authorityId,
      packageSetDigestB64u: fixture.committed.packageSetDigestB64u,
    });
    expect(installAttempts).toBe(2);
    expect(activationAttempts).toBe(1);
    expect(persistedResume?.authorityId).toBe(fixture.committed.authority.authorityId);
    expect(persistedResume?.packageSetDigestB64u).toBe(fixture.committed.packageSetDigestB64u);
    expect(persistedResume?.signerActivations).toEqual(
      fixture.committed.authority.signerActivations,
    );

    // A new persistence-port context can read only the durable identity. The
    // worker key handle and package plaintext remain unavailable here.
    const reloadedInstallation: DeviceLinkingAuthorityInstallationPortV1 = { ...installation };
    const reloaded = await reloadedInstallation.readCommittedDeliveryResumeV1({
      authorityId: fixture.committed.authority.authorityId,
    });
    expect(reloaded).toEqual(persistedResume);
    if (!reloaded) throw new Error('committed resume descriptor was not persisted');
    expect(
      compareDeviceLinkingCommittedResumeV1({
        resume: reloaded,
        linkSessionId: fixture.inputBase.linkSessionId,
        committed: fixture.committed,
        targetFactor: fixture.targetFactor,
      }),
    ).toBeNull();
  });

  test('retries wallet session issuance against the same durable local install', async () => {
    const fixture = await buildResumeFixture('wallet-session-issuance-retry');
    let persistedResume: DeviceLinkingCommittedResumeV1 | null = null;
    let installAttempts = 0;
    let activationAttempts = 0;
    let finalizationAttempts = 0;
    const installation: DeviceLinkingAuthorityInstallationPortV1 = {
      async persistCommittedDeliveryResumeV1(input) {
        persistedResume = buildDeviceLinkingCommittedResumeV1(input);
      },
      async readCommittedDeliveryResumeV1() {
        return persistedResume;
      },
      async clearCommittedDeliveryResumeV1() {
        persistedResume = null;
      },
      async persistPendingActivationAcknowledgementV1() {},
      async readPendingActivationAcknowledgementV1() {
        return null;
      },
      async clearPendingActivationAcknowledgementV1() {},
      async readLocalAuthorityInstallationReceiptV1() {
        return fixture.receipt;
      },
      async installLocalAuthorityV1(input) {
        expect(input.committed).toBe(fixture.committed);
        installAttempts += 1;
        return fixture.receipt;
      },
      async publishLocalAuthorityActivationV1() {},
      async finalizeLocalAuthorityActivationV1(input) {
        expect(input.active).toBe(fixture.active);
        finalizationAttempts += 1;
      },
    };
    const transport: DeviceLinkingAuthorityActivationTransportPortV1 = {
      async receiveCommittedAuthorityPackagesV1() {
        return fixture.committed;
      },
      async activateInstalledAuthorityV1(input) {
        expect(input.receipt).toBe(fixture.receipt);
        activationAttempts += 1;
        return activationAttempts === 1
          ? {
              kind: 'pending_local_install',
              authorityId: fixture.committed.authority.authorityId,
              reason: { kind: 'wallet_session_issuance_pending' },
            }
          : fixture.active;
      },
      async acknowledgeLocalAuthorityActivationV1() {
        throw new Error('acknowledgement is outside authority activation');
      },
    };
    const input = activationInput(fixture, transport, installation);

    await expect(activateLinkedAuthorityV1(input)).resolves.toEqual({
      kind: 'pending_local_install',
      authorityId: fixture.committed.authority.authorityId,
      packageSetDigestB64u: fixture.committed.packageSetDigestB64u,
    });
    expect(finalizationAttempts).toBe(0);
    expect(persistedResume?.authorityId).toBe(fixture.committed.authority.authorityId);

    await expect(activateLinkedAuthorityV1(input)).resolves.toEqual({
      kind: 'active',
      session: fixture.active.walletSession,
      operationCredential: fixture.operationCredential,
    });
    expect(installAttempts).toBe(2);
    expect(activationAttempts).toBe(2);
    expect(finalizationAttempts).toBe(1);
    expect(persistedResume?.packageSetDigestB64u).toBe(
      fixture.committed.packageSetDigestB64u,
    );
  });

  test('replays the retained receipt after an interruption during local finalization', async () => {
    const fixture = await buildResumeFixture('finalize-retry');
    let installAttempts = 0;
    let activationAttempts = 0;
    let finalizationAttempts = 0;
    let acknowledgementAttempts = 0;
    let persistedResume: DeviceLinkingCommittedResumeV1 | null = null;
    const installation: DeviceLinkingAuthorityInstallationPortV1 = {
      async persistCommittedDeliveryResumeV1(input) {
        persistedResume = buildDeviceLinkingCommittedResumeV1(input);
      },
      async readCommittedDeliveryResumeV1() {
        return persistedResume;
      },
      async clearCommittedDeliveryResumeV1() {
        persistedResume = null;
      },
      async persistPendingActivationAcknowledgementV1() {},
      async readPendingActivationAcknowledgementV1() {
        return null;
      },
      async clearPendingActivationAcknowledgementV1() {},
      async readLocalAuthorityInstallationReceiptV1() {
        return fixture.receipt;
      },
      async installLocalAuthorityV1(input) {
        expect(input.committed).toBe(fixture.committed);
        installAttempts += 1;
        return fixture.receipt;
      },
      async publishLocalAuthorityActivationV1() {},
      async finalizeLocalAuthorityActivationV1(input) {
        expect(input.active).toBe(fixture.active);
        finalizationAttempts += 1;
        if (finalizationAttempts === 1) throw new Error('local finalization interrupted');
      },
    };
    const transport: DeviceLinkingAuthorityActivationTransportPortV1 = {
      async receiveCommittedAuthorityPackagesV1() {
        return fixture.committed;
      },
      async activateInstalledAuthorityV1(input) {
        expect(input.receipt).toBe(fixture.receipt);
        activationAttempts += 1;
        return fixture.active;
      },
      async acknowledgeLocalAuthorityActivationV1(input) {
        expect(input.acknowledgement.authorityId).toBe(fixture.committed.authority.authorityId);
        expect(input.acknowledgement.packageSetDigestB64u).toBe(
          fixture.committed.packageSetDigestB64u,
        );
        acknowledgementAttempts += 1;
      },
    };
    const input = activationInput(fixture, transport, installation);

    await expect(activateLinkedAuthorityV1(input)).rejects.toThrow(
      'local finalization interrupted',
    );
    await expect(activateLinkedAuthorityV1(input)).resolves.toEqual({
      kind: 'active',
      session: fixture.active.walletSession,
      operationCredential: fixture.operationCredential,
    });
    expect(installAttempts).toBe(2);
    expect(activationAttempts).toBe(2);
    expect(finalizationAttempts).toBe(2);
    // Acknowledgement is persisted and sent by the owning link flow after this
    // activation helper returns the decrypted credential.
    expect(acknowledgementAttempts).toBe(0);
    expect(persistedResume).not.toBeNull();
  });

  test('replays a durable acknowledgement after recipient-handle loss and page reload', async () => {
    const fixture = await buildResumeFixture('bootstrap-replay');
    const acknowledgement: LocalAuthorityActivationFinalAckV1 = {
      kind: 'local_authority_activation_final_ack_v1',
      linkSessionId: fixture.inputBase.linkSessionId,
      authorityId: fixture.active.authority.authorityId,
      packageSetDigestB64u: fixture.committed.packageSetDigestB64u,
      authorizationId: fixture.active.walletSession.authorizationId,
      walletSessionId: fixture.active.walletSession.walletSessionId,
      credentialDigestB64u: await computeWalletSessionOperationCredentialDigestB64u(
        fixture.operationCredential,
      ),
      installationReceiptDigestB64u: await computeWalletSessionInstallationReceiptDigestB64u(
        fixture.receipt,
      ),
      acknowledgedAtMs: 500,
    };
    let pending = [acknowledgement];
    let resumes = [
      buildDeviceLinkingCommittedResumeV1({
        linkSessionId: fixture.inputBase.linkSessionId,
        committed: fixture.committed,
        targetFactor: fixture.targetFactor,
        committedAtMs: fixture.receipt.installedAtMs,
      }),
    ];
    let transportCalls = 0;
    const installation: DeviceLinkingDeliveryResumePortV1 = {
      async listCommittedDeliveryResumesV1() {
        return resumes;
      },
      async listPendingActivationAcknowledgementsV1() {
        return pending;
      },
      async clearCommittedDeliveryResumeV1({ authorityId }) {
        resumes = resumes.filter((resume) => resume.authorityId !== authorityId);
      },
      async clearPendingActivationAcknowledgementV1({ authorityId }) {
        pending = pending.filter((ack) => ack.authorityId !== authorityId);
      },
    };
    const transport: DeviceLinkingWalletSessionAcknowledgementReplayPortV1 = {
      async acknowledgeLocalAuthorityActivationWithWalletSessionV1(input) {
        transportCalls += 1;
        expect(input.acknowledgement).toEqual(acknowledgement);
        expect(input.operationCredential).toBe(fixture.operationCredential);
      },
    };
    let exactSessionAvailable = false;
    const readExactSession: DeviceLinkingAcknowledgementExactSessionReaderV1 = async (input) => {
      expect(input).toEqual({
        walletId: fixture.committed.authority.walletId,
        authorityId: fixture.committed.authority.authorityId,
        authMethodId: fixture.committed.authMethod.walletAuthMethodId,
      });
      return exactSessionAvailable
        ? { kind: 'found', operationCredential: fixture.operationCredential }
        : { kind: 'missing' };
    };

    await expect(
      resumePendingDeviceLinkingAcknowledgementsV1({
        installation,
        transport,
        readExactSession,
      }),
    ).resolves.toBeUndefined();
    expect(transportCalls).toBe(0);
    expect(pending).toEqual([acknowledgement]);
    expect(resumes).toHaveLength(1);

    exactSessionAvailable = true;
    await expect(
      resumePendingDeviceLinkingAcknowledgementsV1({
        installation,
        transport,
        readExactSession,
      }),
    ).resolves.toBeUndefined();
    expect(transportCalls).toBe(1);
    expect(pending).toEqual([]);
    expect(resumes).toEqual([]);
    await expect(
      replayPendingDeviceLinkingAcknowledgementsV1({
        installation,
        transport,
        walletId: fixture.committed.authority.walletId,
        authorityId: fixture.committed.authority.authorityId,
        authMethodId: fixture.committed.authMethod.walletAuthMethodId,
        operationCredential: fixture.operationCredential,
      }),
    ).resolves.toEqual({ kind: 'none' });
    expect(transportCalls).toBe(1);
  });
});
