import { expect, test } from '@playwright/test';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import {
  buildActiveWalletAuthorityV1,
  buildPendingWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
} from '@shared/authorization/walletAuthority';
import {
  type ActivateInstalledAuthorityResultV1,
  type ActiveWalletSessionV1,
  type CommittedAuthorityPackagesV1,
  type LinkSessionStateV1,
  type LocalAuthorityInstallationReceiptV1,
  type VerifiedTargetFactorV1,
} from '@shared/device-linking';
import {
  parseDeviceId,
  parseWalletSessionAuthorizationId,
} from '@shared/authorization/capabilityKinds';
import { parseExactAdministeredSignerManifestV1 } from '@shared/device-linking/delegatedActivationPlan';
import {
  parseLinkDeviceSessionId,
  parseLinkedDeviceEnrollmentId,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { buildWalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import {
  activateLinkedAuthorityV1,
  type DeviceLinkingAuthorityActivationFlowInputV1,
} from '@/SeamsWeb/operations/devices/deviceLinkingAuthorityInstallation';
import {
  buildDeviceLinkingCommittedResumeV1,
  compareDeviceLinkingCommittedResumeV1,
  type DeviceLinkingCommittedResumeV1,
} from '@/SeamsWeb/operations/devices/deviceLinkingResume';
import type {
  DeviceLinkingAuthorityActivationTransportPortV1,
  DeviceLinkingAuthorityInstallationPortV1,
  DeviceLinkingKeyMaterialHandleV1,
} from '@/SeamsWeb/operations/devices/deviceLinkingPorts';
import {
  buildOrdinaryEd25519ActivationReceiptFixture,
  buildOrdinaryEd25519ClientMaterialFixture,
  buildOrdinaryEd25519SignerFixture,
  buildOrdinaryMaterialActivationFixture,
} from './helpers/ordinarySignerMaterialReservation.fixtures';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

type ResumeFixture = {
  readonly committed: CommittedAuthorityPackagesV1;
  readonly targetFactor: VerifiedTargetFactorV1;
  readonly receipt: LocalAuthorityInstallationReceiptV1;
  readonly active: Extract<ActivateInstalledAuthorityResultV1, { readonly kind: 'active' }>;
  readonly inputBase: Pick<
    DeviceLinkingAuthorityActivationFlowInputV1,
    | 'linkSessionId'
    | 'targetFactor'
    | 'keyMaterial'
    | 'resealedExportRoot'
    | 'expectedLockGeneration'
    | 'nowMs'
    | 'sessionState'
  >;
};

function buildResumeFixture(label: string): ResumeFixture {
  const walletId = required(parseWalletId(`wallet:ordinary-reservation:${label}`));
  const authorityId = required(parseWalletAuthorityId(`authority:resume:${label}`));
  const authMethodId = required(parseWalletAuthMethodId(`passkey:wallet.example.test:${label}`));
  const deviceId = required(parseDeviceId(`device:resume:${label}`));
  const enrollmentId = required(parseLinkedDeviceEnrollmentId(`enrollment:resume:${label}`));
  const linkSessionId = required(parseLinkDeviceSessionId(`link-session:resume:${label}`));
  const sourceAuthorityId = required(parseWalletAuthorityId(`authority:source:${label}`));
  const signer = buildOrdinaryEd25519SignerFixture(label);
  const materialActivation = buildOrdinaryMaterialActivationFixture(label);
  const manifest = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ed25519'],
    signers: [
      {
        kind: 'exact_administered_ed25519_signer_v1',
        keyFamily: 'ed25519',
        walletId,
        walletKeyId: signer.walletKeyId,
        registeredPublicKeyB64u: signer.registeredPublicKeyB64u,
      },
    ],
  });
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest,
    materialActivations: { keyFamilies: ['ed25519'], ed25519: materialActivation },
  });
  const digest = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(9)));
  const pendingAuthority = buildPendingWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId,
    walletId,
    principal: { kind: 'owner_device', deviceId },
    provenance: {
      kind: 'device_link',
      enrollmentId,
      sourceAuthorityId,
      linkSessionId,
    },
    permissions: buildFullOwnerPermissionsV1(),
    signerActivations,
    signerActivationSetDigestB64u: digest,
    authorityDigestB64u: digest,
    revocationEpoch: 0,
    createdAtMs: 100,
    updatedAtMs: 100,
    state: 'pending_local_install',
    localInstallPackageSetDigestB64u: digest,
  });
  const rpId = required(parseWebAuthnRpId('wallet.example.test'));
  const credentialIdB64u = required(
    parseWebAuthnCredentialIdB64u(base64UrlEncode(new Uint8Array(32).fill(10))),
  );
  const pendingAuthMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: authMethodId,
    walletId,
    walletAuthorityId: authorityId,
    kind: 'passkey',
    status: 'pending_local_install',
    rpId,
    credentialIdB64u,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(11)),
    counter: 0,
    createdAtMs: 100,
    updatedAtMs: 100,
  });
  if (pendingAuthMethod.status !== 'pending_local_install') {
    throw new Error('resume fixture auth method is not pending');
  }
  const clientMaterial = buildOrdinaryEd25519ClientMaterialFixture(label);
  const committed: CommittedAuthorityPackagesV1 = {
    kind: 'committed_authority_packages_v1',
    authority: pendingAuthority,
    authMethod: pendingAuthMethod,
    signerPackages: {
      kind: 'committed_signer_package_set_v1',
      keyFamilies: ['ed25519'],
      ed25519: {
        kind: 'committed_ed25519_signer_package_v1',
        materialActivation,
        participantIds: [1, 2],
        activationReceipt: buildOrdinaryEd25519ActivationReceiptFixture(label, materialActivation),
        deriver_a_client_package: clientMaterial.deriver_a_client_package,
        deriver_b_client_package: clientMaterial.deriver_b_client_package,
      },
    },
    ed25519ExportRootPackage: null,
    packageSetDigestB64u: digest,
  };
  const targetFactor: VerifiedTargetFactorV1 = {
    kind: 'verified_passkey_target_v1',
    authMethod: {
      walletAuthMethodId: authMethodId,
      walletId,
      createdAtMs: 100,
      kind: 'passkey',
      rpId,
      credentialIdB64u,
      credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(11)),
      counter: 0,
    },
    verificationDigestB64u: digest,
    verifiedAtMs: 200,
  };
  const receipt: LocalAuthorityInstallationReceiptV1 = {
    kind: 'local_authority_installation_receipt_v1',
    authorityId,
    walletId,
    authMethodId,
    deviceId,
    packageSetDigestB64u: digest,
    installedActivationRefs: signerActivations,
    installedRecordSetDigestB64u: digest,
    targetFactorVerificationDigestB64u: digest,
    installedAtMs: 300,
  };
  const activeAuthority = buildActiveWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId,
    walletId,
    principal: { kind: 'owner_device', deviceId },
    provenance: pendingAuthority.provenance,
    permissions: pendingAuthority.permissions,
    signerActivations,
    signerActivationSetDigestB64u: digest,
    authorityDigestB64u: digest,
    revocationEpoch: 0,
    createdAtMs: 100,
    updatedAtMs: 400,
    state: 'active',
    activatedAtMs: 400,
  });
  const activeAuthMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: authMethodId,
    walletId,
    walletAuthorityId: authorityId,
    kind: 'passkey',
    status: 'active',
    rpId,
    credentialIdB64u,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(11)),
    counter: 0,
    createdAtMs: 100,
    updatedAtMs: 400,
    activatedAtMs: 400,
  });
  if (activeAuthMethod.status !== 'active')
    throw new Error('resume fixture auth method is not active');
  const authorizationId = required(
    parseWalletSessionAuthorizationId(`wallet-session:resume:${label}`),
  );
  const walletSession: ActiveWalletSessionV1 = {
    kind: 'active_wallet_session_v1',
    walletId,
    authorityId,
    authMethodId,
    authorizationId,
    authorityDigestB64u: digest,
    authorityRevocationEpoch: 0,
    capabilitySubjects: [{ kind: 'sign', keyFamily: 'ed25519', materialActivation }],
    issuedAtMs: 400,
    expiresAtMs: 3_600_400,
  };
  const active: Extract<ActivateInstalledAuthorityResultV1, { readonly kind: 'active' }> = {
    kind: 'active',
    authority: activeAuthority,
    authMethod: activeAuthMethod,
    walletSession,
  };
  const keyMaterial: DeviceLinkingKeyMaterialHandleV1 = {
    kind: 'device_linking_key_material_handle_v1',
    handleId: `resume-${label}`,
  };
  const sessionState: Extract<LinkSessionStateV1, { readonly state: 'provisioning' }> = {
    state: 'provisioning',
    deviceId,
  };
  return {
    committed,
    targetFactor,
    receipt,
    active,
    inputBase: {
      linkSessionId,
      targetFactor,
      keyMaterial,
      resealedExportRoot: null,
      expectedLockGeneration: 7,
      nowMs: () => 500,
      sessionState,
    },
  };
}

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
  };
}

test.describe('linked-device committed delivery continuation', () => {
  test('reuses the exact committed package state after an interrupted local install', async () => {
    const fixture = buildResumeFixture('install-retry');
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
      async installLocalAuthorityV1(input) {
        expect(input.committed).toBe(fixture.committed);
        expect(input.keyMaterial).toBe(fixture.inputBase.keyMaterial);
        installAttempts += 1;
        if (installAttempts === 1) throw new Error('local install interrupted');
        return fixture.receipt;
      },
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

  test('replays the retained receipt after an interruption during local finalization', async () => {
    const fixture = buildResumeFixture('finalize-retry');
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
      async installLocalAuthorityV1(input) {
        expect(input.committed).toBe(fixture.committed);
        installAttempts += 1;
        return fixture.receipt;
      },
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
    });
    expect(installAttempts).toBe(2);
    expect(activationAttempts).toBe(2);
    expect(finalizationAttempts).toBe(2);
    expect(acknowledgementAttempts).toBe(1);
    expect(persistedResume).toBeNull();
  });
});
