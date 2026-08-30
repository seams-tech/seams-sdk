import { buildSigningOnlyPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import {
  buildActiveWalletAuthorityV1,
  buildPendingWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
} from '@shared/authorization/walletAuthority';
import type {
  ActivateInstalledAuthorityResultV1,
  ActiveWalletSessionV1,
  CommittedAuthorityPackagesV1,
  LinkSessionStateV1,
  LocalAuthorityInstallationReceiptV1,
  VerifiedTargetFactorV1,
  WalletSessionOperationCredentialV1,
} from '@shared/device-linking';
import {
  buildLinkedDeviceWalletSessionCredentialDeliveryBindingV1,
  computeLinkedDeviceWalletSessionCredentialDeliveryAadDigestB64u,
  computeLinkedDeviceWalletSessionCredentialEnvelopeDigestB64u,
  type LinkedDeviceWalletSessionCredentialDeliveryV1,
} from '@shared/device-linking/walletSessionCredentialDelivery';
import {
  parseDeviceId,
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  parseTenantId,
} from '@shared/authorization/capabilityKinds';
import { parseWalletSessionOperationCredentialV1 } from '@shared/device-linking/parsers';
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
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import {
  computeWalletSessionInstallationReceiptDigestB64u,
  computeWalletSessionOperationCredentialDigestB64u,
} from '@shared/device-linking/digests';
import { buildWalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import type { DeviceLinkingAuthorityActivationFlowInputV1 } from '@/SeamsWeb/operations/devices/deviceLinkingAuthorityInstallation';
import type { DeviceLinkingKeyMaterialHandleV1 } from '@/SeamsWeb/operations/devices/deviceLinkingPorts';
import type { WalletAuthoritySignerMaterialRecordV1 } from '@/core/indexedDB';
import {
  buildOrdinaryEd25519ReservationPreparationFixture,
  buildOrdinaryEd25519SignerFixture,
  buildOrdinaryEd25519SignerMaterialRecordFixture,
  buildOrdinaryMaterialActivationFixture,
} from './ordinarySignerMaterialReservation.fixtures';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

export type ResumeFixture = {
  readonly committed: CommittedAuthorityPackagesV1;
  readonly targetFactor: VerifiedTargetFactorV1;
  readonly receipt: LocalAuthorityInstallationReceiptV1;
  readonly signerMaterials: readonly [
    WalletAuthoritySignerMaterialRecordV1,
    ...WalletAuthoritySignerMaterialRecordV1[],
  ];
  readonly active: Extract<ActivateInstalledAuthorityResultV1, { readonly kind: 'active' }>;
  readonly operationCredential: WalletSessionOperationCredentialV1;
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

export async function buildResumeFixture(label: string): Promise<ResumeFixture> {
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
    permissions: buildSigningOnlyPermissionsV1(),
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
  const signerMaterial = buildOrdinaryEd25519SignerMaterialRecordFixture({
    authorityId,
    walletAuthMethodId: authMethodId,
    materialActivation,
    sealedMaterialB64u: 'sealed-material-resume',
    sealedMaterialDigestB64u: digest,
  });
  const preparation = buildOrdinaryEd25519ReservationPreparationFixture(label, materialActivation);
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
        targetBinding: preparation.targetBinding,
        applicationBinding: preparation.applicationBinding,
        activationReceipt: preparation.sourceContribution.activationReceipt,
        deriver_a_client_package: preparation.sourceContribution.deriver_a_client_package,
        deriver_b_client_package: preparation.sourceContribution.deriver_b_client_package,
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
  const walletSessionId = required(parseWalletSessionId(`wallet-session:resume:${label}`));
  const quotaId = required(parseMpcWalletSigningQuotaId(`quota:resume:${label}`));
  const walletSession: ActiveWalletSessionV1 = {
    kind: 'active_wallet_session_v1',
    walletId,
    authorityId,
    authMethodId,
    authorizationId,
    quotaId,
    authorityDigestB64u: digest,
    authorityRevocationEpoch: 0,
    capabilitySubjects: [{ kind: 'sign', keyFamily: 'ed25519', materialActivation }],
    issuedAtMs: 400,
    expiresAtMs: 3_600_400,
  };
  const operationCredential = parseWalletSessionOperationCredentialV1({
    kind: 'opaque_wallet_session_operation_credential_v1',
    token: `wst_${'R'.repeat(43)}`,
    walletSessionId,
  });
  const tenantId = required(parseTenantId(`tenant:resume:${label}`));
  const principalId = required(parsePrincipalId(`linked-device:${String(deviceId)}`));
  const recipientBytes = new Uint8Array(65).fill(12);
  recipientBytes[0] = 4;
  const recipientPublicKey65B64u = base64UrlEncode(recipientBytes);
  const ephemeralBytes = new Uint8Array(65).fill(13);
  ephemeralBytes[0] = 4;
  const sealedEnvelope = {
    kind: 'linked_device_wallet_session_credential_envelope_v1' as const,
    algorithm: 'p256-ecdh-aes256gcm-v1' as const,
    serverEphemeralPublicKey65B64u: base64UrlEncode(ephemeralBytes),
    nonce12B64u: base64UrlEncode(new Uint8Array(12).fill(14)),
    ciphertextB64u: base64UrlEncode(new Uint8Array([15])),
  };
  const installationReceiptDigestB64u =
    await computeWalletSessionInstallationReceiptDigestB64u(receipt);
  const aad = {
    kind: 'linked_device_wallet_session_credential_delivery_aad_v1' as const,
    namespace: 'signer',
    orgId: 'org_test',
    projectId: 'project_test',
    envId: 'env_test',
    tenantId,
    principalId,
    linkSessionId,
    walletId,
    authorityId,
    walletAuthMethodId: authMethodId,
    authorizationId,
    walletSessionId,
    quotaId,
    credentialDigestB64u: await computeWalletSessionOperationCredentialDigestB64u(
      operationCredential,
    ),
    recipientPublicKey65B64u,
    issuedAtMs: walletSession.issuedAtMs,
    expiresAtMs: walletSession.expiresAtMs,
  };
  const recipientBindingDigestB64u = parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(
        alphabetizeStringify({
          domain: 'seams/linked-device/delivery-recipient/v1',
          recipientPublicKey65B64u,
        }),
      ),
    ),
  );
  const sealedDelivery: LinkedDeviceWalletSessionCredentialDeliveryV1 = {
    kind: 'linked_device_wallet_session_credential_delivery_v1',
    aad,
    aadDigestB64u: await computeLinkedDeviceWalletSessionCredentialDeliveryAadDigestB64u(aad),
    recipientBindingDigestB64u,
    envelope: sealedEnvelope,
    envelopeDigestB64u:
      await computeLinkedDeviceWalletSessionCredentialEnvelopeDigestB64u(sealedEnvelope),
    installationReceiptDigestB64u,
  };
  const active: Extract<ActivateInstalledAuthorityResultV1, { readonly kind: 'active' }> = {
    kind: 'active',
    authority: activeAuthority,
    authMethod: activeAuthMethod,
    walletSession,
    deliveryBinding: buildLinkedDeviceWalletSessionCredentialDeliveryBindingV1(aad),
    sealedDelivery,
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
    signerMaterials: [signerMaterial],
    active,
    operationCredential,
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
