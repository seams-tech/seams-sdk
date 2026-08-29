import type {
  ActivateInstalledAuthorityResultV1,
  CommittedAuthorityPackagesV1,
  LinkIntegrityFailureV1,
  LinkSessionStateV1,
  LinkedAuthorityActivationResultV1,
  LocalAuthorityInstallationReceiptV1,
  VerifiedTargetFactorV1,
} from '@shared/device-linking';
import {
  computeWalletSessionInstallationReceiptDigestB64u,
  computeWalletSessionOperationCredentialDigestB64u,
} from '@shared/device-linking/digests';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { LinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { encodeWalletSignerActivationSetV1 } from '@shared/authorization/walletAuthority';
import type {
  LocalAuthorityActivationFinalizationInputV1,
  LocalWalletAuthMethodRecord,
  ProfileAuthenticatorRecord,
  UpsertProfileInput,
  WalletAuthorityExportRootRecordV1,
  WalletAuthoritySignerMaterialRecordV1,
} from '@/core/indexedDB';
import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { base64UrlDecode } from '@shared/utils/base64';
import { buildEmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type {
  DeviceLinkingAuthorityActivationTransportPortV1,
  DeviceLinkingKeyMaterialHandleV1,
} from './deviceLinkingPorts';
import type { DeviceLinkingResealedEd25519ExportRootV1 } from './deviceLinkingEd25519ExportRoot';
import {
  buildDeviceLinkingCommittedResumeV1,
  committedResumeAppStateKeyV1,
  compareDeviceLinkingCommittedResumeV1,
  parseDeviceLinkingCommittedResumeV1,
  type DeviceLinkingCommittedResumeV1,
} from './deviceLinkingResume';

export type DeviceLinkingSealedAuthorityRecordsV1 = {
  readonly signerMaterials: readonly [
    WalletAuthoritySignerMaterialRecordV1,
    ...WalletAuthoritySignerMaterialRecordV1[],
  ];
  readonly exportRoot: WalletAuthorityExportRootRecordV1 | null;
  readonly installedRecordSetDigestB64u: ReturnType<typeof parseDigestB64u>;
};

/**
 * The worker owns package decryption and factor sealing. The browser receives
 * only already-sealed persistence records at this boundary.
 */
export type DeviceLinkingCommittedPackageSealingPortV1 = {
  sealCommittedAuthorityPackagesV1(input: {
    readonly committed: CommittedAuthorityPackagesV1;
    readonly targetFactor: VerifiedTargetFactorV1;
    readonly keyMaterial: DeviceLinkingKeyMaterialHandleV1;
    /** Produced by the custody worker's open-and-reseal operation. */
    readonly resealedExportRoot: DeviceLinkingResealedEd25519ExportRootV1 | null;
  }): Promise<DeviceLinkingSealedAuthorityRecordsV1>;
};

export type DeviceLinkingAuthorityInstallationPortV1 = {
  persistCommittedDeliveryResumeV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly committed: CommittedAuthorityPackagesV1;
    readonly targetFactor: VerifiedTargetFactorV1;
    readonly committedAtMs: number;
  }): Promise<void>;
  readCommittedDeliveryResumeV1(input: {
    readonly authorityId: CommittedAuthorityPackagesV1['authority']['authorityId'];
  }): Promise<DeviceLinkingCommittedResumeV1 | null>;
  clearCommittedDeliveryResumeV1(input: {
    readonly authorityId: CommittedAuthorityPackagesV1['authority']['authorityId'];
  }): Promise<void>;
  installLocalAuthorityV1(input: {
    readonly committed: CommittedAuthorityPackagesV1;
    readonly targetFactor: VerifiedTargetFactorV1;
    readonly keyMaterial: DeviceLinkingKeyMaterialHandleV1;
    readonly resealedExportRoot: DeviceLinkingResealedEd25519ExportRootV1 | null;
    readonly expectedLockGeneration: number;
  }): Promise<LocalAuthorityInstallationReceiptV1>;
  finalizeLocalAuthorityActivationV1(input: {
    readonly active: Extract<ActivateInstalledAuthorityResultV1, { readonly kind: 'active' }>;
    readonly expectedLockGeneration: number;
  }): Promise<void>;
};

export type DeviceLinkingAuthorityInstallationAssemblyOptionsV1 = {
  readonly indexedDB: UnifiedIndexedDBManager;
  readonly sealing: DeviceLinkingCommittedPackageSealingPortV1;
  readonly nowMs: () => number;
};

export type DeviceLinkingAuthorityActivationFlowInputV1 = {
  readonly transport: DeviceLinkingAuthorityActivationTransportPortV1;
  readonly committed: CommittedAuthorityPackagesV1;
  readonly installation: DeviceLinkingAuthorityInstallationPortV1;
  readonly sessionState: Extract<
    LinkSessionStateV1,
    { readonly state: 'provisioning' | 'authority_pending_local_install' | 'active' }
  >;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly targetFactor: VerifiedTargetFactorV1;
  readonly keyMaterial: DeviceLinkingKeyMaterialHandleV1;
  readonly resealedExportRoot: DeviceLinkingResealedEd25519ExportRootV1 | null;
  readonly expectedLockGeneration: number;
  readonly nowMs: () => number;
};

type LocalAuthorityProfileProjectionV1 = {
  readonly profile: UpsertProfileInput;
  readonly authenticator: ProfileAuthenticatorRecord | null;
  readonly localAuthMethod: Extract<LocalWalletAuthMethodRecord, { kind: 'email_otp' }> | null;
};

function localAuthorityProfileProjectionV1(
  authMethod: CommittedAuthorityPackagesV1['authMethod'],
  targetFactor: VerifiedTargetFactorV1,
): LocalAuthorityProfileProjectionV1 {
  const profileId = String(authMethod.walletId);
  switch (authMethod.kind) {
    case 'passkey': {
      const credentialId = String(authMethod.credentialIdB64u);
      return {
        profile: {
          profileId,
          defaultSignerSlot: 1,
          passkeyCredential: { id: credentialId, rawId: credentialId },
        },
        authenticator: {
          profileId,
          signerSlot: 1,
          credentialId,
          credentialPublicKey: base64UrlDecode(authMethod.credentialPublicKeyB64u),
          registered: new Date(authMethod.createdAtMs).toISOString(),
          syncedAt: new Date(authMethod.updatedAtMs).toISOString(),
        },
        localAuthMethod: null,
      };
    }
    case 'email_otp': {
      if (
        targetFactor.kind !== 'verified_email_otp_target_v1' ||
        targetFactor.authMethod.walletAuthMethodId !== authMethod.walletAuthMethodId ||
        targetFactor.authMethod.walletId !== authMethod.walletId ||
        targetFactor.authMethod.emailHashHex !== authMethod.emailHashHex ||
        targetFactor.authMethod.registrationAuthorityId !== authMethod.registrationAuthorityId
      ) {
        throw new Error('linked Email OTP target factor does not match the committed auth method');
      }
      const baseAuthority = buildEmailOtpWalletAuthAuthority({
        walletId: authMethod.walletId,
        provider: targetFactor.enrollment.kind === 'existing_enrollment' ? 'google' : 'email',
        providerUserId: targetFactor.providerUserId,
        emailHashHex: authMethod.emailHashHex,
      });
      return {
        profile: { profileId, defaultSignerSlot: 1 },
        authenticator: null,
        localAuthMethod: {
          version: 'wallet_auth_method_v1',
          kind: 'email_otp',
          status: 'active',
          localStatus: 'synced',
          walletId: authMethod.walletId,
          emailHashHex: authMethod.emailHashHex,
          registrationAuthorityId: authMethod.registrationAuthorityId,
          authority: {
            walletId: baseAuthority.walletId,
            factor: baseAuthority.factor,
            verifier: baseAuthority.verifier,
            bindingId: authMethod.walletAuthMethodId,
          },
          createdAtMs: authMethod.createdAtMs,
          updatedAtMs: authMethod.updatedAtMs,
        },
      };
    }
    default: {
      const _exhaustive: never = authMethod;
      throw new Error(`Unsupported linked-device auth method: ${String(_exhaustive)}`);
    }
  }
}

export function createDeviceLinkingAuthorityInstallationPortV1(
  options: DeviceLinkingAuthorityInstallationAssemblyOptionsV1,
): DeviceLinkingAuthorityInstallationPortV1 {
  return {
    persistCommittedDeliveryResumeV1: async (input) => {
      const resume = buildDeviceLinkingCommittedResumeV1(input);
      await options.indexedDB.setAppState(committedResumeAppStateKeyV1(resume.authorityId), resume);
    },
    readCommittedDeliveryResumeV1: async ({ authorityId }) =>
      parseDeviceLinkingCommittedResumeV1(
        await options.indexedDB.getAppState<unknown>(committedResumeAppStateKeyV1(authorityId)),
      ),
    clearCommittedDeliveryResumeV1: async ({ authorityId }) => {
      await options.indexedDB.setAppState(committedResumeAppStateKeyV1(authorityId), null);
    },
    installLocalAuthorityV1: (input) => installLocalAuthorityV1({ ...input, ...options }),
    finalizeLocalAuthorityActivationV1: ({ active, expectedLockGeneration }) =>
      finalizeLocalAuthorityActivationV1({
        indexedDB: options.indexedDB,
        active,
        expectedLockGeneration,
      }),
  };
}

export async function installLocalAuthorityV1(input: {
  readonly indexedDB: UnifiedIndexedDBManager;
  readonly sealing: DeviceLinkingCommittedPackageSealingPortV1;
  readonly nowMs: () => number;
  readonly committed: CommittedAuthorityPackagesV1;
  readonly targetFactor: VerifiedTargetFactorV1;
  readonly keyMaterial: DeviceLinkingKeyMaterialHandleV1;
  readonly resealedExportRoot: DeviceLinkingResealedEd25519ExportRootV1 | null;
  readonly expectedLockGeneration: number;
}): Promise<LocalAuthorityInstallationReceiptV1> {
  const existingReceipt = await input.indexedDB.getLocalAuthorityInstallationReceipt(
    input.committed.authority.authorityId,
  );
  if (existingReceipt) {
    assertReceiptMatchesCommitted({
      committed: input.committed,
      targetFactor: input.targetFactor,
      receipt: existingReceipt,
    });
    return existingReceipt;
  }
  const sealed = await input.sealing.sealCommittedAuthorityPackagesV1({
    committed: input.committed,
    targetFactor: input.targetFactor,
    keyMaterial: input.keyMaterial,
    resealedExportRoot: input.resealedExportRoot,
  });
  assertSealedAuthorityRecordsMatchCommitted({ committed: input.committed, sealed });
  const localProfileProjection = localAuthorityProfileProjectionV1(
    input.committed.authMethod,
    input.targetFactor,
  );
  const installedAtMs = input.nowMs();
  if (!Number.isSafeInteger(installedAtMs) || installedAtMs <= 0) {
    throw new Error('local authority installation clock is invalid');
  }
  const receipt: LocalAuthorityInstallationReceiptV1 = {
    kind: 'local_authority_installation_receipt_v1',
    authorityId: input.committed.authority.authorityId,
    walletId: input.committed.authority.walletId,
    authMethodId: input.committed.authMethod.walletAuthMethodId,
    deviceId: input.committed.authority.principal.deviceId,
    packageSetDigestB64u: input.committed.packageSetDigestB64u,
    installedActivationRefs: input.committed.authority.signerActivations,
    installedRecordSetDigestB64u: sealed.installedRecordSetDigestB64u,
    targetFactorVerificationDigestB64u: input.targetFactor.verificationDigestB64u,
    installedAtMs,
  };
  const result = await input.indexedDB.installLocalAuthority({
    authority: input.committed.authority,
    authMethod: input.committed.authMethod,
    profile: localProfileProjection.profile,
    authenticator: localProfileProjection.authenticator,
    localAuthMethod: localProfileProjection.localAuthMethod,
    signerMaterials: sealed.signerMaterials,
    exportRoot: sealed.exportRoot,
    receipt,
    expectedLockGeneration: input.expectedLockGeneration,
  });
  switch (result.kind) {
    case 'installed':
    case 'idempotent_replay':
      return result.receipt;
    case 'stale_lock_generation':
      throw new Error(
        `local authority installation lock generation is stale (expected ${result.expectedLockGeneration}, actual ${result.actualLockGeneration})`,
      );
    case 'integrity_error':
      throw new Error(`local authority installation integrity error: ${result.reason}`);
  }
}

export async function finalizeLocalAuthorityActivationV1(input: {
  readonly indexedDB: UnifiedIndexedDBManager;
  readonly active: Extract<ActivateInstalledAuthorityResultV1, { readonly kind: 'active' }>;
  readonly expectedLockGeneration: number;
}): Promise<void> {
  const finalization: LocalAuthorityActivationFinalizationInputV1 = {
    authority: input.active.authority,
    authMethod: input.active.authMethod,
    walletSession: input.active.walletSession,
    operationCredential: input.active.operationCredential,
    expectedLockGeneration: input.expectedLockGeneration,
  };
  const result = await input.indexedDB.finalizeLocalAuthorityActivation(finalization);
  switch (result.kind) {
    case 'finalized':
      return;
    case 'stale_lock_generation':
      throw new Error(
        `local authority activation lock generation is stale (expected ${result.expectedLockGeneration}, actual ${result.actualLockGeneration})`,
      );
    case 'wallet_locked':
      throw new Error(
        `local authority activation refused while wallet is locked at generation ${result.lockGeneration}`,
      );
    default:
      result satisfies never;
      throw new Error('local authority activation returned an unknown result');
  }
}

export async function activateLinkedAuthorityV1(
  input: DeviceLinkingAuthorityActivationFlowInputV1,
): Promise<LinkedAuthorityActivationResultV1> {
  const committedStateResult = assertCommittedAuthorityStateMatchesSession({
    committed: input.committed,
    sessionState: input.sessionState,
  });
  if (committedStateResult) return committedStateResult;
  const durableResume = await input.installation.readCommittedDeliveryResumeV1({
    authorityId: input.committed.authority.authorityId,
  });
  if (durableResume) {
    const mismatch = compareDeviceLinkingCommittedResumeV1({
      resume: durableResume,
      linkSessionId: input.linkSessionId,
      committed: input.committed,
      targetFactor: input.targetFactor,
    });
    if (mismatch) return { kind: 'integrity_error', reason: mismatch };
  } else {
    await input.installation.persistCommittedDeliveryResumeV1({
      linkSessionId: input.linkSessionId,
      committed: input.committed,
      targetFactor: input.targetFactor,
      committedAtMs: input.nowMs(),
    });
  }
  const receipt = await input.installation.installLocalAuthorityV1({
    committed: input.committed,
    targetFactor: input.targetFactor,
    keyMaterial: input.keyMaterial,
    resealedExportRoot: input.resealedExportRoot,
    expectedLockGeneration: input.expectedLockGeneration,
  });
  const active = await input.transport.activateInstalledAuthorityV1({
    linkSessionId: input.linkSessionId,
    receipt,
  });
  switch (active.kind) {
    case 'pending_local_install':
      return {
        kind: 'pending_local_install',
        authorityId: active.authorityId,
        packageSetDigestB64u: receipt.packageSetDigestB64u,
      };
    case 'integrity_error':
      return active;
    case 'active': {
      const activationReceiptResult = assertActivationResultMatchesReceipt({
        active,
        receipt,
      });
      if (activationReceiptResult) return activationReceiptResult;
      await input.installation.finalizeLocalAuthorityActivationV1({
        active,
        expectedLockGeneration: input.expectedLockGeneration,
      });
      const acknowledgedAtMs = input.nowMs();
      if (!Number.isSafeInteger(acknowledgedAtMs) || acknowledgedAtMs <= 0) {
        throw new Error('local authority activation acknowledgement clock is invalid');
      }
      await input.transport.acknowledgeLocalAuthorityActivationV1({
        acknowledgement: {
          kind: 'local_authority_activation_final_ack_v1',
          linkSessionId: input.linkSessionId,
          authorityId: active.authority.authorityId,
          packageSetDigestB64u: receipt.packageSetDigestB64u,
          authorizationId: active.walletSession.authorizationId,
          walletSessionId: active.operationCredential.walletSessionId,
          credentialDigestB64u: await computeWalletSessionOperationCredentialDigestB64u(
            active.operationCredential,
          ),
          installationReceiptDigestB64u:
            await computeWalletSessionInstallationReceiptDigestB64u(receipt),
          acknowledgedAtMs,
        },
      });
      await input.installation.clearCommittedDeliveryResumeV1({
        authorityId: active.authority.authorityId,
      });
      return {
        kind: 'active',
        session: active.walletSession,
        operationCredential: active.operationCredential,
      };
    }
  }
}

function assertCommittedAuthorityStateMatchesSession(input: {
  readonly committed: CommittedAuthorityPackagesV1;
  readonly sessionState: Extract<
    LinkSessionStateV1,
    { readonly state: 'provisioning' | 'authority_pending_local_install' | 'active' }
  >;
}): { readonly kind: 'integrity_error'; readonly reason: LinkIntegrityFailureV1 } | null {
  if (input.sessionState.state === 'provisioning') return null;
  if (input.committed.authority.authorityId !== input.sessionState.authorityId) {
    return {
      kind: 'integrity_error',
      reason: {
        kind: 'authority_id_mismatch',
        expectedAuthorityId: input.sessionState.authorityId,
        actualAuthorityId: input.committed.authority.authorityId,
      },
    };
  }
  if (
    input.sessionState.state !== 'active' &&
    input.committed.packageSetDigestB64u !== input.sessionState.packageSetDigestB64u
  ) {
    return {
      kind: 'integrity_error',
      reason: {
        kind: 'package_set_digest_mismatch',
        expectedPackageSetDigestB64u: input.sessionState.packageSetDigestB64u,
        actualPackageSetDigestB64u: input.committed.packageSetDigestB64u,
      },
    };
  }
  return null;
}

function assertActivationResultMatchesReceipt(input: {
  readonly active: Extract<ActivateInstalledAuthorityResultV1, { readonly kind: 'active' }>;
  readonly receipt: LocalAuthorityInstallationReceiptV1;
}): { readonly kind: 'integrity_error'; readonly reason: LinkIntegrityFailureV1 } | null {
  if (input.active.authority.authorityId !== input.receipt.authorityId) {
    return {
      kind: 'integrity_error',
      reason: {
        kind: 'authority_id_mismatch',
        expectedAuthorityId: input.receipt.authorityId,
        actualAuthorityId: input.active.authority.authorityId,
      },
    };
  }
  if (input.active.authority.walletId !== input.receipt.walletId) {
    return {
      kind: 'integrity_error',
      reason: { kind: 'installation_receipt_mismatch', field: 'walletId' },
    };
  }
  if (input.active.walletSession.walletId !== input.receipt.walletId) {
    return {
      kind: 'integrity_error',
      reason: { kind: 'installation_receipt_mismatch', field: 'walletId' },
    };
  }
  if (
    input.active.authMethod.walletAuthMethodId !== input.receipt.authMethodId ||
    input.active.walletSession.authMethodId !== input.receipt.authMethodId
  ) {
    return {
      kind: 'integrity_error',
      reason: { kind: 'installation_receipt_mismatch', field: 'authMethodId' },
    };
  }
  return null;
}

function assertSealedAuthorityRecordsMatchCommitted(input: {
  readonly committed: CommittedAuthorityPackagesV1;
  readonly sealed: DeviceLinkingSealedAuthorityRecordsV1;
}): void {
  const authority = input.committed.authority;
  const authMethod = input.committed.authMethod;
  const expectedActivations = signerMaterialActivations(authority.signerActivations);
  if (input.sealed.signerMaterials.length !== expectedActivations.length) {
    throw new Error('sealed signer material count does not match committed authority');
  }
  for (let index = 0; index < expectedActivations.length; index += 1) {
    const expected = expectedActivations[index];
    const actual = input.sealed.signerMaterials[index];
    if (
      !actual ||
      actual.authorityId !== authority.authorityId ||
      actual.walletAuthMethodId !== authMethod.walletAuthMethodId ||
      actual.keyFamily !== expected.keyFamily ||
      actual.activationId !== expected.materialActivation.activationId ||
      actual.materialActivation.activationId !== expected.materialActivation.activationId
    ) {
      throw new Error('sealed signer material identity does not match committed authority');
    }
  }
  const requiresExportRoot =
    hasEd25519SignerFamily(authority.signerActivations) &&
    authority.permissions.includes('export_keys');
  if (requiresExportRoot !== (input.sealed.exportRoot !== null)) {
    throw new Error('sealed Ed25519 export root presence does not match committed authority');
  }
  if (input.sealed.exportRoot) {
    if (
      input.sealed.exportRoot.authorityId !== authority.authorityId ||
      input.sealed.exportRoot.walletAuthMethodId !== authMethod.walletAuthMethodId
    ) {
      throw new Error('sealed export root identity does not match committed authority');
    }
  }
  parseDigestB64u(input.sealed.installedRecordSetDigestB64u);
}

function assertReceiptMatchesCommitted(input: {
  readonly committed: CommittedAuthorityPackagesV1;
  readonly targetFactor: VerifiedTargetFactorV1;
  readonly receipt: LocalAuthorityInstallationReceiptV1;
}): void {
  if (
    input.receipt.authorityId !== input.committed.authority.authorityId ||
    input.receipt.walletId !== input.committed.authority.walletId ||
    input.receipt.authMethodId !== input.committed.authMethod.walletAuthMethodId ||
    input.receipt.deviceId !== input.committed.authority.principal.deviceId ||
    input.receipt.packageSetDigestB64u !== input.committed.packageSetDigestB64u ||
    input.receipt.targetFactorVerificationDigestB64u !==
      input.targetFactor.verificationDigestB64u ||
    !walletSignerActivationSetsMatch(
      input.receipt.installedActivationRefs,
      input.committed.authority.signerActivations,
    )
  ) {
    throw new Error('stored local authority receipt does not match committed packages');
  }
}

function walletSignerActivationSetsMatch(
  left: CommittedAuthorityPackagesV1['authority']['signerActivations'],
  right: CommittedAuthorityPackagesV1['authority']['signerActivations'],
): boolean {
  const leftBytes = encodeWalletSignerActivationSetV1(left);
  const rightBytes = encodeWalletSignerActivationSetV1(right);
  if (leftBytes.byteLength !== rightBytes.byteLength) return false;
  for (let index = 0; index < leftBytes.byteLength; index += 1) {
    if (leftBytes[index] !== rightBytes[index]) return false;
  }
  return true;
}

function hasEd25519SignerFamily(
  activations: CommittedAuthorityPackagesV1['authority']['signerActivations'],
): boolean {
  return activations.keyFamilies.length === 2 || activations.keyFamilies[0] === 'ed25519';
}

function signerMaterialActivations(
  activations: CommittedAuthorityPackagesV1['authority']['signerActivations'],
): readonly {
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
  readonly materialActivation: MpcMaterialActivationRef;
}[] {
  if (activations.keyFamilies.length === 1 && activations.keyFamilies[0] === 'ed25519') {
    if (!activations.ed25519) throw new Error('Ed25519 activation is missing');
    return [{ keyFamily: 'ed25519', materialActivation: activations.ed25519.materialActivation }];
  }
  if (activations.keyFamilies.length === 1 && activations.keyFamilies[0] === 'ecdsa_secp256k1') {
    if (!activations.ecdsa) throw new Error('ECDSA activation is missing');
    return [
      { keyFamily: 'ecdsa_secp256k1', materialActivation: activations.ecdsa.materialActivation },
    ];
  }
  if (activations.keyFamilies.length === 2) {
    if (!activations.ed25519 || !activations.ecdsa) {
      throw new Error('combined signer activations are incomplete');
    }
    return [
      { keyFamily: 'ed25519', materialActivation: activations.ed25519.materialActivation },
      { keyFamily: 'ecdsa_secp256k1', materialActivation: activations.ecdsa.materialActivation },
    ];
  }
  throw new Error('committed signer activation families are invalid');
}
