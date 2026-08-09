import { alphabetizeStringify } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import type { EcdsaClientRootPublicKey33B64u } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import type { EcdsaServerGeneration } from '@shared/utils/ecdsaCapabilityActivation';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { WalletId } from '@shared/utils/domainIds';
import type { ThresholdEcdsaChainTarget } from '../../../core/thresholdEcdsaChainTarget';
import type {
  RouterAbEd25519YaoApplicationBindingFactsV1,
  RouterAbEd25519YaoBytes32V1,
  RouterAbEd25519YaoLifecycleScopeV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  sameRouterAbMpcMaterialActivationRef,
  type RouterAbMpcMaterialActivationRefWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import {
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaRegistrationActivationReceiptV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  ecdsaPostRegistrationRequestMatchesCapability,
  type WalletEcdsaPendingSessionActivationRecord,
  type WalletEcdsaSignerRecord,
  type WalletEd25519SignerRecord,
} from '../../../core/WalletStore';
import type { D1WalletStore } from '../../../core/d1WalletStore';
import {
  deriveWalletRecoveryKeyLifecycleId,
  parseRecoveryCodeReservationId,
  type WalletRecoveryKeySetId,
} from '@shared/wallet-recovery/recoveryCodeReservation';

export type { WalletRecoveryKeySetId } from '@shared/wallet-recovery/recoveryCodeReservation';

export type WalletRecoveryKeyManifestEntryV1 =
  | {
      readonly kind: 'near_ed25519';
      readonly keySetId: `near_ed25519:${string}`;
      readonly signerId: string;
      readonly nearAccountId: string;
      readonly nearEd25519SigningKeyId: string;
      readonly publicKey: string;
      readonly registeredPublicKeyB64u: string;
      readonly recordedKeyManifestDigestB64u: string;
      readonly recoveryBasis: {
        readonly capabilityKind: 'registration' | 'recovery';
        readonly activeCapabilityBinding: readonly number[];
        readonly activeMaterialActivation: WalletEd25519SignerRecord['activeYaoCapability']['activationResult']['public_receipt']['material_activation'];
        readonly scope: WalletEd25519SignerRecord['activeYaoCapability']['admissionRequest']['scope'];
        readonly applicationBinding: WalletEd25519SignerRecord['activeYaoCapability']['admissionRequest']['application_binding'];
        readonly participantIds: readonly [number, number];
        readonly registeredPublicKey: readonly number[];
        readonly runtimePolicyScope: WalletEd25519SignerRecord['runtimePolicyScope'];
        readonly activationTranscript: readonly number[];
        readonly activationStateEpoch: number;
        readonly signingWorkerVerifyingShare: readonly number[];
      };
    }
  | {
      readonly kind: 'evm_family_ecdsa';
      readonly keySetId: `evm_family_ecdsa:${string}`;
      readonly keyHandle: string;
      readonly evmFamilySigningKeySlotId: string;
      readonly recordedKeyManifestDigestB64u: string;
      readonly clientRootPublicKey33B64u: EcdsaClientRootPublicKey33B64u;
      readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
      readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
      readonly chainTargets: readonly ThresholdEcdsaChainTarget[];
      readonly chainTargetKeys: readonly string[];
      readonly ecdsaThresholdKeyId: WalletEcdsaSignerRecord['walletKey']['ecdsaThresholdKeyId'];
      readonly signingRootId: string;
      readonly signingRootVersion: string;
      readonly runtimePolicyScope: RuntimePolicyScope;
      readonly participantIds: readonly [number, number];
    };

export type WalletRecoveryKeyManifestV1 = {
  readonly version: 'wallet_recovery_key_manifest_v1';
  readonly walletId: WalletId;
  readonly entries: readonly WalletRecoveryKeyManifestEntryV1[];
};

export type WalletRecoveryPreparationKeyManifestEntryV1 =
  | {
      readonly kind: 'near_ed25519';
      readonly keySetId: `near_ed25519:${string}`;
      readonly signerId: string;
      readonly nearAccountId: string;
      readonly recordedKeyManifestDigestB64u: string;
      readonly recoveryBasis: WalletRecoveryPreparationNearRecoveryBasisV1;
    }
  | {
      readonly kind: 'evm_family_ecdsa';
      readonly keySetId: `evm_family_ecdsa:${string}`;
      readonly keyHandle: string;
      readonly evmFamilySigningKeySlotId: string;
      readonly recordedKeyManifestDigestB64u: string;
      readonly recoveryBasis: WalletRecoveryPreparationEcdsaRecoveryBasisV1;
    };

export type WalletRecoveryPreparationNearRecoveryBasisV1 = {
  readonly capabilityKind: 'registration' | 'recovery';
  readonly activeCapabilityBinding: RouterAbEd25519YaoBytes32V1;
  readonly scope: RouterAbEd25519YaoLifecycleScopeV1;
  readonly applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
  readonly participantIds: readonly [number, number];
  readonly registeredPublicKey: RouterAbEd25519YaoBytes32V1;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly activationTranscript: RouterAbEd25519YaoBytes32V1;
  readonly activationStateEpoch: number;
  readonly signingWorkerVerifyingShare: RouterAbEd25519YaoBytes32V1;
};

export type WalletRecoveryPreparationEcdsaRecoveryBasisV1 = {
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  readonly serverGeneration: EcdsaServerGeneration;
  readonly clientRootPublicKey33B64u: EcdsaClientRootPublicKey33B64u;
  readonly chainTargets: readonly ThresholdEcdsaChainTarget[];
  readonly ecdsaThresholdKeyId: WalletEcdsaSignerRecord['walletKey']['ecdsaThresholdKeyId'];
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly participantIds: readonly [number, number];
};

export type WalletUnlockKeyManifestEntryV1 =
  | {
      readonly kind: 'near_ed25519';
      readonly keySetId: `near_ed25519:${string}`;
      readonly signerId: string;
      readonly nearAccountId: string;
      readonly nearEd25519SigningKeyId: string;
      readonly signerSlot: number;
      readonly registeredPublicKeyB64u: string;
      readonly recordedKeyManifestDigestB64u: string;
      readonly activeCapabilityBinding: readonly number[];
    }
  | {
      readonly kind: 'evm_family_ecdsa';
      readonly keySetId: `evm_family_ecdsa:${string}`;
      readonly keyHandle: string;
      readonly evmFamilySigningKeySlotId: string;
      readonly recordedKeyManifestDigestB64u: string;
      readonly clientRootPublicKey33B64u: EcdsaClientRootPublicKey33B64u;
      readonly applicationBindingDigestB64u: string;
      readonly chainTargetKeys: readonly string[];
    };

export type WalletUnlockKeyManifestV1 = {
  readonly version: 'wallet_custody_unlock_key_manifest_v1';
  readonly walletId: WalletId;
  readonly entries: readonly WalletUnlockKeyManifestEntryV1[];
};

export type WalletRecoveryPreparationKeyManifestV1 = {
  readonly version: 'wallet_recovery_preparation_key_manifest_v1';
  readonly walletId: WalletId;
  readonly entries: readonly WalletRecoveryPreparationKeyManifestEntryV1[];
};

export type WalletRecoveryActivationVerification =
  | {
      readonly kind: 'verified';
      readonly keySetIds: readonly WalletRecoveryKeySetId[];
      readonly ecdsaPromotions: readonly WalletRecoveryEcdsaSignerPromotionV1[];
    }
  | { readonly kind: 'refused'; readonly reason: string };

/**
 * The exact ECDSA state transition admitted by recovery verification. The
 * signer rows and pending protocol pair are carried into the commit store so
 * their CAS writes and deletes share the custody promotion transaction.
 */
export type WalletRecoveryEcdsaSignerPromotionV1 = {
  readonly keySetId: `evm_family_ecdsa:${string}`;
  readonly keyHandle: string;
  readonly currentSigners: readonly WalletEcdsaSignerRecord[];
  readonly recovery: Extract<
    WalletEcdsaPendingSessionActivationRecord,
    { readonly operation: 'recovery' }
  >;
  readonly refresh: Extract<
    WalletEcdsaPendingSessionActivationRecord,
    { readonly operation: 'refresh' }
  >;
  readonly nextPublicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  readonly nextActivationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
};

type WalletRecoveryRegistry = Pick<
  D1WalletStore,
  | 'listEd25519SignersForWallet'
  | 'listEcdsaSignersForWallet'
  | 'listEcdsaPendingSessionActivationsForLifecycle'
>;

type EcdsaManifestAccumulator = {
  readonly signer: WalletEcdsaSignerRecord;
  readonly chainTargets: ThresholdEcdsaChainTarget[];
  readonly chainTargetKeys: string[];
};

export async function resolveWalletRecoveryKeyManifestV1(input: {
  readonly registry: WalletRecoveryRegistry;
  readonly walletId: WalletId;
}): Promise<WalletRecoveryKeyManifestV1> {
  const [ed25519Signers, ecdsaSigners] = await Promise.all([
    input.registry.listEd25519SignersForWallet({ walletId: input.walletId }),
    input.registry.listEcdsaSignersForWallet({ walletId: input.walletId }),
  ]);
  const entries = [
    ...ed25519ManifestEntries(ed25519Signers),
    ...ecdsaManifestEntries(ecdsaSigners),
  ];
  if (entries.length === 0) {
    throw new Error('wallet recovery has no registered key capabilities');
  }
  return {
    version: 'wallet_recovery_key_manifest_v1',
    walletId: input.walletId,
    entries,
  };
}

export function projectWalletRecoveryPreparationKeyManifestV1(
  manifest: WalletRecoveryKeyManifestV1,
): WalletRecoveryPreparationKeyManifestV1 {
  return {
    version: 'wallet_recovery_preparation_key_manifest_v1',
    walletId: manifest.walletId,
    entries: manifest.entries.map(projectWalletRecoveryPreparationEntryV1),
  };
}

export function projectWalletUnlockKeyManifestV1(
  manifest: WalletRecoveryKeyManifestV1,
): WalletUnlockKeyManifestV1 {
  return {
    version: 'wallet_custody_unlock_key_manifest_v1',
    walletId: manifest.walletId,
    entries: manifest.entries.map(projectWalletUnlockEntryV1),
  };
}

function projectWalletUnlockEntryV1(
  entry: WalletRecoveryKeyManifestEntryV1,
): WalletUnlockKeyManifestEntryV1 {
  switch (entry.kind) {
    case 'near_ed25519':
      return {
        kind: entry.kind,
        keySetId: entry.keySetId,
        signerId: entry.signerId,
        nearAccountId: entry.nearAccountId,
        nearEd25519SigningKeyId: entry.nearEd25519SigningKeyId,
        signerSlot: entry.recoveryBasis.applicationBinding.key_creation_signer_slot,
        registeredPublicKeyB64u: entry.registeredPublicKeyB64u,
        recordedKeyManifestDigestB64u: entry.recordedKeyManifestDigestB64u,
        activeCapabilityBinding: [...entry.recoveryBasis.activeCapabilityBinding],
      };
    case 'evm_family_ecdsa':
      return {
        kind: entry.kind,
        keySetId: entry.keySetId,
        keyHandle: entry.keyHandle,
        evmFamilySigningKeySlotId: entry.evmFamilySigningKeySlotId,
        recordedKeyManifestDigestB64u: entry.recordedKeyManifestDigestB64u,
        clientRootPublicKey33B64u: entry.clientRootPublicKey33B64u,
        applicationBindingDigestB64u:
          entry.publicCapability.context.application_binding_digest_b64u,
        chainTargetKeys: [...entry.chainTargetKeys],
      };
  }
}

function projectWalletRecoveryPreparationEntryV1(
  entry: WalletRecoveryKeyManifestEntryV1,
): WalletRecoveryPreparationKeyManifestEntryV1 {
  switch (entry.kind) {
    case 'near_ed25519':
      return {
        kind: entry.kind,
        keySetId: entry.keySetId,
        signerId: entry.signerId,
        nearAccountId: entry.nearAccountId,
        recordedKeyManifestDigestB64u: entry.recordedKeyManifestDigestB64u,
        recoveryBasis: {
          capabilityKind: entry.recoveryBasis.capabilityKind,
          activeCapabilityBinding: [...entry.recoveryBasis.activeCapabilityBinding],
          scope: projectEd25519LifecycleScope(entry.recoveryBasis.scope),
          applicationBinding: projectEd25519ApplicationBinding(
            entry.recoveryBasis.applicationBinding,
          ),
          participantIds: [
            entry.recoveryBasis.participantIds[0],
            entry.recoveryBasis.participantIds[1],
          ],
          registeredPublicKey: [...entry.recoveryBasis.registeredPublicKey],
          runtimePolicyScope: projectRuntimePolicyScope(entry.recoveryBasis.runtimePolicyScope),
          activationTranscript: [...entry.recoveryBasis.activationTranscript],
          activationStateEpoch: entry.recoveryBasis.activationStateEpoch,
          signingWorkerVerifyingShare: [...entry.recoveryBasis.signingWorkerVerifyingShare],
        },
      };
    case 'evm_family_ecdsa':
      return {
        kind: entry.kind,
        keySetId: entry.keySetId,
        keyHandle: entry.keyHandle,
        evmFamilySigningKeySlotId: entry.evmFamilySigningKeySlotId,
        recordedKeyManifestDigestB64u: entry.recordedKeyManifestDigestB64u,
        recoveryBasis: {
          publicCapability: entry.publicCapability,
          serverGeneration: entry.activationReceipt.server_generation,
          clientRootPublicKey33B64u: entry.clientRootPublicKey33B64u,
          chainTargets: entry.chainTargets.map(projectThresholdEcdsaChainTarget),
          ecdsaThresholdKeyId: entry.ecdsaThresholdKeyId,
          signingRootId: entry.signingRootId,
          signingRootVersion: entry.signingRootVersion,
          runtimePolicyScope: projectRuntimePolicyScope(entry.runtimePolicyScope),
          participantIds: [entry.participantIds[0], entry.participantIds[1]],
        },
      };
  }
}

function projectEd25519LifecycleScope(
  scope: RouterAbEd25519YaoLifecycleScopeV1,
): RouterAbEd25519YaoLifecycleScopeV1 {
  return {
    lifecycle_id: scope.lifecycle_id,
    root_share_epoch: scope.root_share_epoch,
    account_id: scope.account_id,
    threshold_session_id: scope.threshold_session_id,
    signer_set_id: scope.signer_set_id,
    signing_worker_id: scope.signing_worker_id,
    material_activation: projectMaterialActivation(scope.material_activation),
  };
}

function projectMaterialActivation(
  materialActivation: RouterAbMpcMaterialActivationRefWire,
): RouterAbMpcMaterialActivationRefWire {
  return {
    kind: materialActivation.kind,
    activation_id: materialActivation.activation_id,
    capability: materialActivation.capability,
    material_owner: materialActivation.material_owner,
    key_binding: materialActivation.key_binding,
    lifecycle_binding: materialActivation.lifecycle_binding,
    signing_worker: materialActivation.signing_worker,
  };
}

function projectEd25519ApplicationBinding(
  applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1,
): RouterAbEd25519YaoApplicationBindingFactsV1 {
  return {
    wallet_id: applicationBinding.wallet_id,
    near_ed25519_signing_key_id: applicationBinding.near_ed25519_signing_key_id,
    signing_root_id: applicationBinding.signing_root_id,
    key_creation_signer_slot: applicationBinding.key_creation_signer_slot,
  };
}

function projectRuntimePolicyScope(scope: RuntimePolicyScope): RuntimePolicyScope {
  return {
    orgId: scope.orgId,
    projectId: scope.projectId,
    envId: scope.envId,
    signingRootVersion: scope.signingRootVersion,
  };
}

function projectThresholdEcdsaChainTarget(
  target: ThresholdEcdsaChainTarget,
): ThresholdEcdsaChainTarget {
  return { ...target };
}

export async function verifyWalletRecoveryKeyActivationsV1(input: {
  readonly registry: WalletRecoveryRegistry;
  readonly walletId: WalletId;
  readonly recoveryCorrelationId: string;
}): Promise<WalletRecoveryActivationVerification> {
  let recoveryReservationId;
  try {
    recoveryReservationId = parseRecoveryCodeReservationId(input.recoveryCorrelationId);
  } catch {
    return refused('wallet recovery activation correlation is missing');
  }
  let manifest: WalletRecoveryKeyManifestV1;
  try {
    manifest = await resolveWalletRecoveryKeyManifestV1({
      registry: input.registry,
      walletId: input.walletId,
    });
  } catch (error: unknown) {
    return refused(errorMessage(error, 'wallet recovery key manifest is unavailable'));
  }
  let ecdsaSigners: readonly WalletEcdsaSignerRecord[];
  try {
    ecdsaSigners = await input.registry.listEcdsaSignersForWallet({
      walletId: input.walletId,
    });
  } catch (error: unknown) {
    return refused(errorMessage(error, 'wallet recovery ECDSA signer state is unavailable'));
  }
  const ecdsaPromotions: WalletRecoveryEcdsaSignerPromotionV1[] = [];
  for (const entry of manifest.entries) {
    const keyLifecycleId = await deriveWalletRecoveryKeyLifecycleId({
      reservationId: recoveryReservationId,
      keySetId: entry.keySetId,
    });
    switch (entry.kind) {
      case 'near_ed25519': {
        const failure = verifyEd25519RecoveryActivation(entry, keyLifecycleId);
        if (failure) return refused(failure);
        break;
      }
      case 'evm_family_ecdsa': {
        const pending = await input.registry.listEcdsaPendingSessionActivationsForLifecycle({
          walletId: input.walletId,
          lifecycleId: keyLifecycleId,
        });
        const matching = recordsForPublicCapability(pending, entry.publicCapability);
        const failure = verifyEcdsaRecoveryActivation({
          entry,
          records: matching,
          keyLifecycleId,
        });
        if (failure) return refused(failure);
        if (matching.length !== pending.length) {
          return refused(`wallet recovery has extra ECDSA receipts for ${entry.keySetId}`);
        }
        const currentSigners = ecdsaSigners.filter(
          (signer) => signer.walletKey.keyHandle === entry.keyHandle,
        );
        if (currentSigners.length === 0) {
          return refused(`wallet recovery has no ECDSA signer rows for ${entry.keySetId}`);
        }
        if (
          currentSigners.some(
            (signer) => !samePublicCapability(signer.walletKey.publicCapability, entry.publicCapability),
          )
        ) {
          return refused(`wallet recovery ECDSA signer rows changed for ${entry.keySetId}`);
        }
        const recovery = matching.find(isEcdsaRecoveryRecord);
        const refresh = matching.find(isEcdsaRefreshRecord);
        if (!recovery || !refresh) {
          return refused(`wallet recovery ECDSA receipt pair is incomplete for ${entry.keySetId}`);
        }
        const currentServerGenerations = new Set(
          currentSigners.map((signer) => signer.activationReceipt.server_generation),
        );
        if (currentServerGenerations.size !== 1) {
          return refused(`wallet recovery ECDSA signer generations conflict for ${entry.keySetId}`);
        }
        if (
          refresh.response.signing_worker_activation.server_generation ===
          currentSigners[0]?.activationReceipt.server_generation
        ) {
          return refused(`wallet recovery ECDSA activation generation is stale for ${entry.keySetId}`);
        }
        const nextPublicCapability = deriveEcdsaRecoveryPublicCapability({
          current: entry.publicCapability,
          receipt: refresh.response.signing_worker_activation,
        });
        ecdsaPromotions.push({
          keySetId: entry.keySetId,
          keyHandle: entry.keyHandle,
          currentSigners,
          recovery,
          refresh,
          nextPublicCapability,
          nextActivationReceipt: refresh.response.signing_worker_activation,
        });
        break;
      }
    }
  }
  return {
    kind: 'verified',
    keySetIds: manifest.entries.map(manifestEntryKeySetId),
    ecdsaPromotions,
  };
}

function recordsForPublicCapability(
  records: readonly WalletEcdsaPendingSessionActivationRecord[],
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1,
): readonly WalletEcdsaPendingSessionActivationRecord[] {
  const matching: WalletEcdsaPendingSessionActivationRecord[] = [];
  for (const record of records) {
    if (samePublicCapability(record.publicCapability, publicCapability)) matching.push(record);
  }
  return matching;
}

function ed25519ManifestEntries(
  signers: readonly WalletEd25519SignerRecord[],
): readonly WalletRecoveryKeyManifestEntryV1[] {
  const seen = new Set<string>();
  const entries: WalletRecoveryKeyManifestEntryV1[] = [];
  for (const signer of signers) {
    if (seen.has(signer.signerId)) {
      throw new Error(`wallet has duplicate Ed25519 signer ${signer.signerId}`);
    }
    seen.add(signer.signerId);
    entries.push({
      kind: 'near_ed25519',
      keySetId: `near_ed25519:${signer.signerId}`,
      signerId: signer.signerId,
      nearAccountId: signer.nearAccountId,
      nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
      publicKey: signer.publicKey,
      registeredPublicKeyB64u: base64UrlEncode(
        Uint8Array.from(
          signer.activeYaoCapability.activationResult.public_receipt.registered_public_key,
        ),
      ),
      recordedKeyManifestDigestB64u: signer.custodyKeyManifestDigestB64u,
      recoveryBasis: recoveryBasisFromEd25519Signer(signer),
    });
  }
  return entries.sort(compareManifestEntries);
}

function ecdsaManifestEntries(
  signers: readonly WalletEcdsaSignerRecord[],
): readonly WalletRecoveryKeyManifestEntryV1[] {
  const byKeyHandle = new Map<string, EcdsaManifestAccumulator>();
  for (const signer of signers) {
    const keyHandle = signer.walletKey.keyHandle;
    const current = byKeyHandle.get(keyHandle);
    if (!current) {
      byKeyHandle.set(keyHandle, {
        signer,
        chainTargets: [signer.chainTarget],
        chainTargetKeys: [signer.chainTargetKey],
      });
      continue;
    }
    if (
      !samePublicCapability(
        current.signer.walletKey.publicCapability,
        signer.walletKey.publicCapability,
      )
    ) {
      throw new Error(`wallet has conflicting ECDSA capability ${keyHandle}`);
    }
    if (!current.chainTargetKeys.includes(signer.chainTargetKey)) {
      current.chainTargetKeys.push(signer.chainTargetKey);
      current.chainTargets.push(signer.chainTarget);
    }
  }
  const entries: WalletRecoveryKeyManifestEntryV1[] = [];
  for (const [keyHandle, current] of byKeyHandle) {
    entries.push({
      kind: 'evm_family_ecdsa',
      keySetId: `evm_family_ecdsa:${keyHandle}`,
      keyHandle,
      evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
        walletId: current.signer.walletId,
        signingRootId: current.signer.walletKey.signingRootId,
        signingRootVersion: current.signer.walletKey.signingRootVersion,
      }),
      recordedKeyManifestDigestB64u: current.signer.custodyKeyManifestDigestB64u,
      clientRootPublicKey33B64u: current.signer.custodyClientRootPublicKey33B64u,
      publicCapability: current.signer.walletKey.publicCapability,
      activationReceipt: current.signer.activationReceipt,
      chainTargets: current.chainTargets.map(projectThresholdEcdsaChainTarget),
      chainTargetKeys: current.chainTargetKeys.sort(),
      ecdsaThresholdKeyId: current.signer.walletKey.ecdsaThresholdKeyId,
      signingRootId: current.signer.walletKey.signingRootId,
      signingRootVersion: current.signer.walletKey.signingRootVersion,
      runtimePolicyScope: current.signer.runtimePolicyScope,
      participantIds: [
        current.signer.walletKey.participantIds[0],
        current.signer.walletKey.participantIds[1],
      ],
    });
  }
  return entries.sort(compareManifestEntries);
}

function compareManifestEntries(
  left: WalletRecoveryKeyManifestEntryV1,
  right: WalletRecoveryKeyManifestEntryV1,
): number {
  return left.keySetId.localeCompare(right.keySetId);
}

function manifestEntryKeySetId(entry: WalletRecoveryKeyManifestEntryV1): WalletRecoveryKeySetId {
  return entry.keySetId;
}

function recoveryBasisFromEd25519Signer(
  signer: WalletEd25519SignerRecord,
): Extract<WalletRecoveryKeyManifestEntryV1, { readonly kind: 'near_ed25519' }>['recoveryBasis'] {
  const capability = signer.activeYaoCapability;
  const receipt = capability.activationResult.public_receipt;
  return {
    capabilityKind:
      capability.version === 'wallet_ed25519_yao_registration_capability_v1'
        ? 'registration'
        : 'recovery',
    activeCapabilityBinding: [...capability.activeCapabilityBinding],
    activeMaterialActivation: receipt.material_activation,
    scope: capability.admissionRequest.scope,
    applicationBinding: capability.admissionRequest.application_binding,
    participantIds: [
      capability.admissionRequest.participant_ids[0],
      capability.admissionRequest.participant_ids[1],
    ],
    registeredPublicKey: [...receipt.registered_public_key],
    runtimePolicyScope: capability.runtimePolicyScope,
    activationTranscript: [...receipt.transcript],
    activationStateEpoch: receipt.state_epoch,
    signingWorkerVerifyingShare: [...receipt.signing_worker_verifying_share],
  };
}

function verifyEd25519RecoveryActivation(
  entry: Extract<WalletRecoveryKeyManifestEntryV1, { readonly kind: 'near_ed25519' }>,
  keyLifecycleId: string,
): string | null {
  const recoveryBasis = entry.recoveryBasis;
  if (recoveryBasis.capabilityKind !== 'recovery') {
    return `wallet recovery has no fresh Ed25519 activation for ${entry.keySetId}`;
  }
  if (recoveryBasis.scope.lifecycle_id !== keyLifecycleId) {
    return `wallet recovery Ed25519 activation correlation does not match ${entry.keySetId}`;
  }
  if (
    recoveryBasis.applicationBinding.near_ed25519_signing_key_id !==
    entry.nearEd25519SigningKeyId
  ) {
    return `wallet recovery Ed25519 identity changed for ${entry.keySetId}`;
  }
  return null;
}

function verifyEcdsaRecoveryActivation(input: {
  readonly entry: Extract<WalletRecoveryKeyManifestEntryV1, { readonly kind: 'evm_family_ecdsa' }>;
  readonly records: readonly WalletEcdsaPendingSessionActivationRecord[];
  readonly keyLifecycleId: string;
}): string | null {
  if (input.records.length !== 2) {
    return `wallet recovery needs one ECDSA recovery and refresh receipt for ${input.entry.keySetId}`;
  }
  const recovery = input.records.find(isEcdsaRecoveryRecord);
  const refresh = input.records.find(isEcdsaRefreshRecord);
  if (!recovery || !refresh) {
    return `wallet recovery ECDSA receipt pair is incomplete for ${input.entry.keySetId}`;
  }
  if (
    recovery.lifecycleId !== input.keyLifecycleId ||
    refresh.lifecycleId !== input.keyLifecycleId ||
    recovery.request.lifecycle.lifecycle_id !== input.keyLifecycleId ||
    refresh.request.lifecycle.lifecycle_id !== input.keyLifecycleId
  ) {
    return `wallet recovery ECDSA activation correlation does not match ${input.entry.keySetId}`;
  }
  if (
    !ecdsaPostRegistrationRequestMatchesCapability({
      request: recovery.request,
      capability: input.entry.publicCapability,
    }) ||
    !ecdsaPostRegistrationRequestMatchesCapability({
      request: refresh.request,
      capability: input.entry.publicCapability,
    })
  ) {
    return `wallet recovery ECDSA public identity changed for ${input.entry.keySetId}`;
  }
  const activation = refresh.response.signing_worker_activation;
  if (
    recovery.request.lifecycle.root_share_epoch !== input.entry.publicCapability.activation_epoch ||
    refresh.request.previous_activation_epoch !== input.entry.publicCapability.activation_epoch ||
    activation.lifecycle_id !== input.keyLifecycleId ||
    activation.ecdsa_activation.activation_epoch !== refresh.request.next_activation_epoch ||
    !samePublicValue(activation.ecdsa_activation.context, refresh.request.context) ||
    !samePublicValue(
      activation.ecdsa_activation.public_identity,
      refresh.request.public_identity,
    ) ||
    !samePublicValue(
      activation.ecdsa_activation.signing_worker,
      refresh.request.signer_set.selected_server,
    ) ||
    !sameRouterAbMpcMaterialActivationRef(
      activation.ecdsa_activation.material_activation,
      refresh.request.material_activation,
    )
  ) {
    return `wallet recovery ECDSA activation receipt does not match ${input.entry.keySetId}`;
  }
  if (
    sameRouterAbMpcMaterialActivationRef(
      activation.ecdsa_activation.material_activation,
      input.entry.publicCapability.material_activation,
    )
  ) {
    return `wallet recovery ECDSA activation is stale for ${input.entry.keySetId}`;
  }
  return null;
}

function deriveEcdsaRecoveryPublicCapability(input: {
  readonly current: RouterAbEcdsaDerivationPublicCapabilityV1;
  readonly receipt: RouterAbEcdsaRegistrationActivationReceiptV1;
}): RouterAbEcdsaDerivationPublicCapabilityV1 {
  return parseRouterAbEcdsaDerivationPublicCapabilityV1({
    ...input.current,
    material_activation: input.receipt.ecdsa_activation.material_activation,
    activation_epoch: input.receipt.ecdsa_activation.activation_epoch,
    proof_transcript_digest_b64u: base64UrlEncode(
      Uint8Array.from(input.receipt.transcript_digest.bytes),
    ),
  });
}

function isEcdsaRecoveryRecord(
  record: WalletEcdsaPendingSessionActivationRecord,
): record is Extract<
  WalletEcdsaPendingSessionActivationRecord,
  { readonly operation: 'recovery' }
> {
  return record.operation === 'recovery';
}

function isEcdsaRefreshRecord(
  record: WalletEcdsaPendingSessionActivationRecord,
): record is Extract<WalletEcdsaPendingSessionActivationRecord, { readonly operation: 'refresh' }> {
  return record.operation === 'refresh';
}

function samePublicCapability(
  left: RouterAbEcdsaDerivationPublicCapabilityV1,
  right: RouterAbEcdsaDerivationPublicCapabilityV1,
): boolean {
  return samePublicValue(left, right);
}

function samePublicValue(left: unknown, right: unknown): boolean {
  return alphabetizeStringify(left) === alphabetizeStringify(right);
}

function refused(
  reason: string,
): Extract<WalletRecoveryActivationVerification, { kind: 'refused' }> {
  return { kind: 'refused', reason };
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}
