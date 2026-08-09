import { alphabetizeStringify } from '@shared/utils/digests';
import type { WalletId } from '@shared/utils/domainIds';
import { sameRouterAbMpcMaterialActivationRef } from '@shared/utils/routerAbNormalSigningIdentity';
import type { RouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';
import {
  ecdsaPostRegistrationRequestMatchesCapability,
  type WalletEcdsaPendingSessionActivationRecord,
  type WalletEcdsaSignerRecord,
  type WalletEd25519SignerRecord,
  type WalletEd25519YaoActiveCapabilityRecord,
} from '../../../core/WalletStore';
import type { D1WalletStore } from '../../../core/d1WalletStore';

export type WalletRecoveryKeySetId = `near_ed25519:${string}` | `evm_family_ecdsa:${string}`;

export type WalletRecoveryKeyManifestEntryV1 =
  | {
      readonly kind: 'near_ed25519';
      readonly keySetId: `near_ed25519:${string}`;
      readonly signerId: string;
      readonly nearAccountId: string;
      readonly nearEd25519SigningKeyId: string;
      readonly publicKey: string;
      readonly activeCapability: WalletEd25519YaoActiveCapabilityRecord;
    }
  | {
      readonly kind: 'evm_family_ecdsa';
      readonly keySetId: `evm_family_ecdsa:${string}`;
      readonly keyHandle: string;
      readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
      readonly chainTargetKeys: readonly string[];
    };

export type WalletRecoveryKeyManifestV1 = {
  readonly version: 'wallet_recovery_key_manifest_v1';
  readonly walletId: WalletId;
  readonly entries: readonly WalletRecoveryKeyManifestEntryV1[];
};

export type WalletRecoveryActivationVerification =
  | {
      readonly kind: 'verified';
      readonly keySetIds: readonly WalletRecoveryKeySetId[];
    }
  | { readonly kind: 'refused'; readonly reason: string };

type WalletRecoveryRegistry = Pick<
  D1WalletStore,
  | 'listEd25519SignersForWallet'
  | 'listEcdsaSignersForWallet'
  | 'listEcdsaPendingSessionActivationsForLifecycle'
>;

type EcdsaManifestAccumulator = {
  readonly signer: WalletEcdsaSignerRecord;
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

export async function verifyWalletRecoveryKeyActivationsV1(input: {
  readonly registry: WalletRecoveryRegistry;
  readonly walletId: WalletId;
  readonly recoveryCorrelationId: string;
}): Promise<WalletRecoveryActivationVerification> {
  const recoveryCorrelationId = input.recoveryCorrelationId.trim();
  if (!recoveryCorrelationId) {
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
  const pending = await input.registry.listEcdsaPendingSessionActivationsForLifecycle({
    walletId: input.walletId,
    lifecycleId: recoveryCorrelationId,
  });
  const usedPending = new Set<WalletEcdsaPendingSessionActivationRecord>();
  for (const entry of manifest.entries) {
    switch (entry.kind) {
      case 'near_ed25519': {
        const failure = verifyEd25519RecoveryActivation(entry, recoveryCorrelationId);
        if (failure) return refused(failure);
        break;
      }
      case 'evm_family_ecdsa': {
        const matching = recordsForPublicCapability(pending, entry.publicCapability);
        const failure = verifyEcdsaRecoveryActivation({
          entry,
          records: matching,
          recoveryCorrelationId,
        });
        if (failure) return refused(failure);
        for (const record of matching) usedPending.add(record);
        break;
      }
    }
  }
  if (usedPending.size !== pending.length) {
    return refused('wallet recovery has activation receipts outside its exact key manifest');
  }
  return {
    kind: 'verified',
    keySetIds: manifest.entries.map(manifestEntryKeySetId),
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
      activeCapability: signer.activeYaoCapability,
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
      byKeyHandle.set(keyHandle, { signer, chainTargetKeys: [signer.chainTargetKey] });
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
    }
  }
  const entries: WalletRecoveryKeyManifestEntryV1[] = [];
  for (const [keyHandle, current] of byKeyHandle) {
    entries.push({
      kind: 'evm_family_ecdsa',
      keySetId: `evm_family_ecdsa:${keyHandle}`,
      keyHandle,
      publicCapability: current.signer.walletKey.publicCapability,
      chainTargetKeys: current.chainTargetKeys.sort(),
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

function verifyEd25519RecoveryActivation(
  entry: Extract<WalletRecoveryKeyManifestEntryV1, { readonly kind: 'near_ed25519' }>,
  recoveryCorrelationId: string,
): string | null {
  const capability = entry.activeCapability;
  if (capability.version !== 'wallet_ed25519_yao_recovery_capability_v1') {
    return `wallet recovery has no fresh Ed25519 activation for ${entry.keySetId}`;
  }
  if (capability.admissionRequest.scope.lifecycle_id !== recoveryCorrelationId) {
    return `wallet recovery Ed25519 activation correlation does not match ${entry.keySetId}`;
  }
  if (
    capability.admissionRequest.application_binding.near_ed25519_signing_key_id !==
      entry.nearEd25519SigningKeyId ||
    capability.nearAccountId !== entry.nearAccountId
  ) {
    return `wallet recovery Ed25519 identity changed for ${entry.keySetId}`;
  }
  return null;
}

function verifyEcdsaRecoveryActivation(input: {
  readonly entry: Extract<WalletRecoveryKeyManifestEntryV1, { readonly kind: 'evm_family_ecdsa' }>;
  readonly records: readonly WalletEcdsaPendingSessionActivationRecord[];
  readonly recoveryCorrelationId: string;
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
    recovery.lifecycleId !== input.recoveryCorrelationId ||
    refresh.lifecycleId !== input.recoveryCorrelationId ||
    recovery.request.lifecycle.lifecycle_id !== input.recoveryCorrelationId ||
    refresh.request.lifecycle.lifecycle_id !== input.recoveryCorrelationId
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
    activation.lifecycle_id !== input.recoveryCorrelationId ||
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
