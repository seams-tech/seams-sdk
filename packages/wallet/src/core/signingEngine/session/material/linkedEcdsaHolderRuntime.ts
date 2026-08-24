import type { LinkedDeviceEcdsaSourcePreservingActivationReceiptV1 } from '@shared/device-linking/sourceContribution';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
  type WalletAuthorityId,
  type WalletAuthMethodId,
  type WalletId,
} from '@shared/utils/domainIds';

export type LinkedEcdsaHolderRuntimeV1 = {
  readonly kind: 'linked_ecdsa_holder_runtime_v1';
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly holderHandleId: string;
  readonly ecdsaThresholdKeyId: string;
  readonly activationReceipt: LinkedDeviceEcdsaSourcePreservingActivationReceiptV1;
};

const linkedHolderRuntimes = new Map<string, LinkedEcdsaHolderRuntimeV1>();

function runtimeKey(input: {
  readonly walletId: WalletId;
  readonly materialActivation: MpcMaterialActivationRef;
}): string {
  return `${String(input.walletId)}\0${input.materialActivation.activationId}`;
}

export function installLinkedEcdsaHolderRuntimeV1(runtime: LinkedEcdsaHolderRuntimeV1): void {
  const key = runtimeKey(runtime);
  const existing = linkedHolderRuntimes.get(key);
  if (
    existing &&
    (existing.authorityId !== runtime.authorityId ||
      existing.walletAuthMethodId !== runtime.walletAuthMethodId ||
      existing.holderHandleId !== runtime.holderHandleId ||
      !mpcMaterialActivationRefsEqual(existing.materialActivation, runtime.materialActivation))
  ) {
    throw new Error('linked ECDSA holder runtime conflicts with the active authority');
  }
  linkedHolderRuntimes.set(key, runtime);
}

export function resolveLinkedEcdsaHolderRuntimeV1(input: {
  readonly walletId: WalletId;
  readonly materialActivation: MpcMaterialActivationRef;
}): LinkedEcdsaHolderRuntimeV1 | null {
  return linkedHolderRuntimes.get(runtimeKey(input)) ?? null;
}

export function listLinkedEcdsaHolderRuntimesV1(
  walletId?: WalletId,
): readonly LinkedEcdsaHolderRuntimeV1[] {
  return [...linkedHolderRuntimes.values()].filter(
    (runtime) => walletId === undefined || runtime.walletId === walletId,
  );
}

export function removeLinkedEcdsaHolderRuntimeV1(input: {
  readonly walletId: WalletId;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly holderHandleId: string;
}): void {
  const key = runtimeKey(input);
  const runtime = linkedHolderRuntimes.get(key);
  if (!runtime) return;
  if (runtime.holderHandleId !== input.holderHandleId) {
    throw new Error('linked ECDSA holder runtime changed before removal');
  }
  linkedHolderRuntimes.delete(key);
}

export function clearLinkedEcdsaHolderRuntimesV1(walletId?: WalletId): void {
  if (!walletId) {
    linkedHolderRuntimes.clear();
    return;
  }
  for (const [key, runtime] of linkedHolderRuntimes) {
    if (runtime.walletId === walletId) linkedHolderRuntimes.delete(key);
  }
}
