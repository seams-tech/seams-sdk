import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  thresholdEcdsaChainTargetFromValue,
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '../thresholdEcdsaChainTarget';
import type { RouterAbEcdsaBootstrapExportPort } from '../routerAbSigning/RouterAbEcdsaBootstrapExportRuntime';
import type { NormalizedLogger } from '../logger';
import { isObject } from './record';

export type ThresholdEcdsaKeyInventoryDiagnostics = {
  userId: string;
  inputCount: number;
  returnedCount: number;
  ecdsaBootstrapExportRuntimePresent: boolean;
  rejected: Record<string, number>;
};

export type ThresholdEcdsaKeyInventorySelector = {
  kind: 'key_handle';
  keyHandle: string;
  ecdsaThresholdKeyId?: never;
};

export type ThresholdEcdsaKeyInventoryTarget = {
  keySelector: ThresholdEcdsaKeyInventorySelector;
  selectorKey: string;
  chainTarget: ThresholdEcdsaChainTarget;
};

export type ThresholdEcdsaKeyInventoryRecord = {
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  targetKey: string;
  accountAddress: string;
  ownerAddress: string;
  relayerKeyId: string;
  thresholdEcdsaPublicKeyB64u: string;
  key: {
    walletId: string;
    evmFamilySigningKeySlotId: string;
    keyScope: 'evm-family';
    ecdsaThresholdKeyId: string;
    signingRootId: string;
    signingRootVersion: string;
    participantIds: number[];
    thresholdOwnerAddress: string;
  };
};

export function incrementCount(bucket: Record<string, number>, reason: string): void {
  bucket[reason] = (bucket[reason] || 0) + 1;
}

function thresholdEcdsaKeyInventorySelectorFromRaw(
  raw: Record<string, unknown>,
): { ok: true; value: ThresholdEcdsaKeyInventorySelector } | { ok: false; reason: string } {
  const keyHandle = toOptionalTrimmedString(raw.keyHandle);
  const ecdsaThresholdKeyId = toOptionalTrimmedString(raw.ecdsaThresholdKeyId);
  if (ecdsaThresholdKeyId) return { ok: false, reason: 'threshold_key_id_selector' };
  if (!keyHandle) return { ok: false, reason: 'missing_key_selector' };
  return { ok: true, value: { kind: 'key_handle', keyHandle } };
}

function thresholdEcdsaKeyInventorySelectorKey(
  selector: ThresholdEcdsaKeyInventorySelector,
): string {
  return `keyHandle:${selector.keyHandle}`;
}

export function thresholdEcdsaKeyInventorySelectorMatchesIdentity(
  selector: ThresholdEcdsaKeyInventorySelector,
  identity: { keyHandle: string; ecdsaThresholdKeyId: string },
): boolean {
  return identity.keyHandle === selector.keyHandle;
}

export function parseThresholdEcdsaKeyInventoryTarget(
  raw: unknown,
): { ok: true; value: ThresholdEcdsaKeyInventoryTarget } | { ok: false; reason: string } {
  if (!isObject(raw)) return { ok: false, reason: 'non_object' };
  const keySelector = thresholdEcdsaKeyInventorySelectorFromRaw(raw);
  if (!keySelector.ok) return keySelector;
  const chainTarget = thresholdEcdsaChainTargetFromValue(raw.chainTarget);
  if (!chainTarget) return { ok: false, reason: 'invalid_chain_target' };
  return {
    ok: true,
    value: {
      keySelector: keySelector.value,
      selectorKey: thresholdEcdsaKeyInventorySelectorKey(keySelector.value),
      chainTarget,
    },
  };
}

export function normalizeEvmAddress(value: unknown): string {
  const normalized = toOptionalTrimmedString(value)?.toLowerCase() || '';
  return /^0x[0-9a-f]{40}$/.test(normalized) ? normalized : '';
}

export async function listThresholdEcdsaKeyIdentityTargetsForUser(input: {
  userId: string;
  rpId: string;
  keyTargets: readonly unknown[];
  ecdsaBootstrapExportRuntime: RouterAbEcdsaBootstrapExportPort | null;
  logger?: NormalizedLogger;
}): Promise<{
  records: ThresholdEcdsaKeyInventoryRecord[];
  diagnostics: ThresholdEcdsaKeyInventoryDiagnostics;
}> {
  const userId = toOptionalTrimmedString(input.userId);
  const rpId = toOptionalTrimmedString(input.rpId);
  const diagnostics: ThresholdEcdsaKeyInventoryDiagnostics = {
    userId: userId || '',
    inputCount: input.keyTargets.length,
    returnedCount: 0,
    ecdsaBootstrapExportRuntimePresent: Boolean(input.ecdsaBootstrapExportRuntime),
    rejected: {},
  };
  if (!userId || !rpId) {
    incrementCount(diagnostics.rejected, 'missing_scope');
    return { records: [], diagnostics };
  }
  if (!input.ecdsaBootstrapExportRuntime) {
    incrementCount(diagnostics.rejected, 'ecdsa_bootstrap_export_runtime_missing');
    return { records: [], diagnostics };
  }

  const records: ThresholdEcdsaKeyInventoryRecord[] = [];
  const seen = new Set<string>();
  for (const rawTarget of input.keyTargets) {
    const parsed = parseThresholdEcdsaKeyInventoryTarget(rawTarget);
    if (!parsed.ok) {
      incrementCount(diagnostics.rejected, parsed.reason);
      continue;
    }
    const targetKey = thresholdEcdsaChainTargetKey(parsed.value.chainTarget);
    const requestKey = `${targetKey}::${parsed.value.selectorKey}`;
    if (seen.has(requestKey)) {
      incrementCount(diagnostics.rejected, 'duplicate_target_key');
      continue;
    }
    seen.add(requestKey);
    const identity = await input.ecdsaBootstrapExportRuntime.getEcdsaKeyIdentityMetadata({
      walletId: userId,
      keySelector: parsed.value.keySelector,
    });
    if (!identity) {
      incrementCount(diagnostics.rejected, 'identity_not_found');
      continue;
    }
    if (
      identity.walletId !== userId ||
      !thresholdEcdsaKeyInventorySelectorMatchesIdentity(parsed.value.keySelector, identity)
    ) {
      incrementCount(diagnostics.rejected, 'identity_mismatch');
      continue;
    }
    const keyHandle = toOptionalTrimmedString(identity.keyHandle);
    const ownerAddress = normalizeEvmAddress(identity.thresholdOwnerAddress);
    const relayerKeyId = toOptionalTrimmedString(identity.relayerKeyId);
    const thresholdEcdsaPublicKeyB64u = toOptionalTrimmedString(
      identity.thresholdEcdsaPublicKeyB64u,
    );
    if (!keyHandle || !ownerAddress || !relayerKeyId || !thresholdEcdsaPublicKeyB64u) {
      incrementCount(diagnostics.rejected, 'incomplete_identity');
      continue;
    }
    records.push({
      keyHandle,
      ecdsaThresholdKeyId: identity.ecdsaThresholdKeyId,
      chainTarget: parsed.value.chainTarget,
      targetKey,
      accountAddress: ownerAddress,
      ownerAddress,
      relayerKeyId,
      thresholdEcdsaPublicKeyB64u,
      key: {
        walletId: identity.walletId,
        evmFamilySigningKeySlotId: identity.evmFamilySigningKeySlotId,
        keyScope: identity.keyScope,
        ecdsaThresholdKeyId: identity.ecdsaThresholdKeyId,
        signingRootId: identity.signingRootId,
        signingRootVersion: identity.signingRootVersion,
        participantIds: [...identity.participantIds],
        thresholdOwnerAddress: ownerAddress,
      },
    });
  }
  diagnostics.returnedCount = records.length;
  input.logger?.info('[threshold-ecdsa-key-inventory][diagnostic]', diagnostics);
  return { records, diagnostics };
}
