import type { AccountSignerRecord } from '@/core/indexedDB/passkeyClientDB.types';
import type {
  PersistedEcdsaRoleLocalMaterial,
  ThresholdEcdsaSessionRecord,
} from '../persistence/records';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '../../interfaces/ecdsaChainTarget';
import {
  deriveEvmFamilyKeyFingerprint,
  evmFamilyEcdsaWalletKeyToIdentity,
  type EvmFamilyEcdsaKeyIdentity,
  type EvmFamilyEcdsaWalletKey,
} from '../identity/evmFamilyEcdsaIdentity';
import {
  parseProfileContinuityEcdsaWarmKey,
  type EcdsaPublicCapabilityState,
  type ProfileContinuityEcdsaWarmKeyParseResult,
} from './ecdsaKeyFactsInventory';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { RouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';
import { alphabetizeStringify } from '@shared/utils/digests';

export type WalletUnlockSelection =
  | {
      mode: 'ed25519_only';
      ed25519: true;
      ecdsa?: never;
    }
  | {
      mode: 'ecdsa_only';
      ecdsa: true;
      ed25519?: never;
    }
  | {
      mode: 'ed25519_and_ecdsa';
      ed25519: true;
      ecdsa: true;
    };

export type EcdsaUnlockBlockedReason =
  | 'missing_key_handle'
  | 'invalid_key_handle'
  | 'duplicate_key_handles'
  | 'missing_chain_target'
  | 'missing_key_facts'
  | 'invalid_signer_record';

export type ActiveEcdsaSignerRecord = {
  kind: 'active_ecdsa_signer_record';
  targetKey: string;
  chainTarget: ThresholdEcdsaChainTarget;
  walletKey: EvmFamilyEcdsaWalletKey;
  publicCapability: EcdsaPublicCapabilityState;
  signerId?: string;
  source: 'profile_continuity' | 'wallet';
};

export type KeyFactsInventoryRequiredEcdsaSignerRecord = {
  kind: 'key_facts_inventory_required';
  targetKey: string;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: string;
  reason: 'missing_key_facts';
  signerId?: string;
};

export type BlockedEcdsaSignerRecord = {
  kind: 'blocked';
  targetKey: string;
  reason: EcdsaUnlockBlockedReason;
  signerId?: string;
};

export type ParsedEcdsaUnlockSignerRecord =
  | ActiveEcdsaSignerRecord
  | KeyFactsInventoryRequiredEcdsaSignerRecord
  | BlockedEcdsaSignerRecord
  | {
      kind: 'skipped';
      targetKey?: never;
      chainTarget?: never;
      walletKey?: never;
      keyHandle?: never;
      reason?: never;
      signerId?: never;
    };

export type EcdsaWarmupReadyTarget = {
  targetKey: string;
  chainTarget: ThresholdEcdsaChainTarget;
  walletKey: EvmFamilyEcdsaWalletKey;
  publicCapability: EcdsaPublicCapabilityState;
  localSessionRecord?: ThresholdEcdsaSessionRecord;
};

export type CurrentEcdsaSessionFact = {
  keyHandle: string;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  signingGrantId: string;
  expiresAtMs: number;
  remainingUses: number;
};

export type ConfiguredTargetThresholdEcdsaWarmKey = {
  chainTarget: ThresholdEcdsaChainTarget;
  targetKey: string;
  keyHandle: string;
  key?: EvmFamilyEcdsaKeyIdentity;
  passkeyCredentialIdB64u?: string;
  existingRoleLocalMaterial?: PersistedEcdsaRoleLocalMaterial;
  publicCapability: EcdsaPublicCapabilityState;
};

export type CanonicalThresholdEcdsaWarmSessionContext = {
  ecdsaKeys: ConfiguredTargetThresholdEcdsaWarmKey[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

export type ConfiguredTargetKeyCompletion =
  | {
      kind: 'complete_configured_target_keys';
      context: CanonicalThresholdEcdsaWarmSessionContext;
      missingTargets?: never;
    }
  | {
      kind: 'missing_configured_target_keys';
      missingTargets: string[];
      context?: never;
    };

export type EcdsaUnlockRuntimeConfig = {
  allowAuthenticatedKeyFactsInventory: boolean;
  explicitKeyFactsInventoryMode: boolean;
};

export type EcdsaWarmupPlannerResult =
  | {
      kind: 'no_configured_ecdsa_targets';
      readyTargets?: never;
      keyTargets?: never;
      keyFactsInventoryRequiredRecords?: never;
      blockedRecords?: never;
    }
  | {
      kind: 'ready';
      readyTargets: EcdsaWarmupReadyTarget[];
      keyTargets?: never;
      keyFactsInventoryRequiredRecords?: never;
      blockedRecords?: never;
    }
  | {
      kind: 'awaiting_authenticated_key_facts_inventory';
      keyTargets: {
        keyHandle: string;
        chainTarget: ThresholdEcdsaChainTarget;
      }[];
      keyFactsInventoryRequiredRecords: KeyFactsInventoryRequiredEcdsaSignerRecord[];
      readyTargets?: never;
      blockedRecords?: never;
    }
  | {
      kind: 'key_facts_inventory_required';
      keyFactsInventoryRequiredRecords: KeyFactsInventoryRequiredEcdsaSignerRecord[];
      readyTargets?: never;
      keyTargets?: never;
      blockedRecords?: never;
    }
  | {
      kind: 'blocked';
      blockedRecords: BlockedEcdsaSignerRecord[];
      readyTargets?: never;
      keyTargets?: never;
      keyFactsInventoryRequiredRecords?: never;
    };

export function walletUnlockSelectionIncludesEcdsa(selection: WalletUnlockSelection): boolean {
  switch (selection.mode) {
    case 'ed25519_only':
      return false;
    case 'ecdsa_only':
    case 'ed25519_and_ecdsa':
      return true;
  }
  selection satisfies never;
  return false;
}

function mapProfileBlockedReason(
  result: Extract<ProfileContinuityEcdsaWarmKeyParseResult, { kind: 'blocked' }>,
): EcdsaUnlockBlockedReason {
  switch (result.reason) {
    case 'missing_chain_target':
    case 'missing_key_handle':
    case 'invalid_key_handle':
    case 'duplicate_key_handles':
      return result.reason;
    case 'invalid_chain_target':
      return 'invalid_signer_record';
  }
  result.reason satisfies never;
  return 'invalid_signer_record';
}

export function parseActiveEcdsaSignerRecordForUnlock(args: {
  walletId: WalletId;
  configuredTargets: readonly ThresholdEcdsaChainTarget[];
  signer: AccountSignerRecord;
}): ParsedEcdsaUnlockSignerRecord {
  const signer = args.signer;
  const parsed = parseProfileContinuityEcdsaWarmKey({
    walletId: args.walletId,
    configuredTargets: args.configuredTargets,
    signer: args.signer,
  });
  const signerId =
    typeof signer.signerId === 'string' && signer.signerId.trim()
      ? signer.signerId.trim()
      : undefined;
  switch (parsed.kind) {
    case 'active_wallet_key':
      return {
        kind: 'active_ecdsa_signer_record',
        targetKey: parsed.targetKey,
        chainTarget: parsed.chainTarget,
        walletKey: parsed.walletKey,
        publicCapability: parsed.publicCapability,
        source: 'profile_continuity',
        ...(signerId ? { signerId } : {}),
      };
    case 'key_facts_inventory_required':
      return {
        kind: 'key_facts_inventory_required',
        targetKey: parsed.targetKey,
        chainTarget: parsed.chainTarget,
        keyHandle: parsed.keyHandle,
        reason: parsed.reason,
        ...(signerId ? { signerId } : {}),
      };
    case 'blocked':
      return {
        kind: 'blocked',
        targetKey: parsed.targetKey,
        reason: mapProfileBlockedReason(parsed),
        ...(signerId ? { signerId } : {}),
      };
    case 'skipped':
      return { kind: 'skipped' };
  }
  parsed satisfies never;
  return { kind: 'skipped' };
}

function localSessionForTarget(args: {
  walletKey: EvmFamilyEcdsaWalletKey;
  localSessionRecords: readonly ThresholdEcdsaSessionRecord[];
  nowMs: number;
}): ThresholdEcdsaSessionRecord | undefined {
  return args.localSessionRecords.find((record) => {
    if (String(record.keyHandle) !== String(args.walletKey.keyHandle)) return false;
    if (!thresholdEcdsaChainTargetsEqual(record.chainTarget, args.walletKey.chainTarget)) {
      return false;
    }
    if (Number(record.expiresAtMs) <= args.nowMs) return false;
    if (Number(record.remainingUses) <= 0) return false;
    return true;
  });
}

function activeTargetRecordsByTarget(
  records: readonly ActiveEcdsaSignerRecord[],
): Map<string, ActiveEcdsaSignerRecord | BlockedEcdsaSignerRecord> {
  const byTarget = new Map<string, ActiveEcdsaSignerRecord | BlockedEcdsaSignerRecord>();
  for (const record of records) {
    const existing = byTarget.get(record.targetKey);
    if (!existing) {
      byTarget.set(record.targetKey, record);
      continue;
    }
    if (existing.kind !== 'active_ecdsa_signer_record') {
      continue;
    }
    const existingFingerprint = deriveEvmFamilyKeyFingerprint(
      evmFamilyEcdsaWalletKeyToIdentity(existing.walletKey),
    );
    const nextFingerprint = deriveEvmFamilyKeyFingerprint(
      evmFamilyEcdsaWalletKeyToIdentity(record.walletKey),
    );
    if (
      String(existing.walletKey.keyHandle) !== String(record.walletKey.keyHandle) ||
      existingFingerprint !== nextFingerprint
    ) {
      byTarget.set(record.targetKey, {
        kind: 'blocked',
        targetKey: record.targetKey,
        reason: 'duplicate_key_handles',
        ...(record.signerId ? { signerId: record.signerId } : {}),
      });
    }
  }
  return byTarget;
}

export function configuredTargetThresholdEcdsaWarmKey(args: {
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: string;
  key?: EvmFamilyEcdsaKeyIdentity;
  passkeyCredentialIdB64u?: string;
  publicCapability?: RouterAbEcdsaDerivationPublicCapabilityV1;
  existingRoleLocalMaterial?: PersistedEcdsaRoleLocalMaterial;
}): ConfiguredTargetThresholdEcdsaWarmKey {
  const keyHandle = String(args.keyHandle || '').trim();
  if (!keyHandle) {
    throw new Error('[login] configured-target ECDSA warm key requires keyHandle');
  }
  const passkeyCredentialIdB64u = String(args.passkeyCredentialIdB64u || '').trim();
  if (
    args.key &&
    args.publicCapability &&
    String(args.publicCapability.client_id) !== String(args.key.walletId)
  ) {
    throw new Error('[login] configured-target ECDSA public capability wallet mismatch');
  }
  return {
    chainTarget: args.chainTarget,
    targetKey: thresholdEcdsaChainTargetKey(args.chainTarget),
    keyHandle,
    ...(args.key ? { key: args.key } : {}),
    ...(passkeyCredentialIdB64u ? { passkeyCredentialIdB64u } : {}),
    ...(args.existingRoleLocalMaterial
      ? { existingRoleLocalMaterial: args.existingRoleLocalMaterial }
      : {}),
    publicCapability: args.publicCapability
      ? {
          kind: 'persisted_public_capability',
          value: args.publicCapability,
        }
      : {
          kind: 'missing_public_capability',
        },
  };
}

export function collectConfiguredTargetThresholdEcdsaWarmKeys(args: {
  keys: readonly ConfiguredTargetThresholdEcdsaWarmKey[];
  source: string;
}): ConfiguredTargetThresholdEcdsaWarmKey[] {
  const byTarget = new Map<string, ConfiguredTargetThresholdEcdsaWarmKey>();
  for (const key of args.keys) {
    const targetKey = thresholdEcdsaChainTargetKey(key.chainTarget);
    const keyHandle = String(key.keyHandle || '').trim();
    if (!keyHandle) continue;
    const existing = byTarget.get(targetKey);
    const existingKeyHandle = String(existing?.keyHandle || '').trim();
    if (existingKeyHandle && keyHandle && existingKeyHandle !== keyHandle) {
      throw new Error(
        `[login] threshold ECDSA warm-up received ambiguous ${args.source} key handles for ${targetKey}`,
      );
    }
    if (
      existing?.key &&
      key.key &&
      deriveEvmFamilyKeyFingerprint(existing.key) !== deriveEvmFamilyKeyFingerprint(key.key)
    ) {
      throw new Error(
        `[login] threshold ECDSA warm-up received ambiguous ${args.source} key fingerprints for ${targetKey}`,
      );
    }
    const existingPublicCapability =
      existing?.publicCapability.kind === 'persisted_public_capability'
        ? existing.publicCapability.value
        : null;
    const incomingPublicCapability =
      key.publicCapability.kind === 'persisted_public_capability'
        ? key.publicCapability.value
        : null;
    if (
      existingPublicCapability &&
      incomingPublicCapability &&
      alphabetizeStringify(existingPublicCapability) !==
        alphabetizeStringify(incomingPublicCapability)
    ) {
      throw new Error(
        `[login] threshold ECDSA warm-up received ambiguous ${args.source} public capabilities for ${targetKey}`,
      );
    }
    const publicCapability = incomingPublicCapability || existingPublicCapability;
    const passkeyCredentialIdB64u = String(
      key.passkeyCredentialIdB64u || existing?.passkeyCredentialIdB64u || '',
    ).trim();
    const existingRoleLocalMaterial =
      key.existingRoleLocalMaterial || existing?.existingRoleLocalMaterial;
    if (
      key.existingRoleLocalMaterial &&
      existing?.existingRoleLocalMaterial &&
      key.existingRoleLocalMaterial.materialRef.durableMaterialRef !==
        existing.existingRoleLocalMaterial.materialRef.durableMaterialRef
    ) {
      throw new Error(
        `[login] threshold ECDSA warm-up received ambiguous ${args.source} role-local material for ${targetKey}`,
      );
    }
    byTarget.set(targetKey, {
      chainTarget: key.chainTarget,
      targetKey,
      keyHandle: keyHandle || existingKeyHandle,
      ...(key.key || existing?.key ? { key: key.key || existing?.key } : {}),
      ...(passkeyCredentialIdB64u ? { passkeyCredentialIdB64u } : {}),
      ...(existingRoleLocalMaterial ? { existingRoleLocalMaterial } : {}),
      publicCapability: publicCapability
        ? {
            kind: 'persisted_public_capability',
            value: publicCapability,
          }
        : {
            kind: 'missing_public_capability',
          },
    });
  }
  return [...byTarget.values()];
}

export function mergeCanonicalThresholdEcdsaWarmSessionContexts(
  stored: CanonicalThresholdEcdsaWarmSessionContext,
  relay: CanonicalThresholdEcdsaWarmSessionContext | null,
): CanonicalThresholdEcdsaWarmSessionContext {
  const ecdsaKeys = collectConfiguredTargetThresholdEcdsaWarmKeys({
    source: 'stored/relay',
    keys: [...stored.ecdsaKeys, ...(relay?.ecdsaKeys || [])],
  });
  return {
    ecdsaKeys,
    ...(relay?.runtimePolicyScope
      ? { runtimePolicyScope: relay.runtimePolicyScope }
      : stored.runtimePolicyScope
        ? { runtimePolicyScope: stored.runtimePolicyScope }
        : {}),
  };
}

export function buildConfiguredTargetKeyCompletion(args: {
  context: CanonicalThresholdEcdsaWarmSessionContext;
  configuredTargets: readonly { chainTarget: ThresholdEcdsaChainTarget }[];
}): ConfiguredTargetKeyCompletion {
  if (!args.configuredTargets.length) {
    return { kind: 'complete_configured_target_keys', context: args.context };
  }

  const byTarget = new Map<string, ConfiguredTargetThresholdEcdsaWarmKey>();
  for (const key of args.context.ecdsaKeys) {
    byTarget.set(key.targetKey, key);
  }
  const missingTargetKeys = args.configuredTargets
    .map((target) => thresholdEcdsaChainTargetKey(target.chainTarget))
    .filter((targetKey) => !byTarget.has(targetKey));
  if (missingTargetKeys.length) {
    return { kind: 'missing_configured_target_keys', missingTargets: missingTargetKeys };
  }

  const context: CanonicalThresholdEcdsaWarmSessionContext = {
    ecdsaKeys: collectConfiguredTargetThresholdEcdsaWarmKeys({
      source: 'configured ECDSA target completion',
      keys: [...byTarget.values()],
    }),
    ...(args.context.runtimePolicyScope
      ? { runtimePolicyScope: args.context.runtimePolicyScope }
      : {}),
  };
  const remainingMissingTargets = args.configuredTargets.filter(
    (target) =>
      !context.ecdsaKeys.some(
        (key) => key.targetKey === thresholdEcdsaChainTargetKey(target.chainTarget),
      ),
  );
  if (remainingMissingTargets.length) {
    return {
      kind: 'missing_configured_target_keys',
      missingTargets: remainingMissingTargets.map((target) =>
        thresholdEcdsaChainTargetKey(target.chainTarget),
      ),
    };
  }
  return { kind: 'complete_configured_target_keys', context };
}

export function requireCompleteConfiguredTargetKeyContext(args: {
  completion: ConfiguredTargetKeyCompletion;
  source: string;
}): CanonicalThresholdEcdsaWarmSessionContext {
  switch (args.completion.kind) {
    case 'complete_configured_target_keys':
      return args.completion.context;
    case 'missing_configured_target_keys':
      throw new Error(
        `[login] threshold ECDSA warm-up could not resolve configured target key facts from ${args.source} for ${args.completion.missingTargets.join(
          ', ',
        )}`,
      );
  }
  args.completion satisfies never;
  throw new Error('[login] unsupported ECDSA warm-up key completion state');
}

function dedupeKeyFactsInventoryTargets(
  records: readonly KeyFactsInventoryRequiredEcdsaSignerRecord[],
): {
  keyHandle: string;
  chainTarget: ThresholdEcdsaChainTarget;
}[] {
  const byTarget = new Map<
    string,
    {
      keyHandle: string;
      chainTarget: ThresholdEcdsaChainTarget;
    }
  >();
  for (const record of records) {
    const key = `${record.targetKey}:${record.keyHandle}`;
    byTarget.set(key, {
      keyHandle: record.keyHandle,
      chainTarget: record.chainTarget,
    });
  }
  return [...byTarget.values()];
}

export function planUnlockEcdsaWarmup(args: {
  selection: WalletUnlockSelection;
  configuredTargets: readonly ThresholdEcdsaChainTarget[];
  activeSignerRecords: readonly ActiveEcdsaSignerRecord[];
  keyFactsInventoryRequiredRecords?: readonly KeyFactsInventoryRequiredEcdsaSignerRecord[];
  blockedRecords?: readonly BlockedEcdsaSignerRecord[];
  localSessionRecords: readonly ThresholdEcdsaSessionRecord[];
  currentSessionFacts?: readonly CurrentEcdsaSessionFact[];
  runtimeConfig?: EcdsaUnlockRuntimeConfig;
  allowAuthenticatedKeyFactsInventory?: boolean;
  explicitKeyFactsInventoryMode?: boolean;
  nowMs?: number;
}): EcdsaWarmupPlannerResult {
  if (!walletUnlockSelectionIncludesEcdsa(args.selection) || args.configuredTargets.length === 0) {
    return { kind: 'no_configured_ecdsa_targets' };
  }

  const blockedRecords = [...(args.blockedRecords || [])];
  const activeByTarget = activeTargetRecordsByTarget(args.activeSignerRecords);
  for (const value of activeByTarget.values()) {
    if (value.kind === 'blocked') blockedRecords.push(value);
  }
  if (blockedRecords.length) {
    return { kind: 'blocked', blockedRecords };
  }

  const keyFactsInventoryRequiredByTarget = new Map<
    string,
    KeyFactsInventoryRequiredEcdsaSignerRecord
  >();
  for (const record of args.keyFactsInventoryRequiredRecords || []) {
    keyFactsInventoryRequiredByTarget.set(record.targetKey, record);
  }

  const keyFactsInventoryRequiredRecords: KeyFactsInventoryRequiredEcdsaSignerRecord[] = [];
  const readyTargets: EcdsaWarmupReadyTarget[] = [];
  const nowMs = args.nowMs ?? Date.now();
  for (const chainTarget of args.configuredTargets) {
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    const active = activeByTarget.get(targetKey);
    if (active?.kind === 'active_ecdsa_signer_record') {
      readyTargets.push({
        targetKey,
        chainTarget,
        walletKey: active.walletKey,
        publicCapability: active.publicCapability,
        ...(localSessionForTarget({
          walletKey: active.walletKey,
          localSessionRecords: args.localSessionRecords,
          nowMs,
        })
          ? {
              localSessionRecord: localSessionForTarget({
                walletKey: active.walletKey,
                localSessionRecords: args.localSessionRecords,
                nowMs,
              }),
            }
          : {}),
      });
      continue;
    }
    const keyFactsInventoryRequiredRecord = keyFactsInventoryRequiredByTarget.get(targetKey);
    if (keyFactsInventoryRequiredRecord) {
      keyFactsInventoryRequiredRecords.push(keyFactsInventoryRequiredRecord);
      continue;
    }
    keyFactsInventoryRequiredRecords.push({
      kind: 'key_facts_inventory_required',
      targetKey,
      chainTarget,
      keyHandle: '',
      reason: 'missing_key_facts',
    });
  }

  if (keyFactsInventoryRequiredRecords.length === 0) {
    return { kind: 'ready', readyTargets };
  }

  const inventoryRecordsWithKeyHandles = keyFactsInventoryRequiredRecords.filter((record) =>
    String(record.keyHandle || '').trim(),
  );
  const explicitKeyFactsInventoryMode =
    args.runtimeConfig?.explicitKeyFactsInventoryMode ?? args.explicitKeyFactsInventoryMode;
  const allowAuthenticatedKeyFactsInventory =
    args.runtimeConfig?.allowAuthenticatedKeyFactsInventory ??
    args.allowAuthenticatedKeyFactsInventory;
  if (
    explicitKeyFactsInventoryMode === true &&
    allowAuthenticatedKeyFactsInventory === true &&
    inventoryRecordsWithKeyHandles.length === keyFactsInventoryRequiredRecords.length
  ) {
    return {
      kind: 'awaiting_authenticated_key_facts_inventory',
      keyFactsInventoryRequiredRecords: inventoryRecordsWithKeyHandles,
      keyTargets: dedupeKeyFactsInventoryTargets(inventoryRecordsWithKeyHandles),
    };
  }

  return {
    kind: 'key_facts_inventory_required',
    keyFactsInventoryRequiredRecords,
  };
}
