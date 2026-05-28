import type { AccountSignerRecord } from '@/core/indexedDB/passkeyClientDB.types';
import type { AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '../../interfaces/ecdsaChainTarget';
import {
  deriveEvmFamilyKeyFingerprint,
  evmFamilyEcdsaWalletKeyToIdentity,
  type EvmFamilyEcdsaKeyIdentity,
  type EvmFamilyEcdsaWalletKey,
} from '../identity/evmFamilyEcdsaIdentity';
import {
  parseProfileContinuityEcdsaWarmKey,
  type ProfileContinuityEcdsaWarmKeyParseResult,
} from './ecdsaKeyFactsInventory';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';

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
  | 'ambiguous_key_handle'
  | 'missing_chain_target'
  | 'synthetic_legacy_key_id'
  | 'missing_key_facts'
  | 'invalid_signer_record';

export type ActiveEcdsaSignerRecord = {
  kind: 'active_ecdsa_signer_record';
  targetKey: string;
  chainTarget: ThresholdEcdsaChainTarget;
  walletKey: EvmFamilyEcdsaWalletKey;
  signerId?: string;
  source: 'profile_continuity' | 'wallet';
};

export type RepairRequiredEcdsaSignerRecord = {
  kind: 'repair_required';
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
  | RepairRequiredEcdsaSignerRecord
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
  localSessionRecord?: ThresholdEcdsaSessionRecord;
};

export type CurrentEcdsaSessionFact = {
  keyHandle: string;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  walletSigningSessionId: string;
  expiresAtMs: number;
  remainingUses: number;
};

export type ConfiguredTargetThresholdEcdsaWarmKey = {
  chainTarget: ThresholdEcdsaChainTarget;
  targetKey: string;
  keyHandle: string;
  key?: EvmFamilyEcdsaKeyIdentity;
};

export type CanonicalThresholdEcdsaWarmSessionContext = {
  ecdsaKeys: ConfiguredTargetThresholdEcdsaWarmKey[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

export type SharedKeyTargetCompletion =
  | {
      kind: 'complete_shared_key_targets';
      context: CanonicalThresholdEcdsaWarmSessionContext;
      missingTargets?: never;
      keyHandles?: never;
    }
  | {
      kind: 'ambiguous_shared_key_targets';
      keyHandles: string[];
      missingTargets?: never;
      context?: never;
    }
  | {
      kind: 'missing_shared_key';
      missingTargets: string[];
      context?: never;
      keyHandles?: never;
    };

export type EcdsaUnlockRuntimeConfig = {
  allowAuthenticatedKeyFactsInventory: boolean;
  explicitRepairMode: boolean;
};

export type EcdsaWarmupPlannerResult =
  | {
      kind: 'no_configured_ecdsa_targets';
      readyTargets?: never;
      keyTargets?: never;
      repairRecords?: never;
      blockedRecords?: never;
    }
  | {
      kind: 'ready';
      readyTargets: EcdsaWarmupReadyTarget[];
      keyTargets?: never;
      repairRecords?: never;
      blockedRecords?: never;
    }
  | {
      kind: 'awaiting_authenticated_key_facts_inventory';
      keyTargets: {
        keyHandle: string;
        chainTarget: ThresholdEcdsaChainTarget;
      }[];
      repairRecords: RepairRequiredEcdsaSignerRecord[];
      readyTargets?: never;
      blockedRecords?: never;
    }
  | {
      kind: 'repair_required';
      repairRecords: RepairRequiredEcdsaSignerRecord[];
      readyTargets?: never;
      keyTargets?: never;
      blockedRecords?: never;
    }
  | {
      kind: 'blocked';
      blockedRecords: BlockedEcdsaSignerRecord[];
      readyTargets?: never;
      keyTargets?: never;
      repairRecords?: never;
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
    case 'ambiguous_key_handle':
    case 'synthetic_legacy_key_id':
      return result.reason;
    case 'invalid_chain_target':
      return 'invalid_signer_record';
  }
  result.reason satisfies never;
  return 'invalid_signer_record';
}

export function parseActiveEcdsaSignerRecordForUnlock(args: {
  walletId: AccountId;
  configuredTargets: readonly ThresholdEcdsaChainTarget[];
  signer: AccountSignerRecord | Record<string, unknown> | unknown;
}): ParsedEcdsaUnlockSignerRecord {
  const signer =
    args.signer && typeof args.signer === 'object' && !Array.isArray(args.signer)
      ? (args.signer as Partial<AccountSignerRecord>)
      : {};
  const parsed = parseProfileContinuityEcdsaWarmKey({
    nearAccountId: args.walletId,
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
        source: 'profile_continuity',
        ...(signerId ? { signerId } : {}),
      };
    case 'repair_required':
      return {
        kind: 'repair_required',
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
        reason: 'ambiguous_key_handle',
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
}): ConfiguredTargetThresholdEcdsaWarmKey {
  const keyHandle = String(args.keyHandle || '').trim();
  if (!keyHandle) {
    throw new Error('[login] configured-target ECDSA warm key requires keyHandle');
  }
  return {
    chainTarget: args.chainTarget,
    targetKey: thresholdEcdsaChainTargetKey(args.chainTarget),
    keyHandle,
    ...(args.key ? { key: args.key } : {}),
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
    byTarget.set(targetKey, {
      chainTarget: key.chainTarget,
      targetKey,
      keyHandle: keyHandle || existingKeyHandle,
      ...(key.key || existing?.key ? { key: key.key || existing?.key } : {}),
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

export function buildSharedKeyTargetCompletion(args: {
  context: CanonicalThresholdEcdsaWarmSessionContext;
  configuredTargets: readonly { chainTarget: ThresholdEcdsaChainTarget }[];
}): SharedKeyTargetCompletion {
  if (!args.configuredTargets.length) {
    return { kind: 'complete_shared_key_targets', context: args.context };
  }

  const byTarget = new Map<string, ConfiguredTargetThresholdEcdsaWarmKey>();
  for (const key of args.context.ecdsaKeys) {
    byTarget.set(key.targetKey, key);
  }
  const missingTargetKeys = args.configuredTargets
    .map((target) => thresholdEcdsaChainTargetKey(target.chainTarget))
    .filter((targetKey) => !byTarget.has(targetKey));
  const keyHandles = [
    ...new Set(
      [...byTarget.values()].map((key) => String(key.keyHandle || '').trim()).filter(Boolean),
    ),
  ];
  if (keyHandles.length > 1) {
    return {
      kind: 'ambiguous_shared_key_targets',
      keyHandles,
    };
  }
  const keyFingerprints = [
    ...new Set(
      [...byTarget.values()]
        .map((key) => (key.key ? deriveEvmFamilyKeyFingerprint(key.key) : ''))
        .filter(Boolean),
    ),
  ];
  if (keyFingerprints.length > 1) {
    return {
      kind: 'ambiguous_shared_key_targets',
      keyHandles,
    };
  }

  const sharedKey = [...byTarget.values()].find((key) => key.key)?.key;
  const sharedKeyHandle = keyHandles[0] || '';
  if (!sharedKey) {
    return {
      kind: 'missing_shared_key',
      missingTargets: missingTargetKeys.length
        ? missingTargetKeys
        : args.configuredTargets.map((target) => thresholdEcdsaChainTargetKey(target.chainTarget)),
    };
  }
  for (const target of args.configuredTargets) {
    const targetKey = thresholdEcdsaChainTargetKey(target.chainTarget);
    const existing = byTarget.get(targetKey);
    const targetKeyHandle = String(existing?.keyHandle || sharedKeyHandle).trim();
    if (!targetKeyHandle) {
      return {
        kind: 'missing_shared_key',
        missingTargets: [targetKey],
      };
    }
    byTarget.set(
      targetKey,
      configuredTargetThresholdEcdsaWarmKey({
        chainTarget: target.chainTarget,
        keyHandle: targetKeyHandle,
        key: existing?.key || sharedKey,
      }),
    );
  }

  const context: CanonicalThresholdEcdsaWarmSessionContext = {
    ecdsaKeys: collectConfiguredTargetThresholdEcdsaWarmKeys({
      source: 'configured EVM-family shared-key target completion',
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
      kind: 'missing_shared_key',
      missingTargets: remainingMissingTargets.map((target) =>
        thresholdEcdsaChainTargetKey(target.chainTarget),
      ),
    };
  }
  return { kind: 'complete_shared_key_targets', context };
}

export function requireCompleteSharedKeyTargetContext(args: {
  completion: SharedKeyTargetCompletion;
  source: string;
}): CanonicalThresholdEcdsaWarmSessionContext {
  switch (args.completion.kind) {
    case 'complete_shared_key_targets':
      return args.completion.context;
    case 'ambiguous_shared_key_targets':
      throw new Error(
        `[login] threshold ECDSA warm-up received ambiguous shared key handles from ${args.source}: ${args.completion.keyHandles.join(
          ', ',
        )}`,
      );
    case 'missing_shared_key':
      throw new Error(
        `[login] threshold ECDSA warm-up could not resolve canonical shared key identity from ${args.source} for ${args.completion.missingTargets.join(
          ', ',
        )}`,
      );
  }
  args.completion satisfies never;
  throw new Error('[login] unsupported ECDSA warm-up key completion state');
}

function dedupeRepairKeyTargets(records: readonly RepairRequiredEcdsaSignerRecord[]): {
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
  repairRecords?: readonly RepairRequiredEcdsaSignerRecord[];
  blockedRecords?: readonly BlockedEcdsaSignerRecord[];
  localSessionRecords: readonly ThresholdEcdsaSessionRecord[];
  currentSessionFacts?: readonly CurrentEcdsaSessionFact[];
  runtimeConfig?: EcdsaUnlockRuntimeConfig;
  allowAuthenticatedKeyFactsInventory?: boolean;
  explicitRepairMode?: boolean;
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

  const repairByTarget = new Map<string, RepairRequiredEcdsaSignerRecord>();
  for (const record of args.repairRecords || []) {
    repairByTarget.set(record.targetKey, record);
  }

  const missingOrRepairRecords: RepairRequiredEcdsaSignerRecord[] = [];
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
    const repairRecord = repairByTarget.get(targetKey);
    if (repairRecord) {
      missingOrRepairRecords.push(repairRecord);
      continue;
    }
    missingOrRepairRecords.push({
      kind: 'repair_required',
      targetKey,
      chainTarget,
      keyHandle: '',
      reason: 'missing_key_facts',
    });
  }

  if (missingOrRepairRecords.length === 0) {
    return { kind: 'ready', readyTargets };
  }

  const repairRecordsWithKeyHandles = missingOrRepairRecords.filter((record) =>
    String(record.keyHandle || '').trim(),
  );
  const explicitRepairMode = args.runtimeConfig?.explicitRepairMode ?? args.explicitRepairMode;
  const allowAuthenticatedKeyFactsInventory =
    args.runtimeConfig?.allowAuthenticatedKeyFactsInventory ??
    args.allowAuthenticatedKeyFactsInventory;
  if (
    explicitRepairMode === true &&
    allowAuthenticatedKeyFactsInventory === true &&
    repairRecordsWithKeyHandles.length === missingOrRepairRecords.length
  ) {
    return {
      kind: 'awaiting_authenticated_key_facts_inventory',
      repairRecords: repairRecordsWithKeyHandles,
      keyTargets: dedupeRepairKeyTargets(repairRecordsWithKeyHandles),
    };
  }

  return {
    kind: 'repair_required',
    repairRecords: missingOrRepairRecords,
  };
}
