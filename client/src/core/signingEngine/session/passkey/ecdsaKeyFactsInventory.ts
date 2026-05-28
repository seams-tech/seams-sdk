import { isObject } from '@shared/utils/validation';
import type { AccountId } from '../../../types/accountIds';
import {
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  walletIdFromWalletProfile,
  type ThresholdEcdsaChainTarget,
} from '../../interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import {
  buildEvmFamilyEcdsaWalletKey,
  resolveThresholdEcdsaKeyIdFromRecord,
  resolveThresholdSigningRootBindingFromRecord,
  toEvmFamilyEcdsaKeyHandle,
  toThresholdEcdsaPublicKeyB64u,
  type EvmFamilyEcdsaWalletKey,
} from '../identity/evmFamilyEcdsaIdentity';
import { SIGNER_AUTH_METHODS, SIGNER_KINDS } from '@shared/utils/signerDomain';

export type ThresholdEcdsaKeyIdentityInventoryEntry = {
  accountAddress: string;
  ownerAddress: string;
  walletKey: EvmFamilyEcdsaWalletKey;
};

export type ProfileContinuityEcdsaWarmKeyParseResult =
  | {
      kind: 'active_wallet_key';
      chainTarget: ThresholdEcdsaChainTarget;
      targetKey: string;
      walletKey: EvmFamilyEcdsaWalletKey;
      keyHandle?: never;
      reason?: never;
    }
  | {
      kind: 'repair_required';
      chainTarget: ThresholdEcdsaChainTarget;
      targetKey: string;
      keyHandle: string;
      reason: 'missing_key_facts';
      walletKey?: never;
    }
  | {
      kind: 'blocked';
      targetKey: string;
      reason:
        | 'missing_chain_target'
        | 'invalid_chain_target'
        | 'missing_key_handle'
        | 'ambiguous_key_handle'
        | 'synthetic_legacy_key_id';
      chainTarget?: never;
      walletKey?: never;
      keyHandle?: never;
    }
  | {
      kind: 'skipped';
      chainTarget?: never;
      targetKey?: never;
      walletKey?: never;
      keyHandle?: never;
      reason?: never;
    };

function normalizeEvmOwnerAddress(value: unknown): string {
  const candidate = String(value || '')
    .trim()
    .toLowerCase();
  return /^0x[0-9a-f]{40}$/.test(candidate) ? candidate : '';
}

function isSyntheticLegacyIdentifier(value: unknown): boolean {
  return String(value || '')
    .trim()
    .startsWith('legacy-key-handle:');
}

function resolveProfileContinuityEcdsaKeyHandle(metadata: Record<string, unknown>):
  | { kind: 'resolved'; keyHandle: string }
  | {
      kind: 'blocked';
      reason: 'missing_key_handle' | 'ambiguous_key_handle' | 'synthetic_legacy_key_id';
    } {
  if (
    isSyntheticLegacyIdentifier(metadata.keyHandle) ||
    isSyntheticLegacyIdentifier(metadata.ecdsaThresholdKeyId) ||
    (isObject(metadata.sharedEvmFamilyKey) &&
      (isSyntheticLegacyIdentifier(metadata.sharedEvmFamilyKey.keyHandle) ||
        isSyntheticLegacyIdentifier(metadata.sharedEvmFamilyKey.ecdsaThresholdKeyId)))
  ) {
    return { kind: 'blocked', reason: 'synthetic_legacy_key_id' };
  }
  const directKeyHandle = String(metadata.keyHandle || '').trim();
  const sharedKeyHandle = isObject(metadata.sharedEvmFamilyKey)
    ? String(metadata.sharedEvmFamilyKey.keyHandle || '').trim()
    : '';
  if (!directKeyHandle) {
    return { kind: 'blocked', reason: 'missing_key_handle' };
  }
  if (directKeyHandle && sharedKeyHandle && directKeyHandle !== sharedKeyHandle) {
    return { kind: 'blocked', reason: 'ambiguous_key_handle' };
  }
  return { kind: 'resolved', keyHandle: directKeyHandle };
}

function parseProfileContinuityEvmFamilyEcdsaWalletKey(args: {
  nearAccountId: AccountId;
  metadata: Record<string, unknown>;
  keyHandle: string;
  chainTarget: ThresholdEcdsaChainTarget;
}): EvmFamilyEcdsaWalletKey | null {
  const sharedKey = isObject(args.metadata.sharedEvmFamilyKey)
    ? args.metadata.sharedEvmFamilyKey
    : null;
  const keyFacts = sharedKey || args.metadata;
  const thresholdEcdsaPublicKeyB64u = String(
    keyFacts.thresholdEcdsaPublicKeyB64u || args.metadata.thresholdEcdsaPublicKeyB64u || '',
  ).trim();
  if (!thresholdEcdsaPublicKeyB64u) return null;
  try {
    toThresholdEcdsaPublicKeyB64u(thresholdEcdsaPublicKeyB64u);
    return buildEvmFamilyEcdsaWalletKey({
      walletId: keyFacts.walletId || args.nearAccountId,
      rpId: keyFacts.rpId || args.metadata.rpId,
      keyHandle: args.keyHandle,
      chainTarget: args.chainTarget,
      ecdsaThresholdKeyId: keyFacts.ecdsaThresholdKeyId || args.metadata.ecdsaThresholdKeyId,
      signingRootId: keyFacts.signingRootId || args.metadata.signingRootId,
      signingRootVersion: keyFacts.signingRootVersion || args.metadata.signingRootVersion,
      participantIds: keyFacts.participantIds || args.metadata.participantIds,
      thresholdOwnerAddress:
        keyFacts.thresholdOwnerAddress ||
        args.metadata.thresholdOwnerAddress ||
        args.metadata.ownerAddress,
      thresholdEcdsaPublicKeyB64u,
    });
  } catch {
    return null;
  }
}

export function parseProfileContinuityEcdsaWarmKey(args: {
  nearAccountId: AccountId;
  configuredTargets: readonly ThresholdEcdsaChainTarget[];
  signer: unknown;
}): ProfileContinuityEcdsaWarmKeyParseResult {
  const signer = isObject(args.signer) ? args.signer : {};
  if (signer.status && signer.status !== 'active') return { kind: 'skipped' };
  if (signer.signerKind && signer.signerKind !== SIGNER_KINDS.thresholdEcdsa) {
    return { kind: 'skipped' };
  }
  if (signer.signerAuthMethod && signer.signerAuthMethod !== SIGNER_AUTH_METHODS.passkey) {
    return { kind: 'skipped' };
  }
  const metadata = isObject(signer.metadata) ? signer.metadata : {};
  if (!isObject(metadata.chainTarget)) {
    return {
      kind: 'blocked',
      targetKey: '',
      reason: 'missing_chain_target',
    };
  }
  let chainTarget: ThresholdEcdsaChainTarget;
  try {
    chainTarget = thresholdEcdsaChainTargetFromRequest(metadata.chainTarget);
  } catch (error: unknown) {
    void error;
    return {
      kind: 'blocked',
      targetKey: '',
      reason: 'invalid_chain_target',
    };
  }
  if (
    !args.configuredTargets.some((target) => thresholdEcdsaChainTargetsEqual(target, chainTarget))
  ) {
    return { kind: 'skipped' };
  }
  const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
  const keyHandleResolution = resolveProfileContinuityEcdsaKeyHandle(metadata);
  if (keyHandleResolution.kind === 'blocked') {
    return {
      kind: 'blocked',
      targetKey,
      reason: keyHandleResolution.reason,
    };
  }
  const walletKey = parseProfileContinuityEvmFamilyEcdsaWalletKey({
    nearAccountId: args.nearAccountId,
    metadata,
    keyHandle: keyHandleResolution.keyHandle,
    chainTarget,
  });
  if (!walletKey) {
    return {
      kind: 'repair_required',
      chainTarget,
      targetKey,
      keyHandle: keyHandleResolution.keyHandle,
      reason: 'missing_key_facts',
    };
  }
  return {
    kind: 'active_wallet_key',
    chainTarget,
    targetKey,
    walletKey,
  };
}

function parseThresholdEcdsaKeyIdentityRecord(args: {
  nearAccountId: AccountId;
  rpId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  raw: unknown;
}): ThresholdEcdsaKeyIdentityInventoryEntry | null {
  const { raw } = args;
  if (!isObject(raw) || !isObject(raw.chainTarget)) {
    return null;
  }
  const rawKey = isObject(raw.key) ? raw.key : raw;
  let chainTarget: ThresholdEcdsaChainTarget;
  try {
    chainTarget = thresholdEcdsaChainTargetFromRequest(raw.chainTarget);
  } catch {
    return null;
  }
  const keyHandle = String(raw.keyHandle || '').trim();
  const accountAddress = normalizeEvmOwnerAddress(raw.accountAddress);
  const ownerAddress = normalizeEvmOwnerAddress(raw.ownerAddress);
  const keyWalletId = String(rawKey.walletId || rawKey.walletSessionUserId || '').trim();
  const rawKeySubjectId = String(rawKey.subjectId || '').trim();
  const expectedKeySubjectId = String(
    walletIdFromWalletProfile({ walletId: args.nearAccountId }),
  );
  const keyRpId = String(rawKey.rpId || '').trim();
  const thresholdEcdsaPublicKeyB64u = String(
    rawKey.thresholdEcdsaPublicKeyB64u || raw.thresholdEcdsaPublicKeyB64u || '',
  ).trim();
  const thresholdOwnerAddress = normalizeEvmOwnerAddress(
    rawKey.thresholdOwnerAddress || raw.ownerAddress || raw.accountAddress || raw.ethereumAddress,
  );
  if (
    !keyHandle ||
    isSyntheticLegacyIdentifier(keyHandle) ||
    isSyntheticLegacyIdentifier(raw.ecdsaThresholdKeyId) ||
    !thresholdEcdsaPublicKeyB64u ||
    !ownerAddress ||
    !accountAddress ||
    !thresholdOwnerAddress ||
    keyWalletId !== String(args.nearAccountId) ||
    (rawKeySubjectId && rawKeySubjectId !== expectedKeySubjectId) ||
    keyRpId !== args.rpId ||
    thresholdOwnerAddress !== ownerAddress
  ) {
    return null;
  }
  try {
    const canonicalKeyHandle = toEvmFamilyEcdsaKeyHandle(keyHandle);
    const ecdsaThresholdKeyId = resolveThresholdEcdsaKeyIdFromRecord({
      record: {
        ecdsaThresholdKeyId: raw.ecdsaThresholdKeyId,
      },
    });
    const signingRootBinding = resolveThresholdSigningRootBindingFromRecord({
      record: {
        keyHandle: canonicalKeyHandle,
        runtimePolicyScope: args.runtimePolicyScope,
        signingRootId: raw.signingRootId || rawKey.signingRootId,
        signingRootVersion: raw.signingRootVersion || rawKey.signingRootVersion,
      },
    });
    return {
      accountAddress,
      ownerAddress,
      walletKey: buildEvmFamilyEcdsaWalletKey({
        walletId: args.nearAccountId,
        rpId: args.rpId,
        keyHandle: canonicalKeyHandle,
        chainTarget,
        ecdsaThresholdKeyId,
        signingRootId: signingRootBinding.signingRootId,
        signingRootVersion: signingRootBinding.signingRootVersion,
        participantIds: rawKey.participantIds || raw.participantIds,
        thresholdOwnerAddress,
        thresholdEcdsaPublicKeyB64u,
      }),
    };
  } catch {
    return null;
  }
}

export function parseThresholdEcdsaKeyIdentityTargets(args: {
  nearAccountId: AccountId;
  rpId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  records: readonly unknown[];
}): ThresholdEcdsaKeyIdentityInventoryEntry[] {
  const entries: ThresholdEcdsaKeyIdentityInventoryEntry[] = [];
  for (const raw of args.records) {
    const parsed = parseThresholdEcdsaKeyIdentityRecord({
      nearAccountId: args.nearAccountId,
      rpId: args.rpId,
      ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
      raw,
    });
    if (!parsed) continue;
    entries.push(parsed);
  }
  return entries;
}
