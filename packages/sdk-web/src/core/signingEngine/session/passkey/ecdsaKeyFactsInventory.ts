import { isObject } from '@shared/utils/validation';
import type { AccountSignerRecord } from '@/core/indexedDB/passkeyClientDB.types';
import {
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  walletIdFromWalletProfile,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '../../interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyEcdsaWalletKey,
  parseThresholdSigningRootBinding,
  resolveThresholdEcdsaKeyIdFromRecord,
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
      kind: 'key_facts_inventory_required';
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
        | 'invalid_key_handle'
        | 'duplicate_key_handles';
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

const EVM_FAMILY_ECDSA_KEY_HANDLE_PATTERN = /^ehss-key-[A-Za-z0-9_-]+$/;

function parseCurrentEcdsaKeyHandle(value: unknown):
  | { kind: 'resolved'; keyHandle: string }
  | { kind: 'missing' }
  | { kind: 'invalid' } {
  const normalized = String(value || '').trim();
  if (!normalized) return { kind: 'missing' };
  if (!EVM_FAMILY_ECDSA_KEY_HANDLE_PATTERN.test(normalized)) return { kind: 'invalid' };
  return { kind: 'resolved', keyHandle: normalized };
}

function resolveProfileContinuityEcdsaKeyHandle(metadata: Record<string, unknown>):
  | { kind: 'resolved'; keyHandle: string }
  | {
      kind: 'blocked';
      reason: 'missing_key_handle' | 'invalid_key_handle' | 'duplicate_key_handles';
    } {
  const directKeyHandle = parseCurrentEcdsaKeyHandle(metadata.keyHandle);
  const sharedKeyHandle = isObject(metadata.sharedEvmFamilyKey)
    ? parseCurrentEcdsaKeyHandle(metadata.sharedEvmFamilyKey.keyHandle)
    : { kind: 'missing' as const };
  if (directKeyHandle.kind === 'missing') {
    return { kind: 'blocked', reason: 'missing_key_handle' };
  }
  if (directKeyHandle.kind === 'invalid' || sharedKeyHandle.kind === 'invalid') {
    return { kind: 'blocked', reason: 'invalid_key_handle' };
  }
  if (
    sharedKeyHandle.kind === 'resolved' &&
    directKeyHandle.keyHandle !== sharedKeyHandle.keyHandle
  ) {
    return { kind: 'blocked', reason: 'duplicate_key_handles' };
  }
  return { kind: 'resolved', keyHandle: directKeyHandle.keyHandle };
}

function parseProfileContinuityEvmFamilyEcdsaWalletKey(args: {
  walletId: WalletId;
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
  const keyWalletId = String(keyFacts.walletId || '').trim();
  if (!keyWalletId) return null;
  try {
    toThresholdEcdsaPublicKeyB64u(thresholdEcdsaPublicKeyB64u);
    const ecdsaThresholdKeyId = keyFacts.ecdsaThresholdKeyId || args.metadata.ecdsaThresholdKeyId;
    const signingRootId = keyFacts.signingRootId || args.metadata.signingRootId;
    const signingRootVersion = keyFacts.signingRootVersion || args.metadata.signingRootVersion;
    const participantIds = keyFacts.participantIds || args.metadata.participantIds;
    const thresholdOwnerAddress =
      keyFacts.thresholdOwnerAddress ||
      args.metadata.thresholdOwnerAddress ||
      args.metadata.ownerAddress;
    const evmFamilySigningKeySlotId = keyFacts.evmFamilySigningKeySlotId || args.metadata.evmFamilySigningKeySlotId;
    if (!evmFamilySigningKeySlotId) return null;
    return buildEvmFamilyEcdsaWalletKey({
      walletId: keyWalletId,
      evmFamilySigningKeySlotId,
      keyHandle: args.keyHandle,
      chainTarget: args.chainTarget,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      participantIds,
      thresholdOwnerAddress,
      thresholdEcdsaPublicKeyB64u,
    });
  } catch {
    return null;
  }
}

export function parseProfileContinuityEcdsaWarmKey(args: {
  walletId: WalletId;
  configuredTargets: readonly ThresholdEcdsaChainTarget[];
  signer: AccountSignerRecord;
}): ProfileContinuityEcdsaWarmKeyParseResult {
  const signer = args.signer;
  if (signer.status !== 'active') return { kind: 'skipped' };
  if (signer.signerKind !== SIGNER_KINDS.thresholdEcdsa) {
    return { kind: 'skipped' };
  }
  if (signer.signerAuthMethod !== SIGNER_AUTH_METHODS.passkey) {
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
    walletId: args.walletId,
    metadata,
    keyHandle: keyHandleResolution.keyHandle,
    chainTarget,
  });
  if (!walletKey) {
    return {
      kind: 'key_facts_inventory_required',
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
  walletId: WalletId;
  rpId: string;
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
  const keyHandle = parseCurrentEcdsaKeyHandle(raw.keyHandle);
  const accountAddress = normalizeEvmOwnerAddress(raw.accountAddress);
  const ownerAddress = normalizeEvmOwnerAddress(raw.ownerAddress);
  const keyWalletId = String(rawKey.walletId || '').trim();
  const rawKeySubjectId = String(rawKey.subjectId || '').trim();
  const expectedKeySubjectId = String(walletIdFromWalletProfile({ walletId: args.walletId }));
  const keyRpId = String(rawKey.rpId || '').trim();
  const thresholdEcdsaPublicKeyB64u = String(
    rawKey.thresholdEcdsaPublicKeyB64u || raw.thresholdEcdsaPublicKeyB64u || '',
  ).trim();
  const thresholdOwnerAddress = normalizeEvmOwnerAddress(
    rawKey.thresholdOwnerAddress || raw.ownerAddress || raw.accountAddress || raw.ethereumAddress,
  );
  if (
    keyHandle.kind !== 'resolved' ||
    !thresholdEcdsaPublicKeyB64u ||
    !ownerAddress ||
    !accountAddress ||
    !thresholdOwnerAddress ||
    keyWalletId !== String(args.walletId) ||
    (rawKeySubjectId && rawKeySubjectId !== expectedKeySubjectId) ||
    keyRpId !== args.rpId ||
    thresholdOwnerAddress !== ownerAddress
  ) {
    return null;
  }
  try {
    const canonicalKeyHandle = toEvmFamilyEcdsaKeyHandle(keyHandle.keyHandle);
    const ecdsaThresholdKeyId = resolveThresholdEcdsaKeyIdFromRecord({
      record: {
        ecdsaThresholdKeyId: raw.ecdsaThresholdKeyId,
      },
    });
    const signingRootBinding = parseThresholdSigningRootBinding({
      signingRootId: raw.signingRootId || rawKey.signingRootId,
      signingRootVersion: raw.signingRootVersion || rawKey.signingRootVersion,
    });
    const evmFamilySigningKeySlotId = rawKey.evmFamilySigningKeySlotId || raw.evmFamilySigningKeySlotId;
    if (!evmFamilySigningKeySlotId) return null;
    return {
      accountAddress,
      ownerAddress,
      walletKey: buildEvmFamilyEcdsaWalletKey({
        walletId: args.walletId,
        evmFamilySigningKeySlotId,
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
  walletId: WalletId;
  rpId: string;
  records: readonly unknown[];
}): ThresholdEcdsaKeyIdentityInventoryEntry[] {
  const entries: ThresholdEcdsaKeyIdentityInventoryEntry[] = [];
  for (const raw of args.records) {
    const parsed = parseThresholdEcdsaKeyIdentityRecord({
      walletId: args.walletId,
      rpId: args.rpId,
      raw,
    });
    if (!parsed) continue;
    entries.push(parsed);
  }
  return entries;
}
