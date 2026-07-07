import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import { IndexedDBManager } from '@/core/indexedDB';
import type { AccountSignerRecord, LastProfileState } from '@/core/indexedDB/passkeyClientDB.types';
import { getStoredThresholdEd25519SessionRecordForWallet } from '@/core/signingEngine/session/persistence/records';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  parseNearEd25519SigningKeyId,
  type NearEd25519SigningKeyId,
} from '@shared/utils/registrationIntent';
import { parseSignerSlot, type SignerSlot } from '@shared/utils/signerSlot';
import {
  requireEvmFamilySigningKeySlotId,
  type EvmFamilySigningKeySlotId,
} from '@shared/signing-lanes';

export type WalletUnlockSubject =
  | {
      kind: 'near_ed25519_wallet';
      walletId: WalletId;
      nearAccountId: AccountId;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
      signerSlot: SignerSlot;
    }
  | {
      kind: 'evm_family_ecdsa_wallet';
      walletId: WalletId;
      evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
    };

export type WalletUnlockSubjectSet = {
  readonly kind: 'wallet_unlock_subject_set';
  readonly walletId: WalletId;
  readonly subjects: readonly WalletUnlockSubject[];
};

export type ResolvedWalletUnlockSubjectSet = WalletUnlockSubjectSet & {
  readonly subjects: readonly [WalletUnlockSubject, ...WalletUnlockSubject[]];
};

export type WalletIdentitySource =
  | 'runtime_session_record'
  | 'profile_projection'
  | 'host_last_used_profile';

export type WalletIdentityResolveFailure =
  | 'missing_wallet_profile'
  | 'ambiguous_wallet_profile'
  | 'missing_requested_capability_subject'
  | 'invalid_wallet_profile';

export type WalletSessionReadResolution =
  | {
      kind: 'no_session_request';
      walletId?: never;
      profileId?: never;
      subjectSet?: never;
      source?: never;
      reason?: never;
    }
  | {
      kind: 'resolved';
      walletId: WalletId;
      profileId?: never;
      subjectSet: ResolvedWalletUnlockSubjectSet;
      source: WalletIdentitySource;
      reason?: never;
    }
  | {
      kind: 'unresolvable';
      walletId: WalletId;
      profileId?: never;
      reason: WalletIdentityResolveFailure;
      subjectSet?: never;
      source?: never;
    }
  | {
      kind: 'unresolvable_profile';
      profileId: string;
      walletId?: never;
      reason: WalletIdentityResolveFailure;
      subjectSet?: never;
      source?: never;
    };

type WalletSessionReadTarget =
  | {
      kind: 'explicit_wallet';
      walletId: WalletId;
    }
  | {
      kind: 'last_used_profile';
      profileId: string;
    }
  | {
      kind: 'none';
      walletId?: never;
      profileId?: never;
    };

type LastUsedProfileWalletResolution =
  | {
      kind: 'resolved_wallet';
      walletId: WalletId;
      reason?: never;
    }
  | {
      kind: 'unresolvable_profile';
      walletId?: never;
      reason: WalletIdentityResolveFailure;
    };

function requiredWalletUnlockMetadataString(
  metadata: Record<string, unknown> | undefined,
  field: string,
): string {
  const value = metadata?.[field];
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`wallet unlock signer metadata requires ${field}`);
  }
  return value.trim();
}

function nearEd25519WalletUnlockSubjectFromRuntimeRecord(
  walletId: WalletId,
): Extract<WalletUnlockSubject, { kind: 'near_ed25519_wallet' }> | null {
  const record = getStoredThresholdEd25519SessionRecordForWallet(walletId);
  if (!record?.nearAccountId) return null;
  const signerSlot = parseSignerSlot(record.signerSlot);
  if (!signerSlot) return null;
  return {
    kind: 'near_ed25519_wallet',
    walletId,
    nearAccountId: toAccountId(String(record.nearAccountId)),
    nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(record.nearEd25519SigningKeyId),
    signerSlot,
  };
}

function nearEd25519WalletUnlockSubjectFromSigner(
  walletId: WalletId,
  signer: AccountSignerRecord,
): Extract<WalletUnlockSubject, { kind: 'near_ed25519_wallet' }> | null {
  try {
    const metadataWalletId = String(signer.metadata?.walletId || '').trim();
    if (metadataWalletId && metadataWalletId !== String(walletId)) return null;
    const signerSlot = parseSignerSlot(signer.signerSlot);
    if (!signerSlot) return null;
    return {
      kind: 'near_ed25519_wallet',
      walletId,
      nearAccountId: toAccountId(
        requiredWalletUnlockMetadataString(signer.metadata, 'nearAccountId'),
      ),
      nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(
        requiredWalletUnlockMetadataString(signer.metadata, 'nearEd25519SigningKeyId'),
      ),
      signerSlot,
    };
  } catch {
    return null;
  }
}

function evmFamilyEcdsaWalletUnlockSubjectFromSigner(
  walletId: WalletId,
  signer: AccountSignerRecord,
): Extract<WalletUnlockSubject, { kind: 'evm_family_ecdsa_wallet' }> | null {
  try {
    const metadataWalletId = String(signer.metadata?.walletId || '').trim();
    if (metadataWalletId && metadataWalletId !== String(walletId)) return null;
    return {
      kind: 'evm_family_ecdsa_wallet',
      walletId,
      evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
        requiredWalletUnlockMetadataString(signer.metadata, 'evmFamilySigningKeySlotId'),
      ),
    };
  } catch {
    return null;
  }
}

function walletUnlockSubjectKey(subject: WalletUnlockSubject): string {
  switch (subject.kind) {
    case 'near_ed25519_wallet':
      return [
        subject.kind,
        subject.walletId,
        subject.nearAccountId,
        subject.nearEd25519SigningKeyId,
        subject.signerSlot,
      ].join('\0');
    case 'evm_family_ecdsa_wallet':
      return [subject.kind, subject.walletId, subject.evmFamilySigningKeySlotId].join('\0');
  }
  subject satisfies never;
  return '';
}

function walletUnlockSubjectsIncludeKey(
  subjects: readonly WalletUnlockSubject[],
  key: string,
): boolean {
  for (const subject of subjects) {
    if (walletUnlockSubjectKey(subject) === key) return true;
  }
  return false;
}

function appendUniqueWalletUnlockSubject(
  subjects: WalletUnlockSubject[],
  subject: WalletUnlockSubject | null,
): void {
  if (!subject) return;
  const key = walletUnlockSubjectKey(subject);
  if (walletUnlockSubjectsIncludeKey(subjects, key)) return;
  subjects.push(subject);
}

function noWalletUnlockSignerRecordsAfterLookupFailure(): AccountSignerRecord[] {
  return [];
}

function isNearEd25519WalletUnlockSubject(
  subject: WalletUnlockSubject,
): subject is Extract<WalletUnlockSubject, { kind: 'near_ed25519_wallet' }> {
  return subject.kind === 'near_ed25519_wallet';
}

function hasRuntimeWalletSessionRecord(walletId: WalletId): boolean {
  return Boolean(getStoredThresholdEd25519SessionRecordForWallet(walletId));
}

function parseWalletSessionReadWalletId(raw: WalletId | string | undefined): WalletId | null {
  const value = String(raw || '').trim();
  if (!value) return null;
  try {
    return toWalletId(value);
  } catch {
    return null;
  }
}

function parseWalletSessionReadProfileId(raw: string | undefined): string | null {
  const value = String(raw || '').trim();
  return value ? value : null;
}

function lastProfileWalletSessionReadTarget(
  lastProfileState: LastProfileState | null,
): WalletSessionReadTarget {
  const profileId = parseWalletSessionReadProfileId(lastProfileState?.profileId);
  if (!profileId) return { kind: 'none' };
  return {
    kind: 'last_used_profile',
    profileId,
  };
}

async function resolveLastUsedWalletSessionReadTarget(): Promise<WalletSessionReadTarget> {
  return lastProfileWalletSessionReadTarget(
    await IndexedDBManager.getLastProfileState().catch(() => null),
  );
}

async function resolveWalletSessionReadTarget(
  walletId: WalletId | string | undefined,
): Promise<WalletSessionReadTarget> {
  const explicitWalletId = parseWalletSessionReadWalletId(walletId);
  if (explicitWalletId) {
    return {
      kind: 'explicit_wallet',
      walletId: explicitWalletId,
    };
  }
  if (walletId) return { kind: 'none' };
  return await resolveLastUsedWalletSessionReadTarget();
}

function walletSessionReadSourceForTarget(
  target: Exclude<WalletSessionReadTarget, { kind: 'none' | 'last_used_profile' }>,
): WalletIdentitySource {
  if (hasRuntimeWalletSessionRecord(target.walletId)) return 'runtime_session_record';
  return 'profile_projection';
}

function walletSessionReadSourceForLastUsedProfile(walletId: WalletId): WalletIdentitySource {
  return hasRuntimeWalletSessionRecord(walletId)
    ? 'runtime_session_record'
    : 'host_last_used_profile';
}

function signerMetadataWalletId(signer: AccountSignerRecord): WalletId | null {
  const value = String(signer.metadata?.walletId || '').trim();
  if (!value) return null;
  try {
    return toWalletId(value);
  } catch {
    return null;
  }
}

function uniqueSignerMetadataWalletIds(signers: readonly AccountSignerRecord[]): WalletId[] {
  const walletIds: WalletId[] = [];
  const seen = new Set<string>();
  for (const signer of signers) {
    const walletId = signerMetadataWalletId(signer);
    if (!walletId) continue;
    const key = String(walletId);
    if (seen.has(key)) continue;
    seen.add(key);
    walletIds.push(walletId);
  }
  return walletIds;
}

async function resolveWalletIdForLastUsedProfile(
  profileId: string,
): Promise<LastUsedProfileWalletResolution> {
  const profile = await IndexedDBManager.getProfile(profileId).catch(() => null);
  if (!profile) {
    return {
      kind: 'unresolvable_profile',
      reason: 'missing_wallet_profile',
    };
  }
  const signers = await IndexedDBManager.listAccountSignersByProfile({
    profileId,
    status: 'active',
  }).catch(noWalletUnlockSignerRecordsAfterLookupFailure);
  if (signers.length === 0) {
    return {
      kind: 'unresolvable_profile',
      reason: 'missing_requested_capability_subject',
    };
  }
  const walletIds = uniqueSignerMetadataWalletIds(signers);
  if (walletIds.length === 0) {
    return {
      kind: 'unresolvable_profile',
      reason: 'invalid_wallet_profile',
    };
  }
  if (walletIds.length > 1) {
    return {
      kind: 'unresolvable_profile',
      reason: 'ambiguous_wallet_profile',
    };
  }
  return {
    kind: 'resolved_wallet',
    walletId: walletIds[0]!,
  };
}

function asResolvedWalletUnlockSubjectSet(
  subjectSet: WalletUnlockSubjectSet,
): ResolvedWalletUnlockSubjectSet | null {
  if (subjectSet.subjects.length === 0) return null;
  return subjectSet as ResolvedWalletUnlockSubjectSet;
}

function walletSessionReadFailureForSubjectSet(
  subjectSet: WalletUnlockSubjectSet,
): WalletIdentityResolveFailure | null {
  if (subjectSet.subjects.length === 0) return 'missing_requested_capability_subject';
  const nearSubjects = subjectSet.subjects.filter(isNearEd25519WalletUnlockSubject);
  if (nearSubjects.length > 1) return 'ambiguous_wallet_profile';
  return null;
}

export async function resolveWalletUnlockSubjectSet(
  walletId: string,
): Promise<WalletUnlockSubjectSet> {
  const normalizedWalletId = toWalletId(walletId);
  const subjects: WalletUnlockSubject[] = [];
  appendUniqueWalletUnlockSubject(
    subjects,
    nearEd25519WalletUnlockSubjectFromRuntimeRecord(normalizedWalletId),
  );
  const [nearSigners, ecdsaSigners] = await Promise.all([
    IndexedDBManager.listActiveWalletSigners({
      walletId: normalizedWalletId,
      signerFamily: 'ed25519',
    }).catch(noWalletUnlockSignerRecordsAfterLookupFailure),
    IndexedDBManager.listActiveWalletSigners({
      walletId: normalizedWalletId,
      signerFamily: 'ecdsa',
    }).catch(noWalletUnlockSignerRecordsAfterLookupFailure),
  ]);
  for (const signer of nearSigners) {
    appendUniqueWalletUnlockSubject(
      subjects,
      nearEd25519WalletUnlockSubjectFromSigner(normalizedWalletId, signer),
    );
  }
  for (const signer of ecdsaSigners) {
    appendUniqueWalletUnlockSubject(
      subjects,
      evmFamilyEcdsaWalletUnlockSubjectFromSigner(normalizedWalletId, signer),
    );
  }
  return {
    kind: 'wallet_unlock_subject_set',
    walletId: normalizedWalletId,
    subjects,
  };
}

function selectNearEd25519WalletUnlockSubject(
  subjectSet: WalletUnlockSubjectSet,
): Extract<WalletUnlockSubject, { kind: 'near_ed25519_wallet' }> | null {
  const nearSubjects = subjectSet.subjects.filter(isNearEd25519WalletUnlockSubject);
  if (nearSubjects.length === 0) return null;
  if (nearSubjects.length > 1) {
    throw new Error('wallet unlock found multiple active NEAR Ed25519 subjects');
  }
  return nearSubjects[0] || null;
}

export async function resolveNearEd25519WalletUnlockSubject(
  walletId: string,
): Promise<Extract<WalletUnlockSubject, { kind: 'near_ed25519_wallet' }> | null> {
  return selectNearEd25519WalletUnlockSubject(await resolveWalletUnlockSubjectSet(walletId));
}

export async function resolveWalletSessionReadResolution(
  walletId?: WalletId | string,
): Promise<WalletSessionReadResolution> {
  const target = await resolveWalletSessionReadTarget(walletId);
  if (target.kind === 'none') return { kind: 'no_session_request' };

  let resolvedWalletId: WalletId;
  let source: WalletIdentitySource;
  if (target.kind === 'last_used_profile') {
    const walletTarget = await resolveWalletIdForLastUsedProfile(target.profileId);
    if (walletTarget.kind === 'unresolvable_profile') {
      return {
        kind: 'unresolvable_profile',
        profileId: target.profileId,
        reason: walletTarget.reason,
      };
    }
    resolvedWalletId = walletTarget.walletId;
    source = walletSessionReadSourceForLastUsedProfile(resolvedWalletId);
  } else {
    resolvedWalletId = target.walletId;
    source = walletSessionReadSourceForTarget(target);
  }
  const subjectSet = await resolveWalletUnlockSubjectSet(String(resolvedWalletId));
  const failure = walletSessionReadFailureForSubjectSet(subjectSet);
  if (failure) {
    return {
      kind: 'unresolvable',
      walletId: resolvedWalletId,
      reason: failure,
    };
  }

  const resolvedSubjectSet = asResolvedWalletUnlockSubjectSet(subjectSet);
  if (!resolvedSubjectSet) {
    return {
      kind: 'unresolvable',
      walletId: resolvedWalletId,
      reason: 'missing_requested_capability_subject',
    };
  }
  return {
    kind: 'resolved',
    walletId: resolvedWalletId,
    subjectSet: resolvedSubjectSet,
    source,
  };
}
