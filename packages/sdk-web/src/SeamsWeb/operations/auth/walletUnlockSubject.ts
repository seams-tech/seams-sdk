import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import { IndexedDBManager } from '@/core/indexedDB';
import type { AccountSignerRecord, LastProfileState } from '@/core/indexedDB/passkeyClientDB.types';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  parseNearEd25519SigningKeyId,
  type NearEd25519SigningKeyId,
} from '@shared/utils/registrationIntent';
import { parseSignerSlot, type SignerSlot } from '@shared/utils/signerSlot';
import {
  resolveEvmFamilyEcdsaWalletUnlockSubjects,
  type WalletUnlockCapabilitySubjectResolutionFailure,
} from './walletUnlockEcdsaSubject';
import type {
  NearEd25519WalletUnlockSubject,
  WalletUnlockSubject,
  WalletUnlockSubjectSet,
} from '@/core/signingEngine/session/identity/walletUnlockSubject';

export type {
  NearEd25519WalletUnlockSubject,
  WalletUnlockSubject,
  WalletUnlockSubjectSet,
} from '@/core/signingEngine/session/identity/walletUnlockSubject';

export type WalletUnlockCapabilityFamilyScope =
  | { readonly kind: 'near_ed25519_only' }
  | { readonly kind: 'evm_family_ecdsa_only' }
  | { readonly kind: 'all_registered_mpc' };

export type WalletUnlockSubjectSetResolution =
  | {
      readonly kind: 'resolved';
      readonly subjectSet: WalletUnlockSubjectSet;
    }
  | {
      readonly kind: 'missing_requested_capability_subject';
      readonly walletId: WalletId;
      readonly subjectSet?: never;
      readonly reason?: never;
    }
  | {
      readonly kind: 'capability_subject_resolution_failed';
      readonly walletId: WalletId;
      readonly reason: WalletUnlockCapabilitySubjectResolutionFailure;
      readonly subjectSet?: never;
    };

export type WalletIdentitySource =
  | 'profile_projection'
  | 'host_last_used_profile';

export type WalletIdentityResolveFailure =
  | 'missing_wallet_profile'
  | 'ambiguous_wallet_profile'
  | 'missing_requested_capability_subject'
  | WalletUnlockCapabilitySubjectResolutionFailure
  | 'invalid_wallet_profile';

export type WalletCapabilitySubjectResolution =
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
      subjectSet: WalletUnlockSubjectSet;
      source: WalletIdentitySource;
      reason?: never;
    }
  | {
      kind: 'no_session_for_wallet';
      walletId: WalletId;
      profileId?: never;
      reason: 'missing_requested_capability_subject';
      source: WalletIdentitySource;
      subjectSet?: never;
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

type NearEd25519WalletUnlockSubjectParseResult =
  | {
      readonly kind: 'absent';
      readonly subject?: never;
    }
  | {
      readonly kind: 'valid';
      readonly subject: NearEd25519WalletUnlockSubject;
    }
  | {
      readonly kind: 'invalid';
      readonly subject?: never;
    };

type NearEd25519WalletUnlockSubjectsResolution =
  | {
      readonly kind: 'resolved';
      readonly subjects: readonly NearEd25519WalletUnlockSubject[];
      readonly reason?: never;
    }
  | {
      readonly kind: 'failed';
      readonly reason: WalletUnlockCapabilitySubjectResolutionFailure;
      readonly subjects?: never;
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

function nearEd25519WalletUnlockSubjectFromSigner(
  walletId: WalletId,
  signer: AccountSignerRecord,
): NearEd25519WalletUnlockSubjectParseResult {
  try {
    const metadataWalletId = String(signer.metadata?.walletId || '').trim();
    if (metadataWalletId && metadataWalletId !== String(walletId)) {
      return { kind: 'invalid' };
    }
    const signerSlot = parseSignerSlot(signer.signerSlot);
    if (!signerSlot) return { kind: 'invalid' };
    return {
      kind: 'valid',
      subject: {
        kind: 'near_ed25519_wallet',
        walletId,
        nearAccountId: toAccountId(
          requiredWalletUnlockMetadataString(signer.metadata, 'nearAccountId'),
        ),
        nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(
          requiredWalletUnlockMetadataString(signer.metadata, 'nearEd25519SigningKeyId'),
        ),
        signerSlot,
      },
    };
  } catch {
    return { kind: 'invalid' };
  }
}

async function resolveNearEd25519WalletUnlockSubjects(
  walletId: WalletId,
): Promise<NearEd25519WalletUnlockSubjectsResolution> {
  const subjects: NearEd25519WalletUnlockSubject[] = [];
  let signers: AccountSignerRecord[];
  try {
    signers = await IndexedDBManager.listActiveWalletSigners({
      walletId,
      signerFamily: 'ed25519',
    });
  } catch {
    return {
      kind: 'failed',
      reason: 'capability_subject_lookup_failed',
    };
  }
  for (const signer of signers) {
    const parsed = nearEd25519WalletUnlockSubjectFromSigner(walletId, signer);
    if (parsed.kind !== 'valid') {
      return {
        kind: 'failed',
        reason: 'invalid_capability_subject',
      };
    }
    subjects.push(parsed.subject);
  }
  return {
    kind: 'resolved',
    subjects,
  };
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
      return [
        subject.kind,
        subject.walletId,
        subject.capability,
        subject.authority.authorityDigest,
        subject.ecdsaThresholdKeyId,
      ].join('\0');
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
  subject: WalletUnlockSubject,
): void {
  const key = walletUnlockSubjectKey(subject);
  if (walletUnlockSubjectsIncludeKey(subjects, key)) return;
  subjects.push(subject);
}

function isNearEd25519WalletUnlockSubject(
  subject: WalletUnlockSubject,
): subject is Extract<WalletUnlockSubject, { kind: 'near_ed25519_wallet' }> {
  return subject.kind === 'near_ed25519_wallet';
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

function signerMetadataWalletId(signer: AccountSignerRecord): WalletId | null {
  const value = String(signer.metadata?.walletId || '').trim();
  if (!value) return null;
  try {
    return toWalletId(value);
  } catch {
    return null;
  }
}

function uniqueSignerMetadataWalletIds(signers: readonly AccountSignerRecord[]):
  | {
      readonly kind: 'resolved';
      readonly walletIds: readonly WalletId[];
    }
  | {
      readonly kind: 'invalid';
      readonly walletIds?: never;
    } {
  const walletIds: WalletId[] = [];
  const seen = new Set<string>();
  for (const signer of signers) {
    const walletId = signerMetadataWalletId(signer);
    if (!walletId) return { kind: 'invalid' };
    const key = String(walletId);
    if (seen.has(key)) continue;
    seen.add(key);
    walletIds.push(walletId);
  }
  return {
    kind: 'resolved',
    walletIds,
  };
}

async function resolveWalletIdForLastUsedProfile(
  profileId: string,
): Promise<LastUsedProfileWalletResolution> {
  let profile: Awaited<ReturnType<typeof IndexedDBManager.getProfile>>;
  try {
    profile = await IndexedDBManager.getProfile(profileId);
  } catch {
    return {
      kind: 'unresolvable_profile',
      reason: 'capability_subject_lookup_failed',
    };
  }
  if (!profile) {
    return {
      kind: 'unresolvable_profile',
      reason: 'missing_wallet_profile',
    };
  }
  let signers: AccountSignerRecord[];
  try {
    signers = await IndexedDBManager.listAccountSignersByProfile({
      profileId,
      status: 'active',
    });
  } catch {
    return {
      kind: 'unresolvable_profile',
      reason: 'capability_subject_lookup_failed',
    };
  }
  if (signers.length === 0) {
    return {
      kind: 'unresolvable_profile',
      reason: 'missing_requested_capability_subject',
    };
  }
  const walletIdResolution = uniqueSignerMetadataWalletIds(signers);
  if (walletIdResolution.kind === 'invalid') {
    return {
      kind: 'unresolvable_profile',
      reason: 'invalid_wallet_profile',
    };
  }
  const walletIds = walletIdResolution.walletIds;
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

function buildWalletUnlockSubjectSet(
  walletId: WalletId,
  subjects: readonly WalletUnlockSubject[],
): WalletUnlockSubjectSetResolution {
  const first = subjects[0];
  if (!first) {
    return {
      kind: 'missing_requested_capability_subject',
      walletId,
    };
  }
  return {
    kind: 'resolved',
    subjectSet: {
      kind: 'wallet_unlock_subject_set',
      walletId,
      subjects: [first, ...subjects.slice(1)],
    },
  };
}

function walletSessionReadFailureForSubjectSet(
  subjectSet: WalletUnlockSubjectSet,
): WalletIdentityResolveFailure | null {
  const nearSubjects = subjectSet.subjects.filter(isNearEd25519WalletUnlockSubject);
  if (nearSubjects.length > 1) return 'ambiguous_wallet_profile';
  return null;
}

export async function resolveWalletUnlockSubjectSet(args: {
  readonly walletId: string;
  readonly requestedCapabilityFamilies: WalletUnlockCapabilityFamilyScope;
}): Promise<WalletUnlockSubjectSetResolution> {
  const normalizedWalletId = toWalletId(args.walletId);
  const subjects: WalletUnlockSubject[] = [];
  switch (args.requestedCapabilityFamilies.kind) {
    case 'near_ed25519_only':
    case 'all_registered_mpc': {
      const nearResolution = await resolveNearEd25519WalletUnlockSubjects(normalizedWalletId);
      if (nearResolution.kind === 'failed') {
        return {
          kind: 'capability_subject_resolution_failed',
          walletId: normalizedWalletId,
          reason: nearResolution.reason,
        };
      }
      for (const subject of nearResolution.subjects) {
        appendUniqueWalletUnlockSubject(subjects, subject);
      }
      if (args.requestedCapabilityFamilies.kind === 'near_ed25519_only') {
        return buildWalletUnlockSubjectSet(normalizedWalletId, subjects);
      }
      break;
    }
    case 'evm_family_ecdsa_only':
      break;
    default:
      args.requestedCapabilityFamilies satisfies never;
  }
  const ecdsaResolution = await resolveEvmFamilyEcdsaWalletUnlockSubjects(normalizedWalletId);
  if (ecdsaResolution.kind === 'failed') {
    return {
      kind: 'capability_subject_resolution_failed',
      walletId: normalizedWalletId,
      reason: ecdsaResolution.reason,
    };
  }
  for (const subject of ecdsaResolution.subjects) {
    appendUniqueWalletUnlockSubject(subjects, subject);
  }
  return buildWalletUnlockSubjectSet(normalizedWalletId, subjects);
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
  const resolution = await resolveWalletUnlockSubjectSet({
    walletId,
    requestedCapabilityFamilies: { kind: 'near_ed25519_only' },
  });
  if (resolution.kind === 'missing_requested_capability_subject') return null;
  if (resolution.kind === 'capability_subject_resolution_failed') {
    throw new Error(`wallet unlock subject resolution failed: ${resolution.reason}`);
  }
  return selectNearEd25519WalletUnlockSubject(resolution.subjectSet);
}

export async function resolveWalletCapabilitySubjectResolution(
  walletId?: WalletId | string,
): Promise<WalletCapabilitySubjectResolution> {
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
    source = 'host_last_used_profile';
  } else {
    resolvedWalletId = target.walletId;
    source = 'profile_projection';
  }
  const subjectResolution = await resolveWalletUnlockSubjectSet({
    walletId: String(resolvedWalletId),
    requestedCapabilityFamilies: { kind: 'all_registered_mpc' },
  });
  if (subjectResolution.kind === 'missing_requested_capability_subject') {
    return {
      kind: 'no_session_for_wallet',
      walletId: resolvedWalletId,
      reason: 'missing_requested_capability_subject',
      source,
    };
  }
  if (subjectResolution.kind === 'capability_subject_resolution_failed') {
    return {
      kind: 'unresolvable',
      walletId: resolvedWalletId,
      reason: subjectResolution.reason,
    };
  }
  const subjectSet = subjectResolution.subjectSet;
  const failure = walletSessionReadFailureForSubjectSet(subjectSet);
  if (failure) {
    return {
      kind: 'unresolvable',
      walletId: resolvedWalletId,
      reason: failure,
    };
  }

  return {
    kind: 'resolved',
    walletId: resolvedWalletId,
    subjectSet,
    source,
  };
}
