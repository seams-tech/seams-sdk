import { IndexedDbEcdsaCapabilityManifestStore } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import type { EcdsaWalletActivationSelectorListResult } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import type {
  EvmFamilyEcdsaWalletUnlockSubject,
  EvmFamilyEcdsaWalletUnlockSubjectSet,
} from '@/core/signingEngine/session/identity/walletUnlockSubject';
import { parseWalletId, type WalletId } from '@shared/utils/domainIds';

export type {
  EvmFamilyEcdsaWalletUnlockSubject,
  EvmFamilyEcdsaWalletUnlockSubjectSet,
} from '@/core/signingEngine/session/identity/walletUnlockSubject';

export type WalletUnlockCapabilitySubjectResolutionFailure =
  | 'capability_subject_lookup_failed'
  | 'invalid_capability_subject';

export type EvmFamilyEcdsaWalletUnlockSubjectSetResolution =
  | {
      readonly kind: 'resolved';
      readonly subjectSet: EvmFamilyEcdsaWalletUnlockSubjectSet;
      readonly reason?: never;
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

function requireWalletId(value: unknown): WalletId {
  const parsed = parseWalletId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

const ecdsaCapabilityManifestStore = new IndexedDbEcdsaCapabilityManifestStore();

async function listEvmFamilyEcdsaWalletUnlockSubjects(walletId: WalletId): Promise<
  | {
      readonly kind: 'resolved';
      readonly subjects: readonly EvmFamilyEcdsaWalletUnlockSubject[];
    }
  | {
      readonly kind: 'failed';
      readonly reason: WalletUnlockCapabilitySubjectResolutionFailure;
      readonly subjects?: never;
    }
> {
  const resolved = await ecdsaCapabilityManifestStore.listActiveWalletCapabilitySubjects(walletId);
  if (resolved.kind === 'persistence_unavailable') {
    return {
      kind: 'failed',
      reason: 'capability_subject_lookup_failed',
    };
  }
  if (resolved.kind === 'invalid_current_state') {
    return {
      kind: 'failed',
      reason: 'invalid_capability_subject',
    };
  }
  const subjects: EvmFamilyEcdsaWalletUnlockSubject[] = [];
  for (const subject of resolved.subjects) {
    subjects.push({
      kind: 'evm_family_ecdsa_wallet',
      walletId,
      capability: subject.capability,
      authority: subject.authority,
      ecdsaThresholdKeyId: subject.ecdsaThresholdKeyId,
    });
  }
  return {
    kind: 'resolved',
    subjects,
  };
}

export async function resolveEvmFamilyEcdsaWalletUnlockSubjectSet(
  rawWalletId: unknown,
): Promise<EvmFamilyEcdsaWalletUnlockSubjectSetResolution> {
  const walletId = requireWalletId(rawWalletId);
  const resolution = await listEvmFamilyEcdsaWalletUnlockSubjects(walletId);
  if (resolution.kind === 'failed') {
    return {
      kind: 'capability_subject_resolution_failed',
      walletId,
      reason: resolution.reason,
    };
  }
  const first = resolution.subjects[0];
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
      subjects: [first, ...resolution.subjects.slice(1)],
    },
  };
}

export async function resolveEvmFamilyEcdsaWalletUnlockSubjects(walletId: WalletId): Promise<
  | {
      readonly kind: 'resolved';
      readonly subjects: readonly EvmFamilyEcdsaWalletUnlockSubject[];
    }
  | {
      readonly kind: 'failed';
      readonly reason: WalletUnlockCapabilitySubjectResolutionFailure;
      readonly subjects?: never;
    }
> {
  return await listEvmFamilyEcdsaWalletUnlockSubjects(walletId);
}

export async function resolveEcdsaActivationJournalSelectors(
  walletId: WalletId,
): Promise<EcdsaWalletActivationSelectorListResult> {
  return await ecdsaCapabilityManifestStore.listWalletActivationJournalSelectors(walletId);
}
