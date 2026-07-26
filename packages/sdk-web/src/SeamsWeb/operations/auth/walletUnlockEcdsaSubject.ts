import type { AccountSignerRecord } from '@/core/indexedDB/passkeyClientDB.types';
import { IndexedDBManager } from '@/core/indexedDB';
import {
  parseEcdsaThresholdKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';
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

type EcdsaWalletUnlockSubjectParseResult =
  | {
      readonly kind: 'valid';
      readonly subject: EvmFamilyEcdsaWalletUnlockSubject;
    }
  | {
      readonly kind: 'invalid';
      readonly subject?: never;
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

function ecdsaWalletUnlockSubjectFromSigner(
  walletId: WalletId,
  signer: AccountSignerRecord,
): EcdsaWalletUnlockSubjectParseResult {
  try {
    const metadataWalletId = String(signer.metadata?.walletId || '').trim();
    if (metadataWalletId && metadataWalletId !== String(walletId)) {
      return { kind: 'invalid' };
    }
    return {
      kind: 'valid',
      subject: {
        kind: 'evm_family_ecdsa_wallet',
        walletId,
        ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(
          requiredWalletUnlockMetadataString(signer.metadata, 'ecdsaThresholdKeyId'),
        ),
      },
    };
  } catch {
    return { kind: 'invalid' };
  }
}

function requireWalletId(value: unknown): WalletId {
  const parsed = parseWalletId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

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
  let signers: AccountSignerRecord[];
  try {
    signers = await IndexedDBManager.listActiveWalletSigners({
      walletId,
      signerFamily: 'ecdsa',
    });
  } catch {
    return {
      kind: 'failed',
      reason: 'capability_subject_lookup_failed',
    };
  }
  const subjects: EvmFamilyEcdsaWalletUnlockSubject[] = [];
  const seenThresholdKeyIds = new Set<string>();
  for (const signer of signers) {
    const parsed = ecdsaWalletUnlockSubjectFromSigner(walletId, signer);
    if (parsed.kind === 'invalid') {
      return {
        kind: 'failed',
        reason: 'invalid_capability_subject',
      };
    }
    const key = String(parsed.subject.ecdsaThresholdKeyId);
    if (seenThresholdKeyIds.has(key)) continue;
    seenThresholdKeyIds.add(key);
    subjects.push(parsed.subject);
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
