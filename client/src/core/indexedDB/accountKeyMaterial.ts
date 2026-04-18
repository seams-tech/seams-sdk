import { toTrimmedString } from '@shared/utils/validation';
import type { PasskeyClientDBManager } from './passkeyClientDB/manager';
import type { AccountKeyMaterialDBManager } from './accountKeyMaterialDB/manager';
import type { AccountRef } from './passkeyClientDB.types';
import type { KeyMaterialAlgorithm, KeyMaterialKind, KeyMaterialRecord } from './accountKeyMaterialDB.types';
import { resolveProfileAccountContextFromCandidates } from './profileAccountProjection';

export type AccountKeyMaterialDeps = {
  clientDB: Pick<PasskeyClientDBManager, 'resolveProfileAccountContext'>;
  accountKeyMaterialDB: Pick<AccountKeyMaterialDBManager, 'getKeyMaterial' | 'storeKeyMaterial'>;
};

export type ResolveAccountKeyMaterialTargetInput = {
  accountRefs: AccountRef[];
  explicitProfileId?: string;
  explicitChainIdKey?: string;
};

export type StoreAccountKeyMaterialInput = ResolveAccountKeyMaterialTargetInput & {
  signerSlot: number;
  keyKind: KeyMaterialKind;
  algorithm: KeyMaterialAlgorithm;
  publicKey: string;
  signerId?: string;
  wrapKeySalt?: string;
  payload?: Record<string, unknown>;
  timestamp?: number;
  schemaVersion?: number;
};

export type ResolvedAccountKeyMaterialTarget = {
  profileId: string;
  chainIdKey: string;
};

export async function resolveAccountKeyMaterialTarget(
  clientDB: AccountKeyMaterialDeps['clientDB'],
  input: ResolveAccountKeyMaterialTargetInput,
): Promise<ResolvedAccountKeyMaterialTarget | null> {
  const explicitProfileId = toTrimmedString(input.explicitProfileId || '');
  const explicitChainIdKey = toTrimmedString(input.explicitChainIdKey || '').toLowerCase();
  const hasExplicitProfileId = explicitProfileId.length > 0;
  const hasExplicitChainIdKey = explicitChainIdKey.length > 0;
  if (hasExplicitProfileId !== hasExplicitChainIdKey) {
    throw new Error(
      'IndexedDBManager: profileId and chainIdKey must be provided together for explicit key target writes',
    );
  }

  if (hasExplicitProfileId && hasExplicitChainIdKey) {
    const matchingExplicitRef = input.accountRefs.find(
      (accountRef) =>
        toTrimmedString(accountRef.chainIdKey || '').toLowerCase() === explicitChainIdKey,
    );
    if (matchingExplicitRef) {
      const mapped = await clientDB
        .resolveProfileAccountContext(matchingExplicitRef)
        .catch(() => null);
      if (mapped?.profileId && String(mapped.profileId).trim() !== explicitProfileId) {
        throw new Error(
          `IndexedDBManager: Explicit key target (${explicitProfileId}, ${explicitChainIdKey}, ${matchingExplicitRef.accountAddress}) mismatches mapped profile ${String(mapped.profileId).trim()}`,
        );
      }
    }
    return {
      profileId: explicitProfileId,
      chainIdKey: explicitChainIdKey,
    };
  }

  const resolved = await resolveProfileAccountContextFromCandidates(clientDB, input.accountRefs);
  if (!resolved?.profileId) return null;
  return {
    profileId: resolved.profileId,
    chainIdKey: resolved.accountRef.chainIdKey,
  };
}

export async function getAccountKeyMaterial(args: {
  deps: AccountKeyMaterialDeps;
  accountRefs: AccountRef[];
  signerSlot: number;
  keyKind: KeyMaterialKind;
}): Promise<KeyMaterialRecord | null> {
  const target = await resolveAccountKeyMaterialTarget(args.deps.clientDB, {
    accountRefs: args.accountRefs,
  });
  if (!target?.profileId || !target.chainIdKey) return null;
  return args.deps.accountKeyMaterialDB.getKeyMaterial(
    target.profileId,
    args.signerSlot,
    target.chainIdKey,
    args.keyKind,
  );
}

export async function storeAccountKeyMaterial(
  deps: AccountKeyMaterialDeps,
  input: StoreAccountKeyMaterialInput,
): Promise<void> {
  if (!Number.isSafeInteger(input.signerSlot) || input.signerSlot < 1) {
    throw new Error('IndexedDBManager: Invalid signerSlot for key write');
  }
  const keyKind = toTrimmedString(input.keyKind || '');
  if (!keyKind) {
    throw new Error('IndexedDBManager: Missing keyKind for key write');
  }
  const algorithm = toTrimmedString(input.algorithm || '').toLowerCase();
  if (!algorithm) {
    throw new Error('IndexedDBManager: Missing algorithm for key write');
  }
  const publicKey = toTrimmedString(input.publicKey || '');
  if (!publicKey) {
    throw new Error('IndexedDBManager: Missing publicKey for key write');
  }

  const target = await resolveAccountKeyMaterialTarget(deps.clientDB, input);
  if (!target?.profileId || !target.chainIdKey) {
    throw new Error(
      'IndexedDBManager: Missing profile/account mapping for key write. Persist profile/account first or pass explicit profileId + chainIdKey.',
    );
  }

  const schemaVersion =
    Number.isSafeInteger(input.schemaVersion) &&
    typeof input.schemaVersion === 'number' &&
    input.schemaVersion >= 1
      ? input.schemaVersion
      : 1;

  await deps.accountKeyMaterialDB.storeKeyMaterial({
    profileId: target.profileId,
    signerSlot: input.signerSlot,
    chainIdKey: target.chainIdKey,
    keyKind,
    algorithm,
    publicKey,
    ...(input.signerId ? { signerId: String(input.signerId).trim() } : {}),
    ...(input.wrapKeySalt ? { wrapKeySalt: String(input.wrapKeySalt).trim() } : {}),
    ...(input.payload ? { payload: input.payload } : {}),
    timestamp: typeof input.timestamp === 'number' ? input.timestamp : Date.now(),
    schemaVersion,
  });
}
