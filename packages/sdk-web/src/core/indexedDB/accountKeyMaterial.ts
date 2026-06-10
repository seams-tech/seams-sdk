import { toTrimmedString } from '@shared/utils/validation';
import type { AccountRef } from './passkeyClientDB.types';
import type { KeyMaterialAlgorithm, KeyMaterialKind, KeyMaterialRecord } from './keyMaterial.types';
import {
  resolveProfileAccountContextFromCandidates,
  type ProfileAccountContextPort,
} from './profileAccountProjection';

export type AccountKeyMaterialStorePort = {
  getKeyMaterial: (
    profileId: string,
    signerSlot: number,
    chainIdKey: string,
    keyKind: KeyMaterialKind,
  ) => Promise<KeyMaterialRecord | null>;
  storeKeyMaterial: (input: KeyMaterialRecord) => Promise<void>;
};

export type AccountKeyMaterialDeps = {
  clientDB: ProfileAccountContextPort;
  keyMaterialStore: AccountKeyMaterialStorePort;
};

export type MappedAccountKeyMaterialTargetInput = {
  accountRefs: AccountRef[];
  explicitProfileId?: never;
  explicitChainIdKey?: never;
  explicitAccountAddress?: never;
};

export type ExplicitAccountKeyMaterialTargetInput = {
  accountRefs: AccountRef[];
  explicitProfileId: string;
  explicitChainIdKey: string;
  explicitAccountAddress: string;
};

export type ResolveAccountKeyMaterialTargetInput =
  | MappedAccountKeyMaterialTargetInput
  | ExplicitAccountKeyMaterialTargetInput;

export type StoreAccountKeyMaterialInput = ResolveAccountKeyMaterialTargetInput & {
  signerSlot: number;
  keyKind: KeyMaterialKind;
  algorithm: KeyMaterialAlgorithm;
  publicKey: string;
  signerId: string;
  wrapKeySalt?: string;
  payload?: Record<string, unknown>;
  timestamp?: number;
  schemaVersion?: number;
};

export type ResolvedAccountKeyMaterialTarget = {
  profileId: string;
  chainIdKey: string;
  accountAddress: string;
};

export async function resolveAccountKeyMaterialTarget(
  clientDB: AccountKeyMaterialDeps['clientDB'],
  input: ResolveAccountKeyMaterialTargetInput,
): Promise<ResolvedAccountKeyMaterialTarget | null> {
  const explicitProfileId = toTrimmedString(input.explicitProfileId || '');
  const explicitChainIdKey = toTrimmedString(input.explicitChainIdKey || '').toLowerCase();
  const explicitAccountAddress = toTrimmedString(input.explicitAccountAddress || '').toLowerCase();

  if (explicitProfileId || explicitChainIdKey || explicitAccountAddress) {
    if (!explicitProfileId || !explicitChainIdKey || !explicitAccountAddress) {
      throw new Error(
        'IndexedDBManager: profileId, chainIdKey, and accountAddress are required for explicit key target writes',
      );
    }
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
      accountAddress: explicitAccountAddress,
    };
  }

  const resolved = await resolveProfileAccountContextFromCandidates(clientDB, input.accountRefs);
  if (!resolved?.profileId) return null;
  return {
    profileId: resolved.profileId,
    chainIdKey: resolved.accountRef.chainIdKey,
    accountAddress: resolved.accountRef.accountAddress,
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
  return args.deps.keyMaterialStore.getKeyMaterial(
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
  const signerId = toTrimmedString(input.signerId || '');
  if (!signerId) {
    throw new Error('IndexedDBManager: Missing signerId for key write');
  }

  const target = await resolveAccountKeyMaterialTarget(deps.clientDB, input);
  if (!target?.profileId || !target.chainIdKey || !target.accountAddress) {
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

  const record: KeyMaterialRecord = {
    profileId: target.profileId,
    signerSlot: input.signerSlot,
    chainIdKey: target.chainIdKey,
    accountAddress: target.accountAddress,
    keyKind,
    algorithm,
    publicKey,
    signerId,
    timestamp: typeof input.timestamp === 'number' ? input.timestamp : Date.now(),
    schemaVersion,
  };
  const wrapKeySalt = toTrimmedString(input.wrapKeySalt || '');
  if (wrapKeySalt) {
    record.wrapKeySalt = wrapKeySalt;
  }
  if (input.payload) {
    record.payload = input.payload;
  }
  await deps.keyMaterialStore.storeKeyMaterial(record);
}
