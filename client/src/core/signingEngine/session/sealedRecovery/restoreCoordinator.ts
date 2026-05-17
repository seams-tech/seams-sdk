import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildRestoreWorkItemLookupResult,
  buildRestoreWorkItemLookupResultsForListedRecord,
  type RestoreWorkItemLookupResult,
} from './exactRecordLookup';
import type {
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionForSigningPorts,
  RestorePersistedSessionForSigningResult,
  RestorePersistedSessionPurpose,
  RestorePersistedSessionsForWalletInput,
  RestorePersistedSessionsForWalletPorts,
  RestorePersistedSessionsForWalletResult,
  SigningSessionRestoreAttemptRegistry,
  SigningSessionRestoreCache,
} from './types';
import type { SealedRecoveryRecord } from './recoveryRecord';

type RestorePersistedSessionCacheInput =
  | RestorePersistedSessionForSigningInput
  | RestorePersistedSessionPurpose;

function isMatchedRestoreWorkItemLookup(
  lookup: RestoreWorkItemLookupResult,
): lookup is Extract<RestoreWorkItemLookupResult, { kind: 'matched' }> {
  return lookup.kind === 'matched';
}

function knownMissingCacheKey(input: RestorePersistedSessionForSigningInput): string {
  const chainKey =
    input.curve === 'ecdsa' ? thresholdEcdsaChainTargetKey(input.chainTarget) : input.chain;
  return [
    input.walletId,
    input.authMethod,
    input.curve,
    chainKey,
    input.walletSigningSessionId,
    input.thresholdSessionId,
    input.reason,
    'missing',
  ].join('|');
}

function successfulRestoreCacheKey(
  input: RestorePersistedSessionCacheInput,
  record: SealedRecoveryRecord,
): string {
  const chainKey =
    input.curve === 'ecdsa' ? thresholdEcdsaChainTargetKey(input.chainTarget) : input.chain;
  return [
    input.walletId,
    input.authMethod,
    input.curve,
    chainKey,
    input.reason,
    input.walletSigningSessionId,
    input.thresholdSessionId,
    record.walletSigningSessionId,
    record.thresholdSessionId,
    record.updatedAtMs,
    'restored',
  ].join('|');
}

function purposeCacheKey(purpose: RestorePersistedSessionPurpose, record: SealedRecoveryRecord): string {
  const chainKey =
    purpose.curve === 'ecdsa' ? thresholdEcdsaChainTargetKey(purpose.chainTarget) : purpose.chain;
  return [
    purpose.walletId,
    purpose.authMethod,
    purpose.curve,
    chainKey,
    purpose.walletSigningSessionId,
    purpose.thresholdSessionId,
    record.updatedAtMs,
  ].join('|');
}

export function createSigningSessionRestoreCache(): SigningSessionRestoreCache {
  const knownMissing = new Set<string>();
  const successfulRestores = new Set<string>();
  return {
    hasKnownMissing: (input) => knownMissing.has(knownMissingCacheKey(input)),
    rememberKnownMissing: (input) => {
      knownMissing.add(knownMissingCacheKey(input));
    },
    hasSuccessfulRestore: (input, record) =>
      successfulRestores.has(successfulRestoreCacheKey(input, record)),
    rememberSuccessfulRestore: (input, record) => {
      successfulRestores.add(successfulRestoreCacheKey(input, record));
    },
    clear: () => {
      knownMissing.clear();
      successfulRestores.clear();
    },
  };
}

export function createSigningSessionRestoreAttemptRegistry(): SigningSessionRestoreAttemptRegistry {
  const completed = new Set<string>();
  const inFlight = new Map<string, Promise<void>>();
  return {
    hasCompleted: (key) => completed.has(String(key || '').trim()),
    rememberCompleted: (key) => {
      const normalized = String(key || '').trim();
      if (!normalized) return;
      completed.add(normalized);
    },
    getInFlight: (key) => {
      const normalized = String(key || '').trim();
      return normalized ? inFlight.get(normalized) : undefined;
    },
    setInFlight: (key, task) => {
      const normalized = String(key || '').trim();
      if (!normalized) return;
      inFlight.set(normalized, task);
    },
    clearInFlight: (key) => {
      const normalized = String(key || '').trim();
      if (!normalized) return;
      inFlight.delete(normalized);
    },
    clear: () => {
      completed.clear();
      inFlight.clear();
    },
  };
}

export async function restorePersistedSessionForSigningCommand(
  input: RestorePersistedSessionForSigningInput,
  ports: RestorePersistedSessionForSigningPorts,
): Promise<RestorePersistedSessionForSigningResult> {
  const walletId = String(input.walletId || '').trim();
  if (!walletId) return { attempted: 0, restored: 0, deferred: 0 };
  const normalizedInput: RestorePersistedSessionForSigningInput = {
    ...input,
    walletId,
  };
  if (ports.cache?.hasKnownMissing(normalizedInput)) {
    return { attempted: 0, restored: 0, deferred: 0 };
  }

  let records;
  try {
    if (normalizedInput.curve === 'ecdsa') {
      records = await ports.listExactSealedSessionsForWallet({
        walletId,
        authMethod: normalizedInput.authMethod,
        curve: 'ecdsa',
        chainTarget: normalizedInput.chainTarget,
      });
    } else {
      records = await ports.listExactSealedSessionsForWallet({
        walletId,
        authMethod: normalizedInput.authMethod,
        curve: 'ed25519',
      });
    }
  } catch (error) {
    ports.onListError?.({
      walletId,
      target:
        normalizedInput.curve === 'ecdsa'
          ? thresholdEcdsaChainTargetKey(normalizedInput.chainTarget)
          : normalizedInput.chain,
      reason: normalizedInput.reason,
      error,
    });
    return { attempted: 0, restored: 0, deferred: 0 };
  }

  const exactPurposeLookups = records.map((record) =>
    buildRestoreWorkItemLookupResult(normalizedInput, record),
  );
  for (const lookup of exactPurposeLookups) {
    if (lookup.kind !== 'rejected') continue;
    ports.onRejectedRecord?.({ walletId, rejection: lookup.rejection });
  }
  const exactPurposeWorkItems = exactPurposeLookups
    .filter(isMatchedRestoreWorkItemLookup)
    .map((lookup) => lookup.workItem);
  if (!exactPurposeWorkItems.length) {
    ports.cache?.rememberKnownMissing(normalizedInput);
    return { attempted: 0, restored: 0, deferred: 0 };
  }
  let attempted = 0;
  let restored = 0;
  let deferred = 0;
  await Promise.all(
    exactPurposeWorkItems.map(async ({ record, purpose }) => {
      if (ports.cache?.hasSuccessfulRestore(normalizedInput, record)) return;
      attempted += 1;
      const result = await ports.restoreSealedRecordForWallet({ walletId, record, purpose });
      if (result === 'restored') {
        restored += 1;
        ports.cache?.rememberSuccessfulRestore(normalizedInput, record);
      }
      if (result === 'ready') {
        ports.cache?.rememberSuccessfulRestore(normalizedInput, record);
      }
      if (result === 'deferred') deferred += 1;
    }),
  );
  return { attempted, restored, deferred };
}

export async function restorePersistedSessionsForWalletCommand(
  input: RestorePersistedSessionsForWalletInput,
  ports: RestorePersistedSessionsForWalletPorts,
): Promise<RestorePersistedSessionsForWalletResult> {
  const walletId = String(input.walletId || '').trim();
  const maxRecords = Math.max(0, Math.floor(input.maxRecords ?? 10));
  const empty = { listed: 0, attempted: 0, restored: 0, deferred: 0, skipped: 0, truncated: 0 };
  if (!walletId || maxRecords <= 0) return empty;

  let records;
  try {
    const authMethods = input.authMethod
      ? [input.authMethod]
      : (['email_otp', 'passkey'] as const);
    const listed = await Promise.all(
      authMethods.flatMap((authMethod) => {
        const ecdsaLists = input.ecdsaChainTargets.map((chainTarget) =>
          ports.listExactSealedSessionsForWallet({
            walletId,
            authMethod,
            curve: 'ecdsa' as const,
            chainTarget,
          }),
        );
        if (input.kind === 'restore_wallet_ecdsa_signing_sessions') {
          return ecdsaLists;
        }
        return [
          ports.listExactSealedSessionsForWallet({
            walletId,
            authMethod,
            curve: 'ed25519' as const,
          }),
          ...ecdsaLists,
        ];
      }),
    );
    records = listed.flat();
  } catch (error) {
    ports.onListError?.({ walletId, error });
    return empty;
  }

  const seenWorkItems = new Set<string>();
  const workItems = records
    .flatMap((record) => {
      const ecdsaLookups = input.ecdsaChainTargets.flatMap((chainTarget) =>
        buildRestoreWorkItemLookupResultsForListedRecord({
          walletId,
          record,
          reason: 'session_status',
          requestedCurve: 'ecdsa',
          requestedChainTarget: chainTarget,
        }),
      );
      if (input.kind === 'restore_wallet_ecdsa_signing_sessions') {
        return ecdsaLookups;
      }
      return [
        ...buildRestoreWorkItemLookupResultsForListedRecord({
          walletId,
          record,
          reason: 'session_status',
          requestedCurve: 'ed25519',
        }),
        ...ecdsaLookups,
      ];
    })
    .filter((lookup) => {
      if (lookup.kind !== 'rejected') return true;
      ports.onRejectedRecord?.({ walletId, rejection: lookup.rejection });
      return false;
    })
    .filter(isMatchedRestoreWorkItemLookup)
    .map((lookup) => lookup.workItem)
    .filter((item) => {
      const key = purposeCacheKey(item.purpose, item.record);
      if (seenWorkItems.has(key)) return false;
      seenWorkItems.add(key);
      return true;
    });

  const boundedWorkItems = workItems
    .slice()
    .sort((left, right) => Number(right.record.updatedAtMs || 0) - Number(left.record.updatedAtMs || 0))
    .slice(0, maxRecords);
  let attempted = 0;
  let restored = 0;
  let deferred = 0;
  let skipped = 0;
  await Promise.all(
    boundedWorkItems.map(async ({ record, purpose }) => {
      if (record.authMethod !== 'email_otp' && record.authMethod !== 'passkey') {
        skipped += 1;
        return;
      }
      if (ports.cache?.hasSuccessfulRestore(purpose, record)) {
        skipped += 1;
        return;
      }
      attempted += 1;
      const result = await ports.restoreSealedRecordForWallet({ walletId, record, purpose });
      if (result === 'restored') {
        restored += 1;
        ports.cache?.rememberSuccessfulRestore(purpose, record);
      }
      if (result === 'ready') {
        ports.cache?.rememberSuccessfulRestore(purpose, record);
      }
      if (result === 'deferred') deferred += 1;
    }),
  );

  return {
    listed: records.length,
    attempted,
    restored,
    deferred,
    skipped,
    truncated: Math.max(0, workItems.length - boundedWorkItems.length),
  };
}
