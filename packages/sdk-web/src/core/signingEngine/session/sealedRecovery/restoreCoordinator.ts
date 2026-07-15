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
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletPorts,
  DiscoverPersistedSessionsForWalletResult,
  SigningSessionRestoreAttemptRegistry,
  SigningSessionRestoreCache,
} from './sealedRecovery.types';
import type { SealedRecoveryRecord } from './recoveryRecord';

type RestorePersistedSessionCacheInput =
  | RestorePersistedSessionForSigningInput
  | RestorePersistedSessionPurpose;

function isMatchedRestoreWorkItemLookup(
  lookup: RestoreWorkItemLookupResult,
): lookup is Extract<RestoreWorkItemLookupResult, { kind: 'matched' }> {
  return lookup.kind === 'matched';
}

function successfulRestoreCacheKey(
  input: RestorePersistedSessionCacheInput,
  record: SealedRecoveryRecord,
): string {
  const chainKey = thresholdEcdsaChainTargetKey(input.chainTarget);
  return [
    input.walletId,
    input.authMethod,
    input.curve,
    chainKey,
    input.reason,
    input.signingGrantId,
    input.thresholdSessionId,
    record.signingGrantId,
    record.thresholdSessionId,
    record.updatedAtMs,
    'restored',
  ].join('|');
}

function purposeCacheKey(
  purpose: RestorePersistedSessionPurpose,
  record: SealedRecoveryRecord,
): string {
  const chainKey = thresholdEcdsaChainTargetKey(purpose.chainTarget);
  return [
    purpose.walletId,
    purpose.authMethod,
    purpose.curve,
    chainKey,
    purpose.signingGrantId,
    purpose.thresholdSessionId,
    record.updatedAtMs,
  ].join('|');
}

function completedRestoreResult(args: {
  attempted: number;
  restored: number;
  deferred: number;
}): RestorePersistedSessionForSigningResult {
  return {
    kind: 'completed',
    attempted: args.attempted,
    restored: args.restored,
    deferred: args.deferred,
  };
}

function duplicateRestoreRecordSummaries(
  workItems: readonly Extract<RestoreWorkItemLookupResult, { kind: 'matched' }>['workItem'][],
): Record<string, unknown>[] {
  return workItems.map(({ record, purpose }) => ({
    authMethod: purpose.authMethod,
    curve: purpose.curve,
    chain: thresholdEcdsaChainTargetKey(purpose.chainTarget),
    signingGrantId: purpose.signingGrantId,
    thresholdSessionId: purpose.thresholdSessionId,
    recordSigningGrantId: record.signingGrantId,
    recordThresholdSessionId: record.thresholdSessionId,
    updatedAtMs: record.updatedAtMs,
  }));
}

export function createSigningSessionRestoreCache(): SigningSessionRestoreCache {
  const successfulRestores = new Set<string>();
  return {
    hasSuccessfulRestore: (input, record) =>
      successfulRestores.has(successfulRestoreCacheKey(input, record)),
    rememberSuccessfulRestore: (input, record) => {
      successfulRestores.add(successfulRestoreCacheKey(input, record));
    },
    clear: () => {
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
  if (!walletId) return completedRestoreResult({ attempted: 0, restored: 0, deferred: 0 });
  const normalizedInput: RestorePersistedSessionForSigningInput = {
    ...input,
    walletId,
  };

  let records;
  try {
    records = await ports.listExactSealedSessionsForWallet({
      walletId,
      authMethod: normalizedInput.authMethod,
      curve: 'ecdsa',
      chainTarget: normalizedInput.chainTarget,
    });
  } catch (error) {
    ports.onListError?.({
      walletId,
      target: thresholdEcdsaChainTargetKey(normalizedInput.chainTarget),
      reason: normalizedInput.reason,
      error,
    });
    return completedRestoreResult({ attempted: 0, restored: 0, deferred: 0 });
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
    return completedRestoreResult({ attempted: 0, restored: 0, deferred: 0 });
  }
  if (exactPurposeWorkItems.length > 1) {
    return {
      kind: 'duplicate_records',
      attempted: 0,
      restored: 0,
      deferred: 0,
      duplicateCount: exactPurposeWorkItems.length,
      duplicateRecordSummaries: duplicateRestoreRecordSummaries(exactPurposeWorkItems),
    } satisfies RestorePersistedSessionForSigningResult;
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
  return completedRestoreResult({ attempted, restored, deferred });
}

export async function discoverPersistedSessionsForWalletCommand(
  input: DiscoverPersistedSessionsForWalletInput,
  ports: DiscoverPersistedSessionsForWalletPorts,
): Promise<DiscoverPersistedSessionsForWalletResult> {
  const walletId = String(input.walletId || '').trim();
  const maxRecords = Math.max(0, Math.floor(input.maxRecords ?? 10));
  const empty = { listed: 0, discovered: 0, truncated: 0 };
  if (!walletId || maxRecords <= 0) return empty;

  let records;
  try {
    const authMethods = input.authMethod ? [input.authMethod] : (['email_otp', 'passkey'] as const);
    const listed = await Promise.all(
      authMethods.flatMap((authMethod) => {
        return input.ecdsaChainTargets.map((chainTarget) =>
          ports.listExactSealedSessionsForWallet({
            walletId,
            authMethod,
            curve: 'ecdsa' as const,
            chainTarget,
          }),
        );
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
          requestedChainTarget: chainTarget,
        }),
      );
      return ecdsaLookups;
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

  const boundedWorkItems = workItems.slice(0, maxRecords);
  return {
    listed: records.length,
    discovered: boundedWorkItems.length,
    truncated: Math.max(0, workItems.length - boundedWorkItems.length),
  };
}
