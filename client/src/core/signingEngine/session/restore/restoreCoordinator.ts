import type { SigningSessionSealedStoreRecord } from '../persistence/sealedSessionStore';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

type RestoreSealedSessionListInput =
  | {
      walletId: string;
      authMethod: 'email_otp' | 'passkey';
      curve: 'ed25519';
    }
  | {
      walletId: string;
      authMethod: 'email_otp' | 'passkey';
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    };

type RestorePersistedSessionForSigningBaseInput = {
  walletId: string;
  authMethod: 'email_otp' | 'passkey';
};

type RestorePersistedSessionForSigningTransactionInput =
  RestorePersistedSessionForSigningBaseInput & {
    walletSigningSessionId: string;
    thresholdSessionId: string;
    reason: 'transaction' | 'export';
  };

export type RestorePersistedSessionForSigningInput =
  | (RestorePersistedSessionForSigningTransactionInput & {
      curve: 'ed25519';
      chain: 'near';
    })
  | (RestorePersistedSessionForSigningTransactionInput & {
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    });

export type RestorePersistedSessionForSigningResult = {
  attempted: number;
  restored: number;
  deferred: number;
};

export type RestorePersistedSessionPurpose = {
  walletId: string;
  authMethod: 'email_otp' | 'passkey';
  walletSigningSessionId: string;
  thresholdSessionId: string;
  reason: 'transaction' | 'export' | 'session_status';
} & (
  | {
      curve: 'ed25519';
      chain: 'near';
    }
  | {
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    }
);

type RestorePersistedSessionCacheInput =
  | RestorePersistedSessionForSigningInput
  | RestorePersistedSessionPurpose;

export type RestorePersistedSessionWorkItem = {
  record: SigningSessionSealedStoreRecord;
  purpose: RestorePersistedSessionPurpose;
};

export type RestorePersistedSessionsForAccountInput = {
  walletId: string;
  ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
  authMethod?: 'email_otp' | 'passkey';
  maxRecords?: number;
};

export type RestorePersistedSessionsForAccountResult = {
  listed: number;
  attempted: number;
  restored: number;
  deferred: number;
  skipped: number;
  truncated: number;
};

export type RestoreSealedRecordForAccountResult = 'restored' | 'ready' | 'deferred';

export type SigningSessionRestoreCache = {
  hasKnownMissing: (input: RestorePersistedSessionForSigningInput) => boolean;
  rememberKnownMissing: (input: RestorePersistedSessionForSigningInput) => void;
  hasSuccessfulRestore: (
    input: RestorePersistedSessionCacheInput,
    record: SigningSessionSealedStoreRecord,
  ) => boolean;
  rememberSuccessfulRestore: (
    input: RestorePersistedSessionCacheInput,
    record: SigningSessionSealedStoreRecord,
  ) => void;
  clear: () => void;
};

export type RestorePersistedSessionForSigningPorts = {
  listExactSealedSessionsForAccount: (
    args: RestoreSealedSessionListInput,
  ) => Promise<SigningSessionSealedStoreRecord[]>;
  restoreSealedRecordForAccount: (args: {
    accountId: string;
    record: SigningSessionSealedStoreRecord;
    purpose: RestorePersistedSessionPurpose;
  }) => Promise<RestoreSealedRecordForAccountResult>;
  onListError?: (args: {
    accountId: string;
    target: string;
    reason: RestorePersistedSessionForSigningInput['reason'];
    error: unknown;
  }) => void;
  cache?: SigningSessionRestoreCache;
};

export type RestorePersistedSessionsForAccountPorts = {
  listExactSealedSessionsForAccount: (
    args: RestoreSealedSessionListInput,
  ) => Promise<SigningSessionSealedStoreRecord[]>;
  restoreSealedRecordForAccount: (args: {
    accountId: string;
    record: SigningSessionSealedStoreRecord;
    purpose: RestorePersistedSessionPurpose;
  }) => Promise<RestoreSealedRecordForAccountResult>;
  onListError?: (args: { accountId: string; error: unknown }) => void;
  cache?: SigningSessionRestoreCache;
};

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
  record: SigningSessionSealedStoreRecord,
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
    record.thresholdSessionIds[input.curve] || '',
    record.updatedAtMs,
    'restored',
  ].join('|');
}

function purposeCacheKey(purpose: RestorePersistedSessionPurpose, record: SigningSessionSealedStoreRecord): string {
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

function workItemForRecord(
  input: RestorePersistedSessionForSigningInput,
  record: SigningSessionSealedStoreRecord,
): RestorePersistedSessionWorkItem | null {
  const thresholdSessionId = String(record.thresholdSessionIds[input.curve] || '').trim();
  const walletSigningSessionId = String(record.walletSigningSessionId || '').trim();
  if (!thresholdSessionId || !walletSigningSessionId) return null;
  if (record.authMethod !== input.authMethod) return null;
  if (walletSigningSessionId !== input.walletSigningSessionId) return null;
  if (thresholdSessionId !== input.thresholdSessionId) return null;
  if (
    input.curve === 'ecdsa' &&
    (!record.ecdsaRestore?.chainTarget ||
      !thresholdEcdsaChainTargetsEqual(record.ecdsaRestore.chainTarget, input.chainTarget))
  ) {
    return null;
  }
  if (input.curve === 'ecdsa') {
    return {
      record,
      purpose: {
        walletId: input.walletId,
        authMethod: input.authMethod,
        curve: 'ecdsa',
        chainTarget: input.chainTarget,
        walletSigningSessionId,
        thresholdSessionId,
        reason: input.reason,
      },
    };
  }
  return {
    record,
    purpose: {
      walletId: input.walletId,
      authMethod: input.authMethod,
      curve: 'ed25519',
      chain: 'near',
      walletSigningSessionId,
      thresholdSessionId,
      reason: input.reason,
    },
  };
}

function workItemsForAccountRecord(args: {
  walletId: string;
  record: SigningSessionSealedStoreRecord;
  reason: 'session_status';
  requestedCurve: 'ed25519' | 'ecdsa';
  requestedChainTarget?: ThresholdEcdsaChainTarget;
}): RestorePersistedSessionWorkItem[] {
  const record = args.record;
  const walletSigningSessionId = String(record.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId) return [];
  if (args.requestedCurve === 'ed25519') {
    const thresholdSessionId = String(record.thresholdSessionIds.ed25519 || '').trim();
    if (!thresholdSessionId) return [];
    return [
      {
        record,
        purpose: {
          walletId: args.walletId,
          authMethod: record.authMethod,
          curve: 'ed25519',
          chain: 'near',
          walletSigningSessionId,
          thresholdSessionId,
          reason: args.reason,
        },
      },
    ];
  }
  const chainTarget = args.requestedChainTarget;
  const thresholdSessionId = String(record.thresholdSessionIds.ecdsa || '').trim();
  if (!thresholdSessionId || !chainTarget) return [];
  if (
    !record.ecdsaRestore?.chainTarget ||
    !thresholdEcdsaChainTargetsEqual(record.ecdsaRestore.chainTarget, chainTarget)
  ) {
    return [];
  }
  return [
    {
      record,
      purpose: {
        walletId: args.walletId,
        authMethod: record.authMethod,
        curve: 'ecdsa',
        chainTarget,
        walletSigningSessionId,
        thresholdSessionId,
        reason: args.reason,
      },
    },
  ];
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

export async function restorePersistedSessionForSigningCommand(
  input: RestorePersistedSessionForSigningInput,
  ports: RestorePersistedSessionForSigningPorts,
): Promise<RestorePersistedSessionForSigningResult> {
  const accountId = String(input.walletId || '').trim();
  if (!accountId) return { attempted: 0, restored: 0, deferred: 0 };
  const normalizedInput: RestorePersistedSessionForSigningInput = {
    ...input,
    walletId: accountId,
  };
  if (ports.cache?.hasKnownMissing(normalizedInput)) {
    return { attempted: 0, restored: 0, deferred: 0 };
  }

  let records: SigningSessionSealedStoreRecord[];
  try {
    if (normalizedInput.curve === 'ecdsa') {
      records = await ports.listExactSealedSessionsForAccount({
        walletId: accountId,
        authMethod: normalizedInput.authMethod,
        curve: 'ecdsa',
        chainTarget: normalizedInput.chainTarget,
      });
    } else {
      records = await ports.listExactSealedSessionsForAccount({
        walletId: accountId,
        authMethod: normalizedInput.authMethod,
        curve: 'ed25519',
      });
    }
  } catch (error) {
    ports.onListError?.({
      accountId,
      target:
        normalizedInput.curve === 'ecdsa'
          ? thresholdEcdsaChainTargetKey(normalizedInput.chainTarget)
          : normalizedInput.chain,
      reason: normalizedInput.reason,
      error,
    });
    return { attempted: 0, restored: 0, deferred: 0 };
  }

  const exactPurposeWorkItems = records
    .map((record) => workItemForRecord(normalizedInput, record))
    .filter((item): item is RestorePersistedSessionWorkItem => Boolean(item));
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
      const result = await ports.restoreSealedRecordForAccount({ accountId, record, purpose });
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

export async function restorePersistedSessionsForAccountCommand(
  input: RestorePersistedSessionsForAccountInput,
  ports: RestorePersistedSessionsForAccountPorts,
): Promise<RestorePersistedSessionsForAccountResult> {
  const accountId = String(input.walletId || '').trim();
  const maxRecords = Math.max(0, Math.floor(input.maxRecords ?? 10));
  const empty = { listed: 0, attempted: 0, restored: 0, deferred: 0, skipped: 0, truncated: 0 };
  if (!accountId || maxRecords <= 0) return empty;

  let records: SigningSessionSealedStoreRecord[];
  try {
    const authMethods = input.authMethod
      ? [input.authMethod]
      : (['email_otp', 'passkey'] as const);
    const listed = await Promise.all(
      authMethods.flatMap((authMethod) => [
        ports.listExactSealedSessionsForAccount({
          walletId: accountId,
          authMethod,
          curve: 'ed25519',
        }),
        ...input.ecdsaChainTargets.map((chainTarget) =>
          ports.listExactSealedSessionsForAccount({
            walletId: accountId,
            authMethod,
            curve: 'ecdsa',
            chainTarget,
          }),
        ),
      ]),
    );
    records = listed.flat();
  } catch (error) {
    ports.onListError?.({ accountId, error });
    return empty;
  }

  const seenWorkItems = new Set<string>();
  const workItems = records
    .flatMap((record) => [
      ...workItemsForAccountRecord({
        walletId: accountId,
        record,
        reason: 'session_status',
        requestedCurve: 'ed25519',
      }),
      ...input.ecdsaChainTargets.flatMap((chainTarget) =>
        workItemsForAccountRecord({
          walletId: accountId,
          record,
          reason: 'session_status',
          requestedCurve: 'ecdsa',
          requestedChainTarget: chainTarget,
        }),
      ),
    ])
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
      const result = await ports.restoreSealedRecordForAccount({ accountId, record, purpose });
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
