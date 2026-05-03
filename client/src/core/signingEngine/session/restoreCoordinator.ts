import type { SigningSessionSealedStoreRecord } from './sealedSessionStore';

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
      chain: 'tempo' | 'evm';
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

type RestorePersistedSessionForSigningMaintenanceInput =
  RestorePersistedSessionForSigningBaseInput & {
    walletSigningSessionId?: string;
    thresholdSessionId?: string;
    reason: 'session_status';
  };

export type RestorePersistedSessionForSigningInput =
  | (RestorePersistedSessionForSigningTransactionInput & {
      curve: 'ed25519';
      chain: 'near';
    })
  | (RestorePersistedSessionForSigningTransactionInput & {
      curve: 'ecdsa';
      chain: 'tempo' | 'evm';
    })
  | (RestorePersistedSessionForSigningMaintenanceInput & {
      curve: 'ed25519';
      chain: 'near';
    })
  | (RestorePersistedSessionForSigningMaintenanceInput & {
      curve: 'ecdsa';
      chain: 'tempo' | 'evm';
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
      chain: 'tempo' | 'evm';
    }
);

export type RestorePersistedSessionWorkItem = {
  record: SigningSessionSealedStoreRecord;
  purpose: RestorePersistedSessionPurpose;
};

export type RestorePersistedSessionsForAccountInput = {
  walletId: string;
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
    input: RestorePersistedSessionForSigningInput,
    record: SigningSessionSealedStoreRecord,
  ) => boolean;
  rememberSuccessfulRestore: (
    input: RestorePersistedSessionForSigningInput,
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
    chain: RestorePersistedSessionForSigningInput['chain'];
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
  return [
    input.walletId,
    input.authMethod,
    input.curve,
    input.chain,
    input.walletSigningSessionId || '',
    input.thresholdSessionId || '',
    input.reason,
    'missing',
  ].join('|');
}

function successfulRestoreCacheKey(
  input: RestorePersistedSessionForSigningInput,
  record: SigningSessionSealedStoreRecord,
): string {
  return [
    input.walletId,
    input.authMethod,
    input.curve,
    input.chain,
    input.reason,
    input.walletSigningSessionId || '',
    input.thresholdSessionId || '',
    record.walletSigningSessionId,
    record.thresholdSessionIds[input.curve] || '',
    record.updatedAtMs,
    'restored',
  ].join('|');
}

function purposeCacheKey(purpose: RestorePersistedSessionPurpose, record: SigningSessionSealedStoreRecord): string {
  return [
    purpose.walletId,
    purpose.authMethod,
    purpose.curve,
    purpose.chain,
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
  if (input.walletSigningSessionId && walletSigningSessionId !== input.walletSigningSessionId) {
    return null;
  }
  if (input.thresholdSessionId && thresholdSessionId !== input.thresholdSessionId) {
    return null;
  }
  if (
    input.curve === 'ecdsa' &&
    (input.chain === 'tempo' || input.chain === 'evm') &&
    record.ecdsaRestore?.chain !== input.chain
  ) {
    return null;
  }
  return {
    record,
    purpose: {
      walletId: input.walletId,
      authMethod: input.authMethod,
      curve: input.curve,
      chain: input.chain,
      walletSigningSessionId,
      thresholdSessionId,
      reason: input.reason,
    } as RestorePersistedSessionPurpose,
  };
}

function workItemsForAccountRecord(args: {
  walletId: string;
  record: SigningSessionSealedStoreRecord;
  reason: 'session_status';
  requestedCurve: 'ed25519' | 'ecdsa';
  requestedChain?: 'tempo' | 'evm';
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
  const chain = args.requestedChain;
  const thresholdSessionId = String(record.thresholdSessionIds.ecdsa || '').trim();
  if (!thresholdSessionId || (chain !== 'tempo' && chain !== 'evm')) return [];
  if (record.ecdsaRestore?.chain !== chain) return [];
  return [
    {
      record,
      purpose: {
        walletId: args.walletId,
        authMethod: record.authMethod,
        curve: 'ecdsa',
        chain,
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
        chain: normalizedInput.chain,
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
      chain: normalizedInput.chain,
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
        ports.listExactSealedSessionsForAccount({
          walletId: accountId,
          authMethod,
          curve: 'ecdsa',
          chain: 'tempo',
        }),
        ports.listExactSealedSessionsForAccount({
          walletId: accountId,
          authMethod,
          curve: 'ecdsa',
          chain: 'evm',
        }),
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
      ...workItemsForAccountRecord({
        walletId: accountId,
        record,
        reason: 'session_status',
        requestedCurve: 'ecdsa',
        requestedChain: 'tempo',
      }),
      ...workItemsForAccountRecord({
        walletId: accountId,
        record,
        reason: 'session_status',
        requestedCurve: 'ecdsa',
        requestedChain: 'evm',
      }),
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
      const restoreInput: RestorePersistedSessionForSigningInput = purpose;
      if (ports.cache?.hasSuccessfulRestore(restoreInput, record)) {
        skipped += 1;
        return;
      }
      attempted += 1;
      const result = await ports.restoreSealedRecordForAccount({ accountId, record, purpose });
      if (result === 'restored') {
        restored += 1;
        ports.cache?.rememberSuccessfulRestore(restoreInput, record);
      }
      if (result === 'ready') {
        ports.cache?.rememberSuccessfulRestore(restoreInput, record);
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
