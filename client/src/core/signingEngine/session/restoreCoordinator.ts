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
  walletSigningSessionId?: string;
  thresholdSessionId?: string;
  reason: 'transaction' | 'export' | 'session_status';
};

export type RestorePersistedSessionForSigningInput =
  | (RestorePersistedSessionForSigningBaseInput & {
      curve: 'ed25519';
      chain: 'near';
    })
  | (RestorePersistedSessionForSigningBaseInput & {
      curve: 'ecdsa';
      chain: 'tempo' | 'evm';
    });

export type RestorePersistedSessionForSigningResult = {
  attempted: number;
  restored: number;
  deferred: number;
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

  const exactPurposeRecords = records.filter((record) => {
    if (record.authMethod !== normalizedInput.authMethod) return false;
    if (record.curve !== normalizedInput.curve) return false;
    if (
      normalizedInput.curve === 'ecdsa' &&
      (normalizedInput.chain === 'tempo' || normalizedInput.chain === 'evm') &&
      record.ecdsaRestore?.chain !== normalizedInput.chain
    ) {
      return false;
    }
    if (
      normalizedInput.walletSigningSessionId &&
      record.walletSigningSessionId !== normalizedInput.walletSigningSessionId
    ) {
      return false;
    }
    if (
      normalizedInput.thresholdSessionId &&
      record.thresholdSessionIds[normalizedInput.curve] !== normalizedInput.thresholdSessionId
    ) {
      return false;
    }
    return true;
  });
  if (!exactPurposeRecords.length) {
    ports.cache?.rememberKnownMissing(normalizedInput);
    return { attempted: 0, restored: 0, deferred: 0 };
  }
  let attempted = 0;
  let restored = 0;
  let deferred = 0;
  await Promise.all(
    exactPurposeRecords.map(async (record) => {
      if (ports.cache?.hasSuccessfulRestore(normalizedInput, record)) return;
      attempted += 1;
      const result = await ports.restoreSealedRecordForAccount({ accountId, record });
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
    const seen = new Set<string>();
    records = listed.flat().filter((record) => {
      const key = String(
        record.storeKey ||
          [
            record.authMethod,
            record.curve,
            record.ecdsaRestore?.chain || 'near',
            record.walletSigningSessionId,
            record.thresholdSessionIds[record.curve] || '',
          ].join('|'),
      );
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  } catch (error) {
    ports.onListError?.({ accountId, error });
    return empty;
  }

  const boundedRecords = records
    .slice()
    .sort((left, right) => Number(right.updatedAtMs || 0) - Number(left.updatedAtMs || 0))
    .slice(0, maxRecords);
  let attempted = 0;
  let restored = 0;
  let deferred = 0;
  let skipped = 0;
  await Promise.all(
    boundedRecords.map(async (record) => {
      if (record.authMethod !== 'email_otp' && record.authMethod !== 'passkey') {
        skipped += 1;
        return;
      }
      let restoreInput: RestorePersistedSessionForSigningInput;
      if (record.curve === 'ed25519') {
        restoreInput = {
          walletId: accountId,
          authMethod: record.authMethod,
          curve: 'ed25519',
          chain: 'near',
          thresholdSessionId: record.thresholdSessionIds.ed25519,
          walletSigningSessionId: record.walletSigningSessionId,
          reason: 'session_status',
        };
      } else if (record.curve === 'ecdsa') {
        const chain = record.ecdsaRestore?.chain;
        if (chain !== 'tempo' && chain !== 'evm') {
          skipped += 1;
          return;
        }
        restoreInput = {
          walletId: accountId,
          authMethod: record.authMethod,
          curve: 'ecdsa',
          chain,
          thresholdSessionId: record.thresholdSessionIds.ecdsa,
          walletSigningSessionId: record.walletSigningSessionId,
          reason: 'session_status',
        };
      } else {
        skipped += 1;
        return;
      }
      if (ports.cache?.hasSuccessfulRestore(restoreInput, record)) {
        skipped += 1;
        return;
      }
      attempted += 1;
      const result = await ports.restoreSealedRecordForAccount({ accountId, record });
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
    truncated: Math.max(0, records.length - boundedRecords.length),
  };
}
