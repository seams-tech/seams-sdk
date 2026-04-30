import { expect, test } from '@playwright/test';
import type { SigningSessionSealedStoreRecord } from '@/core/signingEngine/session/sealedSessionStore';
import {
  createSigningSessionRestoreCache,
  restorePersistedSessionsForAccountCommand,
  restorePersistedSessionForSigningCommand,
} from '@/core/signingEngine/session/restoreCoordinator';

function makeSealedRecord(args: {
  authMethod?: 'email_otp' | 'passkey';
  chain?: 'tempo' | 'evm';
  curve?: 'ed25519' | 'ecdsa';
  thresholdSessionId?: string;
  thresholdSessionIds?: {
    ed25519?: string;
    ecdsa?: string;
  };
  walletSigningSessionId?: string;
  updatedAtMs?: number;
}): SigningSessionSealedStoreRecord {
  const authMethod = args.authMethod || 'email_otp';
  const curve = args.curve || 'ecdsa';
  const thresholdSessionId = args.thresholdSessionId || 'tsess-restore';
  return {
    v: 1,
    alg: 'shamir3pass-v1',
    storageScope: 'iframe_origin_indexeddb',
    runtimeSessionId: 'runtime-restore',
    authMethod,
    secretKind: 'signing_session_secret32',
    storeKey: `${authMethod}:${curve}:${args.chain || 'near'}:${thresholdSessionId}`,
    walletSigningSessionId: args.walletSigningSessionId || 'wsess-restore',
    thresholdSessionIds:
      args.thresholdSessionIds ||
      (curve === 'ecdsa' ? { ecdsa: thresholdSessionId } : { ed25519: thresholdSessionId }),
    sealedSecretB64u: 'sealed-secret',
    curve,
    walletId: 'restore.testnet',
    userId: 'restore.testnet',
    ...(curve === 'ecdsa'
      ? {
          ecdsaRestore: {
            chain: args.chain || 'tempo',
            sessionKind: 'jwt' as const,
            thresholdSessionJwt: 'jwt-restore',
            ecdsaThresholdKeyId: 'ecdsa-key-restore',
            relayerKeyId: 'relayer-key-restore',
            participantIds: [1, 2],
          },
        }
      : {}),
    issuedAtMs: 1,
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 5,
    updatedAtMs: args.updatedAtMs || 1,
  };
}

test.describe('restorePersistedSessionForSigningCommand', () => {
  test('caches exact-purpose durable-record absence', async () => {
    const cache = createSigningSessionRestoreCache();
    let listCalls = 0;

    await restorePersistedSessionForSigningCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chain: 'tempo',
        reason: 'transaction',
      },
      {
        cache,
        listExactSealedSessionsForAccount: async () => {
          listCalls += 1;
          return [];
        },
        restoreSealedRecordForAccount: async () => 'restored',
      },
    );
    await restorePersistedSessionForSigningCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chain: 'tempo',
        reason: 'transaction',
      },
      {
        cache,
        listExactSealedSessionsForAccount: async () => {
          listCalls += 1;
          return [];
        },
        restoreSealedRecordForAccount: async () => 'restored',
      },
    );

    expect(listCalls).toBe(1);
  });

  test('does not cache transient list failures as known missing', async () => {
    const cache = createSigningSessionRestoreCache();
    let listCalls = 0;

    const ports = {
      cache,
      listExactSealedSessionsForAccount: async () => {
        listCalls += 1;
        throw new Error('indexeddb temporarily unavailable');
      },
      restoreSealedRecordForAccount: async () => 'restored' as const,
    };

    await restorePersistedSessionForSigningCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chain: 'tempo',
        reason: 'transaction',
      },
      ports,
    );
    await restorePersistedSessionForSigningCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chain: 'tempo',
        reason: 'transaction',
      },
      ports,
    );

    expect(listCalls).toBe(2);
  });

  test('caches exact-purpose misses when only purpose-mismatched records exist', async () => {
    const cache = createSigningSessionRestoreCache();
    let listCalls = 0;
    let restoreCalls = 0;

    const input = {
      walletId: 'restore.testnet',
      authMethod: 'email_otp' as const,
      curve: 'ecdsa' as const,
      chain: 'tempo' as const,
      reason: 'session_status' as const,
    };
    const ports = {
      cache,
      listExactSealedSessionsForAccount: async () => {
        listCalls += 1;
        return [makeSealedRecord({ chain: 'evm', thresholdSessionId: 'tsess-wrong-chain' })];
      },
      restoreSealedRecordForAccount: async () => {
        restoreCalls += 1;
        return 'restored' as const;
      },
    };

    await restorePersistedSessionForSigningCommand(input, ports);
    await restorePersistedSessionForSigningCommand(input, ports);

    expect(listCalls).toBe(1);
    expect(restoreCalls).toBe(0);
  });

  test('caches successful restores by durable record version', async () => {
    const cache = createSigningSessionRestoreCache();
    let restoreCalls = 0;
    let record = makeSealedRecord({ updatedAtMs: 1 });
    const input = {
      walletId: 'restore.testnet',
      authMethod: 'email_otp' as const,
      curve: 'ecdsa' as const,
      chain: 'tempo' as const,
      reason: 'transaction' as const,
    };
    const ports = {
      cache,
      listExactSealedSessionsForAccount: async () => [record],
      restoreSealedRecordForAccount: async () => {
        restoreCalls += 1;
        return 'restored' as const;
      },
    };

    await restorePersistedSessionForSigningCommand(input, ports);
    await restorePersistedSessionForSigningCommand(input, ports);
    record = makeSealedRecord({ updatedAtMs: 2 });
    await restorePersistedSessionForSigningCommand(input, ports);

    expect(restoreCalls).toBe(2);
  });

  test('does not cache deferred restore attempts as successful', async () => {
    const cache = createSigningSessionRestoreCache();
    let restoreCalls = 0;
    const input = {
      walletId: 'restore.testnet',
      authMethod: 'email_otp' as const,
      curve: 'ecdsa' as const,
      chain: 'tempo' as const,
      reason: 'transaction' as const,
    };

    await restorePersistedSessionForSigningCommand(input, {
      cache,
      listExactSealedSessionsForAccount: async () => [makeSealedRecord({})],
      restoreSealedRecordForAccount: async () => {
        restoreCalls += 1;
        return 'deferred';
      },
    });
    await restorePersistedSessionForSigningCommand(input, {
      cache,
      listExactSealedSessionsForAccount: async () => [makeSealedRecord({})],
      restoreSealedRecordForAccount: async () => {
        restoreCalls += 1;
        return 'deferred';
      },
    });

    expect(restoreCalls).toBe(2);
  });

  test('restores Ed25519 intent from an ECDSA-primary companion sealed record', async () => {
    let restoreCalls = 0;
    let restoredRecord: SigningSessionSealedStoreRecord | null = null;
    const companionRecord: SigningSessionSealedStoreRecord = {
      ...makeSealedRecord({
        chain: 'tempo',
        thresholdSessionId: 'tsess-ecdsa-companion',
        walletSigningSessionId: 'wsess-companion',
      }),
      thresholdSessionIds: {
        ecdsa: 'tsess-ecdsa-companion',
        ed25519: 'tsess-ed25519-companion',
      },
    };

    const result = await restorePersistedSessionForSigningCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        curve: 'ed25519',
        chain: 'near',
        thresholdSessionId: 'tsess-ed25519-companion',
        walletSigningSessionId: 'wsess-companion',
        reason: 'transaction',
      },
      {
        listExactSealedSessionsForAccount: async ({ curve }) =>
          curve === 'ed25519' ? [companionRecord] : [],
        restoreSealedRecordForAccount: async ({ record }) => {
          restoreCalls += 1;
          restoredRecord = record;
          return 'restored';
        },
      },
    );

    expect(result).toMatchObject({ attempted: 1, restored: 1, deferred: 0 });
    expect(restoreCalls).toBe(1);
    expect(restoredRecord?.thresholdSessionIds.ed25519).toBe('tsess-ed25519-companion');
    expect(restoredRecord?.thresholdSessionIds.ecdsa).toBe('tsess-ecdsa-companion');
  });

  test('passes Ed25519 purpose through to the restore port for an ECDSA-primary companion record', async () => {
    const companionRecord = makeSealedRecord({
      curve: 'ecdsa',
      chain: 'tempo',
      thresholdSessionId: 'tsess-ecdsa-primary',
      walletSigningSessionId: 'wsess-companion-purpose',
      thresholdSessionIds: {
        ecdsa: 'tsess-ecdsa-primary',
        ed25519: 'tsess-ed25519-purpose',
      },
    });
    const restoredPurposes: unknown[] = [];

    const result = await restorePersistedSessionForSigningCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        curve: 'ed25519',
        chain: 'near',
        reason: 'transaction',
      },
      {
        listExactSealedSessionsForAccount: async (filter) =>
          filter.curve === 'ed25519' ? [companionRecord] : [],
        restoreSealedRecordForAccount: async ({ purpose }) => {
          restoredPurposes.push(purpose);
          return 'restored';
        },
      },
    );

    expect(result).toMatchObject({ attempted: 1, restored: 1, deferred: 0 });
    expect(restoredPurposes).toEqual([
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        curve: 'ed25519',
        chain: 'near',
        walletSigningSessionId: 'wsess-companion-purpose',
        thresholdSessionId: 'tsess-ed25519-purpose',
        reason: 'transaction',
      },
    ]);
  });
});

test.describe('restorePersistedSessionsForAccountCommand', () => {
  test('bounds account-wide restore across exact ECDSA chain identities', async () => {
    const records = [
      makeSealedRecord({ chain: 'tempo', thresholdSessionId: 'tsess-1' }),
      makeSealedRecord({ chain: 'evm', thresholdSessionId: 'tsess-2' }),
      {
        ...makeSealedRecord({ thresholdSessionId: 'tsess-3' }),
        ecdsaRestore: undefined,
      },
    ];
    let restoreCalls = 0;

    const result = await restorePersistedSessionsForAccountCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        maxRecords: 2,
      },
      {
        listExactSealedSessionsForAccount: async (filter) =>
          records.filter((record) => {
            if (record.authMethod !== filter.authMethod) return false;
            if (record.curve !== filter.curve) return false;
            if (filter.curve === 'ecdsa') return record.ecdsaRestore?.chain === filter.chain;
            return true;
          }),
        restoreSealedRecordForAccount: async () => {
          restoreCalls += 1;
          return 'restored';
        },
      },
    );

    expect(result).toMatchObject({
      listed: 2,
      attempted: 2,
      restored: 2,
      deferred: 0,
      skipped: 0,
      truncated: 0,
    });
    expect(restoreCalls).toBe(2);
  });

  test('uses the restore cache for account-wide polling', async () => {
    const cache = createSigningSessionRestoreCache();
    let restoreCalls = 0;

    const input = {
      walletId: 'restore.testnet',
      authMethod: 'email_otp' as const,
      maxRecords: 10,
    };
    const ports = {
      cache,
      listExactSealedSessionsForAccount: async ({ chain }) =>
        chain === 'tempo' ? [makeSealedRecord({ chain: 'tempo' })] : [],
      restoreSealedRecordForAccount: async () => {
        restoreCalls += 1;
        return 'restored' as const;
      },
    };

    await restorePersistedSessionsForAccountCommand(input, ports);
    await restorePersistedSessionsForAccountCommand(input, ports);

    expect(restoreCalls).toBe(1);
  });

  test('enumerates passkey Ed25519 and ECDSA lanes for account startup restore', async () => {
    const records = [
      makeSealedRecord({
        authMethod: 'passkey',
        curve: 'ed25519',
        thresholdSessionId: 'tsess-passkey-ed25519',
      }),
      makeSealedRecord({
        authMethod: 'passkey',
        curve: 'ecdsa',
        chain: 'tempo',
        thresholdSessionId: 'tsess-passkey-tempo',
      }),
      makeSealedRecord({
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chain: 'tempo',
        thresholdSessionId: 'tsess-email-tempo',
      }),
    ];
    const restored: Array<{
      authMethod: string;
      curve: string;
      chain?: string;
      thresholdSessionId?: string;
    }> = [];

    const result = await restorePersistedSessionsForAccountCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'passkey',
        maxRecords: 10,
      },
      {
        listExactSealedSessionsForAccount: async (filter) =>
          records.filter((record) => {
            if (record.authMethod !== filter.authMethod) return false;
            if (record.curve !== filter.curve) return false;
            if (filter.curve === 'ecdsa') return record.ecdsaRestore?.chain === filter.chain;
            return true;
          }),
        restoreSealedRecordForAccount: async ({ record }) => {
          restored.push({
            authMethod: record.authMethod,
            curve: record.curve,
            chain: record.ecdsaRestore?.chain,
            thresholdSessionId: record.thresholdSessionIds[record.curve],
          });
          return 'restored';
        },
      },
    );

    expect(result).toMatchObject({
      listed: 2,
      attempted: 2,
      restored: 2,
      deferred: 0,
      skipped: 0,
      truncated: 0,
    });
    expect(restored).toEqual(
      expect.arrayContaining([
        {
          authMethod: 'passkey',
          curve: 'ed25519',
          thresholdSessionId: 'tsess-passkey-ed25519',
        },
        {
          authMethod: 'passkey',
          curve: 'ecdsa',
          chain: 'tempo',
          thresholdSessionId: 'tsess-passkey-tempo',
        },
      ]),
    );
  });

  test('emits separate account restore work items for a multi-curve sealed record', async () => {
    const companionRecord = makeSealedRecord({
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chain: 'tempo',
      thresholdSessionId: 'tsess-ecdsa-account',
      walletSigningSessionId: 'wsess-account-companion',
      thresholdSessionIds: {
        ecdsa: 'tsess-ecdsa-account',
        ed25519: 'tsess-ed25519-account',
      },
    });
    const restoredPurposes: unknown[] = [];

    const result = await restorePersistedSessionsForAccountCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        maxRecords: 10,
      },
      {
        listExactSealedSessionsForAccount: async (filter) => {
          if (filter.curve === 'ed25519') return [companionRecord];
          if (filter.curve === 'ecdsa' && filter.chain === 'tempo') return [companionRecord];
          return [];
        },
        restoreSealedRecordForAccount: async ({ purpose }) => {
          restoredPurposes.push(purpose);
          return 'restored';
        },
      },
    );

    expect(result).toMatchObject({
      attempted: 2,
      restored: 2,
      deferred: 0,
      skipped: 0,
      truncated: 0,
    });
    expect(restoredPurposes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          curve: 'ecdsa',
          chain: 'tempo',
          thresholdSessionId: 'tsess-ecdsa-account',
        }),
        expect.objectContaining({
          curve: 'ed25519',
          chain: 'near',
          thresholdSessionId: 'tsess-ed25519-account',
        }),
      ]),
    );
  });
});
