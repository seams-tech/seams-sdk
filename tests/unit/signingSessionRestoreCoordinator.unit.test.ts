import { expect, test } from '@playwright/test';
import type { SigningSessionSealedStoreRecord } from '../../packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore';
import type { SealedRecoveryRecord } from '../../packages/sdk-web/src/core/signingEngine/session/sealedRecovery/recoveryRecord';
import {
  createSigningSessionRestoreCache,
  restorePersistedSessionsForWalletCommand,
  restorePersistedSessionForSigningCommand,
} from '../../packages/sdk-web/src/core/signingEngine/session/sealedRecovery/restoreCoordinator';

const TEST_ECDSA_CHAIN_TARGETS = {
  tempo: { kind: 'tempo' as const, chainId: 42431, networkSlug: 'tempo-moderato' },
  evm: {
    kind: 'evm' as const,
    namespace: 'eip155' as const,
    chainId: 5042002,
    networkSlug: 'arc-testnet',
  },
};
const TEST_ECDSA_CHAIN_TARGET_LIST = [TEST_ECDSA_CHAIN_TARGETS.tempo, TEST_ECDSA_CHAIN_TARGETS.evm];

function makeSealedRecord(args: {
  authMethod?: 'email_otp' | 'passkey';
  chain?: 'tempo' | 'evm';
  curve?: 'ed25519' | 'ecdsa';
  thresholdSessionId?: string;
  thresholdSessionIds?: {
    ed25519?: string;
    ecdsa?: string;
  };
  signingGrantId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  updatedAtMs?: number;
}): SigningSessionSealedStoreRecord {
  const authMethod = args.authMethod || 'email_otp';
  const curve = args.curve || 'ecdsa';
  const thresholdSessionId = args.thresholdSessionId || 'tsess-restore';
  const chain = args.chain || 'tempo';
  const chainTarget = TEST_ECDSA_CHAIN_TARGETS[chain];
  return {
    v: 1,
    alg: 'shamir3pass-v1',
    storageScope: 'iframe_origin_indexeddb',
    authMethod,
    secretKind: 'signing_session_secret32',
    storeKey: `${authMethod}:${curve}:${args.chain || 'near'}:${thresholdSessionId}`,
    signingGrantId: args.signingGrantId || 'wsess-restore',
    thresholdSessionIds:
      args.thresholdSessionIds ||
      (curve === 'ecdsa' ? { ecdsa: thresholdSessionId } : { ed25519: thresholdSessionId }),
    sealedSecretB64u: 'sealed-secret',
    curve,
    walletId: 'restore.testnet',
    userId: 'restore.testnet',
    relayerUrl: 'https://relay.example',
    ...(curve === 'ecdsa'
      ? {
          signingRootId: 'root-restore',
          signingRootVersion: 'v1',
          keyVersion: 'seal-v1',
          shamirPrimeB64u: 'prime-b64u',
          ecdsaRestore: {
            chainTarget,
            rpId: 'example.com',
            sessionKind: 'jwt' as const,
            walletSessionJwt: 'jwt-restore',
            keyHandle: 'key-handle-restore',
            ecdsaThresholdKeyId: 'ecdsa-key-restore',
            ethereumAddress: `0x${'33'.repeat(20)}`,
            relayerKeyId: 'relayer-key-restore',
            clientVerifyingShareB64u: 'client-verifying-share-restore',
            thresholdEcdsaPublicKeyB64u: 'threshold-public-key-restore',
            participantIds: [1, 2],
          },
        }
      : {
          ed25519Restore: {
            rpId: 'example.com',
            relayerKeyId: 'relayer-key-restore',
            participantIds: [1, 2],
            sessionKind: 'jwt' as const,
            walletSessionJwt: 'jwt-restore',
            signerSlot: 1,
          },
        }),
    issuedAtMs: 1,
    expiresAtMs: args.expiresAtMs ?? Date.now() + 60_000,
    remainingUses: args.remainingUses ?? 5,
    updatedAtMs: args.updatedAtMs || 1,
  };
}

function makeEd25519RecordWithEcdsaCompanion(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  ecdsaThresholdSessionId: string;
}): SigningSessionSealedStoreRecord {
  return {
    ...makeSealedRecord({
      curve: 'ed25519',
      thresholdSessionId: args.thresholdSessionId,
      signingGrantId: args.signingGrantId,
    }),
    subjectId: 'restore.testnet',
    signingRootId: 'root-restore',
    signingRootVersion: 'v1',
    thresholdSessionIds: {
      ecdsa: args.ecdsaThresholdSessionId,
      ed25519: args.thresholdSessionId,
    },
    ecdsaRestore: {
      chainTarget: TEST_ECDSA_CHAIN_TARGETS.tempo,
      rpId: 'example.com',
      sessionKind: 'jwt',
      walletSessionJwt: 'jwt-restore',
      keyHandle: 'key-handle-restore',
      ecdsaThresholdKeyId: 'ecdsa-key-restore',
      ethereumAddress: `0x${'33'.repeat(20)}`,
      relayerKeyId: 'relayer-key-restore',
      clientVerifyingShareB64u: 'client-verifying-share-restore',
      thresholdEcdsaPublicKeyB64u: 'threshold-public-key-restore',
      participantIds: [1, 2],
    },
  };
}

function makeEcdsaRecordWithEd25519Companion(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  ed25519ThresholdSessionId: string;
}): SigningSessionSealedStoreRecord {
  return {
    ...makeSealedRecord({
      authMethod: 'email_otp',
      curve: 'ecdsa',
      thresholdSessionId: args.thresholdSessionId,
      signingGrantId: args.signingGrantId,
      thresholdSessionIds: {
        ecdsa: args.thresholdSessionId,
        ed25519: args.ed25519ThresholdSessionId,
      },
    }),
    ed25519Restore: {
      rpId: 'example.com',
      relayerKeyId: 'relayer-key-restore',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      walletSessionJwt: 'jwt-ed25519-companion',
      signerSlot: 1,
      runtimePolicyScope: {
        mode: 'single_domain',
        parentOrigin: 'https://wallet.example.localhost',
      },
    },
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
        chainTarget: TEST_ECDSA_CHAIN_TARGETS.tempo,
        signingGrantId: 'wsess-restore',
        thresholdSessionId: 'tsess-restore',
        reason: 'transaction',
      },
      {
        cache,
        listExactSealedSessionsForWallet: async () => {
          listCalls += 1;
          return [];
        },
        restoreSealedRecordForWallet: async () => 'restored',
      },
    );
    await restorePersistedSessionForSigningCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chainTarget: TEST_ECDSA_CHAIN_TARGETS.tempo,
        signingGrantId: 'wsess-restore',
        thresholdSessionId: 'tsess-restore',
        reason: 'transaction',
      },
      {
        cache,
        listExactSealedSessionsForWallet: async () => {
          listCalls += 1;
          return [];
        },
        restoreSealedRecordForWallet: async () => 'restored',
      },
    );

    expect(listCalls).toBe(1);
  });

  test('does not cache transient list failures as known missing', async () => {
    const cache = createSigningSessionRestoreCache();
    let listCalls = 0;

    const ports = {
      cache,
      listExactSealedSessionsForWallet: async () => {
        listCalls += 1;
        throw new Error('indexeddb temporarily unavailable');
      },
      restoreSealedRecordForWallet: async () => 'restored' as const,
    };

    await restorePersistedSessionForSigningCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chainTarget: TEST_ECDSA_CHAIN_TARGETS.tempo,
        signingGrantId: 'wsess-restore',
        thresholdSessionId: 'tsess-restore',
        reason: 'transaction',
      },
      ports,
    );
    await restorePersistedSessionForSigningCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chainTarget: TEST_ECDSA_CHAIN_TARGETS.tempo,
        signingGrantId: 'wsess-restore',
        thresholdSessionId: 'tsess-restore',
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
      chainTarget: TEST_ECDSA_CHAIN_TARGETS.tempo,
      signingGrantId: 'wsess-restore',
      thresholdSessionId: 'tsess-restore',
      reason: 'transaction' as const,
    };
    const ports = {
      cache,
      listExactSealedSessionsForWallet: async () => {
        listCalls += 1;
        return [makeSealedRecord({ chain: 'evm', thresholdSessionId: 'tsess-wrong-chain' })];
      },
      restoreSealedRecordForWallet: async () => {
        restoreCalls += 1;
        return 'restored' as const;
      },
    };

    await restorePersistedSessionForSigningCommand(input, ports);
    await restorePersistedSessionForSigningCommand(input, ports);

    expect(listCalls).toBe(1);
    expect(restoreCalls).toBe(0);
  });

  test('ignores expired and exhausted exact-purpose sealed records', async () => {
    const cache = createSigningSessionRestoreCache();
    let restoreCalls = 0;

    const result = await restorePersistedSessionForSigningCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chainTarget: TEST_ECDSA_CHAIN_TARGETS.tempo,
        signingGrantId: 'wsess-restore',
        thresholdSessionId: 'tsess-restore',
        reason: 'transaction',
      },
      {
        cache,
        listExactSealedSessionsForWallet: async () => [
          makeSealedRecord({ expiresAtMs: Date.now() - 1 }),
          makeSealedRecord({ remainingUses: 0, updatedAtMs: 2 }),
        ],
        restoreSealedRecordForWallet: async () => {
          restoreCalls += 1;
          return 'restored';
        },
      },
    );

    expect(result).toEqual({ attempted: 0, restored: 0, deferred: 0 });
    expect(restoreCalls).toBe(0);
  });

  test('surfaces rejected exact-purpose records through the rejection callback', async () => {
    const rejections: string[] = [];

    const result = await restorePersistedSessionForSigningCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        curve: 'ed25519',
        chain: 'near',
        signingGrantId: 'wsess-restore',
        thresholdSessionId: 'tsess-restore',
        reason: 'transaction',
      },
      {
        listExactSealedSessionsForWallet: async () => [
          {
            ...makeSealedRecord({ curve: 'ed25519' }),
            ed25519Restore: {
              rpId: 'example.com',
              relayerKeyId: 'relayer-key-restore',
              participantIds: [1, 2],
              sessionKind: 'jwt',
              walletSessionJwt: 'jwt-restore',
            },
          },
        ],
        restoreSealedRecordForWallet: async () => 'restored',
        onRejectedRecord: ({ rejection }) => {
          rejections.push(rejection.reason);
        },
      },
    );

    expect(result).toEqual({ attempted: 0, restored: 0, deferred: 0 });
    expect(rejections).toEqual(['missing_restore_metadata']);
  });

  test('restores exhausted passkey exact-purpose sealed records for step-up reconnect', async () => {
    let restoreCalls = 0;

    const result = await restorePersistedSessionForSigningCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'passkey',
        curve: 'ecdsa',
        chainTarget: TEST_ECDSA_CHAIN_TARGETS.tempo,
        signingGrantId: 'wsess-restore',
        thresholdSessionId: 'tsess-restore',
        reason: 'transaction',
      },
      {
        listExactSealedSessionsForWallet: async () => [
          makeSealedRecord({
            authMethod: 'passkey',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 0,
          }),
        ],
        restoreSealedRecordForWallet: async () => {
          restoreCalls += 1;
          return 'restored';
        },
      },
    );

    expect(result).toEqual({ attempted: 1, restored: 1, deferred: 0 });
    expect(restoreCalls).toBe(1);
  });

  test('caches successful restores by durable record version', async () => {
    const cache = createSigningSessionRestoreCache();
    let restoreCalls = 0;
    let record = makeSealedRecord({ updatedAtMs: 1 });
    const input = {
      walletId: 'restore.testnet',
      authMethod: 'email_otp' as const,
      curve: 'ecdsa' as const,
      chainTarget: TEST_ECDSA_CHAIN_TARGETS.tempo,
      signingGrantId: 'wsess-restore',
      thresholdSessionId: 'tsess-restore',
      reason: 'transaction' as const,
    };
    const ports = {
      cache,
      listExactSealedSessionsForWallet: async () => [record],
      restoreSealedRecordForWallet: async () => {
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
      chainTarget: TEST_ECDSA_CHAIN_TARGETS.tempo,
      signingGrantId: 'wsess-restore',
      thresholdSessionId: 'tsess-restore',
      reason: 'transaction' as const,
    };

    await restorePersistedSessionForSigningCommand(input, {
      cache,
      listExactSealedSessionsForWallet: async () => [makeSealedRecord({})],
      restoreSealedRecordForWallet: async () => {
        restoreCalls += 1;
        return 'deferred';
      },
    });
    await restorePersistedSessionForSigningCommand(input, {
      cache,
      listExactSealedSessionsForWallet: async () => [makeSealedRecord({})],
      restoreSealedRecordForWallet: async () => {
        restoreCalls += 1;
        return 'deferred';
      },
    });

    expect(restoreCalls).toBe(2);
  });

  test('restores Ed25519 intent from an ECDSA-primary companion sealed record', async () => {
    let restoreCalls = 0;
    let restoredRecord: SealedRecoveryRecord | null = null;
    const companionRecord = makeEd25519RecordWithEcdsaCompanion({
      thresholdSessionId: 'tsess-ed25519-companion',
      signingGrantId: 'wsess-companion',
      ecdsaThresholdSessionId: 'tsess-ecdsa-companion',
    });

    const result = await restorePersistedSessionForSigningCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        curve: 'ed25519',
        chain: 'near',
        thresholdSessionId: 'tsess-ed25519-companion',
        signingGrantId: 'wsess-companion',
        reason: 'transaction',
      },
      {
        listExactSealedSessionsForWallet: async ({ curve }) =>
          curve === 'ed25519' ? [companionRecord] : [],
        restoreSealedRecordForWallet: async ({ record }) => {
          restoreCalls += 1;
          restoredRecord = record;
          return 'restored';
        },
      },
    );

    expect(result).toMatchObject({ attempted: 1, restored: 1, deferred: 0 });
    expect(restoreCalls).toBe(1);
    expect(restoredRecord).toMatchObject({
      authMethod: 'email_otp',
      curve: 'ed25519',
      thresholdSessionId: 'tsess-ed25519-companion',
      companionEcdsaRecovery: {
        thresholdSessionId: 'tsess-ecdsa-companion',
      },
    });
  });

  test('passes Ed25519 purpose through to the restore port for an ECDSA-primary companion record', async () => {
    const companionRecord = makeEd25519RecordWithEcdsaCompanion({
      thresholdSessionId: 'tsess-ed25519-purpose',
      signingGrantId: 'wsess-companion-purpose',
      ecdsaThresholdSessionId: 'tsess-ecdsa-primary',
    });
    const restoredPurposes: unknown[] = [];

    const result = await restorePersistedSessionForSigningCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        curve: 'ed25519',
        chain: 'near',
        signingGrantId: 'wsess-companion-purpose',
        thresholdSessionId: 'tsess-ed25519-purpose',
        reason: 'transaction',
      },
      {
        listExactSealedSessionsForWallet: async (filter) =>
          filter.curve === 'ed25519' ? [companionRecord] : [],
        restoreSealedRecordForWallet: async ({ purpose }) => {
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
        signingGrantId: 'wsess-companion-purpose',
        thresholdSessionId: 'tsess-ed25519-purpose',
        reason: 'transaction',
      },
    ]);
  });

  test('matches Ed25519 signing purpose from an Email OTP ECDSA sealed record with Ed25519 companion metadata', async () => {
    let restoreCalls = 0;
    let restoredPurpose: unknown = null;
    let restoredRecord: SealedRecoveryRecord | null = null;
    const ecdsaPrimaryRecord = makeEcdsaRecordWithEd25519Companion({
      thresholdSessionId: 'tsess-ecdsa-primary',
      signingGrantId: 'wsess-ecdsa-primary',
      ed25519ThresholdSessionId: 'tsess-ed25519-companion',
    });

    const result = await restorePersistedSessionForSigningCommand(
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        curve: 'ed25519',
        chain: 'near',
        signingGrantId: 'wsess-ecdsa-primary',
        thresholdSessionId: 'tsess-ed25519-companion',
        reason: 'transaction',
      },
      {
        listExactSealedSessionsForWallet: async ({ curve }) =>
          curve === 'ed25519' ? [ecdsaPrimaryRecord] : [],
        restoreSealedRecordForWallet: async ({ purpose, record }) => {
          restoreCalls += 1;
          restoredPurpose = purpose;
          restoredRecord = record;
          return 'restored';
        },
      },
    );

    expect(result).toMatchObject({ attempted: 1, restored: 1, deferred: 0 });
    expect(restoreCalls).toBe(1);
    expect(restoredPurpose).toEqual({
      walletId: 'restore.testnet',
      authMethod: 'email_otp',
      curve: 'ed25519',
      chain: 'near',
      signingGrantId: 'wsess-ecdsa-primary',
      thresholdSessionId: 'tsess-ed25519-companion',
      reason: 'transaction',
    });
    expect(restoredRecord).toMatchObject({
      authMethod: 'email_otp',
      curve: 'ecdsa',
      signingGrantId: 'wsess-ecdsa-primary',
      thresholdSessionId: 'tsess-ecdsa-primary',
      companionEd25519ThresholdSessionId: 'tsess-ed25519-companion',
    });
  });
});

test.describe('restorePersistedSessionsForWalletCommand', () => {
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

    const result = await restorePersistedSessionsForWalletCommand(
      {
        kind: 'restore_wallet_ecdsa_signing_sessions',
        walletId: 'restore.testnet',
        ecdsaChainTargets: TEST_ECDSA_CHAIN_TARGET_LIST,
        authMethod: 'email_otp',
        maxRecords: 2,
      },
      {
        listExactSealedSessionsForWallet: async (filter) =>
          records.filter((record) => {
            if (record.authMethod !== filter.authMethod) return false;
            if (record.curve !== filter.curve) return false;
            if (filter.curve === 'ecdsa') {
              return record.ecdsaRestore?.chainTarget?.kind === filter.chainTarget.kind;
            }
            return true;
          }),
        restoreSealedRecordForWallet: async () => {
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
      kind: 'restore_wallet_ecdsa_signing_sessions' as const,
      walletId: 'restore.testnet',
      ecdsaChainTargets: TEST_ECDSA_CHAIN_TARGET_LIST,
      authMethod: 'email_otp' as const,
      maxRecords: 10,
    };
    const ports = {
      cache,
      listExactSealedSessionsForWallet: async (filter: any) =>
        filter.curve === 'ecdsa' && filter.chainTarget?.kind === 'tempo'
          ? [makeSealedRecord({ chain: 'tempo' })]
          : [],
      restoreSealedRecordForWallet: async () => {
        restoreCalls += 1;
        return 'restored' as const;
      },
    };

    await restorePersistedSessionsForWalletCommand(input, ports);
    await restorePersistedSessionsForWalletCommand(input, ports);

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
      chainTarget?: unknown;
      thresholdSessionId?: string;
    }> = [];

    const result = await restorePersistedSessionsForWalletCommand(
      {
        kind: 'restore_wallet_all_signing_sessions',
        walletId: 'restore.testnet',
        ecdsaChainTargets: TEST_ECDSA_CHAIN_TARGET_LIST,
        authMethod: 'passkey',
        maxRecords: 10,
      },
      {
        listExactSealedSessionsForWallet: async (filter) =>
          records.filter((record) => {
            if (record.authMethod !== filter.authMethod) return false;
            if (record.curve !== filter.curve) return false;
            if (filter.curve === 'ecdsa') {
              return record.ecdsaRestore?.chainTarget?.kind === filter.chainTarget.kind;
            }
            return true;
          }),
        restoreSealedRecordForWallet: async ({ record }) => {
          restored.push({
            authMethod: record.authMethod,
            curve: record.curve,
            chain: record.curve === 'ecdsa' ? record.chainTarget.kind : undefined,
            chainTarget: record.curve === 'ecdsa' ? record.chainTarget : undefined,
            thresholdSessionId: record.thresholdSessionId,
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
        expect.objectContaining({
          authMethod: 'passkey',
          curve: 'ed25519',
          thresholdSessionId: 'tsess-passkey-ed25519',
        }),
        expect.objectContaining({
          authMethod: 'passkey',
          curve: 'ecdsa',
          chainTarget: TEST_ECDSA_CHAIN_TARGETS.tempo,
          thresholdSessionId: 'tsess-passkey-tempo',
        }),
      ]),
    );
  });

  test('emits separate account restore work items for a multi-curve sealed record', async () => {
    const companionRecord = makeEd25519RecordWithEcdsaCompanion({
      thresholdSessionId: 'tsess-ed25519-account',
      signingGrantId: 'wsess-account-companion',
      ecdsaThresholdSessionId: 'tsess-ecdsa-account',
    });
    const restoredPurposes: unknown[] = [];

    const result = await restorePersistedSessionsForWalletCommand(
      {
        kind: 'restore_wallet_all_signing_sessions',
        walletId: 'restore.testnet',
        ecdsaChainTargets: TEST_ECDSA_CHAIN_TARGET_LIST,
        authMethod: 'email_otp',
        maxRecords: 10,
      },
      {
        listExactSealedSessionsForWallet: async (filter) => {
          if (filter.curve === 'ed25519') return [companionRecord];
          if (filter.curve === 'ecdsa' && filter.chainTarget.kind === 'tempo') {
            return [companionRecord];
          }
          return [];
        },
        restoreSealedRecordForWallet: async ({ purpose }) => {
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
          chainTarget: TEST_ECDSA_CHAIN_TARGETS.tempo,
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
