import { expect, test } from '@playwright/test';
import {
  readAvailableSigningLanes,
  type AvailableSigningLanesRuntimeClaim,
  type AvailableSigningLanesRuntimeEd25519Record,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import type { SigningSessionSealedStoreRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  thresholdEcdsaChainTargetKey,
  toWalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const WALLET_ID = 'alice.testnet';
const EXPIRES_AT_MS = 1_778_000_000_000;
const ECDSA_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
});

function sealedEd25519Record(args: {
  authMethod: 'email_otp' | 'passkey';
  walletSigningSessionId: string;
  thresholdSessionId: string;
  updatedAtMs: number;
}): SigningSessionSealedStoreRecord {
  return {
    storeKey: `${args.authMethod}:${args.walletSigningSessionId}:${args.thresholdSessionId}:${args.updatedAtMs}`,
    curve: 'ed25519',
    authMethod: args.authMethod,
    walletId: WALLET_ID,
    walletSigningSessionId: args.walletSigningSessionId,
    thresholdSessionId: args.thresholdSessionId,
    thresholdSessionIds: { ed25519: args.thresholdSessionId },
    sealedSecretB64u: 'sealed',
    expiresAtMs: EXPIRES_AT_MS,
    remainingUses: 1,
    updatedAtMs: args.updatedAtMs,
  } as unknown as SigningSessionSealedStoreRecord;
}

function sealedEcdsaRecord(args: {
  walletSigningSessionId: string;
  thresholdSessionId: string;
  updatedAtMs: number;
  restoreMetadata: 'valid' | 'missing';
}): SigningSessionSealedStoreRecord {
  const issuedAtMs = Date.now();
  return {
    storeKey: `passkey:${args.walletSigningSessionId}:${args.thresholdSessionId}:${args.updatedAtMs}:ecdsa`,
    curve: 'ecdsa',
    authMethod: 'passkey',
    walletId: WALLET_ID,
    walletSigningSessionId: args.walletSigningSessionId,
    thresholdSessionId: args.thresholdSessionId,
    thresholdSessionIds: { ecdsa: args.thresholdSessionId },
    sealedSecretB64u: 'sealed',
    subjectId: WALLET_ID,
    signingRootId: 'sr-test:dev',
    signingRootVersion: 'default',
    relayerUrl: 'https://relay.example.test',
    keyVersion: 'seal-key-v1',
    shamirPrimeB64u: 'shamir-prime',
    ecdsaRestore:
      args.restoreMetadata === 'valid'
        ? {
            chainTarget: ECDSA_TARGET,
            sessionKind: 'cookie',
            ecdsaThresholdKeyId: 'ek-passkey',
            relayerKeyId: 'relayer-key',
            clientVerifyingShareB64u: 'client-verifying-share',
            participantIds: [1, 2],
          }
        : {
            chainTarget: ECDSA_TARGET,
            sessionKind: 'cookie',
            ecdsaThresholdKeyId: 'ek-passkey',
          },
    issuedAtMs,
    expiresAtMs: issuedAtMs + 60_000,
    remainingUses: 1,
    updatedAtMs: args.updatedAtMs,
  } as unknown as SigningSessionSealedStoreRecord;
}

async function readAvailableLanes(args: {
  sealedRecords: SigningSessionSealedStoreRecord[];
  runtimeRecords?: AvailableSigningLanesRuntimeEd25519Record[];
  runtimeClaims?: Map<string, AvailableSigningLanesRuntimeClaim>;
}) {
  return await readAvailableSigningLanes(
    {
      walletId: WALLET_ID,
      subjectId: toWalletSubjectId(WALLET_ID),
      ecdsaChainTargets: [ECDSA_TARGET],
    },
    {
      listSealedRecordsForWallet: async ({ filter }) =>
        args.sealedRecords.filter((record) => record.curve === filter.curve),
      listRuntimeEcdsaLanesForSubject: async () => [],
      listRuntimeEd25519RecordsForAccount: async () => args.runtimeRecords || [],
      readRuntimeClaimsForSessions: async (sessionIds) => {
        const claims = new Map<string, AvailableSigningLanesRuntimeClaim | null>();
        for (const sessionId of sessionIds) {
          claims.set(sessionId, args.runtimeClaims?.get(sessionId) || null);
        }
        return claims;
      },
    },
  );
}

test.describe('Ed25519 available signing lanes duplicate normalization', () => {
  test('collapses duplicate durable entries with the same exact lane identity', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEd25519Record({
          authMethod: 'email_otp',
          walletSigningSessionId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
          updatedAtMs: 100,
        }),
        sealedEd25519Record({
          authMethod: 'email_otp',
          walletSigningSessionId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
          updatedAtMs: 200,
        }),
      ],
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(1);
    expect(availableLanes.candidates.ed25519.near[0]).toMatchObject({
      authMethod: 'email_otp',
      source: 'durable_sealed_record',
      walletSigningSessionId: 'wsess-1',
      thresholdSessionId: 'tsess-1',
      updatedAtMs: 200,
    });
  });

  test('uses the runtime lane when runtime and durable entries share exact identity', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEd25519Record({
          authMethod: 'email_otp',
          walletSigningSessionId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
          updatedAtMs: 100,
        }),
      ],
      runtimeRecords: [
        {
          authMethod: 'email_otp',
          curve: 'ed25519',
          chain: 'near',
          walletSigningSessionId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
        },
      ],
      runtimeClaims: new Map([
        [
          'tsess-1',
          {
            state: 'warm',
            sessionId: 'tsess-1',
            remainingUses: 1,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(1);
    expect(availableLanes.candidates.ed25519.near[0]).toMatchObject({
      authMethod: 'email_otp',
      state: 'ready',
      source: 'runtime_and_durable',
      walletSigningSessionId: 'wsess-1',
      thresholdSessionId: 'tsess-1',
      remainingUses: 1,
    });
  });

  test('keeps same session ids with different auth methods as distinct lanes', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEd25519Record({
          authMethod: 'passkey',
          walletSigningSessionId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
          updatedAtMs: 100,
        }),
      ],
      runtimeRecords: [
        {
          authMethod: 'email_otp',
          curve: 'ed25519',
          chain: 'near',
          walletSigningSessionId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
        },
      ],
      runtimeClaims: new Map([
        [
          'tsess-1',
          {
            state: 'warm',
            sessionId: 'tsess-1',
            remainingUses: 1,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(2);
    expect(availableLanes.candidates.ed25519.near.map((lane) => lane.authMethod).sort()).toEqual([
      'email_otp',
      'passkey',
    ]);
  });

  test('keeps distinct threshold session ids as distinct lanes', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEd25519Record({
          authMethod: 'email_otp',
          walletSigningSessionId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
          updatedAtMs: 100,
        }),
        sealedEd25519Record({
          authMethod: 'email_otp',
          walletSigningSessionId: 'wsess-2',
          thresholdSessionId: 'tsess-2',
          updatedAtMs: 200,
        }),
      ],
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(2);
    expect(availableLanes.candidates.ed25519.near.map((lane) => lane.thresholdSessionId).sort()).toEqual([
      'tsess-1',
      'tsess-2',
    ]);
  });

  test('ignores durable ECDSA entries that cannot normalize for sealed restore', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEcdsaRecord({
          walletSigningSessionId: 'wsess-stale-ecdsa',
          thresholdSessionId: 'tsess-stale-ecdsa',
          updatedAtMs: 300,
          restoreMetadata: 'missing',
        }),
        sealedEcdsaRecord({
          walletSigningSessionId: 'wsess-valid-ecdsa',
          thresholdSessionId: 'tsess-valid-ecdsa',
          updatedAtMs: 200,
          restoreMetadata: 'valid',
        }),
      ],
    });

    const targetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[targetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[targetKey][0]).toMatchObject({
      authMethod: 'passkey',
      source: 'durable_sealed_record',
      state: 'restorable',
      walletSigningSessionId: 'wsess-valid-ecdsa',
      thresholdSessionId: 'tsess-valid-ecdsa',
      ecdsaThresholdKeyId: 'ek-passkey',
    });
  });
});
