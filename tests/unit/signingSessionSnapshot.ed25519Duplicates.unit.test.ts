import { expect, test } from '@playwright/test';
import {
  readSigningSessionSnapshot,
  type SigningSessionSnapshotRuntimeClaim,
  type SigningSessionSnapshotRuntimeEd25519Record,
} from '@/core/signingEngine/session/snapshotReader';
import type { SigningSessionSealedStoreRecord } from '@/core/signingEngine/session/sealedSessionStore';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/session/signingSession/ecdsaChainTarget';

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
  } as SigningSessionSealedStoreRecord;
}

async function readSnapshot(args: {
  sealedRecords: SigningSessionSealedStoreRecord[];
  runtimeRecords?: SigningSessionSnapshotRuntimeEd25519Record[];
  runtimeClaims?: Map<string, SigningSessionSnapshotRuntimeClaim>;
}) {
  return await readSigningSessionSnapshot(
    {
      walletId: WALLET_ID,
      subjectId: WALLET_ID,
      ecdsaChainTargets: [ECDSA_TARGET],
    },
    {
      listSealedRecordsForAccount: async ({ filter }) =>
        filter.curve === 'ed25519' ? args.sealedRecords : [],
      listRuntimeEcdsaLanesForSubject: async () => [],
      listRuntimeEd25519RecordsForAccount: async () => args.runtimeRecords || [],
      readRuntimeClaimsForSessions: async (sessionIds) => {
        const claims = new Map<string, SigningSessionSnapshotRuntimeClaim | null>();
        for (const sessionId of sessionIds) {
          claims.set(sessionId, args.runtimeClaims?.get(sessionId) || null);
        }
        return claims;
      },
    },
  );
}

test.describe('Ed25519 signing-session snapshot duplicate normalization', () => {
  test('collapses duplicate durable entries with the same exact lane identity', async () => {
    const snapshot = await readSnapshot({
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

    expect(snapshot.candidates.ed25519.near).toHaveLength(1);
    expect(snapshot.candidates.ed25519.near[0]).toMatchObject({
      authMethod: 'email_otp',
      source: 'durable_sealed_record',
      walletSigningSessionId: 'wsess-1',
      thresholdSessionId: 'tsess-1',
      updatedAtMs: 200,
    });
  });

  test('uses the runtime lane when runtime and durable entries share exact identity', async () => {
    const snapshot = await readSnapshot({
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

    expect(snapshot.candidates.ed25519.near).toHaveLength(1);
    expect(snapshot.candidates.ed25519.near[0]).toMatchObject({
      authMethod: 'email_otp',
      state: 'ready',
      source: 'runtime_and_durable',
      walletSigningSessionId: 'wsess-1',
      thresholdSessionId: 'tsess-1',
      remainingUses: 1,
    });
  });

  test('keeps same session ids with different auth methods as distinct lanes', async () => {
    const snapshot = await readSnapshot({
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

    expect(snapshot.candidates.ed25519.near).toHaveLength(2);
    expect(snapshot.candidates.ed25519.near.map((lane) => lane.authMethod).sort()).toEqual([
      'email_otp',
      'passkey',
    ]);
  });

  test('keeps distinct threshold session ids as distinct lanes', async () => {
    const snapshot = await readSnapshot({
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

    expect(snapshot.candidates.ed25519.near).toHaveLength(2);
    expect(snapshot.candidates.ed25519.near.map((lane) => lane.thresholdSessionId).sort()).toEqual([
      'tsess-1',
      'tsess-2',
    ]);
  });
});
