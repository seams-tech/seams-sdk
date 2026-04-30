import { expect, test } from '@playwright/test';
import type { SigningSessionSealedStoreRecord } from '@/core/signingEngine/session/sealedSessionStore';
import { readSigningSessionSnapshot } from '@/core/signingEngine/session/snapshotReader';

function makeSealedRecord(args: {
  chain: 'tempo' | 'evm';
  authMethod?: 'email_otp' | 'passkey';
  thresholdSessionId?: string;
  walletSigningSessionId?: string;
  remainingUses?: number;
  expiresAtMs?: number;
  updatedAtMs?: number;
}): SigningSessionSealedStoreRecord {
  const thresholdSessionId = args.thresholdSessionId || `tsess-${args.chain}`;
  return {
    v: 1,
    alg: 'shamir3pass-v1',
    storageScope: 'iframe_origin_indexeddb',
    authMethod: args.authMethod || 'email_otp',
    secretKind: 'signing_session_secret32',
    storeKey: `email_otp:ecdsa:${thresholdSessionId}`,
    walletSigningSessionId: args.walletSigningSessionId || `wsess-${args.chain}`,
    thresholdSessionIds: { ecdsa: thresholdSessionId },
    sealedSecretB64u: 'sealed-secret',
    curve: 'ecdsa',
    walletId: 'snapshot.testnet',
    userId: 'snapshot.testnet',
    ecdsaRestore: {
      chain: args.chain,
      sessionKind: 'jwt',
      thresholdSessionJwt: 'jwt-snapshot',
      ecdsaThresholdKeyId: 'ecdsa-key-snapshot',
      relayerKeyId: 'relayer-key-snapshot',
      participantIds: [1, 2],
    },
    issuedAtMs: 1,
    expiresAtMs: args.expiresAtMs ?? 10_000,
    remainingUses: args.remainingUses ?? 5,
    updatedAtMs: args.updatedAtMs ?? 1,
  };
}

function makeEd25519SealedRecord(args: {
  authMethod?: 'email_otp' | 'passkey';
  thresholdSessionId?: string;
  walletSigningSessionId?: string;
  remainingUses?: number;
  expiresAtMs?: number;
  updatedAtMs?: number;
}): SigningSessionSealedStoreRecord {
  const thresholdSessionId = args.thresholdSessionId || 'tsess-ed25519';
  return {
    v: 1,
    alg: 'shamir3pass-v1',
    storageScope: 'iframe_origin_indexeddb',
    authMethod: args.authMethod || 'email_otp',
    secretKind: 'signing_session_secret32',
    storeKey: `email_otp:ed25519:${thresholdSessionId}`,
    walletSigningSessionId: args.walletSigningSessionId || 'wsess-ed25519',
    thresholdSessionIds: { ed25519: thresholdSessionId },
    sealedSecretB64u: 'sealed-secret',
    curve: 'ed25519',
    walletId: 'snapshot.testnet',
    userId: 'snapshot.testnet',
    issuedAtMs: 1,
    expiresAtMs: args.expiresAtMs ?? 10_000,
    remainingUses: args.remainingUses ?? 5,
    updatedAtMs: args.updatedAtMs ?? 1,
  };
}

test.describe('readSigningSessionSnapshot', () => {
  test('reports durable sealed ECDSA records as restorable without unsealing', async () => {
    let listCalls = 0;
    const snapshot = await readSigningSessionSnapshot(
      {
        walletId: 'snapshot.testnet',
        authMethod: 'email_otp',
        nowMs: 5_000,
      },
      {
        listSealedRecordsForAccount: async ({ filter }) => {
          listCalls += 1;
          return filter.curve === 'ecdsa' && filter.chain === 'tempo'
            ? [makeSealedRecord({ chain: 'tempo', updatedAtMs: 3 })]
            : [];
        },
      },
    );

    expect(listCalls).toBe(3);
    expect(snapshot.generation).toBe(3);
    expect(snapshot.lanes.ecdsa.tempo).toMatchObject({
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chain: 'tempo',
      state: 'restorable',
      source: 'durable_sealed_record',
      thresholdSessionId: 'tsess-tempo',
      walletSigningSessionId: 'wsess-tempo',
      policyHint: {
        remainingUses: 5,
        expiresAtMs: 10_000,
      },
    });
    expect(snapshot.candidates.ecdsa.tempo).toHaveLength(1);
    expect(snapshot.candidates.ecdsa.tempo[0]).toMatchObject({
      authMethod: 'email_otp',
      thresholdSessionId: 'tsess-tempo',
      walletSigningSessionId: 'wsess-tempo',
    });
    expect(snapshot.lanes.ecdsa.evm).toMatchObject({
      chain: 'evm',
      state: 'missing',
    });
    expect(snapshot.lanes.ed25519.near).toMatchObject({
      chain: 'near',
      state: 'missing',
    });
  });

  test('reports durable sealed Ed25519 records as restorable without unsealing', async () => {
    const snapshot = await readSigningSessionSnapshot(
      {
        walletId: 'snapshot.testnet',
        authMethod: 'email_otp',
        nowMs: 5_000,
      },
      {
        listSealedRecordsForAccount: async ({ filter }) =>
          filter.curve === 'ed25519'
            ? [
                makeEd25519SealedRecord({
                  thresholdSessionId: 'tsess-ed25519-ready',
                  walletSigningSessionId: 'wsess-ed25519-ready',
                  updatedAtMs: 6,
                }),
              ]
            : [],
      },
    );

    expect(snapshot.generation).toBe(6);
    expect(snapshot.lanes.ed25519.near).toMatchObject({
      authMethod: 'email_otp',
      curve: 'ed25519',
      chain: 'near',
      state: 'restorable',
      source: 'durable_sealed_record',
      thresholdSessionId: 'tsess-ed25519-ready',
      walletSigningSessionId: 'wsess-ed25519-ready',
      policyHint: {
        remainingUses: 5,
        expiresAtMs: 10_000,
      },
    });
    expect(snapshot.lanes.ecdsa.tempo.state).toBe('missing');
    expect(snapshot.lanes.ecdsa.evm.state).toBe('missing');
  });

  test('reports Ed25519 companion ids on ECDSA-primary sealed records as restorable', async () => {
    const companionRecord: SigningSessionSealedStoreRecord = {
      ...makeSealedRecord({
        chain: 'tempo',
        thresholdSessionId: 'tsess-ecdsa-companion',
        walletSigningSessionId: 'wsess-companion',
        updatedAtMs: 7,
      }),
      thresholdSessionIds: {
        ecdsa: 'tsess-ecdsa-companion',
        ed25519: 'tsess-ed25519-companion',
      },
    };
    const snapshot = await readSigningSessionSnapshot(
      {
        walletId: 'snapshot.testnet',
        authMethod: 'email_otp',
        nowMs: 5_000,
      },
      {
        listSealedRecordsForAccount: async ({ filter }) => {
          if (filter.curve === 'ed25519') return [companionRecord];
          return [];
        },
      },
    );

    expect(snapshot.lanes.ed25519.near).toMatchObject({
      authMethod: 'email_otp',
      curve: 'ed25519',
      chain: 'near',
      state: 'restorable',
      source: 'durable_sealed_record',
      thresholdSessionId: 'tsess-ed25519-companion',
      walletSigningSessionId: 'wsess-companion',
    });
  });

  test('reports raw durable expired and exhausted policy as hints until trusted', async () => {
    const snapshot = await readSigningSessionSnapshot(
      {
        walletId: 'snapshot.testnet',
        nowMs: 5_000,
      },
      {
        listSealedRecordsForAccount: async ({ filter }) =>
          filter.curve === 'ecdsa'
            ? [
                filter.chain === 'tempo'
                  ? makeSealedRecord({
                      chain: 'tempo',
                      thresholdSessionId: 'tsess-exhausted',
                      remainingUses: 0,
                      expiresAtMs: 10_000,
                    })
                  : makeSealedRecord({
                      chain: 'evm',
                      thresholdSessionId: 'tsess-expired',
                      remainingUses: 5,
                      expiresAtMs: 4_000,
                    }),
              ]
            : [],
      },
    );

    expect(snapshot.lanes.ecdsa.tempo).toMatchObject({
      state: 'restorable',
      policyHint: {
        remainingUses: 0,
        expiresAtMs: 10_000,
      },
    });
    expect(snapshot.lanes.ecdsa.evm).toMatchObject({
      state: 'restorable',
      policyHint: {
        remainingUses: 5,
        expiresAtMs: 4_000,
      },
    });
  });

  test('keeps the newest exact-purpose record for each chain', async () => {
    const snapshot = await readSigningSessionSnapshot(
      {
        walletId: 'snapshot.testnet',
        nowMs: 5_000,
      },
      {
        listSealedRecordsForAccount: async ({ filter }) =>
          filter.curve === 'ecdsa' && filter.chain === 'tempo'
            ? [
                makeSealedRecord({
                  chain: 'tempo',
                  thresholdSessionId: 'tsess-old',
                  walletSigningSessionId: 'wsess-old',
                  updatedAtMs: 1,
                }),
                makeSealedRecord({
                  chain: 'tempo',
                  thresholdSessionId: 'tsess-new',
                  walletSigningSessionId: 'wsess-new',
                  updatedAtMs: 2,
                }),
              ]
            : [],
      },
    );

    expect(snapshot.generation).toBe(2);
    expect(snapshot.lanes.ecdsa.tempo).toMatchObject({
      thresholdSessionId: 'tsess-new',
      walletSigningSessionId: 'wsess-new',
      state: 'restorable',
    });
    expect(snapshot.candidates.ecdsa.tempo.map((lane) => lane.thresholdSessionId)).toEqual([
      'tsess-old',
      'tsess-new',
    ]);
  });

  test('exposes linked Email OTP and passkey ECDSA candidates instead of only the merged lane', async () => {
    const snapshot = await readSigningSessionSnapshot(
      {
        walletId: 'snapshot.testnet',
        nowMs: 5_000,
      },
      {
        listSealedRecordsForAccount: async ({ filter }) =>
          filter.curve === 'ecdsa' && filter.chain === 'evm'
            ? [
                makeSealedRecord({
                  authMethod: 'email_otp',
                  chain: 'evm',
                  thresholdSessionId: 'tsess-email-evm',
                  walletSigningSessionId: 'wsess-email-evm',
                  updatedAtMs: 1,
                }),
                makeSealedRecord({
                  authMethod: 'passkey',
                  chain: 'evm',
                  thresholdSessionId: 'tsess-passkey-evm',
                  walletSigningSessionId: 'wsess-passkey-evm',
                  updatedAtMs: 2,
                }),
              ]
            : [],
      },
    );

    expect(snapshot.lanes.ecdsa.evm).toMatchObject({
      authMethod: 'passkey',
      thresholdSessionId: 'tsess-passkey-evm',
    });
    expect(snapshot.candidates.ecdsa.evm).toEqual([
      expect.objectContaining({
        authMethod: 'email_otp',
        thresholdSessionId: 'tsess-email-evm',
        walletSigningSessionId: 'wsess-email-evm',
      }),
      expect.objectContaining({
        authMethod: 'passkey',
        thresholdSessionId: 'tsess-passkey-evm',
        walletSigningSessionId: 'wsess-passkey-evm',
      }),
    ]);
  });

  test('overlays runtime ECDSA readiness without unsealing durable records', async () => {
    const snapshot = await readSigningSessionSnapshot(
      {
        walletId: 'snapshot.testnet',
        nowMs: 5_000,
      },
      {
        listSealedRecordsForAccount: async ({ filter }) =>
          filter.curve === 'ecdsa' && filter.chain === 'tempo'
            ? [
                makeSealedRecord({
                  chain: 'tempo',
                  thresholdSessionId: 'tsess-runtime-ready',
                  walletSigningSessionId: 'wsess-runtime-ready',
                  updatedAtMs: 2,
                }),
              ]
            : [],
        listRuntimeEcdsaRecordsForAccount: async () => [
          {
            authMethod: 'email_otp',
            curve: 'ecdsa',
            chain: 'tempo',
            thresholdSessionId: 'tsess-runtime-ready',
            walletSigningSessionId: 'wsess-runtime-ready',
          },
          {
            authMethod: 'passkey',
            curve: 'ecdsa',
            chain: 'evm',
            thresholdSessionId: 'tsess-passkey-missing',
            walletSigningSessionId: 'wsess-passkey-missing',
          },
        ],
        readRuntimeClaimsForSessions: async (sessionIds) =>
          new Map(
            sessionIds.map((sessionId) => [
              sessionId,
              sessionId === 'tsess-runtime-ready'
                ? {
                    state: 'warm' as const,
                    sessionId,
                    remainingUses: 4,
                    expiresAtMs: 9_000,
                  }
                : {
                    state: 'missing' as const,
                    sessionId,
                  },
            ]),
          ),
      },
    );

    expect(snapshot.lanes.ecdsa.tempo).toMatchObject({
      authMethod: 'email_otp',
      chain: 'tempo',
      state: 'ready',
      source: 'runtime_and_durable',
      thresholdSessionId: 'tsess-runtime-ready',
      walletSigningSessionId: 'wsess-runtime-ready',
      remainingUses: 4,
      expiresAtMs: 9_000,
    });
    expect(snapshot.lanes.ecdsa.evm).toMatchObject({
      authMethod: 'passkey',
      chain: 'evm',
      state: 'missing',
      source: 'runtime_session_record',
      thresholdSessionId: 'tsess-passkey-missing',
    });
  });

  test('preserves durable restorable state when matching runtime worker material is missing', async () => {
    const snapshot = await readSigningSessionSnapshot(
      {
        walletId: 'snapshot.testnet',
        authMethod: 'email_otp',
      },
      {
        listSealedRecordsForAccount: async ({ filter }) =>
          filter.curve === 'ed25519'
            ? [
                makeEd25519SealedRecord({
                  thresholdSessionId: 'tsess-ed25519-worker-missing',
                  walletSigningSessionId: 'wsess-ed25519-worker-missing',
                  updatedAtMs: 8,
                }),
              ]
            : [],
        listRuntimeEd25519RecordsForAccount: async () => [
          {
            authMethod: 'email_otp',
            curve: 'ed25519',
            chain: 'near',
            thresholdSessionId: 'tsess-ed25519-worker-missing',
            walletSigningSessionId: 'wsess-ed25519-worker-missing',
          },
        ],
        readRuntimeClaimsForSessions: async () =>
          new Map([
            [
              'tsess-ed25519-worker-missing',
              { state: 'missing', sessionId: 'tsess-ed25519-worker-missing' },
            ],
          ]),
      },
    );

    expect(snapshot.lanes.ed25519.near).toMatchObject({
      state: 'restorable',
      source: 'runtime_and_durable',
      thresholdSessionId: 'tsess-ed25519-worker-missing',
      walletSigningSessionId: 'wsess-ed25519-worker-missing',
    });
  });

  test('can read passkey exact-purpose runtime snapshots without Email OTP restore', async () => {
    const filters: unknown[] = [];
    const snapshot = await readSigningSessionSnapshot(
      {
        walletId: 'snapshot.testnet',
        authMethod: 'passkey',
        nowMs: 5_000,
      },
      {
        listSealedRecordsForAccount: async ({ filter }) => {
          filters.push(filter);
          return filter.curve === 'ecdsa' && filter.chain === 'tempo'
            ? [
                makeSealedRecord({
                  authMethod: 'passkey',
                  chain: 'tempo',
                  thresholdSessionId: 'tsess-passkey-ready',
                  walletSigningSessionId: 'wsess-passkey-ready',
                  updatedAtMs: 4,
                }),
              ]
            : [];
        },
        listRuntimeEcdsaRecordsForAccount: async () => [
          {
            authMethod: 'passkey',
            curve: 'ecdsa',
            chain: 'tempo',
            thresholdSessionId: 'tsess-passkey-ready',
            walletSigningSessionId: 'wsess-passkey-ready',
          },
          {
            authMethod: 'email_otp',
            curve: 'ecdsa',
            chain: 'evm',
            thresholdSessionId: 'tsess-email-filtered',
          },
        ],
        readRuntimeClaimsForSessions: async (sessionIds) =>
          new Map(
            sessionIds.map((sessionId) => [
              sessionId,
              {
                state: 'warm' as const,
                sessionId,
                remainingUses: 7,
                expiresAtMs: 12_000,
              },
            ]),
          ),
      },
    );

    expect(filters).toEqual([
      { authMethod: 'passkey', curve: 'ecdsa', chain: 'tempo' },
      { authMethod: 'passkey', curve: 'ecdsa', chain: 'evm' },
      { authMethod: 'passkey', curve: 'ed25519' },
    ]);
    expect(snapshot.lanes.ecdsa.tempo).toMatchObject({
      authMethod: 'passkey',
      state: 'ready',
      source: 'runtime_and_durable',
      thresholdSessionId: 'tsess-passkey-ready',
      walletSigningSessionId: 'wsess-passkey-ready',
      remainingUses: 7,
    });
    expect(snapshot.lanes.ecdsa.evm.state).toBe('missing');
  });
});
