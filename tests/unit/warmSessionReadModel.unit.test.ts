import { expect, test } from '@playwright/test';
import {
  deriveEcdsaCapabilityState,
  deriveEd25519CapabilityState,
  normalizeWarmSessionReadPorts,
  readWarmSessionClaims,
  resolveEcdsaAuthMaterial,
  resolveEcdsaSealTransport,
  resolveEd25519AuthMaterial,
  toSigningSessionStatus,
  toWarmSessionClaimFromStatusResult,
} from '@/core/signingEngine/session/warmCapabilities/readModel';
import {
  createThresholdEcdsaStoreFixture,
  createWarmSessionStatusReader,
  resetWarmSessionFixtureState,
  seedEd25519WarmSessionRecord,
  seedEcdsaWarmSessionRecord,
} from './helpers/warmSessionStore.fixtures';

test.describe('warmSessionReadModel', () => {
  test('maps warm-session status results into canonical claim states', () => {
    expect(
      toWarmSessionClaimFromStatusResult({
        sessionId: 'warm-session',
        status: {
          ok: true,
          remainingUses: 3,
          expiresAtMs: 1234,
        },
      }),
    ).toMatchObject({
      state: 'warm',
      sessionId: 'warm-session',
      remainingUses: 3,
      expiresAtMs: 1234,
    });

    expect(
      toWarmSessionClaimFromStatusResult({
        sessionId: 'missing-session',
        status: {
          ok: false,
          code: 'not_found',
          message: 'missing',
        },
      }),
    ).toMatchObject({
      state: 'missing',
      sessionId: 'missing-session',
    });

    expect(
      toWarmSessionClaimFromStatusResult({
        sessionId: 'unavailable-session',
        status: {
          ok: false,
          code: 'worker_error',
          message: 'worker down',
        },
      }),
    ).toMatchObject({
      state: 'unavailable',
      sessionId: 'unavailable-session',
      code: 'worker_error',
    });
  });

  test('uses batch warm-session status reads when available', async () => {
    let batchCalls = 0;
    let singleReads = 0;
    const touchConfirm = normalizeWarmSessionReadPorts({
      getWarmSessionStatus: async () => {
        singleReads += 1;
        return { ok: false, code: 'worker_error', message: 'should not be called' };
      },
      getWarmSessionStatuses: async ({ sessionIds }) => {
        batchCalls += 1;
        return {
          results: sessionIds.map((sessionId) => ({
            sessionId,
            result:
              sessionId === 'warm-session'
                ? {
                    ok: true as const,
                    remainingUses: 2,
                    expiresAtMs: 999,
                  }
                : {
                    ok: false as const,
                    code: 'not_found',
                    message: 'missing',
                  },
          })),
        };
      },
    });
    const claims = await readWarmSessionClaims({
      touchConfirm,
      sessionIds: ['warm-session', 'missing-session'],
    });

    expect(batchCalls).toBe(1);
    expect(singleReads).toBe(0);
    expect(claims.get('warm-session')).toMatchObject({
      state: 'warm',
      sessionId: 'warm-session',
      remainingUses: 2,
    });
    expect(claims.get('missing-session')).toMatchObject({
      state: 'missing',
      sessionId: 'missing-session',
    });
  });

  test('resolves curve-owned auth material without cross-curve fallback', () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'auth.testnet',
      thresholdSessionId: 'ed-auth-session',
      thresholdSessionAuthToken: 'jwt:ed-auth-session',
    });
    const ecdsaRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'auth.testnet',
      chain: 'evm',
    });

    expect(resolveEd25519AuthMaterial(ed25519Record)).toMatchObject({
      capability: 'ed25519',
      thresholdSessionAuthToken: 'jwt:ed-auth-session',
      thresholdSessionAuthTokenSource: 'ed25519',
    });
    expect(resolveEcdsaAuthMaterial(ecdsaRecord)).toMatchObject({
      capability: 'ecdsa',
      thresholdSessionAuthToken: ecdsaRecord.thresholdSessionAuthToken,
      thresholdSessionAuthTokenSource: 'ecdsa',
    });
  });

  test('derives ready vs unavailable capability state from auth and claim state', () => {
    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'derive.testnet',
      thresholdSessionId: 'derive-ed25519-session',
      thresholdSessionAuthToken: 'jwt:derive-ed25519-session',
    });

    expect(
      deriveEd25519CapabilityState({
        record: ed25519Record,
        auth: resolveEd25519AuthMaterial(ed25519Record),
        prfClaim: {
          state: 'warm',
          sessionId: ed25519Record.thresholdSessionId,
          remainingUses: 4,
          expiresAtMs: ed25519Record.expiresAtMs,
        },
      }),
    ).toBe('ready');

    expect(
      deriveEd25519CapabilityState({
        record: ed25519Record,
        auth: resolveEd25519AuthMaterial(ed25519Record),
        prfClaim: {
          state: 'unavailable',
          sessionId: ed25519Record.thresholdSessionId,
          code: 'worker_error',
        },
      }),
    ).toBe('prf_unavailable');
  });

  test('derives ready cookie passkey Ed25519 state from record-backed client base', () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'cookie-record-backed.testnet',
      thresholdSessionId: 'cookie-record-backed-session',
      thresholdSessionKind: 'cookie',
      xClientBaseB64u: 'cookie-record-backed-client-base',
    });

    expect(
      deriveEd25519CapabilityState({
        record: ed25519Record,
        auth: resolveEd25519AuthMaterial(ed25519Record),
        prfClaim: {
          state: 'missing',
          sessionId: ed25519Record.thresholdSessionId,
        },
      }),
    ).toBe('ready');
  });

  test('resolves ECDSA seal transport from the stored capability record', () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ecdsaRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'seal-read-model.testnet',
      chain: 'evm',
      signingSessionSeal: {
        keyVersion: 'kek-s-2026-02',
        shamirPrimeB64u: 'AQAB',
      },
    });

    expect(
      resolveEcdsaSealTransport({
        record: ecdsaRecord,
        auth: resolveEcdsaAuthMaterial(ecdsaRecord),
        keyVersion: 'kek-s-2026-02',
        shamirPrimeB64u: 'AQAB',
      }),
    ).toMatchObject({
      curve: 'ecdsa',
      relayerUrl: ecdsaRecord.relayerUrl,
      thresholdSessionAuthToken: ecdsaRecord.thresholdSessionAuthToken,
      thresholdSessionAuthTokenSource: 'ecdsa',
      keyVersion: 'kek-s-2026-02',
      shamirPrimeB64u: 'AQAB',
    });
  });

  test('maps unavailable claims into unavailable signing-session status', () => {
    expect(
      toSigningSessionStatus({
        sessionId: 'status-unavailable-session',
        claim: {
          state: 'unavailable',
          sessionId: 'status-unavailable-session',
          code: 'worker_error',
        },
      }),
    ).toMatchObject({
      sessionId: 'status-unavailable-session',
      status: 'unavailable',
      statusCode: 'worker_error',
    });
  });
});
