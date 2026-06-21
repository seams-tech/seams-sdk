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
import { parseSigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';

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
      thresholdSessionId: 'ed-wallet-session',
      walletSessionJwt: 'jwt:ed-wallet-session',
    });
    const ecdsaRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'auth.testnet',
      chain: 'evm',
    });

    expect(resolveEd25519AuthMaterial(ed25519Record)).toMatchObject({
      capability: 'ed25519',
      walletSessionJwt: ed25519Record.walletSessionJwt,
      walletSessionJwtSource: 'ed25519_record',
    });
    expect(resolveEcdsaAuthMaterial(ecdsaRecord)).toMatchObject({
      capability: 'ecdsa',
      walletSessionJwt: ecdsaRecord.walletSessionJwt,
      walletSessionJwtSource: 'ecdsa_record',
    });
  });

  test('derives ready vs unavailable capability state from auth and claim state', () => {
    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'derive.testnet',
      thresholdSessionId: 'derive-ed25519-session',
      walletSessionJwt: 'jwt:derive-ed25519-session',
      runtimeValidated: true,
    });
    const unvalidatedRecord = seedEd25519WarmSessionRecord({
      nearAccountId: 'derive-unavailable.testnet',
      thresholdSessionId: 'derive-unavailable-ed25519-session',
      walletSessionJwt: 'jwt:derive-unavailable-ed25519-session',
      ed25519WorkerMaterialHandle: '',
      ed25519WorkerMaterialBindingDigest: '',
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
        record: unvalidatedRecord,
        auth: resolveEd25519AuthMaterial(unvalidatedRecord),
        prfClaim: {
          state: 'unavailable',
          sessionId: unvalidatedRecord.thresholdSessionId,
          code: 'worker_error',
        },
      }),
    ).toBe('prf_unavailable');
  });

  test('derives material_pending for restored Ed25519 records without worker handle', () => {
    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'pending-material.testnet',
      thresholdSessionId: 'pending-material-session',
      walletSessionJwt: 'jwt:pending-material-session',
      clientVerifyingShareB64u: 'restored-client-verifier',
      ed25519WorkerMaterialHandle: '',
      ed25519WorkerMaterialBindingDigest: '',
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
    ).toBe('material_pending');
  });

  test('derives invalid for Ed25519 records missing Router A/B state', () => {
    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'missing-router-ab-ed25519.testnet',
      thresholdSessionId: 'missing-router-ab-ed25519-session',
      walletSessionJwt: 'jwt:missing-router-ab-ed25519-session',
    });
    delete ed25519Record.routerAbNormalSigning;

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
    ).toBe('invalid');
  });

  test('derives auth_missing for cookie passkey Ed25519 state without Wallet Session auth', () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'cookie-record-backed.testnet',
      thresholdSessionId: 'cookie-record-backed-session',
      thresholdSessionKind: 'cookie',
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
    ).toBe('auth_missing');
  });

  test('derives auth_missing for ECDSA cookie or missing Wallet Session JWT records', () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const currentRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'cookie-ecdsa.testnet',
      chain: 'evm',
    });
    const cookieRecord = {
      ...currentRecord,
      thresholdSessionKind: 'cookie' as const,
      walletSessionJwt: '',
    };
    const cookieAuth = resolveEcdsaAuthMaterial(cookieRecord);

    expect(cookieAuth).toMatchObject({
      capability: 'ecdsa',
      state: 'unavailable',
      walletSessionJwtSource: 'none',
      unavailableReason: 'cookie_session',
    });
    expect(
      deriveEcdsaCapabilityState({
        record: cookieRecord,
        auth: cookieAuth,
        prfClaim: {
          state: 'warm',
          sessionId: cookieRecord.thresholdSessionId,
          remainingUses: 4,
          expiresAtMs: cookieRecord.expiresAtMs,
        },
      }),
    ).toBe('auth_missing');

    const jwtRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'missing-jwt-ecdsa.testnet',
      chain: 'tempo',
    });
    const missingJwtRecord = {
      ...jwtRecord,
      walletSessionJwt: '',
    };
    const missingJwtAuth = resolveEcdsaAuthMaterial(missingJwtRecord);

    expect(missingJwtAuth).toMatchObject({
      capability: 'ecdsa',
      state: 'unavailable',
      walletSessionJwtSource: 'none',
      unavailableReason: 'missing_wallet_session_jwt',
    });
    expect(
      deriveEcdsaCapabilityState({
        record: missingJwtRecord,
        auth: missingJwtAuth,
        prfClaim: {
          state: 'warm',
          sessionId: missingJwtRecord.thresholdSessionId,
          remainingUses: 4,
          expiresAtMs: missingJwtRecord.expiresAtMs,
        },
      }),
    ).toBe('auth_missing');
  });

  test('does not derive ready for ECDSA records missing Router A/B state', () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ecdsaRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'missing-router-ab-ecdsa.testnet',
      chain: 'evm',
    });
    delete ecdsaRecord.routerAbEcdsaHssNormalSigning;

    expect(
      deriveEcdsaCapabilityState({
        record: ecdsaRecord,
        auth: resolveEcdsaAuthMaterial(ecdsaRecord),
        prfClaim: {
          state: 'warm',
          sessionId: ecdsaRecord.thresholdSessionId,
          remainingUses: 4,
          expiresAtMs: ecdsaRecord.expiresAtMs,
        },
      }),
    ).toBe('material_pending');
  });

  test('resolves ECDSA seal transport from the stored capability record', () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ecdsaRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'seal-read-model.testnet',
      chain: 'evm',
      signingSessionSeal: {
        keyVersion: 'signing-session-seal-kek-2026-02-r1',
        shamirPrimeB64u: 'AQAB',
      },
    });

    expect(
      resolveEcdsaSealTransport({
        record: ecdsaRecord,
        auth: resolveEcdsaAuthMaterial(ecdsaRecord),
        signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(
          'signing-session-seal-kek-2026-02-r1',
        ),
        shamirPrimeB64u: 'AQAB',
      }),
    ).toMatchObject({
      curve: 'ecdsa',
      relayerUrl: ecdsaRecord.relayerUrl,
      walletSessionJwt: ecdsaRecord.walletSessionJwt,
      walletSessionJwtSource: 'ecdsa',
      signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(
        'signing-session-seal-kek-2026-02-r1',
      ),
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
