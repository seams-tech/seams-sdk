import { expect, test } from '@playwright/test';
import {
  claimWarmSessionPrfFirst,
  ensureEcdsaPrfSealPersisted,
} from '@/core/signingEngine/session/warmSigning/runtime';
import {
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionTouchConfirmFixture,
  resetWarmSessionFixtureState,
  seedEcdsaWarmSessionRecord,
} from './helpers/warmSessionStore.fixtures';

test.describe('warmSessionRuntime', () => {
  test('claims warm PRF material without a preparatory status read', async () => {
    let claimCalls = 0;
    const prfFirst = await claimWarmSessionPrfFirst({
      touchConfirm: {
        claimWarmSessionMaterial: async ({ sessionId }) => {
          claimCalls += 1;
          expect(sessionId).toBe('claim-only-session');
          return {
            ok: true as const,
            prfFirstB64u: 'prf-first:claim-only-session',
            remainingUses: 2,
            expiresAtMs: Date.now() + 120_000,
          };
        },
      },
      thresholdSessionId: 'claim-only-session',
      errorContext: 'threshold-ecdsa authorization bootstrap',
    });

    expect(prfFirst).toBe('prf-first:claim-only-session');
    expect(claimCalls).toBe(1);
  });

  for (const code of ['not_found', 'expired', 'exhausted'] as const) {
    test(`normalizes ${code} claim failures into missing warm PRF errors`, async () => {
      await expect(
        claimWarmSessionPrfFirst({
          touchConfirm: {
            claimWarmSessionMaterial: async () => ({
              ok: false,
              code,
              message: code,
            }),
          },
          thresholdSessionId: `${code}-session`,
          errorContext: 'threshold-ecdsa explicit export',
        }),
      ).rejects.toThrow(
        `Missing warm PRF material for threshold-ecdsa explicit export (${code === 'not_found' ? 'missing' : code})`,
      );
    });
  }

  test('surfaces unavailable claim failures without downgrading them to missing', async () => {
    await expect(
      claimWarmSessionPrfFirst({
        touchConfirm: {
          claimWarmSessionMaterial: async () => ({
            ok: false,
            code: 'worker_error',
            message: 'worker down',
          }),
        },
        thresholdSessionId: 'claim-unavailable-session',
        errorContext: 'threshold-ecdsa explicit export',
      }),
    ).rejects.toThrow(
      'Warm-session claim unavailable for threshold-ecdsa explicit export (worker_error)',
    );
  });

  test('uses one diagnostic status read only when claim returns an invalid empty success payload', async () => {
    let statusReads = 0;
    await expect(
      claimWarmSessionPrfFirst({
        touchConfirm: {
          claimWarmSessionMaterial: async () =>
            ({
              ok: true,
              prfFirstB64u: '',
              remainingUses: 1,
              expiresAtMs: Date.now() + 60_000,
            }) as any,
          getWarmSessionStatus: async () => {
            statusReads += 1;
            return {
              ok: false as const,
              code: 'expired',
              message: 'expired',
            };
          },
        },
        thresholdSessionId: 'claim-diagnostic-session',
        errorContext: 'threshold-ecdsa authorization bootstrap',
      }),
    ).rejects.toThrow(
      'Missing warm PRF material for threshold-ecdsa authorization bootstrap (expired)',
    );
    expect(statusReads).toBe(1);
  });

  test('passes full ECDSA seal transport when persisting a warm-session seal', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const evmRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'seal-persist.testnet',
      chain: 'evm',
      signingSessionSeal: {
        keyVersion: 'kek-s-2026-02',
        shamirPrimeB64u: 'AQAB',
      },
    });
    const touchConfirmFixture = createWarmSessionTouchConfirmFixture({
      claimsBySessionId: {
        [evmRecord.thresholdSessionId]: {
          state: 'warm',
          remainingUses: evmRecord.remainingUses || 5,
          expiresAtMs: evmRecord.expiresAtMs || Date.now() + 120_000,
        },
      },
      sealAndPersistResultBySessionId: {
        [evmRecord.thresholdSessionId]: {
          ok: true,
          sealedSecretB64u: 'sealed-prf-first',
          keyVersion: 'kek-s-2026-02',
          remainingUses: evmRecord.remainingUses || 5,
          expiresAtMs: evmRecord.expiresAtMs || Date.now() + 120_000,
        },
      },
    });

    await ensureEcdsaPrfSealPersisted({
      touchConfirm: touchConfirmFixture.touchConfirm,
      thresholdSessionId: evmRecord.thresholdSessionId,
      required: true,
      errorContext: 'test ECDSA seal persistence',
      sealPersistInFlightBySessionId: new Map(),
      resolveSealTransport: () => ({
        curve: 'ecdsa',
        relayerUrl: evmRecord.relayerUrl,
        thresholdSessionJwt: evmRecord.thresholdSessionJwt,
        thresholdSessionJwtSource: 'ecdsa',
        keyVersion: 'kek-s-2026-02',
        shamirPrimeB64u: 'AQAB',
      }),
    });

    expect(touchConfirmFixture.sealCalls).toHaveLength(1);
    expect(touchConfirmFixture.sealCalls[0]).toMatchObject({
      sessionId: evmRecord.thresholdSessionId,
      transport: {
        relayerUrl: evmRecord.relayerUrl,
        thresholdSessionJwt: evmRecord.thresholdSessionJwt,
        keyVersion: 'kek-s-2026-02',
        shamirPrimeB64u: 'AQAB',
      },
    });
  });

  test('surfaces required seal persistence failures with code and message intact', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'seal-error.testnet',
      chain: 'evm',
      source: 'manual-bootstrap',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'seal-error.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-seal-error',
        sessionId: 'seal-error-session',
        sessionJwt: 'jwt:seal-error-session',
        relayerUrl: 'https://relay.seal-error.example',
      }),
    });

    const fixture = createWarmSessionTouchConfirmFixture({
      claimsBySessionId: {
        [record.thresholdSessionId]: {
          state: 'warm',
          remainingUses: 2,
          expiresAtMs: record.expiresAtMs || Date.now() + 120_000,
        },
      },
      sealAndPersistResultBySessionId: {
        [record.thresholdSessionId]: {
          ok: false,
          code: 'transport_error',
          message: 'relay offline',
        },
      },
    });

    await expect(
      ensureEcdsaPrfSealPersisted({
        touchConfirm: fixture.touchConfirm,
        thresholdSessionId: record.thresholdSessionId,
        required: true,
        errorContext: 'threshold-ecdsa signing seal persistence',
        sealPersistInFlightBySessionId: new Map(),
        resolveSealTransport: () => ({
          curve: 'ecdsa',
          relayerUrl: 'https://relay.seal-error.example',
          thresholdSessionJwt: 'jwt:seal-error-session',
          thresholdSessionJwtSource: 'ecdsa',
        }),
      }),
    ).rejects.toThrow(
      '[WarmSessionStore] threshold-ecdsa signing seal persistence failed (transport_error): relay offline',
    );
  });
});
