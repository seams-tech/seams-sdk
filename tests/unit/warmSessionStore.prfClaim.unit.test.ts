import { expect, test } from '@playwright/test';
import {
  createWarmSessionTestServices,
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionUiConfirmFixture,
  resetWarmSessionFixtureState,
  seedEd25519WarmSessionRecord,
  seedEcdsaWarmSessionRecord,
} from './helpers/warmSessionStore.fixtures';
import {
  clearRouterAbEd25519WorkerMaterialRuntimeValidation,
  markRouterAbEd25519WorkerMaterialRuntimeValidated,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';

test.describe('WarmSessionStore PRF claim handling', () => {
  test('reports signing-session status for warm, missing, expired, exhausted, and unavailable claims', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const warmRecord = seedEd25519WarmSessionRecord({
      nearAccountId: 'warm-status.testnet',
      thresholdSessionId: 'warm-status-session',
      walletSessionJwt: 'jwt:warm-status-session',
    });
    const missingRecord = seedEd25519WarmSessionRecord({
      nearAccountId: 'missing-status.testnet',
      thresholdSessionId: 'missing-status-session',
      walletSessionJwt: 'jwt:missing-status-session',
      ed25519WorkerMaterialHandle: '',
      ed25519WorkerMaterialBindingDigest: '',
      clientVerifyingShareB64u: '',
    });
    const expiredRecord = seedEd25519WarmSessionRecord({
      nearAccountId: 'expired-status.testnet',
      thresholdSessionId: 'expired-status-session',
      walletSessionJwt: 'jwt:expired-status-session',
    });
    const exhaustedRecord = seedEd25519WarmSessionRecord({
      nearAccountId: 'exhausted-status.testnet',
      thresholdSessionId: 'exhausted-status-session',
      walletSessionJwt: 'jwt:exhausted-status-session',
    });
    const unavailableRecord = seedEd25519WarmSessionRecord({
      nearAccountId: 'unavailable-status.testnet',
      thresholdSessionId: 'unavailable-status-session',
      walletSessionJwt: 'jwt:unavailable-status-session',
    });

    const { touchConfirm } = createWarmSessionUiConfirmFixture({
      claimsBySessionId: {
        [warmRecord.thresholdSessionId]: {
          state: 'warm',
          remainingUses: 3,
          expiresAtMs: warmRecord.expiresAtMs,
        },
        [missingRecord.thresholdSessionId]: {
          state: 'missing',
        },
        [expiredRecord.thresholdSessionId]: {
          state: 'expired',
        },
        [exhaustedRecord.thresholdSessionId]: {
          state: 'exhausted',
        },
        [unavailableRecord.thresholdSessionId]: {
          state: 'unavailable',
          code: 'worker_error',
          message: 'worker down',
        },
      },
    });

    const store = createWarmSessionTestServices({ touchConfirm });

    await expect(
      store.getEd25519SigningSessionStatus(warmRecord.nearAccountId),
    ).resolves.toMatchObject({
      sessionId: 'warm-status-session',
      status: 'active',
      remainingUses: 3,
    });
    await expect(
      store.getEd25519SigningSessionStatus(missingRecord.nearAccountId),
    ).resolves.toMatchObject({
      sessionId: 'missing-status-session',
      status: 'not_found',
    });
    await expect(
      store.getEd25519SigningSessionStatus(expiredRecord.nearAccountId),
    ).resolves.toMatchObject({
      sessionId: 'expired-status-session',
      status: 'expired',
    });
    await expect(
      store.getEd25519SigningSessionStatus(exhaustedRecord.nearAccountId),
    ).resolves.toMatchObject({
      sessionId: 'exhausted-status-session',
      status: 'exhausted',
    });
    await expect(
      store.getEd25519SigningSessionStatus(unavailableRecord.nearAccountId),
    ).resolves.toMatchObject({
      sessionId: 'unavailable-status-session',
      status: 'unavailable',
      statusCode: 'worker_error',
    });
  });

  test('does not report cookie passkey Ed25519 records as Router A/B signing status', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const expiresAtMs = Date.now() + 120_000;
    const record = seedEd25519WarmSessionRecord({
      nearAccountId: 'cookie-status.testnet',
      thresholdSessionId: 'cookie-status-session',
      thresholdSessionKind: 'cookie',
      remainingUses: 4,
      expiresAtMs,
    });

    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionUiConfirmFixture({
        claimsBySessionId: {
          [record.thresholdSessionId]: {
            state: 'missing',
          },
        },
      }).touchConfirm,
    });

    await expect(store.getEd25519SigningSessionStatus(record.nearAccountId)).resolves.toMatchObject(
      {
        sessionId: 'cookie-status-session',
        status: 'not_found',
        authMethod: 'passkey',
      },
    );
  });

  test('treats persisted Ed25519 material handles as hints until runtime validation', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    clearRouterAbEd25519WorkerMaterialRuntimeValidation();

    const record = seedEd25519WarmSessionRecord({
      nearAccountId: 'material-hint-status.testnet',
      thresholdSessionId: 'material-hint-status-session',
      walletSessionJwt: 'jwt:material-hint-status-session',
      remainingUses: 4,
      expiresAtMs: Date.now() + 120_000,
    });
    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionUiConfirmFixture({
        claimsBySessionId: {
          [record.thresholdSessionId]: {
            state: 'missing',
          },
        },
      }).touchConfirm,
    });

    try {
      await expect(
        store.getEd25519SigningSessionStatus(record.nearAccountId),
      ).resolves.toMatchObject({
        sessionId: 'material-hint-status-session',
        status: 'not_found',
      });

      expect(markRouterAbEd25519WorkerMaterialRuntimeValidated(record)).toBe(true);
      await expect(
        store.getEd25519SigningSessionStatus(record.nearAccountId),
      ).resolves.toMatchObject({
        sessionId: 'material-hint-status-session',
        status: 'active',
        remainingUses: 4,
      });
    } finally {
      clearRouterAbEd25519WorkerMaterialRuntimeValidation();
    }
  });

  test('claims warm PRF material and returns it', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'consume.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'consume.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-consume',
        sessionId: 'consume-session',
        walletSessionJwt: 'jwt:consume-session',
      }),
    });

    const fixture = createWarmSessionUiConfirmFixture({
      claimsBySessionId: {
        [record.thresholdSessionId]: {
          state: 'warm',
          remainingUses: 2,
          expiresAtMs: record.expiresAtMs || Date.now() + 120_000,
          prfFirstB64u: 'prf-first:consume-session',
        },
      },
    });
    const store = createWarmSessionTestServices({
      touchConfirm: fixture.touchConfirm,
    });

    await expect(
      store.claimWarmSessionPrfFirstMaterial({
        thresholdSessionId: record.thresholdSessionId,
        errorContext: 'threshold-ecdsa authorization bootstrap',
      }),
    ).resolves.toBe('prf-first:consume-session');
    expect(fixture.claimsBySessionId[record.thresholdSessionId]).toMatchObject({
      state: 'warm',
      remainingUses: 1,
    });
  });

  test('claims warm PRF material without requiring a preparatory status read', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'claim-only.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'claim-only.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-claim-only',
        sessionId: 'claim-only-session',
        walletSessionJwt: 'jwt:claim-only-session',
      }),
    });

    let claimCalls = 0;
    const store = createWarmSessionTestServices({
      touchConfirm: {
        claimWarmSessionMaterial: async ({ sessionId }) => {
          claimCalls += 1;
          expect(sessionId).toBe(record.thresholdSessionId);
          return {
            ok: true as const,
            prfFirstB64u: 'prf-first:claim-only-session',
            remainingUses: 2,
            expiresAtMs: Date.now() + 120_000,
          };
        },
      },
    });

    await expect(
      store.claimWarmSessionPrfFirstMaterial({
        thresholdSessionId: record.thresholdSessionId,
        errorContext: 'threshold-ecdsa authorization bootstrap',
      }),
    ).resolves.toBe('prf-first:claim-only-session');
    expect(claimCalls).toBe(1);
  });

  for (const claimState of ['missing', 'expired', 'exhausted'] as const) {
    test(`normalizes ${claimState} claim failures during consumption`, async () => {
      const ecdsaStore = createThresholdEcdsaStoreFixture();
      resetWarmSessionFixtureState(ecdsaStore);

      const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
        nearAccountId: `${claimState}.testnet`,
        chain: 'evm',
        source: 'login',
        bootstrap: createThresholdEcdsaBootstrapFixture({
          nearAccountId: `${claimState}.testnet`,
          chain: 'evm',
          ecdsaThresholdKeyId: `ek-${claimState}`,
          sessionId: `${claimState}-session`,
          walletSessionJwt: `jwt:${claimState}-session`,
        }),
      });

      const { touchConfirm } = createWarmSessionUiConfirmFixture({
        claimsBySessionId: {
          [record.thresholdSessionId]: {
            state: claimState,
          },
        },
      });
      const store = createWarmSessionTestServices({ touchConfirm });

      await expect(
        store.claimWarmSessionPrfFirstMaterial({
          thresholdSessionId: record.thresholdSessionId,
          errorContext: 'threshold-ecdsa explicit export',
        }),
      ).rejects.toThrow(
        `Missing warm PRF material for threshold-ecdsa explicit export (${claimState === 'missing' ? 'missing' : claimState})`,
      );
    });
  }

  test('surfaces claim_unavailable errors without describing them as missing PRF material', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'claim-unavailable.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'claim-unavailable.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-claim-unavailable',
        sessionId: 'claim-unavailable-session',
        walletSessionJwt: 'jwt:claim-unavailable-session',
      }),
    });

    const store = createWarmSessionTestServices({
      touchConfirm: {
        claimWarmSessionMaterial: async () =>
          ({
            ok: false,
            code: 'worker_error',
            message: 'worker down',
          }) as const,
      },
    });

    await expect(
      store.claimWarmSessionPrfFirstMaterial({
        thresholdSessionId: record.thresholdSessionId,
        errorContext: 'threshold-ecdsa explicit export',
      }),
    ).rejects.toThrow(
      'Warm-session claim unavailable for threshold-ecdsa explicit export (worker_error)',
    );
  });

  test('uses one diagnostic status read only when claim returns an invalid empty success payload', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'claim-diagnostic.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'claim-diagnostic.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-claim-diagnostic',
        sessionId: 'claim-diagnostic-session',
        walletSessionJwt: 'jwt:claim-diagnostic-session',
      }),
    });

    let statusReads = 0;
    const store = createWarmSessionTestServices({
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
    });

    await expect(
      store.claimWarmSessionPrfFirstMaterial({
        thresholdSessionId: record.thresholdSessionId,
        errorContext: 'threshold-ecdsa authorization bootstrap',
      }),
    ).rejects.toThrow(
      'Missing warm PRF material for threshold-ecdsa authorization bootstrap (expired)',
    );
    expect(statusReads).toBe(1);
  });

  test('persists a signing-session seal using the resolved warm-session transport auth', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'seal.testnet',
      chain: 'evm',
      source: 'manual-bootstrap',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'seal.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-seal',
        sessionId: 'seal-session',
        walletSessionJwt: 'jwt:seal-session',
        relayerUrl: 'https://relay.seal.example',
      }),
    });

    const fixture = createWarmSessionUiConfirmFixture({
      claimsBySessionId: {
        [record.thresholdSessionId]: {
          state: 'warm',
          remainingUses: 4,
          expiresAtMs: record.expiresAtMs || Date.now() + 120_000,
        },
      },
      sealAndPersistResultBySessionId: {
        [record.thresholdSessionId]: {
          ok: true,
          sealedSecretB64u: 'sealed-prf-first',
          remainingUses: 4,
          expiresAtMs: record.expiresAtMs || Date.now() + 120_000,
        },
      },
    });
    const store = createWarmSessionTestServices({
      touchConfirm: fixture.touchConfirm,
    });

    await expect(
      store.ensureEcdsaPrfSealPersistedByThresholdSessionId({
        chain: 'evm',
        thresholdSessionId: record.thresholdSessionId,
        required: true,
        errorContext: 'threshold session seal persistence',
      }),
    ).resolves.toBeUndefined();

    expect(fixture.sealCalls).toHaveLength(1);
    expect(fixture.sealCalls[0]).toMatchObject({
      sessionId: 'seal-session',
      transport: {
        relayerUrl: 'https://relay.seal.example',
        walletSessionJwt: record.walletSessionJwt,
      },
    });
  });
});
