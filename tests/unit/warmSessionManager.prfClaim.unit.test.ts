import { expect, test } from '@playwright/test';
import { createWarmSessionManager } from '@/core/signingEngine/session/WarmSessionManager';
import {
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionTouchConfirmFixture,
  resetWarmSessionFixtureState,
  seedEd25519WarmSessionRecord,
  seedEcdsaWarmSessionRecord,
} from './helpers/warmSessionManager.fixtures';

test.describe('WarmSessionManager PRF claim handling', () => {
  test('reports signing-session status for warm, missing, expired, exhausted, and unavailable claims', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const warmRecord = seedEd25519WarmSessionRecord({
      nearAccountId: 'warm-status.testnet',
      thresholdSessionId: 'warm-status-session',
      thresholdSessionJwt: 'jwt:warm-status-session',
    });
    const missingRecord = seedEd25519WarmSessionRecord({
      nearAccountId: 'missing-status.testnet',
      thresholdSessionId: 'missing-status-session',
      thresholdSessionJwt: 'jwt:missing-status-session',
    });
    const expiredRecord = seedEd25519WarmSessionRecord({
      nearAccountId: 'expired-status.testnet',
      thresholdSessionId: 'expired-status-session',
      thresholdSessionJwt: 'jwt:expired-status-session',
    });
    const exhaustedRecord = seedEd25519WarmSessionRecord({
      nearAccountId: 'exhausted-status.testnet',
      thresholdSessionId: 'exhausted-status-session',
      thresholdSessionJwt: 'jwt:exhausted-status-session',
    });
    const unavailableRecord = seedEd25519WarmSessionRecord({
      nearAccountId: 'unavailable-status.testnet',
      thresholdSessionId: 'unavailable-status-session',
      thresholdSessionJwt: 'jwt:unavailable-status-session',
    });

    const { touchConfirm } = createWarmSessionTouchConfirmFixture({
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

    const manager = createWarmSessionManager({ touchConfirm });

    await expect(
      manager.getEd25519SigningSessionStatus(warmRecord.nearAccountId),
    ).resolves.toMatchObject({
      sessionId: 'warm-status-session',
      status: 'active',
      remainingUses: 3,
    });
    await expect(
      manager.getEd25519SigningSessionStatus(missingRecord.nearAccountId),
    ).resolves.toMatchObject({
      sessionId: 'missing-status-session',
      status: 'not_found',
    });
    await expect(
      manager.getEd25519SigningSessionStatus(expiredRecord.nearAccountId),
    ).resolves.toMatchObject({
      sessionId: 'expired-status-session',
      status: 'expired',
    });
    await expect(
      manager.getEd25519SigningSessionStatus(exhaustedRecord.nearAccountId),
    ).resolves.toMatchObject({
      sessionId: 'exhausted-status-session',
      status: 'exhausted',
    });
    await expect(
      manager.getEd25519SigningSessionStatus(unavailableRecord.nearAccountId),
    ).resolves.toMatchObject({
      sessionId: 'unavailable-status-session',
      status: 'unavailable',
      statusCode: 'worker_error',
    });
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
        sessionJwt: 'jwt:consume-session',
      }),
    });

    const fixture = createWarmSessionTouchConfirmFixture({
      claimsBySessionId: {
        [record.thresholdSessionId]: {
          state: 'warm',
          remainingUses: 2,
          expiresAtMs: record.expiresAtMs || Date.now() + 120_000,
          prfFirstB64u: 'prf-first:consume-session',
        },
      },
    });
    const manager = createWarmSessionManager({
      touchConfirm: fixture.touchConfirm,
    });

    await expect(
      manager.claimPrfFirstByThresholdSessionId({
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
        sessionJwt: 'jwt:claim-only-session',
      }),
    });

    let claimCalls = 0;
    const manager = createWarmSessionManager({
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
      manager.claimPrfFirstByThresholdSessionId({
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
          sessionJwt: `jwt:${claimState}-session`,
        }),
      });

      const { touchConfirm } = createWarmSessionTouchConfirmFixture({
        claimsBySessionId: {
          [record.thresholdSessionId]: {
            state: claimState,
          },
        },
      });
      const manager = createWarmSessionManager({ touchConfirm });

      await expect(
        manager.claimPrfFirstByThresholdSessionId({
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
        sessionJwt: 'jwt:claim-unavailable-session',
      }),
    });

    const manager = createWarmSessionManager({
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
      manager.claimPrfFirstByThresholdSessionId({
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
        sessionJwt: 'jwt:claim-diagnostic-session',
      }),
    });

    let statusReads = 0;
    const manager = createWarmSessionManager({
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
      manager.claimPrfFirstByThresholdSessionId({
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
        sessionJwt: 'jwt:seal-session',
        relayerUrl: 'https://relay.seal.example',
      }),
    });

    const fixture = createWarmSessionTouchConfirmFixture({
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
    const manager = createWarmSessionManager({
      touchConfirm: fixture.touchConfirm,
    });

    await expect(
      manager.ensureEcdsaPrfSealPersistedByThresholdSessionId({
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
        thresholdSessionJwt: 'jwt:seal-session',
      },
    });
  });
});
