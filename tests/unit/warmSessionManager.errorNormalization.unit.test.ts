import { expect, test } from '@playwright/test';
import {
  createWarmSessionManager,
  THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR,
  THRESHOLD_SESSION_EXHAUSTED_ERROR,
  THRESHOLD_SESSION_STATUS_UNAVAILABLE_ERROR,
} from '@/core/signingEngine/session/WarmSessionManager';
import {
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionTouchConfirmFixture,
  resetWarmSessionFixtureState,
  seedEd25519WarmSessionRecord,
  seedEcdsaWarmSessionRecord,
} from './helpers/warmSessionManager.fixtures';

test.describe('WarmSessionManager caller-facing error normalization', () => {
  test('normalizes missing warm PRF material for explicit threshold-ecdsa authorization bootstrap', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'bootstrap-error.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'bootstrap-error.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-bootstrap-error',
        sessionId: 'bootstrap-error-session',
        sessionJwt: 'jwt:bootstrap-error-session',
      }),
    });

    let provisionCalls = 0;
    const { touchConfirm } = createWarmSessionTouchConfirmFixture({
      claimsBySessionId: {
        [record.thresholdSessionId]: {
          state: 'missing',
        },
      },
    });
    const manager = createWarmSessionManager({
      touchConfirm,
      provisionThresholdEcdsaSession: async () => {
        provisionCalls += 1;
        throw new Error('provisionThresholdEcdsaSession should not be called when warm PRF is absent');
      },
    });

    await expect(
      manager.provisionEcdsaCapability({
        nearAccountId: 'bootstrap-error.testnet',
        chain: 'evm',
        source: 'manual-bootstrap',
        sessionId: record.thresholdSessionId,
        authorizationJwt: 'jwt:bootstrap-error-session',
      }),
    ).rejects.toThrow(
      'Missing warm PRF material for threshold-ecdsa authorization bootstrap (missing)',
    );
    expect(provisionCalls).toBe(0);
  });

  test('normalizes reconnect failure when the refreshed warm capability is still not ready', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const staleBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'reconnect-error.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-reconnect-error',
      sessionId: 'reconnect-error-stale-session',
      sessionJwt: 'jwt:reconnect-error-stale-session',
    });
    const staleRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'reconnect-error.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: staleBootstrap,
    });

    const fixture = createWarmSessionTouchConfirmFixture({
      claimsBySessionId: {
        [staleRecord.thresholdSessionId]: {
          state: 'missing',
        },
      },
    });
    const manager = createWarmSessionManager({
      touchConfirm: fixture.touchConfirm,
      getThresholdEcdsaKeyRefForSigning: () => staleBootstrap.thresholdEcdsaKeyRef,
      provisionThresholdEcdsaSession: async ({ nearAccountId, chain }) => {
        return createThresholdEcdsaBootstrapFixture({
          nearAccountId: String(nearAccountId),
          chain,
          ecdsaThresholdKeyId: 'ek-reconnect-error',
          sessionId: 'reconnect-error-fresh-session',
          sessionJwt: 'jwt:reconnect-error-fresh-session',
        });
      },
    });

    await expect(
      manager.ensureEcdsaCapabilityReady({
        nearAccountId: 'reconnect-error.testnet',
        chain: 'evm',
        usesNeeded: 1,
      }),
    ).rejects.toThrow(
      '[WarmSessionManager] provisioned ECDSA capability was not persisted for reconnect-error.testnet (expected sessionId=reconnect-error-fresh-session, found=reconnect-error-stale-session)',
    );
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
    const manager = createWarmSessionManager({
      touchConfirm: fixture.touchConfirm,
    });

    await expect(
      manager.ensureEcdsaPrfSealPersistedByThresholdSessionId({
        chain: 'evm',
        thresholdSessionId: record.thresholdSessionId,
        required: true,
        errorContext: 'threshold-ecdsa signing seal persistence',
      }),
    ).rejects.toThrow(
      '[WarmSessionManager] threshold-ecdsa signing seal persistence failed (transport_error): relay offline',
    );
  });

  test('normalizes exhausted signing-session readiness through the manager boundary', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'signing-exhausted.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'signing-exhausted.testnet',
        chain: 'evm',
        sessionId: 'signing-exhausted-session',
        sessionJwt: 'jwt:signing-exhausted-session',
      }),
    });

    const manager = createWarmSessionManager({
      touchConfirm: {
        getWarmSessionStatus: async () => ({
          ok: true,
          remainingUses: 1,
          expiresAtMs: Date.now() + 60_000,
        }),
      },
    });

    await expect(
      manager.assertEcdsaSigningSessionReady({
        nearAccountId: 'signing-exhausted.testnet',
        chain: 'evm',
        thresholdSessionId: 'signing-exhausted-session',
        usesNeeded: 2,
      }),
    ).rejects.toThrow(THRESHOLD_SESSION_EXHAUSTED_ERROR);
  });

  test('normalizes Ed25519 auth-unavailable signing plans through the manager boundary', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const manager = createWarmSessionManager({
      touchConfirm: {
        getWarmSessionStatus: async () => ({
          ok: false,
          code: 'not_found',
          message: 'missing',
        }),
      },
    });

    await expect(
      manager.resolveEd25519SigningAuthPlan({
        nearAccountId: 'auth-unavailable.testnet',
        usesNeeded: 1,
      }),
    ).rejects.toThrow(THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR);
  });

  test('fails closed when Ed25519 signing-session status is unavailable', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    seedEd25519WarmSessionRecord({
      nearAccountId: 'status-unavailable.testnet',
      thresholdSessionId: 'status-unavailable-session',
      thresholdSessionJwt: 'jwt:status-unavailable-session',
    });

    const manager = createWarmSessionManager({
      touchConfirm: {
        getWarmSessionStatus: async () => ({
          ok: false,
          code: 'worker_error',
          message: 'worker down',
        }),
      },
    });

    await expect(
      manager.resolveEd25519SigningAuthPlan({
        nearAccountId: 'status-unavailable.testnet',
        usesNeeded: 1,
      }),
    ).rejects.toThrow(`${THRESHOLD_SESSION_STATUS_UNAVAILABLE_ERROR} (worker_error)`);
  });
});
