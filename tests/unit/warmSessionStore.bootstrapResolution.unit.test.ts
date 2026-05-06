import { expect, test } from '@playwright/test';
import {
  createWarmSessionTestServices,
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionStatusReader,
  resetWarmSessionFixtureState,
  seedEd25519WarmSessionRecord,
  seedEcdsaWarmSessionRecord,
} from './helpers/warmSessionStore.fixtures';

test.describe('WarmSessionStore ECDSA bootstrap resolution', () => {
  test('uses explicit ECDSA ownership and does not borrow Ed25519 auth', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    seedEd25519WarmSessionRecord({
      nearAccountId: 'fallback.testnet',
      thresholdSessionId: 'sess-ed25519',
      thresholdSessionAuthToken: 'jwt-ed25519-fallback',
    });

    const fallbackEcdsaRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'fallback.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'fallback.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-fallback',
        sessionId: 'sess-ecdsa-cookie',
        sessionKind: 'cookie',
      }),
    });

    const primaryEcdsaRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'primary.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'primary.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-primary',
        sessionId: 'sess-ecdsa-jwt',
        sessionAuthToken: 'jwt-ecdsa-primary',
        sessionKind: 'jwt',
      }),
    });

    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionStatusReader({
        [fallbackEcdsaRecord.thresholdSessionId]: {
          state: 'warm',
          remainingUses: fallbackEcdsaRecord.remainingUses || 5,
          expiresAtMs: fallbackEcdsaRecord.expiresAtMs || Date.now() + 120_000,
        },
        [primaryEcdsaRecord.thresholdSessionId]: {
          state: 'warm',
          remainingUses: primaryEcdsaRecord.remainingUses || 5,
          expiresAtMs: primaryEcdsaRecord.expiresAtMs || Date.now() + 120_000,
        },
      }),
    });
    const fallbackBootstrap = await store.resolveEcdsaBootstrapRequest({
      nearAccountId: 'fallback.testnet',
      chain: 'evm',
    });
    const primaryBootstrap = await store.resolveEcdsaBootstrapRequest({
      nearAccountId: 'primary.testnet',
      chain: 'evm',
    });

    expect(fallbackBootstrap).toMatchObject({
      nearAccountId: 'fallback.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-fallback',
      participantIds: [1, 2],
      sessionKind: 'cookie',
      sessionId: 'sess-ecdsa-cookie',
    });
    expect('thresholdSessionAuth' in fallbackBootstrap).toBe(false);

    expect(primaryBootstrap).toMatchObject({
      nearAccountId: 'primary.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-primary',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'sess-ecdsa-jwt',
      thresholdSessionAuth: {
        kind: 'threshold_session',
        jwt: 'jwt-ecdsa-primary',
      },
    });
  });
});
