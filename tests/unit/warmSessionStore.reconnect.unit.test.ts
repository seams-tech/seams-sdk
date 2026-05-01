import { expect, test } from '@playwright/test';
import {
  createWarmSessionTestServices,
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionTouchConfirmFixture,
  resetWarmSessionFixtureState,
  seedEcdsaWarmSessionRecord,
} from './helpers/warmSessionStore.fixtures';

test.describe('WarmSessionStore ECDSA reconnect and reuse', () => {
  test('reuses a matching ready ECDSA capability without reconnecting', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const bootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'reuse-ready.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-reuse-ready',
      sessionId: 'reuse-ready-session',
      sessionJwt: 'jwt:reuse-ready-session',
    });
    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'reuse-ready.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap,
    });
    const fixture = createWarmSessionTouchConfirmFixture({
      claimsBySessionId: {
        [record.thresholdSessionId]: {
          state: 'warm',
          remainingUses: 3,
          expiresAtMs: record.expiresAtMs || Date.now() + 120_000,
        },
      },
    });

    let provisionCalls = 0;
    const store = createWarmSessionTestServices({
      touchConfirm: fixture.touchConfirm,
      listThresholdEcdsaKeyRefsForLookup: () => [
        { source: 'login', keyRef: bootstrap.thresholdEcdsaKeyRef },
      ],
      provisionThresholdEcdsaSession: async () => {
        provisionCalls += 1;
        throw new Error('provisionThresholdEcdsaSession should not be called for ready reuse');
      },
    });

    const ready = await store.ensureEcdsaCapabilityReady({
      nearAccountId: 'reuse-ready.testnet',
      chain: 'evm',
      usesNeeded: 2,
      sessionBudgetUses: 2,
    });

    expect(provisionCalls).toBe(0);
    expect(ready.reconnected).toBe(false);
    expect(ready.keyRef).toMatchObject({
      ecdsaThresholdKeyId: 'ek-reuse-ready',
      thresholdSessionId: 'reuse-ready-session',
    });
    expect(ready.capability).toMatchObject({
      state: 'ready',
      chain: 'evm',
    });
    expect(ready.capability.prfClaim).toMatchObject({
      state: 'warm',
      remainingUses: 3,
    });
  });

  test('reconnects ECDSA capability when the stored claim state is no longer warm', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const staleBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'reconnect.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-reconnect',
      sessionId: 'stale-evm-session',
      sessionJwt: 'jwt:stale-evm-session',
    });
    const staleRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'reconnect.testnet',
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

    let provisionCalls = 0;
    const store = createWarmSessionTestServices({
      touchConfirm: fixture.touchConfirm,
      listThresholdEcdsaKeyRefsForLookup: () => [
        { source: 'login', keyRef: staleBootstrap.thresholdEcdsaKeyRef },
      ],
      provisionThresholdEcdsaSession: async ({ nearAccountId, chain }) => {
        provisionCalls += 1;
        const refreshedBootstrap = createThresholdEcdsaBootstrapFixture({
          nearAccountId: String(nearAccountId),
          chain,
          ecdsaThresholdKeyId: 'ek-reconnect',
          sessionId: 'fresh-evm-session',
          sessionJwt: 'jwt:fresh-evm-session',
        });
        const refreshedRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
          nearAccountId: String(nearAccountId),
          chain,
          source: 'manual-bootstrap',
          bootstrap: refreshedBootstrap,
        });
        fixture.claimsBySessionId[refreshedRecord.thresholdSessionId] = {
          state: 'warm',
          remainingUses: refreshedRecord.remainingUses || 5,
          expiresAtMs: refreshedRecord.expiresAtMs || Date.now() + 120_000,
        };
        return refreshedBootstrap;
      },
    });

    const ready = await store.ensureEcdsaCapabilityReady({
      nearAccountId: 'reconnect.testnet',
      chain: 'evm',
      usesNeeded: 1,
      sessionBudgetUses: 1,
    });

    expect(provisionCalls).toBe(1);
    expect(ready.reconnected).toBe(true);
    expect(ready.keyRef).toMatchObject({
      ecdsaThresholdKeyId: 'ek-reconnect',
      thresholdSessionId: 'fresh-evm-session',
    });
    expect(ready.capability).toMatchObject({
      state: 'ready',
      chain: 'evm',
    });
    expect(ready.capability.record).toMatchObject({
      thresholdSessionId: 'fresh-evm-session',
      source: 'manual-bootstrap',
    });
  });
});
