import { expect, test } from '@playwright/test';
import {
  createWarmSessionTestServices,
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  resetWarmSessionFixtureState,
  seedEcdsaWarmSessionRecord,
} from './helpers/warmSessionStore.fixtures';

function createDeferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

test.describe('WarmSessionStore concurrency', () => {
  test('dedupes concurrent ensureEcdsaCapabilityReady reconnects for the same capability', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const staleBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'concurrent-ready.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-concurrent-ready',
      sessionId: 'stale-concurrent-session',
      sessionJwt: 'jwt:stale-concurrent-session',
    });
    const staleRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'concurrent-ready.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: staleBootstrap,
    });
    const freshBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'concurrent-ready.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-concurrent-ready',
      sessionId: 'fresh-concurrent-session',
      sessionJwt: 'jwt:fresh-concurrent-session',
    });

    const readCalls: string[] = [];
    let provisionCalls = 0;
    const provisionDeferred = createDeferred<typeof freshBootstrap>();

    const claimsBySessionId: Record<
      string,
      | { ok: true; remainingUses: number; expiresAtMs: number }
      | { ok: false; code: string; message: string }
    > = {
      [staleRecord.thresholdSessionId]: {
        ok: false,
        code: 'not_found',
        message: 'missing',
      },
    };

    const store = createWarmSessionTestServices({
      touchConfirm: {
        getWarmSessionStatus: async ({ sessionId }) => {
          const normalized = String(sessionId || '').trim();
          readCalls.push(normalized);
          return (
            claimsBySessionId[normalized] || {
              ok: false,
              code: 'not_found',
              message: 'missing',
            }
          );
        },
      },
      listThresholdEcdsaKeyRefsForLookup: () => [
        { source: 'manual-bootstrap', keyRef: staleBootstrap.thresholdEcdsaKeyRef },
      ],
      provisionThresholdEcdsaSession: async ({ nearAccountId, chain }) => {
        provisionCalls += 1;
        const bootstrap = await provisionDeferred.promise;
        seedEcdsaWarmSessionRecord(ecdsaStore, {
          nearAccountId: String(nearAccountId),
          chain,
          source: 'manual-bootstrap',
          bootstrap,
        });
        claimsBySessionId[bootstrap.thresholdEcdsaKeyRef.thresholdSessionId || ''] = {
          ok: true,
          remainingUses: bootstrap.session.remainingUses ?? 5,
          expiresAtMs: bootstrap.session.expiresAtMs ?? Date.now() + 120_000,
        };
        return bootstrap;
      },
    });

    const readyPromiseA = store.ensureEcdsaCapabilityReady({
      nearAccountId: 'concurrent-ready.testnet',
      chain: 'evm',
      usesNeeded: 1,
      sessionBudgetUses: 1,
    });
    const readyPromiseB = store.ensureEcdsaCapabilityReady({
      nearAccountId: 'concurrent-ready.testnet',
      chain: 'evm',
      usesNeeded: 1,
      sessionBudgetUses: 1,
    });

    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(provisionCalls).toBe(1);

    provisionDeferred.resolve(freshBootstrap);

    const [readyA, readyB] = await Promise.all([readyPromiseA, readyPromiseB]);

    expect(provisionCalls).toBe(1);
    expect(readyA.reconnected).toBe(true);
    expect(readyB.reconnected).toBe(true);
    expect(readyA.keyRef.thresholdSessionId).toBe('fresh-concurrent-session');
    expect(readyB.keyRef.thresholdSessionId).toBe('fresh-concurrent-session');
    expect(readyA.capability.prfClaim).toMatchObject({
      state: 'warm',
      remainingUses: 5,
    });
    expect(readyB.capability.prfClaim).toMatchObject({
      state: 'warm',
      remainingUses: 5,
    });
    expect(readCalls).toContain('stale-concurrent-session');
    expect(readCalls).toContain('fresh-concurrent-session');
  });

  test('dedupes concurrent seal persistence for the same threshold session', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'concurrent-seal.testnet',
      chain: 'evm',
      source: 'manual-bootstrap',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'concurrent-seal.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-concurrent-seal',
        sessionId: 'concurrent-seal-session',
        sessionJwt: 'jwt:concurrent-seal-session',
        relayerUrl: 'https://relay.concurrent-seal.example',
      }),
    });

    let sealCalls = 0;
    const sealDeferred = createDeferred<{
      ok: true;
      sealedSecretB64u: string;
      remainingUses: number;
      expiresAtMs: number;
    }>();

    const store = createWarmSessionTestServices({
      touchConfirm: {
        getWarmSessionStatus: async () => ({
          ok: true,
          remainingUses: 4,
          expiresAtMs: record.expiresAtMs || Date.now() + 120_000,
        }),
        sealAndPersistWarmSessionMaterial: async () => {
          sealCalls += 1;
          return await sealDeferred.promise;
        },
      },
    });

    const persistPromiseA = store.ensureEcdsaPrfSealPersistedByThresholdSessionId({
      chain: 'evm',
      thresholdSessionId: record.thresholdSessionId,
      required: true,
      errorContext: 'threshold-ecdsa export seal persistence',
    });
    const persistPromiseB = store.ensureEcdsaPrfSealPersistedByThresholdSessionId({
      chain: 'evm',
      thresholdSessionId: record.thresholdSessionId,
      required: true,
      errorContext: 'threshold-ecdsa export seal persistence',
    });

    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(sealCalls).toBe(1);

    sealDeferred.resolve({
      ok: true,
      sealedSecretB64u: 'sealed-concurrent-prf',
      remainingUses: 4,
      expiresAtMs: record.expiresAtMs || Date.now() + 120_000,
    });

    await Promise.all([persistPromiseA, persistPromiseB]);
    expect(sealCalls).toBe(1);
  });
});
