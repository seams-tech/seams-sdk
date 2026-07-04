import { expect, test } from '@playwright/test';
import { listThresholdEcdsaSessionRecordsForWalletTarget } from '@/core/signingEngine/session/persistence/records';
import { createWarmSessionTestServices } from './helpers/warmSessionTestServices.fixtures';
import {
  createThresholdEcdsaStoreFixture,
  resetWarmSessionFixtureState,
  seedEcdsaWarmSessionRecord,
} from './helpers/signingSessionRecord.fixtures';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';
import { testEcdsaChainTarget } from './helpers/ecdsaChainTarget.fixtures';

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
  test('replaces stale passkey wallet-target records when a fresh bootstrap arrives', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const registrationBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'replace-passkey-target.testnet',
      chain: 'evm',
      sessionId: 'registration-ecdsa-session',
      signingGrantId: 'wsess-registration-ecdsa-session',
    });
    seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'replace-passkey-target.testnet',
      chain: 'evm',
      source: 'registration',
      bootstrap: registrationBootstrap,
    });

    const manualBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'replace-passkey-target.testnet',
      chain: 'evm',
      sessionId: 'manual-ecdsa-session',
      signingGrantId: 'wsess-manual-ecdsa-session',
      ecdsaThresholdKeyId: registrationBootstrap.keygen.ecdsaThresholdKeyId,
      keyHandle: registrationBootstrap.thresholdEcdsaKeyRef.keyHandle,
      signingRootId:
        registrationBootstrap.thresholdEcdsaKeyRef.backendBinding?.ecdsaRoleLocalReadyRecord
          ?.publicFacts.signingRootId,
      signingRootVersion:
        registrationBootstrap.thresholdEcdsaKeyRef.backendBinding?.ecdsaRoleLocalReadyRecord
          ?.publicFacts.signingRootVersion,
      ethereumAddress: registrationBootstrap.keygen.ethereumAddress,
    });
    seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'replace-passkey-target.testnet',
      chain: 'evm',
      source: 'manual-bootstrap',
      bootstrap: manualBootstrap,
    });

    const records = listThresholdEcdsaSessionRecordsForWalletTarget(ecdsaStore, {
      walletId: 'replace-passkey-target.testnet',
      chainTarget: testEcdsaChainTarget('evm'),
    });

    expect(records).toHaveLength(1);
    expect(records[0]?.source).toBe('manual-bootstrap');
    expect(records[0]?.thresholdSessionId).toBe('manual-ecdsa-session');
    expect(records[0]?.signingGrantId).toBe('wsess-manual-ecdsa-session');
  });

  test('dedupes concurrent ensureEcdsaCapabilityReady reconnects for the same capability', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const staleBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'concurrent-ready.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-concurrent-ready',
      sessionId: 'stale-concurrent-session',
      walletSessionJwt: 'jwt:stale-concurrent-session',
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
      walletSessionJwt: 'jwt:fresh-concurrent-session',
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
      listThresholdEcdsaRecordsForWalletTarget: () => [
        { source: 'manual-bootstrap', record: staleRecord },
      ],
      provisionThresholdEcdsaSession: async (request) => {
        provisionCalls += 1;
        if (!('walletKey' in request) || !('lanePolicy' in request)) {
          throw new Error('expected exact ECDSA activation request');
        }
        const bootstrap = await provisionDeferred.promise;
        seedEcdsaWarmSessionRecord(ecdsaStore, {
          nearAccountId: String(request.walletKey.walletId),
          chain: request.lanePolicy.chainTarget.kind,
          source: 'manual-bootstrap',
          bootstrap,
          runtimeValidated: true,
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
      passkeyPrfFirstB64u: 'concurrent-client-root-share',
    });
    const readyPromiseB = store.ensureEcdsaCapabilityReady({
      nearAccountId: 'concurrent-ready.testnet',
      chain: 'evm',
      usesNeeded: 1,
      sessionBudgetUses: 1,
      passkeyPrfFirstB64u: 'concurrent-client-root-share',
    });

    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(provisionCalls).toBe(1);

    provisionDeferred.resolve(freshBootstrap);

    const [readyA, readyB] = await Promise.all([readyPromiseA, readyPromiseB]);

    expect(provisionCalls).toBe(1);
    expect(readyA.reconnected).toBe(true);
    expect(readyB.reconnected).toBe(true);
    expect(readyA.record.thresholdSessionId).toBe('fresh-concurrent-session');
    expect(readyB.record.thresholdSessionId).toBe('fresh-concurrent-session');
    expect(readyA.capability.prfClaim).toMatchObject({
      state: 'warm',
      remainingUses: 5,
    });
    expect(readyB.capability.prfClaim).toMatchObject({
      state: 'warm',
      remainingUses: 5,
    });
    expect(readCalls).toEqual([]);
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
        walletSessionJwt: 'jwt:concurrent-seal-session',
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
