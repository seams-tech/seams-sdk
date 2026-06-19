import { expect, test } from '@playwright/test';
import {
  createWarmSessionTestServices,
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionUiConfirmFixture,
  resetWarmSessionFixtureState,
  seedEcdsaWarmSessionRecord,
  testEcdsaChainTarget,
} from './helpers/warmSessionStore.fixtures';
import {
  buildEcdsaReconnectMaterial,
  buildEcdsaSessionIdentity,
  buildEcdsaSessionProvisionPlan,
} from '@/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan';
import {
  bootstrapReuseWarmEcdsaCapabilityNoPrompt,
  type NoPromptWarmSessionDeps,
} from '@/core/signingEngine/session/passkey/ecdsaWarmCapabilityBootstrap';
import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const unusedNoPromptReconnectDeps: Pick<
  NoPromptWarmSessionDeps,
  'claimEcdsaPasskeyPrfFirst' | 'reconnectWithWalletSessionAuth'
> = {
  claimEcdsaPasskeyPrfFirst: async () => {
    throw new Error('claimEcdsaPasskeyPrfFirst should not be called');
  },
  reconnectWithWalletSessionAuth: async () => {
    throw new Error('reconnectWithWalletSessionAuth should not be called');
  },
};

test.describe('WarmSessionStore ECDSA reconnect and reuse', () => {
  test('no-prompt reuse restores exact ECDSA material without prompt ports', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const walletId = toAccountId('no-prompt-restore.testnet');
    const chainTarget = testEcdsaChainTarget('evm');
    const bootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: String(walletId),
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-no-prompt-restore',
      sessionId: 'no-prompt-restore-session',
      walletSessionJwt: 'jwt:no-prompt-restore-session',
    });
    const fixture = createWarmSessionUiConfirmFixture({
      claimsBySessionId: {},
    });
    const store = createWarmSessionTestServices({
      touchConfirm: fixture.touchConfirm,
    });

    let restoreCalls = 0;
    const result = await bootstrapReuseWarmEcdsaCapabilityNoPrompt(
      {
        getWarmSession: store.getWarmSession,
        ecdsaSessions: ecdsaStore,
        ...unusedNoPromptReconnectDeps,
        restorePersistedSessionsForWallet: async (args) => {
          restoreCalls += 1;
          expect(args).toMatchObject({
            walletId,
            authMethod: 'passkey',
            ecdsaChainTargets: [chainTarget],
            maxRecords: 1,
          });
          const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
            nearAccountId: String(walletId),
            chain: 'evm',
            source: 'login',
            bootstrap,
          });
          fixture.claimsBySessionId[record.thresholdSessionId] = {
            state: 'warm',
            remainingUses: 3,
            expiresAtMs: record.expiresAtMs || Date.now() + 120_000,
          };
          return {
            listed: 1,
            attempted: 1,
            restored: 1,
            deferred: 0,
            skipped: 0,
            truncated: 0,
          };
        },
      },
      walletId,
      {
        kind: 'reuse_warm_ecdsa_bootstrap',
        walletId,
        chainTarget,
        source: 'login',
      },
    );

    expect(restoreCalls).toBe(1);
    expect(result).toMatchObject({
      ok: true,
      source: 'sealed_restore',
      bootstrap: {
        thresholdEcdsaKeyRef: {
          ecdsaThresholdKeyId: bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId,
          thresholdSessionId: 'no-prompt-restore-session',
        },
      },
    });
  });

  test('no-prompt reuse restores passkey ECDSA material without prompt ports', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const walletId = toAccountId('no-prompt-reconnect.testnet');
    const chainTarget = testEcdsaChainTarget('tempo');
    const restoredBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: String(walletId),
      chain: 'tempo',
      ecdsaThresholdKeyId: 'ek-no-prompt-reconnect',
      sessionId: 'no-prompt-reconnect-restored-session',
      walletSessionJwt: 'jwt:no-prompt-reconnect-restored-session',
    });
    const reconnectedBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: String(walletId),
      chain: 'tempo',
      ecdsaThresholdKeyId: 'ek-no-prompt-reconnect',
      sessionId: 'no-prompt-reconnect-refreshed-session',
      walletSessionJwt: 'jwt:no-prompt-reconnect-refreshed-session',
    });
    const fixture = createWarmSessionUiConfirmFixture({
      claimsBySessionId: {},
    });
    const store = createWarmSessionTestServices({
      touchConfirm: fixture.touchConfirm,
    });

    let restoreCalls = 0;
    let claimCalls = 0;
    let reconnectCalls = 0;
    const result = await bootstrapReuseWarmEcdsaCapabilityNoPrompt(
      {
        getWarmSession: store.getWarmSession,
        ecdsaSessions: ecdsaStore,
        restorePersistedSessionsForWallet: async (args) => {
          restoreCalls += 1;
          expect(args).toMatchObject({
            kind: 'restore_wallet_ecdsa_signing_sessions',
            walletId,
            authMethod: 'passkey',
            ecdsaChainTargets: [chainTarget],
            maxRecords: 1,
          });
          const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
            nearAccountId: String(walletId),
            chain: 'tempo',
            source: 'login',
            bootstrap: restoredBootstrap,
          });
          fixture.claimsBySessionId[record.thresholdSessionId] = {
            state: 'warm',
            remainingUses: 3,
            expiresAtMs: record.expiresAtMs || Date.now() + 120_000,
            prfFirstB64u: 'restored-prf-first',
          };
          return {
            listed: 1,
            attempted: 1,
            restored: 1,
            deferred: 0,
            skipped: 0,
            truncated: 0,
          };
        },
        claimEcdsaPasskeyPrfFirst: async (args) => {
          claimCalls += 1;
          expect(args).toMatchObject({
            kind: 'claim_no_prompt_ecdsa_prf_first',
            walletId,
            walletSigningSessionId:
              restoredBootstrap.thresholdEcdsaKeyRef.walletSigningSessionId,
            thresholdSessionId: 'no-prompt-reconnect-restored-session',
            chainTarget,
            uses: 1,
          });
          return 'restored-prf-first';
        },
        reconnectWithWalletSessionAuth: async (request) => {
          reconnectCalls += 1;
          expect(request).toMatchObject({
            kind: 'wallet_session_reconnect_ecdsa_bootstrap',
            source: 'login',
            keyHandle: restoredBootstrap.thresholdEcdsaKeyRef.keyHandle,
            key: {
              walletId,
              ecdsaThresholdKeyId: restoredBootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId,
            },
            lanePolicy: {
              chainTarget,
              thresholdSessionId: 'no-prompt-reconnect-restored-session',
              walletSigningSessionId:
                restoredBootstrap.thresholdEcdsaKeyRef.walletSigningSessionId,
            },
            routeAuth: {
              kind: 'wallet_session',
            },
            passkeyPrfFirstB64u: 'restored-prf-first',
          });
          return reconnectedBootstrap;
        },
      },
      walletId,
      {
        kind: 'reuse_warm_ecdsa_bootstrap',
        walletId,
        chainTarget,
        source: 'login',
      },
    );

    expect(restoreCalls).toBe(1);
    expect(claimCalls).toBe(0);
    expect(reconnectCalls).toBe(0);
    expect(result).toMatchObject({
      ok: true,
      source: 'sealed_restore',
      bootstrap: {
        thresholdEcdsaKeyRef: {
          ecdsaThresholdKeyId: 'ek-no-prompt-reconnect',
          thresholdSessionId: 'no-prompt-reconnect-restored-session',
        },
      },
    });
  });

  test('no-prompt reuse fails closed when exact material is missing', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const walletId = toAccountId('no-prompt-missing.testnet');
    const chainTarget = testEcdsaChainTarget('tempo');
    const store = createWarmSessionTestServices();

    let restoreCalls = 0;
    const result = await bootstrapReuseWarmEcdsaCapabilityNoPrompt(
      {
        getWarmSession: store.getWarmSession,
        ecdsaSessions: ecdsaStore,
        ...unusedNoPromptReconnectDeps,
        restorePersistedSessionsForWallet: async () => {
          restoreCalls += 1;
          return {
            listed: 0,
            attempted: 0,
            restored: 0,
            deferred: 0,
            skipped: 0,
            truncated: 0,
          };
        },
      },
      walletId,
      {
        kind: 'reuse_warm_ecdsa_bootstrap',
        walletId,
        chainTarget,
        source: 'login',
      },
    );

    expect(restoreCalls).toBe(1);
    expect(result).toEqual({
      ok: false,
      code: 'missing_exact_material',
      chainTargetKey: 'tempo:42431',
    });
  });

  test('reuses a matching ready ECDSA capability without reconnecting', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const bootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'reuse-ready.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-reuse-ready',
      sessionId: 'reuse-ready-session',
      walletSessionJwt: 'jwt:reuse-ready-session',
    });
    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'reuse-ready.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap,
    });
    const fixture = createWarmSessionUiConfirmFixture({
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
      listThresholdEcdsaRecordsForWalletTarget: () => [
        { source: 'login', record },
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
      thresholdSessionId: record.thresholdSessionId,
      walletSigningSessionId: record.walletSigningSessionId,
    });

    expect(provisionCalls).toBe(0);
    expect(ready.reconnected).toBe(false);
    expect(ready.record).toMatchObject({
      ecdsaThresholdKeyId: 'ek-reuse-ready',
      thresholdSessionId: 'reuse-ready-session',
    });
    expect(ready.capability).toMatchObject({
      state: 'ready',
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
      walletSessionJwt: 'jwt:stale-evm-session',
    });
    const staleRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'reconnect.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: staleBootstrap,
    });
    const fixture = createWarmSessionUiConfirmFixture({
      claimsBySessionId: {
        [staleRecord.thresholdSessionId]: {
          state: 'missing',
        },
      },
    });

    let provisionCalls = 0;
    const store = createWarmSessionTestServices({
      touchConfirm: fixture.touchConfirm,
      listThresholdEcdsaRecordsForWalletTarget: () => [
        { source: 'login', record: staleRecord },
      ],
      provisionThresholdEcdsaSession: async (request) => {
        provisionCalls += 1;
        if (!('walletKey' in request) || !('lanePolicy' in request)) {
          throw new Error('expected exact ECDSA activation request');
        }
        const walletId = request.walletKey.walletId;
        const chainTarget = request.lanePolicy.chainTarget;
        const refreshedBootstrap = createThresholdEcdsaBootstrapFixture({
          nearAccountId: String(walletId),
          chain: chainTarget.kind,
          ecdsaThresholdKeyId: 'ek-reconnect',
          sessionId: 'fresh-evm-session',
          walletSessionJwt: 'jwt:fresh-evm-session',
        });
        const refreshedRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
          nearAccountId: String(walletId),
          chain: chainTarget.kind,
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
      thresholdSessionId: staleRecord.thresholdSessionId,
      walletSigningSessionId: staleRecord.walletSigningSessionId,
      passkeyPrfFirstB64u: 'reconnect-passkey-prf-first',
    });

    expect(provisionCalls).toBe(1);
    expect(ready.reconnected).toBe(true);
    expect(ready.record).toMatchObject({
      ecdsaThresholdKeyId: 'ek-reconnect',
      thresholdSessionId: 'fresh-evm-session',
    });
    expect(ready.capability).toMatchObject({
      state: 'ready',
    });
    expect(ready.capability.record).toMatchObject({
      thresholdSessionId: 'fresh-evm-session',
      source: 'manual-bootstrap',
    });
  });

  test('uses exact identity for source-agnostic sealed restore', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const restoredBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'restored-source.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-restored-source',
      sessionId: 'restored-evm-session',
      walletSessionJwt: 'jwt:restored-evm-session',
    });
    const restoredRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'restored-source.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: restoredBootstrap,
    });
    const restoredKeyRef = restoredBootstrap.thresholdEcdsaKeyRef;
    const fixture = createWarmSessionUiConfirmFixture({
      claimsBySessionId: {
        [restoredRecord.thresholdSessionId]: {
          state: 'warm',
          remainingUses: 1,
          expiresAtMs: restoredRecord.expiresAtMs || Date.now() + 120_000,
          prfFirstB64u: 'restored-prf-first',
        },
      },
    });

    let capturedRequest: Record<string, unknown> | null = null;
    const store = createWarmSessionTestServices({
      touchConfirm: fixture.touchConfirm,
      listThresholdEcdsaRecordsForWalletTarget: () => [],
      provisionThresholdEcdsaSession: async (request) => {
        capturedRequest = request as Record<string, unknown>;
        if (!('walletKey' in request) || !('lanePolicy' in request)) {
          throw new Error('expected exact ECDSA reconnect request');
        }
        const walletId = request.walletKey.walletId;
        const chainTarget = request.lanePolicy.chainTarget;
        const refreshedBootstrap = createThresholdEcdsaBootstrapFixture({
          nearAccountId: String(walletId),
          chain: chainTarget.kind,
          ecdsaThresholdKeyId: 'ek-restored-source',
          sessionId: request.lanePolicy.thresholdSessionId,
          walletSigningSessionId: request.lanePolicy.walletSigningSessionId,
          walletSessionJwt: 'jwt:restored-evm-session',
        });
        const refreshedRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
          nearAccountId: String(walletId),
          chain: chainTarget.kind,
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
    const plan = buildEcdsaSessionProvisionPlan({
      kind: 'ecdsa_session_reconnect',
      chainTarget: testEcdsaChainTarget('evm'),
      sessionIdentity: buildEcdsaSessionIdentity({
        thresholdSessionId: restoredRecord.thresholdSessionId,
        walletSigningSessionId: restoredRecord.walletSigningSessionId,
      }),
      sessionBudgetUses: 1,
      reconnectMaterial: buildEcdsaReconnectMaterial({
        record: restoredRecord,
      }),
    });

    const ready = await store.ensureEcdsaCapabilityReady({
      nearAccountId: 'restored-source.testnet',
      chain: 'evm',
      source: 'manual-bootstrap',
      keyRef: restoredKeyRef,
      usesNeeded: 1,
      sessionBudgetUses: 1,
      plan,
    });

    expect(ready.reconnected).toBe(false);
    expect(capturedRequest).toBe(null);
    expect(ready.record).toMatchObject({
      thresholdSessionId: restoredRecord.thresholdSessionId,
      walletSigningSessionId: restoredRecord.walletSigningSessionId,
    });
  });
});
