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

test.describe('WarmSessionStore ECDSA reconnect and reuse', () => {
  test('reuses a matching ready ECDSA capability without reconnecting', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const bootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'reuse-ready.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-reuse-ready',
      sessionId: 'reuse-ready-session',
      sessionAuthToken: 'jwt:reuse-ready-session',
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
      listThresholdEcdsaKeyRefsForWalletTarget: () => [
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
      thresholdSessionId: record.thresholdSessionId,
      walletSigningSessionId: record.walletSigningSessionId,
    });

    expect(provisionCalls).toBe(0);
    expect(ready.reconnected).toBe(false);
    expect(ready.keyRef).toMatchObject({
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
      sessionAuthToken: 'jwt:stale-evm-session',
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
      listThresholdEcdsaKeyRefsForWalletTarget: () => [
        { source: 'login', keyRef: staleBootstrap.thresholdEcdsaKeyRef },
      ],
      provisionThresholdEcdsaSession: async (request) => {
        provisionCalls += 1;
        if (!request.key || !request.lanePolicy) {
          throw new Error('expected exact ECDSA activation request');
        }
        const walletId = request.key.walletId;
        const chainTarget = request.lanePolicy.chainTarget;
        const refreshedBootstrap = createThresholdEcdsaBootstrapFixture({
          nearAccountId: String(walletId),
          chain: chainTarget.kind,
          ecdsaThresholdKeyId: 'ek-reconnect',
          sessionId: 'fresh-evm-session',
          sessionAuthToken: 'jwt:fresh-evm-session',
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
      clientRootShare32B64u: 'reconnect-client-root-share',
    });

    expect(provisionCalls).toBe(1);
    expect(ready.reconnected).toBe(true);
    expect(ready.keyRef).toMatchObject({
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

  test('uses exact identity for threshold-session reconnect after source-agnostic sealed restore', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const restoredBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'restored-source.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-restored-source',
      sessionId: 'restored-evm-session',
      sessionAuthToken: 'jwt:restored-evm-session',
    });
    const restoredRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'restored-source.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: restoredBootstrap,
    });
    delete restoredRecord.clientAdditiveShare32B64u;
    const originalBackendBinding = restoredBootstrap.thresholdEcdsaKeyRef.backendBinding;
    if (!originalBackendBinding) {
      throw new Error('expected restored ECDSA key ref backend binding');
    }
    const { clientAdditiveShare32B64u: _clientAdditiveShare32B64u, ...backendBinding } =
      originalBackendBinding;
    const restoredKeyRef = {
      ...restoredBootstrap.thresholdEcdsaKeyRef,
      backendBinding,
    };
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
      listThresholdEcdsaKeyRefsForWalletTarget: () => [],
      provisionThresholdEcdsaSession: async (request) => {
        capturedRequest = request as Record<string, unknown>;
        if (!request.key || !request.lanePolicy || !request.sessionIdentity) {
          throw new Error('expected exact ECDSA reconnect request');
        }
        const walletId = request.key.walletId;
        const chainTarget = request.lanePolicy.chainTarget;
        const refreshedBootstrap = createThresholdEcdsaBootstrapFixture({
          nearAccountId: String(walletId),
          chain: chainTarget.kind,
          ecdsaThresholdKeyId: 'ek-restored-source',
          sessionId: request.sessionIdentity.thresholdSessionId,
          walletSigningSessionId: request.sessionIdentity.walletSigningSessionId,
          sessionAuthToken: 'jwt:restored-evm-session',
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
      subjectId: restoredRecord.subjectId,
      chainTarget: testEcdsaChainTarget('evm'),
      sessionIdentity: buildEcdsaSessionIdentity({
        thresholdSessionId: restoredRecord.thresholdSessionId,
        walletSigningSessionId: restoredRecord.walletSigningSessionId,
      }),
      sessionBudgetUses: 1,
      reconnectMaterial: buildEcdsaReconnectMaterial({
        keyRef: restoredKeyRef,
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

    expect(ready.reconnected).toBe(true);
    expect(capturedRequest).toMatchObject({
      kind: 'threshold_session_auth_reconnect',
      key: { walletId: 'restored-source.testnet' },
      lanePolicy: {
        thresholdSessionId: restoredRecord.thresholdSessionId,
        walletSigningSessionId: restoredRecord.walletSigningSessionId,
      },
    });
  });
});
