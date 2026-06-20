import { expect, test } from '@playwright/test';
import {
  SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR,
  THRESHOLD_SESSION_EXHAUSTED_ERROR,
} from '@/core/signingEngine/session/warmCapabilities/statusReader';
import { isSigningSessionAuthUnavailableError } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  getThresholdEcdsaSessionRecordByThresholdSessionId,
  thresholdEcdsaSessionRecordReadModel,
} from '@/core/signingEngine/session/persistence/records';
import {
  buildNearSigningSessionAuthPlan,
  resolveNearSigningSessionAuthContext,
} from '@/core/signingEngine/flows/signNear/shared/signingSessionAuthMode';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import {
  buildEcdsaLaneBudgetStatusCheck,
  ecdsaWalletBudgetOwner,
} from '@/core/signingEngine/session/budget/budget';
import {
  buildDiscoveredLaneForRecord,
  consumeSigningGrantUse,
  readWalletScopedLaneClaimsForWallet,
} from '@/core/signingEngine/session/availability/readiness';
import { SigningAuthPlanKind } from '@/core/signingEngine/stepUpConfirmation/types';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  createWarmSessionTestServices,
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionUiConfirmFixture,
  resetWarmSessionFixtureState,
  seedEd25519WarmSessionRecord,
  seedEcdsaWarmSessionRecord,
  testEcdsaChainTarget,
} from './helpers/warmSessionStore.fixtures';

async function resolveNearThresholdSigningAuthForTest(args: Parameters<
  typeof resolveNearSigningSessionAuthContext
>[0] & {
  signingSessionCoordinator?: SigningSessionCoordinator;
}) {
  const context = await resolveNearSigningSessionAuthContext(args);
  const resolvedSigningSession = await (
    args.signingSessionCoordinator || new SigningSessionCoordinator()
  ).resolveAuthPlanFromReadiness(context.coordinatorInput);
  return buildNearSigningSessionAuthPlan({ context, resolvedSigningSession });
}

test.describe('WarmSessionStore caller-facing error normalization', () => {
  test('classifies required touch-confirm consume not_found as auth-unavailable for step-up retry', () => {
    const error = new Error(
      '[SigningSessionCoordinator] touch_confirm signing-session consume returned not_found',
    );

    expect(isSigningSessionAuthUnavailableError(error)).toBe(true);
  });

  test('treats strict Router A/B passkey ECDSA records as ready without volatile status', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const evmRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'record-backed-ecdsa.testnet',
      chain: 'evm',
      source: 'registration',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'record-backed-ecdsa.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-record-backed-shared',
        sessionId: 'record-backed-ecdsa-session',
        walletSessionJwt: 'jwt:record-backed-ecdsa-session',
      }),
    });
    const tempoRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'record-backed-ecdsa.testnet',
      chain: 'tempo',
      source: 'registration',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'record-backed-ecdsa.testnet',
        chain: 'tempo',
        ecdsaThresholdKeyId: 'ek-record-backed-shared',
        sessionId: 'record-backed-tempo-session',
        walletSessionJwt: 'jwt:record-backed-tempo-session',
      }),
    });

    const store = createWarmSessionTestServices({
      touchConfirm: {
        getWarmSessionStatus: async () => ({
          ok: false,
          code: 'not_found',
          message: 'volatile status missing',
        }),
      },
      getThresholdEcdsaSessionRecordByThresholdSessionId: (thresholdSessionId) =>
        getThresholdEcdsaSessionRecordByThresholdSessionId(ecdsaStore, thresholdSessionId),
    });

    const warmSession = await store.getWarmSession(evmRecord.walletId);
    expect(warmSession.capabilities.ecdsa.evm.state).toBe('ready');
    expect(warmSession.capabilities.ecdsa.evm.prfClaim).toMatchObject({
      state: 'warm',
      sessionId: evmRecord.thresholdSessionId,
    });
    expect(warmSession.capabilities.ecdsa.tempo.state).toBe('ready');
    expect(warmSession.capabilities.ecdsa.tempo.prfClaim).toMatchObject({
      state: 'warm',
      sessionId: tempoRecord.thresholdSessionId,
    });

    await expect(
      store.assertEcdsaSigningSessionReady({
        walletId: evmRecord.walletId,
        chainTarget: evmRecord.chainTarget,
        thresholdSessionId: evmRecord.thresholdSessionId,
        usesNeeded: 1,
      }),
    ).resolves.toMatchObject({
      ok: true,
      remainingUses: 5,
    });
  });

  test('spends strict Router A/B passkey ECDSA records without touch-confirm material consume', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'record-policy-spend.testnet',
      chain: 'tempo',
      source: 'registration',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'record-policy-spend.testnet',
        chain: 'tempo',
        ecdsaThresholdKeyId: 'ek-record-policy-spend',
        sessionId: 'record-policy-spend-session',
        walletSessionJwt: 'jwt:record-policy-spend-session',
      }),
    });
    const discoveredLane = buildDiscoveredLaneForRecord(record);
    expect(discoveredLane).toMatchObject({
      thresholdSessionId: record.thresholdSessionId,
      signingGrantId: record.signingGrantId,
      backing: 'record_policy',
    });

    let touchConfirmConsumeCalls = 0;
    const readModel = thresholdEcdsaSessionRecordReadModel(record);
    const statusOverrides = new Map();
    const status = await consumeSigningGrantUse({
      deps: {
        touchConfirm: {
          consumeWarmSessionUses: async () => {
            touchConfirmConsumeCalls += 1;
            return {
              ok: false,
              code: 'not_found',
              message: 'volatile material is intentionally absent',
            };
          },
        },
      },
      statusOverrides,
      readStatus: async () => ({
        sessionId: record.signingGrantId,
        status: 'active',
        remainingUses: 4,
        expiresAtMs: record.expiresAtMs,
        projectionVersion: 'projection-record-policy-spend',
      }),
      input: {
        owner: ecdsaWalletBudgetOwner(toWalletId(record.walletId)),
        signingGrantId: record.signingGrantId,
        uses: 1,
        budgetStatusCheck: buildEcdsaLaneBudgetStatusCheck({
          key: readModel.key,
          keyHandle: record.keyHandle,
          chainTarget: record.chainTarget,
          signingGrantId: record.signingGrantId,
          thresholdSessionId: record.thresholdSessionId,
        }),
      },
    });

    expect(touchConfirmConsumeCalls).toBe(0);
    expect(status).toMatchObject({
      sessionId: record.signingGrantId,
      status: 'active',
      remainingUses: 3,
    });
  });

  test('projects explicit record-backed wallet session spends only to the targeted lane', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const walletId = 'shared-budget-record-policy.testnet';
    const signingGrantId = 'wsess-shared-budget-record-policy';
    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: walletId,
      thresholdSessionId: 'shared-budget-ed25519-session',
      signingGrantId,
      walletSessionJwt: 'jwt:shared-budget-ed25519-session',
      remainingUses: 3,
    });
    const ecdsaRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: walletId,
      chain: 'tempo',
      source: 'registration',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: walletId,
        chain: 'tempo',
        ecdsaThresholdKeyId: 'ek-shared-budget-record-policy',
        sessionId: 'shared-budget-tempo-session',
        signingGrantId,
        walletSessionJwt: 'jwt:shared-budget-tempo-session',
      }),
    });
    const readModel = thresholdEcdsaSessionRecordReadModel(ecdsaRecord);
    const statusOverrides = new Map();
    let ed25519ConsumeCalls = 0;
    const deps = {
      touchConfirm: {
        getWarmSessionStatus: async () => ({
          ok: true as const,
          remainingUses: 3,
          expiresAtMs: ed25519Record.expiresAtMs,
        }),
        consumeWarmSessionUses: async () => {
          ed25519ConsumeCalls += 1;
          throw new Error('non-target Ed25519 lane should not consume');
        },
      },
    };

    const status = await consumeSigningGrantUse({
      deps,
      statusOverrides,
      readStatus: async () => ({
        sessionId: signingGrantId,
        status: 'active',
        remainingUses: 3,
        expiresAtMs: ecdsaRecord.expiresAtMs,
        projectionVersion: 'projection-shared-budget-record-policy',
      }),
      input: {
        owner: ecdsaWalletBudgetOwner(toWalletId(ecdsaRecord.walletId)),
        signingGrantId,
        uses: 1,
        budgetStatusCheck: buildEcdsaLaneBudgetStatusCheck({
          key: readModel.key,
          keyHandle: ecdsaRecord.keyHandle,
          chainTarget: ecdsaRecord.chainTarget,
          signingGrantId,
          thresholdSessionId: ecdsaRecord.thresholdSessionId,
        }),
      },
    });

    expect(status).toMatchObject({
      sessionId: signingGrantId,
      status: 'active',
      remainingUses: 2,
    });
    expect(ed25519ConsumeCalls).toBe(0);

    const claims = await readWalletScopedLaneClaimsForWallet({
      deps,
      walletId: toWalletId(walletId),
      statusOverrides,
    });
    expect(claims.get(ed25519Record.thresholdSessionId)).toMatchObject({
      state: 'warm',
      sessionId: ed25519Record.thresholdSessionId,
      remainingUses: 3,
    });
    expect(claims.get(ecdsaRecord.thresholdSessionId)).toMatchObject({
      state: 'warm',
      sessionId: ecdsaRecord.thresholdSessionId,
      remainingUses: 2,
    });
  });

  test('normalizes reconnect failure when the refreshed warm capability is still not ready', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const staleBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'reconnect-error.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-reconnect-error',
      sessionId: 'reconnect-error-stale-session',
      walletSessionJwt: 'jwt:reconnect-error-stale-session',
    });
    const staleRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'reconnect-error.testnet',
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
    const store = createWarmSessionTestServices({
      touchConfirm: fixture.touchConfirm,
      listThresholdEcdsaRecordsForWalletTarget: () => [
        { source: 'login', record: staleRecord },
      ],
      provisionThresholdEcdsaSession: async (request) => {
        if (!('walletKey' in request) || !('lanePolicy' in request)) {
          throw new Error('expected exact ECDSA activation request');
        }
        return createThresholdEcdsaBootstrapFixture({
          nearAccountId: String(request.walletKey.walletId),
          chain: request.lanePolicy.chainTarget.kind,
          ecdsaThresholdKeyId: 'ek-reconnect-error',
          sessionId: 'reconnect-error-fresh-session',
          walletSessionJwt: 'jwt:reconnect-error-fresh-session',
        });
      },
    });

    await expect(
      store.ensureEcdsaCapabilityReady({
        nearAccountId: 'reconnect-error.testnet',
        chain: 'evm',
        requiredSignatureUses: 1,
        sessionBudgetUses: 1,
        passkeyPrfFirstB64u: 'reconnect-error-client-root-share',
      }),
    ).rejects.toThrow('[WarmSessionStore] threshold ECDSA warm capability is not ready after reconnect');
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
        walletSessionJwt: 'jwt:seal-error-session',
        relayerUrl: 'https://relay.seal-error.example',
      }),
    });

    const fixture = createWarmSessionUiConfirmFixture({
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
    const store = createWarmSessionTestServices({
      touchConfirm: fixture.touchConfirm,
    });

    await expect(
      store.ensureEcdsaPrfSealPersistedByThresholdSessionId({
        chain: 'evm',
        thresholdSessionId: record.thresholdSessionId,
        required: true,
        errorContext: 'threshold-ecdsa signing seal persistence',
      }),
    ).rejects.toThrow(
      '[WarmSessionStore] threshold-ecdsa signing seal persistence failed (transport_error): relay offline',
    );
  });

  test('normalizes exhausted signing-session readiness through the store boundary', async () => {
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
        walletSessionJwt: 'jwt:signing-exhausted-session',
      }),
    });

    const store = createWarmSessionTestServices({
      touchConfirm: {
        getWarmSessionStatus: async () => ({
          ok: true,
          remainingUses: 1,
          expiresAtMs: Date.now() + 60_000,
        }),
      },
    });

    await expect(
      store.assertEcdsaSigningSessionReady({
        walletId: 'signing-exhausted.testnet',
        chainTarget: testEcdsaChainTarget('evm'),
        thresholdSessionId: 'signing-exhausted-session',
        usesNeeded: 6,
      }),
    ).rejects.toThrow(THRESHOLD_SESSION_EXHAUSTED_ERROR);
  });

  test('normalizes Ed25519 auth-unavailable signing plans through the planner boundary', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const store = createWarmSessionTestServices({
      touchConfirm: {
        getWarmSessionStatus: async () => ({
          ok: false,
          code: 'not_found',
          message: 'missing',
        }),
      },
    });

    await expect(
      resolveNearThresholdSigningAuthForTest({
        warmSessionReader: store,
        nearAccount: { kind: 'named', accountId: 'auth-unavailable.testnet' as any },
        requiredSignatureUses: 1,
        operationLabel: 'unit-test',
      }),
    ).rejects.toThrow(SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR);
  });

  test('fails closed when Ed25519 wallet signing budget is unavailable', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    seedEd25519WarmSessionRecord({
      nearAccountId: 'status-unavailable.testnet',
      thresholdSessionId: 'status-unavailable-session',
      signingGrantId: 'status-unavailable-wallet-session',
      walletSessionJwt: 'jwt:status-unavailable-session',
    });

    const store = createWarmSessionTestServices({
      touchConfirm: {
        getWarmSessionStatus: async () => ({
          ok: false,
          code: 'worker_error',
          message: 'worker down',
        }),
      },
    });

    await expect(
      resolveNearThresholdSigningAuthForTest({
        warmSessionReader: store,
        nearAccount: { kind: 'named', accountId: 'status-unavailable.testnet' as any },
        requiredSignatureUses: 1,
        operationLabel: 'unit-test',
      }),
    ).rejects.toThrow('[SigningEngine][near] signing session is not ready: budget_unknown');
  });

  test('plans passkey reauth when wallet signing budget is exhausted but Ed25519 material is warm', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    seedEd25519WarmSessionRecord({
      nearAccountId: 'wallet-budget-exhausted-ed25519.testnet',
      thresholdSessionId: 'wallet-budget-exhausted-ed25519-session',
      signingGrantId: 'wallet-budget-exhausted-ed25519-wallet-session',
      walletSessionJwt: 'jwt:wallet-budget-exhausted-ed25519-session',
      remainingUses: 1,
      expiresAtMs: Date.now() + 60_000,
      source: 'login',
    });

    const store = createWarmSessionTestServices({
      touchConfirm: {
        getWarmSessionStatus: async () => ({
          ok: true,
          remainingUses: 1,
          expiresAtMs: Date.now() + 60_000,
        }),
      },
    });
    const signingSessionCoordinator = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: 'wallet-budget-exhausted-ed25519-wallet-session',
        status: 'exhausted',
        remainingUses: 0,
      }),
    });

    const plan = await resolveNearThresholdSigningAuthForTest({
      warmSessionReader: store,
      signingSessionCoordinator,
      nearAccount: { kind: 'named', accountId: 'wallet-budget-exhausted-ed25519.testnet' as any },
      requiredSignatureUses: 1,
      operationLabel: 'unit-test',
    });

    expect(plan.signingAuthPlan?.kind).toBe(SigningAuthPlanKind.PasskeyReauth);
    expect(plan.warmSessionReady).toBe(false);
  });
});
