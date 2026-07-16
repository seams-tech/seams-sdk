import { expect, test } from '@playwright/test';
import {
  SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR,
  THRESHOLD_SESSION_EXHAUSTED_ERROR,
} from '@/core/signingEngine/session/warmCapabilities/statusReader';
import { isSigningSessionAuthUnavailableError } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  getThresholdEcdsaSessionRecordByThresholdSessionId,
  thresholdEcdsaLaneCandidateFromSessionRecord,
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
import {
  nearAccountRefFromAccountId,
  toWalletId,
  type NearCommandSubject,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { createWarmSessionTestServices } from './helpers/warmSessionTestServices.fixtures';
import { createWarmSessionUiConfirmFixture } from './helpers/warmSessionUiConfirm.fixtures';
import {
  createThresholdEcdsaStoreFixture,
  resetWarmSessionFixtureState,
  seedEd25519WarmSessionRecord,
  seedEcdsaWarmSessionRecord,
} from './helpers/signingSessionRecord.fixtures';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';
import { testEcdsaChainTarget } from './helpers/ecdsaChainTarget.fixtures';

function nearCommandSubject(
  walletIdRaw: string,
  nearAccountIdRaw = walletIdRaw,
): NearCommandSubject {
  return {
    walletSession: {
      walletId: toWalletId(walletIdRaw),
      walletSessionUserId: walletIdRaw,
    },
    nearAccount: nearAccountRefFromAccountId(nearAccountIdRaw),
  };
}

async function resolveNearThresholdSigningAuthForTest(
  args: Parameters<typeof resolveNearSigningSessionAuthContext>[0] & {
    signingSessionCoordinator?: SigningSessionCoordinator;
  },
) {
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
      runtimeValidated: true,
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
      runtimeValidated: true,
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
      runtimeValidated: true,
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
          auth: thresholdEcdsaLaneCandidateFromSessionRecord({ record: record }).auth,
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

  test('record-policy spend fails closed without trusted server budget status', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'record-policy-missing-budget.testnet',
      chain: 'tempo',
      source: 'registration',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'record-policy-missing-budget.testnet',
        chain: 'tempo',
        ecdsaThresholdKeyId: 'ek-record-policy-missing-budget',
        sessionId: 'record-policy-missing-budget-session',
        walletSessionJwt: 'jwt:record-policy-missing-budget-session',
      }),
      runtimeValidated: true,
    });
    const readModel = thresholdEcdsaSessionRecordReadModel(record);
    const status = await consumeSigningGrantUse({
      deps: {},
      statusOverrides: new Map(),
      readStatus: async () => null,
      input: {
        owner: ecdsaWalletBudgetOwner(toWalletId(record.walletId)),
        signingGrantId: record.signingGrantId,
        uses: 1,
        budgetStatusCheck: buildEcdsaLaneBudgetStatusCheck({
          key: readModel.key,
          keyHandle: record.keyHandle,
          auth: thresholdEcdsaLaneCandidateFromSessionRecord({ record: record }).auth,
          chainTarget: record.chainTarget,
          signingGrantId: record.signingGrantId,
          thresholdSessionId: record.thresholdSessionId,
        }),
      },
    });

    expect(status).toMatchObject({
      sessionId: record.signingGrantId,
      status: 'budget_unknown',
      statusCode: 'missing_trusted_status',
    });
  });

  test('record-policy spend rejects terminal and malformed trusted budget status', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'record-policy-terminal-budget.testnet',
      chain: 'tempo',
      source: 'registration',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'record-policy-terminal-budget.testnet',
        chain: 'tempo',
        ecdsaThresholdKeyId: 'ek-record-policy-terminal-budget',
        sessionId: 'record-policy-terminal-budget-session',
        walletSessionJwt: 'jwt:record-policy-terminal-budget-session',
      }),
      runtimeValidated: true,
    });
    const readModel = thresholdEcdsaSessionRecordReadModel(record);
    const baseInput = {
      owner: ecdsaWalletBudgetOwner(toWalletId(record.walletId)),
      signingGrantId: record.signingGrantId,
      uses: 1,
      budgetStatusCheck: buildEcdsaLaneBudgetStatusCheck({
        key: readModel.key,
        keyHandle: record.keyHandle,
        auth: thresholdEcdsaLaneCandidateFromSessionRecord({ record: record }).auth,
        chainTarget: record.chainTarget,
        signingGrantId: record.signingGrantId,
        thresholdSessionId: record.thresholdSessionId,
      }),
    };

    const notFound = await consumeSigningGrantUse({
      deps: {},
      statusOverrides: new Map(),
      readStatus: async () => ({
        sessionId: record.signingGrantId,
        status: 'not_found',
      }),
      input: baseInput,
    });
    expect(notFound).toMatchObject({
      sessionId: record.signingGrantId,
      status: 'budget_unknown',
    });

    const expired = await consumeSigningGrantUse({
      deps: {},
      statusOverrides: new Map(),
      readStatus: async () => ({
        sessionId: record.signingGrantId,
        status: 'expired',
        expiresAtMs: Date.now() - 1,
      }),
      input: baseInput,
    });
    expect(expired).toMatchObject({
      sessionId: record.signingGrantId,
      status: 'expired',
    });

    const exhausted = await consumeSigningGrantUse({
      deps: {},
      statusOverrides: new Map(),
      readStatus: async () => ({
        sessionId: record.signingGrantId,
        status: 'exhausted',
        remainingUses: 0,
        expiresAtMs: record.expiresAtMs,
      }),
      input: baseInput,
    });
    expect(exhausted).toMatchObject({
      sessionId: record.signingGrantId,
      status: 'exhausted',
      remainingUses: 0,
    });

    const unavailable = await consumeSigningGrantUse({
      deps: {},
      statusOverrides: new Map(),
      readStatus: async () => ({
        sessionId: record.signingGrantId,
        status: 'unavailable',
        statusCode: 'status_unavailable',
      }),
      input: baseInput,
    });
    expect(unavailable).toMatchObject({
      sessionId: record.signingGrantId,
      status: 'budget_unknown',
    });

    const budgetUnknown = await consumeSigningGrantUse({
      deps: {},
      statusOverrides: new Map(),
      readStatus: async () => ({
        sessionId: record.signingGrantId,
        status: 'budget_unknown',
        statusCode: 'status_unavailable',
      }),
      input: baseInput,
    });
    expect(budgetUnknown).toMatchObject({
      sessionId: record.signingGrantId,
      status: 'budget_unknown',
    });

    const malformedActive = await consumeSigningGrantUse({
      deps: {},
      statusOverrides: new Map(),
      readStatus: async () =>
        ({
          sessionId: record.signingGrantId,
          status: 'active',
          expiresAtMs: record.expiresAtMs,
          projectionVersion: 'projection-malformed-active',
        }) as any,
      input: baseInput,
    });
    expect(malformedActive).toMatchObject({
      sessionId: record.signingGrantId,
      status: 'budget_unknown',
    });

    const fractionalActive = await consumeSigningGrantUse({
      deps: {},
      statusOverrides: new Map(),
      readStatus: async () => ({
        sessionId: record.signingGrantId,
        status: 'active',
        remainingUses: 1.5,
        expiresAtMs: record.expiresAtMs,
        projectionVersion: 'projection-fractional-active',
      }),
      input: baseInput,
    });
    expect(fractionalActive).toMatchObject({
      sessionId: record.signingGrantId,
      status: 'budget_unknown',
    });

    const unavailableUses = await consumeSigningGrantUse({
      deps: {},
      statusOverrides: new Map(),
      readStatus: async () => ({
        sessionId: record.signingGrantId,
        status: 'active',
        remainingUses: 3,
        availableUses: 0,
        expiresAtMs: record.expiresAtMs,
        projectionVersion: 'projection-available-uses-zero',
      }),
      input: baseInput,
    });
    expect(unavailableUses).toMatchObject({
      sessionId: record.signingGrantId,
      status: 'active',
      remainingUses: 2,
    });
  });

  test('projects an explicit lane spend across the shared wallet signing budget', async () => {
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
      runtimeValidated: true,
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
          auth: thresholdEcdsaLaneCandidateFromSessionRecord({ record: ecdsaRecord }).auth,
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
      remainingUses: 2,
    });
    expect(claims.get(ecdsaRecord.thresholdSessionId)).toMatchObject({
      state: 'warm',
      sessionId: ecdsaRecord.thresholdSessionId,
      remainingUses: 2,
    });
  });

  test('does not treat unvalidated passkey ECDSA record policy as signable', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'unvalidated-record-policy.testnet',
      chain: 'evm',
      source: 'registration',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'unvalidated-record-policy.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-unvalidated-record-policy',
        sessionId: 'unvalidated-record-policy-session',
        walletSessionJwt: 'jwt:unvalidated-record-policy-session',
      }),
    });

    expect(buildDiscoveredLaneForRecord(record)).toBeNull();

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

    const warmSession = await store.getWarmSession(record.walletId);
    expect(warmSession.capabilities.ecdsa.evm.state).not.toBe('ready');

    const claims = await readWalletScopedLaneClaimsForWallet({
      deps: {},
      walletId: toWalletId(record.walletId),
    });
    expect(claims.has(record.thresholdSessionId)).toBe(false);
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
      listThresholdEcdsaRecordsForWalletTarget: () => [{ source: 'login', record: staleRecord }],
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
    ).rejects.toThrow(
      '[WarmSessionStore] threshold ECDSA warm capability is not ready after reconnect',
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
      runtimeValidated: true,
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
        commandSubject: nearCommandSubject('auth-unavailable.testnet'),
        requiredSignatureUses: 1,
        operationLabel: 'unit-test',
      }),
    ).rejects.toThrow(SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR);
  });

  test('plans passkey reauth when Ed25519 warm-session status is unavailable', async () => {
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

    const authPlan = await resolveNearThresholdSigningAuthForTest({
      warmSessionReader: store,
      commandSubject: nearCommandSubject('status-unavailable.testnet'),
      requiredSignatureUses: 1,
      operationLabel: 'unit-test',
    });

    expect(authPlan.warmSessionReady).toBe(false);
    expect(authPlan.signingAuthPlan).toEqual({
      kind: SigningAuthPlanKind.PasskeyReauth,
      method: 'passkey',
    });
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
      commandSubject: nearCommandSubject('wallet-budget-exhausted-ed25519.testnet'),
      requiredSignatureUses: 1,
      operationLabel: 'unit-test',
    });

    expect(plan.signingAuthPlan?.kind).toBe(SigningAuthPlanKind.PasskeyReauth);
    expect(plan.warmSessionReady).toBe(false);
  });
});
