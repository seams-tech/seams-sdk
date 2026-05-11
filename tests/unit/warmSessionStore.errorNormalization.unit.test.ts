import { expect, test } from '@playwright/test';
import {
  THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR,
  THRESHOLD_SESSION_EXHAUSTED_ERROR,
  THRESHOLD_SESSION_STATUS_UNAVAILABLE_ERROR,
} from '@/core/signingEngine/session/warmCapabilities/statusReader';
import {
  buildNearThresholdSigningAuthPlan,
  resolveNearThresholdSigningAuthContext,
} from '@/core/signingEngine/flows/signNear/shared/thresholdAuthMode';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import { SigningAuthPlanKind } from '@/core/signingEngine/stepUpConfirmation/types';
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
import { toWalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

async function resolveNearThresholdSigningAuthForTest(args: Parameters<
  typeof resolveNearThresholdSigningAuthContext
>[0] & {
  signingSessionCoordinator?: SigningSessionCoordinator;
}) {
  const context = await resolveNearThresholdSigningAuthContext(args);
  const resolvedSigningSession = await (
    args.signingSessionCoordinator || new SigningSessionCoordinator()
  ).resolveAuthPlanFromReadiness(context.coordinatorInput);
  return buildNearThresholdSigningAuthPlan({ context, resolvedSigningSession });
}

test.describe('WarmSessionStore caller-facing error normalization', () => {
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
        sessionAuthToken: 'jwt:bootstrap-error-session',
      }),
    });

    let provisionCalls = 0;
    const { touchConfirm } = createWarmSessionUiConfirmFixture({
      claimsBySessionId: {
        [record.thresholdSessionId]: {
          state: 'missing',
        },
      },
    });
    const store = createWarmSessionTestServices({
      touchConfirm,
      provisionThresholdEcdsaSession: async () => {
        provisionCalls += 1;
        throw new Error('provisionThresholdEcdsaSession should not be called when warm PRF is absent');
      },
    });

    await expect(
      store.provisionEcdsaCapability({
        nearAccountId: 'bootstrap-error.testnet',
        subjectId: toWalletSubjectId('bootstrap-error.testnet'),
        chainTarget: testEcdsaChainTarget('evm'),
        source: 'manual-bootstrap',
        sessionKind: 'jwt',
        sessionId: record.thresholdSessionId,
        walletSigningSessionId: record.walletSigningSessionId,
        thresholdSessionAuth: {
          kind: 'threshold_session',
          jwt: 'jwt:bootstrap-error-session',
        },
      }),
    ).rejects.toThrow(
      'Missing warm PRF material for threshold-ecdsa restored-session bootstrap (missing)',
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
      sessionAuthToken: 'jwt:reconnect-error-stale-session',
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
      listThresholdEcdsaKeyRefsForAccountTarget: () => [
        { source: 'login', keyRef: staleBootstrap.thresholdEcdsaKeyRef },
      ],
      provisionThresholdEcdsaSession: async ({ nearAccountId, chainTarget }) => {
        return createThresholdEcdsaBootstrapFixture({
          nearAccountId: String(nearAccountId),
          chain: chainTarget.kind,
          ecdsaThresholdKeyId: 'ek-reconnect-error',
          sessionId: 'reconnect-error-fresh-session',
          sessionAuthToken: 'jwt:reconnect-error-fresh-session',
        });
      },
    });

    await expect(
      store.ensureEcdsaCapabilityReady({
        nearAccountId: 'reconnect-error.testnet',
        chain: 'evm',
        usesNeeded: 1,
        sessionBudgetUses: 1,
        clientRootShare32B64u: 'reconnect-error-client-root-share',
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
        sessionAuthToken: 'jwt:seal-error-session',
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
        sessionAuthToken: 'jwt:signing-exhausted-session',
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
        nearAccountId: 'signing-exhausted.testnet',
        chainTarget: testEcdsaChainTarget('evm'),
        thresholdSessionId: 'signing-exhausted-session',
        usesNeeded: 2,
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
        nearAccountId: 'auth-unavailable.testnet',
        usesNeeded: 1,
        operationLabel: 'unit-test',
      }),
    ).rejects.toThrow(THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR);
  });

  test('fails closed when Ed25519 signing-session status is unavailable', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    seedEd25519WarmSessionRecord({
      nearAccountId: 'status-unavailable.testnet',
      thresholdSessionId: 'status-unavailable-session',
      walletSigningSessionId: 'status-unavailable-wallet-session',
      thresholdSessionAuthToken: 'jwt:status-unavailable-session',
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
        nearAccountId: 'status-unavailable.testnet',
        usesNeeded: 1,
        operationLabel: 'unit-test',
      }),
    ).rejects.toThrow(`${THRESHOLD_SESSION_STATUS_UNAVAILABLE_ERROR} (worker_error)`);
  });

  test('plans passkey reauth when wallet signing budget is exhausted but Ed25519 material is warm', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    seedEd25519WarmSessionRecord({
      nearAccountId: 'wallet-budget-exhausted-ed25519.testnet',
      thresholdSessionId: 'wallet-budget-exhausted-ed25519-session',
      walletSigningSessionId: 'wallet-budget-exhausted-ed25519-wallet-session',
      thresholdSessionAuthToken: 'jwt:wallet-budget-exhausted-ed25519-session',
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
      nearAccountId: 'wallet-budget-exhausted-ed25519.testnet',
      usesNeeded: 1,
      operationLabel: 'unit-test',
    });

    expect(plan.signingAuthPlan?.kind).toBe(SigningAuthPlanKind.PasskeyReauth);
    expect(plan.warmSessionReady).toBe(false);
  });
});
