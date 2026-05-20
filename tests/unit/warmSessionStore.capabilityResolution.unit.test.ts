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

test.describe('WarmSessionStore capability resolution', () => {
  test('resolves Ed25519 auth material from the canonical Ed25519 record', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'ed-auth.testnet',
      thresholdSessionId: 'ed-auth-session',
      thresholdSessionAuthToken: 'jwt:ed-auth-session',
    });

    const store = createWarmSessionTestServices();
    const auth = store.resolveEd25519AuthByThresholdSessionId(ed25519Record.thresholdSessionId);

    expect(auth).toMatchObject({
      capability: 'ed25519',
      thresholdSessionAuthToken: 'jwt:ed-auth-session',
      thresholdSessionAuthTokenSource: 'ed25519',
    });
  });

  test('resolves a cookie-backed Ed25519 capability without borrowing JWT state', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'ed-missing-auth.testnet',
      thresholdSessionId: 'ed-missing-auth-session',
      thresholdSessionKind: 'cookie',
    });

    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionStatusReader({
        [ed25519Record.thresholdSessionId]: {
          state: 'warm',
          remainingUses: ed25519Record.remainingUses,
          expiresAtMs: ed25519Record.expiresAtMs,
        },
      }),
    });
    const capability = await store.getEd25519CapabilityByThresholdSessionId(
      ed25519Record.thresholdSessionId,
    );

    expect(capability?.state).toBe('ready');
    expect(capability?.auth?.thresholdSessionAuthToken).toBeUndefined();
    expect(capability?.auth?.thresholdSessionAuthTokenSource).toBe('none');
    expect(capability?.prfClaim?.state).toBe('warm');
  });

  test('resolves ECDSA auth material from the ECDSA record without borrowing Ed25519 JWT state', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    seedEd25519WarmSessionRecord({
      nearAccountId: 'ecdsa-auth.testnet',
      thresholdSessionId: 'ed-fallback-session',
      thresholdSessionAuthToken: 'jwt:ed-fallback-session',
    });
    const evmRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'ecdsa-auth.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'ecdsa-auth.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-ecdsa-auth',
        sessionId: 'ecdsa-auth-session',
        sessionKind: 'cookie',
      }),
    });

    const store = createWarmSessionTestServices();
    const auth = store.resolveEcdsaAuthByThresholdSessionId(evmRecord.thresholdSessionId);

    expect(auth).toMatchObject({
      capability: 'ecdsa',
      thresholdSessionAuthTokenSource: 'none',
    });
    expect(auth?.thresholdSessionAuthToken).toBeUndefined();
  });

  test('surfaces explicit Email OTP auth context on warm ECDSA capability state', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const evmRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'email-otp-auth-state.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'email-otp-auth-state.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-email-otp',
        sessionId: 'ecdsa-email-otp-session',
        sessionAuthToken: 'jwt:ecdsa-email-otp-session',
      }),
    });

    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionStatusReader({
        [evmRecord.thresholdSessionId]: {
          state: 'warm',
          remainingUses: evmRecord.remainingUses || 1,
          expiresAtMs: evmRecord.expiresAtMs || Date.now() + 60_000,
        },
      }),
    });

    const warmSession = await store.getWarmSession('email-otp-auth-state.testnet');
    expect(warmSession.capabilities.ecdsa.evm.emailOtpAuthContext).toEqual({
      policy: 'per_operation',
      retention: 'single_use',
      reason: 'login',
      authMethod: 'email_otp',
    });
  });

  test('keeps exhausted Email OTP ECDSA records available for OTP reauth', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const evmRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'email-otp-exhausted-reauth.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'email-otp-exhausted-reauth.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-email-otp-exhausted',
        sessionId: 'ecdsa-email-otp-exhausted-session',
        sessionAuthToken: 'jwt:ecdsa-email-otp-exhausted-session',
      }),
    });
    let clearCount = 0;
    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionStatusReader({
        [evmRecord.thresholdSessionId]: {
          state: 'exhausted',
        },
      }),
      clearThresholdEcdsaSessionRecordForWalletTarget: () => {
        clearCount += 1;
      },
    });

    const warmSession = await store.getWarmSession('email-otp-exhausted-reauth.testnet');
    const capability = warmSession.capabilities.ecdsa.evm;

    expect(clearCount).toBe(0);
    expect(capability.record?.thresholdSessionId).toBe(evmRecord.thresholdSessionId);
    expect(capability.emailOtpAuthContext).toEqual({
      policy: 'session',
      retention: 'session',
      reason: 'login',
      authMethod: 'email_otp',
    });
    expect(
      store.resolveEcdsaAuthByThresholdSessionId(evmRecord.thresholdSessionId),
    ).toMatchObject({
      capability: 'ecdsa',
      thresholdSessionAuthToken: expect.any(String),
    });
  });

  test('bootstrap request resolution only inherits session auth from a warm primary ECDSA capability', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const staleRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'bootstrap-selection.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'bootstrap-selection.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-shared-bootstrap',
        sessionId: 'ecdsa-stale-session',
        sessionAuthToken: 'jwt:ecdsa-stale-session',
      }),
    });
    const warmRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'bootstrap-selection.testnet',
      chain: 'tempo',
      source: 'manual-bootstrap',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'bootstrap-selection.testnet',
        chain: 'tempo',
        ecdsaThresholdKeyId: 'ek-shared-bootstrap',
        sessionId: 'ecdsa-warm-session',
        sessionAuthToken: 'jwt:ecdsa-warm-session',
      }),
    });

    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionStatusReader({
        [staleRecord.thresholdSessionId]: {
          state: 'missing',
        },
        [warmRecord.thresholdSessionId]: {
          state: 'warm',
          remainingUses: warmRecord.remainingUses || 5,
          expiresAtMs: warmRecord.expiresAtMs || Date.now() + 120_000,
        },
      }),
    });

    const evmBootstrap = await store.resolveEcdsaBootstrapRequest({
      nearAccountId: 'bootstrap-selection.testnet',
      chain: 'evm',
    });
    const tempoBootstrap = await store.resolveEcdsaBootstrapRequest({
      nearAccountId: 'bootstrap-selection.testnet',
      chain: 'tempo',
    });

    expect('sessionId' in evmBootstrap).toBe(false);
    expect('thresholdSessionAuth' in evmBootstrap).toBe(false);
    expect(tempoBootstrap).toMatchObject({
      kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap',
      keyHandle: warmRecord.keyHandle,
      key: {
        ecdsaThresholdKeyId: warmRecord.ecdsaThresholdKeyId,
      },
      lanePolicy: {
        chainTarget: {
          kind: 'tempo',
        },
        thresholdSessionId: 'ecdsa-warm-session',
        walletSigningSessionId: 'wsess-ecdsa-warm-session',
      },
      routeAuth: {
        kind: 'threshold_session',
        jwt: expect.any(String),
      },
    });
  });

});
