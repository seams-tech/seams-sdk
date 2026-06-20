import { expect, test } from '@playwright/test';
import {
  createWarmSessionTestServices,
  createThresholdEcdsaStoreFixture,
  createWarmSessionUiConfirmFixture,
  createWarmSessionStatusReader,
  resetWarmSessionFixtureState,
  seedEd25519WarmSessionRecord,
  seedEcdsaWarmSessionRecord,
  testEcdsaChainTarget,
} from './helpers/warmSessionStore.fixtures';

test.describe('WarmSessionStore lifecycle', () => {
  test('returns an empty envelope when no warm-session records exist', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionStatusReader({}),
    });
    const warmSession = await store.getWarmSession('empty.testnet');

    expect(warmSession.walletId).toBe('empty.testnet');
    expect(warmSession.capabilities.ed25519.state).toBe('missing');
    expect(warmSession.capabilities.ed25519.record).toBeNull();
    expect(warmSession.capabilities.ecdsa.evm.state).toBe('missing');
    expect(warmSession.capabilities.ecdsa.evm.record).toBeNull();
    expect(warmSession.capabilities.ecdsa.tempo.state).toBe('missing');
    expect(warmSession.capabilities.ecdsa.tempo.record).toBeNull();
  });

  test('returns a ready Ed25519 capability when session auth and claim state are warm', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'ed25519-only.testnet',
      thresholdSessionId: 'ed25519-session-1',
      walletSessionJwt: 'jwt:ed25519-session-1',
      runtimeValidated: true,
      remainingUses: 9,
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
    const warmSession = await store.getWarmSession(ed25519Record.nearAccountId);

    expect(warmSession.capabilities.ed25519.state).toBe('ready');
    expect(warmSession.capabilities.ed25519.auth?.walletSessionJwt).toBe('jwt:ed25519-session-1');
    expect(warmSession.capabilities.ed25519.prfClaim).toMatchObject({
      state: 'warm',
      sessionId: 'ed25519-session-1',
      remainingUses: 9,
    });
    expect(warmSession.capabilities.ecdsa.evm.state).toBe('missing');
    expect(warmSession.capabilities.ecdsa.tempo.state).toBe('missing');
  });

  test('does not treat cookie passkey Ed25519 records as ready signing auth', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'cookie-ed25519.testnet',
      thresholdSessionId: 'cookie-ed25519-session',
      thresholdSessionKind: 'cookie',
      remainingUses: 5,
    });

    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionStatusReader({
        [ed25519Record.thresholdSessionId]: {
          state: 'missing',
        },
      }),
    });
    const warmSession = await store.getWarmSession(ed25519Record.nearAccountId);

    expect(warmSession.capabilities.ed25519.state).toBe('auth_missing');
    expect(warmSession.capabilities.ed25519.auth?.walletSessionJwtSource).toBe('none');
    expect(warmSession.capabilities.ed25519.prfClaim).toMatchObject({
      state: 'missing',
      sessionId: 'cookie-ed25519-session',
    });
  });

  test('keeps trusted exhausted Email OTP Ed25519 status terminal after reload', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'email-otp-exhausted.testnet',
      thresholdSessionId: 'email-otp-exhausted-session',
      walletSessionJwt: 'jwt:email-otp-exhausted-session',
      source: 'email_otp',
      remainingUses: 3,
    });
    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionStatusReader({
        [ed25519Record.thresholdSessionId]: {
          state: 'exhausted',
        },
      }),
    });

    const status = await store.getEd25519SigningSessionStatusForSession({
      nearAccountId: ed25519Record.nearAccountId,
      thresholdSessionId: ed25519Record.thresholdSessionId,
    });

    expect(status).toMatchObject({
      sessionId: ed25519Record.thresholdSessionId,
      status: 'exhausted',
      authMethod: 'email_otp',
      retention: 'session',
    });
  });

  test('does not restore an exhausted Email OTP Ed25519 record as active', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'email-otp-record-exhausted.testnet',
      thresholdSessionId: 'email-otp-record-exhausted-session',
      walletSessionJwt: 'jwt:email-otp-record-exhausted-session',
      source: 'email_otp',
      remainingUses: 0,
    });
    const store = createWarmSessionTestServices({
      getEmailOtpWarmSessionStatus: async () => ({
        ok: false,
        code: 'not_found',
        message: 'worker session missing after reload',
      }),
    });

    const status = await store.getEd25519SigningSessionStatusForSession({
      nearAccountId: ed25519Record.nearAccountId,
      thresholdSessionId: ed25519Record.thresholdSessionId,
    });

    expect(status).toMatchObject({
      sessionId: ed25519Record.thresholdSessionId,
      status: 'exhausted',
      remainingUses: 0,
      authMethod: 'email_otp',
      retention: 'session',
    });
  });

  test('uses batch warm-session status reads when the touchConfirm snapshot reader is available', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'batch-status.testnet',
      thresholdSessionId: 'batch-ed25519-session',
      walletSessionJwt: 'jwt:batch-ed25519-session',
      runtimeValidated: true,
      remainingUses: 9,
    });
    const evmRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'batch-status.testnet',
      chain: 'evm',
      source: 'login',
    });
    const tempoRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'batch-status.testnet',
      chain: 'tempo',
      source: 'login',
    });

    let batchCalls = 0;
    let singleReads = 0;
    const statusBySessionId = {
      [ed25519Record.thresholdSessionId]: {
        ok: true as const,
        remainingUses: ed25519Record.remainingUses,
        expiresAtMs: ed25519Record.expiresAtMs,
      },
      [evmRecord.thresholdSessionId]: {
        ok: true as const,
        remainingUses: evmRecord.remainingUses || 5,
        expiresAtMs: evmRecord.expiresAtMs || Date.now() + 120_000,
      },
      [tempoRecord.thresholdSessionId]: {
        ok: false as const,
        code: 'not_found',
        message: 'missing',
      },
    };

    const store = createWarmSessionTestServices({
      touchConfirm: {
        getWarmSessionStatus: async () => {
          singleReads += 1;
          return { ok: false, code: 'worker_error', message: 'should not be called' };
        },
        getWarmSessionStatuses: async ({ sessionIds }) => {
          batchCalls += 1;
          return {
            results: sessionIds.map((sessionId) => ({
              sessionId,
              result: statusBySessionId[sessionId as keyof typeof statusBySessionId] || {
                ok: false as const,
                code: 'not_found',
                message: 'missing',
              },
            })),
          };
        },
      },
    });

    const warmSession = await store.getWarmSession('batch-status.testnet');

    expect(batchCalls).toBe(1);
    expect(singleReads).toBe(0);
    expect(warmSession.capabilities.ed25519.state).toBe('ready');
    expect(warmSession.capabilities.ecdsa.evm.state).toBe('ready');
    expect(warmSession.capabilities.ecdsa.tempo.state).toBe('ready');
    expect(warmSession.capabilities.ecdsa.tempo.prfClaim).toMatchObject({
      state: 'warm',
      sessionId: tempoRecord.thresholdSessionId,
    });
  });

  test('returns a ready ECDSA capability and keeps the other chain missing', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const evmRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'ecdsa-only.testnet',
      chain: 'evm',
      source: 'login',
    });

    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionStatusReader({
        [evmRecord.thresholdSessionId]: {
          state: 'warm',
          remainingUses: evmRecord.remainingUses || 5,
          expiresAtMs: evmRecord.expiresAtMs || Date.now() + 120_000,
        },
      }),
    });
    const warmSession = await store.getWarmSession(evmRecord.walletId);

    expect(warmSession.capabilities.ecdsa.evm.state).toBe('ready');
    expect(warmSession.capabilities.ecdsa.evm.auth?.walletSessionJwt).toBe(
      evmRecord.walletSessionJwt,
    );
    expect(warmSession.capabilities.ecdsa.evm.prfClaim).toMatchObject({
      state: 'warm',
      sessionId: evmRecord.thresholdSessionId,
    });
    expect(warmSession.capabilities.ecdsa.tempo.state).toBe('missing');
    expect(warmSession.capabilities.ed25519.state).toBe('missing');
  });

  test('returns a dual-capability envelope with mixed readiness per capability', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'dual.testnet',
      thresholdSessionId: 'ed25519-dual-session',
      walletSessionJwt: 'jwt:ed25519-dual-session',
      runtimeValidated: true,
      remainingUses: 6,
    });
    const evmRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'dual.testnet',
      chain: 'evm',
      source: 'login',
    });
    const tempoRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'dual.testnet',
      chain: 'tempo',
      source: 'manual-bootstrap',
    });

    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionStatusReader({
        [ed25519Record.thresholdSessionId]: {
          state: 'warm',
          remainingUses: ed25519Record.remainingUses,
          expiresAtMs: ed25519Record.expiresAtMs,
        },
        [evmRecord.thresholdSessionId]: {
          state: 'warm',
          remainingUses: evmRecord.remainingUses || 5,
          expiresAtMs: evmRecord.expiresAtMs || Date.now() + 120_000,
        },
        [tempoRecord.thresholdSessionId]: {
          state: 'missing',
        },
      }),
    });
    const warmSession = await store.getWarmSession('dual.testnet');

    expect(warmSession.capabilities.ed25519.state).toBe('ready');
    expect(warmSession.capabilities.ecdsa.evm.state).toBe('ready');
    expect(warmSession.capabilities.ecdsa.tempo.state).toBe('ready');
    expect(warmSession.capabilities.ecdsa.tempo.auth?.walletSessionJwtSource).toBe('ecdsa_record');
    expect(warmSession.capabilities.ecdsa.tempo.prfClaim).toMatchObject({
      state: 'warm',
      sessionId: tempoRecord.thresholdSessionId,
    });
  });

  test('resolves ECDSA seal transport from the warm-session record', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const evmRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'seal-hints.testnet',
      chain: 'evm',
      signingSessionSeal: {
        keyVersion: 'kek-s-2026-02',
        shamirPrimeB64u: 'AQAB',
      },
    });

    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionStatusReader({
        [evmRecord.thresholdSessionId]: {
          state: 'warm',
          remainingUses: evmRecord.remainingUses || 5,
          expiresAtMs: evmRecord.expiresAtMs || Date.now() + 120_000,
        },
      }),
    });

    expect(
      store.resolveEcdsaSealTransportByThresholdSessionId({
        thresholdSessionId: evmRecord.thresholdSessionId,
        chainTarget: testEcdsaChainTarget('evm'),
      }),
    ).toMatchObject({
      curve: 'ecdsa',
      relayerUrl: evmRecord.relayerUrl,
      walletSessionJwt: evmRecord.walletSessionJwt,
      walletSessionJwtSource: 'ecdsa',
      keyVersion: 'kek-s-2026-02',
      shamirPrimeB64u: 'AQAB',
    });
  });

  test('passes full ECDSA seal transport when persisting a warm-session seal', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const evmRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'seal-persist.testnet',
      chain: 'evm',
      signingSessionSeal: {
        keyVersion: 'kek-s-2026-02',
        shamirPrimeB64u: 'AQAB',
      },
    });
    const touchConfirmFixture = createWarmSessionUiConfirmFixture({
      claimsBySessionId: {
        [evmRecord.thresholdSessionId]: {
          state: 'warm',
          remainingUses: evmRecord.remainingUses || 5,
          expiresAtMs: evmRecord.expiresAtMs || Date.now() + 120_000,
        },
      },
      sealAndPersistResultBySessionId: {
        [evmRecord.thresholdSessionId]: {
          ok: true,
          sealedSecretB64u: 'sealed-prf-first',
          keyVersion: 'kek-s-2026-02',
          remainingUses: evmRecord.remainingUses || 5,
          expiresAtMs: evmRecord.expiresAtMs || Date.now() + 120_000,
        },
      },
    });

    const store = createWarmSessionTestServices({
      touchConfirm: touchConfirmFixture.touchConfirm,
    });

    await store.ensureEcdsaPrfSealPersistedByThresholdSessionId({
      chain: 'evm',
      thresholdSessionId: evmRecord.thresholdSessionId,
      required: true,
      errorContext: 'test ECDSA seal persistence',
    });

    expect(touchConfirmFixture.sealCalls).toHaveLength(1);
    expect(touchConfirmFixture.sealCalls[0]).toMatchObject({
      sessionId: evmRecord.thresholdSessionId,
      transport: {
        relayerUrl: evmRecord.relayerUrl,
        walletSessionJwt: evmRecord.walletSessionJwt,
        keyVersion: 'kek-s-2026-02',
        shamirPrimeB64u: 'AQAB',
      },
    });
  });
});
