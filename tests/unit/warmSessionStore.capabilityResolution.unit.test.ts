import { expect, test } from '@playwright/test';
import { toExactEcdsaSigningLaneIdentity } from '@/core/signingEngine/session/persistence/records';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '@/core/signingEngine/session/identity/laneIdentity';
import { createWarmSessionTestServices } from './helpers/warmSessionTestServices.fixtures';
import { createWarmSessionStatusReader } from './helpers/warmSessionUiConfirm.fixtures';
import {
  createThresholdEcdsaStoreFixture,
  resetWarmSessionFixtureState,
  seedEd25519WarmSessionRecord,
  seedEcdsaWarmSessionRecord,
} from './helpers/signingSessionRecord.fixtures';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';

const FIXTURE_EMAIL_HASH_HEX = '22'.repeat(32);

function emailOtpSessionContext(providerUserId: string) {
  return buildEmailOtpAuthContextForWalletAuthMethod({
    policy: 'session',
    walletId: providerUserId,
    emailHashHex: FIXTURE_EMAIL_HASH_HEX,
    retention: 'session',
    reason: 'login',
    provider: 'email',
    providerUserId,
  });
}

function emailOtpSingleUseSignContext(providerUserId: string) {
  return buildEmailOtpAuthContextForWalletAuthMethod({
    policy: 'per_operation',
    walletId: providerUserId,
    emailHashHex: FIXTURE_EMAIL_HASH_HEX,
    retention: 'single_use',
    provider: 'email',
    providerUserId,
  });
}

test.describe('WarmSessionStore capability resolution', () => {
  test('resolves Ed25519 auth material from the canonical Ed25519 record', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'ed-auth.testnet',
      thresholdSessionId: 'ed-wallet-session',
      walletSessionJwt: 'jwt:ed-wallet-session',
    });

    const store = createWarmSessionTestServices();
    const auth = store.resolveEd25519AuthByThresholdSessionId(ed25519Record.thresholdSessionId);

    expect(auth).toMatchObject({
      capability: 'ed25519',
      walletSessionJwt: ed25519Record.walletSessionJwt,
      walletSessionJwtSource: 'ed25519_record',
    });
  });

  test('reports cookie-backed Ed25519 capability as auth_missing without borrowing JWT state', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'ed-missing-auth.testnet',
      thresholdSessionId: 'ed-missing-wallet-session',
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

    expect(capability?.state).toBe('auth_missing');
    expect(capability?.auth).toMatchObject({
      capability: 'ed25519',
      walletSessionJwtSource: 'none',
    });
    expect(capability?.auth?.walletSessionJwt).toBeUndefined();
    expect(capability?.prfClaim?.state).toBe('warm');
  });

  test('resolves ECDSA auth material from the ECDSA record without borrowing Ed25519 JWT state', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    seedEd25519WarmSessionRecord({
      nearAccountId: 'ecdsa-auth.testnet',
      thresholdSessionId: 'ed-fallback-session',
      walletSessionJwt: 'jwt:ed-fallback-session',
    });
    const evmRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'ecdsa-auth.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'ecdsa-auth.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-ecdsa-auth',
        sessionId: 'ecdsa-wallet-session',
        walletSessionJwt: 'jwt:ecdsa-wallet-session',
      }),
    });

    const store = createWarmSessionTestServices();
    const auth = store.resolveEcdsaAuthByThresholdSessionId(evmRecord.thresholdSessionId);

    expect(auth).toMatchObject({
      capability: 'ecdsa',
      walletSessionJwtSource: 'ecdsa_record',
    });
    expect(auth?.walletSessionJwt).toBeTruthy();
    expect(auth?.walletSessionJwt).not.toBe('jwt:ed-fallback-session');
  });

  test('surfaces explicit Email OTP auth context on material-pending ECDSA capability state', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const evmRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'email-otp-auth-state.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: emailOtpSingleUseSignContext('email-otp-auth-state.testnet'),
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'email-otp-auth-state.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-email-otp',
        sessionId: 'ecdsa-email-otp-session',
        walletSessionJwt: 'jwt:ecdsa-email-otp-session',
        roleLocalAuthMethod: 'email_otp',
        emailOtpAuthSubjectId: 'email-otp-auth-state.testnet',
      }),
    });

    const store = createWarmSessionTestServices();

    const warmSession = await store.getWarmSession(evmRecord.walletId);
    expect(warmSession.capabilities.ecdsa.evm.state).toBe('material_pending');
    expect(warmSession.capabilities.ecdsa.evm.prfClaim).toMatchObject({
      state: 'warm',
      sessionId: evmRecord.thresholdSessionId,
      remainingUses: evmRecord.remainingUses,
      expiresAtMs: evmRecord.expiresAtMs,
    });
    expect(warmSession.capabilities.ecdsa.evm.emailOtpAuthContext).toEqual(
      emailOtpSingleUseSignContext('email-otp-auth-state.testnet'),
    );
  });

  test('keeps exhausted Email OTP ECDSA records available for OTP reauth', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const evmRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'email-otp-exhausted-reauth.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: emailOtpSessionContext('email-otp-exhausted-reauth.testnet'),
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'email-otp-exhausted-reauth.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-email-otp-exhausted',
        sessionId: 'ecdsa-email-otp-exhausted-session',
        walletSessionJwt: 'jwt:ecdsa-email-otp-exhausted-session',
      }),
    });
    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionStatusReader({
        [evmRecord.thresholdSessionId]: {
          state: 'exhausted',
        },
      }),
    });

    const warmSession = await store.getWarmSession(evmRecord.walletId);
    const capability = warmSession.capabilities.ecdsa.evm;

    expect(capability.record?.thresholdSessionId).toBe(evmRecord.thresholdSessionId);
    expect(capability.emailOtpAuthContext).toEqual(
      emailOtpSessionContext('email-otp-exhausted-reauth.testnet'),
    );
    expect(store.resolveEcdsaAuthByThresholdSessionId(evmRecord.thresholdSessionId)).toMatchObject({
      capability: 'ecdsa',
      walletSessionJwt: expect.any(String),
    });
    expect(
      store.resolveEmailOtpEcdsaSigningSessionAuthority({
        lane: toExactEcdsaSigningLaneIdentity(evmRecord),
      }),
    ).toMatchObject({
      authLane: {
        kind: 'signing_session',
        jwt: evmRecord.walletSessionJwt,
        thresholdSessionId: evmRecord.thresholdSessionId,
        curve: 'ecdsa',
        chainTarget: evmRecord.chainTarget,
      },
      authority: evmRecord.emailOtpAuthContext?.authority,
    });
  });

  test('does not resolve Email OTP ECDSA signing authority when Wallet Session JWT is missing', () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const evmRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'email-otp-missing-jwt-authority.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: emailOtpSessionContext('email-otp-missing-jwt-authority.testnet'),
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'email-otp-missing-jwt-authority.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-email-otp-missing-jwt',
        sessionId: 'ecdsa-email-otp-missing-jwt-session',
        walletSessionJwt: 'jwt:ecdsa-email-otp-missing-jwt-session',
        roleLocalAuthMethod: 'email_otp',
        emailOtpAuthSubjectId: 'email-otp-missing-jwt-authority.testnet',
      }),
    });
    const lane = toExactEcdsaSigningLaneIdentity(evmRecord);
    evmRecord.walletSessionJwt = '';

    const store = createWarmSessionTestServices();

    expect(store.resolveEcdsaAuthByThresholdSessionId(evmRecord.thresholdSessionId)).toMatchObject({
      capability: 'ecdsa',
      state: 'unavailable',
      walletSessionJwtSource: 'none',
    });
    expect(
      store.resolveEmailOtpEcdsaSigningSessionAuthority({
        lane,
      }),
    ).toBeNull();
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
        walletSessionJwt: 'jwt:ecdsa-stale-session',
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
        walletSessionJwt: 'jwt:ecdsa-warm-session',
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
    expect('walletSessionRouteAuth' in evmBootstrap).toBe(false);
    expect(tempoBootstrap).toMatchObject({
      kind: 'reuse_warm_ecdsa_bootstrap',
    });
  });
});
