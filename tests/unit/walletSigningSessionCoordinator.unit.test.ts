import { expect, test } from '@playwright/test';
import { createWalletSigningSessionCoordinator } from '@/core/signingEngine/session/WalletSigningSessionCoordinator';
import { upsertStoredThresholdEcdsaSessionRecord } from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import {
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionStatusReader,
  resetWarmSessionFixtureState,
  seedEd25519WarmSessionRecord,
  seedEcdsaWarmSessionRecord,
  type WarmClaimFixture,
} from './helpers/warmSessionManager.fixtures';

function createMutableTouchConfirmStatus(claimsBySessionId: Record<string, WarmClaimFixture>) {
  const reader = createWarmSessionStatusReader(claimsBySessionId);
  const consumeCalls: Array<{ sessionId: string; uses?: number }> = [];
  return {
    consumeCalls,
    touchConfirm: {
      ...reader,
      consumeWarmSessionUses: async (args: { sessionId: string; uses?: number }) => {
        consumeCalls.push(args);
        const sessionId = String(args.sessionId || '').trim();
        const claim = claimsBySessionId[sessionId];
        if (!claim || claim.state !== 'warm') {
          return { ok: false as const, code: 'not_found', message: 'missing' };
        }
        const uses = Math.max(1, Math.floor(Number(args.uses) || 1));
        claim.remainingUses = Math.max(0, claim.remainingUses - uses);
        if (claim.remainingUses <= 0) {
          claimsBySessionId[sessionId] = { state: 'exhausted' };
          return { ok: false as const, code: 'exhausted', message: 'exhausted' };
        }
        return {
          ok: true as const,
          remainingUses: claim.remainingUses,
          expiresAtMs: claim.expiresAtMs,
        };
      },
    },
  };
}

test.describe('WalletSigningSessionCoordinator', () => {
  test('reports one shared Email OTP budget across Ed25519 and ECDSA lanes', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const expiresAtMs = Date.now() + 120_000;
    const walletSigningSessionId = 'ws-email-shared-status';

    seedEd25519WarmSessionRecord({
      nearAccountId: 'email-shared-status.testnet',
      thresholdSessionId: 'ed-email-status',
      walletSigningSessionId,
      thresholdSessionJwt: 'jwt:ed-email-status',
      remainingUses: 5,
      expiresAtMs,
      xClientBaseB64u: 'x-client-base',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
    });
    const ecdsaRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'email-shared-status.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'email-shared-status.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-email-status',
        sessionId: 'ecdsa-email-status',
        sessionJwt: 'jwt:ecdsa-email-status',
        walletSigningSessionId,
      }),
    });
    upsertStoredThresholdEcdsaSessionRecord(ecdsaStore, {
      ...ecdsaRecord,
      clientAdditiveShareHandle: {
        kind: 'email_otp_worker_session',
        sessionId: 'email-worker-status',
      },
    });

    const { touchConfirm } = createMutableTouchConfirmStatus({
      'ed-email-status': { state: 'warm', remainingUses: 5, expiresAtMs },
    });
    const coordinator = createWalletSigningSessionCoordinator({
      touchConfirm,
      getThresholdEcdsaSessionRecordForSigning: ({ chain }) =>
        chain === 'evm' ? (ecdsaStore.recordsByLane.values().next().value ?? null) : null,
      getEmailOtpWarmSessionStatus: async (sessionId) => {
        expect(sessionId).toBe('email-worker-status');
        return { ok: true, remainingUses: 3, expiresAtMs };
      },
    });

    const status = await coordinator.getStatus({
      nearAccountId: 'email-shared-status.testnet',
      walletSigningSessionId,
    });
    const claims = await coordinator.getLaneClaimsForAccount('email-shared-status.testnet');

    expect(status).toMatchObject({
      sessionId: walletSigningSessionId,
      status: 'active',
      authMethod: 'email_otp',
      retention: 'session',
      remainingUses: 3,
    });
    expect(claims.get('ed-email-status')).toMatchObject({
      state: 'warm',
      remainingUses: 3,
    });
    expect(claims.get('ecdsa-email-status')).toMatchObject({
      state: 'warm',
      remainingUses: 3,
    });
  });

  test('does not double-consume the ECDSA Email OTP worker lane after ECDSA signing consumed it', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const expiresAtMs = Date.now() + 120_000;
    const walletSigningSessionId = 'ws-email-ecdsa-consume';

    seedEd25519WarmSessionRecord({
      nearAccountId: 'email-ecdsa-consume.testnet',
      thresholdSessionId: 'ed-email-consume',
      walletSigningSessionId,
      thresholdSessionJwt: 'jwt:ed-email-consume',
      remainingUses: 5,
      expiresAtMs,
      xClientBaseB64u: 'x-client-base',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
    });
    const ecdsaRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'email-ecdsa-consume.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'email-ecdsa-consume.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-email-consume',
        sessionId: 'ecdsa-email-consume',
        sessionJwt: 'jwt:ecdsa-email-consume',
        walletSigningSessionId,
      }),
    });
    upsertStoredThresholdEcdsaSessionRecord(ecdsaStore, {
      ...ecdsaRecord,
      clientAdditiveShareHandle: {
        kind: 'email_otp_worker_session',
        sessionId: 'email-worker-consume',
      },
    });

    const { touchConfirm, consumeCalls } = createMutableTouchConfirmStatus({
      'ed-email-consume': { state: 'warm', remainingUses: 5, expiresAtMs },
    });
    const emailOtpConsumeCalls: Array<{ sessionId: string; uses?: number }> = [];
    const markCalls: Array<{ thresholdSessionId?: string; uses?: number }> = [];
    const coordinator = createWalletSigningSessionCoordinator({
      touchConfirm,
      getThresholdEcdsaSessionRecordForSigning: ({ chain }) =>
        chain === 'evm' ? (ecdsaStore.recordsByLane.values().next().value ?? null) : null,
      getEmailOtpWarmSessionStatus: async () => ({
        ok: true,
        remainingUses: 4,
        expiresAtMs,
      }),
      consumeEmailOtpWarmSessionUses: async (args) => {
        emailOtpConsumeCalls.push(args);
        return { ok: true, remainingUses: 4, expiresAtMs };
      },
      markThresholdEd25519EmailOtpSessionConsumedForAccount: (args) => {
        markCalls.push({
          thresholdSessionId: args.thresholdSessionId,
          uses: args.uses,
        });
      },
    });

    await coordinator.consumeUse({
      nearAccountId: 'email-ecdsa-consume.testnet',
      walletSigningSessionId,
      uses: 1,
      reason: 'transaction_sign',
      alreadyConsumedThresholdSessionIds: ['ecdsa-email-consume'],
    });

    expect(emailOtpConsumeCalls).toEqual([]);
    expect(consumeCalls).toEqual([{ sessionId: 'ed-email-consume', uses: 1 }]);
    expect(markCalls).toEqual([{ thresholdSessionId: 'ed-email-consume', uses: 1 }]);
  });

  test('syncs the sealed-refresh record to the shared Email OTP budget after Ed25519 signing', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const expiresAtMs = Date.now() + 120_000;
    const walletSigningSessionId = 'ws-email-sealed-sync';
    const ed25519ThresholdSessionId = 'ed-email-sealed-sync';
    const ecdsaThresholdSessionId = 'ecdsa-email-sealed-sync';

    seedEd25519WarmSessionRecord({
      nearAccountId: 'email-sealed-sync.testnet',
      thresholdSessionId: ed25519ThresholdSessionId,
      walletSigningSessionId,
      thresholdSessionJwt: 'jwt:ed-email-sealed-sync',
      remainingUses: 5,
      expiresAtMs,
      xClientBaseB64u: 'x-client-base',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
    });
    const ecdsaRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'email-sealed-sync.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'email-sealed-sync.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-email-sealed-sync',
        sessionId: ecdsaThresholdSessionId,
        sessionJwt: 'jwt:ecdsa-email-sealed-sync',
        walletSigningSessionId,
      }),
    });
    upsertStoredThresholdEcdsaSessionRecord(ecdsaStore, {
      ...ecdsaRecord,
      clientAdditiveShareHandle: {
        kind: 'email_otp_worker_session',
        sessionId: 'email-worker-sealed-sync',
      },
    });

    const { touchConfirm } = createMutableTouchConfirmStatus({
      [ed25519ThresholdSessionId]: { state: 'warm', remainingUses: 5, expiresAtMs },
    });
    const sealedPolicyUpdates: Array<{
      thresholdSessionId: string;
      remainingUses?: number;
      expiresAtMs?: number;
    }> = [];
    const coordinator = createWalletSigningSessionCoordinator({
      touchConfirm,
      getThresholdEcdsaSessionRecordForSigning: ({ chain }) =>
        chain === 'evm' ? (ecdsaStore.recordsByLane.values().next().value ?? null) : null,
      getEmailOtpWarmSessionStatus: async () => ({
        ok: true,
        remainingUses: 4,
        expiresAtMs,
      }),
      consumeEmailOtpWarmSessionUses: async () => ({
        ok: true,
        remainingUses: 4,
        expiresAtMs,
      }),
      updateSigningSessionSealedRecordPolicy: async (args) => {
        sealedPolicyUpdates.push({
          thresholdSessionId: args.thresholdSessionId,
          remainingUses: args.remainingUses,
          expiresAtMs: args.expiresAtMs,
        });
      },
    });

    const status = await coordinator.consumeUse({
      nearAccountId: 'email-sealed-sync.testnet',
      walletSigningSessionId,
      uses: 1,
      reason: 'transaction_sign',
    });

    expect(status).toMatchObject({ status: 'active', remainingUses: 4 });
    expect(sealedPolicyUpdates).toEqual(
      expect.arrayContaining([
        { thresholdSessionId: ed25519ThresholdSessionId, remainingUses: 4, expiresAtMs },
        { thresholdSessionId: ecdsaThresholdSessionId, remainingUses: 4, expiresAtMs },
      ]),
    );
  });

  test('consumes passkey Ed25519 and ECDSA lanes through the same coordinator status path', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const expiresAtMs = Date.now() + 120_000;
    const walletSigningSessionId = 'ws-passkey-shared';

    seedEd25519WarmSessionRecord({
      nearAccountId: 'passkey-shared.testnet',
      thresholdSessionId: 'ed-passkey-shared',
      walletSigningSessionId,
      thresholdSessionJwt: 'jwt:ed-passkey-shared',
      remainingUses: 5,
      expiresAtMs,
      source: 'login',
    });
    seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'passkey-shared.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'passkey-shared.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-passkey-shared',
        sessionId: 'ecdsa-passkey-shared',
        sessionJwt: 'jwt:ecdsa-passkey-shared',
        walletSigningSessionId,
      }),
    });

    const { touchConfirm, consumeCalls } = createMutableTouchConfirmStatus({
      'ed-passkey-shared': { state: 'warm', remainingUses: 5, expiresAtMs },
      'ecdsa-passkey-shared': { state: 'warm', remainingUses: 5, expiresAtMs },
    });
    const coordinator = createWalletSigningSessionCoordinator({
      touchConfirm,
      getThresholdEcdsaSessionRecordForSigning: ({ chain }) =>
        chain === 'evm' ? (ecdsaStore.recordsByLane.values().next().value ?? null) : null,
    });

    await coordinator.consumeUse({
      nearAccountId: 'passkey-shared.testnet',
      walletSigningSessionId,
      uses: 1,
      reason: 'transaction_sign',
    });
    const status = await coordinator.getStatus({
      nearAccountId: 'passkey-shared.testnet',
      walletSigningSessionId,
    });

    expect(consumeCalls).toEqual([
      { sessionId: 'ed-passkey-shared', uses: 1 },
      { sessionId: 'ecdsa-passkey-shared', uses: 1 },
    ]);
    expect(status).toMatchObject({
      status: 'active',
      authMethod: 'passkey',
      remainingUses: 4,
    });
  });
});
