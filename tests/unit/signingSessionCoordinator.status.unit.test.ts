import { expect, test } from '@playwright/test';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import { upsertStoredThresholdEcdsaSessionRecord } from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import { readWalletScopedLaneClaimsForAccount } from '@/core/signingEngine/session/signingSession/readiness';
import {
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionStatusReader,
  resetWarmSessionFixtureState,
  seedEd25519WarmSessionRecord,
  seedEcdsaWarmSessionRecord,
  type WarmClaimFixture,
} from './helpers/warmSessionStore.fixtures';

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

test.describe('SigningSessionCoordinator', () => {
  test('read-only lane claim helper composes passkey and Email OTP worker-backed lane claims', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const expiresAtMs = Date.now() + 120_000;
    const accountId = 'readonly-lane-claims.testnet';
    const passkeyWalletSigningSessionId = 'ws-readonly-passkey';

    seedEd25519WarmSessionRecord({
      nearAccountId: accountId,
      thresholdSessionId: 'ed-readonly-passkey',
      walletSigningSessionId: passkeyWalletSigningSessionId,
      thresholdSessionJwt: 'jwt:ed-readonly-passkey',
      remainingUses: 5,
      expiresAtMs,
      source: 'login',
    });
    seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: accountId,
      chain: 'tempo',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: accountId,
        chain: 'tempo',
        ecdsaThresholdKeyId: 'ek-readonly-passkey',
        sessionId: 'ecdsa-readonly-passkey',
        sessionJwt: 'jwt:ecdsa-readonly-passkey',
        walletSigningSessionId: passkeyWalletSigningSessionId,
      }),
    });
    const emailOtpRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: accountId,
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: accountId,
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-readonly-email',
        sessionId: 'ecdsa-readonly-email',
        sessionJwt: 'jwt:ecdsa-readonly-email',
        walletSigningSessionId: 'ws-readonly-email',
      }),
    });
    upsertStoredThresholdEcdsaSessionRecord(ecdsaStore, {
      ...emailOtpRecord,
      clientAdditiveShareHandle: {
        kind: 'email_otp_worker_session',
        sessionId: 'email-worker-readonly',
      },
    });

    const { touchConfirm } = createMutableTouchConfirmStatus({
      'ed-readonly-passkey': { state: 'warm', remainingUses: 5, expiresAtMs },
      'ecdsa-readonly-passkey': { state: 'warm', remainingUses: 4, expiresAtMs },
    });
    const claims = await readWalletScopedLaneClaimsForAccount({
      deps: {
        touchConfirm,
        listThresholdEcdsaSessionRecordsForLookup: ({ chain }) =>
          [...ecdsaStore.recordsByLane.values()].filter((record) => record.chain === chain),
        getEmailOtpWarmSessionStatus: async (sessionId) => {
          expect(sessionId).toBe('email-worker-readonly');
          return { ok: true, remainingUses: 2, expiresAtMs };
        },
      },
      nearAccountId: accountId,
    });

    expect(claims.get('ed-readonly-passkey')).toMatchObject({
      state: 'warm',
      remainingUses: 4,
    });
    expect(claims.get('ecdsa-readonly-passkey')).toMatchObject({
      state: 'warm',
      remainingUses: 4,
    });
    expect(claims.get('ecdsa-readonly-email')).toMatchObject({
      state: 'warm',
      remainingUses: 2,
    });
  });

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
    const coordinator = new SigningSessionCoordinator({
      touchConfirm,
      listThresholdEcdsaSessionRecordsForLookup: ({ chain }) =>
        chain === 'evm' ? [...ecdsaStore.recordsByLane.values()] : [],
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

  test('does not treat threshold session ids as wallet signing-session ids', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const expiresAtMs = Date.now() + 120_000;
    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'missing-wallet-id.testnet',
      chain: 'tempo',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'missing-wallet-id.testnet',
        chain: 'tempo',
        sessionId: 'ecdsa-missing-wallet-id-session',
        sessionJwt: 'jwt:ecdsa-missing-wallet-id-session',
      }),
    });
    const recordWithoutWalletId = { ...record };
    delete recordWithoutWalletId.walletSigningSessionId;
    upsertStoredThresholdEcdsaSessionRecord(ecdsaStore, recordWithoutWalletId);

    const { touchConfirm } = createMutableTouchConfirmStatus({
      [record.thresholdSessionId]: { state: 'warm', remainingUses: 5, expiresAtMs },
    });
    const coordinator = new SigningSessionCoordinator({
      touchConfirm,
      listThresholdEcdsaSessionRecordsForLookup: ({ chain }) =>
        chain === 'tempo' ? [...ecdsaStore.recordsByLane.values()] : [],
    });

    const status = await coordinator.getStatus({
      nearAccountId: 'missing-wallet-id.testnet',
      walletSigningSessionId: record.thresholdSessionId,
    });
    const claims = await coordinator.getLaneClaimsForAccount('missing-wallet-id.testnet');

    expect(status).toBeNull();
    expect(claims.size).toBe(0);
  });

  test('rejects wallet budget consumption for a wallet session id that owns no lanes', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const expiresAtMs = Date.now() + 120_000;
    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'wrong-wallet-budget.testnet',
      chain: 'tempo',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'wrong-wallet-budget.testnet',
        chain: 'tempo',
        sessionId: 'ecdsa-wrong-wallet-budget-session',
        sessionJwt: 'jwt:ecdsa-wrong-wallet-budget-session',
        walletSigningSessionId: 'ws-correct-wallet-budget',
      }),
    });

    const { touchConfirm, consumeCalls } = createMutableTouchConfirmStatus({
      [record.thresholdSessionId]: { state: 'warm', remainingUses: 5, expiresAtMs },
    });
    const coordinator = new SigningSessionCoordinator({
      touchConfirm,
      listThresholdEcdsaSessionRecordsForLookup: ({ chain }) =>
        chain === 'tempo' ? [...ecdsaStore.recordsByLane.values()] : [],
    });

    await expect(
      coordinator.consumeUse({
        nearAccountId: 'wrong-wallet-budget.testnet',
        walletSigningSessionId: 'ws-wrong-wallet-budget',
        uses: 1,
        reason: 'transaction_sign',
      }),
    ).rejects.toThrow('wallet signing-session has no matching signing lanes');

    expect(consumeCalls).toEqual([]);
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
    const coordinator = new SigningSessionCoordinator({
      touchConfirm,
      listThresholdEcdsaSessionRecordsForLookup: ({ chain }) =>
        chain === 'evm' ? [...ecdsaStore.recordsByLane.values()] : [],
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
    expect(consumeCalls).toEqual([
      expect.objectContaining({ sessionId: 'ed-email-consume', uses: 1 }),
    ]);
    expect(markCalls).toEqual([{ thresholdSessionId: 'ed-email-consume', uses: 1 }]);
  });

  test('consumes only the explicit ECDSA target when one chain spends a shared wallet session', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const expiresAtMs = Date.now() + 120_000;
    const walletSigningSessionId = 'ws-cross-chain-shared';

    seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'cross-chain-shared.testnet',
      chain: 'tempo',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'cross-chain-shared.testnet',
        chain: 'tempo',
        ecdsaThresholdKeyId: 'ek-cross-chain-tempo',
        sessionId: 'ecdsa-cross-chain-tempo',
        sessionJwt: 'jwt:ecdsa-cross-chain-tempo',
        walletSigningSessionId,
      }),
    });
    seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'cross-chain-shared.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'cross-chain-shared.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-cross-chain-evm',
        sessionId: 'ecdsa-cross-chain-evm',
        sessionJwt: 'jwt:ecdsa-cross-chain-evm',
        walletSigningSessionId,
      }),
    });

    const { touchConfirm, consumeCalls } = createMutableTouchConfirmStatus({
      'ecdsa-cross-chain-tempo': { state: 'warm', remainingUses: 5, expiresAtMs },
      'ecdsa-cross-chain-evm': { state: 'warm', remainingUses: 5, expiresAtMs },
    });
    const coordinator = new SigningSessionCoordinator({
      touchConfirm,
      listThresholdEcdsaSessionRecordsForLookup: ({ chain }) =>
        [...ecdsaStore.recordsByLane.values()].filter((record) => record.chain === chain),
    });

    const status = await coordinator.consumeUse({
      nearAccountId: 'cross-chain-shared.testnet',
      walletSigningSessionId,
      uses: 1,
      reason: 'transaction_sign',
      targetThresholdSessionIds: ['ecdsa-cross-chain-tempo'],
    });
    const claims = await coordinator.getLaneClaimsForAccount('cross-chain-shared.testnet');

    expect(consumeCalls).toEqual([
      expect.objectContaining({ sessionId: 'ecdsa-cross-chain-tempo', uses: 1 }),
    ]);
    expect(status).toMatchObject({
      status: 'active',
      authMethod: 'passkey',
      remainingUses: 4,
    });
    expect(claims.get('ecdsa-cross-chain-evm')).toMatchObject({
      state: 'warm',
      remainingUses: 5,
    });
  });

  test('does not mark passkey Ed25519 exhausted when sibling ECDSA spends the last local use', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const expiresAtMs = Date.now() + 120_000;
    const walletSigningSessionId = 'ws-passkey-sibling-exhaustion';

    seedEd25519WarmSessionRecord({
      nearAccountId: 'passkey-sibling-exhaustion.testnet',
      thresholdSessionId: 'ed-passkey-sibling-exhaustion',
      walletSigningSessionId,
      thresholdSessionJwt: 'jwt:ed-passkey-sibling-exhaustion',
      remainingUses: 1,
      expiresAtMs,
      source: 'login',
    });
    seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'passkey-sibling-exhaustion.testnet',
      chain: 'tempo',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'passkey-sibling-exhaustion.testnet',
        chain: 'tempo',
        ecdsaThresholdKeyId: 'ek-passkey-sibling-exhaustion',
        sessionId: 'ecdsa-passkey-sibling-exhaustion',
        sessionJwt: 'jwt:ecdsa-passkey-sibling-exhaustion',
        walletSigningSessionId,
      }),
    });

    const { touchConfirm, consumeCalls } = createMutableTouchConfirmStatus({
      'ed-passkey-sibling-exhaustion': { state: 'warm', remainingUses: 1, expiresAtMs },
      'ecdsa-passkey-sibling-exhaustion': { state: 'warm', remainingUses: 1, expiresAtMs },
    });
    const coordinator = new SigningSessionCoordinator({
      touchConfirm,
      listThresholdEcdsaSessionRecordsForLookup: ({ chain }) =>
        chain === 'tempo' ? [...ecdsaStore.recordsByLane.values()] : [],
    });

    const status = await coordinator.consumeUse({
      nearAccountId: 'passkey-sibling-exhaustion.testnet',
      walletSigningSessionId,
      uses: 1,
      reason: 'transaction_sign',
      targetThresholdSessionIds: ['ecdsa-passkey-sibling-exhaustion'],
    });
    const nextStatus = await coordinator.getStatus({
      nearAccountId: 'passkey-sibling-exhaustion.testnet',
      walletSigningSessionId,
    });
    const claims = await coordinator.getLaneClaimsForAccount(
      'passkey-sibling-exhaustion.testnet',
    );

    expect(consumeCalls).toEqual([
      expect.objectContaining({ sessionId: 'ecdsa-passkey-sibling-exhaustion', uses: 1 }),
    ]);
    expect(status).toMatchObject({
      sessionId: walletSigningSessionId,
      status: 'exhausted',
      authMethod: 'passkey',
      remainingUses: 0,
    });
    expect(nextStatus).toMatchObject({
      sessionId: walletSigningSessionId,
      status: 'exhausted',
      authMethod: 'passkey',
    });
    expect(claims.get('ecdsa-passkey-sibling-exhaustion')).toMatchObject({
      state: 'exhausted',
    });
    expect(claims.get('ed-passkey-sibling-exhaustion')).toMatchObject({
      state: 'warm',
      remainingUses: 1,
    });
  });

  test('returns exhausted after an already-consumed ECDSA Email OTP lane disappears', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const walletSigningSessionId = 'ws-email-ecdsa-already-consumed';
    const thresholdSessionId = 'ecdsa-email-already-consumed';

    const ecdsaRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'email-ecdsa-already-consumed.testnet',
      chain: 'tempo',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'sign',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'email-ecdsa-already-consumed.testnet',
        chain: 'tempo',
        ecdsaThresholdKeyId: 'ek-email-already-consumed',
        sessionId: thresholdSessionId,
        sessionJwt: 'jwt:ecdsa-email-already-consumed',
        walletSigningSessionId,
      }),
    });
    upsertStoredThresholdEcdsaSessionRecord(ecdsaStore, {
      ...ecdsaRecord,
      clientAdditiveShareHandle: {
        kind: 'email_otp_worker_session',
        sessionId: 'email-worker-already-consumed',
      },
    });

    const emailOtpConsumeCalls: Array<{ sessionId: string; uses?: number }> = [];
    const coordinator = new SigningSessionCoordinator({
      listThresholdEcdsaSessionRecordsForLookup: ({ chain }) =>
        chain === 'tempo' ? [...ecdsaStore.recordsByLane.values()] : [],
      getEmailOtpWarmSessionStatus: async () => ({
        ok: false,
        code: 'not_found',
        message: 'already consumed by signing worker',
      }),
      consumeEmailOtpWarmSessionUses: async (args) => {
        emailOtpConsumeCalls.push(args);
        return { ok: false, code: 'not_found', message: 'should not be called' };
      },
    });

    const status = await coordinator.consumeUse({
      nearAccountId: 'email-ecdsa-already-consumed.testnet',
      walletSigningSessionId,
      uses: 1,
      reason: 'transaction_sign',
      alreadyConsumedThresholdSessionIds: [thresholdSessionId],
    });

    expect(emailOtpConsumeCalls).toEqual([]);
    expect(status).toMatchObject({
      sessionId: walletSigningSessionId,
      status: 'exhausted',
      authMethod: 'email_otp',
      retention: 'single_use',
      remainingUses: 0,
    });
  });

  test('does not locally consume an already-spent Email OTP Ed25519 signing lane', async () => {
    const expiresAtMs = Date.now() + 120_000;
    const nearAccountId = 'email-ed25519-already-consumed.testnet';
    const walletSigningSessionId = 'ws-email-ed25519-already-consumed';
    const thresholdSessionId = 'ed-email-already-consumed';
    seedEd25519WarmSessionRecord({
      nearAccountId,
      thresholdSessionId,
      walletSigningSessionId,
      thresholdSessionJwt: 'jwt:ed-email-already-consumed',
      remainingUses: 1,
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

    const emailOtpConsumeCalls: Array<{ sessionId: string; uses?: number }> = [];
    const markCalls: Array<{ thresholdSessionId?: string; uses?: number }> = [];
    const { touchConfirm } = createMutableTouchConfirmStatus({
      [thresholdSessionId]: { state: 'warm', remainingUses: 1, expiresAtMs },
    });
    const coordinator = new SigningSessionCoordinator({
      touchConfirm,
      getEmailOtpWarmSessionStatus: async () => ({
        ok: true,
        remainingUses: 1,
        expiresAtMs,
      }),
      consumeEmailOtpWarmSessionUses: async (args) => {
        emailOtpConsumeCalls.push(args);
        return { ok: true, remainingUses: 0, expiresAtMs };
      },
      markThresholdEd25519EmailOtpSessionConsumedForAccount: (args) => {
        markCalls.push({
          thresholdSessionId: args.thresholdSessionId,
          uses: args.uses,
        });
      },
    });

    const status = await coordinator.consumeUse({
      nearAccountId,
      walletSigningSessionId,
      uses: 1,
      reason: 'transaction_sign',
      targetThresholdSessionIds: [thresholdSessionId],
      alreadyConsumedThresholdSessionIds: [thresholdSessionId],
    });

    expect(emailOtpConsumeCalls).toEqual([]);
    expect(markCalls).toEqual([]);
    expect(status).toMatchObject({
      sessionId: walletSigningSessionId,
      status: 'active',
      remainingUses: 1,
    });
  });

  test('uses trusted budget status after an already-spent passkey Ed25519 lane drops local material', async () => {
    const expiresAtMs = Date.now() + 120_000;
    const nearAccountId = 'passkey-ed25519-trusted-budget.testnet';
    const walletSigningSessionId = 'ws-passkey-ed25519-trusted-budget';
    const thresholdSessionId = 'ed-passkey-trusted-budget';
    seedEd25519WarmSessionRecord({
      nearAccountId,
      thresholdSessionId,
      walletSigningSessionId,
      thresholdSessionJwt: 'jwt:ed-passkey-trusted-budget',
      remainingUses: 1,
      expiresAtMs,
      source: 'login',
    });

    const { touchConfirm, consumeCalls } = createMutableTouchConfirmStatus({
      [thresholdSessionId]: { state: 'exhausted' },
    });
    const coordinator = new SigningSessionCoordinator({
      touchConfirm,
      getStatus: async () => ({
        sessionId: walletSigningSessionId,
        status: 'active',
        remainingUses: 1,
        expiresAtMs,
        projectionVersion: 'projection:passkey-ed25519-trusted-budget:1',
      }),
    });

    const status = await coordinator.consumeUse({
      nearAccountId,
      walletSigningSessionId,
      uses: 1,
      reason: 'transaction_sign',
      targetThresholdSessionIds: [thresholdSessionId],
      alreadyConsumedThresholdSessionIds: [thresholdSessionId],
    });

    expect(consumeCalls).toEqual([]);
    expect(status).toMatchObject({
      sessionId: walletSigningSessionId,
      status: 'active',
      remainingUses: 1,
    });
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
    const coordinator = new SigningSessionCoordinator({
      touchConfirm,
      listThresholdEcdsaSessionRecordsForLookup: ({ chain }) =>
        chain === 'evm' ? [...ecdsaStore.recordsByLane.values()] : [],
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
      updateExactSealedSessionPolicy: async (args) => {
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
    const coordinator = new SigningSessionCoordinator({
      touchConfirm,
      listThresholdEcdsaSessionRecordsForLookup: ({ chain }) =>
        chain === 'evm' ? [...ecdsaStore.recordsByLane.values()] : [],
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
      expect.objectContaining({ sessionId: 'ed-passkey-shared', uses: 1 }),
      expect.objectContaining({ sessionId: 'ecdsa-passkey-shared', uses: 1 }),
    ]);
    expect(status).toMatchObject({
      status: 'active',
      authMethod: 'passkey',
      remainingUses: 4,
    });
  });
});
