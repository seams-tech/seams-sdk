import { expect, test } from '@playwright/test';
import { createWalletSigningSessionCoordinator } from '@/core/signingEngine/session/WalletSigningSessionCoordinator';
import { upsertStoredThresholdEcdsaSessionRecord } from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import {
  createSigningSessionSealCipherAdapter,
  createSigningSessionSealService,
} from '@server/threshold/session/signingSessionSeal';
import { walletSigningBudgetSessionId } from '@server/core/ThresholdService/walletSigningBudget';
import {
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  resetWarmSessionFixtureState,
  seedEd25519WarmSessionRecord,
  seedEcdsaWarmSessionRecord,
} from './helpers/warmSessionManager.fixtures';

const NEAR_ACCOUNT_ID = 'wallet-budget-parity.testnet';
const USER_ID = NEAR_ACCOUNT_ID;
const WALLET_SIGNING_SESSION_ID = 'ws-budget-parity';
const ED25519_THRESHOLD_SESSION_ID = 'ed-budget-parity';
const ECDSA_THRESHOLD_SESSION_ID = 'ecdsa-budget-parity';
const ECDSA_WORKER_SESSION_ID = 'email-worker-budget-parity';

function makeSealBody() {
  return {
    thresholdSessionId: ECDSA_THRESHOLD_SESSION_ID,
    ciphertext: 'ciphertext-b64u',
    keyVersion: 'kek-s-2026-02',
  };
}

test.describe('wallet signing-session budget parity', () => {
  test('server sealed-refresh status and client coordinator status follow the same wallet budget', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const expiresAtMs = Date.now() + 120_000;
    let authoritativeRemainingUses = 2;
    const serverBudgetSessionIds: string[] = [];

    seedEd25519WarmSessionRecord({
      nearAccountId: NEAR_ACCOUNT_ID,
      thresholdSessionId: ED25519_THRESHOLD_SESSION_ID,
      walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
      thresholdSessionJwt: 'jwt:ed-budget-parity',
      remainingUses: 99,
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
      nearAccountId: NEAR_ACCOUNT_ID,
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: NEAR_ACCOUNT_ID,
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-budget-parity',
        sessionId: ECDSA_THRESHOLD_SESSION_ID,
        sessionJwt: 'jwt:ecdsa-budget-parity',
        walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
      }),
    });
    upsertStoredThresholdEcdsaSessionRecord(ecdsaStore, {
      ...ecdsaRecord,
      remainingUses: 99,
      clientAdditiveShareHandle: {
        kind: 'email_otp_worker_session',
        sessionId: ECDSA_WORKER_SESSION_ID,
      },
    });

    const readAuthoritativeStatus = async () => {
      if (authoritativeRemainingUses <= 0) {
        return { ok: false as const, code: 'exhausted', message: 'exhausted' };
      }
      return {
        ok: true as const,
        remainingUses: authoritativeRemainingUses,
        expiresAtMs,
      };
    };

    const coordinator = createWalletSigningSessionCoordinator({
      touchConfirm: {
        getWarmSessionStatus: async ({ sessionId }) => {
          expect(sessionId).toBe(ED25519_THRESHOLD_SESSION_ID);
          return readAuthoritativeStatus();
        },
        getWarmSessionStatuses: async ({ sessionIds }) => ({
          results: await Promise.all(
            sessionIds.map(async (sessionId) => ({
              sessionId,
              result: await readAuthoritativeStatus(),
            })),
          ),
        }),
      },
      getThresholdEcdsaSessionRecordForSigning: ({ chain }) =>
        chain === 'evm' ? (ecdsaStore.recordsByLane.values().next().value ?? null) : null,
      getEmailOtpWarmSessionStatus: async (sessionId) => {
        expect(sessionId).toBe(ECDSA_WORKER_SESSION_ID);
        return readAuthoritativeStatus();
      },
    });

    const service = createSigningSessionSealService({
      sessionPolicy: {
        getSession: async (thresholdSessionId: string) => {
          if (thresholdSessionId !== ECDSA_THRESHOLD_SESSION_ID) return null;
          return {
            thresholdSessionId,
            userId: USER_ID,
            expiresAtMs,
            remainingUses: 99,
          };
        },
        getSessionStatus: async (sessionId: string) => {
          serverBudgetSessionIds.push(sessionId);
          if (sessionId !== walletSigningBudgetSessionId(WALLET_SIGNING_SESSION_ID)) {
            return null;
          }
          return {
            thresholdSessionId: sessionId,
            userId: USER_ID,
            expiresAtMs,
            remainingUses: authoritativeRemainingUses,
            record: {
              expiresAtMs,
              relayerKeyId: 'wallet-signing-budget',
              userId: USER_ID,
              rpId: 'localhost',
              participantIds: [1, 2],
            },
          };
        },
      },
      cipher: createSigningSessionSealCipherAdapter({
        applyServerSeal: async (input) => ({ ok: true, ciphertext: `sealed:${input.ciphertext}` }),
        removeServerSeal: async (input) => ({
          ok: true,
          ciphertext: `unsealed:${input.ciphertext}`,
        }),
      }),
    });

    const readServerSealResult = async () =>
      service.removeServerSeal(makeSealBody(), {
        userId: USER_ID,
        claims: {
          walletId: USER_ID,
          walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
        },
      });
    const readClientStatus = async () =>
      coordinator.getStatus({
        nearAccountId: NEAR_ACCOUNT_ID,
        walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
      });

    let serverResult = await readServerSealResult();
    let clientStatus = await readClientStatus();
    expect(serverResult).toMatchObject({ ok: true, remainingUses: 2 });
    expect(clientStatus).toMatchObject({ status: 'active', remainingUses: 2 });

    authoritativeRemainingUses = 1;
    serverResult = await readServerSealResult();
    clientStatus = await readClientStatus();
    expect(serverResult).toMatchObject({ ok: true, remainingUses: 1 });
    expect(clientStatus).toMatchObject({ status: 'active', remainingUses: 1 });

    authoritativeRemainingUses = 0;
    serverResult = await readServerSealResult();
    clientStatus = await readClientStatus();
    expect(serverResult).toEqual({
      ok: false,
      code: 'exhausted',
      message: 'wallet signing session exhausted',
    });
    expect(clientStatus).toMatchObject({ status: 'exhausted' });

    expect(new Set(serverBudgetSessionIds)).toEqual(
      new Set([walletSigningBudgetSessionId(WALLET_SIGNING_SESSION_ID)]),
    );
  });
});
