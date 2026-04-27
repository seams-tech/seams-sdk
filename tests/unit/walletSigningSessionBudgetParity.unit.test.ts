import { expect, test } from '@playwright/test';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import { buildWalletSigningSpendPlan } from '@/core/signingEngine/session/signingSession/budget';
import { buildEvmTransactionSigningLane } from '@/core/signingEngine/session/signingSession/lanes';
import {
  SigningOperationIntent,
  SigningSessionIds,
} from '@/core/signingEngine/session/signingSession/types';
import { upsertStoredThresholdEcdsaSessionRecord } from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import { toAccountId } from '@/core/types/accountIds';
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
} from './helpers/warmSessionStore.fixtures';

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

    const coordinator = new SigningSessionCoordinator({
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
      listThresholdEcdsaSessionRecordsForLookup: ({ chain }) =>
        chain === 'evm' ? [...ecdsaStore.recordsByLane.values()] : [],
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

  test('targeted reservation follows refreshed EVM lane when stale siblings share the wallet session', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const accountId = 'wallet-budget-targeted-passkey.testnet';
    const walletSigningSessionId = 'ws-budget-targeted-passkey';
    const ed25519SessionId = 'ed-budget-targeted-passkey-stale';
    const tempoSessionId = 'tempo-budget-targeted-passkey-stale';
    const evmSessionId = 'evm-budget-targeted-passkey-refreshed';
    const expiresAtMs = Date.now() + 120_000;
    const claimsBySessionId = new Map<
      string,
      | { state: 'warm'; remainingUses: number; expiresAtMs: number }
      | { state: 'exhausted' }
    >([
      [ed25519SessionId, { state: 'exhausted' }],
      [tempoSessionId, { state: 'exhausted' }],
      [evmSessionId, { state: 'warm', remainingUses: 1, expiresAtMs }],
    ]);
    const readStatus = (sessionId: string) => {
      const claim = claimsBySessionId.get(sessionId);
      if (claim?.state === 'warm') {
        return {
          ok: true as const,
          remainingUses: claim.remainingUses,
          expiresAtMs: claim.expiresAtMs,
        };
      }
      return {
        ok: false as const,
        code: 'exhausted',
        message: 'exhausted',
      };
    };
    const consumedSessionIds: string[] = [];

    seedEd25519WarmSessionRecord({
      nearAccountId: accountId,
      thresholdSessionId: ed25519SessionId,
      walletSigningSessionId,
      thresholdSessionJwt: `jwt:${ed25519SessionId}`,
      remainingUses: 0,
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
        sessionId: tempoSessionId,
        walletSigningSessionId,
      }),
    });
    seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: accountId,
      chain: 'evm',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: accountId,
        chain: 'evm',
        sessionId: evmSessionId,
        walletSigningSessionId,
      }),
    });

    const coordinator = new SigningSessionCoordinator({
      touchConfirm: {
        getWarmSessionStatus: async ({ sessionId }) => readStatus(String(sessionId)),
        getWarmSessionStatuses: async ({ sessionIds }) => ({
          results: sessionIds.map((sessionId) => ({
            sessionId,
            result: readStatus(String(sessionId)),
          })),
        }),
        consumeWarmSessionUses: async ({ sessionId, uses }) => {
          const normalizedSessionId = String(sessionId);
          consumedSessionIds.push(normalizedSessionId);
          const claim = claimsBySessionId.get(normalizedSessionId);
          if (claim?.state !== 'warm' || claim.remainingUses <= 0) {
            return {
              ok: false as const,
              code: 'exhausted',
              message: 'exhausted',
            };
          }
          claim.remainingUses = Math.max(0, claim.remainingUses - Math.max(1, uses || 1));
          if (claim.remainingUses <= 0) {
            claimsBySessionId.set(normalizedSessionId, { state: 'exhausted' });
            return {
              ok: false as const,
              code: 'exhausted',
              message: 'exhausted',
            };
          }
          return {
            ok: true as const,
            remainingUses: claim.remainingUses,
            expiresAtMs: claim.expiresAtMs,
          };
        },
      },
      listThresholdEcdsaSessionRecordsForLookup: ({ chain }) =>
        [...ecdsaStore.recordsByLane.values()].filter((record) => record.chain === chain),
    });
    const ledger = new SigningSessionCoordinator({
      getStatus: (args) => coordinator.getStatus(args),
      consumeUse: (args) => coordinator.consumeUse(args),
    });
    const lane = buildEvmTransactionSigningLane({
      accountId: toAccountId(accountId),
      authMethod: 'passkey',
      storageSource: 'login',
      walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(evmSessionId),
      signingRootId: 'sr-test:dev',
    });
    const spend = buildWalletSigningSpendPlan(
      {
        operationId: SigningSessionIds.signingOperation('op-budget-targeted-passkey'),
        operationFingerprint: SigningSessionIds.signingOperationFingerprint(
          'sha256:targeted-passkey',
        ),
        intent: SigningOperationIntent.TransactionSign,
      },
      lane,
    );

    const reservation = await ledger.reserve({ spend });
    expect(reservation).toBeTruthy();
    await expect(ledger.recordSuccess({ spend })).resolves.toMatchObject({
      status: 'exhausted',
    });
    expect(consumedSessionIds).toEqual([
      ed25519SessionId,
      evmSessionId,
      tempoSessionId,
    ]);
  });
});
