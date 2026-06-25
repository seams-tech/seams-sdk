import { expect, test } from '@playwright/test';
import type {
  EcdsaWalletSessionStatus,
  EcdsaWalletSessionStore,
  Ed25519WalletSessionStatus,
  Ed25519WalletSessionStore,
  WalletSessionConsumeUsesResult,
  WalletSigningBudgetSessionStatus,
  WalletSigningBudgetSessionStore,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore';
import { walletSigningBudgetSessionId } from '../../packages/sdk-server-ts/src/core/ThresholdService/walletSigningBudget';
import { createSigningSessionSealPolicyFromWalletSessionStores } from '../../packages/sdk-server-ts/src/threshold/session/signingSessionSeal/policy/sessionPolicy';

function makeStatus(input: {
  userId: string;
  rpId: string;
  relayerKeyId: string;
  participantIds: number[];
  expiresAtMs: number;
  remainingUses: number;
  walletBudgetBinding?: {
    curve: 'ed25519' | 'ecdsa';
    thresholdSessionId: string;
  };
}): Ed25519WalletSessionStatus {
  return {
    record: {
      userId: input.userId,
      walletId: input.userId,
      nearAccountId: input.userId,
      nearEd25519SigningKeyId: input.userId,
      rpId: input.rpId,
      relayerKeyId: input.relayerKeyId,
      participantIds: input.participantIds,
      expiresAtMs: input.expiresAtMs,
      ...(input.walletBudgetBinding ? { walletBudgetBinding: input.walletBudgetBinding } : {}),
    },
    expiresAtMs: input.expiresAtMs,
    committedRemainingUses: input.remainingUses,
    reservedUses: 0,
    availableUses: input.remainingUses,
    remainingUses: input.remainingUses,
  };
}

function makeEcdsaStatus(input: {
  userId: string;
  walletKeyId: string;
  relayerKeyId: string;
  participantIds: number[];
  expiresAtMs: number;
  remainingUses: number;
}): EcdsaWalletSessionStatus {
  return {
    record: {
      walletId: input.userId,
      walletKeyId: input.walletKeyId,
      relayerKeyId: input.relayerKeyId,
      participantIds: input.participantIds,
      expiresAtMs: input.expiresAtMs,
    },
    expiresAtMs: input.expiresAtMs,
    committedRemainingUses: input.remainingUses,
    reservedUses: 0,
    availableUses: input.remainingUses,
    remainingUses: input.remainingUses,
  };
}

function makeBudgetStatus(input: {
  userId: string;
  budgetScope:
    | { kind: 'passkey_rp'; rpId: string }
    | { kind: 'wallet_key'; walletKeyId: string };
  binding: {
    curve: 'ed25519' | 'ecdsa';
    thresholdSessionId: string;
  };
  relayerKeyId: string;
  participantIds: number[];
  expiresAtMs: number;
  remainingUses: number;
}): WalletSigningBudgetSessionStatus {
  return {
    record: {
      kind: 'wallet_signing_budget_session',
      walletId: input.userId,
      budgetScope: input.budgetScope,
      binding: input.binding,
      relayerKeyId: input.relayerKeyId,
      participantIds: input.participantIds,
      expiresAtMs: input.expiresAtMs,
    },
    expiresAtMs: input.expiresAtMs,
    committedRemainingUses: input.remainingUses,
    reservedUses: 0,
    availableUses: input.remainingUses,
    remainingUses: input.remainingUses,
  };
}

function makeStore(entries: {
  sessions?: Record<string, Ed25519WalletSessionStatus | null>;
  consume?: Record<string, WalletSessionConsumeUsesResult>;
}): Ed25519WalletSessionStore {
  const sessions = entries.sessions || {};
  const consume = entries.consume || {};
  return {
    async putSession(): Promise<void> {
      throw new Error('not implemented');
    },
    async getSession(id: string) {
      return sessions[id]?.record || null;
    },
    async getSessionStatus(id: string) {
      return sessions[id] || null;
    },
    async consumeUseCount(id: string) {
      return consume[id] || { ok: false, code: 'not_found', message: 'missing' };
    },
    async consumeUseCountOnce(id: string) {
      return consume[id] || { ok: false, code: 'not_found', message: 'missing' };
    },
    async reserveUseCountOnce() {
      return { ok: false, code: 'not_found', message: 'missing' };
    },
    async commitReservedUseCountOnce() {
      return { ok: false, code: 'not_found', message: 'missing' };
    },
    async validateReservedUseCount() {
      return { ok: false, code: 'not_found', message: 'missing' };
    },
    async releaseReservedUseCount() {
      return {
        ok: false,
        code: 'not_found',
        message: 'missing',
      };
    },
    async releaseReservedUseCountForIdentity() {
      return {
        ok: false,
        code: 'not_found',
        message: 'missing',
      };
    },
    async hasConsumedUseCountOnce() {
      return { ok: true, consumed: false };
    },
    async reserveReplayGuard() {
      return { ok: true };
    },
  };
}

function makeEcdsaStore(entries: {
  sessions?: Record<string, EcdsaWalletSessionStatus | null>;
  consume?: Record<string, WalletSessionConsumeUsesResult>;
}): EcdsaWalletSessionStore {
  const sessions = entries.sessions || {};
  const consume = entries.consume || {};
  return {
    async putSession(): Promise<void> {
      throw new Error('not implemented');
    },
    async getSession(id: string) {
      return sessions[id]?.record || null;
    },
    async getSessionStatus(id: string) {
      return sessions[id] || null;
    },
    async consumeUseCount(id: string) {
      return consume[id] || { ok: false, code: 'not_found', message: 'missing' };
    },
    async consumeUseCountOnce(id: string) {
      return consume[id] || { ok: false, code: 'not_found', message: 'missing' };
    },
    async reserveUseCountOnce() {
      return { ok: false, code: 'not_found', message: 'missing' };
    },
    async commitReservedUseCountOnce() {
      return { ok: false, code: 'not_found', message: 'missing' };
    },
    async validateReservedUseCount() {
      return { ok: false, code: 'not_found', message: 'missing' };
    },
    async releaseReservedUseCount() {
      return {
        ok: false,
        code: 'not_found',
        message: 'missing',
      };
    },
    async releaseReservedUseCountForIdentity() {
      return {
        ok: false,
        code: 'not_found',
        message: 'missing',
      };
    },
    async hasConsumedUseCountOnce() {
      return { ok: true, consumed: false };
    },
    async reserveReplayGuard() {
      return { ok: true };
    },
  };
}

function makeBudgetStore(entries: {
  sessions?: Record<string, WalletSigningBudgetSessionStatus | null>;
  consume?: Record<string, WalletSessionConsumeUsesResult>;
}): WalletSigningBudgetSessionStore {
  const sessions = entries.sessions || {};
  const consume = entries.consume || {};
  return {
    async putSession(): Promise<void> {
      throw new Error('not implemented');
    },
    async getSession(id: string) {
      return sessions[id]?.record || null;
    },
    async getSessionStatus(id: string) {
      return sessions[id] || null;
    },
    async consumeUseCount(id: string) {
      return consume[id] || { ok: false, code: 'not_found', message: 'missing' };
    },
    async consumeUseCountOnce(id: string) {
      return consume[id] || { ok: false, code: 'not_found', message: 'missing' };
    },
    async reserveUseCountOnce() {
      return { ok: false, code: 'not_found', message: 'missing' };
    },
    async commitReservedUseCountOnce() {
      return { ok: false, code: 'not_found', message: 'missing' };
    },
    async validateReservedUseCount() {
      return { ok: false, code: 'not_found', message: 'missing' };
    },
    async releaseReservedUseCount() {
      return {
        ok: false,
        code: 'not_found',
        message: 'missing',
      };
    },
    async releaseReservedUseCountForIdentity() {
      return {
        ok: false,
        code: 'not_found',
        message: 'missing',
      };
    },
    async hasConsumedUseCountOnce() {
      return { ok: true, consumed: false };
    },
    async reserveReplayGuard() {
      return { ok: true };
    },
  };
}

test.describe('signing session seal session policy', () => {
  test('looks up threshold sessions only within the requested curve family', async () => {
    const thresholdSessionId = 'shared-threshold-session';
    const walletBudgetStore = makeBudgetStore({});
    const policy = createSigningSessionSealPolicyFromWalletSessionStores({
      ed25519Stores: [
        makeStore({
          sessions: {
            [thresholdSessionId]: makeStatus({
              userId: 'alice',
              rpId: 'rp-ed25519.example',
              relayerKeyId: 'relayer-ed25519',
              participantIds: [1, 2],
              expiresAtMs: 111_000,
              remainingUses: 4,
            }),
          },
        }),
      ],
      ecdsaStores: [
        makeEcdsaStore({
          sessions: {
            [thresholdSessionId]: makeEcdsaStatus({
              userId: 'alice',
              walletKeyId: 'wallet-key-ecdsa.example',
              relayerKeyId: 'relayer-ecdsa',
              participantIds: [3, 4],
              expiresAtMs: 222_000,
              remainingUses: 9,
            }),
          },
        }),
      ],
      walletBudgetStores: [walletBudgetStore],
    });

    await expect(
      policy.getThresholdSession({
        curve: 'ed25519',
        thresholdSessionId,
      }),
    ).resolves.toEqual({
      curve: 'ed25519',
      thresholdSessionId,
      userId: 'alice',
      expiresAtMs: 111_000,
      relayerKeyId: 'relayer-ed25519',
      rpId: 'rp-ed25519.example',
      participantIds: [1, 2],
    });

    await expect(
      policy.getThresholdSession({
        curve: 'ecdsa',
        thresholdSessionId,
      }),
    ).resolves.toEqual({
      curve: 'ecdsa',
      thresholdSessionId,
      userId: 'alice',
      expiresAtMs: 222_000,
      relayerKeyId: 'relayer-ecdsa',
      walletKeyId: 'wallet-key-ecdsa.example',
      participantIds: [3, 4],
    });
  });

  test('looks up threshold session status only within the requested curve family', async () => {
    const thresholdSessionId = 'shared-threshold-session';
    const walletBudgetStore = makeBudgetStore({});
    const policy = createSigningSessionSealPolicyFromWalletSessionStores({
      ed25519Stores: [
        makeStore({
          sessions: {
            [thresholdSessionId]: makeStatus({
              userId: 'alice',
              rpId: 'rp-ed25519.example',
              relayerKeyId: 'relayer-ed25519',
              participantIds: [1, 2],
              expiresAtMs: 111_000,
              remainingUses: 4,
            }),
          },
        }),
      ],
      ecdsaStores: [
        makeEcdsaStore({
          sessions: {
            [thresholdSessionId]: makeEcdsaStatus({
              userId: 'alice',
              walletKeyId: 'wallet-key-ecdsa.example',
              relayerKeyId: 'relayer-ecdsa',
              participantIds: [3, 4],
              expiresAtMs: 222_000,
              remainingUses: 9,
            }),
          },
        }),
      ],
      walletBudgetStores: [walletBudgetStore],
    });

    await expect(
      policy.getThresholdSessionStatuses({
        curve: 'ed25519',
        thresholdSessionId,
      }),
    ).resolves.toEqual([
      {
        kind: 'wallet_session',
        curve: 'ed25519',
        thresholdSessionId,
        userId: 'alice',
        expiresAtMs: 111_000,
        remainingUses: 4,
        relayerKeyId: 'relayer-ed25519',
        rpId: 'rp-ed25519.example',
        participantIds: [1, 2],
      },
    ]);

    await expect(
      policy.getThresholdSessionStatuses({
        curve: 'ecdsa',
        thresholdSessionId,
      }),
    ).resolves.toEqual([
      {
        kind: 'wallet_session',
        curve: 'ecdsa',
        thresholdSessionId,
        userId: 'alice',
        expiresAtMs: 222_000,
        remainingUses: 9,
        relayerKeyId: 'relayer-ecdsa',
        walletKeyId: 'wallet-key-ecdsa.example',
        participantIds: [3, 4],
      },
    ]);
  });

  test('looks up wallet budget status from the shared wallet budget store', async () => {
    const budgetSessionId = 'budget-session';
    const walletBudgetThresholdSessionId = 'threshold-ed25519-budget-session';
    const walletBudgetStoreSessionId = walletSigningBudgetSessionId(budgetSessionId);
    const walletBudgetStore = makeBudgetStore({
      sessions: {
        [walletBudgetStoreSessionId]: makeBudgetStatus({
          userId: 'alice',
          budgetScope: { kind: 'passkey_rp', rpId: 'rp-wallet-budget.example' },
          binding: {
            curve: 'ed25519',
            thresholdSessionId: walletBudgetThresholdSessionId,
          },
          relayerKeyId: 'relayer-wallet-budget',
          participantIds: [5, 6],
          expiresAtMs: 333_000,
          remainingUses: 2,
        }),
      },
    });
    const policy = createSigningSessionSealPolicyFromWalletSessionStores({
      ed25519Stores: [
        makeStore({
          sessions: {
            [walletBudgetThresholdSessionId]: makeStatus({
              userId: 'alice',
              rpId: 'rp-ed25519.example',
              relayerKeyId: 'relayer-ed25519',
              participantIds: [5, 6],
              expiresAtMs: 333_000,
              remainingUses: 2,
            }),
          },
        }),
      ],
      ecdsaStores: [
        makeEcdsaStore({
          sessions: {
            [walletBudgetThresholdSessionId]: makeEcdsaStatus({
              userId: 'alice',
              walletKeyId: 'wallet-key-ecdsa.example',
              relayerKeyId: 'relayer-ecdsa',
              participantIds: [7, 8],
              expiresAtMs: 444_000,
              remainingUses: 8,
            }),
          },
        }),
      ],
      walletBudgetStores: [walletBudgetStore],
    });

    await expect(
      policy.getWalletBudgetStatus?.({
        curve: 'ed25519',
        signingGrantId: budgetSessionId,
        thresholdSessionId: walletBudgetThresholdSessionId,
      }),
    ).resolves.toEqual({
      kind: 'wallet_budget',
      curve: 'ed25519',
      thresholdSessionId: walletBudgetThresholdSessionId,
      signingGrantId: budgetSessionId,
      userId: 'alice',
      expiresAtMs: 333_000,
      remainingUses: 2,
      committedRemainingUses: 2,
      reservedUses: 0,
      availableUses: 2,
      relayerKeyId: 'relayer-wallet-budget',
      rpId: 'rp-wallet-budget.example',
      participantIds: [5, 6],
    });

    await expect(
      policy.getWalletBudgetStatus?.({
        curve: 'ecdsa',
        signingGrantId: budgetSessionId,
        thresholdSessionId: walletBudgetThresholdSessionId,
      }),
    ).resolves.toBeNull();
  });

  test('wallet budget status requires exact curve and threshold binding', async () => {
    const signingGrantId = 'shared-wallet-session';
    const ed25519ThresholdSessionId = 'threshold-ed25519-shared-wallet';
    const ecdsaThresholdSessionId = 'threshold-ecdsa-shared-wallet';
    const walletBudgetSessionId = walletSigningBudgetSessionId(signingGrantId);
    const walletBudgetStore = makeBudgetStore({
      sessions: {
        [walletBudgetSessionId]: makeBudgetStatus({
          userId: 'alice',
          budgetScope: { kind: 'passkey_rp', rpId: 'rp-wallet-budget.example' },
          binding: {
            curve: 'ed25519',
            thresholdSessionId: ed25519ThresholdSessionId,
          },
          relayerKeyId: 'relayer-wallet-budget',
          participantIds: [1, 2],
          expiresAtMs: 333_000,
          remainingUses: 2,
        }),
      },
    });
    const policy = createSigningSessionSealPolicyFromWalletSessionStores({
      ed25519Stores: [],
      ecdsaStores: [],
      walletBudgetStores: [walletBudgetStore],
    });

    await expect(
      policy.getWalletBudgetStatus?.({
        curve: 'ed25519',
        signingGrantId,
        thresholdSessionId: ed25519ThresholdSessionId,
      }),
    ).resolves.toMatchObject({
      curve: 'ed25519',
      thresholdSessionId: ed25519ThresholdSessionId,
      remainingUses: 2,
    });
    await expect(
      policy.getWalletBudgetStatus?.({
        curve: 'ecdsa',
        signingGrantId,
        thresholdSessionId: ecdsaThresholdSessionId,
      }),
    ).resolves.toBeNull();
    await expect(
      policy.getWalletBudgetStatus?.({
        curve: 'ed25519',
        signingGrantId,
        thresholdSessionId: ecdsaThresholdSessionId,
      }),
    ).resolves.toBeNull();
  });

  test('consumes use counts only within the requested curve family', async () => {
    const thresholdSessionId = 'shared-threshold-session';
    const walletBudgetStore = makeBudgetStore({});
    const policy = createSigningSessionSealPolicyFromWalletSessionStores({
      ed25519Stores: [
        makeStore({
          sessions: {
            [thresholdSessionId]: makeStatus({
              userId: 'alice',
              rpId: 'rp-ed25519.example',
              relayerKeyId: 'relayer-ed25519',
              participantIds: [1, 2],
              expiresAtMs: 111_000,
              remainingUses: 4,
            }),
          },
          consume: {
            [thresholdSessionId]: { ok: true, remainingUses: 3 },
          },
        }),
      ],
      ecdsaStores: [
        makeEcdsaStore({
          sessions: {
            [thresholdSessionId]: makeEcdsaStatus({
              userId: 'alice',
              walletKeyId: 'wallet-key-ecdsa.example',
              relayerKeyId: 'relayer-ecdsa',
              participantIds: [3, 4],
              expiresAtMs: 222_000,
              remainingUses: 9,
            }),
          },
          consume: {
            [thresholdSessionId]: { ok: true, remainingUses: 8 },
          },
        }),
      ],
      walletBudgetStores: [walletBudgetStore],
    });

    await expect(
      policy.consumeUseCount?.({
        curve: 'ed25519',
        thresholdSessionId,
      }),
    ).resolves.toEqual({ ok: true, remainingUses: 3 });

    await expect(
      policy.consumeUseCount?.({
        curve: 'ecdsa',
        thresholdSessionId,
      }),
    ).resolves.toEqual({ ok: true, remainingUses: 8 });
  });
});
