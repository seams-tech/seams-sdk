import { expect, test } from '@playwright/test';
import type {
  Ed25519AuthSessionStatus,
  Ed25519AuthSessionStore,
  ThresholdEd25519AuthConsumeUsesResult,
} from '../../server/src/core/ThresholdService/stores/AuthSessionStore';
import { signerBoundWalletSigningBudgetSessionId } from '../../server/src/core/ThresholdService/walletSigningBudget';
import { createSigningSessionSealPolicyFromThresholdAuthSessionStores } from '../../server/src/threshold/session/signingSessionSeal/policy/sessionPolicy';

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
}): Ed25519AuthSessionStatus {
  return {
    record: {
      userId: input.userId,
      rpId: input.rpId,
      relayerKeyId: input.relayerKeyId,
      participantIds: input.participantIds,
      expiresAtMs: input.expiresAtMs,
      ...(input.walletBudgetBinding ? { walletBudgetBinding: input.walletBudgetBinding } : {}),
    },
    expiresAtMs: input.expiresAtMs,
    remainingUses: input.remainingUses,
  };
}

function makeStore(entries: {
  sessions?: Record<string, Ed25519AuthSessionStatus | null>;
  consume?: Record<string, ThresholdEd25519AuthConsumeUsesResult>;
}): Ed25519AuthSessionStore {
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
    const walletBudgetStore = makeStore({});
    const policy = createSigningSessionSealPolicyFromThresholdAuthSessionStores({
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
        makeStore({
          sessions: {
            [thresholdSessionId]: makeStatus({
              userId: 'alice',
              rpId: 'rp-ecdsa.example',
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
      rpId: 'rp-ecdsa.example',
      participantIds: [3, 4],
    });
  });

  test('looks up threshold session status only within the requested curve family', async () => {
    const thresholdSessionId = 'shared-threshold-session';
    const walletBudgetStore = makeStore({});
    const policy = createSigningSessionSealPolicyFromThresholdAuthSessionStores({
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
        makeStore({
          sessions: {
            [thresholdSessionId]: makeStatus({
              userId: 'alice',
              rpId: 'rp-ecdsa.example',
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
        kind: 'threshold_session',
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
        kind: 'threshold_session',
        curve: 'ecdsa',
        thresholdSessionId,
        userId: 'alice',
        expiresAtMs: 222_000,
        remainingUses: 9,
        relayerKeyId: 'relayer-ecdsa',
        rpId: 'rp-ecdsa.example',
        participantIds: [3, 4],
      },
    ]);
  });

  test('looks up wallet budget status from the shared wallet budget store', async () => {
    const budgetSessionId = 'budget-session';
    const walletBudgetThresholdSessionId = 'threshold-ed25519-budget-session';
    const walletBudgetStoreSessionId = signerBoundWalletSigningBudgetSessionId({
      walletSigningSessionId: budgetSessionId,
      curve: 'ed25519',
      thresholdSessionId: walletBudgetThresholdSessionId,
    });
    const walletBudgetStore = makeStore({
      sessions: {
        [walletBudgetStoreSessionId]: makeStatus({
          userId: 'alice',
          rpId: 'rp-wallet-budget.example',
          relayerKeyId: 'relayer-wallet-budget',
          participantIds: [5, 6],
          expiresAtMs: 333_000,
          remainingUses: 2,
          walletBudgetBinding: {
            curve: 'ed25519',
            thresholdSessionId: walletBudgetThresholdSessionId,
          },
        }),
      },
    });
    const policy = createSigningSessionSealPolicyFromThresholdAuthSessionStores({
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
        makeStore({
          sessions: {
            [walletBudgetThresholdSessionId]: makeStatus({
              userId: 'alice',
              rpId: 'rp-ecdsa.example',
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
        walletSigningSessionId: budgetSessionId,
        thresholdSessionId: walletBudgetThresholdSessionId,
      }),
    ).resolves.toEqual({
      kind: 'wallet_budget',
      curve: 'ed25519',
      thresholdSessionId: walletBudgetThresholdSessionId,
      walletSigningSessionId: budgetSessionId,
      userId: 'alice',
      expiresAtMs: 333_000,
      remainingUses: 2,
      relayerKeyId: 'relayer-wallet-budget',
      rpId: 'rp-wallet-budget.example',
      participantIds: [5, 6],
    });

    await expect(
      policy.getWalletBudgetStatus?.({
        curve: 'ecdsa',
        walletSigningSessionId: budgetSessionId,
        thresholdSessionId: walletBudgetThresholdSessionId,
      }),
    ).resolves.toBeNull();
  });

  test('keeps signer-bound wallet budgets independent under one wallet signing session id', async () => {
    const walletSigningSessionId = 'shared-wallet-session';
    const ed25519ThresholdSessionId = 'threshold-ed25519-shared-wallet';
    const ecdsaThresholdSessionId = 'threshold-ecdsa-shared-wallet';
    const ed25519BudgetSessionId = signerBoundWalletSigningBudgetSessionId({
      walletSigningSessionId,
      curve: 'ed25519',
      thresholdSessionId: ed25519ThresholdSessionId,
    });
    const ecdsaBudgetSessionId = signerBoundWalletSigningBudgetSessionId({
      walletSigningSessionId,
      curve: 'ecdsa',
      thresholdSessionId: ecdsaThresholdSessionId,
    });
    const walletBudgetStore = makeStore({
      sessions: {
        [ed25519BudgetSessionId]: makeStatus({
          userId: 'alice',
          rpId: 'rp-wallet-budget.example',
          relayerKeyId: 'relayer-wallet-budget',
          participantIds: [1, 2],
          expiresAtMs: 333_000,
          remainingUses: 2,
          walletBudgetBinding: {
            curve: 'ed25519',
            thresholdSessionId: ed25519ThresholdSessionId,
          },
        }),
        [ecdsaBudgetSessionId]: makeStatus({
          userId: 'alice',
          rpId: 'rp-wallet-budget.example',
          relayerKeyId: 'relayer-wallet-budget',
          participantIds: [1, 2],
          expiresAtMs: 444_000,
          remainingUses: 3,
          walletBudgetBinding: {
            curve: 'ecdsa',
            thresholdSessionId: ecdsaThresholdSessionId,
          },
        }),
      },
    });
    const policy = createSigningSessionSealPolicyFromThresholdAuthSessionStores({
      ed25519Stores: [],
      ecdsaStores: [],
      walletBudgetStores: [walletBudgetStore],
    });

    await expect(
      policy.getWalletBudgetStatus?.({
        curve: 'ed25519',
        walletSigningSessionId,
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
        walletSigningSessionId,
        thresholdSessionId: ecdsaThresholdSessionId,
      }),
    ).resolves.toMatchObject({
      curve: 'ecdsa',
      thresholdSessionId: ecdsaThresholdSessionId,
      remainingUses: 3,
    });
    await expect(
      policy.getWalletBudgetStatus?.({
        curve: 'ecdsa',
        walletSigningSessionId,
        thresholdSessionId: ed25519ThresholdSessionId,
      }),
    ).resolves.toBeNull();
  });

  test('consumes use counts only within the requested curve family', async () => {
    const thresholdSessionId = 'shared-threshold-session';
    const walletBudgetStore = makeStore({});
    const policy = createSigningSessionSealPolicyFromThresholdAuthSessionStores({
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
        makeStore({
          sessions: {
            [thresholdSessionId]: makeStatus({
              userId: 'alice',
              rpId: 'rp-ecdsa.example',
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
