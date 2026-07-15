import { expect, test } from '@playwright/test';
import type {
  EcdsaWalletSessionStatus,
  EcdsaWalletSessionStore,
  Ed25519WalletSessionStatus,
  Ed25519WalletSessionStore,
  WalletSessionConsumeUsesResult,
  WalletSigningBudgetBindings,
  WalletSigningBudgetSessionStatus,
  WalletSigningBudgetSessionStore,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore';
import { walletSigningBudgetSessionId } from '../../packages/sdk-server-ts/src/core/ThresholdService/walletSigningBudget';
import { createSigningSessionSealPolicyFromWalletSessionStores } from '../../packages/sdk-server-ts/src/threshold/session/signingSessionSeal/policy/sessionPolicy';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';

function webAuthnRpId(value: string) {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error('invalid rpId fixture');
  return parsed.value;
}

function makeStatus(input: {
  userId: string;
  rpId: string;
  relayerKeyId: string;
  participantIds: number[];
  expiresAtMs: number;
  remainingUses: number;
}): Ed25519WalletSessionStatus {
  return {
    record: {
      userId: input.userId,
      walletId: input.userId,
      nearAccountId: input.userId,
      nearEd25519SigningKeyId: input.userId,
      authorityScope: { kind: 'passkey_rp', rpId: webAuthnRpId(input.rpId) },
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

function makeEcdsaStatus(input: {
  userId: string;
  evmFamilySigningKeySlotId: string;
  relayerKeyId: string;
  participantIds: number[];
  expiresAtMs: number;
  remainingUses: number;
}): EcdsaWalletSessionStatus {
  return {
    record: {
      walletId: input.userId,
      evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
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
  expiresAtMs: number;
  remainingUses: number;
  bindings: WalletSigningBudgetBindings;
}): WalletSigningBudgetSessionStatus {
  return {
    record: {
      kind: 'wallet_signing_budget_session',
      walletId: input.userId,
      expiresAtMs: input.expiresAtMs,
      bindings: input.bindings,
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
              evmFamilySigningKeySlotId: 'wallet-key-ecdsa.example',
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
      authorityScope: {
        kind: 'passkey_rp',
        rpId: webAuthnRpId('rp-ed25519.example'),
      },
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
      evmFamilySigningKeySlotId: 'wallet-key-ecdsa.example',
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
              evmFamilySigningKeySlotId: 'wallet-key-ecdsa.example',
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
        authorityScope: {
          kind: 'passkey_rp',
          rpId: webAuthnRpId('rp-ed25519.example'),
        },
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
        evmFamilySigningKeySlotId: 'wallet-key-ecdsa.example',
        participantIds: [3, 4],
      },
    ]);
  });

  test('looks up wallet budget status from the shared wallet budget store', async () => {
    const budgetSessionId = 'budget-session';
    const walletBudgetStoreSessionId = walletSigningBudgetSessionId({
      signingGrantId: budgetSessionId,
    });
    const walletBudgetStore = makeBudgetStore({
      sessions: {
        [walletBudgetStoreSessionId]: makeBudgetStatus({
          userId: 'alice',
          expiresAtMs: 333_000,
          remainingUses: 2,
          bindings: {
            kind: 'ed25519_only',
            ed25519: {
              thresholdSessionId: 'threshold-session-budget-ed25519',
              authorityScope: {
                kind: 'passkey_rp',
                rpId: webAuthnRpId('rp-budget.example'),
              },
              participantIds: [5, 6],
            },
          },
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
        signingGrantId: budgetSessionId,
      }),
    ).resolves.toEqual({
      kind: 'wallet_budget',
      signingGrantId: budgetSessionId,
      userId: 'alice',
      expiresAtMs: 333_000,
      remainingUses: 2,
      committedRemainingUses: 2,
      reservedUses: 0,
      availableUses: 2,
      relayerKeyId: 'wallet-signing-budget',
      bindings: {
        kind: 'ed25519_only',
        ed25519: {
          thresholdSessionId: 'threshold-session-budget-ed25519',
          authorityScope: {
            kind: 'passkey_rp',
            rpId: webAuthnRpId('rp-budget.example'),
          },
          participantIds: [5, 6],
        },
      },
    });

    await expect(
      policy.getWalletBudgetStatus?.({
        signingGrantId: 'missing-budget-session',
      }),
    ).resolves.toBeNull();
  });

  test('wallet budget status is shared across curve-specific threshold sessions', async () => {
    const signingGrantId = 'combined-registration-shared-grant';
    const walletBudgetStore = makeBudgetStore({
      sessions: {
        [walletSigningBudgetSessionId({ signingGrantId })]: makeBudgetStatus({
          userId: 'alice',
          expiresAtMs: 444_000,
          remainingUses: 7,
          bindings: {
            kind: 'ed25519_and_ecdsa',
            ed25519: {
              thresholdSessionId: 'threshold-session-shared-ed25519',
              authorityScope: {
                kind: 'passkey_rp',
                rpId: webAuthnRpId('rp-shared.example'),
              },
              participantIds: [1, 2],
            },
            ecdsa: [
              {
                thresholdSessionId: 'threshold-session-shared-ecdsa',
                evmFamilySigningKeySlotId: 'evm-family-shared-slot',
                participantIds: [1, 2, 3],
              },
            ],
          },
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
        signingGrantId,
      }),
    ).resolves.toMatchObject({
      signingGrantId,
      remainingUses: 7,
      bindings: {
        kind: 'ed25519_and_ecdsa',
        ed25519: { participantIds: [1, 2] },
        ecdsa: [{ participantIds: [1, 2, 3] }],
      },
    });
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
              evmFamilySigningKeySlotId: 'wallet-key-ecdsa.example',
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
