import { expect, test } from '@playwright/test';
import { parseWalletSigningBudgetStatusRequest } from '@server/router/signingBudgetStatus';
import type {
  SigningSessionSealThresholdSessionPolicy,
  SigningSessionSealThresholdSessionStatus,
  SigningSessionSealWalletBudgetStatus,
} from '@server/threshold/session/signingSessionSeal/types';

function makeSession(claims: Record<string, unknown>) {
  return {
    parse: async () => ({ ok: true as const, claims }),
  };
}

function makeThresholdStatus(input: {
  curve: 'ecdsa' | 'ed25519';
  thresholdSessionId: string;
  userId: string;
  rpId: string;
  relayerKeyId: string;
  participantIds: number[];
  expiresAtMs: number;
  remainingUses: number;
}): SigningSessionSealThresholdSessionStatus {
  return {
    kind: 'threshold_session',
    curve: input.curve,
    thresholdSessionId: input.thresholdSessionId,
    userId: input.userId,
    expiresAtMs: input.expiresAtMs,
    remainingUses: input.remainingUses,
    relayerKeyId: input.relayerKeyId,
    rpId: input.rpId,
    participantIds: input.participantIds,
  };
}

function makeWalletBudgetStatus(input: {
  curve: 'ecdsa' | 'ed25519';
  thresholdSessionId: string;
  walletSigningSessionId: string;
  userId: string;
  rpId: string;
  relayerKeyId: string;
  participantIds: number[];
  expiresAtMs: number;
  remainingUses: number;
}): SigningSessionSealWalletBudgetStatus {
  return {
    kind: 'wallet_budget',
    curve: input.curve,
    thresholdSessionId: input.thresholdSessionId,
    walletSigningSessionId: input.walletSigningSessionId,
    userId: input.userId,
    expiresAtMs: input.expiresAtMs,
    remainingUses: input.remainingUses,
    relayerKeyId: input.relayerKeyId,
    rpId: input.rpId,
    participantIds: input.participantIds,
  };
}

function makePolicy(input: {
  thresholdStatuses?: SigningSessionSealThresholdSessionStatus[];
  walletBudgetStatus?: SigningSessionSealWalletBudgetStatus | null;
}): SigningSessionSealThresholdSessionPolicy {
  return {
    async getThresholdSession() {
      return null;
    },
    async getThresholdSessionStatuses() {
      return input.thresholdStatuses || [];
    },
    async getWalletBudgetStatus() {
      return input.walletBudgetStatus || null;
    },
  };
}

function makeEcdsaClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sub: 'wallet-ecdsa',
    walletId: 'wallet-ecdsa',
    kind: 'threshold_ecdsa_session_v1',
    sessionId: 'threshold-session-ecdsa',
    walletSigningSessionId: 'wallet-signing-session-ecdsa',
    subjectId: 'wallet-ecdsa',
    chainTarget: {
      kind: 'evm',
      namespace: 'eip155',
      chainId: 11155111,
      networkSlug: 'ethereum-sepolia',
    },
    ecdsaThresholdKeyId: 'ecdsa-key-1',
    relayerKeyId: 'ecdsa-relayer-1',
    rpId: 'example.localhost',
    thresholdExpiresAtMs: Date.now() + 60_000,
    participantIds: [1, 2],
    ...overrides,
  };
}

function makeEd25519Claims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sub: 'wallet-ed25519',
    walletId: 'wallet-ed25519',
    kind: 'threshold_ed25519_session_v1',
    sessionId: 'threshold-session-ed25519',
    walletSigningSessionId: 'wallet-signing-session-ed25519',
    relayerKeyId: 'ed25519-relayer-1',
    rpId: 'example.localhost',
    thresholdExpiresAtMs: Date.now() + 60_000,
    participantIds: [1, 2],
    ...overrides,
  };
}

test.describe('signing budget status parser', () => {
  test('rejects ECDSA claims when curve-bound auth identity is incomplete', async () => {
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer ecdsa-token' },
      session: makeSession(
        makeEcdsaClaims({
        walletSigningSessionId: '',
        }),
      ),
      sessionPolicy: null,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.body.code).toBe('unauthorized');
  });

  test('rejects Ed25519 claims when curve-bound auth material is incomplete', async () => {
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer ed25519-token' },
      session: makeSession(
        makeEd25519Claims({
        relayerKeyId: '',
        }),
      ),
      sessionPolicy: null,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.body.code).toBe('unauthorized');
  });

  test('rejects claims when thresholdSessionId is missing', async () => {
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer missing-threshold-session' },
      session: makeSession(
        makeEd25519Claims({
          sessionId: '',
        }),
      ),
      sessionPolicy: null,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.body.code).toBe('unauthorized');
  });

  test('rejects claims when the curve discriminant is missing', async () => {
    const rawClaims = makeEcdsaClaims();
    delete rawClaims.kind;
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer missing-curve' },
      session: makeSession(rawClaims),
      sessionPolicy: null,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.body.code).toBe('unauthorized');
  });

  test('rejects claims when thresholdSessionId no longer resolves on the requested curve', async () => {
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer wrong-threshold-session' },
      session: makeSession(makeEd25519Claims()),
      sessionPolicy: makePolicy({
        thresholdStatuses: [],
        walletBudgetStatus: makeWalletBudgetStatus({
          curve: 'ed25519',
          thresholdSessionId: 'wallet-signing:wallet-signing-session-ed25519',
          walletSigningSessionId: 'wallet-signing-session-ed25519',
          userId: 'wallet-ed25519',
          rpId: 'example.localhost',
          relayerKeyId: 'ed25519-relayer-1',
          participantIds: [1, 2],
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
        }),
      }),
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.body.code).toBe('unauthorized');
  });

  test('rejects claims when walletSigningSessionId no longer resolves on the requested curve', async () => {
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer wrong-wallet-signing-session' },
      session: makeSession(makeEcdsaClaims()),
      sessionPolicy: makePolicy({
        thresholdStatuses: [
          makeThresholdStatus({
            curve: 'ecdsa',
            thresholdSessionId: 'threshold-session-ecdsa',
            userId: 'wallet-ecdsa',
            rpId: 'example.localhost',
            relayerKeyId: 'ecdsa-relayer-1',
            participantIds: [1, 2],
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 5,
          }),
        ],
        walletBudgetStatus: null,
      }),
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.body.code).toBe('unauthorized');
  });

  test('rejects claims when participant ids do not match the curve-bound status record', async () => {
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer wrong-participants' },
      session: makeSession(makeEd25519Claims()),
      sessionPolicy: makePolicy({
        thresholdStatuses: [
          makeThresholdStatus({
            curve: 'ed25519',
            thresholdSessionId: 'threshold-session-ed25519',
            userId: 'wallet-ed25519',
            rpId: 'example.localhost',
            relayerKeyId: 'ed25519-relayer-1',
            participantIds: [7, 8],
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 4,
          }),
        ],
        walletBudgetStatus: makeWalletBudgetStatus({
          curve: 'ed25519',
          thresholdSessionId: 'wallet-signing:wallet-signing-session-ed25519',
          walletSigningSessionId: 'wallet-signing-session-ed25519',
          userId: 'wallet-ed25519',
          rpId: 'example.localhost',
          relayerKeyId: 'ed25519-relayer-1',
          participantIds: [7, 8],
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
        }),
      }),
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.body.code).toBe('unauthorized');
  });

  test('rejects claims when relayer key ids do not match the curve-bound status record', async () => {
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer wrong-auth-material' },
      session: makeSession(makeEcdsaClaims()),
      sessionPolicy: makePolicy({
        thresholdStatuses: [
          makeThresholdStatus({
            curve: 'ecdsa',
            thresholdSessionId: 'threshold-session-ecdsa',
            userId: 'wallet-ecdsa',
            rpId: 'example.localhost',
            relayerKeyId: 'wrong-relayer-key',
            participantIds: [1, 2],
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 4,
          }),
        ],
        walletBudgetStatus: makeWalletBudgetStatus({
          curve: 'ecdsa',
          thresholdSessionId: 'wallet-signing:wallet-signing-session-ecdsa',
          walletSigningSessionId: 'wallet-signing-session-ecdsa',
          userId: 'wallet-ecdsa',
          rpId: 'example.localhost',
          relayerKeyId: 'wrong-relayer-key',
          participantIds: [1, 2],
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
        }),
      }),
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.body.code).toBe('unauthorized');
  });
});
