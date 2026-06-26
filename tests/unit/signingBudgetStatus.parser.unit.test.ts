import { expect, test } from '@playwright/test';
import { parseWalletSigningBudgetStatusRequest } from '@server/router/signingBudgetStatus';
import {
  ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
} from '@shared/utils/sessionTokens';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { base64UrlEncode } from '@shared/utils/encoders';
import type {
  SigningSessionSealThresholdSessionPolicy,
  SigningSessionSealThresholdSessionStatus,
  SigningSessionSealWalletBudgetStatus,
} from '@server/threshold/session/signingSessionSeal/signingSessionSeal.types';

function makeSession(claims: Record<string, unknown>) {
  return {
    parse: async () => ({ ok: true as const, claims }),
  };
}

function b64u(bytes: number[]): string {
  return base64UrlEncode(Uint8Array.from(bytes));
}

type ThresholdStatusFixtureInput = {
  curve: 'ecdsa' | 'ed25519';
  thresholdSessionId: string;
  userId: string;
  relayerKeyId: string;
  participantIds: number[];
  expiresAtMs: number;
  remainingUses: number;
} & (
  | { curve: 'ecdsa'; walletKeyId: string; rpId?: never }
  | { curve: 'ed25519'; rpId: string; walletKeyId?: never }
);

function makeThresholdStatus(input: ThresholdStatusFixtureInput): SigningSessionSealThresholdSessionStatus {
  const base = {
    kind: 'wallet_session' as const,
    curve: input.curve,
    thresholdSessionId: input.thresholdSessionId,
    userId: input.userId,
    expiresAtMs: input.expiresAtMs,
    remainingUses: input.remainingUses,
    relayerKeyId: input.relayerKeyId,
    participantIds: input.participantIds,
  };
  switch (input.curve) {
    case 'ecdsa':
      return {
        ...base,
        curve: 'ecdsa',
        walletKeyId: input.walletKeyId,
      };
    case 'ed25519':
      return {
        ...base,
        curve: 'ed25519',
        rpId: input.rpId,
      };
  }
}

type WalletBudgetStatusFixtureInput = {
  curve: 'ecdsa' | 'ed25519';
  thresholdSessionId: string;
  signingGrantId: string;
  userId: string;
  participantIds: number[];
  expiresAtMs: number;
  remainingUses: number;
} & (
  | { curve: 'ecdsa'; walletKeyId: string; rpId?: never }
  | { curve: 'ed25519'; rpId: string; walletKeyId?: never }
);

function makeWalletBudgetStatus(
  input: WalletBudgetStatusFixtureInput,
): SigningSessionSealWalletBudgetStatus {
  const base = {
    kind: 'wallet_budget' as const,
    curve: input.curve,
    thresholdSessionId: input.thresholdSessionId,
    signingGrantId: input.signingGrantId,
    userId: input.userId,
    expiresAtMs: input.expiresAtMs,
    remainingUses: input.remainingUses,
    committedRemainingUses: input.remainingUses,
    reservedUses: 0,
    availableUses: input.remainingUses,
    relayerKeyId: 'wallet-signing-budget',
    participantIds: input.participantIds,
  };
  switch (input.curve) {
    case 'ecdsa':
      return {
        ...base,
        curve: 'ecdsa',
        walletKeyId: input.walletKeyId,
      };
    case 'ed25519':
      return {
        ...base,
        curve: 'ed25519',
        rpId: input.rpId,
      };
  }
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
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    thresholdSessionId: 'threshold-session-ecdsa',
    signingGrantId: 'signing-grant-ecdsa',
    keyScope: 'evm-family',
    subjectId: 'wallet-ecdsa',
    chainTarget: {
      kind: 'evm',
      namespace: 'eip155',
      chainId: 11155111,
      networkSlug: 'ethereum-sepolia',
    },
    keyHandle: 'ehss-key-1',
    relayerKeyId: 'ecdsa-relayer-1',
    walletKeyId: 'wallet-key-ecdsa',
    thresholdExpiresAtMs: Date.now() + 60_000,
    participantIds: [1, 2],
    routerAbEcdsaHssNormalSigning: {
      kind: 'router_ab_ecdsa_hss_normal_signing_v1',
      scope: {
        wallet_key_id: 'wallet-key-ecdsa',
        wallet_id: 'wallet-ecdsa',
        ecdsa_threshold_key_id: 'ehss-key-1',
        signing_root_id: 'signing-root-1',
        signing_root_version: 'v1',
        context: {
          application_binding_digest_b64u: b64u(Array.from({ length: 32 }, () => 7)),
        },
        public_identity: {
          context_binding_b64u: b64u(Array.from({ length: 32 }, (_, index) => index + 1)),
          client_public_key33_b64u: b64u([0x02, ...Array.from({ length: 32 }, () => 1)]),
          server_public_key33_b64u: b64u([0x03, ...Array.from({ length: 32 }, () => 2)]),
          threshold_public_key33_b64u: b64u([0x02, ...Array.from({ length: 32 }, () => 3)]),
          ethereum_address20_b64u: b64u(Array.from({ length: 20 }, () => 0x11)),
          client_share_retry_counter: 0,
          server_share_retry_counter: 0,
        },
        signing_worker: {
          server_id: 'signing-worker-1',
          key_epoch: 'signing-worker-output-epoch',
          recipient_encryption_key: `x25519:${'33'.repeat(32)}`,
        },
        activation_epoch: 'activation-epoch-1',
      },
    },
    ...overrides,
  };
}

function makeEd25519Claims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sub: 'wallet-ed25519',
    walletId: 'wallet-ed25519',
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    nearAccountId: 'alice.testnet',
    nearEd25519SigningKeyId: 'wallet-ed25519',
    thresholdSessionId: 'threshold-session-ed25519',
    signingGrantId: 'signing-grant-ed25519',
    relayerKeyId: 'ed25519-relayer-1',
    rpId: 'example.localhost',
    thresholdExpiresAtMs: Date.now() + 60_000,
    participantIds: [1, 2],
    runtimePolicyScope: {
      orgId: 'org',
      projectId: 'project',
      envId: 'dev',
      signingRootVersion: 'v1',
    },
    routerAbNormalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: 'signing-worker-1',
    },
    ...overrides,
  };
}

test.describe('signing budget status parser', () => {
  test('returns ECDSA wallet budget status requests with keyHandle identity', async () => {
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer ecdsa-token' },
      session: makeSession(makeEcdsaClaims()),
      sessionPolicy: makePolicy({
        thresholdStatuses: [
          makeThresholdStatus({
            curve: 'ecdsa',
            thresholdSessionId: 'threshold-session-ecdsa',
            userId: 'wallet-ecdsa',
            walletKeyId: 'wallet-key-ecdsa',
            relayerKeyId: 'ecdsa-relayer-1',
            participantIds: [1, 2],
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 5,
          }),
        ],
        walletBudgetStatus: makeWalletBudgetStatus({
          curve: 'ecdsa',
          thresholdSessionId: 'threshold-session-ecdsa',
          signingGrantId: 'signing-grant-ecdsa',
          userId: 'wallet-ecdsa',
          walletKeyId: 'wallet-key-ecdsa',
          participantIds: [1, 2],
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
        }),
      }),
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.request).toMatchObject({
      kind: 'ecdsa_wallet_budget_status',
      keyHandle: 'ehss-key-1',
    });
  });

  test('accepts Router A/B ECDSA-HSS Wallet Session JWT claims for budget status', async () => {
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer router-ab-ecdsa-token' },
      session: makeSession(
        makeEcdsaClaims({ kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND }),
      ),
      sessionPolicy: makePolicy({
        thresholdStatuses: [
          makeThresholdStatus({
            curve: 'ecdsa',
            thresholdSessionId: 'threshold-session-ecdsa',
            userId: 'wallet-ecdsa',
            walletKeyId: 'wallet-key-ecdsa',
            relayerKeyId: 'ecdsa-relayer-1',
            participantIds: [1, 2],
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 5,
          }),
        ],
        walletBudgetStatus: makeWalletBudgetStatus({
          curve: 'ecdsa',
          thresholdSessionId: 'threshold-session-ecdsa',
          signingGrantId: 'signing-grant-ecdsa',
          userId: 'wallet-ecdsa',
          walletKeyId: 'wallet-key-ecdsa',
          participantIds: [1, 2],
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
        }),
      }),
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.request).toMatchObject({
      kind: 'ecdsa_wallet_budget_status',
      keyHandle: 'ehss-key-1',
    });
  });

  test('accepts Router A/B Ed25519 Wallet Session JWT claims for budget status', async () => {
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer router-ab-ed25519-token' },
      session: makeSession(
        makeEd25519Claims({ kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND }),
      ),
      sessionPolicy: makePolicy({
        thresholdStatuses: [
          makeThresholdStatus({
            curve: 'ed25519',
            thresholdSessionId: 'threshold-session-ed25519',
            userId: 'wallet-ed25519',
            rpId: 'example.localhost',
            relayerKeyId: 'ed25519-relayer-1',
            participantIds: [1, 2],
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 4,
          }),
        ],
        walletBudgetStatus: makeWalletBudgetStatus({
          curve: 'ed25519',
          thresholdSessionId: 'threshold-session-ed25519',
          signingGrantId: 'signing-grant-ed25519',
          userId: 'wallet-ed25519',
          rpId: 'example.localhost',
          participantIds: [1, 2],
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
        }),
      }),
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.request).toMatchObject({
      kind: 'ed25519_wallet_budget_status',
      ed25519RelayerKeyId: 'ed25519-relayer-1',
    });
  });

  test('rejects legacy threshold-session JWT claims for budget status', async () => {
    for (const claims of [
      makeEcdsaClaims({ kind: 'threshold_ecdsa_session_v2' }),
      makeEd25519Claims({ kind: 'threshold_ed25519_session_v1' }),
    ]) {
      const result = await parseWalletSigningBudgetStatusRequest({
        headers: { Authorization: 'Bearer legacy-threshold-session-token' },
        session: makeSession(claims),
        sessionPolicy: null,
      });

      expect(result.ok).toBe(false);
      if (result.ok) continue;
      expect(result.status).toBe(401);
      expect(result.body.code).toBe('unauthorized');
    }
  });

  test('rejects wallet budget status from another curve authority namespace', async () => {
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer ecdsa-token' },
      session: makeSession(
        makeEcdsaClaims({
          signingGrantId: 'shared-signing-grant',
        }),
      ),
      sessionPolicy: makePolicy({
        thresholdStatuses: [
          makeThresholdStatus({
            curve: 'ecdsa',
            thresholdSessionId: 'threshold-session-ecdsa',
            userId: 'wallet-ecdsa',
            walletKeyId: 'wallet-key-ecdsa',
            relayerKeyId: 'ecdsa-relayer-1',
            participantIds: [1, 2],
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 5,
          }),
        ],
        walletBudgetStatus: makeWalletBudgetStatus({
          curve: 'ed25519',
          thresholdSessionId: 'threshold-session-ed25519',
          signingGrantId: 'shared-signing-grant',
          userId: 'wallet-ecdsa',
          rpId: 'example.localhost',
          participantIds: [1, 2],
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
        }),
      }),
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(403);
    expect(result.body.code).toBe('wallet_budget_forbidden');
  });

  test('rejects wallet budget status from another threshold session', async () => {
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer wrong-wallet-budget-threshold-session' },
      session: makeSession(makeEd25519Claims()),
      sessionPolicy: makePolicy({
        thresholdStatuses: [
          makeThresholdStatus({
            curve: 'ed25519',
            thresholdSessionId: 'threshold-session-ed25519',
            userId: 'wallet-ed25519',
            rpId: 'example.localhost',
            relayerKeyId: 'ed25519-relayer-1',
            participantIds: [1, 2],
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 4,
          }),
        ],
        walletBudgetStatus: makeWalletBudgetStatus({
          curve: 'ed25519',
          thresholdSessionId: 'different-threshold-session-ed25519',
          signingGrantId: 'signing-grant-ed25519',
          userId: 'wallet-ed25519',
          rpId: 'example.localhost',
          participantIds: [1, 2],
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
        }),
      }),
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(403);
    expect(result.body.code).toBe('wallet_budget_forbidden');
  });

  test('rejects claims when backend wallet budget record is expired', async () => {
    const nowMs = Date.now();
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer expired-wallet-budget' },
      session: makeSession(
        makeEd25519Claims({
          thresholdExpiresAtMs: nowMs + 60_000,
        }),
      ),
      sessionPolicy: makePolicy({
        thresholdStatuses: [
          makeThresholdStatus({
            curve: 'ed25519',
            thresholdSessionId: 'threshold-session-ed25519',
            userId: 'wallet-ed25519',
            rpId: 'example.localhost',
            relayerKeyId: 'ed25519-relayer-1',
            participantIds: [1, 2],
            expiresAtMs: nowMs + 60_000,
            remainingUses: 4,
          }),
        ],
        walletBudgetStatus: makeWalletBudgetStatus({
          curve: 'ed25519',
          thresholdSessionId: 'threshold-session-ed25519',
          signingGrantId: 'signing-grant-ed25519',
          userId: 'wallet-ed25519',
          rpId: 'example.localhost',
          participantIds: [1, 2],
          expiresAtMs: nowMs - 1,
          remainingUses: 3,
        }),
      }),
      nowMs: () => nowMs,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(403);
    expect(result.body.code).toBe('wallet_budget_forbidden');
    expect(result.body.message).toBe('Wallet Session budget is no longer active');
  });

  test('rejects claims when backend curve status is expired', async () => {
    const nowMs = Date.now();
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer expired-curve-status' },
      session: makeSession(makeEd25519Claims()),
      sessionPolicy: makePolicy({
        thresholdStatuses: [
          makeThresholdStatus({
            curve: 'ed25519',
            thresholdSessionId: 'threshold-session-ed25519',
            userId: 'wallet-ed25519',
            rpId: 'example.localhost',
            relayerKeyId: 'ed25519-relayer-1',
            participantIds: [1, 2],
            expiresAtMs: nowMs - 1,
            remainingUses: 4,
          }),
        ],
        walletBudgetStatus: makeWalletBudgetStatus({
          curve: 'ed25519',
          thresholdSessionId: 'threshold-session-ed25519',
          signingGrantId: 'signing-grant-ed25519',
          userId: 'wallet-ed25519',
          rpId: 'example.localhost',
          participantIds: [1, 2],
          expiresAtMs: nowMs + 60_000,
          remainingUses: 3,
        }),
      }),
      nowMs: () => nowMs,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(403);
    expect(result.body.code).toBe('wallet_budget_forbidden');
  });

  test('rejects ECDSA claims when curve-bound auth identity is incomplete', async () => {
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer ecdsa-token' },
      session: makeSession(
        makeEcdsaClaims({
          keyHandle: '',
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
          thresholdSessionId: '',
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
          thresholdSessionId: 'threshold-session-ed25519',
          signingGrantId: 'signing-grant-ed25519',
          userId: 'wallet-ed25519',
          rpId: 'example.localhost',
          participantIds: [1, 2],
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
        }),
      }),
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(403);
    expect(result.body.code).toBe('wallet_budget_forbidden');
  });

  test('rejects claims when signingGrantId no longer resolves on the requested curve', async () => {
    const result = await parseWalletSigningBudgetStatusRequest({
      headers: { Authorization: 'Bearer wrong-signing-grant' },
      session: makeSession(makeEcdsaClaims()),
      sessionPolicy: makePolicy({
        thresholdStatuses: [
          makeThresholdStatus({
            curve: 'ecdsa',
            thresholdSessionId: 'threshold-session-ecdsa',
            userId: 'wallet-ecdsa',
            walletKeyId: 'wallet-key-ecdsa',
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
    expect(result.status).toBe(403);
    expect(result.body.code).toBe('wallet_budget_forbidden');
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
          thresholdSessionId: 'threshold-session-ed25519',
          signingGrantId: 'signing-grant-ed25519',
          userId: 'wallet-ed25519',
          rpId: 'example.localhost',
          participantIds: [7, 8],
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
        }),
      }),
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(403);
    expect(result.body.code).toBe('wallet_budget_forbidden');
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
            walletKeyId: 'wallet-key-ecdsa',
            relayerKeyId: 'wrong-relayer-key',
            participantIds: [1, 2],
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 4,
          }),
        ],
        walletBudgetStatus: makeWalletBudgetStatus({
          curve: 'ecdsa',
          thresholdSessionId: 'threshold-session-ecdsa',
          signingGrantId: 'signing-grant-ecdsa',
          userId: 'wallet-ecdsa',
          walletKeyId: 'wallet-key-ecdsa',
          participantIds: [1, 2],
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
        }),
      }),
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(403);
    expect(result.body.code).toBe('wallet_budget_forbidden');
  });
});
