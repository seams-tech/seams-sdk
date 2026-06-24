import { test, expect } from '@playwright/test';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import { createRelayRouter } from '@server/router/express-adaptor';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  createInMemorySigningSessionSealIdempotencyStore,
  createInMemorySigningSessionSealRateLimiter,
  createPassthroughSigningSessionSealCipherAdapter,
  createSigningSessionSealCipherAdapter,
  createSigningSessionSealRoutesOptions,
  createSigningSessionSealService,
  createSigningSessionSealShamir3PassCipherAdapter,
  resolveSigningSessionSealIdempotencyFromEnv,
  resolveSigningSessionSealRateLimitFromEnv,
} from '@server/threshold/session/signingSessionSeal';
import {
  callCf,
  fetchJson,
  makeFakeAuthService,
  makeSessionAdapter,
  startExpressRouter,
} from './helpers';

const FRONTEND_ORIGIN = 'https://example.localhost';
const THRESHOLD_SESSION_ID = 'sess-12345678';
const USER_ID = 'alice.testnet';
const ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND = 'router_ab_ecdsa_hss_wallet_session_v1';

function b64u(bytes: number[]): string {
  return base64UrlEncode(Uint8Array.from(bytes));
}

function makeThresholdSessionClaims(input?: { userId?: string; signingGrantId?: string }) {
  const userId = input?.userId || USER_ID;
  const signingGrantId = input?.signingGrantId || 'signing-grant-1';
  return {
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    sub: userId,
    walletId: userId,
    thresholdSessionId: THRESHOLD_SESSION_ID,
    signingGrantId,
    keyScope: 'evm-family' as const,
    keyHandle: 'ehss-key-seal-test',
    subjectId: userId,
    chainTarget: {
      kind: 'evm' as const,
      namespace: 'eip155' as const,
      chainId: 11155111,
      networkSlug: 'ethereum-sepolia',
    },
    ecdsaThresholdKeyId: 'ecdsa-threshold-key-1',
    relayerKeyId: 'relayer-key-1',
    walletKeyId: FRONTEND_ORIGIN.replace('https://', ''),
    thresholdExpiresAtMs: Date.now() + 60_000,
    participantIds: [1, 2],
    routerAbEcdsaHssNormalSigning: {
      kind: 'router_ab_ecdsa_hss_normal_signing_v1',
      scope: {
        wallet_key_id: FRONTEND_ORIGIN.replace('https://', ''),
        context: {
          wallet_id: userId,
          ecdsa_threshold_key_id: 'ecdsa-threshold-key-1',
          signing_root_id: 'signing-root-1',
          signing_root_version: 'v1',
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
        activation_epoch: THRESHOLD_SESSION_ID,
      },
    },
  };
}

function makeLegacyThresholdSessionClaims(input?: { userId?: string; signingGrantId?: string }) {
  return {
    ...makeThresholdSessionClaims(input),
    kind: 'threshold_ecdsa_session_v2' as const,
  };
}

function makeSession(userId = USER_ID) {
  return makeSessionAdapter({
    parse: async () => ({
      ok: true as const,
      claims: makeThresholdSessionClaims({ userId }),
    }),
  });
}

function makePolicy(
  input?: Partial<{
    userId: string;
    expiresAtMs: number;
    remainingUses: number;
  }>,
) {
  const sessionUserId = input?.userId || USER_ID;
  const expiresAtMs = Number.isFinite(Number(input?.expiresAtMs))
    ? Number(input?.expiresAtMs)
    : Date.now() + 60_000;
  const remainingUses = Number.isFinite(Number(input?.remainingUses))
    ? Number(input?.remainingUses)
    : 7;
  const signingGrantId = 'signing-grant-1';
  const participantIds = [1, 2] as const;
  const walletKeyId = FRONTEND_ORIGIN.replace('https://', '');
  const relayerKeyId = 'relayer-key-1';
  const thresholdSession = {
    curve: 'ecdsa' as const,
    thresholdSessionId: THRESHOLD_SESSION_ID,
    userId: sessionUserId,
    expiresAtMs,
    relayerKeyId,
    walletKeyId,
    participantIds,
    remainingUses,
  };
  const walletBudgetStatus = {
    kind: 'wallet_budget' as const,
    curve: 'ecdsa' as const,
    thresholdSessionId: `wallet-signing:${signingGrantId}`,
    signingGrantId,
    userId: sessionUserId,
    expiresAtMs,
    remainingUses,
    committedRemainingUses: remainingUses,
    reservedUses: 0,
    availableUses: remainingUses,
    relayerKeyId: 'wallet-signing-budget',
    walletKeyId,
    participantIds,
  };
  return {
    getThresholdSession: async ({
      curve,
      thresholdSessionId,
    }: {
      curve: 'ecdsa' | 'ed25519';
      thresholdSessionId: string;
    }) => {
      if (curve !== 'ecdsa' || thresholdSessionId !== THRESHOLD_SESSION_ID) return null;
      return thresholdSession;
    },
    getThresholdSessionStatuses: async ({
      curve,
      thresholdSessionId,
    }: {
      curve: 'ecdsa' | 'ed25519';
      thresholdSessionId: string;
    }) =>
      curve === 'ecdsa' && thresholdSessionId === THRESHOLD_SESSION_ID
        ? [{ kind: 'wallet_session' as const, ...thresholdSession }]
        : [],
    getWalletBudgetStatus: async ({
      curve,
      signingGrantId: requestedSigningGrantId,
    }: {
      curve: 'ecdsa' | 'ed25519';
      signingGrantId: string;
    }) =>
      curve === 'ecdsa' && requestedSigningGrantId === signingGrantId ? walletBudgetStatus : null,
    consumeUseCount: async () => ({
      ok: true as const,
      remainingUses: Math.max(0, remainingUses - 1),
    }),
  };
}

function makeBody(overrides?: Record<string, unknown>) {
  return {
    thresholdSessionId: THRESHOLD_SESSION_ID,
    ciphertext: 'ciphertext-b64u',
    keyVersion: 'signing-session-seal-kek-2026-02-r1',
    ...overrides,
  };
}

function encodePositiveBigIntB64u(value: bigint): string {
  if (value <= 0n) throw new Error('value must be > 0');
  const bytesReversed: number[] = [];
  let cursor = value;
  while (cursor > 0n) {
    bytesReversed.push(Number(cursor & 255n));
    cursor >>= 8n;
  }
  bytesReversed.reverse();
  return base64UrlEncode(Uint8Array.from(bytesReversed));
}

test.describe('signing-session seal routes', () => {
  test('express apply-server-seal returns sealed payload for owner', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      session: makeSession(),
      signingSessionSeal: createSigningSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createPassthroughSigningSessionSealCipherAdapter(),
      }),
    });

    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/v2/wallet-session/seal/apply-server-seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(makeBody()),
      });
      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);
      expect(res.json?.ciphertext).toBe('ciphertext-b64u');
      expect(res.json?.keyVersion).toBe('signing-session-seal-kek-2026-02-r1');
      expect(Number(res.json?.expiresAtMs)).toBeGreaterThan(Date.now());
    } finally {
      await srv.close();
    }
  });

  test('express apply-server-seal rejects legacy threshold-session JWT claims', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true as const,
          claims: makeLegacyThresholdSessionClaims(),
        }),
      }),
      signingSessionSeal: createSigningSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createPassthroughSigningSessionSealCipherAdapter(),
      }),
    });

    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/v2/wallet-session/seal/apply-server-seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(makeBody()),
      });
      expect(res.status).toBe(403);
      expect(res.json).toMatchObject({
        ok: false,
        code: 'forbidden',
        message: 'Wallet Session does not match requested thresholdSessionId',
      });
    } finally {
      await srv.close();
    }
  });

  test('express signing-session seal routes single-flight dedupe identical concurrent apply/remove requests', async () => {
    const service = makeFakeAuthService();
    let applyCalls = 0;
    let removeCalls = 0;
    const router = createRelayRouter(service, {
      session: makeSession(),
      signingSessionSeal: createSigningSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createSigningSessionSealCipherAdapter({
          applyServerSeal: async (input) => {
            applyCalls += 1;
            await new Promise((resolve) => setTimeout(resolve, 25));
            return {
              ok: true,
              ciphertext: `sealed:${input.ciphertext}`,
            };
          },
          removeServerSeal: async (input) => {
            removeCalls += 1;
            await new Promise((resolve) => setTimeout(resolve, 25));
            return {
              ok: true,
              ciphertext: `unsealed:${input.ciphertext}`,
            };
          },
        }),
      }),
    });

    const srv = await startExpressRouter(router);
    try {
      const [applyA, applyB] = await Promise.all([
        fetchJson(`${srv.baseUrl}/v2/wallet-session/seal/apply-server-seal`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(makeBody()),
        }),
        fetchJson(`${srv.baseUrl}/v2/wallet-session/seal/apply-server-seal`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(makeBody()),
        }),
      ]);
      expect(applyA.status).toBe(200);
      expect(applyB.status).toBe(200);
      expect(applyA.json?.ok).toBe(true);
      expect(applyB.json?.ok).toBe(true);
      expect(applyA.json?.ciphertext).toBe('sealed:ciphertext-b64u');
      expect(applyB.json?.ciphertext).toBe('sealed:ciphertext-b64u');
      expect(applyCalls).toBe(1);

      const [removeA, removeB] = await Promise.all([
        fetchJson(`${srv.baseUrl}/v2/wallet-session/seal/remove-server-seal`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(makeBody()),
        }),
        fetchJson(`${srv.baseUrl}/v2/wallet-session/seal/remove-server-seal`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(makeBody()),
        }),
      ]);
      expect(removeA.status).toBe(200);
      expect(removeB.status).toBe(200);
      expect(removeA.json?.ok).toBe(true);
      expect(removeB.json?.ok).toBe(true);
      expect(removeA.json?.ciphertext).toBe('unsealed:ciphertext-b64u');
      expect(removeB.json?.ciphertext).toBe('unsealed:ciphertext-b64u');
      expect(removeCalls).toBe(1);
    } finally {
      await srv.close();
    }
  });

  test('service idempotency does not replay wallet-budget-backed sequential apply requests', async () => {
    let applyCalls = 0;
    const service = createSigningSessionSealService({
      sessionPolicy: makePolicy(),
      cipher: createSigningSessionSealCipherAdapter({
        applyServerSeal: async (input) => {
          applyCalls += 1;
          return {
            ok: true,
            ciphertext: `sealed:${input.ciphertext}:${applyCalls}`,
          };
        },
        removeServerSeal: async (input) => ({
          ok: true,
          ciphertext: `unsealed:${input.ciphertext}`,
        }),
      }),
      idempotency: {
        store: createInMemorySigningSessionSealIdempotencyStore(),
        ttlMs: 10_000,
      },
    });

    const auth = { userId: USER_ID, claims: makeThresholdSessionClaims() };
    const request = makeBody();

    const first = await service.applyServerSeal(request, auth);
    const second = await service.applyServerSeal(request, auth);

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(first).toMatchObject({ ciphertext: 'sealed:ciphertext-b64u:1' });
    expect(second).toMatchObject({ ciphertext: 'sealed:ciphertext-b64u:2' });
    expect(applyCalls).toBe(2);
  });

  test('service reports the shared signing grant budget instead of curve-session uses', async () => {
    const signingGrantId = 'wallet-session-seal-budget';
    const service = createSigningSessionSealService({
      sessionPolicy: {
        getThresholdSession: async () => ({
          curve: 'ecdsa',
          thresholdSessionId: THRESHOLD_SESSION_ID,
          userId: USER_ID,
          expiresAtMs: Date.now() + 60_000,
          relayerKeyId: 'relayer-key-1',
          walletKeyId: 'localhost',
          participantIds: [1, 2],
          remainingUses: 7,
        }),
        getThresholdSessionStatuses: async () => [],
        getWalletBudgetStatus: async ({ signingGrantId: requestedSigningGrantId }) =>
          requestedSigningGrantId !== signingGrantId
            ? null
            : {
                kind: 'wallet_budget',
                curve: 'ecdsa',
                thresholdSessionId: `wallet-signing:${signingGrantId}`,
                signingGrantId,
                userId: USER_ID,
                expiresAtMs: Date.now() + 60_000,
                remainingUses: 2,
                committedRemainingUses: 2,
                reservedUses: 0,
                availableUses: 2,
                relayerKeyId: 'wallet-signing-budget',
                walletKeyId: 'localhost',
                participantIds: [1, 2],
              },
      },
      cipher: createSigningSessionSealCipherAdapter({
        applyServerSeal: async (input) => ({
          ok: true,
          ciphertext: `sealed:${input.ciphertext}`,
        }),
        removeServerSeal: async (input) => ({
          ok: true,
          ciphertext: `unsealed:${input.ciphertext}`,
        }),
      }),
    });

    const result = await service.removeServerSeal(makeBody(), {
      userId: USER_ID,
      claims: makeThresholdSessionClaims({ signingGrantId }),
    });

    expect(result).toMatchObject({
      ok: true,
      ciphertext: 'unsealed:ciphertext-b64u',
      remainingUses: 2,
    });
  });

  test('service rejects sealed refresh when the shared signing grant budget is exhausted', async () => {
    const signingGrantId = 'wallet-session-seal-exhausted';
    let cipherCalls = 0;
    const service = createSigningSessionSealService({
      sessionPolicy: {
        getThresholdSession: async () => ({
          curve: 'ecdsa',
          thresholdSessionId: THRESHOLD_SESSION_ID,
          userId: USER_ID,
          expiresAtMs: Date.now() + 60_000,
          relayerKeyId: 'relayer-key-1',
          walletKeyId: 'localhost',
          participantIds: [1, 2],
          remainingUses: 7,
        }),
        getThresholdSessionStatuses: async () => [],
        getWalletBudgetStatus: async () => ({
          kind: 'wallet_budget',
          curve: 'ecdsa',
          thresholdSessionId: `wallet-signing:${signingGrantId}`,
          signingGrantId,
          userId: USER_ID,
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 0,
          committedRemainingUses: 0,
          reservedUses: 0,
          availableUses: 0,
          relayerKeyId: 'wallet-signing-budget',
          walletKeyId: 'localhost',
          participantIds: [1, 2],
        }),
      },
      cipher: createSigningSessionSealCipherAdapter({
        applyServerSeal: async (input) => {
          cipherCalls += 1;
          return { ok: true, ciphertext: `sealed:${input.ciphertext}` };
        },
        removeServerSeal: async (input) => {
          cipherCalls += 1;
          return { ok: true, ciphertext: `unsealed:${input.ciphertext}` };
        },
      }),
    });

    const result = await service.removeServerSeal(makeBody(), {
      userId: USER_ID,
      claims: makeThresholdSessionClaims({ signingGrantId }),
    });

    expect(result).toEqual({
      ok: false,
      code: 'exhausted',
      message: 'signing grant exhausted',
    });
    expect(cipherCalls).toBe(0);
  });

  test('service does not replay stale idempotent success for wallet-budget-backed seal requests', async () => {
    const signingGrantId = 'wallet-session-no-stale-replay';
    let removeCalls = 0;
    let walletRemainingUses = 2;
    const service = createSigningSessionSealService({
      sessionPolicy: {
        getThresholdSession: async () => ({
          curve: 'ecdsa',
          thresholdSessionId: THRESHOLD_SESSION_ID,
          userId: USER_ID,
          expiresAtMs: Date.now() + 60_000,
          relayerKeyId: 'relayer-key-1',
          walletKeyId: 'localhost',
          participantIds: [1, 2],
          remainingUses: 7,
        }),
        getThresholdSessionStatuses: async () => [],
        getWalletBudgetStatus: async () => ({
          kind: 'wallet_budget',
          curve: 'ecdsa',
          thresholdSessionId: `wallet-signing:${signingGrantId}`,
          signingGrantId,
          userId: USER_ID,
          expiresAtMs: Date.now() + 60_000,
          remainingUses: walletRemainingUses,
          committedRemainingUses: walletRemainingUses,
          reservedUses: 0,
          availableUses: walletRemainingUses,
          relayerKeyId: 'wallet-signing-budget',
          walletKeyId: 'localhost',
          participantIds: [1, 2],
        }),
      },
      cipher: createSigningSessionSealCipherAdapter({
        applyServerSeal: async (input) => ({
          ok: true,
          ciphertext: `sealed:${input.ciphertext}`,
        }),
        removeServerSeal: async (input) => {
          removeCalls += 1;
          return { ok: true, ciphertext: `unsealed:${input.ciphertext}:${removeCalls}` };
        },
      }),
      idempotency: {
        store: createInMemorySigningSessionSealIdempotencyStore(),
        ttlMs: 10_000,
      },
    });
    const auth = {
      userId: USER_ID,
      claims: makeThresholdSessionClaims({ signingGrantId }),
    };

    const first = await service.removeServerSeal(makeBody(), auth);
    walletRemainingUses = 1;
    const second = await service.removeServerSeal(makeBody(), auth);

    expect(first).toMatchObject({
      ok: true,
      ciphertext: 'unsealed:ciphertext-b64u:1',
      remainingUses: 2,
    });
    expect(second).toMatchObject({
      ok: true,
      ciphertext: 'unsealed:ciphertext-b64u:2',
      remainingUses: 1,
    });
    expect(removeCalls).toBe(2);
  });

  test('service idempotency does not replay wallet-budget-backed requests across service instances', async () => {
    let applyCalls = 0;
    const sharedStore = createInMemorySigningSessionSealIdempotencyStore();
    const makeService = () =>
      createSigningSessionSealService({
        sessionPolicy: makePolicy(),
        cipher: createSigningSessionSealCipherAdapter({
          applyServerSeal: async (input) => {
            applyCalls += 1;
            return {
              ok: true,
              ciphertext: `sealed:${input.ciphertext}:${applyCalls}`,
            };
          },
          removeServerSeal: async (input) => ({
            ok: true,
            ciphertext: `unsealed:${input.ciphertext}`,
          }),
        }),
        idempotency: {
          store: sharedStore,
          ttlMs: 10_000,
        },
      });

    const serviceA = makeService();
    const serviceB = makeService();
    const auth = { userId: USER_ID, claims: makeThresholdSessionClaims() };
    const request = makeBody();

    const first = await serviceA.applyServerSeal(request, auth);
    const second = await serviceB.applyServerSeal(request, auth);

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(first).toMatchObject({ ciphertext: 'sealed:ciphertext-b64u:1' });
    expect(second).toMatchObject({ ciphertext: 'sealed:ciphertext-b64u:2' });
    expect(applyCalls).toBe(2);
  });

  test('service idempotency TTL expiry re-executes operation', async () => {
    let applyCalls = 0;
    let now = 1_000_000;
    const service = createSigningSessionSealService({
      sessionPolicy: makePolicy({ expiresAtMs: now + 60_000 }),
      cipher: createSigningSessionSealCipherAdapter({
        applyServerSeal: async (input) => {
          applyCalls += 1;
          return {
            ok: true,
            ciphertext: `sealed:${input.ciphertext}`,
          };
        },
        removeServerSeal: async (input) => ({
          ok: true,
          ciphertext: `unsealed:${input.ciphertext}`,
        }),
      }),
      idempotency: {
        store: createInMemorySigningSessionSealIdempotencyStore(),
        ttlMs: 100,
      },
      nowMs: () => now,
    });

    const auth = { userId: USER_ID, claims: makeThresholdSessionClaims() };
    const request = makeBody();

    const first = await service.applyServerSeal(request, auth);
    now += 101;
    const second = await service.applyServerSeal(request, auth);

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(applyCalls).toBe(2);
  });

  test('service idempotency does not persist internal failures', async () => {
    let applyCalls = 0;
    const service = createSigningSessionSealService({
      sessionPolicy: makePolicy(),
      cipher: createSigningSessionSealCipherAdapter({
        applyServerSeal: async (input) => {
          applyCalls += 1;
          if (applyCalls === 1) {
            return {
              ok: false,
              code: 'internal',
              message: 'transient failure',
            };
          }
          return {
            ok: true,
            ciphertext: `sealed:${input.ciphertext}`,
          };
        },
        removeServerSeal: async (input) => ({
          ok: true,
          ciphertext: `unsealed:${input.ciphertext}`,
        }),
      }),
      idempotency: {
        store: createInMemorySigningSessionSealIdempotencyStore(),
        ttlMs: 10_000,
      },
    });

    const auth = { userId: USER_ID, claims: makeThresholdSessionClaims() };
    const request = makeBody();

    const first = await service.applyServerSeal(request, auth);
    const second = await service.applyServerSeal(request, auth);

    expect(first.ok).toBe(false);
    if (!first.ok) {
      expect(first.code).toBe('internal');
    }
    expect(second.ok).toBe(true);
    expect(applyCalls).toBe(2);
  });

  test('express apply-server-seal rejects cross-user threshold session', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      session: makeSession(),
      signingSessionSeal: createSigningSessionSealRoutesOptions({
        sessionPolicy: makePolicy({ userId: 'bob.testnet' }),
        cipher: createPassthroughSigningSessionSealCipherAdapter(),
      }),
    });

    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/v2/wallet-session/seal/apply-server-seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(makeBody()),
      });
      expect(res.status).toBe(403);
      expect(res.json?.ok).toBe(false);
      expect(res.json?.code).toBe('forbidden');
    } finally {
      await srv.close();
    }
  });

  test('express remove-server-seal rejects stolen sealed record without matching threshold-session auth', async () => {
    const service = makeFakeAuthService();
    let removeCalls = 0;
    const router = createRelayRouter(service, {
      session: makeSession(),
      signingSessionSeal: createSigningSessionSealRoutesOptions({
        sessionPolicy: makePolicy({ userId: 'bob.testnet' }),
        cipher: createSigningSessionSealCipherAdapter({
          applyServerSeal: async (input) => ({
            ok: true,
            ciphertext: `sealed:${input.ciphertext}`,
          }),
          removeServerSeal: async (input) => {
            removeCalls += 1;
            return {
              ok: true,
              ciphertext: `unsealed:${input.ciphertext}`,
            };
          },
        }),
      }),
    });

    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/v2/wallet-session/seal/remove-server-seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(makeBody()),
      });
      expect(res.status).toBe(403);
      expect(res.json?.ok).toBe(false);
      expect(res.json?.code).toBe('forbidden');
      expect(removeCalls).toBe(0);
    } finally {
      await srv.close();
    }
  });

  test('express apply-server-seal enforces rate-limit guard', async () => {
    const service = makeFakeAuthService();
    const limiter = createInMemorySigningSessionSealRateLimiter();
    const router = createRelayRouter(service, {
      session: makeSession(),
      signingSessionSeal: createSigningSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createPassthroughSigningSessionSealCipherAdapter(),
        rateLimit: {
          limiter,
          limit: 1,
          windowMs: 60_000,
        },
      }),
    });

    const srv = await startExpressRouter(router);
    try {
      const first = await fetchJson(`${srv.baseUrl}/v2/wallet-session/seal/apply-server-seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(makeBody()),
      });
      expect(first.status).toBe(200);

      const second = await fetchJson(`${srv.baseUrl}/v2/wallet-session/seal/apply-server-seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(makeBody()),
      });
      expect(second.status).toBe(429);
      expect(second.json?.ok).toBe(false);
      expect(second.json?.code).toBe('rate_limited');
    } finally {
      await srv.close();
    }
  });

  test('express remove-server-seal returns expired for expired threshold session', async () => {
    const service = makeFakeAuthService();
    const nowMs = 1_000_000;
    const router = createRelayRouter(service, {
      session: makeSession(),
      signingSessionSeal: createSigningSessionSealRoutesOptions({
        sessionPolicy: makePolicy({ expiresAtMs: nowMs - 1 }),
        cipher: createPassthroughSigningSessionSealCipherAdapter(),
        nowMs: () => nowMs,
      }),
    });

    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/v2/wallet-session/seal/remove-server-seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(makeBody()),
      });
      expect(res.status).toBe(409);
      expect(res.json?.ok).toBe(false);
      expect(res.json?.code).toBe('expired');
    } finally {
      await srv.close();
    }
  });

  test('express apply-server-seal emits redacted audit event', async () => {
    const service = makeFakeAuthService();
    const auditEvents: Array<Record<string, unknown>> = [];
    const router = createRelayRouter(service, {
      session: makeSession(),
      signingSessionSeal: createSigningSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createPassthroughSigningSessionSealCipherAdapter(),
        audit: async (event) => {
          auditEvents.push(event as unknown as Record<string, unknown>);
        },
      }),
    });

    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/v2/wallet-session/seal/apply-server-seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(makeBody()),
      });
      expect(res.status).toBe(200);
      expect(auditEvents.length).toBe(1);
      expect(auditEvents[0]?.operation).toBe('apply-server-seal');
      expect(auditEvents[0]?.thresholdSessionId).toBe(THRESHOLD_SESSION_ID);
      expect(auditEvents[0]?.ok).toBe(true);
      expect(auditEvents[0]?.ciphertext).toBeUndefined();
    } finally {
      await srv.close();
    }
  });

  test('cloudflare remove-server-seal dispatches through cipher adapter', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: [FRONTEND_ORIGIN],
      session: makeSession(),
      signingSessionSeal: createSigningSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createSigningSessionSealCipherAdapter({
          applyServerSeal: async (input) => ({
            ok: true,
            ciphertext: `sealed:${input.ciphertext}`,
          }),
          removeServerSeal: async (input) => ({
            ok: true,
            ciphertext: `unsealed:${input.ciphertext}`,
          }),
        }),
      }),
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/v2/wallet-session/seal/remove-server-seal',
      origin: FRONTEND_ORIGIN,
      body: makeBody(),
    });

    expect(res.status).toBe(200);
    expect(res.json?.ok).toBe(true);
    expect(res.json?.ciphertext).toBe('unsealed:ciphertext-b64u');
  });

  test('express shamir3pass adapter round-trips apply/remove with keyVersion binding', async () => {
    const service = makeFakeAuthService();
    const keyVersion = 'signing-session-seal-kek-2026-02-r1';
    const primeB64u = encodePositiveBigIntB64u(257n);
    const encryptExponentB64u = encodePositiveBigIntB64u(3n);
    const decryptExponentB64u = encodePositiveBigIntB64u(171n);
    const plaintextCiphertextB64u = encodePositiveBigIntB64u(5n);
    const router = createRelayRouter(service, {
      session: makeSession(),
      signingSessionSeal: createSigningSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createSigningSessionSealShamir3PassCipherAdapter({
          currentKeyVersion: keyVersion,
          keys: [
            {
              keyVersion,
              shamirPrimeB64u: primeB64u,
              serverEncryptExponentB64u: encryptExponentB64u,
              serverDecryptExponentB64u: decryptExponentB64u,
            },
          ],
        }),
      }),
    });

    const srv = await startExpressRouter(router);
    try {
      const applied = await fetchJson(`${srv.baseUrl}/v2/wallet-session/seal/apply-server-seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          makeBody({
            ciphertext: plaintextCiphertextB64u,
          }),
        ),
      });

      expect(applied.status).toBe(200);
      expect(applied.json?.ok).toBe(true);
      expect(applied.json?.keyVersion).toBe(keyVersion);
      expect(applied.json?.ciphertext).not.toBe(plaintextCiphertextB64u);

      const removed = await fetchJson(`${srv.baseUrl}/v2/wallet-session/seal/remove-server-seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          makeBody({
            ciphertext: applied.json?.ciphertext,
            keyVersion,
          }),
        ),
      });

      expect(removed.status).toBe(200);
      expect(removed.json?.ok).toBe(true);
      expect(removed.json?.ciphertext).toBe(plaintextCiphertextB64u);
      expect(removed.json?.keyVersion).toBe(keyVersion);
    } finally {
      await srv.close();
    }
  });

  test('express shamir3pass adapter rejects unknown keyVersion on remove', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      session: makeSession(),
      signingSessionSeal: createSigningSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createSigningSessionSealShamir3PassCipherAdapter({
          currentKeyVersion: 'signing-session-seal-kek-2026-02-r1',
          keys: [
            {
              keyVersion: 'signing-session-seal-kek-2026-02-r1',
              shamirPrimeB64u: encodePositiveBigIntB64u(257n),
              serverEncryptExponentB64u: encodePositiveBigIntB64u(3n),
              serverDecryptExponentB64u: encodePositiveBigIntB64u(171n),
            },
          ],
        }),
      }),
    });

    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/v2/wallet-session/seal/remove-server-seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          makeBody({
            ciphertext: encodePositiveBigIntB64u(7n),
            keyVersion: 'kek-s-unknown',
          }),
        ),
      });
      expect(res.status).toBe(400);
      expect(res.json?.ok).toBe(false);
      expect(res.json?.code).toBe('invalid_key_version');
    } finally {
      await srv.close();
    }
  });

  test('express shamir3pass adapter rejects out-of-range ciphertext on apply', async () => {
    const service = makeFakeAuthService();
    const primeB64u = encodePositiveBigIntB64u(257n);
    const router = createRelayRouter(service, {
      session: makeSession(),
      signingSessionSeal: createSigningSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createSigningSessionSealShamir3PassCipherAdapter({
          currentKeyVersion: 'signing-session-seal-kek-2026-02-r1',
          keys: [
            {
              keyVersion: 'signing-session-seal-kek-2026-02-r1',
              shamirPrimeB64u: primeB64u,
              serverEncryptExponentB64u: encodePositiveBigIntB64u(3n),
              serverDecryptExponentB64u: encodePositiveBigIntB64u(171n),
            },
          ],
        }),
      }),
    });

    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/v2/wallet-session/seal/apply-server-seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          makeBody({
            ciphertext: primeB64u,
            keyVersion: 'signing-session-seal-kek-2026-02-r1',
          }),
        ),
      });
      expect(res.status).toBe(400);
      expect(res.json?.ok).toBe(false);
      expect(res.json?.code).toBe('invalid_ciphertext');
    } finally {
      await srv.close();
    }
  });

  test('idempotency env resolver supports in-memory and validates backend params', async () => {
    const inMemory = resolveSigningSessionSealIdempotencyFromEnv({
      idempotencyKind: 'in-memory',
      ttlMs: 3_000,
    });
    expect(typeof inMemory.store.get).toBe('function');
    expect(typeof inMemory.store.set).toBe('function');
    expect(inMemory.ttlMs).toBe(3_000);
    await expect(inMemory.store.get({ key: 'missing', nowMs: Date.now() })).resolves.toBeNull();

    expect(() =>
      resolveSigningSessionSealIdempotencyFromEnv({
        idempotencyKind: 'upstash-redis-rest',
        upstashUrl: 'https://example.upstash.io',
      }),
    ).toThrow(/upstash/i);

    expect(() =>
      resolveSigningSessionSealIdempotencyFromEnv({
        idempotencyKind: 'redis-tcp',
      }),
    ).toThrow(/redis/i);

    expect(() =>
      resolveSigningSessionSealIdempotencyFromEnv({
        idempotencyKind: 'postgres',
      }),
    ).toThrow(/postgres/i);

    expect(() =>
      resolveSigningSessionSealIdempotencyFromEnv({
        idempotencyKind: 'unsupported-kind',
      }),
    ).toThrow(/unsupported/i);
  });

  test('rate-limit env resolver supports in-memory and validates upstash params', async () => {
    const fromMemory = resolveSigningSessionSealRateLimitFromEnv({
      limiterKind: 'in-memory',
      limit: 3,
      windowMs: 1_000,
    });
    expect(typeof fromMemory.limiter.consume).toBe('function');
    expect(fromMemory.limit).toBe(3);
    expect(fromMemory.windowMs).toBe(1_000);

    expect(() =>
      resolveSigningSessionSealRateLimitFromEnv({
        limiterKind: 'upstash-redis-rest',
        upstashUrl: 'https://example.upstash.io',
        limit: 5,
        windowMs: 2_000,
      }),
    ).toThrow(/upstash/i);
  });

  test('postgres idempotency store round-trips and expires entries', async () => {
    const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
    test.skip(!postgresUrl, 'POSTGRES_URL not set');

    const namespace = `test:signing-session-idempotency:${Date.now().toString(36)}:${Math.random().toString(36).slice(2, 8)}`;
    const idempotency = resolveSigningSessionSealIdempotencyFromEnv({
      idempotencyKind: 'postgres',
      postgresUrl,
      postgresNamespace: namespace,
      ttlMs: 5_000,
    });

    const key = `roundtrip:${Date.now().toString(36)}`;
    const nowMs = Date.now();
    const result = {
      ok: true as const,
      ciphertext: 'sealed:ciphertext-b64u',
      keyVersion: 'signing-session-seal-kek-2026-02-r1',
    };

    await idempotency.store.set({
      key,
      result,
      expiresAtMs: nowMs + 2_000,
    });

    const replay = await idempotency.store.get({ key, nowMs });
    expect(replay).toEqual(result);

    const expiredReplay = await idempotency.store.get({ key, nowMs: nowMs + 2_100 });
    expect(expiredReplay).toBeNull();
  });
});
