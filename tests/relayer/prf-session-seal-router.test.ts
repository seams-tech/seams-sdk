import { test, expect } from '@playwright/test';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import { createRelayRouter } from '@server/router/express-adaptor';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  createInMemoryPrfSessionSealIdempotencyStore,
  createInMemoryPrfSessionSealRateLimiter,
  createPassthroughPrfSessionSealCipherAdapter,
  createPrfSessionSealCipherAdapter,
  createPrfSessionSealRoutesOptions,
  createPrfSessionSealService,
  createPrfSessionSealShamir3PassCipherAdapter,
  resolvePrfSessionSealIdempotencyFromEnv,
  resolvePrfSessionSealRateLimitFromEnv,
} from '@server/threshold/session/prfSessionSeal';
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

function makeSession(userId = USER_ID) {
  return makeSessionAdapter({
    parse: async () => ({ ok: true as const, claims: { sub: userId } }),
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
  return {
    getSession: async (thresholdSessionId: string) => {
      if (thresholdSessionId !== THRESHOLD_SESSION_ID) return null;
      return {
        thresholdSessionId,
        userId: sessionUserId,
        expiresAtMs,
        remainingUses,
      };
    },
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
    keyVersion: 'kek-s-2026-02',
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

test.describe('prf session seal routes', () => {
  test('express apply-server-seal returns sealed payload for owner', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      session: makeSession(),
      prfSessionSeal: createPrfSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createPassthroughPrfSessionSealCipherAdapter(),
      }),
    });

    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/prf-seal/apply-server-seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(makeBody()),
      });
      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);
      expect(res.json?.ciphertext).toBe('ciphertext-b64u');
      expect(res.json?.keyVersion).toBe('kek-s-2026-02');
      expect(Number(res.json?.expiresAtMs)).toBeGreaterThan(Date.now());
    } finally {
      await srv.close();
    }
  });

  test('express PRF seal routes single-flight dedupe identical concurrent apply/remove requests', async () => {
    const service = makeFakeAuthService();
    let applyCalls = 0;
    let removeCalls = 0;
    const router = createRelayRouter(service, {
      session: makeSession(),
      prfSessionSeal: createPrfSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createPrfSessionSealCipherAdapter({
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
        fetchJson(`${srv.baseUrl}/threshold-ecdsa/prf-seal/apply-server-seal`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(makeBody()),
        }),
        fetchJson(`${srv.baseUrl}/threshold-ecdsa/prf-seal/apply-server-seal`, {
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
        fetchJson(`${srv.baseUrl}/threshold-ecdsa/prf-seal/remove-server-seal`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(makeBody()),
        }),
        fetchJson(`${srv.baseUrl}/threshold-ecdsa/prf-seal/remove-server-seal`, {
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

  test('service idempotency replays sequential duplicate apply requests', async () => {
    let applyCalls = 0;
    const service = createPrfSessionSealService({
      sessionPolicy: makePolicy(),
      cipher: createPrfSessionSealCipherAdapter({
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
        store: createInMemoryPrfSessionSealIdempotencyStore(),
        ttlMs: 10_000,
      },
    });

    const auth = { userId: USER_ID, claims: { sub: USER_ID } };
    const request = makeBody();

    const first = await service.applyServerSeal(request, auth);
    const second = await service.applyServerSeal(request, auth);

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(second).toEqual(first);
    expect(applyCalls).toBe(1);
  });

  test('service idempotency replays across service instances sharing the same store', async () => {
    let applyCalls = 0;
    const sharedStore = createInMemoryPrfSessionSealIdempotencyStore();
    const makeService = () =>
      createPrfSessionSealService({
        sessionPolicy: makePolicy(),
        cipher: createPrfSessionSealCipherAdapter({
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
          store: sharedStore,
          ttlMs: 10_000,
        },
      });

    const serviceA = makeService();
    const serviceB = makeService();
    const auth = { userId: USER_ID, claims: { sub: USER_ID } };
    const request = makeBody();

    const first = await serviceA.applyServerSeal(request, auth);
    const second = await serviceB.applyServerSeal(request, auth);

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(second).toEqual(first);
    expect(applyCalls).toBe(1);
  });

  test('service idempotency TTL expiry re-executes operation', async () => {
    let applyCalls = 0;
    let now = 1_000_000;
    const service = createPrfSessionSealService({
      sessionPolicy: makePolicy({ expiresAtMs: now + 60_000 }),
      cipher: createPrfSessionSealCipherAdapter({
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
        store: createInMemoryPrfSessionSealIdempotencyStore(),
        ttlMs: 100,
      },
      nowMs: () => now,
    });

    const auth = { userId: USER_ID, claims: { sub: USER_ID } };
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
    const service = createPrfSessionSealService({
      sessionPolicy: makePolicy(),
      cipher: createPrfSessionSealCipherAdapter({
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
        store: createInMemoryPrfSessionSealIdempotencyStore(),
        ttlMs: 10_000,
      },
    });

    const auth = { userId: USER_ID, claims: { sub: USER_ID } };
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
      prfSessionSeal: createPrfSessionSealRoutesOptions({
        sessionPolicy: makePolicy({ userId: 'bob.testnet' }),
        cipher: createPassthroughPrfSessionSealCipherAdapter(),
      }),
    });

    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/prf-seal/apply-server-seal`, {
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

  test('express apply-server-seal enforces rate-limit guard', async () => {
    const service = makeFakeAuthService();
    const limiter = createInMemoryPrfSessionSealRateLimiter();
    const router = createRelayRouter(service, {
      session: makeSession(),
      prfSessionSeal: createPrfSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createPassthroughPrfSessionSealCipherAdapter(),
        rateLimit: {
          limiter,
          limit: 1,
          windowMs: 60_000,
        },
      }),
    });

    const srv = await startExpressRouter(router);
    try {
      const first = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/prf-seal/apply-server-seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(makeBody()),
      });
      expect(first.status).toBe(200);

      const second = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/prf-seal/apply-server-seal`, {
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
      prfSessionSeal: createPrfSessionSealRoutesOptions({
        sessionPolicy: makePolicy({ expiresAtMs: nowMs - 1 }),
        cipher: createPassthroughPrfSessionSealCipherAdapter(),
        nowMs: () => nowMs,
      }),
    });

    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/prf-seal/remove-server-seal`, {
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
      prfSessionSeal: createPrfSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createPassthroughPrfSessionSealCipherAdapter(),
        audit: async (event) => {
          auditEvents.push(event as unknown as Record<string, unknown>);
        },
      }),
    });

    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/prf-seal/apply-server-seal`, {
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
      prfSessionSeal: createPrfSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createPrfSessionSealCipherAdapter({
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
      path: '/threshold-ecdsa/prf-seal/remove-server-seal',
      origin: FRONTEND_ORIGIN,
      body: makeBody(),
    });

    expect(res.status).toBe(200);
    expect(res.json?.ok).toBe(true);
    expect(res.json?.ciphertext).toBe('unsealed:ciphertext-b64u');
  });

  test('express shamir3pass adapter round-trips apply/remove with keyVersion binding', async () => {
    const service = makeFakeAuthService();
    const keyVersion = 'kek-s-2026-02';
    const primeB64u = encodePositiveBigIntB64u(257n);
    const encryptExponentB64u = encodePositiveBigIntB64u(3n);
    const decryptExponentB64u = encodePositiveBigIntB64u(171n);
    const plaintextCiphertextB64u = encodePositiveBigIntB64u(5n);
    const router = createRelayRouter(service, {
      session: makeSession(),
      prfSessionSeal: createPrfSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createPrfSessionSealShamir3PassCipherAdapter({
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
      const applied = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/prf-seal/apply-server-seal`, {
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

      const removed = await fetchJson(
        `${srv.baseUrl}/threshold-ecdsa/prf-seal/remove-server-seal`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(
            makeBody({
              ciphertext: applied.json?.ciphertext,
              keyVersion,
            }),
          ),
        },
      );

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
      prfSessionSeal: createPrfSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createPrfSessionSealShamir3PassCipherAdapter({
          currentKeyVersion: 'kek-s-2026-02',
          keys: [
            {
              keyVersion: 'kek-s-2026-02',
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
      const res = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/prf-seal/remove-server-seal`, {
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
      prfSessionSeal: createPrfSessionSealRoutesOptions({
        sessionPolicy: makePolicy(),
        cipher: createPrfSessionSealShamir3PassCipherAdapter({
          currentKeyVersion: 'kek-s-2026-02',
          keys: [
            {
              keyVersion: 'kek-s-2026-02',
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
      const res = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/prf-seal/apply-server-seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          makeBody({
            ciphertext: primeB64u,
            keyVersion: 'kek-s-2026-02',
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
    const inMemory = resolvePrfSessionSealIdempotencyFromEnv({
      idempotencyKind: 'in-memory',
      ttlMs: 3_000,
    });
    expect(typeof inMemory.store.get).toBe('function');
    expect(typeof inMemory.store.set).toBe('function');
    expect(inMemory.ttlMs).toBe(3_000);
    await expect(inMemory.store.get({ key: 'missing', nowMs: Date.now() })).resolves.toBeNull();

    expect(() =>
      resolvePrfSessionSealIdempotencyFromEnv({
        idempotencyKind: 'upstash-redis-rest',
        upstashUrl: 'https://example.upstash.io',
      }),
    ).toThrow(/upstash/i);

    expect(() =>
      resolvePrfSessionSealIdempotencyFromEnv({
        idempotencyKind: 'redis-tcp',
      }),
    ).toThrow(/redis/i);

    expect(() =>
      resolvePrfSessionSealIdempotencyFromEnv({
        idempotencyKind: 'postgres',
      }),
    ).toThrow(/postgres/i);

    expect(() =>
      resolvePrfSessionSealIdempotencyFromEnv({
        idempotencyKind: 'unsupported-kind',
      }),
    ).toThrow(/unsupported/i);
  });

  test('rate-limit env resolver supports in-memory and validates upstash params', async () => {
    const fromMemory = resolvePrfSessionSealRateLimitFromEnv({
      limiterKind: 'in-memory',
      limit: 3,
      windowMs: 1_000,
    });
    expect(typeof fromMemory.limiter.consume).toBe('function');
    expect(fromMemory.limit).toBe(3);
    expect(fromMemory.windowMs).toBe(1_000);

    expect(() =>
      resolvePrfSessionSealRateLimitFromEnv({
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

    const namespace = `test:prf-idempotency:${Date.now().toString(36)}:${Math.random().toString(36).slice(2, 8)}`;
    const idempotency = resolvePrfSessionSealIdempotencyFromEnv({
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
      keyVersion: 'kek-s-2026-02',
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
