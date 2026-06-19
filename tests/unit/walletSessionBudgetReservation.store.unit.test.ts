import { expect, test } from '@playwright/test';
import { setTimeout as delay } from 'node:timers/promises';
import {
  createEd25519WalletSessionStore,
  type Ed25519WalletSessionStore,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore';
import { ensurePostgresSchema } from '../../packages/sdk-server-ts/src/storage/postgres';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
  ThresholdStoreConfigInput,
} from '../../packages/sdk-server-ts/src/core/types';
import { ThresholdStoreDurableObject } from '../../packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore';

const logger = {
  info() {},
  warn() {},
  error() {},
  debug() {},
} as const;

function createStore() {
  return createEd25519WalletSessionStore({
    config: { kind: 'in-memory' },
    logger,
    isNode: true,
  });
}

function storeConfig(config: ThresholdStoreConfigInput): ThresholdStoreConfigInput {
  return config;
}

type TestDurableObjectStorageLike = {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<boolean>;
  transaction<T>(fn: (txn: TestDurableObjectStorageLike) => Promise<T>): Promise<T>;
};

function createMemoryDurableObjectNamespace(): CloudflareDurableObjectNamespaceLike {
  const objects = new Map<string, CloudflareDurableObjectStubLike>();
  return {
    idFromName: (name: string) => name,
    get: (id: unknown) => {
      const key = String(id);
      const existing = objects.get(key);
      if (existing) return existing;

      const storageMap = new Map<string, unknown>();
      const storage: TestDurableObjectStorageLike = {
        get: async (storageKey) => storageMap.get(storageKey) ?? null,
        put: async (storageKey, value) => {
          storageMap.set(storageKey, value);
        },
        delete: async (storageKey) => storageMap.delete(storageKey),
        transaction: async (fn) => await fn(storage),
      };
      const durableObject = new ThresholdStoreDurableObject({ storage }, {});
      const stub: CloudflareDurableObjectStubLike = {
        fetch: async (request, init) =>
          durableObject.fetch(request instanceof Request ? request : new Request(request, init)),
      };
      objects.set(key, stub);
      return stub;
    },
  };
}

async function putWalletSession(input: { remainingUses: number }) {
  const store = createStore();
  const expiresAtMs = Date.now() + 60_000;
  await putWalletSessionOnStore(store, {
    id: 'wallet-session-1',
    thresholdSessionId: 'threshold-session-1',
    expiresAtMs,
    remainingUses: input.remainingUses,
  });
  return { store, expiresAtMs };
}

async function putWalletSessionOnStore(
  store: Ed25519WalletSessionStore,
  input: {
    id: string;
    thresholdSessionId: string;
    expiresAtMs: number;
    remainingUses: number;
  },
) {
  await store.putSession(
    input.id,
    {
      userId: 'user-1',
      rpId: 'rp.example',
      relayerKeyId: 'relayer-1',
      participantIds: [1, 2],
      expiresAtMs: input.expiresAtMs,
      walletBudgetBinding: {
        curve: 'ed25519',
        thresholdSessionId: input.thresholdSessionId,
      },
    },
    { ttlMs: Math.max(1, input.expiresAtMs - Date.now()), remainingUses: input.remainingUses },
  );
}

function randomPrefix(label: string): string {
  return `${label}:${Date.now().toString(36)}:${Math.random().toString(36).slice(2)}`;
}

async function expectReservationLifecycleContract(input: {
  store: Ed25519WalletSessionStore;
  label: string;
}) {
  const sessionId = `${input.label}-wallet-session`;
  const thresholdSessionId = `${input.label}-threshold-session`;
  const expiresAtMs = Date.now() + 60_000;
  await putWalletSessionOnStore(input.store, {
    id: sessionId,
    thresholdSessionId,
    expiresAtMs,
    remainingUses: 1,
  });

  const [first, second] = await Promise.all([
    input.store.reserveUseCountOnce({
      walletSigningSessionId: sessionId,
      curve: 'ed25519',
      thresholdSessionId,
      operationId: `${input.label}-operation-1`,
      requestDigest: `${input.label}-digest-1`,
      signatureUses: 1,
      expiresAtMs,
    }),
    input.store.reserveUseCountOnce({
      walletSigningSessionId: sessionId,
      curve: 'ed25519',
      thresholdSessionId,
      operationId: `${input.label}-operation-2`,
      requestDigest: `${input.label}-digest-2`,
      signatureUses: 1,
      expiresAtMs,
    }),
  ]);
  const reserved = [first, second].find((result) => result.ok);
  const blocked = [first, second].find((result) => !result.ok);
  expect(reserved).toMatchObject({ ok: true, availableUses: 0 });
  expect(blocked).toMatchObject({ ok: false, code: 'wallet_budget_in_flight' });
  if (!reserved?.ok) throw new Error(`${input.label} did not reserve budget`);

  const duplicateReserve = await input.store.reserveUseCountOnce({
    walletSigningSessionId: sessionId,
    curve: 'ed25519',
    thresholdSessionId,
    operationId: reserved.reservation.operationId,
    requestDigest: reserved.reservation.requestDigest,
    signatureUses: 1,
    expiresAtMs,
  });
  expect(duplicateReserve).toMatchObject({
    ok: true,
    reservation: { reservationId: reserved.reservation.reservationId },
  });

  const committed = await input.store.commitReservedUseCountOnce({
    walletSigningSessionId: sessionId,
    reservationId: reserved.reservation.reservationId,
    operationId: reserved.reservation.operationId,
    requestDigest: reserved.reservation.requestDigest,
  });
  expect(committed).toEqual({ ok: true, remainingUses: 0 });
  const duplicateCommit = await input.store.commitReservedUseCountOnce({
    walletSigningSessionId: sessionId,
    reservationId: reserved.reservation.reservationId,
    operationId: reserved.reservation.operationId,
    requestDigest: reserved.reservation.requestDigest,
  });
  expect(duplicateCommit).toEqual({ ok: true, remainingUses: 0 });

  const releaseSessionId = `${input.label}-release-wallet-session`;
  const releaseThresholdSessionId = `${input.label}-release-threshold-session`;
  await putWalletSessionOnStore(input.store, {
    id: releaseSessionId,
    thresholdSessionId: releaseThresholdSessionId,
    expiresAtMs,
    remainingUses: 1,
  });
  const releaseReservation = await input.store.reserveUseCountOnce({
    walletSigningSessionId: releaseSessionId,
    curve: 'ed25519',
    thresholdSessionId: releaseThresholdSessionId,
    operationId: `${input.label}-release-operation`,
    requestDigest: `${input.label}-release-digest`,
    signatureUses: 1,
    expiresAtMs,
  });
  expect(releaseReservation.ok).toBe(true);
  if (!releaseReservation.ok) throw new Error(releaseReservation.message);
  await expect(
    input.store.releaseReservedUseCount({
      walletSigningSessionId: releaseSessionId,
      reservationId: releaseReservation.reservation.reservationId,
    }),
  ).resolves.toMatchObject({
    ok: true,
    released: true,
    remainingUses: 1,
    reservedUses: 0,
    availableUses: 1,
  });
}

test.describe('Wallet Session budget reservations', () => {
  test('reserve holds visible available budget and commit is idempotent', async () => {
    const { store, expiresAtMs } = await putWalletSession({ remainingUses: 1 });

    const reservation = await store.reserveUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      curve: 'ed25519',
      thresholdSessionId: 'threshold-session-1',
      operationId: 'operation-1',
      requestDigest: 'digest-1',
      signatureUses: 1,
      expiresAtMs,
    });

    expect(reservation.ok).toBe(true);
    if (!reservation.ok) throw new Error(reservation.message);
    expect(reservation.availableUses).toBe(0);

    const duplicate = await store.reserveUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      curve: 'ed25519',
      thresholdSessionId: 'threshold-session-1',
      operationId: 'operation-1',
      requestDigest: 'digest-1',
      signatureUses: 1,
      expiresAtMs,
    });
    expect(duplicate.ok).toBe(true);
    if (!duplicate.ok) throw new Error(duplicate.message);
    expect(duplicate.reservation.reservationId).toBe(reservation.reservation.reservationId);

    const inFlight = await store.reserveUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      curve: 'ed25519',
      thresholdSessionId: 'threshold-session-1',
      operationId: 'operation-2',
      requestDigest: 'digest-2',
      signatureUses: 1,
      expiresAtMs,
    });
    expect(inFlight).toMatchObject({ ok: false, code: 'wallet_budget_in_flight' });

    const statusWhileReserved = await store.getSessionStatus('wallet-session-1');
    expect(statusWhileReserved).toMatchObject({
      committedRemainingUses: 1,
      reservedUses: 1,
      availableUses: 0,
      remainingUses: 0,
    });

    const committed = await store.commitReservedUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      reservationId: reservation.reservation.reservationId,
      operationId: 'operation-1',
      requestDigest: 'digest-1',
    });
    expect(committed).toEqual({ ok: true, remainingUses: 0 });

    const duplicateCommit = await store.commitReservedUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      reservationId: reservation.reservation.reservationId,
      operationId: 'operation-1',
      requestDigest: 'digest-1',
    });
    expect(duplicateCommit).toEqual({ ok: true, remainingUses: 0 });
  });

  test('release restores available budget for abandoned prepares', async () => {
    const { store, expiresAtMs } = await putWalletSession({ remainingUses: 1 });

    const reservation = await store.reserveUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      curve: 'ed25519',
      thresholdSessionId: 'threshold-session-1',
      operationId: 'operation-1',
      requestDigest: 'digest-1',
      signatureUses: 1,
      expiresAtMs,
    });
    expect(reservation.ok).toBe(true);
    if (!reservation.ok) throw new Error(reservation.message);

    const release = await store.releaseReservedUseCount({
      walletSigningSessionId: 'wallet-session-1',
      reservationId: reservation.reservation.reservationId,
    });

    expect(release).toMatchObject({
      ok: true,
      released: true,
      remainingUses: 1,
      reservedUses: 0,
      availableUses: 1,
    });
    expect(await store.getSessionStatus('wallet-session-1')).toMatchObject({
      remainingUses: 1,
      availableUses: 1,
    });
  });

  test('reserve rejects exhausted budget', async () => {
    const { store, expiresAtMs } = await putWalletSession({ remainingUses: 0 });

    const reservation = await store.reserveUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      curve: 'ed25519',
      thresholdSessionId: 'threshold-session-1',
      operationId: 'operation-1',
      requestDigest: 'digest-1',
      signatureUses: 1,
      expiresAtMs,
    });

    expect(reservation).toMatchObject({
      ok: false,
      code: 'wallet_budget_exhausted',
    });
  });

  test('commit rejects expired reservations and releases visible availability', async () => {
    const { store } = await putWalletSession({ remainingUses: 1 });
    const expiredReservation = await store.reserveUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      curve: 'ed25519',
      thresholdSessionId: 'threshold-session-1',
      operationId: 'operation-1',
      requestDigest: 'digest-1',
      signatureUses: 1,
      expiresAtMs: Date.now() + 1,
    });
    expect(expiredReservation.ok).toBe(true);
    if (!expiredReservation.ok) throw new Error(expiredReservation.message);

    await delay(5);

    const committed = await store.commitReservedUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      reservationId: expiredReservation.reservation.reservationId,
      operationId: 'operation-1',
      requestDigest: 'digest-1',
    });

    expect(committed).toMatchObject({
      ok: false,
      code: 'wallet_budget_reservation_expired',
    });
    expect(await store.getSessionStatus('wallet-session-1')).toMatchObject({
      committedRemainingUses: 1,
      reservedUses: 0,
      availableUses: 1,
      remainingUses: 1,
    });
  });

  test('commit rejects reservation identity mismatch', async () => {
    const { store, expiresAtMs } = await putWalletSession({ remainingUses: 1 });

    const reservation = await store.reserveUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      curve: 'ed25519',
      thresholdSessionId: 'threshold-session-1',
      operationId: 'operation-1',
      requestDigest: 'digest-1',
      signatureUses: 1,
      expiresAtMs,
    });
    expect(reservation.ok).toBe(true);
    if (!reservation.ok) throw new Error(reservation.message);

    const committed = await store.commitReservedUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      reservationId: reservation.reservation.reservationId,
      operationId: 'operation-1',
      requestDigest: 'digest-2',
    });

    expect(committed).toMatchObject({
      ok: false,
      code: 'wallet_budget_reservation_mismatch',
    });
    expect(await store.getSessionStatus('wallet-session-1')).toMatchObject({
      committedRemainingUses: 1,
      reservedUses: 1,
      availableUses: 0,
      remainingUses: 0,
    });
  });
});

test.describe('Wallet Session budget reservation backend contracts', () => {
  test('in-memory store preserves reservation lifecycle semantics', async () => {
    await expectReservationLifecycleContract({
      store: createStore(),
      label: randomPrefix('wallet-budget-memory-contract'),
    });
  });

  test('Cloudflare Durable Object store preserves reservation lifecycle semantics', async () => {
    await expectReservationLifecycleContract({
      store: createEd25519WalletSessionStore({
        config: storeConfig({
          kind: 'cloudflare-do',
          namespace: createMemoryDurableObjectNamespace(),
          name: randomPrefix('wallet-budget-do-object'),
        }),
        logger,
        isNode: false,
      }),
      label: randomPrefix('wallet-budget-do-contract'),
    });
  });

  test('Redis store preserves reservation lifecycle semantics', async () => {
    const redisUrl = String(process.env.REDIS_URL || '').trim();
    test.skip(!redisUrl, 'REDIS_URL not set');

    await expectReservationLifecycleContract({
      store: createEd25519WalletSessionStore({
        config: storeConfig({
          kind: 'redis-tcp',
          redisUrl,
          keyPrefix: randomPrefix('wallet-budget-redis'),
        }),
        logger,
        isNode: true,
      }),
      label: randomPrefix('wallet-budget-redis-contract'),
    });
  });

  test('Upstash store preserves reservation lifecycle semantics', async () => {
    const upstashUrl = String(process.env.UPSTASH_REDIS_REST_URL || '').trim();
    const upstashToken = String(process.env.UPSTASH_REDIS_REST_TOKEN || '').trim();
    test.skip(!upstashUrl || !upstashToken, 'UPSTASH_REDIS_REST_URL / TOKEN not set');

    await expectReservationLifecycleContract({
      store: createEd25519WalletSessionStore({
        config: storeConfig({
          kind: 'upstash-redis-rest',
          url: upstashUrl,
          token: upstashToken,
          keyPrefix: randomPrefix('wallet-budget-upstash'),
        }),
        logger,
        isNode: true,
      }),
      label: randomPrefix('wallet-budget-upstash-contract'),
    });
  });

  test('Postgres store preserves reservation lifecycle semantics', async () => {
    const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
    test.skip(!postgresUrl, 'POSTGRES_URL not set');

    await ensurePostgresSchema({ postgresUrl, logger });
    await expectReservationLifecycleContract({
      store: createEd25519WalletSessionStore({
        config: storeConfig({
          kind: 'postgres',
          postgresUrl,
          keyPrefix: randomPrefix('wallet-budget-postgres'),
        }),
        logger,
        isNode: true,
      }),
      label: randomPrefix('wallet-budget-postgres-contract'),
    });
  });
});
