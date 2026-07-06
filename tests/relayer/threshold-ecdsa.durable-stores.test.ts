import { test, expect } from '@playwright/test';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { base64UrlEncode } from '@shared/utils/encoders';
import { createEcdsaWalletSessionStore } from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore';
import {
  createThresholdEcdsaSigningStores,
  type RouterAbEcdsaHssPoolFillSessionRecord,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/EcdsaSigningStore';
import {
  CloudflareDurableObjectRouterAbEcdsaHssPoolFillLiveSessionOwner,
  CloudflareDurableObjectThresholdEd25519HssCeremonyStore,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/CloudflareDurableObjectStore';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../../packages/sdk-server-ts/src/core/types';
import { ThresholdStoreDurableObject } from '../../packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore';

const EXPORT_REPLAY_GUARD_CLOCK_SKEW_MS = 5 * 60_000;
const testLogger = {
  info() {},
  warn() {},
  error() {},
  debug() {},
} as const;

type TestDurableObjectStorageLike = {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<boolean>;
  transaction<T>(fn: (txn: TestDurableObjectStorageLike) => Promise<T>): Promise<T>;
};

class MemoryDurableObjectStorage implements TestDurableObjectStorageLike {
  private readonly values = new Map<string, unknown>();
  private transactionTail: Promise<void> = Promise.resolve();

  async get(key: string): Promise<unknown> {
    return this.values.get(key) ?? null;
  }

  async put(key: string, value: unknown): Promise<void> {
    this.values.set(key, value);
  }

  async delete(key: string): Promise<boolean> {
    return this.values.delete(key);
  }

  async transaction<T>(fn: (txn: TestDurableObjectStorageLike) => Promise<T>): Promise<T> {
    const previous = this.transactionTail;
    let release: () => void = () => {};
    this.transactionTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await fn(this);
    } finally {
      release();
    }
  }
}

function randPrefix(tag: string): string {
  return `test:${tag}:${Date.now()}:${Math.random().toString(16).slice(2)}:`;
}

function makePresignRecord(args: {
  relayerKeyId: string;
  presignatureId: string;
  createdAtMs?: number;
}) {
  return {
    relayerKeyId: args.relayerKeyId,
    presignatureId: args.presignatureId,
    bigRB64u: 'ddddddddddddddddddddddddddddddddddddddddddd',
    kShareB64u: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    sigmaShareB64u: 'fffffffffffffffffffffffffffffffffffffffffff',
    createdAtMs: args.createdAtMs ?? Date.now(),
  };
}

function makePresignSessionRecord(args?: {
  version?: number;
  stage?: 'triples' | 'triples_done' | 'presign' | 'done';
}) {
  const version = args?.version ?? 1;
  return {
    expiresAtMs: Date.now() + 60_000,
    userId: 'user-1',
    rpId: 'example.localhost',
    relayerKeyId: 'rk-presign',
    presignPoolKey: 'keyHandle:rk-presign',
    poolFill: { kind: 'local_threshold_ecdsa_presignature_pool' },
    participantIds: [1, 2],
    clientParticipantId: 1,
    relayerParticipantId: 2,
    stage: args?.stage ?? 'triples',
    version,
    wasmSessionStateB64u: 'cHJlc2lnbi1zZXNzaW9uLXN0YXRl',
    createdAtMs: Date.now(),
    updatedAtMs: Date.now(),
    signingRootId: 'signing-root',
    walletKeyVersion: 'v1',
    derivationVersion: 1,
  };
}

function createMemoryDurableObjectNamespace(): CloudflareDurableObjectNamespaceLike {
  const objects = new Map<string, CloudflareDurableObjectStubLike>();
  return {
    idFromName: (name: string) => name,
    get: (id: unknown) => {
      const key = String(id);
      const existing = objects.get(key);
      if (existing) return existing;

      const storage = new MemoryDurableObjectStorage();
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

function makeCloudflareDoPresignSessionRecord(input: {
  relayerKeyId: string;
  version: number;
  stage: 'triples' | 'triples_done' | 'presign' | 'done';
}): RouterAbEcdsaHssPoolFillSessionRecord {
  const nowMs = Date.now();
  return {
    expiresAtMs: nowMs + 60_000,
    walletId: 'wallet-do-1',
    evmFamilySigningKeySlotId: 'wallet-key:evm-family:wallet-do-1:signing-root-do-1:root-v1',
    relayerKeyId: input.relayerKeyId,
    presignPoolKey: `keyHandle:${input.relayerKeyId}`,
    poolFill: { kind: 'local_threshold_ecdsa_presignature_pool' },
    participantIds: [1, 2],
    clientParticipantId: 1,
    relayerParticipantId: 2,
    stage: input.stage,
    version: input.version,
    createdAtMs: nowMs,
    updatedAtMs: nowMs + input.version,
    signingRootId: 'signing-root-do-1',
    signingRootVersion: 'root-v1',
    walletKeyVersion: 'wallet-key-version-1',
    derivationVersion: 1,
  };
}

function randomSecpSecretKey32(): Uint8Array {
  const utils = (secp256k1 as unknown as { utils?: { randomSecretKey?: () => Uint8Array } }).utils;
  if (utils?.randomSecretKey) return utils.randomSecretKey();
  throw new Error('secp256k1 random secret key generator is unavailable');
}

function makeEcdsaHssPoolFillLiveSessionMaterial(): {
  relayerThresholdShare32B64u: string;
  groupPublicKey33B64u: string;
} {
  const relayerShare32 = randomSecpSecretKey32();
  return {
    relayerThresholdShare32B64u: base64UrlEncode(relayerShare32),
    groupPublicKey33B64u: base64UrlEncode(secp256k1.getPublicKey(relayerShare32, true)),
  };
}

test.describe('threshold-ed25519 HSS durable ceremony store', () => {
  test('persists client-owned finalization bytes across store instances', async () => {
    const namespace = createMemoryDurableObjectNamespace();
    const keyPrefix = randPrefix('threshold-ed25519:hss:ceremony');
    const firstStore = new CloudflareDurableObjectThresholdEd25519HssCeremonyStore({
      namespace,
      objectName: 'threshold-ed25519-hss-ceremony-test',
      keyPrefix,
    });
    await firstStore.put('ceremony-1', {
      kind: 'session',
      expiresAtMs: Date.now() + 60_000,
      relayerKeyId: 'rk-ed25519',
      operation: 'tx_signing',
      context: {
        applicationBindingDigestB64u: 'application-binding',
        participantIds: [1, 2],
      },
      preparedSession: {
        contextBindingB64u: 'context-binding',
        evaluatorDriverStateB64u: 'evaluator-driver-state',
      },
      preparedServerSession: {
        evaluatorDriverStateBytes: new Uint8Array([1, 2, 3]),
        garblerDriverStateBytes: new Uint8Array([4, 5, 6]),
        serverEvalStateBytes: new Uint8Array([10, 11, 12]),
      },
      evaluationResult: {
        stagedEvaluatorArtifactBytes: new Uint8Array([7, 8, 9]),
        addStageRequestMessageBytes: new Uint8Array([13, 14, 15]),
      },
      advancedServerEval: {
        contextBindingB64u: base64UrlEncode(new Uint8Array(32).fill(1)),
        addStageRequestDigestB64u: base64UrlEncode(new Uint8Array(32).fill(2)),
        advancedServerEvalStateB64u: base64UrlEncode(new Uint8Array([16, 17, 18])),
        finalizeContextB64u: base64UrlEncode(new Uint8Array([22, 23, 24])),
        priorStageResponseMessageB64u: base64UrlEncode(new Uint8Array([19, 20, 21])),
      },
    });

    const restartedStore = new CloudflareDurableObjectThresholdEd25519HssCeremonyStore({
      namespace,
      objectName: 'threshold-ed25519-hss-ceremony-test',
      keyPrefix,
    });
    const restored = await restartedStore.take('ceremony-1');

    expect(restored?.kind).toBe('session');
    expect(Array.from(restored?.evaluationResult?.stagedEvaluatorArtifactBytes ?? [])).toEqual([
      7, 8, 9,
    ]);
    expect(Array.from(restored?.evaluationResult?.addStageRequestMessageBytes ?? [])).toEqual([
      13, 14, 15,
    ]);
    expect(restored?.advancedServerEval?.advancedServerEvalStateB64u).toBe(
      base64UrlEncode(new Uint8Array([16, 17, 18])),
    );
    expect(restored?.advancedServerEval?.finalizeContextB64u).toBe(
      base64UrlEncode(new Uint8Array([22, 23, 24])),
    );
    const restoredServerEvalStateBytes =
      restored && 'serverEvalStateBytes' in restored.preparedServerSession
        ? restored.preparedServerSession.serverEvalStateBytes
        : undefined;
    expect(Array.from(restoredServerEvalStateBytes ?? [])).toEqual([10, 11, 12]);
    await expect(restartedStore.get('ceremony-1')).resolves.toBeNull();
  });
});

test.describe('threshold-ecdsa durable presign stores', () => {
  test.describe('Wallet Session export replay guard', () => {
    test('in-memory store rejects duplicate export nonce inside the same scope', async () => {
      const walletSessionPrefix = randPrefix('threshold-ecdsa:wallet-session:memory');
      const store = createEcdsaWalletSessionStore({
        config: {
          kind: 'in-memory',
          THRESHOLD_ECDSA_WALLET_SESSION_PREFIX: walletSessionPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const expiresAtMs = Date.now() + 60_000;
      await expect(store.reserveReplayGuard('scope-a', 'nonce-a', expiresAtMs)).resolves.toEqual({
        ok: true,
      });
      await expect(store.reserveReplayGuard('scope-a', 'nonce-a', expiresAtMs)).resolves.toEqual({
        ok: false,
        code: 'export_nonce_replay',
        message: 'Export authorization nonce already used',
      });
      await expect(store.reserveReplayGuard('scope-b', 'nonce-a', expiresAtMs)).resolves.toEqual({
        ok: true,
      });
      await expect(
        store.reserveReplayGuard(
          'scope-a',
          'nonce-expired',
          Date.now() - EXPORT_REPLAY_GUARD_CLOCK_SKEW_MS - 1,
        ),
      ).resolves.toMatchObject({
        ok: false,
        code: 'export_authorization_expired',
      });
    });

    test('Cloudflare Durable Object store reserves export nonce once under concurrency', async () => {
      const walletSessionPrefix = randPrefix('threshold-ecdsa:wallet-session:cloudflare-do');
      const store = createEcdsaWalletSessionStore({
        config: {
          kind: 'cloudflare-do',
          namespace: createMemoryDurableObjectNamespace(),
          name: randPrefix('threshold-ecdsa:wallet-session-do-object'),
          THRESHOLD_ECDSA_WALLET_SESSION_PREFIX: walletSessionPrefix,
        },
        logger: testLogger,
        isNode: false,
      });

      const expiresAtMs = Date.now() + 60_000;
      const results = await Promise.all([
        store.reserveReplayGuard('scope-do', 'nonce-do', expiresAtMs),
        store.reserveReplayGuard('scope-do', 'nonce-do', expiresAtMs),
      ]);

      expect(results.filter((result) => result.ok).length).toBe(1);
      const duplicate = results.find((result) => !result.ok);
      expect(duplicate).toMatchObject({
        ok: false,
        code: 'export_nonce_replay',
      });
      await expect(
        store.reserveReplayGuard('scope-do-other', 'nonce-do', expiresAtMs),
      ).resolves.toEqual({ ok: true });
      await expect(
        store.reserveReplayGuard('scope-do', 'nonce-expired', Date.now() - 1),
      ).resolves.toMatchObject({
        ok: false,
        code: 'export_authorization_expired',
      });
    });
  });

  test.describe('Cloudflare Durable Object', () => {
    test('presignaturePool reserve/consume are single-use under concurrency', async () => {
      const prefix = randPrefix('threshold-ecdsa:presign:cloudflare-do');
      const { presignaturePool } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'cloudflare-do',
          namespace: createMemoryDurableObjectNamespace(),
          name: randPrefix('threshold-ecdsa:do-object'),
          THRESHOLD_ECDSA_PRESIGN_PREFIX: prefix,
        },
        logger: testLogger,
        isNode: false,
      });

      const relayerKeyId = 'rk-do-2';
      await presignaturePool.put(
        makePresignRecord({
          relayerKeyId,
          presignatureId: 'ps-do-a',
          createdAtMs: Date.now() - 2,
        }),
      );
      await presignaturePool.put(
        makePresignRecord({
          relayerKeyId,
          presignatureId: 'ps-do-b',
          createdAtMs: Date.now() - 1,
        }),
      );

      const [a, b] = await Promise.all([
        presignaturePool.reserve(relayerKeyId),
        presignaturePool.reserve(relayerKeyId),
      ]);
      expect(a && b).toBeTruthy();
      expect(a?.presignatureId).not.toBe(b?.presignatureId);

      const a1 = await presignaturePool.consume(relayerKeyId, a?.presignatureId || '');
      const a2 = await presignaturePool.consume(relayerKeyId, a?.presignatureId || '');
      expect(a1?.presignatureId).toBe(a?.presignatureId);
      expect(a2).toBeNull();

      const b1 = await presignaturePool.consume(relayerKeyId, b?.presignatureId || '');
      const b2 = await presignaturePool.consume(relayerKeyId, b?.presignatureId || '');
      expect(b1?.presignatureId).toBe(b?.presignatureId);
      expect(b2).toBeNull();
    });

    test('presignaturePool reserveById selects requested item and preserves others', async () => {
      const prefix = randPrefix('threshold-ecdsa:presign:cloudflare-do-by-id');
      const { presignaturePool } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'cloudflare-do',
          namespace: createMemoryDurableObjectNamespace(),
          name: randPrefix('threshold-ecdsa:do-object-by-id'),
          THRESHOLD_ECDSA_PRESIGN_PREFIX: prefix,
        },
        logger: testLogger,
        isNode: false,
      });

      const relayerKeyId = 'rk-do-by-id';
      await presignaturePool.put(
        makePresignRecord({
          relayerKeyId,
          presignatureId: 'ps-do-by-a',
          createdAtMs: Date.now() - 2,
        }),
      );
      await presignaturePool.put(
        makePresignRecord({
          relayerKeyId,
          presignatureId: 'ps-do-by-b',
          createdAtMs: Date.now() - 1,
        }),
      );

      const reservedById = await presignaturePool.reserveById(relayerKeyId, 'ps-do-by-b');
      expect(reservedById?.presignatureId).toBe('ps-do-by-b');
      const consumedById = await presignaturePool.consume(relayerKeyId, 'ps-do-by-b');
      expect(consumedById?.presignatureId).toBe('ps-do-by-b');

      const remaining = await presignaturePool.reserve(relayerKeyId);
      expect(remaining?.presignatureId).toBe('ps-do-by-a');
      const consumedRemaining = await presignaturePool.consume(relayerKeyId, 'ps-do-by-a');
      expect(consumedRemaining?.presignatureId).toBe('ps-do-by-a');
    });

    test('poolFillSessionStore CAS transitions are atomic', async () => {
      const prefix = randPrefix('threshold-ecdsa:presign:cloudflare-do-cas');
      const relayerKeyId = 'rk-do-cas';
      const { poolFillSessionStore } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'cloudflare-do',
          namespace: createMemoryDurableObjectNamespace(),
          name: randPrefix('threshold-ecdsa:do-object-cas'),
          THRESHOLD_ECDSA_PRESIGN_PREFIX: prefix,
        },
        logger: testLogger,
        isNode: false,
      });

      const created = await poolFillSessionStore.createSession(
        'psess-do-1',
        makeCloudflareDoPresignSessionRecord({
          relayerKeyId,
          version: 1,
          stage: 'triples',
        }),
        10_000,
      );
      expect(created.ok).toBe(true);

      const stale = await poolFillSessionStore.advanceSessionCas({
        id: 'psess-do-1',
        expectedVersion: 99,
        nextRecord: makeCloudflareDoPresignSessionRecord({
          relayerKeyId,
          version: 100,
          stage: 'triples',
        }),
        ttlMs: 10_000,
      });
      expect(stale.ok).toBe(false);
      if (!stale.ok) expect(stale.code).toBe('version_mismatch');

      const [a, b] = await Promise.all([
        poolFillSessionStore.advanceSessionCas({
          id: 'psess-do-1',
          expectedVersion: 1,
          nextRecord: makeCloudflareDoPresignSessionRecord({
            relayerKeyId,
            version: 2,
            stage: 'triples_done',
          }),
          ttlMs: 10_000,
        }),
        poolFillSessionStore.advanceSessionCas({
          id: 'psess-do-1',
          expectedVersion: 1,
          nextRecord: makeCloudflareDoPresignSessionRecord({
            relayerKeyId,
            version: 2,
            stage: 'triples_done',
          }),
          ttlMs: 10_000,
        }),
      ]);

      const oks = [a, b].filter((result) => result.ok);
      const errs = [a, b].filter((result) => !result.ok);
      expect(oks.length).toBe(1);
      expect(errs.length).toBe(1);
      if (!errs[0].ok) expect(errs[0].code).toBe('version_mismatch');

      const got = await poolFillSessionStore.getSession('psess-do-1');
      expect(got?.version).toBe(2);
      expect(got?.stage).toBe('triples_done');
    });

    test('pool-fill live session owner shares WASM state across fresh owner instances', async () => {
      const namespace = createMemoryDurableObjectNamespace();
      const objectName = randPrefix('threshold-ecdsa:do-live-pool-fill');
      const firstOwner = new CloudflareDurableObjectRouterAbEcdsaHssPoolFillLiveSessionOwner({
        namespace,
        objectName,
      });
      const freshOwner = new CloudflareDurableObjectRouterAbEcdsaHssPoolFillLiveSessionOwner({
        namespace,
        objectName,
      });
      const presignSessionId = 'psess-do-live-1';
      const record = makeCloudflareDoPresignSessionRecord({
        relayerKeyId: 'rk-do-live',
        version: 1,
        stage: 'triples',
      });
      const material = makeEcdsaHssPoolFillLiveSessionMaterial();

      const created = await firstOwner.createSession({
        presignSessionId,
        record,
        participantIds: [...record.participantIds],
        relayerParticipantId: record.relayerParticipantId,
        relayerThresholdShare32B64u: material.relayerThresholdShare32B64u,
        groupPublicKey33B64u: material.groupPublicKey33B64u,
      });
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error(created.message);

      const stepped = await freshOwner.stepSession({
        presignSessionId,
        record: created.value.record,
        requestedStage: 'triples',
        outgoingMessagesB64u: [],
        thresholdExpiresAtMs: created.value.record.expiresAtMs,
      });
      expect(stepped.ok).toBe(true);
    });
  });

  test.describe('Redis (tcp)', () => {
    const redisUrl = String(process.env.REDIS_URL || '').trim();
    const enabled = Boolean(redisUrl);
    const presignPrefix = randPrefix('threshold-ecdsa:presign:redis');

    test('presignaturePool reserve/consume are single-use under concurrency', async () => {
      test.skip(!enabled, 'REDIS_URL not set');
      const { presignaturePool } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'redis-tcp',
          REDIS_URL: redisUrl,
          THRESHOLD_ECDSA_PRESIGN_PREFIX: presignPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const relayerKeyId = 'rk-11';
      await presignaturePool.put(
        makePresignRecord({
          relayerKeyId,
          presignatureId: 'ps-ra',
          createdAtMs: Date.now() - 2,
        }) as any,
      );
      await presignaturePool.put(
        makePresignRecord({
          relayerKeyId,
          presignatureId: 'ps-rb',
          createdAtMs: Date.now() - 1,
        }) as any,
      );

      const [a, b] = await Promise.all([
        presignaturePool.reserve(relayerKeyId),
        presignaturePool.reserve(relayerKeyId),
      ]);
      expect(a && b).toBeTruthy();
      expect(a!.presignatureId).not.toBe(b!.presignatureId);

      const a1 = await presignaturePool.consume(relayerKeyId, a!.presignatureId);
      const a2 = await presignaturePool.consume(relayerKeyId, a!.presignatureId);
      expect(a1?.presignatureId).toBe(a!.presignatureId);
      expect(a2).toBeNull();

      const b1 = await presignaturePool.consume(relayerKeyId, b!.presignatureId);
      const b2 = await presignaturePool.consume(relayerKeyId, b!.presignatureId);
      expect(b1?.presignatureId).toBe(b!.presignatureId);
      expect(b2).toBeNull();
    });

    test('presignaturePool reserveById selects requested item and preserves others', async () => {
      test.skip(!enabled, 'REDIS_URL not set');
      const { presignaturePool } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'redis-tcp',
          REDIS_URL: redisUrl,
          THRESHOLD_ECDSA_PRESIGN_PREFIX: presignPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const relayerKeyId = 'rk-11-by-id';
      await presignaturePool.put(
        makePresignRecord({
          relayerKeyId,
          presignatureId: 'ps-rby-a',
          createdAtMs: Date.now() - 2,
        }) as any,
      );
      await presignaturePool.put(
        makePresignRecord({
          relayerKeyId,
          presignatureId: 'ps-rby-b',
          createdAtMs: Date.now() - 1,
        }) as any,
      );

      const reservedById = await presignaturePool.reserveById(relayerKeyId, 'ps-rby-b');
      expect(reservedById?.presignatureId).toBe('ps-rby-b');
      const consumedById = await presignaturePool.consume(relayerKeyId, 'ps-rby-b');
      expect(consumedById?.presignatureId).toBe('ps-rby-b');

      const remaining = await presignaturePool.reserve(relayerKeyId);
      expect(remaining?.presignatureId).toBe('ps-rby-a');
      const consumedRemaining = await presignaturePool.consume(relayerKeyId, 'ps-rby-a');
      expect(consumedRemaining?.presignatureId).toBe('ps-rby-a');
    });

    test('poolFillSessionStore CAS transitions are atomic', async () => {
      test.skip(!enabled, 'REDIS_URL not set');
      const { poolFillSessionStore } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'redis-tcp',
          REDIS_URL: redisUrl,
          THRESHOLD_ECDSA_PRESIGN_PREFIX: presignPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const created = await poolFillSessionStore.createSession(
        'psess-r1',
        makePresignSessionRecord({ version: 1, stage: 'triples' }) as any,
        10_000,
      );
      expect(created.ok).toBe(true);

      const stale = await poolFillSessionStore.advanceSessionCas({
        id: 'psess-r1',
        expectedVersion: 99,
        nextRecord: makePresignSessionRecord({ version: 100, stage: 'triples' }) as any,
        ttlMs: 10_000,
      });
      expect(stale.ok).toBe(false);
      if (!stale.ok) expect(stale.code).toBe('version_mismatch');

      const [a, b] = await Promise.all([
        poolFillSessionStore.advanceSessionCas({
          id: 'psess-r1',
          expectedVersion: 1,
          nextRecord: makePresignSessionRecord({ version: 2, stage: 'triples_done' }) as any,
          ttlMs: 10_000,
        }),
        poolFillSessionStore.advanceSessionCas({
          id: 'psess-r1',
          expectedVersion: 1,
          nextRecord: makePresignSessionRecord({ version: 2, stage: 'triples_done' }) as any,
          ttlMs: 10_000,
        }),
      ]);

      const oks = [a, b].filter((r) => r.ok);
      const errs = [a, b].filter((r) => !r.ok);
      expect(oks.length).toBe(1);
      expect(errs.length).toBe(1);
      if (!errs[0].ok) expect(errs[0].code).toBe('version_mismatch');

      const got = await poolFillSessionStore.getSession('psess-r1');
      expect(got?.version).toBe(2);
      expect(got?.stage).toBe('triples_done');

      await poolFillSessionStore.deleteSession('psess-r1');
      const afterDelete = await poolFillSessionStore.getSession('psess-r1');
      expect(afterDelete).toBeNull();
    });
  });

  test.describe('Upstash REST', () => {
    const upstashUrl = String(process.env.UPSTASH_REDIS_REST_URL || '').trim();
    const upstashToken = String(process.env.UPSTASH_REDIS_REST_TOKEN || '').trim();
    const enabled = Boolean(upstashUrl && upstashToken);
    const presignPrefix = randPrefix('threshold-ecdsa:presign:upstash');

    test('presignaturePool reserve/consume are single-use under concurrency', async () => {
      test.skip(!enabled, 'UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN not set');
      const { presignaturePool } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'upstash-redis-rest',
          UPSTASH_REDIS_REST_URL: upstashUrl,
          UPSTASH_REDIS_REST_TOKEN: upstashToken,
          THRESHOLD_ECDSA_PRESIGN_PREFIX: presignPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const relayerKeyId = 'rk-u2';
      await presignaturePool.put(
        makePresignRecord({
          relayerKeyId,
          presignatureId: 'ps-ua',
          createdAtMs: Date.now() - 2,
        }) as any,
      );
      await presignaturePool.put(
        makePresignRecord({
          relayerKeyId,
          presignatureId: 'ps-ub',
          createdAtMs: Date.now() - 1,
        }) as any,
      );

      const [a, b] = await Promise.all([
        presignaturePool.reserve(relayerKeyId),
        presignaturePool.reserve(relayerKeyId),
      ]);
      expect(a && b).toBeTruthy();
      expect(a!.presignatureId).not.toBe(b!.presignatureId);

      const a1 = await presignaturePool.consume(relayerKeyId, a!.presignatureId);
      const a2 = await presignaturePool.consume(relayerKeyId, a!.presignatureId);
      expect(a1?.presignatureId).toBe(a!.presignatureId);
      expect(a2).toBeNull();

      const b1 = await presignaturePool.consume(relayerKeyId, b!.presignatureId);
      const b2 = await presignaturePool.consume(relayerKeyId, b!.presignatureId);
      expect(b1?.presignatureId).toBe(b!.presignatureId);
      expect(b2).toBeNull();
    });

    test('presignaturePool reserveById selects requested item and preserves others', async () => {
      test.skip(!enabled, 'UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN not set');
      const { presignaturePool } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'upstash-redis-rest',
          UPSTASH_REDIS_REST_URL: upstashUrl,
          UPSTASH_REDIS_REST_TOKEN: upstashToken,
          THRESHOLD_ECDSA_PRESIGN_PREFIX: presignPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const relayerKeyId = 'rk-u2-by-id';
      await presignaturePool.put(
        makePresignRecord({
          relayerKeyId,
          presignatureId: 'ps-uby-a',
          createdAtMs: Date.now() - 2,
        }) as any,
      );
      await presignaturePool.put(
        makePresignRecord({
          relayerKeyId,
          presignatureId: 'ps-uby-b',
          createdAtMs: Date.now() - 1,
        }) as any,
      );

      const reservedById = await presignaturePool.reserveById(relayerKeyId, 'ps-uby-b');
      expect(reservedById?.presignatureId).toBe('ps-uby-b');
      const consumedById = await presignaturePool.consume(relayerKeyId, 'ps-uby-b');
      expect(consumedById?.presignatureId).toBe('ps-uby-b');

      const remaining = await presignaturePool.reserve(relayerKeyId);
      expect(remaining?.presignatureId).toBe('ps-uby-a');
      const consumedRemaining = await presignaturePool.consume(relayerKeyId, 'ps-uby-a');
      expect(consumedRemaining?.presignatureId).toBe('ps-uby-a');
    });

    test('poolFillSessionStore CAS transitions are atomic', async () => {
      test.skip(!enabled, 'UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN not set');
      const { poolFillSessionStore } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'upstash-redis-rest',
          UPSTASH_REDIS_REST_URL: upstashUrl,
          UPSTASH_REDIS_REST_TOKEN: upstashToken,
          THRESHOLD_ECDSA_PRESIGN_PREFIX: presignPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const created = await poolFillSessionStore.createSession(
        'psess-u1',
        makePresignSessionRecord({ version: 1, stage: 'triples' }) as any,
        10_000,
      );
      expect(created.ok).toBe(true);

      const stale = await poolFillSessionStore.advanceSessionCas({
        id: 'psess-u1',
        expectedVersion: 99,
        nextRecord: makePresignSessionRecord({ version: 100, stage: 'triples' }) as any,
        ttlMs: 10_000,
      });
      expect(stale.ok).toBe(false);
      if (!stale.ok) expect(stale.code).toBe('version_mismatch');

      const [a, b] = await Promise.all([
        poolFillSessionStore.advanceSessionCas({
          id: 'psess-u1',
          expectedVersion: 1,
          nextRecord: makePresignSessionRecord({ version: 2, stage: 'triples_done' }) as any,
          ttlMs: 10_000,
        }),
        poolFillSessionStore.advanceSessionCas({
          id: 'psess-u1',
          expectedVersion: 1,
          nextRecord: makePresignSessionRecord({ version: 2, stage: 'triples_done' }) as any,
          ttlMs: 10_000,
        }),
      ]);

      const oks = [a, b].filter((r) => r.ok);
      const errs = [a, b].filter((r) => !r.ok);
      expect(oks.length).toBe(1);
      expect(errs.length).toBe(1);
      if (!errs[0].ok) expect(errs[0].code).toBe('version_mismatch');

      const got = await poolFillSessionStore.getSession('psess-u1');
      expect(got?.version).toBe(2);
      expect(got?.stage).toBe('triples_done');

      await poolFillSessionStore.deleteSession('psess-u1');
      const afterDelete = await poolFillSessionStore.getSession('psess-u1');
      expect(afterDelete).toBeNull();
    });
  });
});
