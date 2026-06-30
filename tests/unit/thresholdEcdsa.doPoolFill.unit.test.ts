import { expect, test } from '@playwright/test';
import { ThresholdStoreDurableObject } from '../../packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore';

type TestDurableObjectStorageLike = {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<boolean>;
  transaction<T>(fn: (txn: TestDurableObjectStorageLike) => Promise<T>): Promise<T>;
};

function createThresholdStoreDurableObject(): ThresholdStoreDurableObject {
  const storageMap = new Map<string, unknown>();
  const storage: TestDurableObjectStorageLike = {
    get: async (storageKey) => storageMap.get(storageKey) ?? null,
    put: async (storageKey, value) => {
      storageMap.set(storageKey, value);
    },
    delete: async (storageKey) => storageMap.delete(storageKey),
    transaction: async (fn) => await fn(storage),
  };
  return new ThresholdStoreDurableObject({ storage }, {});
}

async function postDo(durableObject: ThresholdStoreDurableObject, body: unknown): Promise<unknown> {
  const response = await durableObject.fetch(
    new Request('https://threshold-store.test', {
      method: 'POST',
      body: JSON.stringify(body),
      headers: { 'content-type': 'application/json' },
    }),
  );
  return await response.json();
}

test('ThresholdStore DO ECDSA presignature put is idempotent by presignature id', async () => {
  const durableObject = createThresholdStoreDurableObject();
  const listKey = 'ecdsa:presign:avail:relayer-key';
  const reservedKeyPrefix = 'ecdsa:presign:res:relayer-key:';
  const dedupeKey = 'ecdsa:presign:done:relayer-key:presignature-idempotent';
  const value = {
    relayerKeyId: 'relayer-key',
    presignatureId: 'presignature-idempotent',
    bigRB64u: 'big-r',
    kShareB64u: 'k-share',
    sigmaShareB64u: 'sigma-share',
    createdAtMs: 123,
  };

  await expect(
    postDo(durableObject, { op: 'routerAbEcdsaHssPresignaturePut', listKey, dedupeKey, value }),
  ).resolves.toMatchObject({ ok: true });
  await expect(
    postDo(durableObject, { op: 'routerAbEcdsaHssPresignaturePut', listKey, dedupeKey, value }),
  ).resolves.toMatchObject({ ok: true });

  await expect(
    postDo(durableObject, {
      op: 'routerAbEcdsaHssPresignatureReserve',
      listKey,
      reservedKeyPrefix,
      ttlMs: 120_000,
    }),
  ).resolves.toMatchObject({
    ok: true,
    value: { presignatureId: 'presignature-idempotent' },
  });
  await expect(
    postDo(durableObject, {
      op: 'routerAbEcdsaHssPresignatureReserve',
      listKey,
      reservedKeyPrefix,
      ttlMs: 120_000,
    }),
  ).resolves.toEqual({ ok: true, value: null });
});

test('ThresholdStore DO ECDSA presignature put remains idempotent after reserve and consume', async () => {
  const durableObject = createThresholdStoreDurableObject();
  const listKey = 'ecdsa:presign:avail:relayer-key';
  const reservedKeyPrefix = 'ecdsa:presign:res:relayer-key:';
  const presignatureId = 'presignature-consumed';
  const reservedKey = `${reservedKeyPrefix}${presignatureId}`;
  const dedupeKey = `ecdsa:presign:done:relayer-key:${presignatureId}`;
  const value = {
    relayerKeyId: 'relayer-key',
    presignatureId,
    bigRB64u: 'big-r',
    kShareB64u: 'k-share',
    sigmaShareB64u: 'sigma-share',
    createdAtMs: 123,
  };

  await expect(
    postDo(durableObject, { op: 'routerAbEcdsaHssPresignaturePut', listKey, dedupeKey, value }),
  ).resolves.toMatchObject({ ok: true });
  await expect(
    postDo(durableObject, {
      op: 'routerAbEcdsaHssPresignatureReserve',
      listKey,
      reservedKeyPrefix,
      ttlMs: 120_000,
    }),
  ).resolves.toMatchObject({
    ok: true,
    value: { presignatureId },
  });
  await expect(postDo(durableObject, { op: 'getdel', key: reservedKey })).resolves.toMatchObject({
    ok: true,
    value: { presignatureId },
  });
  await expect(
    postDo(durableObject, { op: 'routerAbEcdsaHssPresignaturePut', listKey, dedupeKey, value }),
  ).resolves.toMatchObject({ ok: true });
  await expect(
    postDo(durableObject, {
      op: 'routerAbEcdsaHssPresignatureReserve',
      listKey,
      reservedKeyPrefix,
      ttlMs: 120_000,
    }),
  ).resolves.toEqual({ ok: true, value: null });
});
