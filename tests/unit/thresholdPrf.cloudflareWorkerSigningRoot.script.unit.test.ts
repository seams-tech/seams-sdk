import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/encoders';
import { SIGNING_ROOT_RECORD_VERSION_V1 } from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootRecords';
import {
  sealSigningRootSecretShareWireV1,
  type SigningRootSecretShareKekResolutionInput,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootSecretSealing';
import { CloudflareDurableObjectSigningRootSecretStore } from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/SigningRootSecretStore';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../../packages/sdk-server-ts/src/core/types';
import type {
  SigningRootSecretShareId,
  SigningRootSecretShareWireV1,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootSecretShareWires';
import { ThresholdStoreDurableObject } from '../../packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore';

type ThresholdPrfFixtureShare = {
  readonly id: SigningRootSecretShareId;
  readonly wire_hex: string;
};

type DurableObjectStorageLike = {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<boolean>;
};
type DoOk<T> = { ok: true; value: T };
type DoErr = { ok: false; code: string; message: string };
type DoResp<T> = DoOk<T> | DoErr;

const PROJECT_ID = 'project-alpha';
const ENV_ID = 'dev';
const SIGNING_ROOT_ID = `${PROJECT_ID}:${ENV_ID}`;
const SIGNING_ROOT_VERSION = 'root-v1';
const KEK_ID = 'kek-v1';
const KEK_BYTES = new Uint8Array(32).fill(0x42);

function signingRootSecretShareWire(shareId: SigningRootSecretShareId, fill: number): ThresholdPrfFixtureShare {
  const wire = new Uint8Array([0, shareId, ...new Array(32).fill(fill)]);
  return {
    id: shareId,
    wire_hex: Buffer.from(wire).toString('hex'),
  };
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function createMemoryDurableObjectNamespace(input?: {
  readonly onFetch?: (body: unknown) => void;
}): CloudflareDurableObjectNamespaceLike {
  const objects = new Map<string, CloudflareDurableObjectStubLike>();
  return {
    idFromName: (name: string) => name,
    get: (id: unknown) => {
      const key = String(id);
      const existing = objects.get(key);
      if (existing) return existing;

      const storageMap = new Map<string, unknown>();
      const storage: DurableObjectStorageLike = {
        get: async (storageKey) => storageMap.get(storageKey) ?? null,
        put: async (storageKey, value) => {
          storageMap.set(storageKey, value);
        },
        delete: async (storageKey) => storageMap.delete(storageKey),
      };
      const durableObject = new ThresholdStoreDurableObject({ storage }, {});
      const stub: CloudflareDurableObjectStubLike = {
        fetch: async (request, init) => {
          const materializedRequest =
            request instanceof Request ? request : new Request(request, init);
          if (input?.onFetch) {
            let body: unknown = null;
            try {
              body = await materializedRequest.clone().json();
            } catch {
              body = null;
            }
            input.onFetch(body);
          }
          return durableObject.fetch(materializedRequest);
        },
      };
      objects.set(key, stub);
      return stub;
    },
  };
}

async function postDo<T>(
  stub: CloudflareDurableObjectStubLike,
  body: Record<string, unknown>,
): Promise<DoResp<T>> {
  const response = await stub.fetch('https://threshold-store.invalid/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  expect(response.ok).toBe(true);
  return (await response.json()) as DoResp<T>;
}

test('Cloudflare Durable Object signing-root protocol stores record status and materializes sealed shares', async () => {
  const shares = [
    signingRootSecretShareWire(1, 0x11),
    signingRootSecretShareWire(2, 0x22),
    signingRootSecretShareWire(3, 0x33),
  ];
  const namespace = createMemoryDurableObjectNamespace();
  const objectName = 'signing-root-protocol-test';
  const stub = namespace.get(namespace.idFromName(objectName));
  const sealedSigningRootSecretShares = [];
  const resolveKek = (): Uint8Array => new Uint8Array(KEK_BYTES);

  for (const share of shares) {
    const sealedShare = await sealSigningRootSecretShareWireV1({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
      shareId: share.id,
      kekId: KEK_ID,
      plaintextShareWire: hexToBytes(share.wire_hex) as SigningRootSecretShareWireV1,
      resolveKek,
    });
    sealedSigningRootSecretShares.push({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
      shareId: share.id,
      sealedShareB64u: base64UrlEncode(sealedShare),
      storageId: `storage-${share.id}`,
      kekId: KEK_ID,
    });
  }

  const record = {
    version: SIGNING_ROOT_RECORD_VERSION_V1,
    projectId: PROJECT_ID,
    envId: ENV_ID,
    signingRootId: SIGNING_ROOT_ID,
    walletOrigin: 'https://wallet.example.test',
    authorityScope: { kind: 'passkey_rp', rpId: 'wallet.example.test' },
    signingRootVersion: SIGNING_ROOT_VERSION,
    rootShareEpoch: 1,
    shareThreshold: 2,
    shareCount: 3,
    sealedSigningRootSecretShares,
    derivationVersion: 1,
    createdAtMs: 10,
    updatedAtMs: 20,
    source: 'customer-import',
  };

  const put = await postDo<{
    shareIds: number[];
    contextHashB64u: string;
  }>(stub, { op: 'signingRootPut', record });
  expect(put.ok).toBe(true);
  if (!put.ok) throw new Error(put.message);
  expect(put.value.shareIds).toEqual([1, 2, 3]);
  expect(put.value.contextHashB64u.length).toBeGreaterThan(20);

  const status = await postDo<Record<string, unknown>>(stub, {
    op: 'signingRootStatus',
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  expect(status.ok).toBe(true);
  if (!status.ok) throw new Error(status.message);
  expect(status.value).not.toHaveProperty('sealedSigningRootSecretShares');
  expect(status.value.shareIds).toEqual([1, 2, 3]);

  const get = await postDo<{ sealedSigningRootSecretShares: Array<{ sealedShareB64u: string }> }>(
    stub,
    {
      op: 'signingRootGet',
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
    },
  );
  expect(get.ok).toBe(true);
  if (!get.ok) throw new Error(get.message);
  expect(get.value.sealedSigningRootSecretShares[0].sealedShareB64u).toBe(
    sealedSigningRootSecretShares[0].sealedShareB64u,
  );

  const store = new CloudflareDurableObjectSigningRootSecretStore({ namespace, objectName });
  const listed = await store.listSealedSigningRootSecretShares({
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  expect(listed.map((share) => share.shareId)).toEqual([1, 2, 3]);

  const deleted = await postDo<{ deleted: boolean }>(stub, {
    op: 'signingRootDelete',
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  expect(deleted).toEqual({ ok: true, value: { deleted: true } });

  const statusAfterDelete = await postDo<unknown>(stub, {
    op: 'signingRootStatus',
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  expect(statusAfterDelete).toEqual({ ok: true, value: null });
  await expect(
    store.listSealedSigningRootSecretShares({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
    }),
  ).resolves.toEqual([]);
});

test('Cloudflare Durable Object signing-root store optionally caches sealed share listings', async () => {
  const fetchBodies: unknown[] = [];
  const namespace = createMemoryDurableObjectNamespace({
    onFetch: (body) => fetchBodies.push(body),
  });
  const store = new CloudflareDurableObjectSigningRootSecretStore({
    namespace,
    objectName: 'signing-root-cache-test',
    cacheTtlMs: 60_000,
  });

  await store.putSealedSigningRootSecretShare({
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    shareId: 1,
    sealedShare: new Uint8Array([1, 2, 3]),
    kekId: KEK_ID,
  });
  fetchBodies.length = 0;

  await expect(
    store.listSealedSigningRootSecretShares({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
    }),
  ).resolves.toHaveLength(1);
  const firstReadFetchCount = fetchBodies.length;
  expect(firstReadFetchCount).toBeGreaterThan(0);

  await expect(
    store.listSealedSigningRootSecretShares({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
    }),
  ).resolves.toHaveLength(1);
  expect(fetchBodies).toHaveLength(firstReadFetchCount);

  await store.deleteSigningRootSecretShares({
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  await expect(
    store.listSealedSigningRootSecretShares({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
    }),
  ).resolves.toEqual([]);
  expect(fetchBodies.length).toBeGreaterThan(firstReadFetchCount);
});
