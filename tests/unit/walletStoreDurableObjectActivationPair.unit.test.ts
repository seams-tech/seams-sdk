import { expect, test } from '@playwright/test';
import { parseWalletId } from '../../packages/shared-ts/src/utils/domainIds';
import { createWalletStore } from '../../packages/sdk-server-ts/src/core/WalletStore';
import { normalizeLogger } from '../../packages/sdk-server-ts/src/core/logger';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../../packages/sdk-server-ts/src/core/types';
import { ThresholdStoreDurableObject } from '../../packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore';

class MemoryStorage {
  readonly values = new Map<string, unknown>();
  transactionCount = 0;

  async get(key: string): Promise<unknown> {
    return this.values.get(key) ?? null;
  }

  async put(key: string, value: unknown): Promise<void> {
    this.values.set(key, value);
  }

  async delete(key: string): Promise<boolean> {
    return this.values.delete(key);
  }

  async transaction<T>(operation: (storage: MemoryStorage) => Promise<T>): Promise<T> {
    this.transactionCount += 1;
    return await operation(this);
  }
}

class RecordingNamespace implements CloudflareDurableObjectNamespaceLike {
  readonly requests: Record<string, unknown>[] = [];

  idFromName(name: string): unknown {
    return name;
  }

  get(_id: unknown): CloudflareDurableObjectStubLike {
    return {
      fetch: async (_input, init) => {
        this.requests.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
        return new Response(JSON.stringify({ ok: true, value: null }), {
          headers: { 'content-type': 'application/json' },
        });
      },
    };
  }
}

async function post(
  durableObject: ThresholdStoreDurableObject,
  body: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const response = await durableObject.fetch(
    new Request('https://threshold-store.invalid/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );
  return (await response.json()) as Record<string, unknown>;
}

function testWalletId() {
  const parsed = parseWalletId('frost-fjord-rgcmpa');
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

test('wallet activation pair operation consumes both records atomically', async () => {
  const storage = new MemoryStorage();
  const durableObject = new ThresholdStoreDurableObject({ storage }, {});
  const recoveryKey = 'wallet:activation:recovery';
  const refreshKey = 'wallet:activation:refresh';
  const recovery = { operation: 'recovery', proof: 'recovery-proof' };
  const refresh = { operation: 'refresh', proof: 'refresh-proof' };
  const request = {
    op: 'walletTakeEcdsaPendingSessionActivationPair',
    recoveryKey,
    refreshKey,
  };

  storage.values.set(recoveryKey, recovery);
  await expect(post(durableObject, request)).resolves.toEqual({
    ok: true,
    value: null,
  });
  expect(storage.values.get(recoveryKey)).toEqual(recovery);

  storage.values.set(refreshKey, refresh);
  await expect(post(durableObject, request)).resolves.toEqual({
    ok: true,
    value: { recovery, refresh },
  });
  expect(storage.values.has(recoveryKey)).toBe(false);
  expect(storage.values.has(refreshKey)).toBe(false);

  await expect(post(durableObject, request)).resolves.toEqual({
    ok: true,
    value: null,
  });
  expect(storage.transactionCount).toBe(3);
});

test('Cloudflare wallet store requests one activation-pair boundary operation', async () => {
  const namespace = new RecordingNamespace();
  const walletId = testWalletId();
  const store = createWalletStore({
    config: {
      kind: 'cloudflare-do',
      namespace,
    },
    logger: normalizeLogger(),
    isNode: false,
  });

  await expect(
    store.takeEcdsaPendingSessionActivationPair({
      walletId,
      recovery: {
        lifecycleId: 'lifecycle-recovery',
        requestId: 'request-recovery',
      },
      refresh: {
        lifecycleId: 'lifecycle-refresh',
        requestId: 'request-refresh',
      },
    }),
  ).resolves.toBeNull();

  expect(namespace.requests).toHaveLength(1);
  expect(namespace.requests[0]).toMatchObject({
    op: 'walletTakeEcdsaPendingSessionActivationPair',
    recoveryKey: expect.stringContaining(`${walletId}:lifecycle-recovery:request-recovery`),
    refreshKey: expect.stringContaining(`${walletId}:lifecycle-refresh:request-refresh`),
  });
});
