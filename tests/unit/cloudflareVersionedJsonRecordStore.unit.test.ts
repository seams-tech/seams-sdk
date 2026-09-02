import { expect, test } from '@playwright/test';
import { isPlainObject } from '@shared/utils/validation';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../../packages/wallet-server/src/core/types';
import {
  CloudflareVersionedJsonRecordStoreError,
  createCloudflareDurableObjectVersionedJsonRecordStore,
} from '../../packages/wallet-server/src/router/cloudflare/durableObjects/versionedJsonRecordStore';
import type { VersionedJsonObject } from '../../packages/wallet-server/src/router/framework/versionedJsonRecordStore';
import { ThresholdStoreDurableObject } from '../../packages/wallet-server/src/router/cloudflare/durableObjects/thresholdStore';

type CeremonyRecord = {
  readonly kind: 'test_ceremony_v1';
  readonly ceremonyId: string;
  readonly state: 'prepared' | 'running';
  readonly count: number;
};

type TestStorage = {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<boolean>;
  transaction<T>(fn: (storage: TestStorage) => Promise<T>): Promise<T>;
};

class MemoryStorage implements TestStorage {
  private readonly values = new Map<string, unknown>();
  private tail: Promise<void> = Promise.resolve();

  async get(key: string): Promise<unknown> {
    return this.values.get(key) ?? null;
  }

  async put(key: string, value: unknown): Promise<void> {
    this.values.set(key, value);
  }

  async delete(key: string): Promise<boolean> {
    return this.values.delete(key);
  }

  async transaction<T>(fn: (storage: TestStorage) => Promise<T>): Promise<T> {
    const previous = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => {
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

class MemoryNamespace implements CloudflareDurableObjectNamespaceLike {
  private readonly objects = new Map<string, CloudflareDurableObjectStubLike>();

  idFromName(name: string): string {
    return name;
  }

  get(id: unknown): CloudflareDurableObjectStubLike {
    const name = String(id);
    const existing = this.objects.get(name);
    if (existing) return existing;
    const durableObject = new ThresholdStoreDurableObject({ storage: new MemoryStorage() }, {});
    const stub: CloudflareDurableObjectStubLike = {
      fetch: async (request, init) =>
        durableObject.fetch(request instanceof Request ? request : new Request(request, init)),
    };
    this.objects.set(name, stub);
    return stub;
  }
}

function encodeCeremony(value: CeremonyRecord): VersionedJsonObject {
  return {
    kind: value.kind,
    ceremonyId: value.ceremonyId,
    state: value.state,
    count: value.count,
  };
}

function parseCeremony(raw: unknown): CeremonyRecord | null {
  if (!isPlainObject(raw)) return null;
  const record = raw;
  if (
    record.kind !== 'test_ceremony_v1' ||
    typeof record.ceremonyId !== 'string' ||
    (record.state !== 'prepared' && record.state !== 'running') ||
    typeof record.count !== 'number' ||
    !Number.isSafeInteger(record.count)
  ) {
    return null;
  }
  return {
    kind: 'test_ceremony_v1',
    ceremonyId: record.ceremonyId,
    state: record.state,
    count: record.count,
  };
}

function parseNoCeremony(_raw: unknown): CeremonyRecord | null {
  return null;
}

function ceremonyObjectName(key: string): string {
  return `ceremony:${key}`;
}

function createStore(namespace: CloudflareDurableObjectNamespaceLike) {
  return createCloudflareDurableObjectVersionedJsonRecordStore<CeremonyRecord>({
    namespace,
    objectNameForKey: ceremonyObjectName,
    keyPrefix: 'test-record',
    encode: encodeCeremony,
    parse: parseCeremony,
  });
}

function ceremony(
  ceremonyId: string,
  count: number,
  state: CeremonyRecord['state'],
): CeremonyRecord {
  return { kind: 'test_ceremony_v1', ceremonyId, count, state };
}

test.describe('Cloudflare versioned JSON record store', () => {
  test('creates, reads, and updates a record with an opaque version', async () => {
    const store = createStore(new MemoryNamespace());
    await expect(store.read('pair-a')).resolves.toEqual({ kind: 'missing' });

    const created = await store.put('pair-a', ceremony('pair-a', 1, 'prepared'), null);
    expect(created.kind).toBe('stored');
    if (created.kind !== 'stored') return;
    expect(created.version).not.toContain('pair-a');
    expect(created.version).not.toContain('prepared');

    await expect(store.read('pair-a')).resolves.toEqual({
      kind: 'present',
      value: ceremony('pair-a', 1, 'prepared'),
      version: created.version,
    });

    const updated = await store.put('pair-a', ceremony('pair-a', 2, 'running'), created.version);
    expect(updated.kind).toBe('stored');
    if (updated.kind !== 'stored') return;
    expect(updated.version).not.toBe(created.version);
  });

  test('uses atomic compare-and-swap and preserves the winner on stale writes', async () => {
    const store = createStore(new MemoryNamespace());
    const created = await store.put('pair-b', ceremony('pair-b', 1, 'prepared'), null);
    expect(created.kind).toBe('stored');
    if (created.kind !== 'stored') return;

    const [first, second] = await Promise.all([
      store.put('pair-b', ceremony('pair-b', 2, 'running'), created.version),
      store.put('pair-b', ceremony('pair-b', 3, 'running'), created.version),
    ]);
    expect([first.kind, second.kind].sort()).toEqual(['stored', 'version_mismatch']);
    await expect(store.read('pair-b')).resolves.toMatchObject({
      kind: 'present',
      value: expect.objectContaining({ ceremonyId: 'pair-b', state: 'running' }),
    });
  });

  test('rejects empty keys and malformed stored records at the request boundary', async () => {
    const namespace = new MemoryNamespace();
    const store = createStore(namespace);
    await expect(store.read('')).rejects.toThrow('record key is required');
    await expect(store.put('pair-c', ceremony('pair-c', 1, 'prepared'), '')).rejects.toThrow(
      'expectedVersion',
    );

    await store.put('pair-c', ceremony('pair-c', 1, 'prepared'), null);
    const corruptParserStore =
      createCloudflareDurableObjectVersionedJsonRecordStore<CeremonyRecord>({
        namespace,
        objectNameForKey: ceremonyObjectName,
        keyPrefix: 'test-record',
        encode: encodeCeremony,
        parse: parseNoCeremony,
      });
    await expect(corruptParserStore.read('pair-c')).rejects.toMatchObject({
      name: 'CloudflareVersionedJsonRecordStoreError',
      code: 'invalid_record',
    });
    expect(CloudflareVersionedJsonRecordStoreError).toBeDefined();
  });
});
