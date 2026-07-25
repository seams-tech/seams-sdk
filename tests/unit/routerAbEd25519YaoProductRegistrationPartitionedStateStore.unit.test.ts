import { expect, test } from '@playwright/test';
import {
  ROUTER_AB_ED25519_YAO_SHARED_STATE_RECORD_KEY_V1,
  createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  type RouterAbEd25519YaoProductRegistrationPartitionBatchResultV1,
  type RouterAbEd25519YaoProductRegistrationPartitionMutationV1,
  type RouterAbEd25519YaoProductRegistrationPartitionRecordStoreV1,
  type RouterAbEd25519YaoProductRegistrationPartitionRecordV1,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistrationPartitionedStateStore';
import { createRouterAbEd25519YaoProductRegistrationStateV1 } from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistration';
import type { CloudflareVersionedJsonRecordReadResult } from '../../packages/sdk-server-ts/src/router/cloudflare/versionedJsonRecordStore';

type StoredRecord = {
  readonly value: RouterAbEd25519YaoProductRegistrationPartitionRecordV1;
  readonly version: number;
};

class MemoryPartitionRecordStore implements RouterAbEd25519YaoProductRegistrationPartitionRecordStoreV1 {
  readonly records = new Map<string, StoredRecord>();

  async readMany(
    keys: readonly string[],
  ): Promise<
    readonly {
      readonly key: string;
      readonly result: CloudflareVersionedJsonRecordReadResult<RouterAbEd25519YaoProductRegistrationPartitionRecordV1>;
    }[]
  > {
    return keys.map((key) => {
      const record = this.records.get(key);
      return {
        key,
        result: record
          ? {
              kind: 'present' as const,
              value: structuredClone(record.value),
              version: String(record.version),
            }
          : { kind: 'missing' as const },
      };
    });
  }

  async putMany(
    mutations: readonly RouterAbEd25519YaoProductRegistrationPartitionMutationV1[],
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionBatchResultV1> {
    for (const mutation of mutations) {
      const current = this.records.get(mutation.key);
      if (mutation.expectedVersion === null) {
        if (current) return { kind: 'version_mismatch', key: mutation.key };
        continue;
      }
      if (!current || String(current.version) !== mutation.expectedVersion) {
        return { kind: 'version_mismatch', key: mutation.key };
      }
    }
    for (const mutation of mutations) {
      const current = this.records.get(mutation.key);
      this.records.set(mutation.key, {
        value: structuredClone(mutation.value),
        version: (current?.version ?? 0) + 1,
      });
    }
    return {
      kind: 'stored',
      versions: mutations.map((mutation) => ({
        key: mutation.key,
        version: String(this.records.get(mutation.key)?.version ?? 0),
      })),
    };
  }
}

test.describe('partitioned Gateway product-state composition', () => {
  test('loads empty records and commits shared plus one ceremony atomically', async () => {
    const backend = new MemoryPartitionRecordStore();
    const store = createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1(backend);
    const empty = await store.load('lifecycle-a');
    expect(empty.sharedVersion).toBeNull();
    expect(empty.ceremonyVersion).toBeNull();

    const state = createRouterAbEd25519YaoProductRegistrationStateV1();
    state.registration.lifecycleSessions.set('lifecycle-a', 'session-a');
    state.export.authorizationNonces.add('first');
    await expect(
      store.commit({
        lifecycleId: 'lifecycle-a',
        state,
        sharedState: empty.sharedState,
        sharedVersion: empty.sharedVersion,
        ceremonyVersion: empty.ceremonyVersion,
      }),
    ).resolves.toEqual({ kind: 'stored', sharedVersion: '1', ceremonyVersion: '1' });

    const loaded = await store.load('lifecycle-a');
    expect(loaded.state.registration.lifecycleSessions.get('lifecycle-a')).toBe('session-a');
    expect(backend.records.has(ROUTER_AB_ED25519_YAO_SHARED_STATE_RECORD_KEY_V1)).toBeTruthy();
  });

  test('preserves another ceremony while committing a separate lifecycle', async () => {
    const backend = new MemoryPartitionRecordStore();
    const store = createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1(backend);
    const stateA = createRouterAbEd25519YaoProductRegistrationStateV1();
    stateA.registration.lifecycleSessions.set('lifecycle-a', 'session-a');
    const first = await store.load('lifecycle-a');
    await store.commit({
      lifecycleId: 'lifecycle-a',
      state: stateA,
      sharedState: first.sharedState,
      sharedVersion: first.sharedVersion,
      ceremonyVersion: first.ceremonyVersion,
    });

    const stateB = createRouterAbEd25519YaoProductRegistrationStateV1();
    stateB.registration.lifecycleSessions.set('lifecycle-b', 'session-b');
    const second = await store.load('lifecycle-b');
    await expect(
      store.commit({
        lifecycleId: 'lifecycle-b',
        state: stateB,
        sharedState: second.sharedState,
        sharedVersion: second.sharedVersion,
        ceremonyVersion: second.ceremonyVersion,
      }),
    ).resolves.toEqual({ kind: 'stored', sharedVersion: null, ceremonyVersion: '1' });

    await expect(store.load('lifecycle-a')).resolves.toMatchObject({
      state: { registration: { lifecycleSessions: new Map([['lifecycle-a', 'session-a']]) } },
      sharedVersion: null,
      ceremonyVersion: '1',
    });
    await expect(store.load('lifecycle-b')).resolves.toMatchObject({
      state: { registration: { lifecycleSessions: new Map([['lifecycle-b', 'session-b']]) } },
      sharedVersion: null,
      ceremonyVersion: '1',
    });
  });

  test('returns a typed conflict without applying either record on stale state', async () => {
    const backend = new MemoryPartitionRecordStore();
    const store = createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1(backend);
    const initial = await store.load('lifecycle-c');
    const initialState = createRouterAbEd25519YaoProductRegistrationStateV1();
    await store.commit({
      lifecycleId: 'lifecycle-c',
      state: initialState,
      sharedState: initial.sharedState,
      sharedVersion: initial.sharedVersion,
      ceremonyVersion: initial.ceremonyVersion,
    });

    const stale = await store.load('lifecycle-c');
    const winner = await store.load('lifecycle-c');
    winner.state.registration.lifecycleSessions.set('lifecycle-c', 'winner');
    winner.state.export.authorizationNonces.add('winner');
    await store.commit({
      lifecycleId: 'lifecycle-c',
      state: winner.state,
      sharedState: winner.sharedState,
      sharedVersion: winner.sharedVersion,
      ceremonyVersion: winner.ceremonyVersion,
    });

    stale.state.registration.lifecycleSessions.set('lifecycle-c', 'stale');
    stale.state.export.authorizationNonces.add('stale');
    await expect(
      store.commit({
        lifecycleId: 'lifecycle-c',
        state: stale.state,
        sharedState: stale.sharedState,
        sharedVersion: stale.sharedVersion,
        ceremonyVersion: stale.ceremonyVersion,
      }),
    ).resolves.toEqual({ kind: 'version_mismatch', key: 'shared' });

    await expect(store.load('lifecycle-c')).resolves.toMatchObject({
      state: { registration: { lifecycleSessions: new Map([['lifecycle-c', 'winner']]) } },
      sharedVersion: '1',
      ceremonyVersion: '2',
    });
  });
});
