import { expect, test } from '@playwright/test';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../packages/wallet-server/src/storage/tenantRoute';
import {
  createCloudflareD1VersionedJsonRecordStore,
  type CloudflareD1VersionedJsonRecordScopeV1,
} from '../../packages/wallet-server/src/router/cloudflare/d1/versionedJson/d1VersionedJsonRecordStore';
import type { VersionedJsonObject } from '../../packages/wallet-server/src/router/framework/versionedJsonRecordStore';
import {
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
} from '../helpers/sqliteD1';

type RecordValue = {
  readonly kind: 'test_d1_record_v1';
  readonly id: string;
  readonly count: number;
};

type StoredRow = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly recordKey: string;
  version: number;
  recordJson: string;
};

class MemoryD1 implements D1DatabaseLike {
  readonly rows = new Map<string, StoredRow>();
  lastChanges = 0;

  prepare(query: string): D1PreparedStatementLike {
    return new MemoryStatement(this, query);
  }

  async batch<T = unknown>(statements: readonly D1PreparedStatementLike[]): Promise<readonly T[]> {
    const snapshot = new Map(
      [...this.rows.entries()].map(([key, row]) => [key, { ...row }] as const),
    );
    const previousChanges = this.lastChanges;
    const results: T[] = [];
    try {
      for (const statement of statements) results.push((await statement.run<T>()) as T);
      return results;
    } catch (error: unknown) {
      this.rows.clear();
      for (const [key, row] of snapshot) this.rows.set(key, row);
      this.lastChanges = previousChanges;
      throw error;
    }
  }

  async exec(_query: string): Promise<unknown> {
    return undefined;
  }
}

class MemoryStatement implements D1PreparedStatementLike {
  private values: readonly unknown[] = [];

  constructor(
    private readonly database: MemoryD1,
    private readonly query: string,
  ) {}

  bind(...values: readonly unknown[]): D1PreparedStatementLike {
    this.values = values;
    return this;
  }

  async first<T = unknown>(_columnName?: string): Promise<T | null> {
    const result = await this.all<T>();
    return result.results?.[0] ?? null;
  }

  async all<T = unknown>(): Promise<D1ResultLike<T>> {
    if (!this.query.startsWith('SELECT')) throw new Error('unexpected all query');
    const row = this.database.rows.get(this.key());
    return {
      success: true,
      results: row
        ? ([{ version: row.version, record_json: row.recordJson }] as unknown as readonly T[])
        : [],
    };
  }

  async run<T = unknown>(): Promise<D1ResultLike<T>> {
    if (this.query.startsWith('SELECT')) return (await this.all<T>()) as D1ResultLike<T>;
    if (this.query.startsWith('INSERT OR IGNORE')) return this.insert<T>();
    if (this.query.startsWith('UPDATE')) return this.update<T>();
    if (this.query.startsWith('INSERT INTO router_ab_yao_versioned_json_cas_guard')) {
      return this.guard<T>();
    }
    throw new Error('unexpected run query');
  }

  private insert<T>(): D1ResultLike<T> {
    const row = this.rowFromInsert();
    if (this.database.rows.has(this.key())) {
      this.database.lastChanges = 0;
      return { success: true, meta: { changes: 0 } };
    }
    this.database.rows.set(this.key(), row);
    this.database.lastChanges = 1;
    return { success: true, meta: { changes: 1 } };
  }

  private update<T>(): D1ResultLike<T> {
    const row = this.database.rows.get(this.key());
    const expectedVersion = Number(this.values[7]);
    if (!row || row.version !== expectedVersion) {
      this.database.lastChanges = 0;
      return { success: true, meta: { changes: 0 } };
    }
    row.version += 1;
    row.recordJson = String(this.values[5]);
    this.database.lastChanges = 1;
    return { success: true, meta: { changes: 1 } };
  }

  private guard<T>(): D1ResultLike<T> {
    if (this.database.lastChanges === 0) {
      throw new Error('UNIQUE constraint failed: router_ab_yao_versioned_json_cas_guard.guard_id');
    }
    this.database.lastChanges = 0;
    return { success: true, meta: { changes: 0 } };
  }

  private rowFromInsert(): StoredRow {
    return {
      namespace: String(this.values[0]),
      orgId: String(this.values[1]),
      projectId: String(this.values[2]),
      envId: String(this.values[3]),
      recordKey: String(this.values[4]),
      version: 1,
      recordJson: String(this.values[5]),
    };
  }

  private key(): string {
    return [this.values[0], this.values[1], this.values[2], this.values[3], this.values[4]].join(
      '|',
    );
  }
}

const scope: CloudflareD1VersionedJsonRecordScopeV1 = {
  namespace: 'test-namespace',
  orgId: 'org-test',
  projectId: 'project-test',
  envId: 'env-test',
};

function encodeRecord(value: RecordValue): VersionedJsonObject {
  return { kind: value.kind, id: value.id, count: value.count };
}

function parseRecord(raw: unknown): RecordValue | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  return record.kind === 'test_d1_record_v1' &&
    typeof record.id === 'string' &&
    typeof record.count === 'number' &&
    Number.isSafeInteger(record.count)
    ? { kind: 'test_d1_record_v1', id: record.id, count: record.count }
    : null;
}

function createStore(database: MemoryD1) {
  return createCloudflareD1VersionedJsonRecordStore<RecordValue>({
    database,
    scope,
    keyPrefix: 'test-record',
    encode: encodeRecord,
    parse: parseRecord,
  });
}

function record(id: string, count: number): RecordValue {
  return { kind: 'test_d1_record_v1', id, count };
}

test.describe('Cloudflare D1 versioned JSON record store', () => {
  test('creates, reads, and updates one scoped record', async () => {
    const store = createStore(new MemoryD1());
    await expect(store.read('pair-a')).resolves.toEqual({ kind: 'missing' });

    const created = await store.put('pair-a', record('pair-a', 1), null);
    expect(created).toEqual({ kind: 'stored', version: '1' });
    await expect(store.read('pair-a')).resolves.toEqual({
      kind: 'present',
      value: record('pair-a', 1),
      version: '1',
    });

    await expect(store.put('pair-a', record('pair-a', 2), '1')).resolves.toEqual({
      kind: 'stored',
      version: '2',
    });
  });

  test('fails stale writes atomically and preserves the winner', async () => {
    const store = createStore(new MemoryD1());
    await store.put('pair-b', record('pair-b', 1), null);
    const [first, second] = await Promise.all([
      store.put('pair-b', record('pair-b', 2), '1'),
      store.put('pair-b', record('pair-b', 3), '1'),
    ]);
    expect([first.kind, second.kind].sort()).toEqual(['stored', 'version_mismatch']);
    await expect(store.read('pair-b')).resolves.toMatchObject({
      kind: 'present',
      value: expect.objectContaining({ id: 'pair-b', count: expect.any(Number) }),
      version: '2',
    });
  });

  test('reads shared and ceremony records from one batch snapshot', async () => {
    const store = createStore(new MemoryD1());
    await store.put('shared', record('shared', 1), null);
    const entries = await store.readMany(['shared', 'ceremony-a']);
    expect(entries).toEqual([
      {
        key: 'shared',
        result: { kind: 'present', value: record('shared', 1), version: '1' },
      },
      { key: 'ceremony-a', result: { kind: 'missing' } },
    ]);
    await expect(store.readMany(['shared', 'shared'])).rejects.toThrow('duplicate keys');
  });

  test('commits shared and ceremony records in one batch', async () => {
    const store = createStore(new MemoryD1());
    await expect(
      store.putMany([
        { key: 'shared', value: record('shared', 1), expectedVersion: null },
        { key: 'ceremony-a', value: record('ceremony-a', 1), expectedVersion: null },
      ]),
    ).resolves.toEqual({
      kind: 'stored',
      versions: [
        { key: 'shared', version: '1' },
        { key: 'ceremony-a', version: '1' },
      ],
    });
    await expect(store.read('shared')).resolves.toMatchObject({
      kind: 'present',
      value: record('shared', 1),
      version: '1',
    });
    await expect(store.read('ceremony-a')).resolves.toMatchObject({
      kind: 'present',
      value: record('ceremony-a', 1),
      version: '1',
    });
  });

  test('rolls back every mutation when one expected version is stale', async () => {
    const store = createStore(new MemoryD1());
    await store.putMany([
      { key: 'shared', value: record('shared', 1), expectedVersion: null },
      { key: 'ceremony-b', value: record('ceremony-b', 1), expectedVersion: null },
    ]);

    await expect(
      store.putMany([
        { key: 'shared', value: record('shared', 2), expectedVersion: '1' },
        { key: 'ceremony-b', value: record('ceremony-b', 2), expectedVersion: '9' },
      ]),
    ).resolves.toEqual({ kind: 'version_mismatch', key: 'ceremony-b' });
    await expect(store.read('shared')).resolves.toMatchObject({
      kind: 'present',
      value: record('shared', 1),
      version: '1',
    });
    await expect(store.read('ceremony-b')).resolves.toMatchObject({
      kind: 'present',
      value: record('ceremony-b', 1),
      version: '1',
    });
  });

  test('rejects invalid keys, versions, and stored records', async () => {
    const database = new MemoryD1();
    const store = createStore(database);
    await expect(store.read('')).rejects.toThrow('record key is required');
    await expect(store.put('pair-c', record('pair-c', 1), '')).rejects.toThrow('expectedVersion');

    database.rows.set('test-namespace|org-test|project-test|env-test|test-record:corrupt', {
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      recordKey: 'test-record:corrupt',
      version: 1,
      recordJson: '{invalid',
    });
    await expect(store.read('corrupt')).rejects.toThrow('record is invalid');
  });

  test('lists prefixes literally without compiling caller data as a LIKE pattern', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await temporary.database.exec(`
        CREATE TABLE router_ab_yao_versioned_json_cas_guard (
          guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
        );
        CREATE TABLE router_ab_yao_versioned_json_records (
          namespace TEXT NOT NULL,
          org_id TEXT NOT NULL,
          project_id TEXT NOT NULL,
          env_id TEXT NOT NULL,
          record_key TEXT NOT NULL,
          version INTEGER NOT NULL,
          record_json TEXT NOT NULL,
          created_at_ms INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
          updated_at_ms INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
          PRIMARY KEY (namespace, org_id, project_id, env_id, record_key),
          CHECK (version > 0),
          CHECK (json_valid(record_json))
        );
      `);
      const store = createCloudflareD1VersionedJsonRecordStore<RecordValue>({
        database: temporary.database,
        scope,
        keyPrefix: 'test-record',
        encode: encodeRecord,
        parse: parseRecord,
      });
      await store.put('literal%_:match', record('literal', 1), null);
      await store.put('literalXX:no-match', record('other', 2), null);

      await expect(store.listByKeyPrefix('literal%_')).resolves.toMatchObject([
        { key: 'literal%_:match', result: { kind: 'present', value: record('literal', 1) } },
      ]);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });
});
