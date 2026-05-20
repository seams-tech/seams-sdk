import { expect, test } from '@playwright/test';
import { createRequire } from 'module';
import { normalizeLogger } from '../../server/src/core/logger';
import { createThresholdEcdsaKeyStore } from '../../server/src/core/ThresholdService/stores/KeyStore';

type FakeQueryResult = { rows: any[]; rowCount?: number };
type FakePool = {
  query: (text: string, values?: unknown[]) => Promise<FakeQueryResult>;
  connect?: never;
  end?: never;
};

async function withFakePgPool<T>(input: {
  postgresUrl: string;
  pool: FakePool;
  run: () => Promise<T>;
}): Promise<T> {
  const require = createRequire(import.meta.url);
  const pg = require('pg') as {
    Pool: new (opts: { connectionString: string }) => FakePool;
    default?: { Pool?: new (opts: { connectionString: string }) => FakePool };
  };
  const originalPool = pg.Pool;
  const originalDefaultPool = pg.default?.Pool;

  class FakePoolCtor {
    constructor(_opts: { connectionString: string }) {
      return input.pool;
    }
  }

  pg.Pool = FakePoolCtor as typeof pg.Pool;
  if (pg.default) {
    pg.default.Pool = FakePoolCtor as typeof pg.Pool;
  }

  try {
    return await input.run();
  } finally {
    pg.Pool = originalPool;
    if (pg.default) {
      pg.default.Pool = originalDefaultPool as typeof pg.Pool;
    }
  }
}

test.describe('threshold-ecdsa postgres key store schema validation', () => {
  test('validates indexed identity columns without startup prune or backfill', async () => {
    const postgresUrl = 'postgres://threshold-backfill/shared';
    const namespace = 'threshold-backfill-namespace';
    const keyHandle = 'ehss-key-current';

    const queryLog: string[] = [];
    let validatedIndexedColumns = false;
    await withFakePgPool({
      postgresUrl,
      pool: {
        async query(text: string, values?: unknown[]) {
          const normalized = text.replace(/\s+/g, ' ').trim();
          queryLog.push(normalized);
          if (
            normalized.startsWith('UPDATE threshold_ecdsa_keys') &&
            normalized.includes("record_json->>'keyHandle'")
          ) {
            throw new Error('startup key identity backfill should not run');
          }
          if (
            normalized.startsWith('DELETE FROM threshold_ecdsa_keys') &&
            normalized.includes('key_handle IS NULL OR') &&
            normalized.includes('public_key_b64u IS NULL')
          ) {
            throw new Error('startup legacy-row prune should not run');
          }
          if (normalized.includes('SELECT COUNT(*)::INT AS missing_count')) {
            validatedIndexedColumns = true;
            return { rows: [{ missing_count: 0 }] };
          }
          if (
            normalized.includes('FROM threshold_ecdsa_keys') &&
            normalized.includes('WHERE namespace = $1 AND key_handle = $2') &&
            normalized.includes('LIMIT 1')
          ) {
            expect(validatedIndexedColumns).toBe(true);
            expect(values).toEqual([namespace, keyHandle]);
            return { rows: [] };
          }
          if (
            normalized.startsWith('UPDATE threshold_ecdsa_keys SET') &&
            normalized.includes('record_json = $9') &&
            normalized.includes('WHERE namespace = $1 AND relayer_key_id = $2')
          ) {
            throw new Error('legacy key-handle derivation update should not run');
          }
          return { rows: [] };
        },
      },
      run: async () => {
        const store = createThresholdEcdsaKeyStore({
          config: {
            kind: 'postgres',
            postgresUrl,
            keyPrefix: namespace,
          },
          logger: normalizeLogger(null),
          isNode: true,
        });
        const found = await store.getRoleLocalByKeyHandle(keyHandle);
        expect(found).toBeNull();
        expect(validatedIndexedColumns).toBe(true);
      },
    });
  });
});
