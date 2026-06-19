import { expect, test } from '@playwright/test';
import { createRequire } from 'module';
import { createEd25519WalletSessionStore } from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore';
import { createThresholdEcdsaSigningStores } from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/EcdsaSigningStore';
import { ensureThresholdEd25519SessionsKindConstraint } from '../../packages/sdk-server-ts/src/storage/postgres';

type FakeQueryResult = { rows: any[]; rowCount?: number };
type FakePool = {
  query: (text: string, values?: unknown[]) => Promise<FakeQueryResult>;
  connect?: never;
  end?: never;
};

const logger = {
  info() {},
  warn() {},
  error() {},
  debug() {},
} as const;

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

test.describe('threshold postgres malformed-row cleanup', () => {
  test('prunes obsolete Ed25519 session kinds before tightening the kind constraint', async () => {
    const queries: string[] = [];
    await ensureThresholdEd25519SessionsKindConstraint({
      async query(text: string) {
        queries.push(text);
        return { rows: [] };
      },
    });

    const dropKindCheckIndex = queries.findIndex((query) =>
      query.includes('DROP CONSTRAINT IF EXISTS threshold_ed25519_sessions_kind_check'),
    );
    const pruneObsoleteKindsIndex = queries.findIndex(
      (query) =>
        query.includes('DELETE FROM threshold_ed25519_sessions') &&
        query.includes("kind NOT IN ('mpc', 'signing', 'coordinator', 'wallet_session', 'presign', 'presign_rate')"),
    );
    const addKindCheckIndex = queries.findIndex(
      (query) =>
        query.includes('ADD CONSTRAINT threshold_ed25519_sessions_kind_check') &&
        query.includes("CHECK (kind IN ('mpc', 'signing', 'coordinator', 'wallet_session', 'presign', 'presign_rate'))"),
    );

    expect(dropKindCheckIndex).toBeGreaterThanOrEqual(0);
    expect(pruneObsoleteKindsIndex).toBeGreaterThan(dropKindCheckIndex);
    expect(addKindCheckIndex).toBeGreaterThan(pruneObsoleteKindsIndex);
  });

  test('deletes malformed Wallet Session, presign-session, and presignature rows on read boundaries', async () => {
    const deletedSessionIds: string[] = [];
    const deletedPresignSessionIds: string[] = [];
    const deletedPresignatures: Array<{ relayerKeyId: string; presignatureId: string }> = [];
    const postgresUrl = 'postgres://threshold-cleanup/shared';
    await withFakePgPool({
      postgresUrl,
      pool: {
        async query(text: string, values?: unknown[]) {
          if (text.includes('DELETE FROM threshold_ed25519_sessions')) {
            deletedSessionIds.push(String(values?.[2] || ''));
            return { rows: [] };
          }
          if (text.includes('DELETE FROM threshold_ecdsa_presign_sessions')) {
            deletedPresignSessionIds.push(String(values?.[1] || ''));
            return { rows: [] };
          }
          if (
            text.includes('DELETE FROM threshold_ecdsa_presignatures') &&
            text.includes('presignature_id = $3')
          ) {
            deletedPresignatures.push({
              relayerKeyId: String(values?.[1] || ''),
              presignatureId: String(values?.[2] || ''),
            });
            return { rows: [] };
          }
          if (text.includes('SELECT record_json, expires_at_ms, remaining_uses')) {
            return {
              rows: [
                {
                  record_json: {
                    expiresAtMs: 123_456,
                    relayerKeyId: 'relayer-key',
                    userId: 'alice.testnet',
                    rpId: 'example.localhost',
                  },
                  expires_at_ms: 123_456,
                  remaining_uses: 3,
                },
              ],
            };
          }
          if (
            text.includes('SELECT record_json, expires_at_ms') &&
            text.includes('threshold_ecdsa_presign_sessions')
          ) {
            return {
              rows: [
                {
                  record_json: {
                    expiresAtMs: 999_999,
                    userId: 'alice.testnet',
                    rpId: 'example.localhost',
                    relayerKeyId: 'relayer-key',
                    clientParticipantId: 1,
                    relayerParticipantId: 2,
                    stage: 'triples',
                    version: 1,
                    createdAtMs: 100,
                    updatedAtMs: 120,
                    signingRootId: 'signing-root',
                    walletKeyVersion: 'wallet-key-v1',
                    derivationVersion: 1,
                  },
                  expires_at_ms: 999_999,
                },
              ],
            };
          }
          if (
            text.includes('UPDATE threshold_ecdsa_presignatures p') &&
            text.includes('RETURNING p.record_json, p.presignature_id')
          ) {
            return {
              rows: [
                {
                  record_json: {
                    relayerKeyId: 'relayer-key',
                    presignatureId: 'presignature-1',
                    bigRB64u: 'big-r',
                    kShareB64u: 'k-share',
                    createdAtMs: 123,
                  },
                  presignature_id: 'presignature-1',
                },
              ],
            };
          }
          throw new Error(`Unexpected query: ${text}`);
        },
      },
      run: async () => {
        const walletSessionStore = createEd25519WalletSessionStore({
          config: {
            kind: 'postgres',
            postgresUrl,
            keyPrefix: 'threshold-wallet-session-cleanup',
          },
          logger,
          isNode: true,
        });
        const stores = createThresholdEcdsaSigningStores({
          config: {
            kind: 'postgres',
            postgresUrl,
            THRESHOLD_ECDSA_PRESIGN_PREFIX: 'threshold-ecdsa-presign-cleanup',
          },
          logger,
          isNode: true,
        });

        await expect(walletSessionStore.getSession('wallet-session-1')).resolves.toBeNull();
        await expect(stores.poolFillSessionStore.getSession('presign-session-1')).resolves.toBeNull();
        await expect(stores.presignaturePool.reserve('relayer-key')).resolves.toBeNull();
      },
    });

    expect(deletedSessionIds).toEqual(['wallet-session-1']);
    expect(deletedPresignSessionIds).toEqual(['presign-session-1']);
    expect(deletedPresignatures).toEqual([
      {
        relayerKeyId: 'relayer-key',
        presignatureId: 'presignature-1',
      },
    ]);
  });
});
