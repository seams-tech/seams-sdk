import { expect, test } from '@playwright/test';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import { createRequire } from 'module';
import { normalizeLogger } from '../../server/src/core/logger';
import { createThresholdEcdsaKeyStore } from '../../server/src/core/ThresholdService/stores/KeyStore';
import type { EcdsaHssRoleLocalKeyRecord } from '../../server/src/core/types';

type FakeQueryResult = { rows: any[]; rowCount?: number };
type FakePool = {
  query: (text: string, values?: unknown[]) => Promise<FakeQueryResult>;
  connect?: never;
  end?: never;
};

function b64uBytes(length: number, lastByte: number, firstByte = 0): string {
  const bytes = Buffer.alloc(length, 0);
  bytes[0] = firstByte;
  bytes[length - 1] = lastByte;
  return bytes.toString('base64url');
}

function publicKey33B64u(lastByte: number, prefix: 0x02 | 0x03 = 0x02): string {
  return b64uBytes(33, lastByte, prefix);
}

async function makeRoleLocalKeyRecord(
  overrides: Partial<EcdsaHssRoleLocalKeyRecord> = {},
): Promise<EcdsaHssRoleLocalKeyRecord> {
  const base = {
    version: 'threshold_ecdsa_hss_role_local_v2',
    ecdsaThresholdKeyId: 'threshold-key-current',
    walletId: 'alice.testnet',
    rpId: 'example.localhost',
    signingRootId: 'signing-root-current',
    signingRootVersion: 'default',
    keyScope: 'evm-family',
    relayerKeyId: 'relayer-key-current',
    contextBinding32B64u: b64uBytes(32, 1),
    relayerShare32B64u: b64uBytes(32, 2),
    relayerPublicKey33B64u: publicKey33B64u(3),
    clientPublicKey33B64u: publicKey33B64u(4, 0x03),
    groupPublicKey33B64u: publicKey33B64u(5),
    ethereumAddress: '0x1111111111111111111111111111111111111111',
    relayerCaitSithInput: {
      participantId: 2,
      mappedPrivateShare32B64u: b64uBytes(32, 6),
      verifyingShare33B64u: publicKey33B64u(7, 0x03),
    },
    publicTranscriptDigest32B64u: b64uBytes(32, 8),
    createdAtMs: 100,
    updatedAtMs: 200,
    ...overrides,
  } satisfies Omit<EcdsaHssRoleLocalKeyRecord, 'keyHandle'> & { keyHandle?: string };
  const keyHandle =
    overrides.keyHandle ??
    String(
      await deriveThresholdEcdsaKeyHandle({
        ecdsaThresholdKeyId: base.ecdsaThresholdKeyId,
        signingRootId: base.signingRootId,
        signingRootVersion: base.signingRootVersion,
      }),
    );
  return { ...base, keyHandle };
}

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
  test('uses nullable indexed identity columns without startup prune or backfill', async () => {
    const postgresUrl = 'postgres://threshold-backfill/shared';
    const namespace = 'threshold-backfill-namespace';
    const keyHandle = 'ehss-key-current';
    const record = await makeRoleLocalKeyRecord();
    const repairRecord = await makeRoleLocalKeyRecord({
      ecdsaThresholdKeyId: 'threshold-key-read-repair',
      relayerKeyId: 'relayer-key-read-repair',
      walletId: 'repair.alice.testnet',
      signingRootId: 'signing-root-read-repair',
    });
    const staleIndexedRow = {
      relayer_key_id: repairRecord.ecdsaThresholdKeyId,
      key_handle: repairRecord.keyHandle,
      threshold_key_id: 'stale-threshold-key',
      wallet_session_user_id: repairRecord.walletId,
      subject_id: repairRecord.walletId,
      rp_id: repairRecord.rpId,
      signing_root_id: repairRecord.signingRootId,
      signing_root_version: repairRecord.signingRootVersion,
      owner_address: '0x2222222222222222222222222222222222222222',
      public_key_b64u: publicKey33B64u(99),
      record_json: repairRecord,
    };

    const queryLog: string[] = [];
    let createdPartialKeyHandleIndex = false;
    let createdPartialThresholdIdentityIndex = false;
    let createdPartialSharedIdentityIndex = false;
    let checkedSharedIdentityColumns = false;
    let insertedDeclaredIdentityColumns = false;
    let repairedIndexedIdentity = false;
    await withFakePgPool({
      postgresUrl,
      pool: {
        async query(text: string, values?: unknown[]) {
          const normalized = text.replace(/\s+/g, ' ').trim();
          queryLog.push(normalized);
          if (normalized.includes("record_json->>'walletSessionUserId'")) {
            throw new Error('shared identity lookup must use wallet_session_user_id');
          }
          if (normalized.includes("record_json->>'subjectId'")) {
            throw new Error('shared identity lookup must use subject_id');
          }
          if (normalized.includes("record_json->>'rpId'")) {
            throw new Error('shared identity lookup must use rp_id');
          }
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
            throw new Error('startup missing indexed-column validation should not run');
          }
          if (
            normalized.startsWith(
              'CREATE UNIQUE INDEX IF NOT EXISTS threshold_ecdsa_keys_key_handle_uidx',
            )
          ) {
            createdPartialKeyHandleIndex = true;
            expect(normalized).toContain('WHERE key_handle IS NOT NULL');
            return { rows: [] };
          }
          if (
            normalized.startsWith(
              'CREATE UNIQUE INDEX IF NOT EXISTS threshold_ecdsa_keys_threshold_identity_uidx',
            )
          ) {
            createdPartialThresholdIdentityIndex = true;
            expect(normalized).toContain('threshold_key_id IS NOT NULL');
            expect(normalized).toContain('signing_root_id IS NOT NULL');
            expect(normalized).toContain('signing_root_version IS NOT NULL');
            return { rows: [] };
          }
          if (
            normalized.startsWith(
              'CREATE UNIQUE INDEX IF NOT EXISTS threshold_ecdsa_keys_shared_identity_uidx',
            )
          ) {
            createdPartialSharedIdentityIndex = true;
            expect(normalized).toContain('wallet_id IS NOT NULL');
            expect(normalized).toContain('rp_id IS NOT NULL');
            expect(normalized).toContain('signing_root_id IS NOT NULL');
            expect(normalized).toContain('signing_root_version IS NOT NULL');
            return { rows: [] };
          }
          if (
            normalized.includes('FROM threshold_ecdsa_keys') &&
            normalized.includes('WHERE namespace = $1 AND key_handle = $2') &&
            normalized.includes('LIMIT 1')
          ) {
            if (values?.[1] === keyHandle) {
              expect(values).toEqual([namespace, keyHandle]);
              return { rows: [] };
            }
            if (values?.[1] === repairRecord.keyHandle) {
              expect(values).toEqual([namespace, repairRecord.keyHandle]);
              return { rows: [staleIndexedRow] };
            }
            throw new Error(`unexpected ECDSA key-handle read: ${JSON.stringify(values)}`);
          }
          if (
            normalized.includes('WHERE namespace = $1') &&
            normalized.includes('AND relayer_key_id <> $2') &&
            normalized.includes('AND key_handle = $3')
          ) {
            expect(values).toEqual([namespace, record.ecdsaThresholdKeyId, record.keyHandle]);
            return { rows: [] };
          }
          if (
            normalized.startsWith('SELECT relayer_key_id, record_json FROM threshold_ecdsa_keys')
          ) {
            checkedSharedIdentityColumns = true;
            expect(normalized).toContain('wallet_id = $3');
            expect(normalized).toContain('rp_id = $4');
            expect(normalized).toContain('signing_root_id = $5');
            expect(normalized).toContain('signing_root_version = $6');
            expect(values).toEqual([
              namespace,
              record.ecdsaThresholdKeyId,
              record.walletId,
              record.rpId,
              record.signingRootId,
              record.signingRootVersion,
            ]);
            return { rows: [] };
          }
          if (
            normalized.startsWith('INSERT INTO threshold_ecdsa_keys') &&
            normalized.includes('wallet_id') &&
            normalized.includes('rp_id') &&
            normalized.includes('VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)')
          ) {
            insertedDeclaredIdentityColumns = true;
            expect(values).toEqual([
              namespace,
              record.ecdsaThresholdKeyId,
              record.keyHandle,
              record.ecdsaThresholdKeyId,
              record.walletId,
              record.rpId,
              record.signingRootId,
              record.signingRootVersion,
              record.ethereumAddress,
              record.groupPublicKey33B64u,
              record,
            ]);
            return { rows: [] };
          }
          if (
            normalized.startsWith('UPDATE threshold_ecdsa_keys SET') &&
            normalized.includes('public_key_b64u = $10') &&
            normalized.includes('WHERE namespace = $1 AND relayer_key_id = $2')
          ) {
            repairedIndexedIdentity = true;
            expect(values).toEqual([
              namespace,
              repairRecord.ecdsaThresholdKeyId,
              repairRecord.keyHandle,
              repairRecord.ecdsaThresholdKeyId,
              repairRecord.walletId,
              repairRecord.rpId,
              repairRecord.signingRootId,
              repairRecord.signingRootVersion,
              repairRecord.ethereumAddress,
              repairRecord.groupPublicKey33B64u,
            ]);
            return { rows: [], rowCount: 1 };
          }
          if (
            normalized.startsWith('UPDATE threshold_ecdsa_keys SET') &&
            normalized.includes('record_json = $11') &&
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
        await store.putRoleLocalByKeyHandle(record);
        await expect(store.getRoleLocalByKeyHandle(repairRecord.keyHandle)).resolves.toEqual(
          repairRecord,
        );
        expect(createdPartialKeyHandleIndex, queryLog.join('\n')).toBe(true);
        expect(createdPartialThresholdIdentityIndex, queryLog.join('\n')).toBe(true);
        expect(createdPartialSharedIdentityIndex, queryLog.join('\n')).toBe(true);
        expect(checkedSharedIdentityColumns, queryLog.join('\n')).toBe(true);
        expect(insertedDeclaredIdentityColumns, queryLog.join('\n')).toBe(true);
        expect(repairedIndexedIdentity, queryLog.join('\n')).toBe(true);
      },
    });
  });
});
