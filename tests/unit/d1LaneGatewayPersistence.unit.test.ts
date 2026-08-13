import { expect, test } from '@playwright/test';
import { CloudflareD1LaneEffectJournalStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/signingLanes/d1LaneEffectJournalStore';
import { CloudflareD1LaneLockStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/signingLanes/d1LaneLockStore';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import {
  buildR102LaneEffectRecordFixture,
  buildR102LaneLockIdentitiesFixture,
} from './helpers/r102LaneGateway.fixtures';

const scope = {
  namespace: 'r102-test-namespace',
  orgId: 'r102-test-org',
  projectId: 'r102-test-project',
  envId: 'r102-test-env',
} as const;

test.describe('R102 Gateway D1 persistence', () => {
  test('records and confirms one exact server effect with replay/conflict outcomes', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
      await seedEffectParents(temporary.database);
      const store = new CloudflareD1LaneEffectJournalStore({ database: temporary.database, scope });
      const record = buildR102LaneEffectRecordFixture();
      const commandDigestB64u = 'command-digest-r102-fixture';

      await expect(store.recordEffect({ record, commandDigestB64u })).resolves.toMatchObject({
        outcome: 'applied',
        version: 1,
      });
      await expect(store.recordEffect({ record, commandDigestB64u })).resolves.toMatchObject({
        outcome: 'replayed',
        version: 1,
      });
      await expect(
        store.recordEffect({
          record: { ...record, requestDigestB64u: 'different-request-digest' },
          commandDigestB64u: 'different-command-digest',
        }),
      ).resolves.toMatchObject({ outcome: 'conflict', actualVersion: 1 });

      const confirmed = {
        responseDigestB64u: 'response-digest-r102-fixture',
        confirmedAtMs: 1_001,
      };
      await expect(
        store.confirmEffect({
          effectId: record.effectId,
          expectedVersion: 1,
          commandDigestB64u: 'confirm-command-digest',
          ...confirmed,
        }),
      ).resolves.toMatchObject({ outcome: 'applied', version: 2 });
      await expect(
        store.confirmEffect({
          effectId: record.effectId,
          expectedVersion: 1,
          commandDigestB64u: 'confirm-command-digest',
          ...confirmed,
        }),
      ).resolves.toMatchObject({ outcome: 'replayed', version: 2 });
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('uses wallet-key and enrollment lock namespaces with expiry fencing', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
      const store = new CloudflareD1LaneLockStore({ database: temporary.database, scope });
      const { walletKeyId, enrollmentId } = buildR102LaneLockIdentitiesFixture();

      await expect(
        store.acquireWalletKeyLock({ walletKeyId, lockId: 'lock-a', ttlMs: 100, nowMs: 1_000 }),
      ).resolves.toMatchObject({
        outcome: 'applied',
        lock: { lockKey: 'wallet-key:wallet-key-r102-lock' },
      });
      await expect(
        store.acquireWalletKeyLock({ walletKeyId, lockId: 'lock-a', ttlMs: 100, nowMs: 1_050 }),
      ).resolves.toMatchObject({ outcome: 'replayed' });
      await expect(
        store.acquireWalletKeyLock({ walletKeyId, lockId: 'lock-b', ttlMs: 100, nowMs: 1_050 }),
      ).resolves.toMatchObject({ outcome: 'conflict' });
      await expect(
        store.acquireWalletKeyLock({ walletKeyId, lockId: 'lock-b', ttlMs: 100, nowMs: 1_100 }),
      ).resolves.toMatchObject({ outcome: 'applied' });
      await expect(
        store.acquireEnrollmentLock({
          enrollmentId,
          lockId: 'enrollment-lock',
          ttlMs: 100,
          nowMs: 1_000,
        }),
      ).resolves.toMatchObject({
        outcome: 'applied',
        lock: { lockKey: 'enrollment:enrollment-r102-lock' },
      });
      await expect(
        store.releaseLock({
          lockKey: 'enrollment:enrollment-r102-lock',
          lockId: 'enrollment-lock',
        }),
      ).resolves.toBe(true);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });
});

async function seedEffectParents(
  database: Parameters<typeof applyD1MigrationFiles>[0],
): Promise<void> {
  await database.exec(`
    INSERT INTO lane_enrollments (
      namespace, org_id, project_id, env_id, enrollment_id, wallet_id,
      manifest_digest_b64u, manifest_json, lifecycle_json, version,
      command_digest_b64u, created_at_ms, updated_at_ms
    ) VALUES (
      '${scope.namespace}', '${scope.orgId}', '${scope.projectId}', '${scope.envId}',
      'enrollment-r102-fixture', 'wallet-r102-fixture', 'manifest-digest-r102-fixture',
      '{"kind":"lane_enrollment_manifest_v1"}', '{"state":"preparing","manifestDigestB64u":"manifest-digest-r102-fixture","startedAtMs":1000}',
      1, 'command-digest-r102-fixture', 1000, 1000
    );
    INSERT INTO lane_protocol_operations (
      namespace, org_id, project_id, env_id, operation_id, enrollment_id, wallet_id,
      wallet_key_id, source_lane_id, source_lane_share_epoch, source_revocation_epoch,
      target_lane_id, target_lane_share_epoch, target_material_activation_id,
      key_family, job_json, lifecycle_json, version, command_digest_b64u, created_at_ms, updated_at_ms
    ) VALUES (
      '${scope.namespace}', '${scope.orgId}', '${scope.projectId}', '${scope.envId}',
      'operation-r102-fixture', 'enrollment-r102-fixture', 'wallet-r102-fixture',
      'wallet-key-r102-fixture', 'source-lane-r102-fixture', 'source-epoch-r102-fixture', 0,
      'lane-r102-fixture', 'epoch-r102-fixture', 'activation-r102-fixture', 'ed25519',
      '{"kind":"fixture"}', '{"state":"preparing","startedAtMs":1000}',
      1, 'command-digest-r102-fixture', 1000, 1000
    );
  `);
}
