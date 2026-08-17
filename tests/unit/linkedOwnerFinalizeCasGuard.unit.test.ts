import { expect, test } from '@playwright/test';
import {
  D1LinkedDeviceSessionStoreV1,
  type D1LinkedDeviceSessionScopeV1,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSessionStore';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import {
  buildR103AwaitingTargetPasskeySessionRecordV1,
  buildR103UnclaimedLinkedDeviceSessionRecordV1,
} from './helpers/deviceLinkingServer.fixtures';
import {
  buildCancelledClaimedPrecommitLinkedDeviceSessionState,
  buildProvisioningLinkedDeviceSessionState,
} from '../../packages/shared-ts/src/device-linking/parsers';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';

/**
 * The half of the finalize fence that a plan cannot express: what the database
 * actually does when the session moves between the read and the batch.
 *
 * The session CAS rides in the finalize's batch alongside the credential, and
 * D1 does not fail a batch for an `UPDATE` that matches no row — zero rows
 * changed is a successful statement. Without the guard the credential would
 * commit anyway, which is the exact split-brain the fence exists to prevent.
 *
 * These run against the canonical signer migration, so they fail if the guard
 * row is absent rather than passing on a mock that cannot be wrong.
 */
const scope: D1LinkedDeviceSessionScopeV1 = {
  namespace: 'signer',
  orgId: 'org_owner_finalize_guard',
  projectId: 'project_owner_finalize_guard',
  envId: 'env_owner_finalize_guard',
};

let temporary: TemporaryD1Database | undefined;

test.afterEach(() => {
  if (temporary) cleanupTemporaryD1Database(temporary.tempDir);
  temporary = undefined;
});

/** A stand-in for the credential writes the finalize batch carries. */
function companionWriteStatement(database: TemporaryD1Database['database'], marker: string) {
  return database
    .prepare(
      `INSERT INTO linked_device_session_transcripts (
         namespace, org_id, project_id, env_id, link_session_id,
         transcript_kind, digest_b64u, transcript_json, created_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      marker,
      'claim',
      marker,
      '{}',
      1,
    );
}

/**
 * The session's raw state and revision.
 *
 * Read as columns rather than through `getSessionV1`, which also verifies the
 * immutable transcript rows a full session carries. Those are a different
 * invariant with their own tests; what these need to know is whether the CAS
 * landed.
 */
async function readSessionRowV1(
  database: TemporaryD1Database['database'],
  linkSessionId: string,
): Promise<{ readonly state: string; readonly revision: number }> {
  const row = await database
    .prepare(
      `SELECT state, revision FROM linked_device_sessions
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND link_session_id = ? LIMIT 1`,
    )
    .bind(scope.namespace, scope.orgId, scope.projectId, scope.envId, linkSessionId)
    .first<{ state: string; revision: number }>();
  if (!row) throw new Error('seeded linked-device session row is missing');
  return { state: String(row.state), revision: Number(row.revision) };
}

async function companionWriteLanded(
  database: TemporaryD1Database['database'],
  marker: string,
): Promise<boolean> {
  const row = await database
    .prepare(
      `SELECT link_session_id FROM linked_device_session_transcripts
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND link_session_id = ? LIMIT 1`,
    )
    .bind(scope.namespace, scope.orgId, scope.projectId, scope.envId, marker)
    .first();
  return Boolean(row);
}

async function seedAwaitingSession() {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const store = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const seeded = await store.createUnclaimedSessionV1(
    buildR103UnclaimedLinkedDeviceSessionRecordV1(fixture),
  );
  if (seeded.outcome !== 'applied') throw new Error(`seed failed: ${seeded.outcome}`);
  // Advanced with the same statement builder under test, because the row's
  // columns and its record_json have to agree for the reader to accept it and
  // only the store knows how to keep them in step.
  const record = await buildR103AwaitingTargetPasskeySessionRecordV1(fixture, {
    revision: 2,
    credentialDeadlineMs: 9_000,
    updatedAtMs: 1_000,
  });
  await temporary.database.batch(
    store.buildTargetCredentialCasStatementsV1({
      linkSessionId: record.linkSessionId,
      expectedRevision: 1,
      nextRecord: record,
      nowMs: 1_000,
    }),
  );
  return { fixture, store, record, database: temporary.database };
}

/** The provisioning record a successful finalize would advance this session to. */
async function provisioningRecordV1(
  fixture: ReturnType<typeof buildR103DeviceLinkFixture>,
  record: Awaited<ReturnType<typeof buildR103AwaitingTargetPasskeySessionRecordV1>>,
  revision: number,
  updatedAtMs: number,
) {
  return await buildR103AwaitingTargetPasskeySessionRecordV1(fixture, {
    revision,
    updatedAtMs,
    state: buildProvisioningLinkedDeviceSessionState({
      linkSessionId: record.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      keyManifestDigestB64u: record.approvalTranscript?.sourceKeyManifestDigestB64u as never,
    }),
  });
}

test('a lost session CAS takes the whole batch down with it', async () => {
  const { fixture, store, record, database } = await seedAwaitingSession();
  // Built against the revision the finalize would have read...
  const statements = store.buildTargetCredentialCasStatementsV1({
    linkSessionId: record.linkSessionId,
    expectedRevision: record.revision,
    nextRecord: await provisioningRecordV1(fixture, record, record.revision + 1, 2_000),
    nowMs: 2_000,
  });
  // ...and then the owner cancels, exactly in the window the fence covers.
  await database.batch(
    store.buildTargetCredentialCasStatementsV1({
      linkSessionId: record.linkSessionId,
      expectedRevision: record.revision,
      nextRecord: await buildR103AwaitingTargetPasskeySessionRecordV1(fixture, {
        revision: record.revision + 1,
        updatedAtMs: 1_500,
        state: buildCancelledClaimedPrecommitLinkedDeviceSessionState({
          linkSessionId: record.linkSessionId,
          walletId: fixture.approval.walletId,
          enrollmentId: fixture.approval.enrollmentId,
          cancelledAtMs: 1_500,
        }),
      }),
      nowMs: 1_500,
    }),
  );

  await expect(
    database.batch([companionWriteStatement(database, 'guard-loses'), ...statements]),
  ).rejects.toThrow();
  // The credential stand-in did not survive: the batch rolled back whole.
  expect(await companionWriteLanded(database, 'guard-loses')).toBe(false);
  // And the cancellation stands, rather than being overwritten by a stale CAS.
  expect((await readSessionRowV1(database, String(record.linkSessionId))).state).toBe(
    'cancelled_claimed_precommit',
  );
});

test('a winning session CAS lets the batch commit', async () => {
  const { fixture, store, record, database } = await seedAwaitingSession();
  // The positive control: nothing moved, so the same shape of batch commits.
  // Without this the failure above could be a guard that rejects everything.
  await database.batch([
    companionWriteStatement(database, 'guard-wins'),
    ...store.buildTargetCredentialCasStatementsV1({
      linkSessionId: record.linkSessionId,
      expectedRevision: record.revision,
      nextRecord: await provisioningRecordV1(fixture, record, record.revision + 1, 2_000),
      nowMs: 2_000,
    }),
  ]);
  expect(await companionWriteLanded(database, 'guard-wins')).toBe(true);
  const persisted = await readSessionRowV1(database, String(record.linkSessionId));
  expect(persisted.state).toBe('provisioning');
  expect(persisted.revision).toBe(record.revision + 1);
});

test('a replayed finalize does not advance the session twice', async () => {
  const { fixture, store, record, database } = await seedAwaitingSession();
  const advance = store.buildTargetCredentialCasStatementsV1({
    linkSessionId: record.linkSessionId,
    expectedRevision: record.revision,
    nextRecord: await provisioningRecordV1(fixture, record, record.revision + 1, 2_000),
    nowMs: 2_000,
  });
  await database.batch([companionWriteStatement(database, 'replay-first'), ...advance]);
  // Replaying the same statements is what the finalize deliberately does not
  // do: the CAS names a revision the session has left, so it would fail the
  // retry's batch against its own completed work.
  await expect(
    database.batch([
      companionWriteStatement(database, 'replay-second'),
      ...store.buildTargetCredentialCasStatementsV1({
        linkSessionId: record.linkSessionId,
        expectedRevision: record.revision,
        nextRecord: await provisioningRecordV1(fixture, record, record.revision + 1, 2_100),
        nowMs: 2_100,
      }),
    ]),
  ).rejects.toThrow();
  expect(await companionWriteLanded(database, 'replay-second')).toBe(false);
  expect((await readSessionRowV1(database, String(record.linkSessionId))).revision).toBe(
    record.revision + 1,
  );
});
