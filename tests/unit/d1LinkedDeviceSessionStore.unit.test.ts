import { expect, test } from '@playwright/test';
import { buildLinkedDeviceApprovalV1 } from '@shared/device-linking/parsers';
import {
  buildR103EcdsaSourceContributionV1,
  buildR103DeviceLinkFixture,
  buildR103OwnerApprovalContextV1,
  buildR103EcdsaSourceContributionPreparationV1,
} from './helpers/deviceLinkContracts.fixtures';
import {
  D1LinkedDeviceSessionStoreV1,
  type D1LinkedDeviceSessionScopeV1,
} from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSessionStore';
import {
  LinkedDeviceSessionServiceV1,
  type LinkedDeviceOwnerAuthorizationPortV1,
} from '../../packages/wallet-server/src/core/deviceLinking/linkedDeviceSession';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';
import { parseWalletAuthorityId } from '@shared/utils/domainIds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';

const scope: D1LinkedDeviceSessionScopeV1 = {
  namespace: 'signer',
  orgId: 'org_test',
  projectId: 'project_test',
  envId: 'env_test',
};

const nowMs = 3_000;
const authorityId = parseWalletAuthorityId('authority:r103').value;
const alternateAuthorityId = parseWalletAuthorityId('authority:r103-other').value;
const alternatePackageDigestB64u = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(9)));

let temporary: TemporaryD1Database | undefined;

test.afterEach(() => {
  if (temporary) cleanupTemporaryD1Database(temporary.tempDir);
  temporary = undefined;
});

test('signer D1 schema accepts source-contribution state and transcript', async () => {
  temporary = await openDatabase();
  const recordJson = JSON.stringify({ state: { state: 'awaiting_source_contribution' } });

  await temporary.database
    .prepare(
      `INSERT INTO linked_device_sessions (
         namespace, org_id, project_id, env_id, link_session_id,
         link_public_key_b64u, device_public_key_b64u, state, record_json,
         revision, expires_at_ms, created_at_ms, updated_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      'link-session:r103-schema-awaiting-source',
      'link-public',
      'device-public',
      'awaiting_source_contribution',
      recordJson,
      1,
      nowMs + 1_000,
      nowMs,
      nowMs,
    )
    .run();

  const transcriptJson = JSON.stringify({ source: 'contribution' });
  await temporary.database
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
      'link-session:r103-schema-awaiting-source',
      'source_contribution',
      'source-digest',
      transcriptJson,
      nowMs,
    )
    .run();

  const row = await temporary.database
    .prepare(
      `SELECT state, record_json
         FROM linked_device_sessions
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND link_session_id = ?`,
    )
    .bind(
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      'link-session:r103-schema-awaiting-source',
    )
    .first<{ readonly state: string; readonly record_json: string }>();

  expect(row).toEqual({
    state: 'awaiting_source_contribution',
    record_json: recordJson,
  });

  const transcript = await temporary.database
    .prepare(
      `SELECT transcript_kind, transcript_json
         FROM linked_device_session_transcripts
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND link_session_id = ?`,
    )
    .bind(
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      'link-session:r103-schema-awaiting-source',
    )
    .first<{ readonly transcript_kind: string; readonly transcript_json: string }>();

  expect(transcript).toEqual({
    transcript_kind: 'source_contribution',
    transcript_json: transcriptJson,
  });
});

test('persists the canonical linear precommit states and replays exact claim and approval', async () => {
  temporary = await openDatabase();
  const fixture = buildR103DeviceLinkFixture({ linkSessionId: 'link-session:r103-store-linear' });
  const service = buildService(fixture);

  const created = await service.createUnclaimedSessionV1({ payload: fixture.payload, nowMs });
  expect(created.outcome).toBe('applied');
  if (created.outcome !== 'applied') throw new Error('expected displaying_qr');
  expect(created.record.state).toEqual({ state: 'displaying_qr' });

  const claimed = await service.claimSessionV1({
    payload: fixture.payload,
    owner: buildR103OwnerApprovalContextV1(fixture.approval),
    nowMs: nowMs + 1,
  });
  expect(claimed.outcome).toBe('applied');
  if (claimed.outcome !== 'applied') throw new Error('expected claimed');
  expect(claimed.record.state.state).toBe('claimed');
  expect(claimed.record.state.deviceId).toBe(fixture.approval.deviceId);

  const claimReplay = await service.claimSessionV1({
    payload: fixture.payload,
    owner: buildR103OwnerApprovalContextV1(fixture.approval),
    nowMs: nowMs + 1,
  });
  expect(claimReplay.outcome).toBe('replayed');

  const approval = { ...fixture.approval, expiresAtMs: nowMs + 5_000 };
  const approved = await service.recordOwnerApprovalV1({
    owner: buildR103OwnerApprovalContextV1(approval),
    approval,
    nowMs: nowMs + 2,
  });
  expect(approved.outcome).toBe('applied');
  if (approved.outcome !== 'applied') throw new Error('expected awaiting_target_factor');
  expect(approved.record.state.state).toBe('awaiting_target_factor');

  const approvalReplay = await service.recordOwnerApprovalV1({
    owner: buildR103OwnerApprovalContextV1(approval),
    approval,
    nowMs: nowMs + 2,
  });
  expect(approvalReplay.outcome).toBe('replayed');

  const provisioning = await service.recordTargetCredentialV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: approved.record.revision,
    sourceContributionPreparation: buildR103EcdsaSourceContributionPreparationV1(fixture),
    nowMs: nowMs + 3,
  });
  expect(provisioning.outcome).toBe('applied');
  if (provisioning.outcome !== 'applied') throw new Error('expected source contribution wait');
  expect(provisioning.record.state.state).toBe('awaiting_source_contribution');

  const persisted = await service.getSessionV1({
    linkSessionId: fixture.payload.linkSessionId,
    nowMs: nowMs + 3,
  });
  expect(persisted?.state.state).toBe('awaiting_source_contribution');
});

test('commits one authority/package identity, rejects mismatches, and resumes to active', async () => {
  temporary = await openDatabase();
  const fixture = buildR103DeviceLinkFixture({ linkSessionId: 'link-session:r103-store-commit' });
  const service = buildService(fixture);

  const provisioning = await reachProvisioning(service, fixture);
  const pending = await service.markAuthorityPendingLocalInstallV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: provisioning.revision,
    authorityId,
    packageSetDigestB64u: fixture.packageSetDigestB64u,
    nowMs: nowMs + 4,
  });
  expect(pending.outcome).toBe('applied');
  if (pending.outcome !== 'applied') throw new Error('expected pending authority');
  expect(pending.record.state).toEqual({
    state: 'authority_pending_local_install',
    deviceId: pending.record.state.deviceId,
    authorityId,
    packageSetDigestB64u: fixture.packageSetDigestB64u,
  });

  const pendingReplay = await service.markAuthorityPendingLocalInstallV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: pending.record.revision,
    authorityId,
    packageSetDigestB64u: fixture.packageSetDigestB64u,
    nowMs: nowMs + 4,
  });
  expect(pendingReplay.outcome).toBe('replayed');

  const authorityMismatch = await service.markAuthorityPendingLocalInstallV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: pending.record.revision,
    authorityId: alternateAuthorityId,
    packageSetDigestB64u: fixture.packageSetDigestB64u,
    nowMs: nowMs + 4,
  });
  expect(authorityMismatch).toMatchObject({
    outcome: 'integrity_error',
    reason: 'authority_id_mismatch',
  });

  const packageMismatch = await service.activateSessionV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: pending.record.revision,
    authorityId,
    packageSetDigestB64u: alternatePackageDigestB64u,
    activatedAtMs: nowMs + 5,
    nowMs: nowMs + 5,
  });
  expect(packageMismatch).toMatchObject({
    outcome: 'integrity_error',
    reason: 'package_set_digest_mismatch',
  });

  const cancelled = await service.cancelSessionV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: pending.record.revision,
    nowMs: nowMs + 5,
  });
  expect(cancelled.outcome).toBe('invalid_state');
  const expired = await service.expireSessionV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: pending.record.revision,
    nowMs: nowMs + 5,
  });
  expect(expired.outcome).toBe('invalid_state');

  const active = await service.activateSessionV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: pending.record.revision,
    authorityId,
    packageSetDigestB64u: fixture.packageSetDigestB64u,
    activatedAtMs: nowMs + 5,
    nowMs: nowMs + 5,
  });
  expect(active.outcome).toBe('applied');
  if (active.outcome !== 'applied') throw new Error('expected active');
  expect(active.record.state.state).toBe('active');
  expect(active.record.packageSetDigestB64u).toBe(fixture.packageSetDigestB64u);

  const activeReplay = await service.activateSessionV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: active.record.revision,
    authorityId,
    packageSetDigestB64u: fixture.packageSetDigestB64u,
    activatedAtMs: nowMs + 5,
    nowMs: nowMs + 5,
  });
  expect(activeReplay.outcome).toBe('replayed');

  const row = await temporary.database
    .prepare(
      `SELECT authority_id, package_set_digest_b64u, state
         FROM linked_device_sessions
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND link_session_id = ?`,
    )
    .bind(
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(fixture.payload.linkSessionId),
    )
    .first<{ authority_id?: unknown; package_set_digest_b64u?: unknown; state?: unknown }>();
  expect(row).toEqual({
    authority_id: String(authorityId),
    package_set_digest_b64u: fixture.packageSetDigestB64u,
    state: 'active',
  });

  const deleted = await service.deleteActiveSessionV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: active.record.revision,
    authorityId,
    packageSetDigestB64u: fixture.packageSetDigestB64u,
    nowMs: nowMs + 6,
  });
  expect(deleted).toEqual({ outcome: 'deleted', record: null });
  await expect(
    service.getSessionV1({ linkSessionId: fixture.payload.linkSessionId, nowMs: nowMs + 6 }),
  ).resolves.toBeNull();
});

test('expires precommit records and rejects tampered durable identity', async () => {
  temporary = await openDatabase();
  const fixture = buildR103DeviceLinkFixture({ linkSessionId: 'link-session:r103-store-expiry' });
  const service = buildService(fixture);
  const created = await service.createUnclaimedSessionV1({
    payload: { ...fixture.payload, expiresAtMs: nowMs + 2 },
    nowMs,
  });
  expect(created.outcome).toBe('applied');

  const expired = await service.getSessionV1({
    linkSessionId: fixture.payload.linkSessionId,
    nowMs: nowMs + 3,
  });
  expect(expired?.state).toEqual({ state: 'expired', expiredAtMs: nowMs + 3 });

  await temporary.database
    .prepare(
      `UPDATE linked_device_sessions
          SET record_json = json_set(record_json, '$.qrPayload.linkSessionId', 'link-session:tampered')
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND link_session_id = ?`,
    )
    .bind(
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(fixture.payload.linkSessionId),
    )
    .run();
  await expect(
    service.getSessionV1({ linkSessionId: fixture.payload.linkSessionId, nowMs }),
  ).rejects.toThrow();
});

async function openDatabase(): Promise<TemporaryD1Database> {
  const database = createTemporaryD1Database();
  await applyD1MigrationFiles(database.database, listD1MigrationFiles('d1-signer'));
  return database;
}

function buildService(
  fixture: ReturnType<typeof buildR103DeviceLinkFixture>,
): LinkedDeviceSessionServiceV1 {
  return new LinkedDeviceSessionServiceV1({
    store: new D1LinkedDeviceSessionStoreV1({ database: temporary!.database, scope }),
    authorization: ownerAuthorization(fixture),
  });
}

async function reachProvisioning(
  service: LinkedDeviceSessionServiceV1,
  fixture: ReturnType<typeof buildR103DeviceLinkFixture>,
): Promise<
  Extract<
    Awaited<ReturnType<LinkedDeviceSessionServiceV1['recordSourceContributionV1']>>,
    { readonly outcome: 'applied' }
  >['record']
> {
  await service.createUnclaimedSessionV1({ payload: fixture.payload, nowMs });
  await service.claimSessionV1({
    payload: fixture.payload,
    owner: buildR103OwnerApprovalContextV1(fixture.approval),
    nowMs: nowMs + 1,
  });
  const approval = { ...fixture.approval, expiresAtMs: nowMs + 5_000 };
  const approved = await service.recordOwnerApprovalV1({
    owner: buildR103OwnerApprovalContextV1(approval),
    approval,
    nowMs: nowMs + 2,
  });
  if (approved.outcome !== 'applied') throw new Error('expected approval');
  const awaitingSourceContribution = await service.recordTargetCredentialV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: approved.record.revision,
    sourceContributionPreparation: buildR103EcdsaSourceContributionPreparationV1(fixture),
    nowMs: nowMs + 3,
  });
  if (awaitingSourceContribution.outcome !== 'applied') {
    throw new Error('expected source contribution wait');
  }
  const sourceContributionApproval = buildLinkedDeviceApprovalV1({
    ...approval,
    sourceContribution: [buildR103EcdsaSourceContributionV1(fixture)],
  });
  const provisioning = await service.recordSourceContributionV1({
    approval: sourceContributionApproval,
    owner: buildR103OwnerApprovalContextV1(sourceContributionApproval),
    nowMs: nowMs + 4,
  });
  if (provisioning.outcome !== 'applied') throw new Error('expected provisioning');
  return provisioning.record;
}

function ownerAuthorization(
  fixture: ReturnType<typeof buildR103DeviceLinkFixture>,
): LinkedDeviceOwnerAuthorizationPortV1 {
  return {
    authorizeOwnerClaimV1: async () => ({
      kind: 'authorized' as const,
      identity: {
        walletId: fixture.approval.walletId,
        enrollmentId: fixture.approval.enrollmentId,
        deviceId: fixture.approval.deviceId,
        claimExpiresAtMs: nowMs + 7_000,
      },
    }),
    authorizeOwnerApprovalV1: async () => ({
      kind: 'authorized' as const,
      sourceKeyManifestDigestsB64u: { ed25519: fixture.packageSetDigestB64u },
    }),
  };
}
