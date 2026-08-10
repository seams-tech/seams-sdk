import { expect, test } from '@playwright/test';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseLinkDeviceSessionId,
} from '@shared/signing-lanes';
import {
  buildAwaitingAggregateReceiptLinkedDeviceSessionState,
  buildLinkedDeviceEnrollmentReceiptV1,
} from '@shared/device-linking/parsers';
import { parseWalletId } from '@shared/utils/domainIds';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import {
  D1LinkedDeviceSessionStoreV1,
  type D1LinkedDeviceSessionScopeV1,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSessionStore';
import {
  LinkedDeviceSessionServiceV1,
  parseLinkedDeviceSessionRecordV1,
  type LinkedDeviceOwnerAuthorizationPortV1,
} from '../../packages/sdk-server-ts/src/core/deviceLinking/linkedDeviceSession';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';

const scope: D1LinkedDeviceSessionScopeV1 = {
  namespace: 'signer',
  orgId: 'org_test',
  projectId: 'project_test',
  envId: 'env_test',
};

const nowMs = 1_800_000_000_000;

let temporary: TemporaryD1Database | undefined;

test.afterEach(() => {
  if (temporary) cleanupTemporaryD1Database(temporary.tempDir);
  temporary = undefined;
});

test('claims exactly once, replays the exact claim, and never writes identity before claim', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const store = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const auth = ownerAuth();
  const service = new LinkedDeviceSessionServiceV1({ store, authorization: auth });
  const payload = qrPayload('session-one');

  const created = await service.createUnclaimedSessionV1({ payload, nowMs });
  expect(created.outcome).toBe('applied');
  if (created.outcome !== 'applied') throw new Error('expected create');
  expect(created.record.state.state).toBe('displaying_qr');
  expect('walletId' in created.record.state).toBe(false);

  const claimed = await service.claimSessionV1({ payload, nowMs: nowMs + 1 });
  expect(claimed.outcome).toBe('applied');
  if (claimed.outcome !== 'applied') throw new Error('expected claim');
  expect(claimed.record.state.state).toBe('claimed_by_owner');

  const replayed = await service.claimSessionV1({ payload, nowMs: nowMs + 1 });
  expect(replayed.outcome).toBe('replayed');
  if (replayed.outcome !== 'replayed') throw new Error('expected replay');
  expect(replayed.record.revision).toBe(claimed.record.revision);
});

test('expires an unclaimed session through the read projection and preserves terminal state', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const store = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const service = new LinkedDeviceSessionServiceV1({ store, authorization: ownerAuth() });
  const payload = { ...qrPayload('session-two'), expiresAtMs: nowMs + 5 };
  await service.createUnclaimedSessionV1({ payload, nowMs });

  const expired = await service.getSessionV1({
    linkSessionId: payload.linkSessionId,
    nowMs: nowMs + 6,
  });
  expect(expired?.state.state).toBe('expired_unclaimed');
  expect(expired?.state).not.toHaveProperty('walletId');
});

test('records owner approval exactly once, rejects a conflicting transcript, and cancels before commit', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const store = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const service = new LinkedDeviceSessionServiceV1({
    store,
    authorization: ownerAuthForFixture(),
  });
  const created = await service.createUnclaimedSessionV1({ payload: fixture.payload, nowMs: 3_000 });
  expect(created.outcome).toBe('applied');
  const claimed = await service.claimSessionV1({ payload: fixture.payload, nowMs: 3_001 });
  expect(claimed.outcome).toBe('applied');
  const approval = { ...fixture.approval, expiresAtMs: 8_000 };
  const approved = await service.recordOwnerApprovalV1({ approval, nowMs: 3_002 });
  expect(approved.outcome).toBe('applied');
  if (approved.outcome !== 'applied') throw new Error('expected approval');
  const replayed = await service.recordOwnerApprovalV1({ approval, nowMs: 3_002 });
  expect(replayed.outcome).toBe('replayed');
  const conflicting = await service.recordOwnerApprovalV1({
    approval: { ...approval, approvedAtMs: 2_001 },
    nowMs: 3_002,
  });
  expect(conflicting.outcome).toBe('conflict');
  const cancelled = await service.cancelSessionV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: approved.record.revision,
    nowMs: 3_003,
  });
  expect(cancelled.outcome).toBe('applied');
  if (cancelled.outcome !== 'applied') throw new Error('expected cancellation');
  expect(cancelled.record.state.state).toBe('cancelled_claimed_precommit');
  const cancelReplay = await service.cancelSessionV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: cancelled.record.revision,
    nowMs: 3_003,
  });
  expect(cancelReplay.outcome).toBe('replayed');
});

test('refuses postcommit cancellation, records completion-required state, and replays aggregate activation', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const store = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const service = new LinkedDeviceSessionServiceV1({ store, authorization: ownerAuthForFixture() });
  await service.createUnclaimedSessionV1({ payload: fixture.payload, nowMs: 3_000 });
  await service.claimSessionV1({ payload: fixture.payload, nowMs: 3_001 });
  const approval = { ...fixture.approval, expiresAtMs: 8_000 };
  const approved = await service.recordOwnerApprovalV1({ approval, nowMs: 3_002 });
  expect(approved.outcome).toBe('applied');
  if (approved.outcome !== 'applied') throw new Error('expected approval');
  const provisioning = parseLinkedDeviceSessionRecordV1({
    ...approved.record,
    state: {
      state: 'provisioning',
      linkSessionId: fixture.payload.linkSessionId,
      walletId: approved.record.state.walletId,
      enrollmentId: approved.record.state.enrollmentId,
      keyManifestDigestB64u: fixture.approval.policyDigestB64u,
    },
    revision: approved.record.revision + 1,
    updatedAtMs: 3_003,
  });
  await overwriteRecord(provisioning);
  const cancelled = await service.cancelSessionV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: provisioning.revision,
    nowMs: 3_004,
  });
  expect(cancelled.outcome).toBe('invalid_state');
  const committed = await service.markCommittedCompletionRequiredV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: provisioning.revision,
    transcriptSetDigestB64u: fixture.approval.policyDigestB64u,
    nowMs: 3_004,
  });
  expect(committed.outcome).toBe('applied');
  if (committed.outcome !== 'applied') throw new Error('expected committed state');
  const committedReplay = await service.markCommittedCompletionRequiredV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: committed.record.revision,
    transcriptSetDigestB64u: fixture.approval.policyDigestB64u,
    nowMs: 3_004,
  });
  expect(committedReplay.outcome).toBe('replayed');

  const awaitingReceipt = parseLinkedDeviceSessionRecordV1({
    ...committed.record,
    state: {
      state: 'awaiting_aggregate_receipt',
      linkSessionId: fixture.payload.linkSessionId,
      walletId: committed.record.state.walletId,
      enrollmentId: committed.record.state.enrollmentId,
      keyManifestDigestB64u: fixture.approval.policyDigestB64u,
    },
    revision: committed.record.revision + 1,
    updatedAtMs: 3_005,
  });
  await overwriteRecord(awaitingReceipt);
  const activated = await service.recordAggregateActivationV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: awaitingReceipt.revision,
    receipt: fixture.receipt,
    nowMs: 3_006,
  });
  expect(activated.outcome).toBe('applied');
  if (activated.outcome !== 'applied') throw new Error('expected activation');
  const activationReplay = await service.recordAggregateActivationV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: activated.record.revision,
    receipt: fixture.receipt,
    nowMs: 3_006,
  });
  expect(activationReplay.outcome).toBe('replayed');
  const postcommitCancel = await service.cancelSessionV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: activated.record.revision,
    nowMs: 3_007,
  });
  expect(postcommitCancel.outcome).toBe('invalid_state');
});

test('rejects aggregate activation unless the approved manifest and child set match exactly', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const store = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const service = new LinkedDeviceSessionServiceV1({ store, authorization: ownerAuthForFixture() });
  await service.createUnclaimedSessionV1({ payload: fixture.payload, nowMs: 3_000 });
  await service.claimSessionV1({ payload: fixture.payload, nowMs: 3_001 });
  const approval = { ...fixture.approval, expiresAtMs: 8_000 };
  const approved = await service.recordOwnerApprovalV1({ approval, nowMs: 3_002 });
  expect(approved.outcome).toBe('applied');
  if (approved.outcome !== 'applied') throw new Error('expected approval');
  const awaitingReceipt = parseLinkedDeviceSessionRecordV1({
    ...approved.record,
    state: buildAwaitingAggregateReceiptLinkedDeviceSessionState({
      linkSessionId: fixture.payload.linkSessionId,
      walletId: approved.record.state.walletId,
      enrollmentId: approved.record.state.enrollmentId,
      keyManifestDigestB64u: fixture.approval.policyDigestB64u,
    }),
    revision: approved.record.revision + 1,
    updatedAtMs: 3_003,
  });
  await overwriteRecord(awaitingReceipt);

  const differentManifestDigest = parseDigestB64u(
    base64UrlEncode(new Uint8Array(32).fill(9)),
  );
  const wrongManifest = buildLinkedDeviceEnrollmentReceiptV1({
    enrollmentId: fixture.receipt.enrollmentId,
    walletId: fixture.receipt.walletId,
    deviceId: fixture.receipt.deviceId,
    manifestDigestB64u: differentManifestDigest,
    aggregateReceiptDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
    orderedChildReceipts: fixture.receipt.orderedChildReceipts,
    activatedAtMs: fixture.receipt.activatedAtMs,
  });
  const manifestResult = await service.recordAggregateActivationV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: awaitingReceipt.revision,
    receipt: wrongManifest,
    nowMs: 3_004,
  });
  expect(manifestResult).toEqual({
    outcome: 'invalid_input',
    message: 'aggregate receipt manifest digest differs from the approved manifest',
  });

  const child = fixture.receipt.orderedChildReceipts[0];
  if (!child) throw new Error('fixture child receipt is missing');
  const wrongFamily = buildLinkedDeviceEnrollmentReceiptV1({
    enrollmentId: fixture.receipt.enrollmentId,
    walletId: fixture.receipt.walletId,
    deviceId: fixture.receipt.deviceId,
    manifestDigestB64u: fixture.receipt.manifestDigestB64u,
    aggregateReceiptDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
    orderedChildReceipts: [
      {
        ...child,
        keyFamily: 'ecdsa_secp256k1',
      },
    ],
    activatedAtMs: fixture.receipt.activatedAtMs,
  });
  const familyResult = await service.recordAggregateActivationV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: awaitingReceipt.revision,
    receipt: wrongFamily,
    nowMs: 3_004,
  });
  expect(familyResult).toEqual({
    outcome: 'invalid_input',
    message: 'aggregate receipt child differs from the approved manifest',
  });

  const duplicateChildren = buildLinkedDeviceEnrollmentReceiptV1({
    enrollmentId: fixture.receipt.enrollmentId,
    walletId: fixture.receipt.walletId,
    deviceId: fixture.receipt.deviceId,
    manifestDigestB64u: fixture.receipt.manifestDigestB64u,
    aggregateReceiptDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
    orderedChildReceipts: [child, child],
    activatedAtMs: fixture.receipt.activatedAtMs,
  });
  const duplicateResult = await service.recordAggregateActivationV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: awaitingReceipt.revision,
    receipt: duplicateChildren,
    nowMs: 3_004,
  });
  expect(duplicateResult).toEqual({
    outcome: 'invalid_input',
    message: 'aggregate receipt contains duplicate child coverage',
  });

  const persisted = await store.getSessionV1(fixture.payload.linkSessionId);
  expect(persisted?.state.state).toBe('awaiting_aggregate_receipt');
});

test('rejects tampered durable record and transcript rows', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const store = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const service = new LinkedDeviceSessionServiceV1({ store, authorization: ownerAuthForFixture() });
  await service.createUnclaimedSessionV1({ payload: fixture.payload, nowMs: 3_000 });
  const claimed = await service.claimSessionV1({ payload: fixture.payload, nowMs: 3_001 });
  expect(claimed.outcome).toBe('applied');
  if (claimed.outcome !== 'applied') throw new Error('expected claim');
  await temporary.database
    .prepare(
      `UPDATE linked_device_sessions
          SET record_json = ?
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ? AND link_session_id = ?`,
    )
    .bind(
      JSON.stringify(tamperClaimDeviceId(claimed.record)),
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(fixture.payload.linkSessionId),
    )
    .run();
  await expect(store.getSessionV1(fixture.payload.linkSessionId)).rejects.toThrow();
  await temporary.database
    .prepare(
      `UPDATE linked_device_sessions
          SET record_json = ?
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ? AND link_session_id = ?`,
    )
    .bind(
      JSON.stringify(claimed.record),
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(fixture.payload.linkSessionId),
    )
    .run();
  await temporary.database
    .prepare(
      `UPDATE linked_device_session_transcripts
          SET transcript_json = ?
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ? AND link_session_id = ?`,
    )
    .bind(
      JSON.stringify({}),
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(fixture.payload.linkSessionId),
    )
    .run();
  await expect(store.getSessionV1(fixture.payload.linkSessionId)).rejects.toThrow();
});

function qrPayload(session: string) {
  const linkSessionId = parseLinkDeviceSessionId(session).value;
  return {
    version: 'v4' as const,
    purpose: 'linked_device_lane_creation' as const,
    linkSessionId,
    linkPublicKeyB64u: 'AQ',
    devicePublicKeyB64u: 'Ag',
    requestedPermission: {
      kind: 'owner_equivalent_signing' as const,
      administrationScope: 'signing_only' as const,
      localUserPresence: 'required' as const,
    },
    issuedAtMs: nowMs - 10,
    expiresAtMs: nowMs + 60_000,
  };
}

function ownerAuth(): LinkedDeviceOwnerAuthorizationPortV1 {
  return {
    authorizeOwnerClaimV1: async () => ({
      kind: 'authorized' as const,
      identity: {
        walletId: parseWalletId('wallet-owner').value,
        enrollmentId: parseLinkedDeviceEnrollmentId('enrollment-one').value,
        deviceId: parseLinkedDeviceId('device-one').value,
        claimExpiresAtMs: nowMs + 30_000,
      },
    }),
    authorizeOwnerApprovalV1: async () => ({ kind: 'authorized' as const }),
  };
}

function ownerAuthForFixture(): LinkedDeviceOwnerAuthorizationPortV1 {
  return {
    authorizeOwnerClaimV1: async () => ({
      kind: 'authorized' as const,
      identity: {
        walletId: parseWalletId('wallet:r103').value,
        enrollmentId: parseLinkedDeviceEnrollmentId('enrollment:r103').value,
        deviceId: parseLinkedDeviceId('device:r103').value,
        claimExpiresAtMs: 9_000,
      },
    }),
    authorizeOwnerApprovalV1: async () => ({ kind: 'authorized' as const }),
  };
}

async function overwriteRecord(record: {
  readonly linkSessionId: string;
  readonly state: { readonly state: string };
  readonly qrPayload: { readonly expiresAtMs: number };
  readonly revision: number;
  readonly claimTranscript?: { readonly value: { readonly claimExpiresAtMs: number }; readonly digestB64u: string };
  readonly approvalTranscript?: { readonly digestB64u: string };
  readonly updatedAtMs: number;
  readonly createdAtMs: number;
}): Promise<void> {
  if (!temporary) throw new Error('temporary database is unavailable');
  await temporary.database
    .prepare(
      `UPDATE linked_device_sessions
          SET state = ?, record_json = ?, revision = ?, expires_at_ms = ?,
              claim_expires_at_ms = ?, claim_digest_b64u = ?, approval_digest_b64u = ?,
              created_at_ms = ?, updated_at_ms = ?
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ? AND link_session_id = ?`,
    )
    .bind(
      record.state.state,
      JSON.stringify(record),
      record.revision,
      record.qrPayload.expiresAtMs,
      record.claimTranscript?.value.claimExpiresAtMs ?? null,
      record.claimTranscript?.digestB64u ?? null,
      record.approvalTranscript?.digestB64u ?? null,
      record.createdAtMs,
      record.updatedAtMs,
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(record.linkSessionId),
    )
    .run();
}

function tamperClaimDeviceId(record: unknown): unknown {
  const copied = JSON.parse(JSON.stringify(record)) as Record<string, unknown>;
  const transcript = copied.claimTranscript;
  if (!isRecord(transcript) || !isRecord(transcript.value)) throw new Error('claim transcript is unavailable');
  transcript.value = { ...transcript.value, deviceId: 'device:tampered' };
  return copied;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
