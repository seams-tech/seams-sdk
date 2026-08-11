import { expect, test } from '@playwright/test';
import { parseWalletId } from '@shared/utils/domainIds';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import {
  LinkedDeviceSessionServiceV1,
  type LinkedDeviceAggregateActivationVerifierV1,
} from '../../packages/sdk-server-ts/src/core/deviceLinking/linkedDeviceSession';
import {
  D1LinkedDeviceManagementStoreV1,
  D1LinkedDeviceSigningActivitySourceV1,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceManagementStore';
import {
  D1LinkedDeviceSessionStoreV1,
  type D1LinkedDeviceSessionScopeV1,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSessionStore';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';

const scope: D1LinkedDeviceSessionScopeV1 = {
  namespace: 'signer',
  orgId: 'org_management_store_test',
  projectId: 'project_management_store_test',
  envId: 'env_management_store_test',
};

let temporary: TemporaryD1Database | undefined;

const aggregateActivationVerifier = {
  verifyAggregateActivationV1: async () => ({ kind: 'verified' as const }),
} satisfies LinkedDeviceAggregateActivationVerifierV1;

test.afterEach(() => {
  if (temporary) cleanupTemporaryD1Database(temporary.tempDir);
  temporary = undefined;
});

test('uses the core session clock before projecting management rows', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const sessionStore = new D1LinkedDeviceSessionStoreV1({
    database: temporary.database,
    scope,
  });
  const sessionService = new LinkedDeviceSessionServiceV1({
    store: sessionStore,
    authorization: {
      authorizeOwnerClaimV1: async () => ({
        kind: 'authorized' as const,
        identity: {
          walletId: fixture.approval.walletId,
          enrollmentId: fixture.approval.enrollmentId,
          deviceId: fixture.approval.deviceId,
          claimExpiresAtMs: 9_000,
        },
      }),
      authorizeOwnerApprovalV1: async () => ({ kind: 'authorized' as const }),
    },
    aggregateActivationVerifier,
  });
  expect(
    (await sessionService.createUnclaimedSessionV1({ payload: fixture.payload, nowMs: 3_000 }))
      .outcome,
  ).toBe('applied');
  expect(
    (await sessionService.claimSessionV1({ payload: fixture.payload, nowMs: 3_001 })).outcome,
  ).toBe('applied');
  const approval = { ...fixture.approval, expiresAtMs: 9_000 };
  expect((await sessionService.recordOwnerApprovalV1({ approval, nowMs: 3_002 })).outcome).toBe(
    'applied',
  );

  const reads: Array<{ readonly linkSessionId: unknown; readonly nowMs: number }> = [];
  const projection = new D1LinkedDeviceManagementStoreV1({
    database: temporary.database,
    scope,
    sessionService: {
      getSessionV1: async (input) => {
        reads.push(input);
        return null;
      },
    },
    nowV1: () => 12_000,
    metadata: {
      readLinkedDeviceMetadataV1: async () => null,
    },
  });

  const result = await projection.listLinkedDevicesV1(parseWalletId('wallet:r103').value);
  expect(result).toEqual([]);
  expect(reads).toHaveLength(1);
  expect(reads[0].nowMs).toBe(12_000);
  expect(String(reads[0].linkSessionId)).toBe(String(fixture.payload.linkSessionId));
});

test('reads only exact scope and device signing activity from authorization audit rows', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const rows = [
    {
      suffix: 'matching',
      grantKind: 'linked_device_wallet_session_authorization_v1',
      projectId: scope.projectId,
      deviceId: fixture.approval.deviceId,
      completedAtMs: 8_000,
    },
    {
      suffix: 'other-device',
      grantKind: 'linked_device_wallet_session_authorization_v1',
      projectId: scope.projectId,
      deviceId: 'device:other',
      completedAtMs: 12_000,
    },
    {
      suffix: 'other-project',
      grantKind: 'linked_device_wallet_session_authorization_v1',
      projectId: 'project:other',
      deviceId: fixture.approval.deviceId,
      completedAtMs: 13_000,
    },
    {
      suffix: 'owner-grant',
      grantKind: 'wallet_session_authorization',
      projectId: scope.projectId,
      deviceId: fixture.approval.deviceId,
      completedAtMs: 14_000,
    },
  ] as const;
  for (const row of rows) {
    await temporary.database
      .prepare(
        `INSERT INTO authorized_operation_audit_events (
           namespace, tenant_id, audit_event_id, authorized_operation_id,
           operation_fingerprint_digest, authorization_source_kind, authorization_id,
           evidence_set_digest, quota_id, material_activation_id, result_kind,
           claimed_at_ms, completed_at_ms, authorization_grant_kind,
           linked_wallet_id, linked_enrollment_id, linked_device_id,
           linked_scope_org_id, linked_scope_project_id, linked_scope_env_id
         ) VALUES (?, ?, ?, ?, ?, 'authorization_grant', ?, NULL, ?, ?, 'succeeded',
                   ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        scope.namespace,
        `tenant:${row.suffix}`,
        `audit:${row.suffix}`,
        `operation:${row.suffix}`,
        `fingerprint:${row.suffix}`,
        `authorization:${row.suffix}`,
        `quota:${row.suffix}`,
        `activation:${row.suffix}`,
        row.completedAtMs - 1_000,
        row.completedAtMs,
        row.grantKind,
        fixture.approval.walletId,
        fixture.approval.enrollmentId,
        row.deviceId,
        scope.orgId,
        row.projectId,
        scope.envId,
      )
      .run();
  }

  const activity = new D1LinkedDeviceSigningActivitySourceV1({
    database: temporary.database,
    scope,
  });
  await expect(
    activity.readLastSigningActivityAtMsV1({
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
    }),
  ).resolves.toBe(8_000);
});
