import { expect, test } from '@playwright/test';
import { parseWalletId } from '@shared/utils/domainIds';
import {
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  buildR103ActiveExecutionFixture,
  buildR103DeviceLinkFixture,
  buildR103OwnerApprovalContextV1,
  buildR103OwnerEnrollmentCeremonyReaderV1,
} from './helpers/deviceLinkContracts.fixtures';
import { buildR102ActiveProductEpoch } from './helpers/r102LaneGateway.fixtures';
import {
  LinkedDeviceSessionServiceV1,
  type LinkedDeviceAggregateActivationVerifierV1,
} from '../../packages/wallet-server/src/core/deviceLinking/linkedDeviceSession';
import {
  D1LinkedDeviceManagementStoreV1,
  D1LinkedDeviceCanonicalOwnerAuthMetadataSourceV1,
  D1LinkedDeviceSigningActivitySourceV1,
} from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceManagementStore';
import {
  assertOwnerAuthBindingBatchApplied,
  D1LinkedDeviceOwnerAuthBindingStoreV1,
} from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOwnerAuthBindingStore';
import { parseTenantId } from '../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  D1LinkedDeviceSessionStoreV1,
  type D1LinkedDeviceSessionScopeV1,
} from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSessionStore';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';
import type {
  D1DatabaseLike,
  D1ResultLike,
} from '../../packages/wallet-server/src/storage/tenantRoute';
import { buildLinkedOwnerPasskeyBindingFixtureV1 } from './helpers/linkedOwnerAuthBinding.fixtures';
import {
  insertWalletAuthMethod,
  insertWebAuthn,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import { buildLaneProductEpochActiveV1 } from '../../packages/shared-ts/src/signing-lanes/rotationParsers';

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

// R103C: sessions are workflow history. The list projection enumerates durable
// owner bindings only, so a wallet with claimed, approved, or even corrupt
// session rows and no binding projects an empty device list — and the session
// service is never consulted.
test('ignores session workflow history when projecting a wallet with no owner bindings', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const sessionStore = new D1LinkedDeviceSessionStoreV1({
    database: temporary.database,
    scope,
  });
  const sessionService = new LinkedDeviceSessionServiceV1({
    ownerEnrollmentCeremonies: buildR103OwnerEnrollmentCeremonyReaderV1(fixture.approval),
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
  expect(
    (
      await sessionService.recordOwnerApprovalV1({
        owner: buildR103OwnerApprovalContextV1(approval),
        approval,
        nowMs: 3_002,
      })
    ).outcome,
  ).toBe('applied');

  // A corrupt session for another wallet stays outside this projection query.
  await temporary.database
    .prepare(
      `INSERT INTO linked_device_sessions (
         namespace, org_id, project_id, env_id, link_session_id,
         link_public_key_b64u, device_public_key_b64u, state, record_json,
         revision, expires_at_ms, claim_expires_at_ms, claim_digest_b64u,
         approval_digest_b64u, created_at_ms, updated_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, 1, ?, NULL, NULL, NULL, ?, ?)`,
    )
    .bind(
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      `${String(fixture.payload.linkSessionId)}-other`,
      fixture.payload.linkPublicKeyB64u,
      fixture.payload.devicePublicKeyB64u,
      JSON.stringify({ corrupt: true }),
      20_000,
      3_000,
      3_000,
    )
    .run();

  const projection = new D1LinkedDeviceManagementStoreV1({
    database: temporary.database,
    scope,
    metadata: {
      readLinkedDeviceMetadataV1: async () => null,
      readLinkedDeviceMetadataBatchV1: async () => new Map(),
      listUnlinkedOwnerDeviceSummariesV1: async () => [],
    },
  });

  const result = await projection.listLinkedDevicesV1({
    walletId: parseWalletId('wallet:r103').value,
    limit: 10,
    cursor: null,
  });
  expect(result).toEqual({ devices: [], ownerDevices: [], nextCursor: null });
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

test('omits linked sessions without owner bindings from the management projection', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  let queryCount = 0;
  const countedDatabase: D1DatabaseLike = {
    prepare: (query) => {
      queryCount += 1;
      return temporary!.database.prepare(query);
    },
    batch: async (statements) => {
      queryCount += 1;
      return await temporary!.database.batch(statements);
    },
    exec: async (query) => await temporary!.database.exec(query),
  };
  const fixture = buildR103DeviceLinkFixture();
  const secondFixture = buildR103DeviceLinkFixture({ linkSessionId: 'link-session:r103-second' });
  const sessionStore = new D1LinkedDeviceSessionStoreV1({ database: countedDatabase, scope });
  const sessionService = new LinkedDeviceSessionServiceV1({
    ownerEnrollmentCeremonies: buildR103OwnerEnrollmentCeremonyReaderV1(fixture.approval),
    store: sessionStore,
    authorization: {
      authorizeOwnerClaimV1: async ({ payload: _payload, requestedAtMs }) => ({
        kind: 'authorized' as const,
        identity: {
          walletId: fixture.approval.walletId,
          enrollmentId: fixture.approval.enrollmentId,
          deviceId: fixture.approval.deviceId,
          claimExpiresAtMs: requestedAtMs + 5_000,
        },
      }),
      authorizeOwnerApprovalV1: async () => ({ kind: 'authorized' as const }),
    },
    aggregateActivationVerifier,
  });
  for (const item of [fixture, secondFixture]) {
    await sessionService.createUnclaimedSessionV1({ payload: item.payload, nowMs: 3_000 });
    await sessionService.claimSessionV1({ payload: item.payload, nowMs: 3_001 });
    await sessionService.recordOwnerApprovalV1({
      approval: { ...item.approval, expiresAtMs: 8_000 },
      nowMs: 3_002,
      owner: {
        walletId: item.approval.walletId,
        walletSessionId: parseWalletSessionId('wallet-session:r103').value,
        authorizationId: parseWalletSessionAuthorizationId('authorization:r103').value,
        expiresAtMs: 10_000,
        curve: 'ed25519',
        keyManifestDigestB64u: item.receipt.manifestDigestB64u,
      },
    });
  }
  const firstPage = await sessionService.listSessionsForWalletV1({
    walletId: fixture.approval.walletId,
    nowMs: 10_000,
    limit: 1,
    cursor: null,
  });
  expect(firstPage.records).toHaveLength(1);
  expect(String(firstPage.records[0]?.linkSessionId)).toBe(String(fixture.payload.linkSessionId));
  expect(firstPage.nextCursor).toEqual({
    updatedAtMs: 3_002,
    linkSessionId: fixture.payload.linkSessionId,
  });
  const secondPage = await sessionService.listSessionsForWalletV1({
    walletId: fixture.approval.walletId,
    nowMs: 10_000,
    limit: 1,
    cursor: firstPage.nextCursor,
  });
  expect(secondPage.records).toHaveLength(1);
  expect(String(secondPage.records[0]?.linkSessionId)).toBe(
    String(secondFixture.payload.linkSessionId),
  );
  expect(secondPage.nextCursor).toBeNull();
  queryCount = 0;
  const projection = new D1LinkedDeviceManagementStoreV1({
    database: countedDatabase,
    scope,
    metadata: new D1LinkedDeviceCanonicalOwnerAuthMetadataSourceV1({
      database: countedDatabase,
      scope,
      tenantId: parseTenantId(scope.orgId).value,
    }),
  });
  await expect(
    projection.listLinkedDevicesV1({
      walletId: parseWalletId('wallet:r103').value,
      limit: 10,
      cursor: null,
    }),
  ).resolves.toEqual({ devices: [], ownerDevices: [], nextCursor: null });
  expect(queryCount).toBeLessThanOrEqual(8);
});

test('keeps canonical metadata for bound identities while omitting orphan identities', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const binding = buildLinkedOwnerPasskeyBindingFixtureV1({
    walletId: String(fixture.approval.walletId),
    enrollmentId: String(fixture.approval.enrollmentId),
    deviceId: String(fixture.approval.deviceId),
    rpId: 'wallet.example.test',
    credentialIdB64u: 'credential-r103-bound',
  });
  if (binding.factor.kind !== 'passkey') throw new Error('expected passkey binding');
  await insertWalletAuthMethod({
    database: temporary.database,
    ...scope,
    record: {
      version: 'wallet_auth_method_v1',
      kind: 'passkey',
      status: 'active',
      walletId: String(binding.walletId),
      rpId: String(binding.factor.rpId),
      credentialIdB64u: String(binding.factor.credentialIdB64u),
      credentialPublicKeyB64u: 'credential-public-key',
      counter: 0,
      createdAtMs: binding.createdAtMs,
      updatedAtMs: binding.updatedAtMs,
    },
  });
  await insertWebAuthn({
    database: temporary.database,
    ...scope,
    userId: String(binding.walletId),
    rpId: String(binding.factor.rpId),
    credentialIdB64u: String(binding.factor.credentialIdB64u),
    credentialPublicKeyB64u: 'credential-public-key',
  });
  const bindingStore = new D1LinkedDeviceOwnerAuthBindingStoreV1({
    database: temporary.database,
    scope,
  });
  assertOwnerAuthBindingBatchApplied(
    await temporary.database.batch<D1ResultLike>([bindingStore.buildInsertV1(binding).statement]),
    1,
  );

  const orphan = buildR103DeviceLinkFixture({
    enrollmentId: 'enrollment:r103-orphan',
    deviceId: 'device:r103-orphan',
  });
  const metadata = await new D1LinkedDeviceCanonicalOwnerAuthMetadataSourceV1({
    database: temporary.database,
    scope,
    tenantId: binding.tenantId,
  }).readLinkedDeviceMetadataBatchV1([
    {
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
    },
    {
      walletId: orphan.approval.walletId,
      enrollmentId: orphan.approval.enrollmentId,
      deviceId: orphan.approval.deviceId,
    },
  ]);

  expect(
    metadata.get(
      `${String(fixture.approval.walletId)}\u0000${String(fixture.approval.enrollmentId)}\u0000${String(fixture.approval.deviceId)}`,
    ),
  ).toBeDefined();
  expect(metadata.size).toBe(1);
});

test('lists and retrieves a binding-only device from its verified durable lane records', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const seeded = await seedDurableLinkedDeviceProjection(temporary.database);
  const projection = new D1LinkedDeviceManagementStoreV1({
    database: temporary.database,
    scope,
    metadata: new D1LinkedDeviceCanonicalOwnerAuthMetadataSourceV1({
      database: temporary.database,
      scope,
      tenantId: seeded.binding.tenantId,
    }),
  });

  const listed = await projection.listLinkedDevicesV1({
    walletId: seeded.binding.walletId,
    limit: 1,
    cursor: null,
  });
  expect(listed.devices).toHaveLength(1);
  expect(listed.devices[0]).toMatchObject({
    deviceId: seeded.binding.deviceId,
    enrollmentId: seeded.binding.enrollmentId,
    state: 'active',
    revocationEpoch: 0,
  });
  expect(listed.nextCursor).toBeNull();

  const direct = await projection.getLinkedDeviceV1({
    walletId: seeded.binding.walletId,
    deviceId: seeded.binding.deviceId,
  });
  expect(direct?.summary).toEqual(listed.devices[0]);
  expect(direct?.products).toHaveLength(1);

  await temporary.database
    .prepare(
      `UPDATE lane_enrollments
          SET manifest_digest_b64u = ?1
        WHERE namespace = ?2 AND org_id = ?3 AND project_id = ?4 AND env_id = ?5
          AND enrollment_id = ?6`,
    )
    .bind(
      'tampered-manifest-digest',
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(seeded.binding.enrollmentId),
    )
    .run();
  await expect(
    projection.getLinkedDeviceV1({
      walletId: seeded.binding.walletId,
      deviceId: seeded.binding.deviceId,
    }),
  ).rejects.toThrow('manifest digest disagrees');
});

async function seedDurableLinkedDeviceProjection(database: D1DatabaseLike) {
  const execution = await buildR103ActiveExecutionFixture();
  const manifest = execution.provisioning.deliveries.manifest;
  const manifestDigestB64u = execution.deviceLink.receipt.manifestDigestB64u;
  const job = execution.provisioning.deliveries.orderedChildren[0].job;
  const baseProduct = await buildR102ActiveProductEpoch(job);
  const product = buildLaneProductEpochActiveV1({
    walletId: baseProduct.walletId,
    walletKeyId: baseProduct.walletKeyId,
    laneId: baseProduct.laneId,
    laneKind: baseProduct.laneKind,
    laneShareEpoch: baseProduct.laneShareEpoch,
    keyFamily: baseProduct.keyFamily,
    enrollmentId: baseProduct.enrollmentId,
    operationId: baseProduct.operationId,
    targetMaterialActivationId: baseProduct.targetMaterialActivationId,
    materialActivation: baseProduct.materialActivation,
    publicIdentityDigestB64u: baseProduct.publicIdentityDigestB64u,
    holderParticipant: baseProduct.holderParticipant,
    signingWorkerParticipant: baseProduct.signingWorkerParticipant,
    participantSetBindingDigestB64u: baseProduct.participantSetBindingDigestB64u,
    revocationEpoch: baseProduct.revocationEpoch,
    createdAtMs: baseProduct.createdAtMs,
    aggregateManifestDigestB64u: manifestDigestB64u,
    aggregateActivationReceiptDigestB64u: manifestDigestB64u,
    activatedAtMs: baseProduct.activatedAtMs,
  });
  const binding = buildLinkedOwnerPasskeyBindingFixtureV1({
    walletId: String(execution.deviceLink.approval.walletId),
    enrollmentId: String(execution.deviceLink.approval.enrollmentId),
    deviceId: String(execution.deviceLink.approval.deviceId),
    rpId: 'wallet.example.test',
    credentialIdB64u: 'credential-r103-durable-management',
    keyManifestDigestB64u: String(manifestDigestB64u),
    activatedAtMs: 5_000,
  });
  if (binding.factor.kind !== 'passkey') throw new Error('expected passkey binding');
  await insertWalletAuthMethod({
    database,
    ...scope,
    record: {
      version: 'wallet_auth_method_v1',
      kind: 'passkey',
      status: 'active',
      walletId: String(binding.walletId),
      rpId: String(binding.factor.rpId),
      credentialIdB64u: String(binding.factor.credentialIdB64u),
      credentialPublicKeyB64u: 'credential-public-key',
      counter: 0,
      createdAtMs: binding.createdAtMs,
      updatedAtMs: binding.updatedAtMs,
    },
  });
  await insertWebAuthn({
    database,
    ...scope,
    userId: String(binding.walletId),
    rpId: String(binding.factor.rpId),
    credentialIdB64u: String(binding.factor.credentialIdB64u),
    credentialPublicKeyB64u: 'credential-public-key',
  });
  const bindingStore = new D1LinkedDeviceOwnerAuthBindingStoreV1({ database, scope });
  assertOwnerAuthBindingBatchApplied(
    await database.batch<D1ResultLike>([bindingStore.buildInsertV1(binding).statement]),
    1,
  );
  await database
    .prepare(
      `INSERT INTO lane_enrollments (
         namespace, org_id, project_id, env_id, enrollment_id, wallet_id,
         manifest_digest_b64u, manifest_json, lifecycle_json, version,
         command_digest_b64u, created_at_ms, updated_at_ms
       ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?11, ?12)`,
    )
    .bind(
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(manifest.enrollmentId),
      String(manifest.walletId),
      String(manifestDigestB64u),
      JSON.stringify(manifest),
      JSON.stringify({
        state: 'active',
        manifestDigestB64u,
        aggregateReceiptDigestB64u: manifestDigestB64u,
        activatedAtMs: product.activatedAtMs,
      }),
      String(manifestDigestB64u),
      manifest.createdAtMs,
      product.activatedAtMs,
    )
    .run();
  await database
    .prepare(
      `INSERT INTO lane_product_epochs (
         namespace, org_id, project_id, env_id, wallet_id, wallet_key_id,
         lane_id, lane_share_epoch, enrollment_id, operation_id,
         target_material_activation_id, material_activation_json,
         holder_participant_json, signing_worker_participant_json,
         participant_set_binding_digest_b64u, revocation_epoch, lane_kind,
         key_family, public_identity_digest_b64u, state, product_json,
         version, command_digest_b64u, created_at_ms, updated_at_ms
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
         ?14, ?15, ?16, ?17, ?18, ?19, 'active', ?20, 1, ?21, ?22, ?23
       )`,
    )
    .bind(
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(product.walletId),
      String(product.walletKeyId),
      String(product.laneId),
      String(product.laneShareEpoch),
      String(product.enrollmentId),
      String(product.operationId),
      String(product.targetMaterialActivationId),
      JSON.stringify(product.materialActivation),
      JSON.stringify(product.holderParticipant),
      JSON.stringify(product.signingWorkerParticipant),
      String(product.participantSetBindingDigestB64u),
      product.revocationEpoch,
      product.laneKind,
      product.keyFamily,
      String(product.publicIdentityDigestB64u),
      JSON.stringify(product),
      String(manifestDigestB64u),
      product.createdAtMs,
      product.activatedAtMs,
    )
    .run();
  return { binding };
}
