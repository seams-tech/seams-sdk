import { expect, test } from '@playwright/test';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  readTableColumnNames,
} from '../helpers/sqliteD1';

const TABLE = 'wallet_session_authorizations_v2';

const AUTHORITY_RECORD = JSON.stringify({
  authorityId: 'authority:migration',
  walletId: 'wallet:migration',
  state: 'active',
  revocationEpoch: 0,
  authorityDigestB64u: 'digest:migration',
  signerActivationSetDigestB64u: 'digest:migration',
});

const AUTH_METHOD_RECORD = JSON.stringify({
  version: 'wallet_auth_method_v2',
  walletAuthMethodId: 'auth-method:migration',
  walletId: 'wallet:migration',
  walletAuthorityId: 'authority:migration',
  kind: 'passkey',
  status: 'active',
  createdAtMs: 1,
  updatedAtMs: 2,
  rpId: 'wallet.example.test',
  credentialIdB64u: 'credential:migration',
  credentialPublicKeyB64u: 'public-key:migration',
  counter: 0,
});

function walletSessionAuthorizationRecord(
  authorizationId: string,
  walletSessionId: string,
  quotaId: string,
  capabilitySubjects: readonly unknown[],
  issuedAtMs: number,
  expiresAtMs: number,
): string {
  return JSON.stringify({
    kind: 'wallet_session_authorization_v2',
    tenantId: 'tenant:migration',
    principalId: 'principal:migration',
    walletId: 'wallet:migration',
    authorityId: 'authority:migration',
    walletAuthMethodId: 'auth-method:migration',
    authorityDigestB64u: 'digest:migration',
    authorityRevocationEpoch: 0,
    mintId: `mint:${authorizationId}`,
    authorizationId,
    walletSessionId,
    quotaId,
    capabilitySubjects,
    createdAtMs: issuedAtMs,
    expiresAtMs,
  });
}

async function insertAuthorityAndAuthMethod(
  database: ReturnType<typeof createTemporaryD1Database>['database'],
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO wallet_authorities (
         namespace, org_id, project_id, env_id, authority_id, wallet_id, device_id,
         provenance_kind, enrollment_id, source_authority_id, link_session_id,
         lifecycle_state, permissions_json, signer_activations_json,
         local_install_package_set_digest_b64u, signer_activation_set_digest_b64u,
         authority_digest_b64u, revocation_epoch, record_json, created_at_ms,
         updated_at_ms, activated_at_ms, revoked_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      'namespace:migration',
      'org:migration',
      'project:migration',
      'env:migration',
      'authority:migration',
      'wallet:migration',
      'device:migration',
      'wallet_registration',
      null,
      null,
      null,
      'active',
      '["sign"]',
      '[{}]',
      null,
      'digest:migration',
      'digest:migration',
      0,
      AUTHORITY_RECORD,
      1,
      2,
      2,
      null,
    )
    .run();
  await database
    .prepare(
      `INSERT INTO wallet_auth_methods (
         namespace, org_id, project_id, env_id, wallet_id, wallet_authority_id,
         rp_id, kind, status, wallet_auth_method_id, auth_identifier_key,
         credential_id_b64u, credential_public_key_b64u, email_hash_hex,
         registration_authority_id, record_json, created_at_ms, updated_at_ms,
         activated_at_ms, revoked_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      'namespace:migration',
      'org:migration',
      'project:migration',
      'env:migration',
      'wallet:migration',
      'authority:migration',
      'wallet.example.test',
      'passkey',
      'active',
      'auth-method:migration',
      'credential:migration',
      'credential:migration',
      'public-key:migration',
      null,
      null,
      AUTH_METHOD_RECORD,
      1,
      2,
      2,
      null,
    )
    .run();
}

async function insertQuota(
  database: ReturnType<typeof createTemporaryD1Database>['database'],
  quotaId: string,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO authorization_wallet_session_quotas (
         namespace, tenant_id, quota_id, wallet_session_id, principal_id,
         remaining_uses, lifecycle_kind, expires_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      'namespace:migration',
      'tenant:migration',
      quotaId,
      `session-for-${quotaId}`,
      'principal:migration',
      3,
      'active',
      100,
    )
    .run();
}

async function insertAuthorization(
  database: ReturnType<typeof createTemporaryD1Database>['database'],
  options: {
    readonly authorizationId: string;
    readonly walletSessionId: string;
    readonly quotaId: string;
    readonly capabilitySubjects: readonly unknown[];
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
  },
): Promise<void> {
  const recordJson = walletSessionAuthorizationRecord(
    options.authorizationId,
    options.walletSessionId,
    options.quotaId,
    options.capabilitySubjects,
    options.issuedAtMs,
    options.expiresAtMs,
  );
  await database
    .prepare(
      `INSERT INTO ${TABLE} (
         namespace, org_id, project_id, env_id, tenant_id, authorization_id,
         mint_id, wallet_session_id, quota_id, principal_id, wallet_id,
         authority_id, wallet_auth_method_id, authority_digest_b64u,
         authority_revocation_epoch, capability_subjects_json, issued_at_ms,
         expires_at_ms, retired_at_ms, record_json
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      'namespace:migration',
      'org:migration',
      'project:migration',
      'env:migration',
      'tenant:migration',
      options.authorizationId,
      `mint:${options.authorizationId}`,
      options.walletSessionId,
      options.quotaId,
      'principal:migration',
      'wallet:migration',
      'authority:migration',
      'auth-method:migration',
      'digest:migration',
      0,
      JSON.stringify(options.capabilitySubjects),
      options.issuedAtMs,
      options.expiresAtMs,
      null,
      recordJson,
    )
    .run();
}

test('D1 signer migrations install and constrain Wallet Session authorization V2', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));

    await expect(readTableColumnNames(temporary.database, TABLE)).resolves.toEqual([
      'namespace',
      'org_id',
      'project_id',
      'env_id',
      'tenant_id',
      'authorization_id',
      'mint_id',
      'wallet_session_id',
      'quota_id',
      'principal_id',
      'wallet_id',
      'authority_id',
      'wallet_auth_method_id',
      'authority_digest_b64u',
      'authority_revocation_epoch',
      'capability_subjects_json',
      'issued_at_ms',
      'expires_at_ms',
      'retired_at_ms',
      'operation_credential_hash',
      'record_json',
    ]);

    const indexes = await temporary.database
      .prepare(`PRAGMA index_list(${TABLE})`)
      .all<{ readonly name?: unknown }>();
    expect(indexes.results.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        'wallet_session_authorizations_v2_authority_idx',
        'wallet_session_authorizations_v2_method_idx',
        'wallet_session_authorizations_v2_wallet_idx',
        'wallet_session_authorizations_v2_expiry_idx',
        'wallet_session_authorizations_v2_operation_credential_uidx',
      ]),
    );

    const foreignKeys = await temporary.database
      .prepare(`PRAGMA foreign_key_list(${TABLE})`)
      .all<{ readonly table?: unknown }>();
    expect(new Set(foreignKeys.results.map((row) => row.table))).toEqual(
      new Set([
        'wallet_authorities',
        'wallet_auth_methods',
        'authorization_wallet_session_quotas',
      ]),
    );

    await insertAuthorityAndAuthMethod(temporary.database);
    await insertQuota(temporary.database, 'quota:migration-valid');
    const validSubjects = [{ kind: 'link_devices', authorityId: 'authority:migration' }];
    await insertAuthorization(temporary.database, {
      authorizationId: 'authorization:migration-valid',
      walletSessionId: 'session:migration-valid',
      quotaId: 'quota:migration-valid',
      capabilitySubjects: validSubjects,
      issuedAtMs: 10,
      expiresAtMs: 20,
    });

    await insertQuota(temporary.database, 'quota:migration-empty-subjects');
    await expect(
      insertAuthorization(temporary.database, {
        authorizationId: 'authorization:migration-empty-subjects',
        walletSessionId: 'session:migration-empty-subjects',
        quotaId: 'quota:migration-empty-subjects',
        capabilitySubjects: [],
        issuedAtMs: 10,
        expiresAtMs: 20,
      }),
    ).rejects.toThrow();

    await insertQuota(temporary.database, 'quota:migration-invalid-expiry');
    await expect(
      insertAuthorization(temporary.database, {
        authorizationId: 'authorization:migration-invalid-expiry',
        walletSessionId: 'session:migration-invalid-expiry',
        quotaId: 'quota:migration-invalid-expiry',
        capabilitySubjects: validSubjects,
        issuedAtMs: 20,
        expiresAtMs: 20,
      }),
    ).rejects.toThrow();
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('R103E signer baseline removes retired linked-device projections', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));

    const retiredObjectNames = [
      'wallet_auth_methods_legacy',
      'linked_device_owner_auth_bindings',
      'linked_device_owner_planning_snapshots',
      'linked_device_provisioning_records',
      'linked_device_source_handoffs',
      'linked_device_target_deployment_descriptors',
      'linked_device_wallet_session_authorizations',
      'linked_device_wallet_session_quotas',
      'authorized_operation_linked_grant_claim_atomic',
      'authorized_operation_audit_linked_device_activity_idx',
      'linked_device_wallet_session_authorization_identity_insert',
      'linked_device_wallet_session_authorization_identity_update',
      'linked_device_wallet_session_authorization_revoke_atomic',
      'linked_device_wallet_session_quota_revoke_guard',
    ];
    const retiredObjects = await temporary.database
      .prepare(
        `SELECT type, name FROM sqlite_master
           WHERE name IN (${retiredObjectNames.map(() => '?').join(', ')})
           ORDER BY type, name`,
      )
      .bind(...retiredObjectNames)
      .all<{ readonly type?: unknown; readonly name?: unknown }>();
    expect(retiredObjects.results).toEqual([]);

    const grantShapeGuard = await temporary.database
      .prepare(`SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?`)
      .bind('authorized_operation_grant_shape_guard')
      .first<{ readonly sql?: unknown }>();
    expect(grantShapeGuard?.sql).toEqual(expect.any(String));
    expect(grantShapeGuard?.sql).not.toContain('linked_device_wallet_session_authorization_v1');

    await expect(readTableColumnNames(temporary.database, 'wallet_auth_methods')).resolves.toEqual(
      expect.arrayContaining(['wallet_authority_id', 'wallet_auth_method_id']),
    );

    const retainedBoundaryTables = await temporary.database
      .prepare(
        `SELECT name FROM sqlite_master
           WHERE type = 'table' AND name IN (
             'linked_device_request_proof_nonces',
             'linked_device_session_transcripts',
             'linked_device_sessions',
             'linked_device_target_commit_reservations',
             'linked_device_target_credentials',
             'linked_device_email_otp_grants',
             'linked_device_ed25519_export_root_transfers'
           )
           ORDER BY name`,
      )
      .all<{ readonly name?: unknown }>();
    expect(retainedBoundaryTables.results.map((row) => row.name)).toEqual([
      'linked_device_ed25519_export_root_transfers',
      'linked_device_email_otp_grants',
      'linked_device_request_proof_nonces',
      'linked_device_session_transcripts',
      'linked_device_sessions',
      'linked_device_target_commit_reservations',
      'linked_device_target_credentials',
    ]);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});
