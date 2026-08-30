import { basename } from 'node:path';
import { expect, test } from '@playwright/test';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  readTableColumnNames,
} from '../helpers/sqliteD1';

const SCOPE = {
  namespace: 'namespace:migration',
  orgId: 'org:migration',
  projectId: 'project:migration',
  envId: 'env:migration',
  tenantId: 'tenant:migration',
} as const;

const AUTHORITY_ID = 'authority:migration';
const WALLET_ID = 'wallet:migration';
const AUTH_METHOD_ID = 'auth-method:migration';
const PRINCIPAL_ID = 'principal:migration';

const AUTHORITY_RECORD = JSON.stringify({
  authorityId: AUTHORITY_ID,
  walletId: WALLET_ID,
  state: 'active',
  revocationEpoch: 0,
  authorityDigestB64u: 'digest:migration',
  signerActivationSetDigestB64u: 'digest:migration',
});

function authMethodRecord(walletAuthMethodId: string, credentialIdB64u: string): string {
  return JSON.stringify({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId,
    walletId: WALLET_ID,
    walletAuthorityId: AUTHORITY_ID,
    kind: 'passkey',
    status: 'active',
    createdAtMs: 1,
    updatedAtMs: 2,
    rpId: 'wallet.example.test',
    credentialIdB64u,
    credentialPublicKeyB64u: `public-key:${credentialIdB64u}`,
    counter: 0,
  });
}

type Database = ReturnType<typeof createTemporaryD1Database>['database'];

function migrationPrefix(): readonly string[] {
  const files = listD1MigrationFiles('d1-signer');
  const bridgeIndex = files.findIndex((file) => basename(file).startsWith('0028_'));
  if (bridgeIndex < 0) throw new Error('R103F Phase 1 bridge migration is missing');
  return files.slice(0, bridgeIndex);
}

function migrationFilesThroughBridge(): readonly string[] {
  const files = listD1MigrationFiles('d1-signer');
  const bridgeIndex = files.findIndex((file) => basename(file).startsWith('0028_'));
  if (bridgeIndex < 0) throw new Error('R103F Phase 1 bridge migration is missing');
  return files.slice(0, bridgeIndex + 1);
}

async function insertAuthorityAndAuthMethod(database: Database): Promise<void> {
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
      SCOPE.namespace,
      SCOPE.orgId,
      SCOPE.projectId,
      SCOPE.envId,
      AUTHORITY_ID,
      WALLET_ID,
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
  await insertAuthMethod(database, AUTH_METHOD_ID, 'credential:migration');
}

async function insertAuthMethod(
  database: Database,
  walletAuthMethodId: string,
  credentialIdB64u: string,
): Promise<void> {
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
      SCOPE.namespace,
      SCOPE.orgId,
      SCOPE.projectId,
      SCOPE.envId,
      WALLET_ID,
      AUTHORITY_ID,
      'wallet.example.test',
      'passkey',
      'active',
      walletAuthMethodId,
      credentialIdB64u,
      credentialIdB64u,
      `public-key:${credentialIdB64u}`,
      null,
      null,
      authMethodRecord(walletAuthMethodId, credentialIdB64u),
      1,
      2,
      2,
      null,
    )
    .run();
}

async function insertQuota(
  database: Database,
  quotaId: string,
  walletSessionId: string,
  expiresAtMs = 100,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO authorization_wallet_session_quotas (
         namespace, tenant_id, quota_id, wallet_session_id, principal_id,
         remaining_uses, lifecycle_kind, expires_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      SCOPE.namespace,
      SCOPE.tenantId,
      quotaId,
      walletSessionId,
      PRINCIPAL_ID,
      3,
      'active',
      expiresAtMs,
    )
    .run();
}

function authorizationRecordJson(input: {
  readonly authorizationId: string;
  readonly walletSessionId: string;
  readonly quotaId: string;
  readonly walletAuthMethodId: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}): string {
  return JSON.stringify({
    kind: 'wallet_session_authorization_v2',
    tenantId: SCOPE.tenantId,
    principalId: PRINCIPAL_ID,
    walletId: WALLET_ID,
    authorityId: AUTHORITY_ID,
    walletAuthMethodId: input.walletAuthMethodId,
    authorityDigestB64u: 'digest:migration',
    authorityRevocationEpoch: 0,
    mintId: `mint:${input.authorizationId}`,
    authorizationId: input.authorizationId,
    walletSessionId: input.walletSessionId,
    quotaId: input.quotaId,
    capabilitySubjects: [{ kind: 'link_devices', authorityId: AUTHORITY_ID }],
    createdAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
  });
}

async function insertAuthorization(
  database: Database,
  input: {
    readonly authorizationId: string;
    readonly walletSessionId: string;
    readonly quotaId: string;
    readonly walletAuthMethodId: string;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
    readonly operationCredentialHash: string | null;
  },
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO wallet_session_authorizations_v2 (
         namespace, org_id, project_id, env_id, tenant_id, authorization_id,
         mint_id, wallet_session_id, quota_id, principal_id, wallet_id,
         authority_id, wallet_auth_method_id, authority_digest_b64u,
         authority_revocation_epoch, capability_subjects_json, issued_at_ms,
         expires_at_ms, retired_at_ms, record_json, operation_credential_hash
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      SCOPE.namespace,
      SCOPE.orgId,
      SCOPE.projectId,
      SCOPE.envId,
      SCOPE.tenantId,
      input.authorizationId,
      `mint:${input.authorizationId}`,
      input.walletSessionId,
      input.quotaId,
      PRINCIPAL_ID,
      WALLET_ID,
      AUTHORITY_ID,
      input.walletAuthMethodId,
      'digest:migration',
      0,
      '[{"kind":"link_devices","authorityId":"authority:migration"}]',
      input.issuedAtMs,
      input.expiresAtMs,
      null,
      authorizationRecordJson(input),
      input.operationCredentialHash,
    )
    .run();
}

async function insertV1Session(database: Database): Promise<void> {
  await insertQuota(database, 'quota:v1', 'session:v1');
  await database
    .prepare(
      `INSERT INTO reusable_wallet_sessions (
         namespace, tenant_id, wallet_session_id, principal_id, wallet_id,
         authority_digest, mint_id, quota_id, lifecycle_kind, created_at_ms,
         expires_at_ms, authorization_id, wallet_auth_method_id
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      SCOPE.namespace,
      SCOPE.tenantId,
      'session:v1',
      PRINCIPAL_ID,
      WALLET_ID,
      'digest:migration',
      'mint:v1',
      'quota:v1',
      'active',
      1,
      100,
      'authorization:v1',
      AUTH_METHOD_ID,
    )
    .run();
}

async function insertClaim(
  database: Database,
  input: {
    readonly operationId: string;
    readonly authorizationId: string;
    readonly quotaId: string | null;
    readonly quotaKind: 'consume_reusable_wallet_session' | 'quota_neutral';
    readonly linkedScope: readonly [string | null, string | null, string | null];
    readonly claimedAtMs: number;
  },
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO authorized_operations (
         namespace, tenant_id, authorized_operation_id, audit_event_id,
         principal_id, capability_id, capability_kind, operation_kind,
         operation_id, operation_fingerprint_digest, lane_digest, intent_digest,
         display_digest, authorization_source_kind, authorization_id,
         evidence_set_digest, quota_id, quota_kind, lifecycle_kind, result_kind,
         result_digest, result_status, result_content_type, result_body_text,
         claimed_at_ms, completed_at_ms, authorization_grant_kind,
         linked_scope_org_id, linked_scope_project_id, linked_scope_env_id
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      SCOPE.namespace,
      SCOPE.tenantId,
      input.operationId,
      `audit:${input.operationId}`,
      PRINCIPAL_ID,
      `capability:${input.operationId}`,
      'near_ed25519_mpc_signing',
      'near.sign_transaction',
      `operation:${input.operationId}`,
      `fingerprint:${input.operationId}`,
      `lane:${input.operationId}`,
      `intent:${input.operationId}`,
      `display:${input.operationId}`,
      'authorization_grant',
      input.authorizationId,
      null,
      input.quotaId,
      input.quotaKind,
      'claimed',
      'pending',
      null,
      null,
      null,
      null,
      input.claimedAtMs,
      null,
      'wallet_session_authorization',
      ...input.linkedScope,
    )
    .run();
}

async function installAllocationFixture(database: Database): Promise<void> {
  await database.exec(`
    CREATE TABLE linked_device_authority_allocations (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      link_session_id TEXT NOT NULL,
      authority_id TEXT NOT NULL,
      wallet_id TEXT NOT NULL,
      enrollment_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
      UNIQUE (namespace, org_id, project_id, env_id, authority_id),
      CHECK (created_at_ms >= 0)
    );
  `);
}

async function readForeignKeyTables(
  database: Database,
  tableName: string,
): Promise<readonly string[]> {
  const rows = await database
    .prepare(`PRAGMA foreign_key_list(${tableName})`)
    .all<{ readonly id?: unknown; readonly table?: unknown }>();
  const byId = new Map<number, string>();
  for (const row of rows.results) {
    const id = Number(row.id);
    if (Number.isInteger(id) && typeof row.table === 'string') byId.set(id, row.table);
  }
  return [...byId.entries()].sort(([left], [right]) => left - right).map(([, table]) => table);
}

async function readForeignKeyColumns(
  database: Database,
  tableName: string,
  id: number,
): Promise<readonly (readonly [string, string])[]> {
  const rows = await database.prepare(`PRAGMA foreign_key_list(${tableName})`).all<{
    readonly id?: unknown;
    readonly seq?: unknown;
    readonly from?: unknown;
    readonly to?: unknown;
  }>();
  return rows.results
    .filter((row) => Number(row.id) === id)
    .sort((left, right) => Number(left.seq) - Number(right.seq))
    .map((row) => [String(row.from), String(row.to)] as const);
}

async function readRequiredIndexes(
  database: Database,
  tableName: string,
): Promise<readonly string[]> {
  const rows = await database
    .prepare(`PRAGMA index_list(${tableName})`)
    .all<{ readonly name?: unknown }>();
  return rows.results.flatMap((row) => (typeof row.name === 'string' ? [row.name] : []));
}

test('R103F Phase 1 applies cleanly and after every immutable signer migration', async () => {
  const clean = createTemporaryD1Database();
  const historical = createTemporaryD1Database();
  try {
    const files = listD1MigrationFiles('d1-signer');
    const bridge = files.find((file) => basename(file).startsWith('0028_'));
    if (!bridge) throw new Error('R103F Phase 1 bridge migration is missing');
    const prefix = migrationPrefix();
    const deliveryRecipientMigration = files.find((file) =>
      basename(file).startsWith('0033_'),
    );
    if (!deliveryRecipientMigration) throw new Error('R103F delivery recipient migration is missing');

    await applyD1MigrationFiles(clean.database, files);

    await applyD1MigrationFiles(historical.database, prefix);
    await insertAuthorityAndAuthMethod(historical.database);
    const historicalExpiry = Date.now() + 60_000;
    await insertQuota(
      historical.database,
      'quota:historical',
      'session:historical',
      historicalExpiry,
    );
    await insertAuthorization(historical.database, {
      authorizationId: 'authorization:historical',
      walletSessionId: 'session:historical',
      quotaId: 'quota:historical',
      walletAuthMethodId: AUTH_METHOD_ID,
      issuedAtMs: Date.now() - 1_000,
      expiresAtMs: historicalExpiry,
      operationCredentialHash: 'credential:historical',
    });
    await installAllocationFixture(historical.database);
    await applyD1MigrationFiles(historical.database, [bridge]);
    await applyD1MigrationFiles(historical.database, [deliveryRecipientMigration]);

    for (const tableName of [
      'wallet_session_hosted_credentials_v2',
      'wallet_session_hosted_exchange_codes_v2',
      'linked_device_wallet_session_credential_deliveries_v1',
      'linked_device_authority_allocations',
      'linked_device_authority_installations',
    ]) {
      await expect(readTableColumnNames(historical.database, tableName)).resolves.toEqual(
        await readTableColumnNames(clean.database, tableName),
      );
    }
    await expect(
      historical.database
        .prepare(
          `SELECT COUNT(*) AS row_count FROM wallet_session_authorizations_v2
             WHERE authorization_id = 'authorization:historical'`,
        )
        .first<{ readonly row_count?: unknown }>(),
    ).resolves.toMatchObject({ row_count: 1 });

    await expect(
      readForeignKeyTables(clean.database, 'wallet_session_hosted_credentials_v2'),
    ).resolves.toEqual(['wallet_session_authorizations_v2']);
    await expect(
      readForeignKeyTables(clean.database, 'wallet_session_hosted_exchange_codes_v2'),
    ).resolves.toEqual([
      'wallet_session_hosted_credentials_v2',
      'wallet_session_authorizations_v2',
    ]);
    await expect(
      readForeignKeyTables(clean.database, 'linked_device_wallet_session_credential_deliveries_v1'),
    ).resolves.toEqual([
      'wallet_session_authorizations_v2',
      'linked_device_authority_installations',
    ]);
    await expect(
      readForeignKeyColumns(clean.database, 'wallet_session_hosted_credentials_v2', 0),
    ).resolves.toEqual([
      ['namespace', 'namespace'],
      ['org_id', 'org_id'],
      ['project_id', 'project_id'],
      ['env_id', 'env_id'],
      ['tenant_id', 'tenant_id'],
      ['authorization_id', 'authorization_id'],
      ['wallet_session_id', 'wallet_session_id'],
      ['quota_id', 'quota_id'],
      ['principal_id', 'principal_id'],
      ['wallet_id', 'wallet_id'],
      ['authority_id', 'authority_id'],
      ['wallet_auth_method_id', 'wallet_auth_method_id'],
    ]);
    await expect(
      readForeignKeyColumns(clean.database, 'wallet_session_hosted_exchange_codes_v2', 0),
    ).resolves.toEqual([
      ['namespace', 'namespace'],
      ['org_id', 'org_id'],
      ['project_id', 'project_id'],
      ['env_id', 'env_id'],
      ['tenant_id', 'tenant_id'],
      ['hosted_credential_id', 'hosted_credential_id'],
      ['authorization_id', 'authorization_id'],
      ['wallet_session_id', 'wallet_session_id'],
      ['quota_id', 'quota_id'],
      ['principal_id', 'principal_id'],
      ['wallet_id', 'wallet_id'],
      ['authority_id', 'authority_id'],
      ['wallet_auth_method_id', 'wallet_auth_method_id'],
    ]);
    await expect(
      readRequiredIndexes(clean.database, 'wallet_session_hosted_credentials_v2'),
    ).resolves.toEqual(
      expect.arrayContaining([
        'wallet_session_hosted_credentials_v2_parent_idx',
        'wallet_session_hosted_credentials_v2_expiry_idx',
        'wallet_session_hosted_credentials_v2_exact_identity_uidx',
      ]),
    );
    await expect(
      readRequiredIndexes(clean.database, 'linked_device_authority_allocations'),
    ).resolves.toEqual(
      expect.arrayContaining(['linked_device_authority_allocations_authority_idx']),
    );

    for (const database of [clean.database, historical.database]) {
      await expect(database.prepare('PRAGMA foreign_key_check').all()).resolves.toMatchObject({
        results: [],
      });
    }
  } finally {
    cleanupTemporaryD1Database(clean.tempDir);
    cleanupTemporaryD1Database(historical.tempDir);
  }
});

test('R103F bridge trigger admits V1/V2 claims and rejects partial scope', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, migrationFilesThroughBridge());
    await insertAuthorityAndAuthMethod(temporary.database);
    await insertV1Session(temporary.database);
    await insertClaim(temporary.database, {
      operationId: 'operation:v1',
      authorizationId: 'authorization:v1',
      quotaId: 'quota:v1',
      quotaKind: 'consume_reusable_wallet_session',
      linkedScope: [null, null, null],
      claimedAtMs: 10,
    });
    await expect(
      temporary.database
        .prepare(
          `SELECT remaining_uses FROM authorization_wallet_session_quotas
             WHERE quota_id = 'quota:v1'`,
        )
        .first<{ readonly remaining_uses?: unknown }>(),
    ).resolves.toMatchObject({ remaining_uses: 2 });

    await insertQuota(temporary.database, 'quota:v2', 'session:v2', 100);
    await insertAuthorization(temporary.database, {
      authorizationId: 'authorization:v2',
      walletSessionId: 'session:v2',
      quotaId: 'quota:v2',
      walletAuthMethodId: AUTH_METHOD_ID,
      issuedAtMs: 1,
      expiresAtMs: 100,
      operationCredentialHash: 'credential:v2',
    });
    await insertClaim(temporary.database, {
      operationId: 'operation:v2',
      authorizationId: 'authorization:v2',
      quotaId: 'quota:v2',
      quotaKind: 'consume_reusable_wallet_session',
      linkedScope: [SCOPE.orgId, SCOPE.projectId, SCOPE.envId],
      claimedAtMs: 10,
    });
    await expect(
      temporary.database
        .prepare(
          `SELECT remaining_uses FROM authorization_wallet_session_quotas
             WHERE quota_id = 'quota:v2'`,
        )
        .first<{ readonly remaining_uses?: unknown }>(),
    ).resolves.toMatchObject({ remaining_uses: 2 });

    await expect(
      insertClaim(temporary.database, {
        operationId: 'operation:partial',
        authorizationId: 'authorization:v2',
        quotaId: 'quota:v2',
        quotaKind: 'consume_reusable_wallet_session',
        linkedScope: [SCOPE.orgId, null, SCOPE.envId],
        claimedAtMs: 10,
      }),
    ).rejects.toThrow(/authorization_grant_kind_rejected/u);
    await expect(
      temporary.database
        .prepare(
          `SELECT COUNT(*) AS row_count FROM authorized_operations WHERE authorized_operation_id = 'operation:partial'`,
        )
        .first<{ readonly row_count?: unknown }>(),
    ).resolves.toMatchObject({ row_count: 0 });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('R103F exact trigger admits only fully scoped V2 claims', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
    await insertAuthorityAndAuthMethod(temporary.database);
    await insertQuota(temporary.database, 'quota:exact', 'session:exact', 100);
    await insertAuthorization(temporary.database, {
      authorizationId: 'authorization:exact',
      walletSessionId: 'session:exact',
      quotaId: 'quota:exact',
      walletAuthMethodId: AUTH_METHOD_ID,
      issuedAtMs: 1,
      expiresAtMs: 100,
      operationCredentialHash: 'credential:exact',
    });

    await insertClaim(temporary.database, {
      operationId: 'operation:exact',
      authorizationId: 'authorization:exact',
      quotaId: 'quota:exact',
      quotaKind: 'consume_reusable_wallet_session',
      linkedScope: [SCOPE.orgId, SCOPE.projectId, SCOPE.envId],
      claimedAtMs: 10,
    });
    await expect(
      temporary.database
        .prepare(
          `SELECT remaining_uses FROM authorization_wallet_session_quotas
             WHERE quota_id = 'quota:exact'`,
        )
        .first<{ readonly remaining_uses?: unknown }>(),
    ).resolves.toMatchObject({ remaining_uses: 2 });

    await expect(insertV1Session(temporary.database)).rejects.toThrow(
      /no such table: reusable_wallet_sessions/u,
    );
    await expect(
      insertClaim(temporary.database, {
        operationId: 'operation:v1-fallback',
        authorizationId: 'authorization:v1',
        quotaId: 'quota:v1',
        quotaKind: 'consume_reusable_wallet_session',
        linkedScope: [null, null, null],
        claimedAtMs: 10,
      }),
    ).rejects.toThrow(/authorization_grant_kind_rejected/u);

    await expect(
      insertClaim(temporary.database, {
        operationId: 'operation:partial',
        authorizationId: 'authorization:exact',
        quotaId: 'quota:exact',
        quotaKind: 'consume_reusable_wallet_session',
        linkedScope: [SCOPE.orgId, null, SCOPE.envId],
        claimedAtMs: 10,
      }),
    ).rejects.toThrow(/authorization_grant_kind_rejected/u);

    await expect(
      insertClaim(temporary.database, {
        operationId: 'operation:scope-mismatch',
        authorizationId: 'authorization:exact',
        quotaId: 'quota:exact',
        quotaKind: 'consume_reusable_wallet_session',
        linkedScope: ['org:other', SCOPE.projectId, SCOPE.envId],
        claimedAtMs: 10,
      }),
    ).rejects.toThrow(/authorization_wallet_session_rejected/u);

    await expect(
      insertClaim(temporary.database, {
        operationId: 'operation:quota-mismatch',
        authorizationId: 'authorization:exact',
        quotaId: 'quota:other',
        quotaKind: 'consume_reusable_wallet_session',
        linkedScope: [SCOPE.orgId, SCOPE.projectId, SCOPE.envId],
        claimedAtMs: 10,
      }),
    ).rejects.toThrow(/authorization_wallet_session_rejected/u);

    await expect(
      temporary.database
        .prepare(`SELECT COUNT(*) AS row_count FROM authorized_operations`)
        .first<{ readonly row_count?: unknown }>(),
    ).resolves.toMatchObject({ row_count: 1 });
    await expect(
      temporary.database
        .prepare(
          `SELECT COUNT(*) AS row_count FROM authorized_operations
            WHERE authorized_operation_id = 'operation:v1-fallback'`,
        )
        .first<{ readonly row_count?: unknown }>(),
    ).resolves.toMatchObject({ row_count: 0 });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('R103F child and delivery rows retain exact parent identity and acknowledgement tombstone', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
    await insertAuthorityAndAuthMethod(temporary.database);
    await insertQuota(temporary.database, 'quota:child-a', 'session:child-a', 100);
    await insertAuthorization(temporary.database, {
      authorizationId: 'authorization:child-a',
      walletSessionId: 'session:child-a',
      quotaId: 'quota:child-a',
      walletAuthMethodId: AUTH_METHOD_ID,
      issuedAtMs: 1,
      expiresAtMs: 100,
      operationCredentialHash: 'credential:child-a',
    });
    const siblingAuthMethodId = 'auth-method:migration-sibling';
    await insertAuthMethod(temporary.database, siblingAuthMethodId, 'credential:migration-sibling');
    await insertQuota(temporary.database, 'quota:child-b', 'session:child-b', 100);
    await insertAuthorization(temporary.database, {
      authorizationId: 'authorization:child-b',
      walletSessionId: 'session:child-b',
      quotaId: 'quota:child-b',
      walletAuthMethodId: siblingAuthMethodId,
      issuedAtMs: 1,
      expiresAtMs: 100,
      operationCredentialHash: 'credential:child-b',
    });
    await expect(
      temporary.database
        .prepare(
          `INSERT INTO wallet_session_hosted_credentials_v2 (
           namespace, org_id, project_id, env_id, tenant_id, hosted_credential_id,
           authorization_id, wallet_session_id, quota_id, principal_id, wallet_id,
           authority_id, wallet_auth_method_id, credential_digest_b64u, app_origin,
           wallet_origin, issued_at_ms, expires_at_ms, lifecycle_kind, retired_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          SCOPE.namespace,
          SCOPE.orgId,
          SCOPE.projectId,
          SCOPE.envId,
          SCOPE.tenantId,
          'hosted:direct-retired',
          'authorization:child-a',
          'session:child-a',
          'quota:child-a',
          PRINCIPAL_ID,
          WALLET_ID,
          AUTHORITY_ID,
          AUTH_METHOD_ID,
          'digest:direct-retired',
          'https://app.example.test',
          'https://wallet.example.test',
          10,
          90,
          'retired',
          20,
        )
        .run(),
    ).rejects.toThrow(/hosted_credential_initial_state_rejected/u);
    await temporary.database
      .prepare(
        `INSERT INTO wallet_session_hosted_credentials_v2 (
         namespace, org_id, project_id, env_id, tenant_id, hosted_credential_id,
         authorization_id, wallet_session_id, quota_id, principal_id, wallet_id,
         authority_id, wallet_auth_method_id, credential_digest_b64u, app_origin,
         wallet_origin, issued_at_ms, expires_at_ms, lifecycle_kind, retired_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        SCOPE.namespace,
        SCOPE.orgId,
        SCOPE.projectId,
        SCOPE.envId,
        SCOPE.tenantId,
        'hosted:child-a',
        'authorization:child-a',
        'session:child-a',
        'quota:child-a',
        PRINCIPAL_ID,
        WALLET_ID,
        AUTHORITY_ID,
        AUTH_METHOD_ID,
        'digest:child-a',
        'https://app.example.test',
        'https://wallet.example.test',
        10,
        90,
        'active',
        null,
      )
      .run();
    await expect(
      temporary.database
        .prepare(
          `UPDATE wallet_session_hosted_credentials_v2
            SET app_origin = 'https://other.example.test'
          WHERE hosted_credential_id = 'hosted:child-a'`,
        )
        .run(),
    ).rejects.toThrow(/hosted_credential_identity_rejected/u);
    await expect(
      temporary.database
        .prepare(
          `INSERT INTO wallet_session_hosted_exchange_codes_v2 (
           namespace, org_id, project_id, env_id, tenant_id, exchange_code_id,
           authorization_id, wallet_session_id, quota_id, principal_id, wallet_id,
           authority_id, wallet_auth_method_id, code_hash, nonce_digest, app_origin,
           wallet_origin, issued_at_ms, expires_at_ms, lifecycle_kind,
           hosted_credential_id, consumed_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          SCOPE.namespace,
          SCOPE.orgId,
          SCOPE.projectId,
          SCOPE.envId,
          SCOPE.tenantId,
          'exchange:direct-consumed',
          'authorization:child-a',
          'session:child-a',
          'quota:child-a',
          PRINCIPAL_ID,
          WALLET_ID,
          AUTHORITY_ID,
          AUTH_METHOD_ID,
          'code:direct-consumed',
          'nonce:direct-consumed',
          'https://app.example.test',
          'https://wallet.example.test',
          10,
          90,
          'consumed',
          'hosted:child-a',
          20,
        )
        .run(),
    ).rejects.toThrow(/hosted_exchange_initial_state_rejected/u);
    await temporary.database
      .prepare(
        `INSERT INTO wallet_session_hosted_exchange_codes_v2 (
         namespace, org_id, project_id, env_id, tenant_id, exchange_code_id,
         authorization_id, wallet_session_id, quota_id, principal_id, wallet_id,
         authority_id, wallet_auth_method_id, code_hash, nonce_digest, app_origin,
         wallet_origin, issued_at_ms, expires_at_ms, lifecycle_kind,
         hosted_credential_id, consumed_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        SCOPE.namespace,
        SCOPE.orgId,
        SCOPE.projectId,
        SCOPE.envId,
        SCOPE.tenantId,
        'exchange:valid',
        'authorization:child-a',
        'session:child-a',
        'quota:child-a',
        PRINCIPAL_ID,
        WALLET_ID,
        AUTHORITY_ID,
        AUTH_METHOD_ID,
        'code:valid',
        'nonce:valid',
        'https://app.example.test',
        'https://wallet.example.test',
        10,
        90,
        'issued',
        null,
        null,
      )
      .run();
    await temporary.database
      .prepare(
        `UPDATE wallet_session_hosted_exchange_codes_v2
          SET lifecycle_kind = 'consumed', hosted_credential_id = 'hosted:child-a', consumed_at_ms = 20
        WHERE exchange_code_id = 'exchange:valid'`,
      )
      .run();
    await expect(
      temporary.database
        .prepare(
          `UPDATE wallet_session_hosted_exchange_codes_v2
            SET lifecycle_kind = 'issued', hosted_credential_id = NULL, consumed_at_ms = NULL
          WHERE exchange_code_id = 'exchange:valid'`,
        )
        .run(),
    ).rejects.toThrow(/hosted_exchange_transition_rejected/u);
    await expect(
      temporary.database
        .prepare(
          `UPDATE wallet_session_hosted_exchange_codes_v2
            SET code_hash = 'code:rewritten'
          WHERE exchange_code_id = 'exchange:valid'`,
        )
        .run(),
    ).rejects.toThrow(/hosted_exchange_identity_rejected/u);

    await expect(
      temporary.database.exec(`
        PRAGMA foreign_keys = ON;
        INSERT INTO wallet_session_hosted_exchange_codes_v2 (
          namespace, org_id, project_id, env_id, tenant_id, exchange_code_id,
          authorization_id, wallet_session_id, quota_id, principal_id, wallet_id,
          authority_id, wallet_auth_method_id, code_hash, nonce_digest, app_origin,
          wallet_origin, issued_at_ms, expires_at_ms, lifecycle_kind,
          hosted_credential_id, consumed_at_ms
        ) VALUES (
          '${SCOPE.namespace}', '${SCOPE.orgId}', '${SCOPE.projectId}', '${SCOPE.envId}',
          '${SCOPE.tenantId}', 'exchange:cross-parent', 'authorization:child-b',
          'session:child-b', 'quota:child-b', '${PRINCIPAL_ID}', '${WALLET_ID}',
          '${AUTHORITY_ID}', '${AUTH_METHOD_ID}', 'code:cross-parent', 'nonce:cross-parent',
          'https://app.example.test', 'https://wallet.example.test', 10, 90, 'consumed',
          'hosted:child-a', 20
        );
      `),
    ).rejects.toThrow();

    await temporary.database
      .prepare(
        `INSERT INTO wallet_session_hosted_exchange_codes_v2 (
         namespace, org_id, project_id, env_id, tenant_id, exchange_code_id,
         authorization_id, wallet_session_id, quota_id, principal_id, wallet_id,
         authority_id, wallet_auth_method_id, code_hash, nonce_digest, app_origin,
         wallet_origin, issued_at_ms, expires_at_ms, lifecycle_kind,
         hosted_credential_id, consumed_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        SCOPE.namespace,
        SCOPE.orgId,
        SCOPE.projectId,
        SCOPE.envId,
        SCOPE.tenantId,
        'exchange:update',
        'authorization:child-a',
        'session:child-a',
        'quota:child-a',
        PRINCIPAL_ID,
        WALLET_ID,
        AUTHORITY_ID,
        AUTH_METHOD_ID,
        'code:update',
        'nonce:update',
        'https://app.example.test',
        'https://wallet.example.test',
        10,
        90,
        'issued',
        null,
        null,
      )
      .run();

    await temporary.database
      .prepare(
        `INSERT INTO linked_device_authority_installations (
         namespace, org_id, project_id, env_id, link_session_id, authority_id,
         wallet_id, auth_method_id, device_id, package_set_digest_b64u,
         target_factor_verification_digest_b64u, target_factor_verified_at_ms,
         source_manifest_digest_b64u, packages_json, server_reservation_ids_json,
         installed_record_set_digest_b64u, activated_at_ms, created_at_ms, updated_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        SCOPE.namespace,
        SCOPE.orgId,
        SCOPE.projectId,
        SCOPE.envId,
        'link:delivery',
        AUTHORITY_ID,
        WALLET_ID,
        AUTH_METHOD_ID,
        'device:migration',
        'digest:package-set',
        'digest:target-factor',
        5,
        'digest:source-manifest',
        '{}',
        '[]',
        null,
        null,
        1,
        2,
      )
      .run();

    const deliveryValues = [
      SCOPE.namespace,
      SCOPE.orgId,
      SCOPE.projectId,
      SCOPE.envId,
      'link:delivery',
      SCOPE.tenantId,
      'authorization:child-a',
      'session:child-a',
      'quota:child-a',
      PRINCIPAL_ID,
      AUTHORITY_ID,
      WALLET_ID,
      AUTH_METHOD_ID,
      'digest:delivery',
      'p256_ecdh',
      'public:recipient',
      'digest:recipient',
      'p256-ecdh-aes256gcm-v1',
      'digest:aad',
      '{"ciphertext":"sealed"}',
      'digest:sealed',
      'digest:receipt',
      10,
      90,
      'issued',
      null,
      null,
      'pending',
      null,
      null,
      null,
      null,
      null,
    ];
    const directAcknowledgedValues = [...deliveryValues];
    directAcknowledgedValues[19] = null;
    directAcknowledgedValues[24] = 'acknowledged';
    directAcknowledgedValues[25] = 20;
    directAcknowledgedValues[26] = '{"ack":true}';
    directAcknowledgedValues[28] = '{"cleanup":true}';
    directAcknowledgedValues[30] = 'digest:recipient';
    directAcknowledgedValues[31] = 'digest:package-set';
    directAcknowledgedValues[32] = 80;
    await expect(
      temporary.database
        .prepare(
          `INSERT INTO linked_device_wallet_session_credential_deliveries_v1 (
           namespace, org_id, project_id, env_id, link_session_id, tenant_id,
           authorization_id, wallet_session_id, quota_id, principal_id, authority_id,
           wallet_id, wallet_auth_method_id, credential_digest_b64u, recipient_kind,
           recipient_public_key_b64u, recipient_binding_digest_b64u, envelope_alg,
           aad_digest_b64u, sealed_envelope_json, sealed_envelope_digest_b64u,
           installation_receipt_digest_b64u, issued_at_ms, expires_at_ms, lifecycle_kind,
           acknowledged_at_ms, acknowledgement_receipt_json, cleanup_state,
           cleanup_receipt_json, cleanup_completed_at_ms, acknowledgement_auth_binding_digest_b64u,
           acknowledgement_auth_package_set_digest_b64u, acknowledgement_auth_expires_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(...directAcknowledgedValues)
        .run(),
    ).rejects.toThrow(/delivery_initial_state_rejected/u);
    await temporary.database
      .prepare(
        `INSERT INTO linked_device_wallet_session_credential_deliveries_v1 (
         namespace, org_id, project_id, env_id, link_session_id, tenant_id,
         authorization_id, wallet_session_id, quota_id, principal_id, authority_id,
         wallet_id, wallet_auth_method_id, credential_digest_b64u, recipient_kind,
         recipient_public_key_b64u, recipient_binding_digest_b64u, envelope_alg,
         aad_digest_b64u, sealed_envelope_json, sealed_envelope_digest_b64u,
         installation_receipt_digest_b64u, issued_at_ms, expires_at_ms, lifecycle_kind,
         acknowledged_at_ms, acknowledgement_receipt_json, cleanup_state,
         cleanup_receipt_json, cleanup_completed_at_ms, acknowledgement_auth_binding_digest_b64u,
         acknowledgement_auth_package_set_digest_b64u, acknowledgement_auth_expires_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(...deliveryValues)
      .run();

    await expect(
      temporary.database
        .prepare(
          `INSERT INTO linked_device_wallet_session_credential_deliveries_v1 (
           namespace, org_id, project_id, env_id, link_session_id, tenant_id,
           authorization_id, wallet_session_id, quota_id, principal_id, authority_id,
           wallet_id, wallet_auth_method_id, credential_digest_b64u, recipient_kind,
           recipient_public_key_b64u, recipient_binding_digest_b64u, envelope_alg,
           aad_digest_b64u, sealed_envelope_json, sealed_envelope_digest_b64u,
           installation_receipt_digest_b64u, issued_at_ms, expires_at_ms, lifecycle_kind,
           cleanup_state
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          ...deliveryValues.slice(0, 19),
          null,
          'digest:sealed-invalid',
          'digest:receipt-invalid',
          10,
          90,
          'issued',
          null,
          'pending',
        )
        .run(),
    ).rejects.toThrow();

    await temporary.database
      .prepare(
        `UPDATE linked_device_wallet_session_credential_deliveries_v1
          SET lifecycle_kind = 'acknowledged', sealed_envelope_json = NULL,
              acknowledged_at_ms = 20, acknowledgement_receipt_json = '{"ack":true}',
              cleanup_state = 'pending', cleanup_receipt_json = '{"cleanup":true}',
              acknowledgement_auth_binding_digest_b64u = 'digest:recipient',
              acknowledgement_auth_package_set_digest_b64u = 'digest:package-set',
              acknowledgement_auth_expires_at_ms = 80
        WHERE link_session_id = 'link:delivery'`,
      )
      .run();
    await temporary.database
      .prepare(
        `UPDATE linked_device_wallet_session_credential_deliveries_v1
          SET cleanup_state = 'allocation_removed'
        WHERE link_session_id = 'link:delivery'`,
      )
      .run();
    await temporary.database
      .prepare(
        `UPDATE linked_device_wallet_session_credential_deliveries_v1
          SET cleanup_state = 'session_removed'
        WHERE link_session_id = 'link:delivery'`,
      )
      .run();
    await expect(
      temporary.database
        .prepare(
          `UPDATE linked_device_wallet_session_credential_deliveries_v1
            SET cleanup_state = 'pending'
          WHERE link_session_id = 'link:delivery'`,
        )
        .run(),
    ).rejects.toThrow(/delivery_transition_rejected/u);
    await expect(
      temporary.database
        .prepare(
          `SELECT lifecycle_kind, sealed_envelope_json, acknowledgement_auth_expires_at_ms FROM linked_device_wallet_session_credential_deliveries_v1`,
        )
        .first(),
    ).resolves.toMatchObject({
      lifecycle_kind: 'acknowledged',
      sealed_envelope_json: null,
      acknowledgement_auth_expires_at_ms: 80,
    });
    await expect(
      temporary.database
        .prepare(
          `UPDATE linked_device_wallet_session_credential_deliveries_v1
            SET cleanup_receipt_json = '{"rewritten":true}'
          WHERE link_session_id = 'link:delivery'`,
        )
        .run(),
    ).rejects.toThrow(/cleanup_receipt_rejected/u);
    await expect(
      temporary.database
        .prepare(
          `UPDATE linked_device_wallet_session_credential_deliveries_v1
            SET credential_digest_b64u = 'digest:rewritten'
          WHERE link_session_id = 'link:delivery'`,
        )
        .run(),
    ).rejects.toThrow(/delivery_identity_rejected/u);
    await expect(
      temporary.database
        .prepare(
          `UPDATE linked_device_wallet_session_credential_deliveries_v1
            SET acknowledgement_auth_package_set_digest_b64u = 'digest:rewritten-package'
          WHERE link_session_id = 'link:delivery'`,
        )
        .run(),
    ).rejects.toThrow(/delivery_acknowledgement_rejected/u);
    await temporary.database
      .prepare(
        `UPDATE linked_device_wallet_session_credential_deliveries_v1
          SET lifecycle_kind = 'cleanup_complete', cleanup_state = 'complete',
              cleanup_completed_at_ms = 30
        WHERE link_session_id = 'link:delivery'`,
      )
      .run();
    await expect(
      temporary.database
        .prepare(
          `UPDATE linked_device_wallet_session_credential_deliveries_v1
            SET cleanup_completed_at_ms = 40
          WHERE link_session_id = 'link:delivery'`,
        )
        .run(),
    ).rejects.toThrow(/cleanup_completion_rejected/u);
    await temporary.database
      .prepare(
        `UPDATE wallet_session_hosted_credentials_v2
          SET lifecycle_kind = 'retired', retired_at_ms = 30
        WHERE hosted_credential_id = 'hosted:child-a'`,
      )
      .run();
    await expect(
      temporary.database
        .prepare(
          `UPDATE wallet_session_hosted_credentials_v2
            SET lifecycle_kind = 'active', retired_at_ms = NULL
          WHERE hosted_credential_id = 'hosted:child-a'`,
        )
        .run(),
    ).rejects.toThrow(/hosted_credential_(?:transition|retirement)_rejected/u);
    await temporary.database
      .prepare(
        `UPDATE wallet_session_authorizations_v2
          SET retired_at_ms = 30
        WHERE authorization_id = 'authorization:child-a'`,
      )
      .run();
    await expect(
      temporary.database
        .prepare(
          `UPDATE wallet_session_hosted_exchange_codes_v2
            SET lifecycle_kind = 'consumed', hosted_credential_id = 'hosted:child-a', consumed_at_ms = 20
          WHERE exchange_code_id = 'exchange:update'`,
        )
        .run(),
    ).rejects.toThrow(/hosted_exchange_(?:parent|child)_rejected/u);
    await expect(
      temporary.database.prepare('PRAGMA foreign_key_check').all(),
    ).resolves.toMatchObject({ results: [] });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('R103F delivery migration permits successor acknowledgement after delivery expiry', async () => {
  const temporary = createTemporaryD1Database();
  try {
    const files = listD1MigrationFiles('d1-signer');
    const cutoverIndex = files.findIndex((file) => basename(file).startsWith('0034_'));
    const acknowledgementWindowMigration = files.find((file) => basename(file).startsWith('0035_'));
    if (cutoverIndex < 0 || !acknowledgementWindowMigration) {
      throw new Error('R103F acknowledgement cleanup migration is missing');
    }

    await applyD1MigrationFiles(temporary.database, files.slice(0, cutoverIndex + 1));
    await insertAuthorityAndAuthMethod(temporary.database);
    await insertQuota(
      temporary.database,
      'quota:expired-delivery',
      'session:expired-delivery',
      100,
    );
    await insertAuthorization(temporary.database, {
      authorizationId: 'authorization:expired-delivery',
      walletSessionId: 'session:expired-delivery',
      quotaId: 'quota:expired-delivery',
      walletAuthMethodId: AUTH_METHOD_ID,
      issuedAtMs: 10,
      expiresAtMs: 100,
      operationCredentialHash: 'credential:expired-delivery',
    });
    await temporary.database
      .prepare(
        `INSERT INTO linked_device_authority_installations (
           namespace, org_id, project_id, env_id, link_session_id, authority_id,
           wallet_id, auth_method_id, device_id, package_set_digest_b64u,
           target_factor_verification_digest_b64u, target_factor_verified_at_ms,
           source_manifest_digest_b64u, packages_json, server_reservation_ids_json,
           installed_record_set_digest_b64u, activated_at_ms, created_at_ms, updated_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        SCOPE.namespace,
        SCOPE.orgId,
        SCOPE.projectId,
        SCOPE.envId,
        'link:expired-delivery',
        AUTHORITY_ID,
        WALLET_ID,
        AUTH_METHOD_ID,
        'device:migration',
        'digest:package-set',
        'digest:target-factor',
        5,
        'digest:source-manifest',
        '{}',
        '[]',
        null,
        null,
        1,
        2,
      )
      .run();

    const deliveryValues = [
      SCOPE.namespace,
      SCOPE.orgId,
      SCOPE.projectId,
      SCOPE.envId,
      'link:expired-delivery',
      SCOPE.tenantId,
      'authorization:expired-delivery',
      'session:expired-delivery',
      'quota:expired-delivery',
      PRINCIPAL_ID,
      AUTHORITY_ID,
      WALLET_ID,
      AUTH_METHOD_ID,
      'digest:expired-delivery',
      'p256_ecdh',
      'public:recipient',
      'digest:recipient',
      'p256-ecdh-aes256gcm-v1',
      'digest:aad',
      '{"ciphertext":"sealed"}',
      'digest:sealed',
      'digest:receipt',
      10,
      90,
      'issued',
      null,
      null,
      'pending',
      null,
      null,
      null,
      null,
      null,
    ];
    await temporary.database
      .prepare(
        `INSERT INTO linked_device_wallet_session_credential_deliveries_v1 (
           namespace, org_id, project_id, env_id, link_session_id, tenant_id,
           authorization_id, wallet_session_id, quota_id, principal_id, authority_id,
           wallet_id, wallet_auth_method_id, credential_digest_b64u, recipient_kind,
           recipient_public_key_b64u, recipient_binding_digest_b64u, envelope_alg,
           aad_digest_b64u, sealed_envelope_json, sealed_envelope_digest_b64u,
           installation_receipt_digest_b64u, issued_at_ms, expires_at_ms, lifecycle_kind,
           acknowledged_at_ms, acknowledgement_receipt_json, cleanup_state,
           cleanup_receipt_json, cleanup_completed_at_ms, acknowledgement_auth_binding_digest_b64u,
           acknowledgement_auth_package_set_digest_b64u, acknowledgement_auth_expires_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(...deliveryValues)
      .run();

    const successorAcknowledgement = temporary.database
      .prepare(
        `UPDATE linked_device_wallet_session_credential_deliveries_v1
            SET lifecycle_kind = 'acknowledged', sealed_envelope_json = NULL,
                acknowledged_at_ms = 100, acknowledgement_receipt_json = '{"ack":true}',
                cleanup_state = 'pending', cleanup_receipt_json = '{"cleanup":true}',
                acknowledgement_auth_binding_digest_b64u = 'digest:recipient',
                acknowledgement_auth_package_set_digest_b64u = 'digest:package-set',
                acknowledgement_auth_expires_at_ms = 400
          WHERE link_session_id = 'link:expired-delivery'`,
      )
      .run();
    await expect(successorAcknowledgement).rejects.toThrow(/constraint failed/u);

    await applyD1MigrationFiles(temporary.database, [acknowledgementWindowMigration]);
    await expect(
      temporary.database
        .prepare(
          `SELECT COUNT(*) AS row_count
             FROM linked_device_wallet_session_credential_deliveries_v1
            WHERE link_session_id = 'link:expired-delivery'`,
        )
        .first(),
    ).resolves.toMatchObject({ row_count: 1 });
    await expect(
      temporary.database
        .prepare(
          `SELECT name FROM sqlite_master
             WHERE type = 'trigger'
               AND name LIKE 'linked_device_wallet_session_credential_delivery_%'
             ORDER BY name`,
        )
        .all(),
    ).resolves.toMatchObject({
      results: expect.arrayContaining([
        { name: 'linked_device_wallet_session_credential_delivery_acknowledgement_guard' },
        { name: 'linked_device_wallet_session_credential_delivery_cleanup_completion_guard' },
        { name: 'linked_device_wallet_session_credential_delivery_cleanup_receipt_guard' },
        { name: 'linked_device_wallet_session_credential_delivery_envelope_guard' },
        { name: 'linked_device_wallet_session_credential_delivery_identity_guard' },
        { name: 'linked_device_wallet_session_credential_delivery_insert_lifecycle_guard' },
        { name: 'linked_device_wallet_session_credential_delivery_lifecycle_guard' },
        { name: 'linked_device_wallet_session_credential_delivery_parent_guard' },
      ]),
    });
    await expect(
      readRequiredIndexes(
        temporary.database,
        'linked_device_wallet_session_credential_deliveries_v1',
      ),
    ).resolves.toEqual(
      expect.arrayContaining([
        'linked_device_wallet_session_credential_deliveries_v1_lifecycle_idx',
        'linked_device_wallet_session_credential_deliveries_v1_parent_idx',
      ]),
    );

    await temporary.database
      .prepare(
        `UPDATE linked_device_wallet_session_credential_deliveries_v1
            SET lifecycle_kind = 'acknowledged', sealed_envelope_json = NULL,
                acknowledged_at_ms = 100, acknowledgement_receipt_json = '{"ack":true}',
                cleanup_state = 'pending', cleanup_receipt_json = '{"cleanup":true}',
                acknowledgement_auth_binding_digest_b64u = 'digest:recipient',
                acknowledgement_auth_package_set_digest_b64u = 'digest:package-set',
                acknowledgement_auth_expires_at_ms = 400
          WHERE link_session_id = 'link:expired-delivery'`,
      )
      .run();
    await temporary.database
      .prepare(
        `UPDATE linked_device_wallet_session_credential_deliveries_v1
            SET cleanup_state = 'allocation_removed'
          WHERE link_session_id = 'link:expired-delivery'`,
      )
      .run();
    await temporary.database
      .prepare(
        `UPDATE linked_device_wallet_session_credential_deliveries_v1
            SET cleanup_state = 'session_removed'
          WHERE link_session_id = 'link:expired-delivery'`,
      )
      .run();
    await temporary.database
      .prepare(
        `UPDATE linked_device_wallet_session_credential_deliveries_v1
            SET lifecycle_kind = 'cleanup_complete', cleanup_state = 'complete',
                cleanup_completed_at_ms = 110
          WHERE link_session_id = 'link:expired-delivery'`,
      )
      .run();
    await expect(
      temporary.database
        .prepare(
          `SELECT lifecycle_kind, acknowledged_at_ms, acknowledgement_auth_expires_at_ms,
                  cleanup_state, cleanup_completed_at_ms
             FROM linked_device_wallet_session_credential_deliveries_v1
            WHERE link_session_id = 'link:expired-delivery'`,
        )
        .first(),
    ).resolves.toMatchObject({
      lifecycle_kind: 'cleanup_complete',
      acknowledged_at_ms: 100,
      acknowledgement_auth_expires_at_ms: 400,
      cleanup_state: 'complete',
      cleanup_completed_at_ms: 110,
    });
    await expect(
      temporary.database
        .prepare(
          `UPDATE linked_device_wallet_session_credential_deliveries_v1
              SET authority_id = 'authority:rewritten'
            WHERE link_session_id = 'link:expired-delivery'`,
        )
        .run(),
    ).rejects.toThrow(/delivery_identity_rejected/u);
    await expect(
      temporary.database.prepare('PRAGMA foreign_key_check').all(),
    ).resolves.toMatchObject({
      results: [],
    });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('R103F bridge retires unusable V2 rows and aborts duplicate usable tuples', async () => {
  const cleanup = createTemporaryD1Database();
  const duplicates = createTemporaryD1Database();
  try {
    const prefix = migrationPrefix();
    const bridge = listD1MigrationFiles('d1-signer').find((file) =>
      basename(file).startsWith('0028_'),
    );
    if (!bridge) throw new Error('R103F Phase 1 bridge migration is missing');

    await applyD1MigrationFiles(cleanup.database, prefix);
    await insertAuthorityAndAuthMethod(cleanup.database);
    const nowMs = Date.now();
    await insertQuota(
      cleanup.database,
      'quota:null-credential',
      'session:null-credential',
      nowMs + 60_000,
    );
    await insertAuthorization(cleanup.database, {
      authorizationId: 'authorization:null-credential',
      walletSessionId: 'session:null-credential',
      quotaId: 'quota:null-credential',
      walletAuthMethodId: AUTH_METHOD_ID,
      issuedAtMs: nowMs,
      expiresAtMs: nowMs + 60_000,
      operationCredentialHash: null,
    });
    await insertQuota(cleanup.database, 'quota:expired', 'session:expired', nowMs + 60_000);
    await insertAuthorization(cleanup.database, {
      authorizationId: 'authorization:expired',
      walletSessionId: 'session:expired',
      quotaId: 'quota:expired',
      walletAuthMethodId: AUTH_METHOD_ID,
      issuedAtMs: nowMs - 2_000,
      expiresAtMs: nowMs - 1_000,
      operationCredentialHash: 'credential:expired',
    });
    await applyD1MigrationFiles(cleanup.database, [bridge]);
    const retiredRows = await cleanup.database
      .prepare(
        `SELECT authorization_id, retired_at_ms
           FROM wallet_session_authorizations_v2
          WHERE authorization_id IN ('authorization:null-credential', 'authorization:expired')
          ORDER BY authorization_id`,
      )
      .all<{ readonly authorization_id?: unknown; readonly retired_at_ms?: unknown }>();
    expect(retiredRows.results).toEqual([
      { authorization_id: 'authorization:expired', retired_at_ms: nowMs - 1_000 },
      { authorization_id: 'authorization:null-credential', retired_at_ms: nowMs },
    ]);

    await applyD1MigrationFiles(duplicates.database, prefix);
    await insertAuthorityAndAuthMethod(duplicates.database);
    const duplicateNowMs = Date.now();
    for (const suffix of ['one', 'two']) {
      await insertQuota(
        duplicates.database,
        `quota:duplicate-${suffix}`,
        `session:duplicate-${suffix}`,
        duplicateNowMs + 60_000,
      );
      await insertAuthorization(duplicates.database, {
        authorizationId: `authorization:duplicate-${suffix}`,
        walletSessionId: `session:duplicate-${suffix}`,
        quotaId: `quota:duplicate-${suffix}`,
        walletAuthMethodId: AUTH_METHOD_ID,
        issuedAtMs: duplicateNowMs,
        expiresAtMs: duplicateNowMs + 60_000,
        operationCredentialHash: `credential:duplicate-${suffix}`,
      });
    }
    await expect(applyD1MigrationFiles(duplicates.database, [bridge])).rejects.toThrow();
  } finally {
    cleanupTemporaryD1Database(cleanup.tempDir);
    cleanupTemporaryD1Database(duplicates.tempDir);
  }
});

test('R103F final cutover deletes the registration replay adapter schema', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
    const objects = await temporary.database
      .prepare(
        `SELECT type, name
           FROM sqlite_master
          WHERE name LIKE 'registration_replay_opaque_wallet_session_tokens_v1%'
          ORDER BY type, name`,
      )
      .all<{ readonly type?: unknown; readonly name?: unknown }>();
    expect(objects.results).toEqual([]);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});
