import { readFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { expect, test } from '@playwright/test';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  readTableColumnNames,
} from '../helpers/sqliteD1';

const SCOPE = {
  namespace: 'namespace:final-cutover',
  orgId: 'org:final-cutover',
  projectId: 'project:final-cutover',
  envId: 'env:final-cutover',
  tenantId: 'tenant:final-cutover',
} as const;

const AUTHORITY_ID = 'authority:final-cutover';
const WALLET_ID = 'wallet:final-cutover';
const AUTH_METHOD_ID = 'auth-method:final-cutover';
const PRINCIPAL_ID = 'principal:final-cutover';
const FUTURE_MS = 9_000_000_000_000;
const FINAL_MIGRATION_PREFIX = '0034_r103f_exact_wallet_session_cutover.sql';
const FINAL_PARENT_COLUMNS = [
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
  'record_json',
  'operation_credential_hash',
] as const;
const FINAL_SESSION_MANIFEST_TABLES = [
  'authorization_wallet_session_quotas',
  'wallet_session_authorizations_v2',
  'wallet_session_hosted_credentials_v2',
  'wallet_session_hosted_exchange_codes_v2',
  'linked_device_wallet_session_credential_deliveries_v1',
] as const;
const RETIRED_SESSION_TABLES = [
  'reusable_wallet_sessions',
  'opaque_wallet_session_tokens',
  'hosted_wallet_session_exchange_codes',
  'registration_replay_opaque_wallet_session_tokens_v1',
] as const;

const AUTHORITY_RECORD = JSON.stringify({
  authorityId: AUTHORITY_ID,
  walletId: WALLET_ID,
  state: 'active',
  revocationEpoch: 0,
  authorityDigestB64u: 'digest:final-cutover',
  signerActivationSetDigestB64u: 'digest:final-cutover',
});

const AUTH_METHOD_RECORD = JSON.stringify({
  version: 'wallet_auth_method_v2',
  walletAuthMethodId: AUTH_METHOD_ID,
  walletId: WALLET_ID,
  walletAuthorityId: AUTHORITY_ID,
  kind: 'passkey',
  status: 'active',
  createdAtMs: 1,
  updatedAtMs: 2,
  rpId: 'wallet.example.test',
  credentialIdB64u: 'credential:final-cutover',
  credentialPublicKeyB64u: 'public-key:final-cutover',
  counter: 0,
});

type Database = ReturnType<typeof createTemporaryD1Database>['database'];

function migrationFilesThrough(prefix: string): readonly string[] {
  const files = listD1MigrationFiles('d1-signer');
  const index = files.findIndex((file) => basename(file).startsWith(prefix));
  if (index < 0) throw new Error(`Migration ${prefix} is missing`);
  return files.slice(0, index + 1);
}

function finalMigrationFile(): string {
  const files = listD1MigrationFiles('d1-signer');
  const file = files.find((candidate) => basename(candidate) === FINAL_MIGRATION_PREFIX);
  if (!file) throw new Error(`Migration ${FINAL_MIGRATION_PREFIX} is missing`);
  return file;
}

async function applyFinalMigration(database: Database): Promise<void> {
  await database.exec(`
    PRAGMA foreign_keys = ON;
    BEGIN IMMEDIATE;
    ${readFileSync(finalMigrationFile(), 'utf8')}
    COMMIT;
  `);
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
      'device:final-cutover',
      'wallet_registration',
      null,
      null,
      null,
      'active',
      '["sign"]',
      '[{}]',
      null,
      'digest:final-cutover',
      'digest:final-cutover',
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
      SCOPE.namespace,
      SCOPE.orgId,
      SCOPE.projectId,
      SCOPE.envId,
      WALLET_ID,
      AUTHORITY_ID,
      'wallet.example.test',
      'passkey',
      'active',
      AUTH_METHOD_ID,
      'credential:final-cutover',
      'credential:final-cutover',
      'public-key:final-cutover',
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
  database: Database,
  quotaId: string,
  walletSessionId: string,
  expiresAtMs = FUTURE_MS,
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
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}): string {
  return JSON.stringify({
    kind: 'wallet_session_authorization_v2',
    tenantId: SCOPE.tenantId,
    principalId: PRINCIPAL_ID,
    walletId: WALLET_ID,
    authorityId: AUTHORITY_ID,
    walletAuthMethodId: AUTH_METHOD_ID,
    authorityDigestB64u: 'digest:final-cutover',
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
      AUTH_METHOD_ID,
      'digest:final-cutover',
      0,
      '[{"kind":"link_devices","authorityId":"authority:final-cutover"}]',
      input.issuedAtMs,
      input.expiresAtMs,
      null,
      authorizationRecordJson(input),
      input.operationCredentialHash,
    )
    .run();
}

async function insertV1SessionAndChildren(database: Database): Promise<void> {
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
      'digest:final-cutover',
      'mint:v1',
      'quota:v1',
      'active',
      1,
      FUTURE_MS,
      'authorization:v1',
      AUTH_METHOD_ID,
    )
    .run();
  await database
    .prepare(
      `INSERT INTO opaque_wallet_session_tokens (
         namespace, tenant_id, token_hash, curve, wallet_session_id, binding_json
       ) VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .bind(SCOPE.namespace, SCOPE.tenantId, 'token-hash:v1', 'ed25519', 'session:v1', '{}')
    .run();
  await database
    .prepare(
      `INSERT INTO hosted_wallet_session_exchange_codes (
         namespace, tenant_id, exchange_code_id, wallet_session_id, code_hash,
         nonce_digest, app_origin, wallet_origin, lifecycle_kind, issued_at_ms,
         expires_at_ms, token_hash, curve, binding_json, consumed_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      SCOPE.namespace,
      SCOPE.tenantId,
      'exchange:v1',
      'session:v1',
      'code:v1',
      'nonce:v1',
      'https://app.example.test',
      'https://wallet.example.test',
      'issued',
      1,
      FUTURE_MS,
      null,
      'ed25519',
      '{}',
      null,
    )
    .run();
}

async function insertAuthorizedOperation(
  database: Database,
  input: {
    readonly operationId: string;
    readonly authorizationId: string;
    readonly quotaId: string | null;
    readonly quotaKind: 'consume_reusable_wallet_session' | 'quota_neutral';
    readonly linkedScope: readonly [string | null, string | null, string | null];
    readonly claimedAtMs: number;
    readonly operationKind?: string;
    readonly capabilityKind?: string;
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
      input.capabilityKind ?? 'near_ed25519_mpc_signing',
      input.operationKind ?? 'near.sign_transaction',
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

async function insertHostedCredential(database: Database): Promise<void> {
  await database
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
      'hosted-credential:preserve',
      'authorization:active',
      'session:active',
      'quota:active',
      PRINCIPAL_ID,
      WALLET_ID,
      AUTHORITY_ID,
      AUTH_METHOD_ID,
      'digest:hosted-credential',
      'https://app.example.test',
      'https://wallet.example.test',
      100,
      FUTURE_MS - 1,
      'active',
      null,
    )
    .run();
}

async function insertConsumedHostedExchange(database: Database): Promise<void> {
  await database
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
      'exchange:preserve',
      'authorization:active',
      'session:active',
      'quota:active',
      PRINCIPAL_ID,
      WALLET_ID,
      AUTHORITY_ID,
      AUTH_METHOD_ID,
      'code:preserve',
      'nonce:preserve',
      'https://app.example.test',
      'https://wallet.example.test',
      100,
      FUTURE_MS - 1,
      'issued',
      null,
      null,
    )
    .run();
  await database
    .prepare(
      `UPDATE wallet_session_hosted_exchange_codes_v2
          SET lifecycle_kind = 'consumed',
              hosted_credential_id = 'hosted-credential:preserve',
              consumed_at_ms = 200
        WHERE exchange_code_id = 'exchange:preserve'`,
    )
    .run();
}

async function insertLinkedInstallation(database: Database): Promise<void> {
  await database
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
      'link:preserve',
      AUTHORITY_ID,
      WALLET_ID,
      AUTH_METHOD_ID,
      'device:final-cutover',
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
}

async function insertAcknowledgedDelivery(database: Database): Promise<void> {
  const issuedValues = [
    SCOPE.namespace,
    SCOPE.orgId,
    SCOPE.projectId,
    SCOPE.envId,
    'link:preserve',
    SCOPE.tenantId,
    'authorization:active',
    'session:active',
    'quota:active',
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
    'digest:installation-receipt',
    100,
    FUTURE_MS - 1,
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
  await database
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
    .bind(...issuedValues)
    .run();
  await database
    .prepare(
      `UPDATE linked_device_wallet_session_credential_deliveries_v1
          SET lifecycle_kind = 'acknowledged', sealed_envelope_json = NULL,
              acknowledged_at_ms = 200, acknowledgement_receipt_json = '{"ack":true}',
              cleanup_state = 'pending', cleanup_receipt_json = '{"cleanup":true}',
              acknowledgement_auth_binding_digest_b64u = 'digest:recipient',
              acknowledgement_auth_package_set_digest_b64u = 'digest:package-set',
              acknowledgement_auth_expires_at_ms = 500
        WHERE link_session_id = 'link:preserve'`,
    )
    .run();
}

function registrationPrepared(): Record<string, string> {
  return {
    kind: 'd1_wallet_registration_operation_prepared_v1',
    walletAuthorityId: AUTHORITY_ID,
    deviceId: 'device:final-cutover',
    walletAuthMethodId: AUTH_METHOD_ID,
  };
}

function registrationRecord(
  kind: 'claim' | 'completionV1' | 'completionV2',
  operation: string,
): string {
  const prepared = registrationPrepared();
  if (kind === 'claim') {
    return JSON.stringify({
      kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
      operation,
      requestFingerprint: `request:${operation}`,
      preparedArtifactFingerprint: `artifact:${operation}`,
      claimedAtMs: 10,
      prepared,
    });
  }
  if (kind === 'completionV1') {
    return JSON.stringify({
      kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
      operation,
      requestFingerprint: `request:${operation}`,
      preparedArtifactFingerprint: `artifact:${operation}`,
      claimedAtMs: 10,
      completedAtMs: 20,
      prepared,
      response: {
        registrationEstablishedSession: {
          tokens: { ed25519: { walletSessionToken: 'legacy-bearer' } },
        },
      },
    });
  }
  return JSON.stringify({
    kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v2',
    operation,
    requestFingerprint: `request:${operation}`,
    preparedArtifactFingerprint: `artifact:${operation}`,
    claimedAtMs: 10,
    completedAtMs: 20,
    prepared,
    receipt: {
      kind: 'wallet_registration_session_commit_receipt_v2',
      operation,
      operationFingerprint: `request:${operation}`,
      registrationCeremonyId: `ceremony:${operation}`,
      committed: { kind: 'wallet_registration_committed_v1' },
    },
  });
}

async function insertRegistrationRecord(
  database: Database,
  recordKey: string,
  recordJson: string,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO router_ab_yao_versioned_json_records (
         namespace, org_id, project_id, env_id, record_key, version,
         record_json, created_at_ms, updated_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      SCOPE.namespace,
      SCOPE.orgId,
      SCOPE.projectId,
      SCOPE.envId,
      recordKey,
      1,
      recordJson,
      1,
      1,
    )
    .run();
}

async function seedCurrentHistory(database: Database): Promise<void> {
  const through0031 = migrationFilesThrough('0031_');
  await applyD1MigrationFiles(database, through0031);
  await insertAuthorityAndAuthMethod(database);
  await insertV1SessionAndChildren(database);
  await insertAuthorizedOperation(database, {
    operationId: 'operation:v1-pending',
    authorizationId: 'authorization:v1',
    quotaId: 'quota:v1',
    quotaKind: 'consume_reusable_wallet_session',
    linkedScope: [null, null, null],
    claimedAtMs: 10,
  });
  await applyD1MigrationFiles(database, migrationFilesThrough('0033_').slice(through0031.length));

  await insertQuota(database, 'quota:active', 'session:active');
  await insertAuthorization(database, {
    authorizationId: 'authorization:active',
    walletSessionId: 'session:active',
    quotaId: 'quota:active',
    issuedAtMs: 100,
    expiresAtMs: FUTURE_MS,
    operationCredentialHash: 'credential:active',
  });
  await insertHostedCredential(database);
  await insertConsumedHostedExchange(database);
  await insertLinkedInstallation(database);
  await insertAcknowledgedDelivery(database);

  await insertQuota(database, 'quota:null-digest', 'session:null-digest');
  await insertAuthorization(database, {
    authorizationId: 'authorization:null-digest',
    walletSessionId: 'session:null-digest',
    quotaId: 'quota:null-digest',
    issuedAtMs: 300,
    expiresAtMs: FUTURE_MS,
    operationCredentialHash: null,
  });
  await insertQuota(database, 'quota:expired', 'session:expired', 100);
  await insertAuthorization(database, {
    authorizationId: 'authorization:expired',
    walletSessionId: 'session:expired',
    quotaId: 'quota:expired',
    issuedAtMs: 1,
    expiresAtMs: 100,
    operationCredentialHash: 'credential:expired',
  });

  await insertRegistrationRecord(
    database,
    'wallet-registration-activate:claim',
    registrationRecord('claim', 'registration_activate'),
  );
  await insertRegistrationRecord(
    database,
    'wallet-registration-activate:legacy',
    registrationRecord('completionV1', 'registration_activate'),
  );
  await insertRegistrationRecord(
    database,
    'wallet-registration-near-provisioning:receipt',
    registrationRecord('completionV2', 'near_provisioning'),
  );
  await insertRegistrationRecord(database, 'unrelated-record:preserve', '{"keep":true}');
}

async function readTableNames(database: Database): Promise<readonly string[]> {
  const rows = await database
    .prepare(
      `SELECT name FROM sqlite_master
        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
        ORDER BY name`,
    )
    .all<{ readonly name?: unknown }>();
  return rows.results.flatMap((row) => (typeof row.name === 'string' ? [row.name] : []));
}

async function readForeignKeySignatures(
  database: Database,
  tableName: string,
): Promise<readonly string[]> {
  const rows = await database.prepare(`PRAGMA foreign_key_list(${tableName})`).all<{
    readonly id?: unknown;
    readonly seq?: unknown;
    readonly table?: unknown;
    readonly from?: unknown;
    readonly to?: unknown;
  }>();
  return rows.results
    .map((row) => ({
      id: Number(row.id),
      seq: Number(row.seq),
      signature: `${Number(row.id)}:${Number(row.seq)}:${row.table}:${row.from}->${row.to}`,
    }))
    .sort((left, right) => left.id - right.id || left.seq - right.seq)
    .map((row) => row.signature);
}

function readManifestTables(filePath: string, constantName: string): readonly string[] {
  const source = readFileSync(filePath, 'utf8');
  const match = source.match(
    new RegExp(`const ${constantName} = Object\\.freeze\\(\\[([\\s\\S]*?)\\]\\);`),
  );
  if (!match) throw new Error(`${constantName} is missing from ${filePath}`);
  return [...match[1].matchAll(/'([^']+)'/gu)].map((entry) => entry[1] || '');
}

async function expectForeignKeyCheckEmpty(database: Database): Promise<void> {
  await expect(database.prepare('PRAGMA foreign_key_check').all()).resolves.toMatchObject({
    results: [],
  });
}

test('R103F final cutover installs exact tables and both readiness manifests agree', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, migrationFilesThrough('0033_'));
    await applyFinalMigration(temporary.database);

    await expect(
      readTableColumnNames(temporary.database, 'wallet_session_authorizations_v2'),
    ).resolves.toEqual(FINAL_PARENT_COLUMNS);
    const tableNames = await readTableNames(temporary.database);
    expect(tableNames).toEqual(expect.arrayContaining([...FINAL_SESSION_MANIFEST_TABLES]));
    expect(tableNames).not.toEqual(expect.arrayContaining([...RETIRED_SESSION_TABLES]));
    await expectForeignKeyCheckEmpty(temporary.database);

    const localManifest = readManifestTables(
      resolve(
        import.meta.dirname,
        '../../packages/wallet-console-server-ts/src/router/cloudflare/d1LocalDevWorker.ts',
      ),
      'SIGNER_READY_TABLES',
    );
    const stagingManifest = readManifestTables(
      resolve(
        import.meta.dirname,
        '../../packages/wallet-console-server-ts/src/router/cloudflare/d1RouterApiStagingWorker.ts',
      ),
      'RELAY_SIGNER_READY_TABLES',
    );
    const finalNames = new Set<string>([
      ...FINAL_SESSION_MANIFEST_TABLES,
      ...RETIRED_SESSION_TABLES,
    ]);
    const localSessionEntries = localManifest.filter((name) => finalNames.has(name));
    const stagingSessionEntries = stagingManifest.filter((name) => finalNames.has(name));
    expect(localSessionEntries).toEqual([...FINAL_SESSION_MANIFEST_TABLES]);
    expect(stagingSessionEntries).toEqual([...FINAL_SESSION_MANIFEST_TABLES]);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('R103F final cutover preserves all V2 children and removes only retired credential-bearing state', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await seedCurrentHistory(temporary.database);
    await applyFinalMigration(temporary.database);

    await expect(
      temporary.database
        .prepare(
          `SELECT hosted_credential_id, authorization_id, lifecycle_kind
             FROM wallet_session_hosted_credentials_v2`,
        )
        .all(),
    ).resolves.toMatchObject({
      results: [
        {
          hosted_credential_id: 'hosted-credential:preserve',
          authorization_id: 'authorization:active',
          lifecycle_kind: 'active',
        },
      ],
    });
    await expect(
      temporary.database
        .prepare(
          `SELECT exchange_code_id, hosted_credential_id, lifecycle_kind, consumed_at_ms
             FROM wallet_session_hosted_exchange_codes_v2`,
        )
        .all(),
    ).resolves.toMatchObject({
      results: [
        {
          exchange_code_id: 'exchange:preserve',
          hosted_credential_id: 'hosted-credential:preserve',
          lifecycle_kind: 'consumed',
          consumed_at_ms: 200,
        },
      ],
    });
    await expect(
      temporary.database
        .prepare(
          `SELECT link_session_id, authorization_id, lifecycle_kind,
                          acknowledgement_receipt_json
             FROM linked_device_wallet_session_credential_deliveries_v1`,
        )
        .all(),
    ).resolves.toMatchObject({
      results: [
        {
          link_session_id: 'link:preserve',
          authorization_id: 'authorization:active',
          lifecycle_kind: 'acknowledged',
          acknowledgement_receipt_json: '{"ack":true}',
        },
      ],
    });

    await expect(
      readForeignKeySignatures(temporary.database, 'wallet_session_hosted_credentials_v2'),
    ).resolves.toEqual([
      '0:0:wallet_session_authorizations_v2:namespace->namespace',
      '0:1:wallet_session_authorizations_v2:org_id->org_id',
      '0:2:wallet_session_authorizations_v2:project_id->project_id',
      '0:3:wallet_session_authorizations_v2:env_id->env_id',
      '0:4:wallet_session_authorizations_v2:tenant_id->tenant_id',
      '0:5:wallet_session_authorizations_v2:authorization_id->authorization_id',
      '0:6:wallet_session_authorizations_v2:wallet_session_id->wallet_session_id',
      '0:7:wallet_session_authorizations_v2:quota_id->quota_id',
      '0:8:wallet_session_authorizations_v2:principal_id->principal_id',
      '0:9:wallet_session_authorizations_v2:wallet_id->wallet_id',
      '0:10:wallet_session_authorizations_v2:authority_id->authority_id',
      '0:11:wallet_session_authorizations_v2:wallet_auth_method_id->wallet_auth_method_id',
    ]);
    await expect(
      readForeignKeySignatures(temporary.database, 'wallet_session_hosted_exchange_codes_v2'),
    ).resolves.toEqual([
      '0:0:wallet_session_hosted_credentials_v2:namespace->namespace',
      '0:1:wallet_session_hosted_credentials_v2:org_id->org_id',
      '0:2:wallet_session_hosted_credentials_v2:project_id->project_id',
      '0:3:wallet_session_hosted_credentials_v2:env_id->env_id',
      '0:4:wallet_session_hosted_credentials_v2:tenant_id->tenant_id',
      '0:5:wallet_session_hosted_credentials_v2:hosted_credential_id->hosted_credential_id',
      '0:6:wallet_session_hosted_credentials_v2:authorization_id->authorization_id',
      '0:7:wallet_session_hosted_credentials_v2:wallet_session_id->wallet_session_id',
      '0:8:wallet_session_hosted_credentials_v2:quota_id->quota_id',
      '0:9:wallet_session_hosted_credentials_v2:principal_id->principal_id',
      '0:10:wallet_session_hosted_credentials_v2:wallet_id->wallet_id',
      '0:11:wallet_session_hosted_credentials_v2:authority_id->authority_id',
      '0:12:wallet_session_hosted_credentials_v2:wallet_auth_method_id->wallet_auth_method_id',
      '1:0:wallet_session_authorizations_v2:namespace->namespace',
      '1:1:wallet_session_authorizations_v2:org_id->org_id',
      '1:2:wallet_session_authorizations_v2:project_id->project_id',
      '1:3:wallet_session_authorizations_v2:env_id->env_id',
      '1:4:wallet_session_authorizations_v2:tenant_id->tenant_id',
      '1:5:wallet_session_authorizations_v2:authorization_id->authorization_id',
      '1:6:wallet_session_authorizations_v2:wallet_session_id->wallet_session_id',
      '1:7:wallet_session_authorizations_v2:quota_id->quota_id',
      '1:8:wallet_session_authorizations_v2:principal_id->principal_id',
      '1:9:wallet_session_authorizations_v2:wallet_id->wallet_id',
      '1:10:wallet_session_authorizations_v2:authority_id->authority_id',
      '1:11:wallet_session_authorizations_v2:wallet_auth_method_id->wallet_auth_method_id',
    ]);
    await expect(
      readForeignKeySignatures(
        temporary.database,
        'linked_device_wallet_session_credential_deliveries_v1',
      ),
    ).resolves.toEqual([
      '0:0:wallet_session_authorizations_v2:namespace->namespace',
      '0:1:wallet_session_authorizations_v2:org_id->org_id',
      '0:2:wallet_session_authorizations_v2:project_id->project_id',
      '0:3:wallet_session_authorizations_v2:env_id->env_id',
      '0:4:wallet_session_authorizations_v2:tenant_id->tenant_id',
      '0:5:wallet_session_authorizations_v2:authorization_id->authorization_id',
      '0:6:wallet_session_authorizations_v2:wallet_session_id->wallet_session_id',
      '0:7:wallet_session_authorizations_v2:quota_id->quota_id',
      '0:8:wallet_session_authorizations_v2:principal_id->principal_id',
      '0:9:wallet_session_authorizations_v2:wallet_id->wallet_id',
      '0:10:wallet_session_authorizations_v2:authority_id->authority_id',
      '0:11:wallet_session_authorizations_v2:wallet_auth_method_id->wallet_auth_method_id',
      '1:0:linked_device_authority_installations:namespace->namespace',
      '1:1:linked_device_authority_installations:org_id->org_id',
      '1:2:linked_device_authority_installations:project_id->project_id',
      '1:3:linked_device_authority_installations:env_id->env_id',
      '1:4:linked_device_authority_installations:link_session_id->link_session_id',
      '1:5:linked_device_authority_installations:authority_id->authority_id',
      '1:6:linked_device_authority_installations:wallet_id->wallet_id',
      '1:7:linked_device_authority_installations:wallet_auth_method_id->auth_method_id',
    ]);

    const retiredTables = await readTableNames(temporary.database);
    expect(retiredTables).not.toEqual(expect.arrayContaining([...RETIRED_SESSION_TABLES]));
    await expect(
      temporary.database
        .prepare(
          `SELECT COUNT(*) AS count
             FROM router_ab_yao_versioned_json_records
            WHERE json_extract(record_json, '$.kind') =
              'router_ab_ed25519_yao_registration_side_effect_completion_v1'`,
        )
        .first(),
    ).resolves.toMatchObject({ count: 0 });
    await expect(
      temporary.database
        .prepare(
          `SELECT record_key FROM router_ab_yao_versioned_json_records
            WHERE record_key IN (
              'wallet-registration-activate:claim',
              'wallet-registration-near-provisioning:receipt',
              'unrelated-record:preserve'
            ) ORDER BY record_key`,
        )
        .all(),
    ).resolves.toMatchObject({
      results: [
        { record_key: 'unrelated-record:preserve' },
        { record_key: 'wallet-registration-activate:claim' },
        { record_key: 'wallet-registration-near-provisioning:receipt' },
      ],
    });
    await expect(
      temporary.database
        .prepare(
          `SELECT authorization_id, retired_at_ms, operation_credential_hash
             FROM wallet_session_authorizations_v2
            WHERE authorization_id IN (
              'authorization:active', 'authorization:null-digest', 'authorization:expired'
            ) ORDER BY authorization_id`,
        )
        .all(),
    ).resolves.toMatchObject({
      results: [
        {
          authorization_id: 'authorization:active',
          retired_at_ms: null,
          operation_credential_hash: 'credential:active',
        },
        {
          authorization_id: 'authorization:expired',
          retired_at_ms: 100,
          operation_credential_hash: 'credential:expired',
        },
        {
          authorization_id: 'authorization:null-digest',
          retired_at_ms: 300,
          operation_credential_hash: null,
        },
      ],
    });
    await expect(
      temporary.database
        .prepare(
          `SELECT COUNT(*) AS count FROM authorized_operations
            WHERE authorized_operation_id = 'operation:v1-pending'`,
        )
        .first(),
    ).resolves.toMatchObject({ count: 0 });
    await expect(
      temporary.database
        .prepare(
          `SELECT COUNT(*) AS count FROM authorization_wallet_session_quotas
            WHERE quota_id = 'quota:v1'`,
        )
        .first(),
    ).resolves.toMatchObject({ count: 0 });
    await expectForeignKeyCheckEmpty(temporary.database);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('R103F final cutover aborts unknown registration inventory', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, migrationFilesThrough('0033_'));
    await insertRegistrationRecord(
      temporary.database,
      'wallet-registration-activate:unknown',
      '{"kind":"unknown_registration_shape"}',
    );
    await expect(applyFinalMigration(temporary.database)).rejects.toThrow();
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('R103F final cutover aborts a partial-scope pending grant', async () => {
  const temporary = createTemporaryD1Database();
  try {
    const through0002 = migrationFilesThrough('0002_');
    await applyD1MigrationFiles(temporary.database, through0002);
    await temporary.database.exec(`
      DROP TRIGGER authorized_operation_grant_shape_guard;
      DROP TRIGGER authorized_operation_owner_grant_claim_atomic;
    `);
    await insertAuthorizedOperation(temporary.database, {
      operationId: 'operation:partial-scope',
      authorizationId: 'authorization:partial-scope',
      quotaId: null,
      quotaKind: 'quota_neutral',
      linkedScope: ['org:partial-scope', null, null],
      claimedAtMs: 10,
      operationKind: 'near.export_key',
      capabilityKind: 'near_ed25519_mpc_signing',
    });
    await applyD1MigrationFiles(temporary.database, migrationFilesThrough('0033_').slice(2));
    await expect(applyFinalMigration(temporary.database)).rejects.toThrow();
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('R103F final cutover aborts duplicate usable exact tuples', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, migrationFilesThrough('0033_'));
    await insertAuthorityAndAuthMethod(temporary.database);
    await insertQuota(temporary.database, 'quota:duplicate-a', 'session:duplicate-a');
    await insertAuthorization(temporary.database, {
      authorizationId: 'authorization:duplicate-a',
      walletSessionId: 'session:duplicate-a',
      quotaId: 'quota:duplicate-a',
      issuedAtMs: 100,
      expiresAtMs: FUTURE_MS,
      operationCredentialHash: 'credential:duplicate-a',
    });
    await insertQuota(temporary.database, 'quota:duplicate-b', 'session:duplicate-b');
    await insertAuthorization(temporary.database, {
      authorizationId: 'authorization:duplicate-b',
      walletSessionId: 'session:duplicate-b',
      quotaId: 'quota:duplicate-b',
      issuedAtMs: 101,
      expiresAtMs: FUTURE_MS,
      operationCredentialHash: 'credential:duplicate-b',
    });
    await expect(applyFinalMigration(temporary.database)).rejects.toThrow();
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('R103F current-history unscoped pending state is deleted at final cutover', async () => {
  const temporary = createTemporaryD1Database();
  try {
    const through0031 = migrationFilesThrough('0031_');
    await applyD1MigrationFiles(temporary.database, through0031);
    await insertAuthorityAndAuthMethod(temporary.database);
    await insertV1SessionAndChildren(temporary.database);
    await insertAuthorizedOperation(temporary.database, {
      operationId: 'operation:unscoped-only',
      authorizationId: 'authorization:v1',
      quotaId: 'quota:v1',
      quotaKind: 'consume_reusable_wallet_session',
      linkedScope: [null, null, null],
      claimedAtMs: 10,
    });
    await applyD1MigrationFiles(
      temporary.database,
      migrationFilesThrough('0033_').slice(through0031.length),
    );
    await applyFinalMigration(temporary.database);
    await expect(
      temporary.database
        .prepare(
          `SELECT COUNT(*) AS count FROM authorized_operations
            WHERE authorized_operation_id = 'operation:unscoped-only'`,
        )
        .first(),
    ).resolves.toMatchObject({ count: 0 });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});
