import { expect, test } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import type {
  CloudflareD1EmailOtpDeliveryProviderInput,
  CloudflareD1EmailOtpDeliveryProviderResult,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1RelayAuthService';
import { createCloudflareD1RelayAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RelayAuthService';
import { base64UrlDecode, base64UrlEncode } from '../../packages/shared-ts/src/utils/encoders';
import {
  buildEmailOtpRecoveryWrapBinding,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
} from '../../packages/shared-ts/src/utils/emailOtpRecoveryKey';
import {
  secp256k1PrivateKey32ToPublicKey33,
  signSecp256k1Recoverable,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/ethSignerWasm';

type SqliteJsonRow = Record<string, unknown>;

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

class RecordingEmailOtpDeliveryProvider {
  readonly calls: CloudflareD1EmailOtpDeliveryProviderInput[] = [];

  constructor(
    private readonly result: CloudflareD1EmailOtpDeliveryProviderResult = { ok: true },
  ) {}

  async deliver(
    input: CloudflareD1EmailOtpDeliveryProviderInput,
  ): Promise<CloudflareD1EmailOtpDeliveryProviderResult> {
    this.calls.push(input);
    return this.result;
  }
}

class SqliteCliD1Database implements D1DatabaseLike {
  constructor(readonly databasePath: string) {}

  prepare(query: string): D1PreparedStatementLike {
    return new SqliteCliD1PreparedStatement(this.databasePath, query, []);
  }

  async batch<T = unknown>(statements: readonly D1PreparedStatementLike[]): Promise<readonly T[]> {
    const sqlStatements: string[] = [];
    for (const statement of statements) sqlStatements.push(sqlFromD1PreparedStatement(statement));
    runSqlite(this.databasePath, `BEGIN IMMEDIATE; ${sqlStatements.join(' ')} COMMIT;`);
    return sqlStatements.map(successfulD1BatchResult) as readonly T[];
  }

  async exec(query: string): Promise<unknown> {
    runSqlite(this.databasePath, query);
    return null;
  }
}

class SqliteCliD1PreparedStatement implements D1PreparedStatementLike {
  constructor(
    private readonly databasePath: string,
    private readonly query: string,
    private readonly values: readonly unknown[],
  ) {}

  bind(...values: readonly unknown[]): D1PreparedStatementLike {
    return new SqliteCliD1PreparedStatement(this.databasePath, this.query, values);
  }

  async first<T = unknown>(columnName?: string): Promise<T | null> {
    const result = await this.all<SqliteJsonRow>();
    const row = result.results?.[0] || null;
    if (!row) return null;
    if (!columnName) return row as T;
    const value = row[columnName];
    return value === undefined ? null : (value as T);
  }

  async all<T = unknown>(): Promise<D1ResultLike<T>> {
    const results = runSqliteJson(this.databasePath, this.toSql());
    return {
      success: true,
      results: results as readonly T[],
      meta: { rows_read: results.length, rows_written: 0 },
    };
  }

  async run<T = unknown>(): Promise<D1ResultLike<T>> {
    const sql = `${this.toSql()} SELECT changes() AS changes, last_insert_rowid() AS last_row_id;`;
    const results = runSqliteJson(this.databasePath, sql);
    const metaRow = results.at(-1) || {};
    return {
      success: true,
      results: [] as readonly T[],
      meta: {
        changes: toInteger(metaRow.changes),
        last_row_id: toInteger(metaRow.last_row_id),
        rows_written: toInteger(metaRow.changes),
      },
    };
  }

  toSql(): string {
    return interpolateSql(this.query, this.values);
  }
}

function createTemporaryD1Database(): { readonly database: D1DatabaseLike; readonly tempDir: string } {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'seams-d1-relay-auth-test-'));
  return {
    database: new SqliteCliD1Database(path.join(tempDir, 'test.sqlite')),
    tempDir,
  };
}

function cleanupTemporaryD1Database(tempDir: string): void {
  rmSync(tempDir, { recursive: true, force: true });
}

function utf8Bytes(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}

function jsonBase64Url(input: Record<string, unknown>): string {
  return base64UrlEncode(utf8Bytes(JSON.stringify(input)));
}

async function generateGoogleOidcTestKey(kid: string): Promise<{
  readonly kid: string;
  readonly privateKey: CryptoKey;
  readonly publicJwk: JsonWebKey;
}> {
  const keyPair = (await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  const exportedPublicJwk = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey;
  return {
    kid,
    privateKey: keyPair.privateKey,
    publicJwk: {
      ...exportedPublicJwk,
      kid,
      use: 'sig',
      alg: 'RS256',
    },
  };
}

async function makeSignedGoogleIdToken(input: {
  readonly privateKey: CryptoKey;
  readonly kid: string;
  readonly payload: Record<string, unknown>;
}): Promise<string> {
  const headerB64u = jsonBase64Url({ alg: 'RS256', typ: 'JWT', kid: input.kid });
  const payloadB64u = jsonBase64Url(input.payload);
  const data = utf8Bytes(`${headerB64u}.${payloadB64u}`);
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, input.privateKey, data),
  );
  return `${headerB64u}.${payloadB64u}.${base64UrlEncode(signature)}`;
}

let googleJwksFetchMockPublicJwk: JsonWebKey | null = null;

async function googleJwksFetchMock(input: RequestInfo | URL): Promise<Response> {
  expect(String(input)).toBe('https://www.googleapis.com/oauth2/v3/certs');
  return new Response(JSON.stringify({ keys: [googleJwksFetchMockPublicJwk] }), {
    status: 200,
    headers: { 'cache-control': 'public, max-age=300' },
  });
}

function installGoogleJwksFetchMock(publicJwk: JsonWebKey): typeof globalThis.fetch {
  const originalFetch = globalThis.fetch;
  googleJwksFetchMockPublicJwk = publicJwk;
  globalThis.fetch = googleJwksFetchMock;
  return originalFetch;
}

function restoreGoogleJwksFetchMock(originalFetch: typeof globalThis.fetch): void {
  globalThis.fetch = originalFetch;
  googleJwksFetchMockPublicJwk = null;
}

function applySignerMigrations(database: D1DatabaseLike): Promise<void> {
  return applyMigrations(database, [
    'packages/sdk-server-ts/migrations/d1-signer/0003_signer_webauthn.sql',
    'packages/sdk-server-ts/migrations/d1-signer/0004_signer_identity.sql',
    'packages/sdk-server-ts/migrations/d1-signer/0005_signer_recovery.sql',
    'packages/sdk-server-ts/migrations/d1-signer/0006_signer_near_public_keys.sql',
    'packages/sdk-server-ts/migrations/d1-signer/0008_signer_email_otp.sql',
    'packages/sdk-server-ts/migrations/d1-signer/0009_signer_email_otp_rate_limits.sql',
  ]);
}

async function applyMigrations(
  database: D1DatabaseLike,
  migrationPaths: readonly string[],
): Promise<void> {
  for (const migrationPath of migrationPaths) {
    await database.exec(readFileSync(path.join(repoRoot, migrationPath), 'utf8'));
  }
}

function runSqlite(databasePath: string, sql: string): void {
  const result = spawnSync('sqlite3', [databasePath, sql], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status === 0) return;
  throw new Error(formatSqliteError(result.stderr, sql));
}

function runSqliteJson(databasePath: string, sql: string): readonly SqliteJsonRow[] {
  const result = spawnSync('sqlite3', ['-json', databasePath, sql], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(formatSqliteError(result.stderr, sql));
  const stdout = result.stdout.trim();
  if (!stdout) return [];
  const parsed: unknown = JSON.parse(stdout);
  if (!Array.isArray(parsed)) {
    throw new Error(`sqlite3 JSON output was not an array: ${stdout}`);
  }
  return parsed.filter(isSqliteJsonRow);
}

function formatSqliteError(stderr: string, sql: string): string {
  return `sqlite3 failed: ${stderr.trim() || 'unknown error'}\nSQL: ${sql}`;
}

function isSqliteJsonRow(input: unknown): input is SqliteJsonRow {
  return Boolean(input && typeof input === 'object' && !Array.isArray(input));
}

function interpolateSql(query: string, values: readonly unknown[]): string {
  const segments = splitSqlByPlaceholders(query);
  if (segments.length - 1 !== values.length) {
    throw new Error(
      `SQL placeholder count ${segments.length - 1} did not match bound value count ${values.length}`,
    );
  }
  let sql = segments[0] || '';
  for (let index = 0; index < values.length; index += 1) {
    sql += `${sqlLiteral(values[index])}${segments[index + 1] || ''}`;
  }
  return ensureSqlStatementTerminator(sql);
}

function splitSqlByPlaceholders(query: string): readonly string[] {
  const segments: string[] = [];
  let current = '';
  let inSingleQuote = false;
  for (let index = 0; index < query.length; index += 1) {
    const char = query[index] || '';
    const next = query[index + 1] || '';
    if (char === "'" && inSingleQuote && next === "'") {
      current += "''";
      index += 1;
      continue;
    }
    if (char === "'") {
      inSingleQuote = !inSingleQuote;
      current += char;
      continue;
    }
    if (char === '?' && !inSingleQuote) {
      segments.push(current);
      current = '';
      continue;
    }
    current += char;
  }
  segments.push(current);
  return segments;
}

function ensureSqlStatementTerminator(sql: string): string {
  const trimmed = sql.trim();
  return trimmed.endsWith(';') ? trimmed : `${trimmed};`;
}

function sqlLiteral(value: unknown): string {
  if (value === null || value === undefined) return 'NULL';
  if (typeof value === 'boolean') return value ? '1' : '0';
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Uint8Array) return `X'${Buffer.from(value).toString('hex')}'`;
  if (value instanceof Date) return quoteSqlString(value.toISOString());
  return quoteSqlString(String(value));
}

function quoteSqlString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function toInteger(value: unknown): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : 0;
}

function sqlFromD1PreparedStatement(statement: D1PreparedStatementLike): string {
  if (statement instanceof SqliteCliD1PreparedStatement) return statement.toSql();
  throw new Error('Expected SqliteCliD1PreparedStatement');
}

function successfulD1BatchResult(): D1ResultLike<unknown> {
  return { success: true, results: [], meta: { changes: 1, rows_written: 1 } };
}

async function insertIdentity(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly userId: string;
  readonly subject: string;
}): Promise<void> {
  await input.database
    .prepare(
      `INSERT INTO signer_identity_links (
        namespace, org_id, project_id, env_id, subject, user_id, record_json, created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.subject,
      input.userId,
      JSON.stringify({
        version: 'identity_subject_v1',
        subject: input.subject,
        userId: input.userId,
        createdAtMs: 100,
        updatedAtMs: 100,
      }),
      100,
      100,
    )
    .run();
}

async function insertWebAuthn(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly userId: string;
}): Promise<void> {
  await input.database
    .prepare(
      `INSERT INTO signer_webauthn_authenticators (
        namespace, org_id, project_id, env_id, user_id, credential_id_b64u,
        credential_public_key_b64u, counter, created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.userId,
      'credential-a',
      'credential-public-key-a',
      0,
      200,
      300,
    )
    .run();
  await input.database
    .prepare(
      `INSERT INTO signer_webauthn_credential_bindings (
        namespace, org_id, project_id, env_id, rp_id, credential_id_b64u, user_id,
        signer_slot, record_json, created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      'example.com',
      'credential-a',
      input.userId,
      2,
      JSON.stringify({
        version: 'webauthn_credential_binding_v1',
        rpId: 'example.com',
        credentialIdB64u: 'credential-a',
        userId: input.userId,
        nearAccountId: 'near.testnet',
        nearEd25519SigningKeyId: 'ed25519:key',
        signerSlot: 2,
        publicKey: 'ed25519:public',
        createdAtMs: 150,
        updatedAtMs: 250,
      }),
      150,
      250,
    )
    .run();
}

async function readWebAuthnChallengeRow(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly challengeId: string;
}): Promise<SqliteJsonRow | null> {
  return await input.database
    .prepare(
      `SELECT challenge_kind, record_json, created_at_ms, expires_at_ms
         FROM signer_webauthn_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?
        LIMIT 1`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.challengeId,
    )
    .first<SqliteJsonRow>();
}

async function insertNearPublicKey(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly userId: string;
}): Promise<void> {
  const record = {
    version: 'near_public_key_v1',
    userId: input.userId,
    publicKey: 'ed25519:near-public',
    kind: 'threshold',
    signerSlot: 1,
    credentialIdB64u: 'credential-a',
    rpId: 'example.com',
    createdAtMs: 400,
    updatedAtMs: 500,
  };
  await input.database
    .prepare(
      `INSERT INTO signer_near_public_keys (
        namespace, org_id, project_id, env_id, user_id, public_key, kind, signer_slot,
        record_json, created_at_ms, updated_at_ms, removed_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.userId,
      record.publicKey,
      record.kind,
      record.signerSlot,
      JSON.stringify(record),
      record.createdAtMs,
      record.updatedAtMs,
      null,
    )
    .run();
}

async function insertEmailOtpEnrollment(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly walletId?: string;
  readonly providerUserId?: string;
  readonly verifiedEmail?: string;
  readonly clientUnlockPublicKeyB64u?: string;
}): Promise<void> {
  const record = {
    version: 'email_otp_wallet_enrollment_v1',
    walletId: input.walletId || 'email-wallet.testnet',
    providerUserId: input.providerUserId || 'google:email-user',
    orgId: input.orgId,
    verifiedEmail: input.verifiedEmail || 'alice@example.test',
    enrollmentId: 'enrollment-a',
    enrollmentVersion: 'enrollment-v1',
    enrollmentSealKeyVersion: 'seal-v1',
    signingRootId: 'project-a:env-a',
    signingRootVersion: 'root-v1',
    recoveryWrappedEnrollmentEscrowCount: 3,
    clientUnlockPublicKeyB64u: input.clientUnlockPublicKeyB64u || 'client-unlock-public-key',
    unlockKeyVersion: 'unlock-v1',
    thresholdEcdsaClientVerifyingShareB64u: 'ecdsa-verifying-share',
    createdAtMs: 600,
    updatedAtMs: 700,
  };
  await input.database
    .prepare(
      `INSERT INTO signer_email_otp_wallet_enrollments (
        namespace, org_id, project_id, env_id, wallet_id, provider_user_id, record_org_id,
        verified_email, record_json, created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      record.walletId,
      record.providerUserId,
      record.orgId,
      record.verifiedEmail,
      JSON.stringify(record),
      record.createdAtMs,
      record.updatedAtMs,
    )
    .run();
}

async function listGoogleEmailOtpRegistrationAttemptRows(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
}): Promise<SqliteJsonRow[]> {
  const result = await input.database
    .prepare(
      `SELECT attempt_id, state, app_session_version, runtime_org_id, runtime_policy_key,
              offer_wallet_ids_json, record_json
         FROM signer_email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
        ORDER BY created_at_ms ASC, attempt_id ASC`,
    )
    .bind(input.namespace, input.orgId, input.projectId, input.envId)
    .all<SqliteJsonRow>();
  return [...(result.results || [])];
}

function registrationAttemptRecordFromRow(row: SqliteJsonRow): Record<string, unknown> {
  const raw = row.record_json;
  if (typeof raw !== 'string') throw new Error('registration attempt record_json missing');
  const parsed: unknown = JSON.parse(raw);
  if (!isSqliteJsonRow(parsed)) throw new Error('registration attempt record_json invalid');
  return parsed;
}

async function insertEmailOtpAuthState(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
}): Promise<void> {
  const record = {
    version: 'email_otp_auth_state_v1',
    walletId: 'email-wallet.testnet',
    providerUserId: 'google:email-user',
    orgId: input.orgId,
    createdAtMs: 750,
    updatedAtMs: 800,
    lastEmailOtpLoginAtMs: 800,
  };
  await input.database
    .prepare(
      `INSERT INTO signer_email_otp_auth_states (
        namespace, org_id, project_id, env_id, wallet_id, provider_user_id, record_org_id,
        record_json, created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      record.walletId,
      record.providerUserId,
      record.orgId,
      JSON.stringify(record),
      record.createdAtMs,
      record.updatedAtMs,
    )
    .run();
}

async function insertEmailOtpRecoveryEscrow(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly recoveryKeyId: string;
  readonly recoveryKeyStatus: 'active' | 'consumed' | 'revoked';
  readonly issuedAtMs: number;
  readonly updatedAtMs: number;
}): Promise<void> {
  const record = emailOtpRecoveryEscrowRecord(input);
  await input.database
    .prepare(
      `INSERT INTO signer_email_otp_recovery_wrapped_enrollment_escrows (
        namespace, org_id, project_id, env_id, wallet_id, recovery_key_id, recovery_key_status,
        record_json, issued_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      record.walletId,
      record.recoveryKeyId,
      record.recoveryKeyStatus,
      JSON.stringify(record),
      record.issuedAtMs,
      record.updatedAtMs,
    )
    .run();
}

async function insertEmailOtpGrant(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly grantToken: string;
  readonly appSessionVersion: string;
}): Promise<void> {
  const record = emailOtpGrantRecord(input);
  await input.database
    .prepare(
      `INSERT INTO signer_email_otp_grants (
        namespace, org_id, project_id, env_id, grant_token, user_id, wallet_id, record_org_id,
        challenge_id, action, record_json, issued_at_ms, expires_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      record.grantToken,
      record.userId,
      record.walletId,
      record.orgId,
      record.challengeId,
      record.action,
      JSON.stringify(record),
      record.issuedAtMs,
      record.expiresAtMs,
    )
    .run();
}

function emailOtpGrantRecord(input: {
  readonly orgId: string;
  readonly grantToken: string;
  readonly appSessionVersion: string;
}) {
  return {
    version: 'email_otp_grant_v1',
    grantToken: input.grantToken,
    userId: 'google:email-user',
    walletId: 'email-wallet.testnet',
    orgId: input.orgId,
    challengeId: `challenge-${input.grantToken}`,
    otpChannel: 'email_otp',
    sessionHash: 'session-hash-a',
    appSessionVersion: input.appSessionVersion,
    action: 'wallet_email_otp_unseal',
    issuedAtMs: Date.now() - 1_000,
    expiresAtMs: Date.now() + 60_000,
  };
}

function emailOtpRecoveryEscrowRecord(input: {
  readonly orgId: string;
  readonly recoveryKeyId: string;
  readonly recoveryKeyStatus: 'active' | 'consumed' | 'revoked';
  readonly issuedAtMs: number;
  readonly updatedAtMs: number;
}) {
  return {
    version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
    alg: 'chacha20poly1305-hkdf-sha256-v1',
    secretKind: 'email_otp_device_enrollment_escrow',
    escrowKind: 'recovery_wrapped_enrollment_escrow',
    walletId: 'email-wallet.testnet',
    userId: 'google:email-user',
    authSubjectId: 'google:email-user',
    authMethod: 'google_sso_email_otp',
    enrollmentId: 'enrollment-a',
    enrollmentVersion: 'enrollment-v1',
    enrollmentSealKeyVersion: 'seal-v1',
    signingRootId: 'project-a:env-a',
    signingRootVersion: 'root-v1',
    recoveryKeyId: input.recoveryKeyId,
    recoveryKeyStatus: input.recoveryKeyStatus,
    nonceB64u: `nonce-${input.recoveryKeyId}`,
    wrappedDeviceEnrollmentEscrowB64u: `wrapped-${input.recoveryKeyId}`,
    aadHashB64u: `aad-${input.recoveryKeyId}`,
    issuedAtMs: input.issuedAtMs,
    updatedAtMs: input.updatedAtMs,
    ...(input.recoveryKeyStatus === 'consumed' ? { consumedAtMs: input.updatedAtMs } : {}),
    ...(input.recoveryKeyStatus === 'revoked' ? { revokedAtMs: input.updatedAtMs } : {}),
  };
}

type RecoveryRotationEscrowInput = {
  readonly recoveryKeyId: string;
  readonly nonceB64u: string;
  readonly wrappedDeviceEnrollmentEscrowB64u: string;
  readonly aadHashB64u: string;
};

function makeRecoveryRotationEscrowInputs(): RecoveryRotationEscrowInput[] {
  const inputs: RecoveryRotationEscrowInput[] = [];
  for (let index = 1; index <= 10; index += 1) {
    inputs.push(recoveryRotationEscrowInput(index));
  }
  return inputs;
}

function recoveryRotationEscrowInput(index: number): RecoveryRotationEscrowInput {
  const recoveryKeyId = `rotated-recovery-${index}`;
  const binding = buildEmailOtpRecoveryWrapBinding({
    walletId: 'email-wallet.testnet',
    userId: 'google:email-user',
    authSubjectId: 'google:email-user',
    authMethod: 'google_sso_email_otp',
    enrollmentId: 'enrollment-a',
    enrollmentVersion: 'enrollment-v1',
    enrollmentSealKeyVersion: 'seal-v1',
    signingRootId: 'project-a:env-a',
    signingRootVersion: 'root-v1',
    recoveryKeyId,
  });
  return {
    recoveryKeyId,
    nonceB64u: base64UrlEncode(new Uint8Array(12).fill(index)),
    wrappedDeviceEnrollmentEscrowB64u: base64UrlEncode(new Uint8Array(32).fill(index + 10)),
    aadHashB64u: base64UrlEncode(
      createHash('sha256')
        .update(encodeEmailOtpRecoveryWrappedEnrollmentAad(binding))
        .digest(),
    ),
  };
}

async function readRecoveryEscrowStatusCounts(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
}): Promise<Record<string, number>> {
  const result = await input.database
    .prepare(
      `SELECT recovery_key_status, COUNT(*) AS count
         FROM signer_email_otp_recovery_wrapped_enrollment_escrows
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        GROUP BY recovery_key_status`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      'email-wallet.testnet',
    )
    .all<SqliteJsonRow>();
  const counts: Record<string, number> = {};
  for (const row of result.results || []) {
    const status = String(row.recovery_key_status || '').trim();
    if (status) counts[status] = toInteger(row.count);
  }
  return counts;
}

async function insertRecoverySession(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly sessionId: string;
  readonly status?: 'prepared' | 'verified' | 'near_recovered' | 'failed';
  readonly metadata?: Record<string, unknown>;
}): Promise<void> {
  const record = recoverySessionRecord(input);
  await input.database
    .prepare(
      `INSERT INTO signer_recovery_sessions (
        namespace, org_id, project_id, env_id, session_id, near_account_id, record_json,
        expires_at_ms, created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      record.sessionId,
      record.nearAccountId,
      JSON.stringify(record),
      record.expiresAtMs,
      record.createdAtMs,
      record.updatedAtMs,
    )
    .run();
}

function recoverySessionRecord(input: {
  readonly sessionId: string;
  readonly status?: 'prepared' | 'verified' | 'near_recovered' | 'failed';
  readonly metadata?: Record<string, unknown>;
}) {
  return {
    version: 'recovery_session_v1',
    sessionId: input.sessionId,
    userId: 'recovery-user',
    nearAccountId: 'alice.testnet',
    signerSlot: 1,
    status: input.status || 'prepared',
    createdAtMs: 1_000,
    updatedAtMs: 1_100,
    expiresAtMs: Date.now() + 60_000,
    newNearPublicKey: 'ed25519:new-public-key',
    newEvmOwnerAddress: '0x00000000000000000000000000000000000000aa',
    recoveryDeadlineEpochSeconds: Math.floor(Date.now() / 1_000) + 3_600,
    recoveryEmailPayloadHash: 'recovery-payload-hash',
    ...(input.metadata ? { metadata: input.metadata } : {}),
  };
}

test('Cloudflare D1 relay auth service reads signer metadata with tenant scope', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      userId: 'wallet-a',
    };
    await insertIdentity({ database, ...scope, subject: 'google:alice' });
    await insertIdentity({ database, ...scope, orgId: 'org-b', subject: 'google:bob' });
    await insertIdentity({
      database,
      ...scope,
      userId: 'linked.testnet',
      subject: 'wallet:oidc:linked',
    });
    await insertWebAuthn({ database, ...scope });
    await insertNearPublicKey({ database, ...scope });
    await insertEmailOtpEnrollment({ database, ...scope });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-active',
      recoveryKeyStatus: 'active',
      issuedAtMs: 900,
      updatedAtMs: 910,
    });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-consumed',
      recoveryKeyStatus: 'consumed',
      issuedAtMs: 880,
      updatedAtMs: 920,
    });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-revoked',
      recoveryKeyStatus: 'revoked',
      issuedAtMs: 890,
      updatedAtMs: 930,
    });
    await insertEmailOtpGrant({
      database,
      ...scope,
      grantToken: 'grant-valid',
      appSessionVersion: 'grant-session-v1',
    });
    await insertEmailOtpGrant({
      database,
      ...scope,
      grantToken: 'grant-mismatch',
      appSessionVersion: 'grant-session-v2',
    });

    const service = createCloudflareD1RelayAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      relayerAccount: 'relay.local',
      relayerPublicKey: 'relay-public-key',
      googleOidcClientId: 'google-client',
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
    });

    await expect(service.listIdentities({ userId: scope.userId })).resolves.toEqual({
      ok: true,
      subjects: ['google:alice'],
    });
    await expect(
      service.linkIdentity({ userId: 'wallet-b', subject: 'google:alice' }),
    ).resolves.toMatchObject({ ok: false, code: 'already_linked' });
    await expect(
      service.linkIdentity({ userId: scope.userId, subject: 'google:carol' }),
    ).resolves.toEqual({ ok: true });
    await expect(service.listIdentities({ userId: scope.userId })).resolves.toEqual({
      ok: true,
      subjects: ['google:alice', 'google:carol'],
    });
    await expect(
      service.unlinkIdentity({ userId: scope.userId, subject: 'google:alice' }),
    ).resolves.toEqual({ ok: true });
    await expect(service.listIdentities({ userId: scope.userId })).resolves.toEqual({
      ok: true,
      subjects: ['google:carol'],
    });
    await expect(
      service.unlinkIdentity({ userId: scope.userId, subject: 'google:carol' }),
    ).resolves.toMatchObject({ ok: false, code: 'cannot_unlink_last_identity' });
    await insertIdentity({
      database,
      ...scope,
      userId: 'wallet-solo',
      subject: 'google:solo',
    });
    await expect(
      service.linkIdentity({
        userId: scope.userId,
        subject: 'google:solo',
        allowMoveIfSoleIdentity: true,
      }),
    ).resolves.toEqual({ ok: true, movedFromUserId: 'wallet-solo' });
    await expect(service.listIdentities({ userId: 'wallet-solo' })).resolves.toEqual({
      ok: true,
      subjects: [],
    });
    await insertIdentity({
      database,
      ...scope,
      userId: 'wallet-many',
      subject: 'google:many-a',
    });
    await insertIdentity({
      database,
      ...scope,
      userId: 'wallet-many',
      subject: 'google:many-b',
    });
    await expect(
      service.linkIdentity({
        userId: scope.userId,
        subject: 'google:many-a',
        allowMoveIfSoleIdentity: true,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'already_linked' });
    await expect(
      service.resolveOidcWalletId({
        providerSubject: 'oidc:linked',
        runtimePolicyScope: {
          orgId: scope.orgId,
          projectId: scope.projectId,
          envId: scope.envId,
          signingRootVersion: 'v1',
        },
      }),
    ).resolves.toBe('linked.testnet');
    const derivedOidcWalletId = await service.resolveOidcWalletId({
      providerSubject: 'oidc:new-user',
      email: 'new-user@example.test',
      runtimePolicyScope: {
        orgId: scope.orgId,
        projectId: scope.projectId,
        envId: scope.envId,
        signingRootVersion: 'v1',
      },
    });
    expect(derivedOidcWalletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relay\.local$/);
    await expect(
      service.readEmailOtpEnrollment({
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
      }),
    ).resolves.toMatchObject({
      ok: true,
      enrollment: {
        walletId: 'email-wallet.testnet',
        providerUserId: 'google:email-user',
        orgId: scope.orgId,
        verifiedEmail: 'alice@example.test',
      },
    });
    await expect(
      service.readActiveEmailOtpEnrollment({
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        providerUserId: 'google:other-user',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'provider_identity_mismatch' });
    await expect(
      service.readActiveEmailOtpEnrollment({
        walletId: 'email-wallet.testnet',
        orgId: 'org-b',
        providerUserId: 'google:email-user',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'tenant_scope_mismatch' });
    await expect(
      service.isEmailOtpStrongAuthRequired({ walletId: 'email-wallet.testnet' }),
    ).resolves.toEqual({
      ok: true,
      required: false,
      walletId: 'email-wallet.testnet',
    });
    await insertEmailOtpAuthState({ database, ...scope });
    await expect(
      service.isEmailOtpStrongAuthRequired({ walletId: 'email-wallet.testnet' }),
    ).resolves.toEqual({
      ok: true,
      required: true,
      walletId: 'email-wallet.testnet',
      lastEmailOtpLoginAtMs: 800,
    });
    const strongAuth = await service.markEmailOtpStrongAuthSatisfied({
      walletId: 'email-wallet.testnet',
    });
    expect(strongAuth.ok).toBe(true);
    if (!strongAuth.ok) throw new Error(strongAuth.message);
    expect(strongAuth.lastStrongAuthAtMs).toBeGreaterThanOrEqual(800);
    await expect(
      service.isEmailOtpStrongAuthRequired({ walletId: 'email-wallet.testnet' }),
    ).resolves.toMatchObject({
      ok: true,
      required: false,
      walletId: 'email-wallet.testnet',
      lastEmailOtpLoginAtMs: 800,
      lastStrongAuthAtMs: strongAuth.lastStrongAuthAtMs,
    });
    await expect(
      service.getEmailOtpRecoveryCodeStatus({
        userId: 'google:not-enrolled',
        walletId: 'missing-email-wallet.testnet',
        orgId: scope.orgId,
      }),
    ).resolves.toEqual({
      ok: true,
      status: 'not_enrolled',
      walletId: 'missing-email-wallet.testnet',
      enrollmentId: '',
      enrollmentSealKeyVersion: '',
      expectedRecoveryCodeCount: 10,
      activeRecoveryCodeCount: 0,
      consumedRecoveryCodeCount: 0,
      revokedRecoveryCodeCount: 0,
      totalRecoveryCodeCount: 0,
      issuedAtMs: null,
    });
    await expect(
      service.getEmailOtpRecoveryCodeStatus({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
      }),
    ).resolves.toEqual({
      ok: true,
      status: 'incomplete',
      walletId: 'email-wallet.testnet',
      enrollmentId: 'enrollment-a',
      enrollmentSealKeyVersion: 'seal-v1',
      expectedRecoveryCodeCount: 10,
      activeRecoveryCodeCount: 1,
      consumedRecoveryCodeCount: 1,
      revokedRecoveryCodeCount: 1,
      totalRecoveryCodeCount: 3,
      issuedAtMs: 880,
    });
    await expect(
      service.consumeEmailOtpGrant({
        loginGrant: 'grant-valid',
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'grant-session-v1',
      }),
    ).resolves.toEqual({
      ok: true,
      challengeId: 'challenge-grant-valid',
      otpChannel: 'email_otp',
    });
    await expect(
      service.consumeEmailOtpGrant({
        loginGrant: 'grant-valid',
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'grant-session-v1',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'login_grant_invalid_or_expired' });
    await expect(
      service.consumeEmailOtpGrant({
        loginGrant: 'grant-mismatch',
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'wrong-session',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'recovery_grant_binding_mismatch' });
    await expect(
      service.consumeEmailOtpGrant({
        loginGrant: 'grant-mismatch',
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'grant-session-v2',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'login_grant_invalid_or_expired' });
    const session = await service.getOrCreateAppSessionVersion({ userId: scope.userId });
    expect(session.ok).toBe(true);
    if (!session.ok) throw new Error(session.message);
    await expect(
      service.validateAppSessionVersion({
        userId: scope.userId,
        appSessionVersion: session.appSessionVersion,
      }),
    ).resolves.toEqual({ ok: true });
    const rotated = await service.rotateAppSessionVersion({ userId: scope.userId });
    expect(rotated.ok).toBe(true);
    if (!rotated.ok) throw new Error(rotated.message);
    await expect(
      service.validateAppSessionVersion({
        userId: scope.userId,
        appSessionVersion: session.appSessionVersion,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_session_version' });
    await expect(
      service.listWebAuthnAuthenticatorsForUser({ userId: scope.userId, rpId: 'example.com' }),
    ).resolves.toMatchObject({
      ok: true,
      authenticators: [
        {
          credentialIdB64u: 'credential-a',
          signerSlot: 2,
          publicKey: 'ed25519:public',
          createdAtMs: 200,
          updatedAtMs: 300,
        },
      ],
    });
    const loginOptions = await service.createWebAuthnLoginOptions({
      userId: scope.userId,
      rpId: 'example.com',
      ttlMs: 60_000,
    });
    expect(loginOptions.ok).toBe(true);
    if (!loginOptions.ok) throw new Error(loginOptions.message);
    const loginChallengeId = String(loginOptions.challengeId || '');
    expect(loginChallengeId).not.toBe('');
    expect(loginOptions.challengeB64u).toEqual(expect.any(String));
    expect(loginOptions.expiresAtMs).toBeGreaterThan(Date.now());
    const loginChallengeRow = await readWebAuthnChallengeRow({
      database,
      ...scope,
      challengeId: loginChallengeId,
    });
    expect(loginChallengeRow?.challenge_kind).toBe('login');
    expect(loginChallengeRow?.created_at_ms).toEqual(expect.any(Number));
    expect(loginChallengeRow?.expires_at_ms).toBe(loginOptions.expiresAtMs);
    const rawLoginChallengeRecord = loginChallengeRow?.record_json;
    if (typeof rawLoginChallengeRecord !== 'string') {
      throw new Error('Expected WebAuthn login challenge record_json');
    }
    const loginChallengeRecord: unknown = JSON.parse(rawLoginChallengeRecord);
    expect(loginChallengeRecord).toMatchObject({
      version: 'webauthn_login_challenge_v1',
      challengeId: loginChallengeId,
      userId: scope.userId,
      rpId: 'example.com',
      challengeB64u: loginOptions.challengeB64u,
      expiresAtMs: loginOptions.expiresAtMs,
    });
    await expect(
      service.createWebAuthnLoginOptions({ userId: 'bad user', rpId: 'example.com' }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'Invalid userId',
    });
    const syncOptions = await service.createWebAuthnSyncAccountOptions({
      rp_id: 'example.com',
      account_id: scope.userId,
      ttl_ms: 60_000,
    });
    expect(syncOptions.ok).toBe(true);
    if (!syncOptions.ok) throw new Error(syncOptions.message);
    const syncChallengeId = String(syncOptions.challengeId || '');
    expect(syncChallengeId).not.toBe('');
    expect(syncOptions.challengeB64u).toEqual(expect.any(String));
    expect(syncOptions.credentialIds).toEqual(['credential-a']);
    expect(syncOptions.walletBinding).toEqual({
      walletId: scope.userId,
      nearAccountId: 'near.testnet',
      nearEd25519SigningKeyId: 'ed25519:key',
      rpId: 'example.com',
      signerSlot: 2,
    });
    const syncChallengeRow = await readWebAuthnChallengeRow({
      database,
      ...scope,
      challengeId: syncChallengeId,
    });
    expect(syncChallengeRow?.challenge_kind).toBe('sync');
    expect(syncChallengeRow?.expires_at_ms).toBe(syncOptions.expiresAtMs);
    const rawSyncChallengeRecord = syncChallengeRow?.record_json;
    if (typeof rawSyncChallengeRecord !== 'string') {
      throw new Error('Expected WebAuthn sync challenge record_json');
    }
    const syncChallengeRecord: unknown = JSON.parse(rawSyncChallengeRecord);
    expect(syncChallengeRecord).toMatchObject({
      version: 'webauthn_sync_challenge_v1',
      challengeId: syncChallengeId,
      rpId: 'example.com',
      expectedUserId: scope.userId,
      challengeB64u: syncOptions.challengeB64u,
      expiresAtMs: syncOptions.expiresAtMs,
    });
    await expect(
      service.createWebAuthnSyncAccountOptions({
        account_id: scope.userId,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'Missing rp_id',
    });
    await expect(service.listNearPublicKeysForUser({ userId: scope.userId })).resolves.toEqual({
      ok: true,
      keys: [
        {
          publicKey: 'ed25519:near-public',
          kind: 'threshold',
          signerSlot: 1,
          createdAtMs: 400,
          updatedAtMs: 500,
          rpId: 'example.com',
          credentialIdB64u: 'credential-a',
        },
      ],
    });
    expect(service.getConfiguredRelayerAccount()).toBe('relay.local');
    await expect(service.getRelayerAccount()).resolves.toEqual({
      accountId: 'relay.local',
      publicKey: 'relay-public-key',
    });
    expect(service.getGoogleOidcPublicConfig()).toEqual({
      configured: true,
      clientId: 'google-client',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 relay auth service verifies Google OIDC tokens and links identity', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  const key = await generateGoogleOidcTestKey('google-kid-success');
  const originalFetch = installGoogleJwksFetchMock(key.publicJwk);
  try {
    await applySignerMigrations(database);
    const service = createCloudflareD1RelayAuthService({
      database,
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      relayerAccount: 'relay.local',
      googleOidcClientId: 'google-client',
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
    });
    const nowSec = Math.floor(Date.now() / 1000);
    const idToken = await makeSignedGoogleIdToken({
      privateKey: key.privateKey,
      kid: key.kid,
      payload: {
        iss: 'https://accounts.google.com',
        aud: 'google-client',
        sub: 'subject-123',
        email: 'Alice@Example.Test',
        email_verified: true,
        name: 'Alice Example',
        given_name: 'Alice',
        family_name: 'Example',
        hd: 'example.test',
        iat: nowSec,
        exp: nowSec + 300,
      },
    });

    const verified = await service.verifyGoogleLogin({ idToken });
    expect(verified).toMatchObject({
      ok: true,
      verified: true,
      userId: 'google:subject-123',
      providerSubject: 'google:subject-123',
      sub: 'subject-123',
      email: 'Alice@Example.Test',
      emailVerified: true,
      hostedDomain: 'example.test',
    });
    await expect(service.listIdentities({ userId: 'google:subject-123' })).resolves.toEqual({
      ok: true,
      subjects: ['google:subject-123'],
    });

    const parts = idToken.split('.');
    const tamperedPayloadB64u = jsonBase64Url({
      iss: 'https://accounts.google.com',
      aud: 'google-client',
      sub: 'subject-999',
      iat: nowSec,
      exp: nowSec + 300,
    });
    const tampered = `${parts[0]}.${tamperedPayloadB64u}.${parts[2]}`;
    await expect(service.verifyGoogleLogin({ idToken: tampered })).resolves.toMatchObject({
      ok: false,
      verified: false,
      code: 'invalid_signature',
    });
  } finally {
    restoreGoogleJwksFetchMock(originalFetch);
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 relay auth service starts, reuses, and restarts Google Email OTP registration attempts', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const runtimePolicyScope = {
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      signingRootVersion: 'root-v1',
    };
    const service = createCloudflareD1RelayAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      relayerAccount: 'relay.local',
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
    });
    const appSession = await service.getOrCreateAppSessionVersion({
      userId: 'google:register-user',
    });
    expect(appSession.ok).toBe(true);
    if (!appSession.ok) throw new Error(appSession.message);

    const rateLimit = await service.consumeGoogleEmailOtpRegistrationAttemptRateLimit({
      providerSubject: 'google:register-user',
      email: 'Alice@Example.Test',
      accountMode: 'register',
      runtimePolicyScope,
      appSessionUserId: 'google:register-user',
      clientIp: '203.0.113.10',
    });
    expect(rateLimit).toEqual({ ok: true });

    const first = await service.resolveGoogleEmailOtpSession({
      providerSubject: 'google:register-user',
      email: 'Alice@Example.Test',
      accountMode: 'register',
      appSessionVersion: appSession.appSessionVersion,
      runtimePolicyScope,
    });
    expect(first.ok).toBe(true);
    expect(first.mode).toBe('register_started');
    if (!first.ok || first.mode !== 'register_started') return;
    expect(first.walletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relay\.local$/);
    expect(first.email).toBe('alice@example.test');
    expect(first.offer.candidates).toHaveLength(5);
    expect(first.offer.selectedCandidateId).toBe(first.offer.candidates[0].candidateId);

    const reused = await service.resolveGoogleEmailOtpSession({
      providerSubject: 'google:register-user',
      email: 'alice@example.test',
      accountMode: 'register',
      appSessionVersion: appSession.appSessionVersion,
      runtimePolicyScope,
    });
    expect(reused.ok).toBe(true);
    expect(reused.mode).toBe('register_started');
    if (!reused.ok || reused.mode !== 'register_started') return;
    expect(reused.registrationAttemptId).toBe(first.registrationAttemptId);
    expect(reused.walletId).toBe(first.walletId);

    const rowsAfterReuse = await listGoogleEmailOtpRegistrationAttemptRows({
      database,
      ...scope,
    });
    expect(rowsAfterReuse).toHaveLength(1);
    expect(rowsAfterReuse[0].state).toBe('started');
    expect(rowsAfterReuse[0].app_session_version).toBe(appSession.appSessionVersion);
    expect(rowsAfterReuse[0].runtime_org_id).toBe(scope.orgId);
    expect(rowsAfterReuse[0].runtime_policy_key).toBe(
      `${scope.orgId}\n${scope.projectId}\n${scope.envId}\nroot-v1`,
    );
    const stored = registrationAttemptRecordFromRow(rowsAfterReuse[0]);
    expect(stored.providerSubject).toBe('google:register-user');
    expect(stored.walletId).toBe(first.walletId);
    expect(stored.runtimePolicyScope).toEqual(runtimePolicyScope);

    const restarted = await service.resolveGoogleEmailOtpSession({
      providerSubject: 'google:register-user',
      email: 'alice@example.test',
      accountMode: 'register',
      appSessionVersion: appSession.appSessionVersion,
      runtimePolicyScope,
      restartRegistrationOffer: true,
    });
    expect(restarted.ok).toBe(true);
    expect(restarted.mode).toBe('register_started');
    if (!restarted.ok || restarted.mode !== 'register_started') return;
    expect(restarted.registrationAttemptId).not.toBe(first.registrationAttemptId);

    const rowsAfterRestart = await listGoogleEmailOtpRegistrationAttemptRows({
      database,
      ...scope,
    });
    expect(rowsAfterRestart).toHaveLength(2);
    const states: unknown[] = [];
    for (const row of rowsAfterRestart) states.push(row.state);
    states.sort();
    expect(states).toEqual(['abandoned', 'started']);

    await expect(
      service.linkIdentity({
        userId: first.walletId,
        subject: 'wallet:google:register-user',
      }),
    ).resolves.toEqual({ ok: true });
    const cleaned = await service.cleanupGoogleEmailOtpDevRegistrationState({
      providerSubject: 'google:register-user',
      walletId: first.walletId,
      orgId: scope.orgId,
      nowMs: Date.now() + 31 * 60_000,
    });
    expect(cleaned).toEqual({
      ok: true,
      providerSubject: 'google:register-user',
      expiredRegistrationAttemptsDeleted: 2,
      linkedWalletId: first.walletId,
      orphanedWalletMappingRemoved: true,
    });
    await expect(service.listIdentities({ userId: first.walletId })).resolves.toEqual({
      ok: true,
      subjects: [],
    });
    await expect(
      listGoogleEmailOtpRegistrationAttemptRows({
        database,
        ...scope,
      }),
    ).resolves.toEqual([]);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 relay auth service rate-limits Google Email OTP registration attempts', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const runtimePolicyScope = {
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      signingRootVersion: 'root-v1',
    };
    const service = createCloudflareD1RelayAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpGoogleRegistrationAttemptRateLimitMax: 1,
      emailOtpGoogleRegistrationAttemptRateLimitWindowMs: 60_000,
    });

    const first = await service.consumeGoogleEmailOtpRegistrationAttemptRateLimit({
      providerSubject: 'google:rate-user',
      email: 'rate@example.test',
      accountMode: 'register',
      runtimePolicyScope,
      appSessionUserId: 'google:rate-user',
      clientIp: '203.0.113.20',
    });
    expect(first).toEqual({ ok: true });

    const second = await service.consumeGoogleEmailOtpRegistrationAttemptRateLimit({
      providerSubject: 'google:rate-user',
      email: 'rate@example.test',
      accountMode: 'register',
      runtimePolicyScope,
      appSessionUserId: 'google:rate-user',
      clientIp: '203.0.113.20',
    });
    expect(second.ok).toBe(false);
    if (second.ok) return;
    expect(second.code).toBe('rate_limited');
    expect(second.retryAfterMs).toBeGreaterThan(0);
    expect(second.resetAtMs).toBeGreaterThan(Date.now());
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 relay auth service rotates Email OTP recovery keys after fresh auth', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });
    await insertEmailOtpAuthState({ database, ...scope });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-old-active',
      recoveryKeyStatus: 'active',
      issuedAtMs: 900,
      updatedAtMs: 910,
    });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-old-consumed',
      recoveryKeyStatus: 'consumed',
      issuedAtMs: 920,
      updatedAtMs: 930,
    });

    const service = createCloudflareD1RelayAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpGrantTtlMs: 60_000,
    });
    const freshAuth = await service.markEmailOtpStrongAuthSatisfied({
      walletId: 'email-wallet.testnet',
    });
    expect(freshAuth.ok).toBe(true);
    if (!freshAuth.ok) throw new Error(freshAuth.message);

    const rotated = await service.rotateEmailOtpRecoveryKeys({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      enrollmentId: 'enrollment-a',
      enrollmentSealKeyVersion: 'seal-v1',
      recoveryWrappedEnrollmentEscrows: makeRecoveryRotationEscrowInputs(),
    });
    expect(rotated.ok).toBe(true);
    if (!rotated.ok) throw new Error(rotated.message);
    expect(rotated).toMatchObject({
      walletId: 'email-wallet.testnet',
      enrollmentId: 'enrollment-a',
      enrollmentSealKeyVersion: 'seal-v1',
      activeRecoveryCodeCount: 10,
      revokedRecoveryCodeCount: 1,
      totalRecoveryCodeCount: 12,
    });

    const counts = await readRecoveryEscrowStatusCounts({ database, ...scope });
    expect(counts).toEqual({ active: 10, consumed: 1, revoked: 1 });
    await expect(
      service.getEmailOtpRecoveryCodeStatus({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
      }),
    ).resolves.toMatchObject({
      ok: true,
      status: 'ready',
      activeRecoveryCodeCount: 10,
      consumedRecoveryCodeCount: 1,
      revokedRecoveryCodeCount: 1,
      totalRecoveryCodeCount: 12,
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 relay auth service rejects stale Email OTP recovery-key rotation', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });
    await insertEmailOtpAuthState({ database, ...scope });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-old-active',
      recoveryKeyStatus: 'active',
      issuedAtMs: 900,
      updatedAtMs: 910,
    });

    const service = createCloudflareD1RelayAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpGrantTtlMs: 60_000,
    });
    await expect(
      service.rotateEmailOtpRecoveryKeys({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        enrollmentId: 'enrollment-a',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryWrappedEnrollmentEscrows: makeRecoveryRotationEscrowInputs(),
      }),
    ).resolves.toMatchObject({ ok: false, code: 'fresh_auth_required' });

    const counts = await readRecoveryEscrowStatusCounts({ database, ...scope });
    expect(counts).toEqual({ active: 1 });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 relay auth service rejects invalid Email OTP recovery-key rotation payloads', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });
    await insertEmailOtpAuthState({ database, ...scope });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-old-active',
      recoveryKeyStatus: 'active',
      issuedAtMs: 900,
      updatedAtMs: 910,
    });

    const service = createCloudflareD1RelayAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpGrantTtlMs: 60_000,
    });
    const freshAuth = await service.markEmailOtpStrongAuthSatisfied({
      walletId: 'email-wallet.testnet',
    });
    expect(freshAuth.ok).toBe(true);
    if (!freshAuth.ok) throw new Error(freshAuth.message);

    const duplicateInputs = makeRecoveryRotationEscrowInputs();
    duplicateInputs[1] = {
      ...duplicateInputs[1],
      recoveryKeyId: duplicateInputs[0].recoveryKeyId,
      aadHashB64u: duplicateInputs[0].aadHashB64u,
    };
    await expect(
      service.rotateEmailOtpRecoveryKeys({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        enrollmentId: 'enrollment-a',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryWrappedEnrollmentEscrows: duplicateInputs,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_body' });

    const badAadInputs = makeRecoveryRotationEscrowInputs();
    badAadInputs[0] = {
      ...badAadInputs[0],
      aadHashB64u: base64UrlEncode(new Uint8Array(32).fill(250)),
    };
    await expect(
      service.rotateEmailOtpRecoveryKeys({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        enrollmentId: 'enrollment-a',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryWrappedEnrollmentEscrows: badAadInputs,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_body' });

    const counts = await readRecoveryEscrowStatusCounts({ database, ...scope });
    expect(counts).toEqual({ active: 1 });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 relay auth service tracks recovery sessions and executions', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertRecoverySession({
      database,
      ...scope,
      sessionId: 'recovery-session-a',
      metadata: { source: 'fixture' },
    });

    const service = createCloudflareD1RelayAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
    });

    const initial = await service.getRecoverySession({ sessionId: 'recovery-session-a' });
    expect(initial.ok).toBe(true);
    if (!initial.ok) throw new Error(initial.message);
    expect(initial.record).toMatchObject({
      sessionId: 'recovery-session-a',
      status: 'prepared',
      nearAccountId: 'alice.testnet',
      metadata: { source: 'fixture' },
    });

    const updated = await service.updateRecoverySessionStatus({
      sessionId: 'recovery-session-a',
      status: 'verified',
      metadataPatch: {
        verifiedAtMs: 1_250,
      },
    });
    expect(updated.ok).toBe(true);
    if (!updated.ok) throw new Error(updated.message);
    expect(updated.record).toMatchObject({
      sessionId: 'recovery-session-a',
      status: 'verified',
      metadata: { source: 'fixture', verifiedAtMs: 1_250 },
    });
    expect(updated.record.updatedAtMs).toBeGreaterThanOrEqual(updated.record.createdAtMs);

    const pending = await service.recordRecoveryExecution({
      sessionId: 'recovery-session-a',
      chainIdKey: 'NEAR:TESTNET',
      accountAddress: 'alice.testnet',
      action: 'near_email_recovery',
      status: 'pending',
      metadata: {
        expectedNewNearPublicKey: 'ed25519:new-public-key',
      },
    });
    expect(pending.ok).toBe(true);
    if (!pending.ok) throw new Error(pending.message);
    expect(pending.record).toMatchObject({
      sessionId: 'recovery-session-a',
      userId: 'recovery-user',
      nearAccountId: 'alice.testnet',
      chainIdKey: 'near:testnet',
      accountAddress: 'alice.testnet',
      action: 'near_email_recovery',
      status: 'pending',
    });

    const submitted = await service.recordRecoveryExecution({
      sessionId: 'recovery-session-a',
      chainIdKey: 'near:testnet',
      accountAddress: 'alice.testnet',
      action: 'near_email_recovery',
      status: 'submitted',
      transactionHash: 'near-tx-a',
    });
    expect(submitted.ok).toBe(true);
    if (!submitted.ok) throw new Error(submitted.message);
    expect(submitted.record).toMatchObject({
      status: 'submitted',
      transactionHash: 'near-tx-a',
    });
    expect(submitted.record.createdAtMs).toBe(pending.record.createdAtMs);

    const executionRow = await database
      .prepare(
        `SELECT status, record_json
           FROM signer_recovery_executions
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND session_id = ?
            AND chain_id_key = ?
            AND account_address = ?
            AND action = ?
          LIMIT 1`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        'recovery-session-a',
        'near:testnet',
        'alice.testnet',
        'near_email_recovery',
      )
      .first<SqliteJsonRow>();
    expect(executionRow?.status).toBe('submitted');
    expect(JSON.parse(String(executionRow?.record_json || '{}'))).toMatchObject({
      transactionHash: 'near-tx-a',
    });

    await expect(
      service.recordRecoveryExecution({
        sessionId: 'missing-session',
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
        action: 'near_email_recovery',
        status: 'pending',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_args' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 relay auth service issues and verifies login Email OTP challenges', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });

    const service = createCloudflareD1RelayAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'memory',
      emailOtpMaxAttempts: 2,
    });

    const challenge = await service.createEmailOtpChallenge({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      otpChannel: 'email_otp',
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
      operation: 'wallet_unlock',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    expect(challenge.delivery).toMatchObject({
      status: 'sent',
      mode: 'memory',
      emailHint: 'a***e@e***e.test',
    });

    const outbox = await service.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);
    expect(outbox.otpCode).toMatch(/^[0-9]{6}$/);

    await expect(
      service.verifyEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        challengeId: challenge.challenge.challengeId,
        otpCode: '000000' === outbox.otpCode ? '111111' : '000000',
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_otp', attemptsRemaining: 1 });

    const verified = await service.verifyEmailOtpChallenge({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      challengeId: challenge.challenge.challengeId,
      otpCode: outbox.otpCode,
      otpChannel: 'email_otp',
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
      operation: 'wallet_unlock',
    });
    expect(verified.ok).toBe(true);
    if (!verified.ok) throw new Error(verified.message);
    expect(verified.challengeId).toBe(challenge.challenge.challengeId);
    expect(verified.loginGrant).toMatch(/^[A-Za-z0-9_-]+$/);

    await expect(
      service.readEmailOtpOutboxEntry({
        challengeId: challenge.challenge.challengeId,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'not_found' });
    await expect(
      service.verifyEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'challenge_expired_or_invalid' });

    await expect(
      service.consumeEmailOtpGrant({
        loginGrant: verified.loginGrant,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
      }),
    ).resolves.toEqual({
      ok: true,
      challengeId: challenge.challenge.challengeId,
      otpChannel: 'email_otp',
    });
    await expect(
      service.consumeEmailOtpGrant({
        loginGrant: verified.loginGrant,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'login_grant_invalid_or_expired' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 relay auth service delivers Email OTP through configured provider', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });
    const provider = new RecordingEmailOtpDeliveryProvider();

    const service = createCloudflareD1RelayAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'email_provider',
      emailOtpDeliveryProvider: provider,
      emailOtpProduction: true,
    });

    const challenge = await service.createEmailOtpChallenge({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      otpChannel: 'email_otp',
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
      operation: 'wallet_unlock',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    expect(challenge.delivery).toMatchObject({
      status: 'sent',
      mode: 'email_provider',
      emailHint: 'a***e@e***e.test',
    });
    expect(provider.calls).toHaveLength(1);
    expect(provider.calls[0]).toMatchObject({
      challengeId: challenge.challenge.challengeId,
      walletId: 'email-wallet.testnet',
      userId: 'google:email-user',
      orgId: scope.orgId,
      email: 'alice@example.test',
      emailHint: 'a***e@e***e.test',
      otpChannel: 'email_otp',
      action: 'wallet_email_otp_login',
      operation: 'wallet_unlock',
      expiresAtMs: challenge.challenge.expiresAtMs,
    });
    expect(provider.calls[0]?.otpCode).toMatch(/^[0-9]{6}$/);

    await expect(
      service.readEmailOtpOutboxEntry({
        challengeId: challenge.challenge.challengeId,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'not_found' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 relay auth service fails closed when Email OTP provider is missing', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });

    const service = createCloudflareD1RelayAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'email_provider',
      emailOtpProduction: true,
    });

    await expect(
      service.createEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'email_otp_delivery_not_configured',
    });

    const challengeRows = await database
      .prepare(
        `SELECT challenge_id
           FROM signer_email_otp_challenges
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?`,
      )
      .bind(scope.namespace, scope.orgId, scope.projectId, scope.envId)
      .all<SqliteJsonRow>();
    expect(challengeRows.results || []).toEqual([]);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 relay auth service issues and verifies device recovery Email OTP challenges', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-active',
      recoveryKeyStatus: 'active',
      issuedAtMs: 900,
      updatedAtMs: 910,
    });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-consumed',
      recoveryKeyStatus: 'consumed',
      issuedAtMs: 880,
      updatedAtMs: 920,
    });

    const service = createCloudflareD1RelayAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'memory',
      emailOtpRecoveryKeyAttemptRateLimitMax: 1,
      emailOtpRecoveryKeyAttemptRateLimitWindowMs: 60_000,
    });

    const challenge = await service.createEmailOtpDeviceRecoveryChallenge({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      otpChannel: 'email_otp',
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    expect(challenge.challenge).toMatchObject({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      action: 'wallet_email_otp_device_recovery',
      operation: 'wallet_unlock',
    });

    const outbox = await service.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);

    await expect(
      service.verifyEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'challenge_purpose_mismatch' });

    const verified = await service.verifyEmailOtpDeviceRecoveryChallenge({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      challengeId: challenge.challenge.challengeId,
      otpCode: outbox.otpCode,
      otpChannel: 'email_otp',
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
    });
    expect(verified.ok).toBe(true);
    if (!verified.ok) throw new Error(verified.message);
    expect(verified.challengeId).toBe(challenge.challenge.challengeId);
    expect(verified.recoveryConsumeGrant).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(verified.recoveryWrappedEnrollmentEscrows).toHaveLength(1);
    expect(verified.recoveryWrappedEnrollmentEscrows[0]).toMatchObject({
      walletId: 'email-wallet.testnet',
      userId: 'google:email-user',
      enrollmentId: 'enrollment-a',
      nonceB64u: 'nonce-recovery-active',
    });
    expect(
      Object.prototype.hasOwnProperty.call(
        verified.recoveryWrappedEnrollmentEscrows[0],
        'recoveryKeyId',
      ),
    ).toBe(false);
    expect(verified.enrollment).toMatchObject({
      walletId: 'email-wallet.testnet',
      providerUserId: 'google:email-user',
      recoveryWrappedEnrollmentEscrowCount: 3,
    });

    const grantRow = await database
      .prepare(
        `SELECT action
           FROM signer_email_otp_grants
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND grant_token = ?
          LIMIT 1`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        verified.recoveryConsumeGrant,
      )
      .first<SqliteJsonRow>();
    expect(grantRow?.action).toBe('wallet_email_otp_device_recovery');

    const failureReport = await service.recordEmailOtpRecoveryKeyAttemptFailure({
      recoveryConsumeGrant: verified.recoveryConsumeGrant,
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
      clientIp: '203.0.113.42',
    });
    expect(failureReport.ok).toBe(true);
    if (!failureReport.ok) throw new Error(failureReport.message);
    expect(failureReport.walletId).toBe('email-wallet.testnet');
    expect(failureReport.recordedAtMs).toBeGreaterThan(0);

    await expect(
      service.recordEmailOtpRecoveryKeyAttemptFailure({
        recoveryConsumeGrant: verified.recoveryConsumeGrant,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
        clientIp: '203.0.113.42',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'rate_limited' });

    const consumed = await service.consumeEmailOtpRecoveryKey({
      recoveryConsumeGrant: verified.recoveryConsumeGrant,
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      recoveryKeyId: 'recovery-active',
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
    });
    expect(consumed.ok).toBe(true);
    if (!consumed.ok) throw new Error(consumed.message);
    expect(consumed).toMatchObject({
      walletId: 'email-wallet.testnet',
      recoveryKeyId: 'recovery-active',
      activeRecoveryWrappedEnrollmentEscrowCount: 0,
    });
    expect(consumed.consumedAtMs).toBeGreaterThan(0);

    const consumedEscrowRow = await database
      .prepare(
        `SELECT recovery_key_status
           FROM signer_email_otp_recovery_wrapped_enrollment_escrows
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND wallet_id = ?
            AND recovery_key_id = ?
          LIMIT 1`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        'email-wallet.testnet',
        'recovery-active',
      )
      .first<SqliteJsonRow>();
    expect(consumedEscrowRow?.recovery_key_status).toBe('consumed');

    await expect(
      service.consumeEmailOtpRecoveryKey({
        recoveryConsumeGrant: verified.recoveryConsumeGrant,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        recoveryKeyId: 'recovery-active',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'recovery_consume_grant_invalid_or_expired',
    });

    await expect(
      service.verifyEmailOtpDeviceRecoveryChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'challenge_expired_or_invalid' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 relay auth service enforces Email OTP challenge rate limits', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });

    const service = createCloudflareD1RelayAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'memory',
      emailOtpChallengeRateLimitMax: 1,
      emailOtpChallengeRateLimitWindowMs: 60_000,
    });

    await expect(
      service.createEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({ ok: true });
    await expect(
      service.createEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-b',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'rate_limited' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 relay auth service verifies Email OTP unlock proofs once', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const privateKey32 = new Uint8Array(32);
    privateKey32[31] = 1;
    const publicKey33 = await secp256k1PrivateKey32ToPublicKey33(privateKey32);
    const publicKeyB64u = base64UrlEncode(publicKey33);
    await insertEmailOtpEnrollment({
      database,
      ...scope,
      clientUnlockPublicKeyB64u: publicKeyB64u,
    });

    const service = createCloudflareD1RelayAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
    });

    const challenge = await service.createEmailOtpUnlockChallenge({
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    expect(challenge.unlockKeyVersion).toBe('unlock-v1');

    const signature65 = await signSecp256k1Recoverable(
      base64UrlDecode(challenge.challengeB64u),
      privateKey32,
    );
    const verified = await service.verifyEmailOtpUnlockProof({
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      challengeId: challenge.challengeId,
      unlockProof: {
        publicKey: publicKeyB64u,
        signature: base64UrlEncode(signature65),
      },
    });
    expect(verified).toEqual({
      ok: true,
      verified: true,
      userId: 'email-wallet.testnet',
      walletId: 'email-wallet.testnet',
      unlockKeyVersion: 'unlock-v1',
    });

    await expect(
      service.verifyEmailOtpUnlockProof({
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        challengeId: challenge.challengeId,
        unlockProof: {
          publicKey: publicKeyB64u,
          signature: base64UrlEncode(signature65),
        },
      }),
    ).resolves.toMatchObject({ ok: false, code: 'challenge_expired_or_invalid' });
    await expect(
      service.isEmailOtpStrongAuthRequired({ walletId: 'email-wallet.testnet' }),
    ).resolves.toMatchObject({
      ok: true,
      required: true,
      walletId: 'email-wallet.testnet',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
