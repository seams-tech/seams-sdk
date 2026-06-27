import { expect, test } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import { createCloudflareD1RelayAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RelayAuthService';

type SqliteJsonRow = Record<string, unknown>;

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

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

function applySignerMigrations(database: D1DatabaseLike): Promise<void> {
  return applyMigrations(database, [
    'packages/sdk-server-ts/migrations/d1-signer/0003_signer_webauthn.sql',
    'packages/sdk-server-ts/migrations/d1-signer/0004_signer_identity.sql',
    'packages/sdk-server-ts/migrations/d1-signer/0006_signer_near_public_keys.sql',
    'packages/sdk-server-ts/migrations/d1-signer/0008_signer_email_otp.sql',
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
}): Promise<void> {
  const record = {
    version: 'email_otp_wallet_enrollment_v1',
    walletId: 'email-wallet.testnet',
    providerUserId: 'google:email-user',
    orgId: input.orgId,
    verifiedEmail: 'alice@example.test',
    enrollmentId: 'enrollment-a',
    enrollmentVersion: 'enrollment-v1',
    enrollmentSealKeyVersion: 'seal-v1',
    signingRootId: 'project-a:env-a',
    signingRootVersion: 'root-v1',
    recoveryWrappedEnrollmentEscrowCount: 3,
    clientUnlockPublicKeyB64u: 'client-unlock-public-key',
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
