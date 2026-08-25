import { expect, test } from '@playwright/test';
import { CloudflareD1EmailOtpEnrollmentStore } from '../../packages/wallet-server/src/router/cloudflare/d1/emailOtp/d1EmailOtpEnrollmentStore';
import type { D1DatabaseLike } from '../../packages/wallet-server/src/storage/tenantRoute';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';

/*
 * Refactor 109C separates two lifetimes that used to be conflated.
 *
 * Each Email method owns its own custody envelope, but every Email method on a
 * wallet unwraps through ONE shared provider enrollment — R109D depends on that
 * sharing. So revoking a method must leave the enrollment alone, and only the
 * loss of its last active or pending reference may remove it.
 */

const signerMigrations = listD1MigrationFiles('d1-signer');
const SCOPE = {
  namespace: 'r109c-enrollment-refs',
  orgId: 'tenant:r109c',
  projectId: 'project-a',
  envId: 'env-a',
} as const;
const WALLET_ID = 'alice.testnet';
const PROVIDER_USER_ID = 'google:117142622123955425762';
const EMAIL_HASH_HEX = 'ab'.repeat(32);

function scopedPrepare(database: D1DatabaseLike) {
  return (sql: string, values: readonly unknown[]) =>
    database
      .prepare(sql)
      .bind(SCOPE.namespace, SCOPE.orgId, SCOPE.projectId, SCOPE.envId, ...values);
}

async function seedEnrollment(database: D1DatabaseLike): Promise<void> {
  await database
    .prepare(
      `INSERT INTO email_otp_wallet_enrollments (
         namespace, org_id, project_id, env_id, wallet_id, provider_user_id,
         record_org_id, verified_email, record_json, created_at_ms, updated_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      SCOPE.namespace,
      SCOPE.orgId,
      SCOPE.projectId,
      SCOPE.envId,
      WALLET_ID,
      PROVIDER_USER_ID,
      SCOPE.orgId,
      'name6@gmail.com',
      JSON.stringify({
        version: 'email_otp_wallet_enrollment_v1',
        walletId: WALLET_ID,
        providerUserId: PROVIDER_USER_ID,
        orgId: SCOPE.orgId,
        verifiedEmail: 'name6@gmail.com',
        createdAtMs: 1_000,
        updatedAtMs: 1_000,
      }),
      1_000,
      1_000,
    )
    .run();
}

async function seedEmailMethod(
  database: D1DatabaseLike,
  args: { readonly walletAuthMethodId: string; readonly status: 'active' | 'revoked' },
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO wallet_auth_methods (
         namespace, org_id, project_id, env_id, wallet_id, wallet_authority_id,
         rp_id, kind, status, wallet_auth_method_id, auth_identifier_key,
         email_hash_hex, registration_authority_id, record_json,
         created_at_ms, updated_at_ms, activated_at_ms, revoked_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, '', 'email_otp', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      SCOPE.namespace,
      SCOPE.orgId,
      SCOPE.projectId,
      SCOPE.envId,
      WALLET_ID,
      'wallet-authority:r109c',
      args.status,
      args.walletAuthMethodId,
      EMAIL_HASH_HEX,
      EMAIL_HASH_HEX,
      `challenge:${args.walletAuthMethodId}`,
      JSON.stringify({
        version: 'wallet_auth_method_v2',
        walletAuthMethodId: args.walletAuthMethodId,
        walletId: WALLET_ID,
        walletAuthorityId: 'wallet-authority:r109c',
        kind: 'email_otp',
        status: args.status,
        emailHashHex: EMAIL_HASH_HEX,
        registrationAuthorityId: `challenge:${args.walletAuthMethodId}`,
        createdAtMs: 1_000,
        updatedAtMs: 1_000,
      }),
      1_000,
      1_000,
      1_000,
      args.status === 'revoked' ? 2_000 : null,
    )
    .run();
}

async function enrollmentRows(database: D1DatabaseLike): Promise<number> {
  const row = await database
    .prepare('SELECT COUNT(*) AS count FROM email_otp_wallet_enrollments')
    .first<{ readonly count?: unknown }>();
  return Number(row?.count ?? 0);
}

test('revoking one Email method leaves the shared enrollment for its sibling', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    await seedEnrollment(temporary.database);
    await seedEmailMethod(temporary.database, {
      walletAuthMethodId: 'wallet-auth-method:revoked',
      status: 'revoked',
    });
    await seedEmailMethod(temporary.database, {
      walletAuthMethodId: 'wallet-auth-method:sibling',
      status: 'active',
    });

    const store = new CloudflareD1EmailOtpEnrollmentStore({
      prepare: scopedPrepare(temporary.database),
    });
    await store.prepareDeleteEnrollmentIfUnreferencedStatement(WALLET_ID).run();

    expect(await enrollmentRows(temporary.database)).toBe(1);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('revoking the final Email method removes the shared enrollment', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    await seedEnrollment(temporary.database);
    await seedEmailMethod(temporary.database, {
      walletAuthMethodId: 'wallet-auth-method:last',
      status: 'revoked',
    });

    const store = new CloudflareD1EmailOtpEnrollmentStore({
      prepare: scopedPrepare(temporary.database),
    });
    await store.prepareDeleteEnrollmentIfUnreferencedStatement(WALLET_ID).run();

    expect(await enrollmentRows(temporary.database)).toBe(0);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});
