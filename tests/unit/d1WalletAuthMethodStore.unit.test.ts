import { expect, test } from '@playwright/test';
import { D1WalletAuthMethodStore } from '../../packages/wallet-server/src/core/d1WalletAuthMethodStore';
import type { D1DatabaseLike } from '../../packages/wallet-server/src/storage/tenantRoute';
import { buildWalletAuthMethodRecordV2 } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseWalletAuthMethodId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import {
  buildLinkedDeviceManagementAuthorityFixture,
  fullOwnerPermissionsForManagementFixture,
} from './helpers/linkedDeviceManagement.fixtures';

const signerMigrations = listD1MigrationFiles('d1-signer');
const TEST_SCOPE = {
  namespace: 'wallet-auth-method-revocation-test',
  orgId: 'tenant:management',
  projectId: 'project-a',
  envId: 'env-a',
} as const;

async function countRows(database: D1DatabaseLike, table: string): Promise<number> {
  const row = await database
    .prepare(`SELECT COUNT(*) AS count FROM ${table}`)
    .first<{ readonly count?: unknown }>();
  return Number(row?.count ?? 0);
}

function buildAuthorityEmailOtpMethod(
  source: Awaited<ReturnType<typeof buildLinkedDeviceManagementAuthorityFixture>>,
  label: string,
) {
  const walletAuthMethodId = parseWalletAuthMethodId(`wallet-auth-method:${label}`);
  if (!walletAuthMethodId.ok) throw new Error(walletAuthMethodId.error.message);
  return buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: walletAuthMethodId.value,
    walletId: source.authMethod.walletId,
    walletAuthorityId: source.authMethod.walletAuthorityId,
    kind: 'email_otp',
    status: 'active',
    emailHashHex: 'ab'.repeat(32),
    registrationAuthorityId: `challenge-${label}`,
    createdAtMs: 1,
    updatedAtMs: 1,
    activatedAtMs: 1,
  });
}

/*
 * R109C's missing-family rule has two halves. The admission read at ceremony
 * start answers `already_configured` for the ordinary case; this guard is the
 * half that survives two ceremonies racing, which a read cannot do. Migration
 * 0011 dropped the Email uniqueness index so linked devices could share one
 * address, so without this nothing in the batch enforces it.
 */
test('the target-family guard admits the first Email method on an authority', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const source = await buildLinkedDeviceManagementAuthorityFixture({
      label: 'target-family-first',
      permissions: fullOwnerPermissionsForManagementFixture(),
      provenance: 'wallet_registration',
    });
    const authMethods = new D1WalletAuthMethodStore({
      database: temporary.database,
      ...TEST_SCOPE,
      ensureSchema: false,
    });
    const added = buildAuthorityEmailOtpMethod(source, 'target-family-first-email');

    await temporary.database.batch([
      ...authMethods.prepareActiveV2TargetFamilyAbsentGuardStatements({
        walletId: added.walletId,
        walletAuthorityId: added.walletAuthorityId,
        kind: 'email_otp',
      }),
      ...authMethods.prepareV2InsertStatements(added),
    ]);

    expect(await countRows(temporary.database, 'wallet_auth_methods')).toBe(1);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('the target-family guard aborts a second Email method on the same authority', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const source = await buildLinkedDeviceManagementAuthorityFixture({
      label: 'target-family-race',
      permissions: fullOwnerPermissionsForManagementFixture(),
      provenance: 'wallet_registration',
    });
    const authMethods = new D1WalletAuthMethodStore({
      database: temporary.database,
      ...TEST_SCOPE,
      ensureSchema: false,
    });
    const winner = buildAuthorityEmailOtpMethod(source, 'target-family-race-winner');
    await authMethods.putV2(winner);
    expect(await countRows(temporary.database, 'wallet_auth_methods')).toBe(1);

    // The losing ceremony holds a different allocated method id, so the
    // insert's own id guard would let it through.
    const loser = buildAuthorityEmailOtpMethod(source, 'target-family-race-loser');
    expect(String(loser.walletAuthMethodId)).not.toBe(String(winner.walletAuthMethodId));

    let aborted = false;
    try {
      await temporary.database.batch([
        ...authMethods.prepareActiveV2TargetFamilyAbsentGuardStatements({
          walletId: loser.walletId,
          walletAuthorityId: loser.walletAuthorityId,
          kind: 'email_otp',
        }),
        ...authMethods.prepareV2InsertStatements(loser),
      ]);
    } catch {
      aborted = true;
    }

    expect(aborted).toBe(true);
    expect(await countRows(temporary.database, 'wallet_auth_methods')).toBe(1);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});
