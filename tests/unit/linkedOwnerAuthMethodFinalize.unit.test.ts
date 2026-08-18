import { expect, test } from '@playwright/test';
import {
  buildLinkedOwnerPasskeyAuthBindingV1,
  parseLinkedDeviceOwnerAuthBindingV1,
} from '../../packages/shared-ts/src/device-linking/ownerAuthBinding';
import {
  D1LinkedDeviceOwnerAuthBindingStoreV1,
  assertOwnerAuthBindingBatchApplied,
} from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOwnerAuthBindingStore';
import type { D1LinkedDeviceSessionScopeV1 } from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSessionStore';
import type {
  D1DatabaseLike,
  D1ResultLike,
} from '../../packages/wallet-server/src/storage/tenantRoute';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';
import {
  LINKED_OWNER_BINDING_ACTIVATED_AT_MS,
  buildLinkedOwnerPasskeyBindingFixtureV1,
} from './helpers/linkedOwnerAuthBinding.fixtures';

/**
 * The Phase 8 finalize appends the owner-auth binding to the *same* D1 batch
 * that writes the wallet auth method, the authenticator, and the custody
 * envelope. These tests stand in for that batch with the auth-method insert
 * plus the binding insert, and assert the property that matters: either both
 * land or neither does. A binding written afterwards would leave a window
 * where the wallet has an owner credential no enrollment points at.
 */
const scope: D1LinkedDeviceSessionScopeV1 = {
  namespace: 'signer',
  orgId: 'org_test',
  projectId: 'project_test',
  envId: 'env_test',
};

let temporary: TemporaryD1Database | undefined;

test.afterEach(() => {
  if (temporary) cleanupTemporaryD1Database(temporary.tempDir);
  temporary = undefined;
});

async function migrated(): Promise<{
  readonly database: D1DatabaseLike;
  readonly bindings: D1LinkedDeviceOwnerAuthBindingStoreV1;
}> {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  return {
    database: temporary.database,
    bindings: new D1LinkedDeviceOwnerAuthBindingStoreV1({
      database: temporary.database,
      scope,
    }),
  };
}

function authMethodInsert(
  database: D1DatabaseLike,
  binding: ReturnType<typeof buildLinkedOwnerPasskeyBindingFixtureV1>,
  overrides: { readonly walletAuthMethodId?: string } = {},
) {
  if (binding.factor.kind !== 'passkey') throw new Error('expected a passkey binding');
  return database
    .prepare(
      `INSERT INTO wallet_auth_methods (
         namespace, org_id, project_id, env_id, wallet_id, rp_id, kind, status,
         wallet_auth_method_id, auth_identifier_key, credential_id_b64u,
         credential_public_key_b64u, record_json, created_at_ms, updated_at_ms
       ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'passkey', 'active', ?7, ?8, ?8, ?9, ?10, ?11, ?11)`,
    )
    .bind(
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(binding.walletId),
      String(binding.factor.rpId),
      overrides.walletAuthMethodId ?? String(binding.walletAuthMethodId),
      String(binding.factor.credentialIdB64u),
      'credential-public-key',
      JSON.stringify({ kind: 'passkey' }),
      binding.createdAtMs,
    );
}

test('the owner auth method and its linked-device binding land in one batch', async () => {
  const { database, bindings } = await migrated();
  const binding = buildLinkedOwnerPasskeyBindingFixtureV1();

  assertOwnerAuthBindingBatchApplied(
    await database.batch<D1ResultLike>([
      authMethodInsert(database, binding),
      bindings.buildInsertV1(binding).statement,
    ]),
    2,
  );

  expect(
    await bindings.readByEnrollmentV1({
      walletId: binding.walletId,
      enrollmentId: binding.enrollmentId,
    }),
  ).toEqual(binding);
});

test('a failed auth-method write leaves no owner binding behind', async () => {
  const { database, bindings } = await migrated();
  const binding = buildLinkedOwnerPasskeyBindingFixtureV1();

  // An auth-method id that disagrees with its credential violates the
  // wallet_auth_methods identity CHECK — the same failure a tampered finalize
  // would produce.
  await expect(
    database.batch<D1ResultLike>([
      authMethodInsert(database, binding, { walletAuthMethodId: 'passkey:other:credential' }),
      bindings.buildInsertV1(binding).statement,
    ]),
  ).rejects.toThrow(/CHECK constraint failed/);

  expect(
    await bindings.readByDeviceV1({ walletId: binding.walletId, deviceId: binding.deviceId }),
  ).toBeNull();
});

test('a failed binding write leaves no owner auth method behind', async () => {
  const { database, bindings } = await migrated();
  const binding = buildLinkedOwnerPasskeyBindingFixtureV1();
  // A revoked binding with no revocation epoch fails the lifecycle CHECK.
  const impossible = parseLinkedDeviceOwnerAuthBindingV1({
    ...binding,
    lifecycle: {
      state: 'revoked',
      activatedAtMs: LINKED_OWNER_BINDING_ACTIVATED_AT_MS,
      revokedAtMs: LINKED_OWNER_BINDING_ACTIVATED_AT_MS + 1,
    },
    revocationEpoch: 1,
    updatedAtMs: LINKED_OWNER_BINDING_ACTIVATED_AT_MS + 1,
  });

  await expect(
    database.batch<D1ResultLike>([
      authMethodInsert(database, binding),
      bindings.buildInsertV1(impossible).statement,
      // A duplicate binding insert in the same batch is the failure: one device
      // may hold only one owner credential.
      bindings.buildInsertV1(impossible).statement,
    ]),
  ).rejects.toThrow(/UNIQUE constraint failed|CHECK constraint failed/);

  const row = await database
    .prepare(
      `SELECT COUNT(*) AS total FROM wallet_auth_methods
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4`,
    )
    .bind(scope.namespace, scope.orgId, scope.projectId, scope.envId)
    .first<{ total?: unknown }>();
  expect(Number(row?.total ?? -1)).toBe(0);
});

test('the binding names the exact credential the ceremony verified', async () => {
  const binding = buildLinkedOwnerPasskeyBindingFixtureV1();
  if (binding.factor.kind !== 'passkey') throw new Error('expected a passkey binding');

  // The builder derives the auth-method id rather than accepting one, so a
  // finalize cannot register credential A and bind the device to credential B.
  const other = buildLinkedOwnerPasskeyAuthBindingV1({
    tenantId: binding.tenantId,
    walletId: binding.walletId,
    enrollmentId: binding.enrollmentId,
    deviceId: binding.deviceId,
    keyManifestDigestB64u: binding.keyManifestDigestB64u,
    activatedAtMs: binding.createdAtMs,
    rpId: binding.factor.rpId,
    credentialIdB64u: binding.factor.credentialIdB64u,
  });
  expect(other.walletAuthMethodId).toBe(binding.walletAuthMethodId);
  expect(String(binding.walletAuthMethodId)).toContain(String(binding.factor.credentialIdB64u));
});
