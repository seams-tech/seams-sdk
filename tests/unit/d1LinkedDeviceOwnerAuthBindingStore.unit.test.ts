import { expect, test } from '@playwright/test';
import {
  linkedOwnerAuthBindingAdmitsUseV1,
  parseLinkedDeviceOwnerAuthBindingV1,
  pauseLinkedOwnerAuthBindingV1,
  resumeLinkedOwnerAuthBindingV1,
  revokeLinkedOwnerAuthBindingV1,
  type LinkedDeviceOwnerAuthBindingV1,
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
  buildLinkedOwnerEmailOtpBindingFixtureV1,
  buildLinkedOwnerPasskeyBindingFixtureV1,
} from './helpers/linkedOwnerAuthBinding.fixtures';

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

async function migratedStore(): Promise<{
  readonly database: D1DatabaseLike;
  readonly store: D1LinkedDeviceOwnerAuthBindingStoreV1;
}> {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  return {
    database: temporary.database,
    store: new D1LinkedDeviceOwnerAuthBindingStoreV1({ database: temporary.database, scope }),
  };
}

/**
 * The binding's foreign key is what makes the enrollment resolve one exact
 * canonical auth method. Seeding the referenced row keeps these tests honest
 * against a runtime that enforces it, even though the sqlite CLI harness runs
 * with `foreign_keys` off.
 */
async function seedCanonicalPasskeyAuthMethod(
  database: D1DatabaseLike,
  binding: LinkedDeviceOwnerAuthBindingV1,
): Promise<void> {
  if (binding.factor.kind !== 'passkey') throw new Error('expected a passkey binding');
  await database
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
      String(binding.walletAuthMethodId),
      String(binding.factor.credentialIdB64u),
      'credential-public-key',
      JSON.stringify({ kind: 'passkey' }),
      binding.createdAtMs,
    )
    .run();
}

test('persists a linked passkey owner binding and resolves it by enrollment, device, and auth method', async () => {
  const { database, store } = await migratedStore();
  const binding = buildLinkedOwnerPasskeyBindingFixtureV1();
  await seedCanonicalPasskeyAuthMethod(database, binding);

  const write = store.buildInsertV1(binding);
  assertOwnerAuthBindingBatchApplied(await database.batch<D1ResultLike>([write.statement]), 1);

  expect(String(binding.walletAuthMethodId)).toBe(
    'passkey:wallet.example.localhost:credential-device-2',
  );

  const byEnrollment = await store.readByEnrollmentV1({
    walletId: binding.walletId,
    enrollmentId: binding.enrollmentId,
  });
  expect(byEnrollment).toEqual(binding);

  const byDevice = await store.readByDeviceV1({
    walletId: binding.walletId,
    deviceId: binding.deviceId,
  });
  expect(byDevice).toEqual(binding);

  const byAuthMethod = await store.readByAuthMethodV1({
    walletId: binding.walletId,
    walletAuthMethodId: binding.walletAuthMethodId,
  });
  expect(byAuthMethod).toEqual(binding);

  const batch = await store.readBatchForWalletV1(binding.walletId);
  expect([...batch.keys()]).toEqual([String(binding.deviceId)]);
});

test('pages wallet bindings by durable update time and device identity without duplicates', async () => {
  const { database, store } = await migratedStore();
  const bindings = [
    buildLinkedOwnerPasskeyBindingFixtureV1({
      enrollmentId: 'enrollment:r103p8:a',
      deviceId: 'device:r103p8:a',
      credentialIdB64u: 'credential-device-a',
      activatedAtMs: 3_000,
    }),
    buildLinkedOwnerPasskeyBindingFixtureV1({
      enrollmentId: 'enrollment:r103p8:b',
      deviceId: 'device:r103p8:b',
      credentialIdB64u: 'credential-device-b',
      activatedAtMs: 3_000,
    }),
    buildLinkedOwnerPasskeyBindingFixtureV1({
      enrollmentId: 'enrollment:r103p8:c',
      deviceId: 'device:r103p8:c',
      credentialIdB64u: 'credential-device-c',
      activatedAtMs: 2_000,
    }),
  ];
  for (const binding of bindings) await seedCanonicalPasskeyAuthMethod(database, binding);
  assertOwnerAuthBindingBatchApplied(
    await database.batch<D1ResultLike>(
      bindings.map((binding) => store.buildInsertV1(binding).statement),
    ),
    bindings.length,
  );

  const first = await store.listPageForWalletV1({
    walletId: bindings[0].walletId,
    limit: 2,
    cursor: null,
  });
  expect(first.records.map((binding) => String(binding.deviceId))).toEqual([
    'device:r103p8:a',
    'device:r103p8:b',
  ]);
  expect(first.nextCursor).toEqual({
    updatedAtMs: 3_000,
    deviceId: bindings[1].deviceId,
  });

  const second = await store.listPageForWalletV1({
    walletId: bindings[0].walletId,
    limit: 2,
    cursor: first.nextCursor,
  });
  expect(second.records.map((binding) => String(binding.deviceId))).toEqual(['device:r103p8:c']);
  expect(second.nextCursor).toBeNull();
});

test('an Email OTP binding stores no WebAuthn identity and derives its own auth-method id', async () => {
  const { database, store } = await migratedStore();
  const binding = buildLinkedOwnerEmailOtpBindingFixtureV1();

  assertOwnerAuthBindingBatchApplied(
    await database.batch<D1ResultLike>([store.buildInsertV1(binding).statement]),
    1,
  );

  expect(String(binding.walletAuthMethodId)).toBe(`email_otp:wallet:r103p8:${'b'.repeat(64)}`);

  const row = await database
    .prepare(
      `SELECT factor_kind, rp_id, credential_id_b64u, email_hash_hex, registration_authority_id
         FROM linked_device_owner_auth_bindings
        WHERE enrollment_id = ?1`,
    )
    .bind(String(binding.enrollmentId))
    .first<Record<string, unknown>>();
  expect(row).toEqual({
    factor_kind: 'email_otp',
    rp_id: null,
    credential_id_b64u: null,
    email_hash_hex: 'b'.repeat(64),
    registration_authority_id: 'google',
  });

  expect(
    await store.readByEnrollmentV1({
      walletId: binding.walletId,
      enrollmentId: binding.enrollmentId,
    }),
  ).toEqual(binding);
});

test('one device cannot hold two owner credentials and one credential cannot serve two devices', async () => {
  const { database, store } = await migratedStore();
  const first = buildLinkedOwnerPasskeyBindingFixtureV1();
  await database.batch<D1ResultLike>([store.buildInsertV1(first).statement]);

  const sameDevice = buildLinkedOwnerPasskeyBindingFixtureV1({
    enrollmentId: 'enrollment:r103p8:second',
    credentialIdB64u: 'credential-device-2-replacement',
  });
  await expect(
    database.batch<D1ResultLike>([store.buildInsertV1(sameDevice).statement]),
  ).rejects.toThrow(/UNIQUE constraint failed/);

  const sameCredential = buildLinkedOwnerPasskeyBindingFixtureV1({
    enrollmentId: 'enrollment:r103p8:third',
    deviceId: 'device:r103p8:other',
  });
  await expect(
    database.batch<D1ResultLike>([store.buildInsertV1(sameCredential).statement]),
  ).rejects.toThrow(/UNIQUE constraint failed/);
});

test('the binding row is a foreign key into the canonical wallet auth methods table', async () => {
  const { database } = await migratedStore();
  const foreignKeys = await database
    .prepare('PRAGMA foreign_key_list(linked_device_owner_auth_bindings)')
    .all<Record<string, unknown>>();
  const references = (foreignKeys.results || []).map((row) => ({
    table: row.table,
    from: row.from,
    to: row.to,
  }));
  expect(references).toEqual(
    expect.arrayContaining([
      { table: 'wallet_auth_methods', from: 'wallet_auth_method_id', to: 'wallet_auth_method_id' },
    ]),
  );
});

test('activation and its binding land in one batch, so a failed activation writes no owner credential', async () => {
  const { database, store } = await migratedStore();
  const binding = buildLinkedOwnerPasskeyBindingFixtureV1();
  // Stands in for the activation statement the caller batches alongside the
  // binding. It violates a NOT NULL constraint, so the transaction rolls back.
  const failingActivation = database.prepare(
    `INSERT INTO linked_device_owner_auth_bindings (namespace, org_id, project_id, env_id, enrollment_id)
       VALUES ('x', 'y', 'z', 'w', 'broken')`,
  );

  await expect(
    database.batch<D1ResultLike>([failingActivation, store.buildInsertV1(binding).statement]),
  ).rejects.toThrow();

  expect(
    await store.readByEnrollmentV1({
      walletId: binding.walletId,
      enrollmentId: binding.enrollmentId,
    }),
  ).toBeNull();
});

test('lifecycle transitions fence use, stay resumable until revoked, and advance the revocation epoch', async () => {
  const { database, store } = await migratedStore();
  const active = buildLinkedOwnerPasskeyBindingFixtureV1();
  await database.batch<D1ResultLike>([store.buildInsertV1(active).statement]);
  expect(linkedOwnerAuthBindingAdmitsUseV1(active)).toBe(true);

  const paused = pauseLinkedOwnerAuthBindingV1({
    binding: active,
    pausedAtMs: LINKED_OWNER_BINDING_ACTIVATED_AT_MS + 1_000,
  });
  if (!paused.ok) throw new Error('expected pause to apply');
  expect(paused.binding.lifecycle).toEqual({
    state: 'paused',
    activatedAtMs: LINKED_OWNER_BINDING_ACTIVATED_AT_MS,
    pausedAtMs: LINKED_OWNER_BINDING_ACTIVATED_AT_MS + 1_000,
  });
  expect(linkedOwnerAuthBindingAdmitsUseV1(paused.binding)).toBe(false);
  expect(paused.binding.revocationEpoch).toBe(0);

  assertOwnerAuthBindingBatchApplied(
    await database.batch<D1ResultLike>([
      store.buildLifecycleUpdateV1(paused.binding, active.revocationEpoch).statement,
    ]),
    1,
  );
  // Pausing keeps the device visible: it is still readable through every lookup.
  expect(
    await store.readByDeviceV1({ walletId: active.walletId, deviceId: active.deviceId }),
  ).toEqual(paused.binding);

  const resumed = resumeLinkedOwnerAuthBindingV1({
    binding: paused.binding,
    resumedAtMs: LINKED_OWNER_BINDING_ACTIVATED_AT_MS + 2_000,
  });
  if (!resumed.ok) throw new Error('expected resume to apply');
  expect(linkedOwnerAuthBindingAdmitsUseV1(resumed.binding)).toBe(true);

  const revoked = revokeLinkedOwnerAuthBindingV1({
    binding: resumed.binding,
    revokedAtMs: LINKED_OWNER_BINDING_ACTIVATED_AT_MS + 3_000,
  });
  if (!revoked.ok) throw new Error('expected revoke to apply');
  expect(revoked.binding.revocationEpoch).toBe(1);
  expect(linkedOwnerAuthBindingAdmitsUseV1(revoked.binding)).toBe(false);

  expect(
    revokeLinkedOwnerAuthBindingV1({
      binding: revoked.binding,
      revokedAtMs: LINKED_OWNER_BINDING_ACTIVATED_AT_MS + 4_000,
    }),
  ).toEqual({ ok: false, error: { code: 'already_revoked' } });
  expect(
    resumeLinkedOwnerAuthBindingV1({
      binding: revoked.binding,
      resumedAtMs: LINKED_OWNER_BINDING_ACTIVATED_AT_MS + 4_000,
    }),
  ).toEqual({ ok: false, error: { code: 'already_revoked' } });
});

test('a lifecycle write is compare-and-set on the revocation epoch', async () => {
  const { database, store } = await migratedStore();
  const active = buildLinkedOwnerPasskeyBindingFixtureV1();
  await database.batch<D1ResultLike>([store.buildInsertV1(active).statement]);

  const revoked = revokeLinkedOwnerAuthBindingV1({
    binding: active,
    revokedAtMs: LINKED_OWNER_BINDING_ACTIVATED_AT_MS + 1_000,
  });
  if (!revoked.ok) throw new Error('expected revoke to apply');
  const applied = await database.batch<D1ResultLike>([
    store.buildLifecycleUpdateV1(revoked.binding, active.revocationEpoch).statement,
  ]);
  expect(applied[0]?.meta?.changes).toBe(1);

  // A second revocation racing on the stale epoch changes nothing.
  const raced = await database.batch<D1ResultLike>([
    store.buildLifecycleUpdateV1(revoked.binding, active.revocationEpoch).statement,
  ]);
  expect(raced[0]?.meta?.changes).toBe(0);

  const stored = await store.readByEnrollmentV1({
    walletId: active.walletId,
    enrollmentId: active.enrollmentId,
  });
  expect(stored?.revocationEpoch).toBe(1);
  expect(stored?.lifecycle.state).toBe('revoked');
});

test('a stored record that points at another credential fails closed at the boundary', async () => {
  const binding = buildLinkedOwnerPasskeyBindingFixtureV1();
  const substituted = {
    ...binding,
    factor: { kind: 'passkey' as const, rpId: binding.factor.rpId, credentialIdB64u: 'other' },
  };
  expect(() => parseLinkedDeviceOwnerAuthBindingV1(substituted)).toThrow(
    /walletAuthMethodId does not match its factor identity/,
  );

  const crossBranch = {
    ...binding,
    factor: {
      kind: 'email_otp' as const,
      emailHashHex: 'c'.repeat(64),
      registrationAuthorityId: 'google',
    },
  };
  expect(() => parseLinkedDeviceOwnerAuthBindingV1(crossBranch)).toThrow(
    /walletAuthMethodId does not match its factor identity/,
  );
});

test('a revoked binding cannot be persisted without a revocation epoch', async () => {
  const { database, store } = await migratedStore();
  const active = buildLinkedOwnerPasskeyBindingFixtureV1();
  const revokedWithoutEpoch: LinkedDeviceOwnerAuthBindingV1 = {
    ...active,
    lifecycle: {
      state: 'revoked',
      activatedAtMs: LINKED_OWNER_BINDING_ACTIVATED_AT_MS,
      revokedAtMs: LINKED_OWNER_BINDING_ACTIVATED_AT_MS + 1_000,
    },
    updatedAtMs: LINKED_OWNER_BINDING_ACTIVATED_AT_MS + 1_000,
  };

  await expect(
    database.batch<D1ResultLike>([store.buildInsertV1(revokedWithoutEpoch).statement]),
  ).rejects.toThrow(/CHECK constraint failed/);
  expect(() => parseLinkedDeviceOwnerAuthBindingV1(revokedWithoutEpoch)).toThrow(
    /revoked binding requires a revocation epoch/,
  );
});
