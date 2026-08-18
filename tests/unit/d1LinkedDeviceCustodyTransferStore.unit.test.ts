import { expect, test } from '@playwright/test';
import { parseLinkDeviceSessionId } from '../../packages/shared-ts/src/signing-lanes/ids';
import { D1LinkedDeviceCustodyTransferStoreV1 } from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceCustodyTransferStore';
import type { D1LinkedDeviceSessionScopeV1 } from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSessionStore';
import type { D1DatabaseLike } from '../../packages/wallet-server/src/storage/tenantRoute';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';
import {
  LINKED_DEVICE_TRANSFER_EPHEMERAL_PUBLIC_KEY_B64U,
  LINKED_DEVICE_TRANSFER_SEALED_AT_MS,
  buildLinkedDeviceCustodyTransferPackageFixtureV1,
  buildLinkedDeviceCustodyTransferRecipientFixtureV1,
} from './helpers/linkedDeviceCustodyTransfer.fixtures';

const scope: D1LinkedDeviceSessionScopeV1 = {
  namespace: 'signer',
  orgId: 'org_test',
  projectId: 'project_test',
  envId: 'env_test',
};

const LINK_SESSION_ID = 'link-session:r103p8';

function linkSessionId() {
  const parsed = parseLinkDeviceSessionId(LINK_SESSION_ID);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

let temporary: TemporaryD1Database | undefined;

test.afterEach(() => {
  if (temporary) cleanupTemporaryD1Database(temporary.tempDir);
  temporary = undefined;
});

async function migratedStore(): Promise<{
  readonly database: D1DatabaseLike;
  readonly store: D1LinkedDeviceCustodyTransferStoreV1;
}> {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  return {
    database: temporary.database,
    store: new D1LinkedDeviceCustodyTransferStoreV1({ database: temporary.database, scope }),
  };
}

test('registers a recipient key, then accepts exactly one sealed package for it', async () => {
  const { store } = await migratedStore();
  const recipient = buildLinkedDeviceCustodyTransferRecipientFixtureV1();

  expect(await store.registerRecipientV1({ recipient })).toEqual({ outcome: 'applied' });
  expect(await store.readTransferV1(linkSessionId())).toEqual({
    state: 'recipient_registered',
    recipient,
  });

  const sealed = buildLinkedDeviceCustodyTransferPackageFixtureV1();
  expect(
    await store.submitPackageV1({ linkSessionId: linkSessionId(), package: sealed }),
  ).toEqual({ outcome: 'applied' });
  expect(await store.readTransferV1(linkSessionId())).toEqual({
    state: 'sealed',
    recipient,
    package: sealed,
  });
});

test('a relay retry of either half replays rather than conflicting', async () => {
  const { store } = await migratedStore();
  const recipient = buildLinkedDeviceCustodyTransferRecipientFixtureV1();
  const sealed = buildLinkedDeviceCustodyTransferPackageFixtureV1();

  await store.registerRecipientV1({ recipient });
  expect(await store.registerRecipientV1({ recipient })).toEqual({ outcome: 'replayed' });

  await store.submitPackageV1({ linkSessionId: linkSessionId(), package: sealed });
  expect(
    await store.submitPackageV1({ linkSessionId: linkSessionId(), package: sealed }),
  ).toEqual({ outcome: 'replayed' });
});

test('the recipient key is immutable once registered', async () => {
  const { store } = await migratedStore();
  await store.registerRecipientV1({
    recipient: buildLinkedDeviceCustodyTransferRecipientFixtureV1(),
  });

  // Device 1 seals to whatever the row says, so a second registration naming
  // another key could redirect a seed that is already in flight.
  const redirected = buildLinkedDeviceCustodyTransferRecipientFixtureV1({
    recipientPublicKeyB64u: LINKED_DEVICE_TRANSFER_EPHEMERAL_PUBLIC_KEY_B64U,
  });
  expect(await store.registerRecipientV1({ recipient: redirected })).toEqual({
    outcome: 'conflict',
    reason: 'recipient_already_registered_with_another_key',
  });
});

test('a package cannot land before a recipient exists', async () => {
  const { store } = await migratedStore();
  expect(
    await store.submitPackageV1({
      linkSessionId: linkSessionId(),
      package: buildLinkedDeviceCustodyTransferPackageFixtureV1(),
    }),
  ).toEqual({ outcome: 'conflict', reason: 'recipient_not_registered' });
  expect(await store.readTransferV1(linkSessionId())).toBeNull();
});

test('a package addressed to another recipient is refused by identity, not by decryption', async () => {
  const { store } = await migratedStore();
  await store.registerRecipientV1({
    recipient: buildLinkedDeviceCustodyTransferRecipientFixtureV1(),
  });

  for (const misaddressed of [
    buildLinkedDeviceCustodyTransferPackageFixtureV1({
      recipientPublicKeyB64u: LINKED_DEVICE_TRANSFER_EPHEMERAL_PUBLIC_KEY_B64U,
      ephemeralPublicKeyB64u: buildLinkedDeviceCustodyTransferRecipientFixtureV1()
        .recipientPublicKeyB64u,
    }),
    buildLinkedDeviceCustodyTransferPackageFixtureV1({ deviceId: 'device:3' }),
    buildLinkedDeviceCustodyTransferPackageFixtureV1({ enrollmentId: 'enrollment:other' }),
    buildLinkedDeviceCustodyTransferPackageFixtureV1({ walletId: 'bob.testnet' }),
  ]) {
    expect(
      await store.submitPackageV1({ linkSessionId: linkSessionId(), package: misaddressed }),
    ).toEqual({ outcome: 'conflict', reason: 'package_addressed_to_another_recipient' });
  }
  expect((await store.readTransferV1(linkSessionId()))?.state).toBe('recipient_registered');
});

test('a second, different seal cannot replace the one already recorded', async () => {
  const { store } = await migratedStore();
  const recipient = buildLinkedDeviceCustodyTransferRecipientFixtureV1();
  await store.registerRecipientV1({ recipient });
  const first = buildLinkedDeviceCustodyTransferPackageFixtureV1();
  await store.submitPackageV1({ linkSessionId: linkSessionId(), package: first });

  const second = buildLinkedDeviceCustodyTransferPackageFixtureV1({
    ephemeralPublicKeyB64u: recipient.recipientPublicKeyB64u.replace(/^F/, 'B'),
  });
  expect(
    await store.submitPackageV1({ linkSessionId: linkSessionId(), package: second }),
  ).toEqual({ outcome: 'conflict', reason: 'package_already_sealed_differently' });
  expect((await store.readTransferV1(linkSessionId()))?.package).toEqual(first);
});

test('the schema refuses a half-written transfer and a self-addressed ephemeral key', async () => {
  const { database } = await migratedStore();

  // `sealed` without the package columns is the shape a partial write would
  // leave behind; the state CHECK rejects it outright.
  await expect(
    database
      .prepare(
        `INSERT INTO linked_device_custody_transfers (
           namespace, org_id, project_id, env_id, link_session_id,
           wallet_id, enrollment_id, device_id, state, transfer_alg,
           recipient_public_key_b64u, recipient_json, registered_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, 'alice.testnet', 'enrollment:device-2', 'device:2',
                   'sealed', 'x25519-hkdf-sha256-chacha20poly1305-v1', 'key', '{}', 1)`,
      )
      .bind(...Object.values(scope), LINK_SESSION_ID)
      .run(),
  ).rejects.toThrow(/CHECK constraint failed/);

  const store = new D1LinkedDeviceCustodyTransferStoreV1({ database, scope });
  await store.registerRecipientV1({
    recipient: buildLinkedDeviceCustodyTransferRecipientFixtureV1(),
  });
  // Republishing the recipient key as the ephemeral key means no ephemeral key
  // was generated at all. The parser rejects it before the schema has to.
  expect(() =>
    buildLinkedDeviceCustodyTransferPackageFixtureV1({
      ephemeralPublicKeyB64u: buildLinkedDeviceCustodyTransferRecipientFixtureV1()
        .recipientPublicKeyB64u,
    }),
  ).toThrow(/repeats the recipient key/);
});

test('a transfer is scoped to its tenant', async () => {
  const { database, store } = await migratedStore();
  await store.registerRecipientV1({
    recipient: buildLinkedDeviceCustodyTransferRecipientFixtureV1(),
  });
  const otherTenant = new D1LinkedDeviceCustodyTransferStoreV1({
    database,
    scope: { ...scope, orgId: 'org_other' },
  });
  expect(await otherTenant.readTransferV1(linkSessionId())).toBeNull();
  expect(
    await otherTenant.submitPackageV1({
      linkSessionId: linkSessionId(),
      package: buildLinkedDeviceCustodyTransferPackageFixtureV1(),
    }),
  ).toEqual({ outcome: 'conflict', reason: 'recipient_not_registered' });
  expect(LINKED_DEVICE_TRANSFER_SEALED_AT_MS).toBeGreaterThan(0);
});
