import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { buildLinkedDeviceUnlockRuntimeFixture } from './helpers/linkedDeviceUnlockRuntime.fixtures';

test('persists and rereads one exact Wallet Session operation credential row', async ({ page }) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const result = await page.evaluate(
    async ({ activeWalletSession, walletSessionId }) => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `operation_credential_${crypto.randomUUID()}`,
      );
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repository = new repositoryModule.WalletSessionAuthorizationRepository(manager);
      const operationCredential = {
        kind: 'opaque_wallet_session_operation_credential_v1' as const,
        token: `wst_${'c'.repeat(43)}`,
        walletSessionId,
      };
      await repository.writeExactWithOperationCredential({
        record: activeWalletSession,
        operationCredential,
      });
      const db = await manager.getDB();
      const raw = await db.get(
        schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations,
        walletSessionId,
      );
      const legacyKeyRaw = await db.get(
        schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations,
        activeWalletSession.authorizationId,
      );
      const reread = await repository.readExactWithOperationCredential({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
      });
      const exact = await repository.readExact(walletSessionId);
      return { raw, legacyKeyRaw, reread, exact, operationCredential };
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      walletSessionId: fixture.ed25519Session.walletSessionId,
    },
  );

  expect(result.raw).toMatchObject({
    record_version: 'wallet_session_authorization_v5',
    wallet_session_id: result.operationCredential.walletSessionId,
    operation_credential: result.operationCredential,
  });
  expect(result.legacyKeyRaw).toBeUndefined();
  expect(result.exact).toEqual(fixture.activeWalletSession);
  expect(result.reread).toEqual({
    record: fixture.activeWalletSession,
    operationCredential: result.operationCredential,
  });
});

test('same-wallet sibling exact sessions coexist and read by their exact method', async ({
  page,
}) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const result = await page.evaluate(
    async ({ activeWalletSession, operationCredential }) => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `operation_credential_siblings_${crypto.randomUUID()}`,
      );
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repository = new repositoryModule.WalletSessionAuthorizationRepository(manager);
      await repository.writeExactWithOperationCredential({
        record: activeWalletSession,
        operationCredential,
      });
      const sibling = repositoryModule.buildActiveWalletSessionV1({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: 'wallet-auth-method:linked-runtime-sibling',
        authorizationId: 'authorization:linked-runtime-sibling',
        authorityDigestB64u: activeWalletSession.authorityDigestB64u,
        authorityRevocationEpoch: activeWalletSession.authorityRevocationEpoch,
        capabilitySubjects: activeWalletSession.capabilitySubjects,
        issuedAtMs: activeWalletSession.issuedAtMs,
        expiresAtMs: activeWalletSession.expiresAtMs,
      });
      const siblingCredential = {
        kind: 'opaque_wallet_session_operation_credential_v1' as const,
        token: `wst_${'s'.repeat(43)}`,
        walletSessionId: 'wallet-session:linked-runtime-sibling',
      };
      await repository.writeExactWithOperationCredential({
        record: sibling,
        operationCredential: siblingCredential,
      });
      const db = await manager.getDB();
      const rows = await db.getAllFromIndex(
        schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations,
        schemaNames.SEAMS_WALLET_INDEXES.walletId,
        activeWalletSession.walletId,
      );
      const first = await repository.readExactWithOperationCredential({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
      });
      const second = await repository.readExactWithOperationCredential({
        walletId: sibling.walletId,
        authorityId: sibling.authorityId,
        authMethodId: sibling.authMethodId,
      });
      return { first, second, rows };
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
    },
  );

  expect(result.first).toEqual({
    record: fixture.activeWalletSession,
    operationCredential: fixture.operationCredential,
  });
  expect(result.second).toEqual({
    record: expect.objectContaining({
      authorizationId: 'authorization:linked-runtime-sibling',
      authMethodId: 'wallet-auth-method:linked-runtime-sibling',
    }),
    operationCredential: {
      kind: 'opaque_wallet_session_operation_credential_v1',
      token: `wst_${'s'.repeat(43)}`,
      walletSessionId: 'wallet-session:linked-runtime-sibling',
    },
  });
  expect(result.rows).toHaveLength(2);
  expect(result.rows.map((row) => row.wallet_session_id).sort()).toEqual([
    'wallet-session:linked-runtime',
    'wallet-session:linked-runtime-sibling',
  ]);
});

test('does not fall back to an exact V4 Wallet Session row', async ({ page }) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const result = await page.evaluate(
    async ({ activeWalletSession }) => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `operation_credential_v4_${crypto.randomUUID()}`,
      );
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repository = new repositoryModule.WalletSessionAuthorizationRepository(manager);
      await repository.writeExact(activeWalletSession);
      const db = await manager.getDB();
      const raw = await db.get(
        schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations,
        activeWalletSession.authorizationId,
      );
      const legacy = repositoryModule.parseStoredExactWalletSessionAuthorizationRow(raw);
      const exactByCredential = await repository.readExactWithOperationCredential({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
      });
      return { legacy, exactByCredential };
    },
    { activeWalletSession: fixture.activeWalletSession },
  );

  expect(result.legacy).toEqual(fixture.activeWalletSession);
  expect(result.exactByCredential).toBeNull();
});

test('replaces duplicate exact V5 Wallet Session rows at the write boundary', async ({ page }) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const result = await page.evaluate(
    async ({ activeWalletSession, walletSessionId }) => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `operation_credential_duplicate_${crypto.randomUUID()}`,
      );
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repository = new repositoryModule.WalletSessionAuthorizationRepository(manager);
      const operationCredential = {
        kind: 'opaque_wallet_session_operation_credential_v1' as const,
        token: `wst_${'d'.repeat(43)}`,
        walletSessionId,
      };
      await repository.writeExactWithOperationCredential({
        record: activeWalletSession,
        operationCredential,
      });
      const duplicate = repositoryModule.buildActiveWalletSessionV1({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
        authorizationId: 'authorization:operation-credential-duplicate',
        authorityDigestB64u: activeWalletSession.authorityDigestB64u,
        authorityRevocationEpoch: activeWalletSession.authorityRevocationEpoch,
        capabilitySubjects: activeWalletSession.capabilitySubjects,
        issuedAtMs: activeWalletSession.issuedAtMs,
        expiresAtMs: activeWalletSession.expiresAtMs,
      });
      await repository.writeExactWithOperationCredential({
        record: duplicate,
        operationCredential: {
          kind: 'opaque_wallet_session_operation_credential_v1' as const,
          token: `wst_${'e'.repeat(43)}`,
          walletSessionId: 'wallet-session:linked-runtime-replacement',
        },
      });
      const exact = await repository.readExactWithOperationCredential({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
      });
      const db = await manager.getDB();
      const rows = await db.getAllFromIndex(
        schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations,
        schemaNames.SEAMS_WALLET_INDEXES.walletId,
        activeWalletSession.walletId,
      );
      return { exact, rows };
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      walletSessionId: fixture.ed25519Session.walletSessionId,
    },
  );

  expect(result.exact).toEqual({
    record: expect.objectContaining({
      authorizationId: 'authorization:operation-credential-duplicate',
    }),
    operationCredential: {
      kind: 'opaque_wallet_session_operation_credential_v1',
      token: `wst_${'e'.repeat(43)}`,
      walletSessionId: 'wallet-session:linked-runtime-replacement',
    },
  });
  expect(result.rows).toHaveLength(2);
  expect(
    result.rows.filter((row) => row.record_version === 'wallet_session_authorization_v5'),
  ).toHaveLength(1);
  expect(
    result.rows.find((row) => row.record_version === 'wallet_session_authorization_v4'),
  ).toMatchObject({ status: 'retired' });
});

test('retiring an exact V5 session removes its Wallet Session key', async ({ page }) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const result = await page.evaluate(
    async ({ activeWalletSession, operationCredential }) => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `operation_credential_retire_${crypto.randomUUID()}`,
      );
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repository = new repositoryModule.WalletSessionAuthorizationRepository(manager);
      await repository.writeExactWithOperationCredential({
        record: activeWalletSession,
        operationCredential,
      });
      const retired = await repository.retireExactActiveForWallet({
        walletId: activeWalletSession.walletId,
        reason: 'wallet_locked',
        retiredAtMs: activeWalletSession.expiresAtMs,
      });
      const db = await manager.getDB();
      const rows = await db.getAllFromIndex(
        schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations,
        schemaNames.SEAMS_WALLET_INDEXES.walletId,
        activeWalletSession.walletId,
      );
      return { retired, rows };
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
    },
  );

  expect(result.retired).toEqual([
    expect.objectContaining({
      kind: 'retired_wallet_session_v1',
      walletId: fixture.activeWalletSession.walletId,
      authorizationId: fixture.activeWalletSession.authorizationId,
      retirementReason: 'wallet_locked',
    }),
  ]);
  expect(result.rows).toHaveLength(1);
  expect(result.rows[0]).toMatchObject({
    record_version: 'wallet_session_authorization_v4',
    wallet_session_id: fixture.activeWalletSession.authorizationId,
    status: 'retired',
  });
});

test('rejects a corrupt matching exact V5 Wallet Session row', async ({ page }) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const errorMessage = await page.evaluate(
    async ({ activeWalletSession, walletSessionId }) => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `operation_credential_corrupt_${crypto.randomUUID()}`,
      );
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repository = new repositoryModule.WalletSessionAuthorizationRepository(manager);
      const operationCredential = {
        kind: 'opaque_wallet_session_operation_credential_v1' as const,
        token: `wst_${'e'.repeat(43)}`,
        walletSessionId,
      };
      await repository.writeExactWithOperationCredential({
        record: activeWalletSession,
        operationCredential,
      });
      const db = await manager.getDB();
      const raw = await db.get(
        schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations,
        walletSessionId,
      );
      if (!raw) throw new Error('stored V5 Wallet Session row is missing');
      await db.put(schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations, {
        ...raw,
        operation_credential: {
          ...raw.operation_credential,
          walletSessionId: 'wallet-session:wrong-key',
        },
      });
      try {
        await repository.readExactWithOperationCredential({
          walletId: activeWalletSession.walletId,
          authorityId: activeWalletSession.authorityId,
          authMethodId: activeWalletSession.authMethodId,
        });
        return null;
      } catch (error) {
        return error instanceof Error ? error.message : String(error);
      }
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      walletSessionId: fixture.ed25519Session.walletSessionId,
    },
  );

  expect(errorMessage).toBe('Stored Wallet Session authorization v5 is corrupt');
});
