import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { buildLinkedDeviceUnlockRuntimeFixture } from './helpers/linkedDeviceUnlockRuntime.fixtures';
import { buildWalletAuthAuthorityRefForAuthorityFixture } from './helpers/ecdsaMaterialRef.fixtures';

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
      const exactActive = await repository.readExactActiveForWallet({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
      });
      const exact = await repository.readExact(walletSessionId);
      return { raw, legacyKeyRaw, reread, exactActive, exact, operationCredential };
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      walletSessionId: fixture.ed25519Session.walletSessionId,
    },
  );

  expect(result.raw).toMatchObject({
    record_version: 'wallet_session_authorization_v6',
    wallet_session_id: result.operationCredential.walletSessionId,
    authorization_id: fixture.activeWalletSession.authorizationId,
    operation_credential: result.operationCredential,
  });
  expect(result.legacyKeyRaw).toBeUndefined();
  expect(result.exact).toEqual(fixture.activeWalletSession);
  expect(result.reread).toEqual({
    kind: 'found',
    record: fixture.activeWalletSession,
    operationCredential: result.operationCredential,
  });
  expect(result.exactActive).toEqual(result.reread);
});

test('V6 parser cross-checks the Wallet Session key and authorization identity', async ({
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
      const dbName = schemaNames.createSeamsTestWalletDbName(`v6_parser_${crypto.randomUUID()}`);
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repository = new repositoryModule.WalletSessionAuthorizationRepository(manager);
      await repository.writeExactWithOperationCredential({
        record: activeWalletSession,
        operationCredential,
      });
      const storeName = schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations;
      const db = await manager.getDB();
      const row = await db.get(storeName, operationCredential.walletSessionId);
      if (!row) throw new Error('stored V6 Wallet Session row is missing');
      const valid = await repository.readExactActiveForWallet({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
      });
      await db.put(storeName, {
        ...row,
        authorization_id: 'authorization:v6-wrong',
      });
      const authorizationMismatch = await repository.readExactActiveForWallet({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
      });
      await db.put(storeName, row);
      await db.put(storeName, {
        ...row,
        operation_credential: {
          ...row.operation_credential,
          walletSessionId: 'wallet-session:v6-wrong',
        },
      });
      const sessionMismatch = await repository.readExactActiveForWallet({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
      });
      await db.put(storeName, row);
      await db.put(storeName, {
        ...row,
        record: {
          ...row.record,
          walletSessionId: 'wallet-session:v6-record-wrong',
        },
      });
      const recordSessionMismatch = await repository.readExactActiveForWallet({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
      });
      return { row, valid, sessionMismatch, authorizationMismatch, recordSessionMismatch };
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
    },
  );

  expect(result.row).toMatchObject({
    record_version: 'wallet_session_authorization_v6',
    wallet_session_id: fixture.operationCredential.walletSessionId,
    authorization_id: fixture.activeWalletSession.authorizationId,
    record: {
      walletSessionId: fixture.operationCredential.walletSessionId,
    },
  });
  expect(result.valid).toEqual({
    kind: 'found',
    record: fixture.activeWalletSession,
    operationCredential: fixture.operationCredential,
  });
  expect(result.sessionMismatch).toEqual({ kind: 'corrupt' });
  expect(result.authorizationMismatch).toEqual({ kind: 'corrupt' });
  expect(result.recordSessionMismatch).toEqual({ kind: 'corrupt' });
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
        quotaId: 'wallet-quota:linked-runtime-sibling',
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
    kind: 'found',
    record: fixture.activeWalletSession,
    operationCredential: fixture.operationCredential,
  });
  expect(result.second).toEqual({
    kind: 'found',
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
  expect(result.exactByCredential).toEqual({ kind: 'missing' });
});

test('replaces duplicate exact V6 Wallet Session rows at the write boundary', async ({ page }) => {
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
        quotaId: 'wallet-quota:operation-credential-duplicate',
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
    kind: 'found',
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
    result.rows.filter((row) => row.record_version === 'wallet_session_authorization_v6'),
  ).toHaveLength(1);
  expect(
    result.rows.find((row) => row.record_version === 'wallet_session_authorization_v4'),
  ).toMatchObject({ status: 'retired' });
});

test('retiring an exact V6 session removes its Wallet Session key', async ({ page }) => {
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

test('rejects a corrupt matching exact V6 Wallet Session row', async ({ page }) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const result = await page.evaluate(
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
      if (!raw) throw new Error('stored V6 Wallet Session row is missing');
      await db.put(schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations, {
        ...raw,
        operation_credential: {
          ...raw.operation_credential,
          walletSessionId: 'wallet-session:wrong-key',
        },
      });
      const exactActive = await repository.readExactActiveForWallet({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
      });
      try {
        await repository.readExactWithOperationCredential({
          walletId: activeWalletSession.walletId,
          authorityId: activeWalletSession.authorityId,
          authMethodId: activeWalletSession.authMethodId,
        });
        return { exactActive, errorMessage: null };
      } catch (error) {
        return {
          exactActive,
          errorMessage: error instanceof Error ? error.message : String(error),
        };
      }
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      walletSessionId: fixture.ed25519Session.walletSessionId,
    },
  );

  expect(result.exactActive).toEqual({ kind: 'corrupt' });
  expect(result.errorMessage).toBe('Stored Wallet Session authorization v6 is corrupt');
});

test('rejects a malformed V6 row during exact replacement', async ({ page }) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const result = await page.evaluate(
    async ({ activeWalletSession, operationCredential }) => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(`malformed_v6_${crypto.randomUUID()}`);
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repository = new repositoryModule.WalletSessionAuthorizationRepository(manager);
      const db = await manager.getDB();
      const storeName = schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations;
      await repository.writeExactWithOperationCredential({
        record: activeWalletSession,
        operationCredential,
      });
      const valid = await db.get(storeName, operationCredential.walletSessionId);
      if (!valid) throw new Error('stored V6 Wallet Session row is missing');
      const malformed = {
        ...valid,
        record: {
          ...valid.record,
          recordVersion: 'wallet_session_authorization_v3',
        },
        authorization_id: 'authorization:v6-malformed',
      };
      await db.put(storeName, malformed);
      const exactActive = await repository.readExactActiveForWallet({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
      });
      let errorMessage: string | null = null;
      try {
        await repository.replaceExactActive({
          active: activeWalletSession,
          operationCredential,
          replacedAtMs: activeWalletSession.issuedAtMs,
        });
      } catch (error) {
        errorMessage = error instanceof Error ? error.message : String(error);
      }
      return { exactActive, errorMessage };
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
    },
  );

  expect(result.exactActive).toEqual({ kind: 'corrupt' });
  expect(result.errorMessage).toBe('Stored Wallet Session authorization v6 is corrupt');
});

test('quarantines V3, V4, and V5 rows during exact installation', async ({ page }) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const authorityRef = buildWalletAuthAuthorityRefForAuthorityFixture(fixture.factorAuthority);
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const result = await page.evaluate(
    async ({ activeWalletSession, authorityRef, walletSessionToken, operationCredential }) => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `quarantine_legacy_${crypto.randomUUID()}`,
      );
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repository = new repositoryModule.WalletSessionAuthorizationRepository(manager);
      const legacyActive = repositoryModule.buildActiveWalletSessionAuthorizationProjection({
        walletId: activeWalletSession.walletId,
        walletSessionId: 'wallet-session:quarantine-v3',
        quotaId: 'wallet-quota:quarantine-v3',
        walletSessionTokens: {
          kind: 'near_ed25519',
          ed25519: {
            authorizationId: 'authorization:quarantine-v3',
            walletSessionToken,
            thresholdSessionId: 'threshold-ed25519:linked-runtime',
          },
        },
        authMethod: 'passkey',
        authority: authorityRef,
        expiresAtMs: activeWalletSession.expiresAtMs,
      });
      const legacyRetired = repositoryModule.retireWalletSessionAuthorizationProjection({
        active: legacyActive,
        reason: 'replaced',
        retiredAtMs: activeWalletSession.expiresAtMs,
      });
      const legacyExactRetired = repositoryModule.retireWalletSessionV1({
        active: activeWalletSession,
        reason: 'replaced',
        retiredAtMs: activeWalletSession.expiresAtMs,
      });
      await repository.write(legacyRetired);
      await repository.writeExact(legacyExactRetired);
      const db = await manager.getDB();
      const storeName = schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations;
      await db.put(
        storeName,
        repositoryModule.toStoredExactWalletSessionAuthorizationRowV5(activeWalletSession, {
          kind: 'opaque_wallet_session_operation_credential_v1',
          token: `wst_${'Q'.repeat(43)}`,
          walletSessionId: 'wallet-session:quarantine-v5',
        }),
      );
      await repository.replaceExactActive({
        active: activeWalletSession,
        operationCredential,
        replacedAtMs: activeWalletSession.issuedAtMs,
      });
      const rows = await db.getAllFromIndex(
        storeName,
        schemaNames.SEAMS_WALLET_INDEXES.walletId,
        activeWalletSession.walletId,
      );
      const read = await repository.readExactActiveForWallet({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
      });
      return { rows, read };
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      authorityRef,
      walletSessionToken: fixture.operationCredential.token,
      operationCredential: fixture.operationCredential,
    },
  );

  expect(result.rows).toHaveLength(4);
  expect(result.rows).toContainEqual(
    expect.objectContaining({
      record: expect.objectContaining({
        recordVersion: 'wallet_session_authorization_v3',
      }),
    }),
  );
  expect(
    result.rows
      .map((row) => row.record_version)
      .filter(Boolean)
      .sort(),
  ).toEqual([
    'wallet_session_authorization_v4',
    'wallet_session_authorization_v5',
    'wallet_session_authorization_v6',
  ]);
  expect(result.read).toEqual({
    kind: 'found',
    record: fixture.activeWalletSession,
    operationCredential: fixture.operationCredential,
  });
});

test('returns upgrade_required and preserves a future exact Wallet Session row', async ({
  page,
}) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const result = await page.evaluate(
    async ({ activeWalletSession }) => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `operation_credential_future_${crypto.randomUUID()}`,
      );
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repository = new repositoryModule.WalletSessionAuthorizationRepository(manager);
      const future = {
        record_version: 'wallet_session_authorization_v7',
        wallet_session_id: 'wallet-session:future-only',
        wallet_id: activeWalletSession.walletId,
        wallet_authority_id: activeWalletSession.authorityId,
        wallet_auth_method_id: activeWalletSession.authMethodId,
        future_payload: { preserved: true, marker: 'future-only' },
      };
      const db = await manager.getDB();
      await db.put(schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations, future);
      const read = await repository.readExactWithOperationCredential({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
      });
      const persisted = await db.get(
        schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations,
        future.wallet_session_id,
      );
      return { read, future, persisted };
    },
    { activeWalletSession: fixture.activeWalletSession },
  );

  expect(result.read).toEqual({ kind: 'upgrade_required' });
  expect(result.persisted).toEqual(result.future);
});

test('future exact rows dominate a readable V6 Wallet Session row', async ({ page }) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const result = await page.evaluate(
    async ({ activeWalletSession, operationCredential }) => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `operation_credential_mixed_future_${crypto.randomUUID()}`,
      );
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repository = new repositoryModule.WalletSessionAuthorizationRepository(manager);
      await repository.writeExactWithOperationCredential({
        record: activeWalletSession,
        operationCredential,
      });
      const future = {
        record_version: 'wallet_session_authorization_v7',
        wallet_session_id: 'wallet-session:future-with-v6',
        wallet_id: activeWalletSession.walletId,
        wallet_authority_id: activeWalletSession.authorityId,
        wallet_auth_method_id: activeWalletSession.authMethodId,
        future_payload: { preserved: true, marker: 'future-with-v6' },
      };
      const db = await manager.getDB();
      await db.put(schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations, future);
      const read = await repository.readExactWithOperationCredential({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
      });
      const persisted = await db.get(
        schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations,
        future.wallet_session_id,
      );
      return { read, future, persisted };
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
    },
  );

  expect(result.read).toEqual({ kind: 'upgrade_required' });
  expect(result.persisted).toEqual(result.future);
});

test('login surfaces exact-session upgrade_required without mutating authentication', async ({
  page,
}) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const result = await page.evaluate(
    async ({
      activeWalletSession,
      authority,
      authMethod,
      selection,
      signerMaterials,
      walletId,
    }) => {
      const loginModule = await import('/_test-sdk/esm/SeamsWeb/operations/auth/login.js');
      const indexedDbModule = await import('/_test-sdk/esm/core/indexedDB/index.js');
      const storeModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.js');
      const originalResolve = indexedDbModule.IndexedDBManager.resolveSelectedWalletAuthority;
      const originalRead = storeModule.walletSessionAuthorizations.readExactWithOperationCredential;
      let setWalletAuthenticatedCalls = 0;
      indexedDbModule.IndexedDBManager.resolveSelectedWalletAuthority = async () => ({
        kind: 'resolved',
        selection,
        authMethod,
        authority,
        signerMaterials,
      });
      storeModule.walletSessionAuthorizations.readExactWithOperationCredential = async () => ({
        kind: 'upgrade_required',
      });
      try {
        let error: unknown = null;
        try {
          await loginModule.getWalletSession(
            {
              configs: {
                network: { chains: [] },
                signing: { mode: { mode: 'threshold-signer' } },
              },
              signingEngine: {
                readWalletAuthenticationState: () => ({ kind: 'signed_out' }),
                setWalletAuthenticated: () => {
                  setWalletAuthenticatedCalls += 1;
                },
              },
            },
            walletId,
          );
        } catch (caught) {
          error = caught;
        }
        return {
          errorName: error instanceof Error ? error.name : String(error),
          errorKind: error && typeof error === 'object' && 'kind' in error ? error.kind : null,
          errorCode: error && typeof error === 'object' && 'code' in error ? error.code : null,
          setWalletAuthenticatedCalls,
          activeWalletSession,
        };
      } finally {
        indexedDbModule.IndexedDBManager.resolveSelectedWalletAuthority = originalResolve;
        storeModule.walletSessionAuthorizations.readExactWithOperationCredential = originalRead;
      }
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      authority: fixture.authority,
      authMethod: fixture.authMethod,
      selection: fixture.selection,
      signerMaterials: fixture.signerMaterials,
      walletId: fixture.walletId,
    },
  );

  expect(result.errorName).toBe('WalletSessionAuthorizationUpgradeRequiredError');
  expect(result.errorKind).toBe('upgrade_required');
  expect(result.errorCode).toBe('upgrade_required');
  expect(result.setWalletAuthenticatedCalls).toBe(0);
  expect(result.activeWalletSession.kind).toBe('active_wallet_session_v1');
});

test('preserves unknown future rows across legacy Wallet Session writers', async ({ page }) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const authorityRef = buildWalletAuthAuthorityRefForAuthorityFixture(fixture.factorAuthority);
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const results = await page.evaluate(
    async ({ activeWalletSession, authorityRef, walletSessionToken }) => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.js');
      const storeName = schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations;
      const writerNames = [
        'replaceActive',
        'createOrMergeExactActive',
        'upsertActiveWithCurveMerge',
      ] as const;
      const results: Array<{
        readonly writer: (typeof writerNames)[number];
        readonly future: Record<string, unknown>;
        readonly persisted: unknown;
        readonly rows: readonly Record<string, unknown>[];
      }> = [];
      for (const writer of writerNames) {
        const dbName = schemaNames.createSeamsTestWalletDbName(
          `future_legacy_writer_${writer}_${crypto.randomUUID()}`,
        );
        const manager = new managerModule.SeamsWalletDBManager();
        manager.setDbName(dbName);
        const repository = new repositoryModule.WalletSessionAuthorizationRepository(manager);
        const active = repositoryModule.buildActiveWalletSessionAuthorizationProjection({
          walletId: activeWalletSession.walletId,
          walletSessionId: `wallet-session:${writer}-initial`,
          quotaId: `wallet-quota:${writer}-initial`,
          walletSessionTokens: {
            kind: 'near_ed25519',
            ed25519: {
              authorizationId: `authorization:${writer}-initial`,
              walletSessionToken,
              thresholdSessionId: 'threshold-ed25519:linked-runtime',
            },
          },
          authMethod: 'passkey',
          authority: authorityRef,
          expiresAtMs: activeWalletSession.expiresAtMs,
        });
        await repository.replaceActive({
          active,
          replacedAtMs: activeWalletSession.expiresAtMs,
        });
        const future = {
          record_version: 'wallet_session_authorization_v7',
          wallet_session_id: `wallet-session:${writer}-future`,
          wallet_id: activeWalletSession.walletId,
          wallet_authority_id: activeWalletSession.authorityId,
          wallet_auth_method_id: activeWalletSession.authMethodId,
          future_payload: { preserved: true, writer },
        };
        const db = await manager.getDB();
        await db.put(storeName, future);
        switch (writer) {
          case 'replaceActive':
            await repository.replaceActive({
              active: repositoryModule.buildActiveWalletSessionAuthorizationProjection({
                walletId: activeWalletSession.walletId,
                walletSessionId: `wallet-session:${writer}-replacement`,
                quotaId: `wallet-quota:${writer}-replacement`,
                walletSessionTokens: {
                  kind: 'near_ed25519',
                  ed25519: {
                    authorizationId: `authorization:${writer}-replacement`,
                    walletSessionToken,
                    thresholdSessionId: 'threshold-ed25519:linked-runtime',
                  },
                },
                authMethod: 'passkey',
                authority: authorityRef,
                expiresAtMs: activeWalletSession.expiresAtMs,
              }),
              replacedAtMs: activeWalletSession.expiresAtMs,
            });
            break;
          case 'createOrMergeExactActive':
            await repository.createOrMergeExactActive({
              incoming: active,
              mergedAtMs: activeWalletSession.expiresAtMs,
            });
            break;
          case 'upsertActiveWithCurveMerge':
            await repository.upsertActiveWithCurveMerge({
              incoming: active,
              writtenAtMs: activeWalletSession.expiresAtMs,
            });
            break;
        }
        results.push({
          writer,
          future,
          persisted: await db.get(storeName, future.wallet_session_id),
          rows: await db.getAllFromIndex(
            storeName,
            schemaNames.SEAMS_WALLET_INDEXES.walletId,
            activeWalletSession.walletId,
          ),
        });
      }
      return results;
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      authorityRef,
      walletSessionToken: fixture.operationCredential.token,
    },
  );

  expect(results).toHaveLength(3);
  for (const result of results) {
    expect(result.persisted).toEqual(result.future);
  }
  const replacement = results.find((result) => result.writer === 'replaceActive');
  expect(replacement?.rows).toContainEqual(
    expect.objectContaining({
      record: expect.objectContaining({
        recordVersion: 'wallet_session_authorization_v3',
      }),
      status: 'retired',
      wallet_session_id: 'wallet-session:replaceActive-initial',
    }),
  );
  expect(replacement?.rows).toContainEqual(
    expect.objectContaining({
      record: expect.objectContaining({
        recordVersion: 'wallet_session_authorization_v3',
      }),
      status: 'active',
      wallet_session_id: 'wallet-session:replaceActive-replacement',
    }),
  );
});

test('contains late legacy and future rows during exact V6 replacement', async ({ page }) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const authorityRef = buildWalletAuthAuthorityRefForAuthorityFixture(fixture.factorAuthority);
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const result = await page.evaluate(
    async ({ activeWalletSession, operationCredential, authorityRef, walletSessionToken }) => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(`late_v6_${crypto.randomUUID()}`);
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repository = new repositoryModule.WalletSessionAuthorizationRepository(manager);
      await repository.writeExactWithOperationCredential({
        record: activeWalletSession,
        operationCredential,
      });
      const legacyActive = repositoryModule.buildActiveWalletSessionAuthorizationProjection({
        walletId: activeWalletSession.walletId,
        walletSessionId: 'wallet-session:late-legacy',
        quotaId: 'wallet-quota:late-legacy',
        walletSessionTokens: {
          kind: 'near_ed25519',
          ed25519: {
            authorizationId: 'authorization:late-legacy',
            walletSessionToken,
            thresholdSessionId: 'threshold-ed25519:linked-runtime',
          },
        },
        authMethod: 'passkey',
        authority: authorityRef,
        expiresAtMs: activeWalletSession.expiresAtMs,
      });
      const legacy = repositoryModule.retireWalletSessionAuthorizationProjection({
        active: legacyActive,
        reason: 'replaced',
        retiredAtMs: activeWalletSession.expiresAtMs,
      });
      await repository.write(legacy);
      const db = await manager.getDB();
      const storeName = schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations;
      const future = {
        record_version: 'wallet_session_authorization_v7',
        wallet_session_id: 'wallet-session:late-future',
        wallet_id: activeWalletSession.walletId,
        wallet_authority_id: activeWalletSession.authorityId,
        wallet_auth_method_id: activeWalletSession.authMethodId,
        future_payload: { preserved: true, marker: 'late-future-row' },
      };
      await db.put(storeName, future);
      const next = repositoryModule.buildActiveWalletSessionV1({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
        authorizationId: 'authorization:late-v5-replacement',
        quotaId: 'wallet-quota:late-v5-replacement',
        authorityDigestB64u: activeWalletSession.authorityDigestB64u,
        authorityRevocationEpoch: activeWalletSession.authorityRevocationEpoch,
        capabilitySubjects: activeWalletSession.capabilitySubjects,
        issuedAtMs: activeWalletSession.issuedAtMs + 1,
        expiresAtMs: activeWalletSession.expiresAtMs,
      });
      const nextCredential = {
        kind: 'opaque_wallet_session_operation_credential_v1' as const,
        token: `wst_${'V'.repeat(43)}`,
        walletSessionId: 'wallet-session:late-v5-replacement',
      };
      await repository.writeExactWithOperationCredential({
        record: next,
        operationCredential: nextCredential,
      });
      const latest = repositoryModule.buildActiveWalletSessionV1({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
        authorizationId: 'authorization:late-v4-replacement',
        quotaId: 'wallet-quota:late-v4-replacement',
        authorityDigestB64u: activeWalletSession.authorityDigestB64u,
        authorityRevocationEpoch: activeWalletSession.authorityRevocationEpoch,
        capabilitySubjects: activeWalletSession.capabilitySubjects,
        issuedAtMs: activeWalletSession.issuedAtMs + 2,
        expiresAtMs: activeWalletSession.expiresAtMs,
      });
      const latestCredential = {
        kind: 'opaque_wallet_session_operation_credential_v1' as const,
        token: `wst_${'L'.repeat(43)}`,
        walletSessionId: 'wallet-session:late-v4-replacement',
      };
      await repository.replaceExactActive({
        active: latest,
        operationCredential: latestCredential,
        replacedAtMs: activeWalletSession.issuedAtMs + 2,
      });
      const rows = await db.getAllFromIndex(
        storeName,
        schemaNames.SEAMS_WALLET_INDEXES.walletId,
        activeWalletSession.walletId,
      );
      const legacyRaw = await db.get(storeName, legacy.walletSessionId);
      const futureRaw = await db.get(storeName, future.wallet_session_id);
      return { rows, legacy, legacyRaw, future, futureRaw, latest, latestCredential };
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
      authorityRef,
      walletSessionToken: fixture.operationCredential.token,
    },
  );

  expect(result.legacyRaw).toMatchObject({
    wallet_session_id: result.legacy.walletSessionId,
    wallet_id: result.legacy.walletId,
    status: result.legacy.status,
    expires_at_ms: result.legacy.expiresAtMs,
    record: result.legacy,
  });
  expect(result.futureRaw).toEqual(result.future);
  expect(result.rows).toHaveLength(5);
  expect(
    result.rows.filter((row) => row.record_version === 'wallet_session_authorization_v6'),
  ).toHaveLength(1);
  expect(result.rows).toContainEqual(
    expect.objectContaining({
      record_version: 'wallet_session_authorization_v6',
      status: 'active',
      wallet_session_id: 'wallet-session:late-v4-replacement',
    }),
  );
  expect(result.rows).toContainEqual(
    expect.objectContaining({
      record_version: 'wallet_session_authorization_v4',
      status: 'retired',
      wallet_session_id: 'authorization:linked-runtime',
    }),
  );
  expect(result.rows).toContainEqual(
    expect.objectContaining({
      record_version: 'wallet_session_authorization_v4',
      status: 'retired',
      wallet_session_id: 'authorization:late-v5-replacement',
    }),
  );
});
