import { expect, test } from '@playwright/test';
import { buildActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { buildWalletAuthAuthorityRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
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
        activeWalletSession.authorizationId,
      );
      const reread = await repository.readExactWithOperationCredential({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
      });
      return { raw, reread, operationCredential };
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      walletSessionId: fixture.ed25519Session.walletSessionId,
    },
  );

  expect(result.raw).toMatchObject({
    record_version: 'wallet_session_authorization_v5',
    operation_credential: result.operationCredential,
  });
  expect(result.reread).toEqual({
    record: fixture.activeWalletSession,
    operationCredential: result.operationCredential,
  });
});

test('curve projection upsert preserves a coexisting exact V5 operation credential row', async ({
  page,
}) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const curveProjection = buildActiveWalletSessionAuthorizationProjection({
    walletId: fixture.walletId,
    walletSessionId: fixture.ed25519Session.walletSessionId,
    quotaId: fixture.ed25519Session.quotaId,
    walletSessionTokens: {
      kind: 'near_ed25519',
      ed25519: {
        authorizationId: fixture.activeWalletSession.authorizationId,
        walletSessionToken: fixture.ed25519Session.walletSessionToken,
        thresholdSessionId: fixture.ed25519Session.thresholdSessionId,
      },
    },
    authMethod: 'passkey',
    authority: buildWalletAuthAuthorityRefFixture({
      walletId: String(fixture.walletId),
      label: 'linked-runtime',
    }),
    expiresAtMs: fixture.activeWalletSession.expiresAtMs,
  });
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const result = await page.evaluate(
    async ({ activeWalletSession, curveProjection, operationCredential }) => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `operation_credential_v5_curve_merge_${crypto.randomUUID()}`,
      );
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repository = new repositoryModule.WalletSessionAuthorizationRepository(manager);
      await repository.writeExactWithOperationCredential({
        record: activeWalletSession,
        operationCredential,
      });
      const merged = await repository.upsertActiveWithCurveMerge({
        incoming: curveProjection,
        writtenAtMs: Date.now(),
      });
      const active = await repository.readActiveForWallet(curveProjection.walletId);
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
      return { merged, active, exact, rows };
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      curveProjection,
      operationCredential: fixture.operationCredential,
    },
  );

  expect(result.merged).toEqual(curveProjection);
  expect(result.active).toEqual({ kind: 'found', projection: curveProjection });
  expect(result.exact).toEqual({
    record: fixture.activeWalletSession,
    operationCredential: fixture.operationCredential,
  });
  expect(result.rows).toHaveLength(2);
  expect(
    result.rows.find((row) => row.record_version === 'wallet_session_authorization_v5'),
  ).toMatchObject({
    wallet_session_id: fixture.activeWalletSession.authorizationId,
    operation_credential: fixture.operationCredential,
  });
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
      return await repository.readExactWithOperationCredential({
        walletId: activeWalletSession.walletId,
        authorityId: activeWalletSession.authorityId,
        authMethodId: activeWalletSession.authMethodId,
      });
    },
    { activeWalletSession: fixture.activeWalletSession },
  );

  expect(result).toBeNull();
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
        activeWalletSession.authorizationId,
      );
      if (!raw) throw new Error('stored V5 Wallet Session row is missing');
      await db.put(schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations, {
        ...raw,
        operation_credential: {
          ...raw.operation_credential,
          token: 'wst_invalid',
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
