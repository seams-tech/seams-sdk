import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { buildLinkedDeviceUnlockRuntimeFixture } from './helpers/linkedDeviceUnlockRuntime.fixtures';
import { buildWalletSessionCleanupPersistenceFixture } from './helpers/walletSessionCleanup.fixtures';

test('clearing Wallet Session rows preserves unrelated IndexedDB stores', async ({ page }) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const persistence = buildWalletSessionCleanupPersistenceFixture({
    walletId: fixture.activeWalletSession.walletId,
    authorityId: fixture.activeWalletSession.authorityId,
  });
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const result = await page.evaluate(
    async ({ activeWalletSession, operationCredential, persistence }) => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(`cleanup_${crypto.randomUUID()}`);
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repository = new repositoryModule.WalletSessionAuthorizationRepository(manager);
      const sessionStore = schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations;

      await repository.writeExactWithOperationCredential({
        record: activeWalletSession,
        operationCredential,
      });
      const survivor = repositoryModule.buildActiveWalletSessionV1({
        walletId: 'wallet:cleanup-survivor',
        authorityId: 'authority:cleanup-survivor',
        authMethodId: 'wallet-auth-method:cleanup-survivor',
        authorizationId: 'authorization:cleanup-survivor',
        quotaId: 'wallet-quota:cleanup-survivor',
        authorityDigestB64u: activeWalletSession.authorityDigestB64u,
        authorityRevocationEpoch: activeWalletSession.authorityRevocationEpoch,
        capabilitySubjects: activeWalletSession.capabilitySubjects,
        issuedAtMs: activeWalletSession.issuedAtMs,
        expiresAtMs: activeWalletSession.expiresAtMs,
      });
      const survivorCredential = {
        kind: 'opaque_wallet_session_operation_credential_v1' as const,
        token: `wst_${'s'.repeat(43)}`,
        walletSessionId: 'wallet-session:cleanup-survivor',
      };
      await repository.writeExactWithOperationCredential({
        record: survivor,
        operationCredential: survivorCredential,
      });

      const db = await manager.getDB();
      for (const row of persistence.legacyRows) await db.put(sessionStore, row);
      await db.put(schemaNames.SEAMS_WALLET_STORES.wallets, persistence.preservedRows.wallet);
      await db.put(
        schemaNames.SEAMS_WALLET_STORES.walletAuthorities,
        persistence.preservedRows.authority,
      );
      await db.put(
        schemaNames.SEAMS_WALLET_STORES.walletAuthMethods,
        persistence.preservedRows.authMethod,
      );
      await db.put(
        schemaNames.SEAMS_WALLET_STORES.walletAuthoritySignerMaterials,
        persistence.preservedRows.signerMaterial,
      );
      await db.put(
        schemaNames.SEAMS_WALLET_STORES.walletAuthorityExportRoots,
        persistence.preservedRows.exportRoot,
      );
      await db.put(
        schemaNames.SEAMS_WALLET_STORES.pendingWalletRecoveryCodeBackups,
        persistence.preservedRows.recoveryCode,
      );
      await db.put(schemaNames.SEAMS_WALLET_STORES.appState, persistence.preservedRows.appState);

      await repository.clearWallet(activeWalletSession.walletId);

      const remainingSessionIds = (
        await db.getAll(schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations)
      ).map((row) => row.wallet_session_id);
      const preservedReadback = {
        wallet: await db.get(schemaNames.SEAMS_WALLET_STORES.wallets, activeWalletSession.walletId),
        authority: await db.get(
          schemaNames.SEAMS_WALLET_STORES.walletAuthorities,
          activeWalletSession.authorityId,
        ),
        authMethod: await db.get(
          schemaNames.SEAMS_WALLET_STORES.walletAuthMethods,
          persistence.readbackKeys.authMethod,
        ),
        signerMaterial: await db.get(
          schemaNames.SEAMS_WALLET_STORES.walletAuthoritySignerMaterials,
          persistence.readbackKeys.signerMaterial,
        ),
        exportRoot: await db.get(schemaNames.SEAMS_WALLET_STORES.walletAuthorityExportRoots, [
          ...persistence.readbackKeys.exportRoot,
        ]),
        recoveryCode: await db.get(
          schemaNames.SEAMS_WALLET_STORES.pendingWalletRecoveryCodeBackups,
          persistence.readbackKeys.recoveryCode,
        ),
        appState: await db.get(
          schemaNames.SEAMS_WALLET_STORES.appState,
          persistence.readbackKeys.appState,
        ),
      };
      const targetSession = await db.get(sessionStore, operationCredential.walletSessionId);
      const legacySessionRows = await Promise.all(
        persistence.legacyRows.map((row) => db.get(sessionStore, row.wallet_session_id)),
      );
      const survivorSession = await db.get(sessionStore, survivorCredential.walletSessionId);
      manager.close();
      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });
      return {
        legacySessionRows,
        preservedReadback,
        preservedRows: persistence.preservedRows,
        remainingSessionIds,
        survivorSession,
        targetSession,
      };
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
      persistence,
    },
  );

  expect(result.targetSession).toBeUndefined();
  expect(result.legacySessionRows).toEqual([undefined, undefined, undefined]);
  expect(result.remainingSessionIds).toEqual(['wallet-session:cleanup-survivor']);
  expect(result.survivorSession).toMatchObject({
    wallet_session_id: 'wallet-session:cleanup-survivor',
    wallet_id: 'wallet:cleanup-survivor',
  });
  expect(result.preservedReadback).toEqual(result.preservedRows);
});
