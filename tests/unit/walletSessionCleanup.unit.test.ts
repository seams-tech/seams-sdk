import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { buildLinkedDeviceUnlockRuntimeFixture } from './helpers/linkedDeviceUnlockRuntime.fixtures';

test('clearing Wallet Session rows preserves unrelated IndexedDB stores', async ({ page }) => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

  const result = await page.evaluate(
    async ({ activeWalletSession, operationCredential }) => {
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
      const legacyRows = [
        {
          record_version: 'wallet_session_authorization_v3',
          wallet_session_id: 'wallet-session:cleanup-v3',
          wallet_id: activeWalletSession.walletId,
          wallet_authority_id: activeWalletSession.authorityId,
          wallet_auth_method_id: activeWalletSession.authMethodId,
          record: { status: 'retired', marker: 'v3' },
        },
        {
          record_version: 'wallet_session_authorization_v4',
          wallet_session_id: 'wallet-session:cleanup-v4',
          wallet_id: activeWalletSession.walletId,
          wallet_authority_id: activeWalletSession.authorityId,
          wallet_auth_method_id: activeWalletSession.authMethodId,
          record: { status: 'retired', marker: 'v4' },
        },
        {
          record_version: 'wallet_session_authorization_v5',
          wallet_session_id: 'wallet-session:cleanup-v5',
          wallet_id: activeWalletSession.walletId,
          wallet_authority_id: activeWalletSession.authorityId,
          wallet_auth_method_id: activeWalletSession.authMethodId,
          record: { status: 'retired', marker: 'v5' },
        },
      ];
      for (const row of legacyRows) await db.put(sessionStore, row);

      const preservedRows = {
        wallet: {
          wallet_id: activeWalletSession.walletId,
          rp_id: 'wallet.example.test',
          status: 'active',
          updated_at: 1,
          record: { marker: 'wallet' },
        },
        authority: {
          authority_id: activeWalletSession.authorityId,
          wallet_id: activeWalletSession.walletId,
          state: 'active',
          device_id: 'device:cleanup',
          updated_at: 1,
          record: { marker: 'authority' },
        },
        authMethod: {
          wallet_auth_method_id: 'wallet-auth-method:cleanup',
          wallet_id: activeWalletSession.walletId,
          wallet_authority_id: activeWalletSession.authorityId,
          kind: 'email_otp',
          auth_method: 'email_otp',
          rp_id: 'wallet.example.test',
          auth_identifier_key: 'email:cleanup',
          credential_id_b64u: 'credential-cleanup',
          status: 'active',
          updated_at: 1,
          record: { marker: 'auth-method' },
        },
        signerMaterial: {
          wallet_authority_id: activeWalletSession.authorityId,
          wallet_auth_method_id: 'wallet-auth-method:cleanup',
          activation_id: 'activation:cleanup',
          key_family: 'ed25519',
          sealed_material_b64u: 'sealed-material-cleanup',
          sealed_material_digest_b64u: 'digest-cleanup',
          record: { marker: 'signer-material' },
        },
        exportRoot: {
          wallet_authority_id: activeWalletSession.authorityId,
          wallet_auth_method_id: 'wallet-auth-method:cleanup',
          wallet_key_id: 'wallet-key:cleanup',
          sealed_root_b64u: 'sealed-root-cleanup',
          sealed_root_digest_b64u: 'digest-cleanup',
          record: { marker: 'export-root' },
        },
        recoveryCode: {
          record_version: 1,
          wallet_id: activeWalletSession.walletId,
          enrollment_id: 'wallet_recovery_codes_v1',
          recovery_codes_issued_at_ms: 1,
          status: 'pending',
          key: 'recovery-key-cleanup',
          iv: new Uint8Array([1, 2, 3]),
          ciphertext: new Uint8Array([4, 5, 6]),
        },
        appState: {
          key: 'cleanup-preserve',
          value: { marker: 'app-state' },
        },
      };
      await db.put(schemaNames.SEAMS_WALLET_STORES.wallets, preservedRows.wallet);
      await db.put(schemaNames.SEAMS_WALLET_STORES.walletAuthorities, preservedRows.authority);
      await db.put(schemaNames.SEAMS_WALLET_STORES.walletAuthMethods, preservedRows.authMethod);
      await db.put(
        schemaNames.SEAMS_WALLET_STORES.walletAuthoritySignerMaterials,
        preservedRows.signerMaterial,
      );
      await db.put(
        schemaNames.SEAMS_WALLET_STORES.walletAuthorityExportRoots,
        preservedRows.exportRoot,
      );
      await db.put(
        schemaNames.SEAMS_WALLET_STORES.pendingWalletRecoveryCodeBackups,
        preservedRows.recoveryCode,
      );
      await db.put(schemaNames.SEAMS_WALLET_STORES.appState, preservedRows.appState);

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
          'wallet-auth-method:cleanup',
        ),
        signerMaterial: await db.get(
          schemaNames.SEAMS_WALLET_STORES.walletAuthoritySignerMaterials,
          [activeWalletSession.authorityId, 'wallet-auth-method:cleanup', 'activation:cleanup'],
        ),
        exportRoot: await db.get(schemaNames.SEAMS_WALLET_STORES.walletAuthorityExportRoots, [
          activeWalletSession.authorityId,
          'wallet-auth-method:cleanup',
          'wallet-key:cleanup',
        ]),
        recoveryCode: await db.get(
          schemaNames.SEAMS_WALLET_STORES.pendingWalletRecoveryCodeBackups,
          [activeWalletSession.walletId, 'wallet_recovery_codes_v1'],
        ),
        appState: await db.get(schemaNames.SEAMS_WALLET_STORES.appState, 'cleanup-preserve'),
      };
      const targetSession = await db.get(sessionStore, operationCredential.walletSessionId);
      const legacySessionRows = await Promise.all(
        legacyRows.map((row) => db.get(sessionStore, row.wallet_session_id)),
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
        preservedRows,
        remainingSessionIds,
        survivorSession,
        targetSession,
      };
    },
    {
      activeWalletSession: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
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
