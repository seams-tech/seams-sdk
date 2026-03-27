import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  clientDb: '/sdk/esm/core/indexedDB/passkeyClientDB/manager.js',
  nearKeysDb: '/sdk/esm/core/indexedDB/passkeyNearKeysDB/manager.js',
  unifiedDb: '/sdk/esm/core/indexedDB/index.js',
} as const;

test.describe('signer mutation saga pending behavior', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('confirms undeployed add-signer operations without activating the signer locally', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        try {
          const { PasskeyClientDBManager } = await import(paths.clientDb);
          const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDb);
          const { UnifiedIndexedDBManager } = await import(paths.unifiedDb);

          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const clientDB = new PasskeyClientDBManager();
          clientDB.setDbName(`PasskeyClientDB-signerSagaUndeployed-${suffix}`);
          const nearKeysDB = new PasskeyNearKeysDBManager();
          nearKeysDB.setDbName(`PasskeyNearKeys-signerSagaUndeployed-${suffix}`);
          const indexedDB = new UnifiedIndexedDBManager({ clientDB, nearKeysDB });

          await clientDB.upsertNearAccountProjection({
            nearAccountId: 'alice.testnet',
            deviceNumber: 2,
            operationalPublicKey: 'ed25519:device-2',
            lastUpdated: Date.now(),
            passkeyCredential: {
              id: 'cred-id',
              rawId: 'cred-raw-id',
            },
            version: 2,
          });
          const context = await clientDB.resolveNearAccountContext('alice.testnet');
          if (!context?.profileId) throw new Error('missing near account context');

          await clientDB.upsertChainAccount({
            profileId: context.profileId,
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'11'.repeat(20)}`,
            accountModel: 'erc4337',
            isPrimary: true,
            deployed: false,
          });
          await clientDB.upsertAccountSigner({
            profileId: context.profileId,
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'11'.repeat(20)}`,
            signerId: `0x${'aa'.repeat(20)}`,
            signerSlot: 2,
            signerType: 'threshold',
            status: 'pending',
          });
          await nearKeysDB.storeKeyMaterial({
            profileId: context.profileId,
            deviceNumber: 2,
            chainIdKey: 'evm:11155111',
            keyKind: 'threshold_share_v1',
            algorithm: 'webauthn-p256',
            publicKey: `04${'12'.repeat(64)}`,
            payload: {
              wrappedShare: 'ciphertext-b64u',
            },
            timestamp: Date.now(),
            schemaVersion: 1,
          });

          const before = await clientDB.listSignerOperations();
          const summary = await indexedDB.repairSignerMutationSagas();
          const signer = await clientDB.getAccountSigner({
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'11'.repeat(20)}`,
            signerId: `0x${'aa'.repeat(20)}`,
          });
          const after = await clientDB.listSignerOperations({
            statuses: ['queued', 'submitted', 'failed', 'confirmed', 'dead-letter'],
            dueBefore: Number.MAX_SAFE_INTEGER,
          });

          return {
            before,
            summary,
            signer,
            after,
          };
        } catch (error: any) {
          return { error: error?.message || String(error) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.error).toBeUndefined();
    expect(result.before).toHaveLength(1);
    expect(result.before[0]?.status).toBe('queued');
    expect(result.summary).toEqual({
      scanned: 1,
      confirmed: 1,
      failed: 0,
      deadLettered: 0,
    });
    expect(result.signer?.status).toBe('pending');
    expect(result.after).toHaveLength(1);
    expect(result.after[0]?.status).toBe('confirmed');
    expect(result.after[0]?.lastError ?? null).toBeNull();
  });

  test('keeps deployed add-signer operations pending until the owner-management executor exists', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        try {
          const { PasskeyClientDBManager } = await import(paths.clientDb);
          const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDb);
          const { UnifiedIndexedDBManager } = await import(paths.unifiedDb);

          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const clientDB = new PasskeyClientDBManager();
          clientDB.setDbName(`PasskeyClientDB-signerSagaDeployed-${suffix}`);
          const nearKeysDB = new PasskeyNearKeysDBManager();
          nearKeysDB.setDbName(`PasskeyNearKeys-signerSagaDeployed-${suffix}`);
          const indexedDB = new UnifiedIndexedDBManager({ clientDB, nearKeysDB });

          await clientDB.upsertNearAccountProjection({
            nearAccountId: 'alice.testnet',
            deviceNumber: 2,
            operationalPublicKey: 'ed25519:device-2',
            lastUpdated: Date.now(),
            passkeyCredential: {
              id: 'cred-id',
              rawId: 'cred-raw-id',
            },
            version: 2,
          });
          const context = await clientDB.resolveNearAccountContext('alice.testnet');
          if (!context?.profileId) throw new Error('missing near account context');

          await clientDB.upsertChainAccount({
            profileId: context.profileId,
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'22'.repeat(20)}`,
            accountModel: 'erc4337',
            isPrimary: true,
            deployed: true,
          });
          await clientDB.upsertAccountSigner({
            profileId: context.profileId,
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'22'.repeat(20)}`,
            signerId: `0x${'bb'.repeat(20)}`,
            signerSlot: 2,
            signerType: 'threshold',
            status: 'pending',
          });
          await nearKeysDB.storeKeyMaterial({
            profileId: context.profileId,
            deviceNumber: 2,
            chainIdKey: 'evm:11155111',
            keyKind: 'threshold_share_v1',
            algorithm: 'webauthn-p256',
            publicKey: `04${'34'.repeat(64)}`,
            payload: {
              wrappedShare: 'ciphertext-b64u',
            },
            timestamp: Date.now(),
            schemaVersion: 1,
          });

          const before = await clientDB.listSignerOperations();
          const repairNow = Date.now() + 60_000;
          const summary = await indexedDB.repairSignerMutationSagas({ now: repairNow });
          const signer = await clientDB.getAccountSigner({
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'22'.repeat(20)}`,
            signerId: `0x${'bb'.repeat(20)}`,
          });
          const after = await clientDB.listSignerOperations({
            statuses: ['queued', 'submitted', 'failed', 'confirmed', 'dead-letter'],
            dueBefore: Number.MAX_SAFE_INTEGER,
          });

          return {
            before,
            repairNow,
            summary,
            signer,
            after,
          };
        } catch (error: any) {
          return { error: error?.message || String(error) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.error).toBeUndefined();
    expect(result.before).toHaveLength(1);
    expect(result.before[0]?.status).toBe('queued');
    expect(result.summary).toEqual({
      scanned: 1,
      confirmed: 0,
      failed: 1,
      deadLettered: 0,
    });
    expect(result.signer?.status).toBe('pending');
    expect(result.after).toHaveLength(1);
    expect(result.after[0]?.status).toBe('failed');
    expect(result.after[0]?.attemptCount).toBe(1);
    expect(result.after[0]?.lastError).toContain('owner-management executor');
    expect(result.after[0]?.nextAttemptAt).toBe(result.repairNow + 5_000);
  });

  test('activates deployed add-signer operations after the owner-management executor succeeds', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        try {
          const { PasskeyClientDBManager } = await import(paths.clientDb);
          const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDb);
          const { UnifiedIndexedDBManager } = await import(paths.unifiedDb);

          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const clientDB = new PasskeyClientDBManager();
          clientDB.setDbName(`PasskeyClientDB-signerSagaExec-${suffix}`);
          const nearKeysDB = new PasskeyNearKeysDBManager();
          nearKeysDB.setDbName(`PasskeyNearKeys-signerSagaExec-${suffix}`);
          const indexedDB = new UnifiedIndexedDBManager({ clientDB, nearKeysDB });

          await clientDB.upsertNearAccountProjection({
            nearAccountId: 'alice.testnet',
            deviceNumber: 1,
            operationalPublicKey: 'ed25519:device-1',
            lastUpdated: Date.now(),
            passkeyCredential: {
              id: 'cred-id',
              rawId: 'cred-raw-id',
            },
            version: 2,
          });
          const context = await clientDB.resolveNearAccountContext('alice.testnet');
          if (!context?.profileId) throw new Error('missing near account context');

          await clientDB.upsertChainAccount({
            profileId: context.profileId,
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'33'.repeat(20)}`,
            accountModel: 'erc4337',
            isPrimary: true,
            deployed: true,
          });
          await clientDB.upsertAccountSigner({
            profileId: context.profileId,
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'33'.repeat(20)}`,
            signerId: `0x${'cc'.repeat(20)}`,
            signerSlot: 2,
            signerType: 'threshold',
            status: 'pending',
          });
          await nearKeysDB.storeKeyMaterial({
            profileId: context.profileId,
            deviceNumber: 2,
            chainIdKey: 'evm:11155111',
            keyKind: 'threshold_share_v1',
            algorithm: 'webauthn-p256',
            publicKey: `04${'56'.repeat(64)}`,
            payload: {
              wrappedShare: 'ciphertext-b64u',
            },
            timestamp: Date.now(),
            schemaVersion: 1,
          });

          const runtimeCalls: Array<Record<string, unknown>> = [];
          const summary = await indexedDB.repairSignerMutationSagasWithRuntime({
            now: Date.now() + 60_000,
            runtime: {
              executeDeployedAddSigner: async (input: Record<string, unknown>) => {
                runtimeCalls.push({
                  nearAccountId: input.nearAccountId,
                  opType: (input.op as any)?.opType,
                  signerId: (input.signer as any)?.signerId,
                  accountAddress: (input.chainAccount as any)?.accountAddress,
                });
                return { txHash: `0x${'ab'.repeat(32)}` };
              },
            },
          });
          const signer = await clientDB.getAccountSigner({
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'33'.repeat(20)}`,
            signerId: `0x${'cc'.repeat(20)}`,
          });
          const after = await clientDB.listSignerOperations({
            statuses: ['queued', 'submitted', 'failed', 'confirmed', 'dead-letter'],
            dueBefore: Number.MAX_SAFE_INTEGER,
          });

          return {
            summary,
            signer,
            after,
            runtimeCalls,
          };
        } catch (error: any) {
          return { error: error?.message || String(error) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.error).toBeUndefined();
    expect(result.summary).toEqual({
      scanned: 1,
      confirmed: 1,
      failed: 0,
      deadLettered: 0,
    });
    expect(result.runtimeCalls).toEqual([
      {
        nearAccountId: 'alice.testnet',
        opType: 'add-signer',
        signerId: `0x${'cc'.repeat(20)}`,
        accountAddress: `0x${'33'.repeat(20)}`,
      },
    ]);
    expect(result.signer?.status).toBe('active');
    expect(result.after).toHaveLength(1);
    expect(result.after[0]?.status).toBe('confirmed');
    expect(result.after[0]?.txHash).toBe(`0x${'ab'.repeat(32)}`);
  });

  test('confirms deployed revoke-signer operations after the owner-management executor succeeds', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        try {
          const { PasskeyClientDBManager } = await import(paths.clientDb);
          const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDb);
          const { UnifiedIndexedDBManager } = await import(paths.unifiedDb);

          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const clientDB = new PasskeyClientDBManager();
          clientDB.setDbName(`PasskeyClientDB-signerSagaRevoke-${suffix}`);
          const nearKeysDB = new PasskeyNearKeysDBManager();
          nearKeysDB.setDbName(`PasskeyNearKeys-signerSagaRevoke-${suffix}`);
          const indexedDB = new UnifiedIndexedDBManager({ clientDB, nearKeysDB });

          await clientDB.upsertNearAccountProjection({
            nearAccountId: 'alice.testnet',
            deviceNumber: 1,
            operationalPublicKey: 'ed25519:device-1',
            lastUpdated: Date.now(),
            passkeyCredential: {
              id: 'cred-id',
              rawId: 'cred-raw-id',
            },
            version: 2,
          });
          const context = await clientDB.resolveNearAccountContext('alice.testnet');
          if (!context?.profileId) throw new Error('missing near account context');

          await clientDB.upsertChainAccount({
            profileId: context.profileId,
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'44'.repeat(20)}`,
            accountModel: 'erc4337',
            isPrimary: true,
            deployed: true,
          });
          await clientDB.upsertAccountSigner({
            profileId: context.profileId,
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'44'.repeat(20)}`,
            signerId: `0x${'dd'.repeat(20)}`,
            signerSlot: 2,
            signerType: 'threshold',
            status: 'active',
            mutation: { routeThroughOutbox: false },
          });
          await nearKeysDB.storeKeyMaterial({
            profileId: context.profileId,
            deviceNumber: 2,
            chainIdKey: 'evm:11155111',
            keyKind: 'threshold_share_v1',
            algorithm: 'webauthn-p256',
            publicKey: `04${'78'.repeat(64)}`,
            payload: {
              wrappedShare: 'ciphertext-b64u',
            },
            timestamp: Date.now(),
            schemaVersion: 1,
          });
          await clientDB.setAccountSignerStatus({
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'44'.repeat(20)}`,
            signerId: `0x${'dd'.repeat(20)}`,
            status: 'revoked',
            removedAt: Date.now(),
          });

          const runtimeCalls: Array<Record<string, unknown>> = [];
          const summary = await indexedDB.repairSignerMutationSagasWithRuntime({
            now: Date.now() + 60_000,
            runtime: {
              executeDeployedAddSigner: async () => ({ txHash: null }),
              executeDeployedRemoveSigner: async (input: Record<string, unknown>) => {
                runtimeCalls.push({
                  nearAccountId: input.nearAccountId,
                  opType: (input.op as any)?.opType,
                  signerId: (input.signer as any)?.signerId,
                  accountAddress: (input.chainAccount as any)?.accountAddress,
                });
                return { txHash: `0x${'bc'.repeat(32)}` };
              },
            },
          });
          const signer = await clientDB.getAccountSigner({
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'44'.repeat(20)}`,
            signerId: `0x${'dd'.repeat(20)}`,
          });
          const keys = await nearKeysDB.listKeyMaterialByProfileAndDevice(
            context.profileId,
            2,
            'evm:11155111',
          );
          const after = await clientDB.listSignerOperations({
            statuses: ['queued', 'submitted', 'failed', 'confirmed', 'dead-letter'],
            dueBefore: Number.MAX_SAFE_INTEGER,
          });

          return {
            summary,
            signer,
            keys,
            after,
            runtimeCalls,
          };
        } catch (error: any) {
          return { error: error?.message || String(error) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.error).toBeUndefined();
    expect(result.summary).toEqual({
      scanned: 1,
      confirmed: 1,
      failed: 0,
      deadLettered: 0,
    });
    expect(result.runtimeCalls).toEqual([
      {
        nearAccountId: 'alice.testnet',
        opType: 'revoke-signer',
        signerId: `0x${'dd'.repeat(20)}`,
        accountAddress: `0x${'44'.repeat(20)}`,
      },
    ]);
    expect(result.signer?.status).toBe('revoked');
    expect(result.keys).toHaveLength(0);
    expect(result.after).toHaveLength(1);
    expect(result.after[0]?.status).toBe('confirmed');
    expect(result.after[0]?.txHash).toBe(`0x${'bc'.repeat(32)}`);
  });
});
