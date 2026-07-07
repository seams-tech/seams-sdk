import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  unifiedDb: '/_test-sdk/esm/core/indexedDB/index.js',
} as const;

test.describe('signer mutation saga pending behavior', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('confirms undeployed add-signer operations without activating the signer locally', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        try {
          const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
            await import(paths.unifiedDb);

          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const seamsWalletDB = new SeamsWalletDBManager();
          seamsWalletDB.setDbName(createSeamsTestWalletDbName(`signer-saga-undeployed-${suffix}`));
          const indexedDB = new UnifiedIndexedDBManager({ seamsWalletDB });
          const nearAccountRef = {
            chainIdKey: 'near:testnet',
            accountAddress: 'alice.testnet',
          };
          const profileId = 'profile-near:alice.testnet';

          await indexedDB.upsertProfile({
            profileId,
            defaultSignerSlot: 2,
            passkeyCredential: {
              id: 'cred-id',
              rawId: 'cred-raw-id',
            },
          });
          await indexedDB.upsertChainAccount({
            profileId,
            chainIdKey: nearAccountRef.chainIdKey,
            accountAddress: nearAccountRef.accountAddress,
            accountModel: 'near-native',
            isPrimary: true,
          });
          await indexedDB.activateAccountSigner({
            account: {
              profileId,
              chainIdKey: nearAccountRef.chainIdKey,
              accountAddress: nearAccountRef.accountAddress,
              accountModel: 'near-native',
            },
            signer: {
              signerId: 'ed25519:device-2',
              signerType: 'threshold',
              signerKind: 'threshold-ed25519',
              signerAuthMethod: 'passkey',
              signerSource: 'passkey_registration',
            },
            activationPolicy: { mode: 'fail_if_occupied', signerSlot: 2 },
            preferredSlot: 2,
            mutation: { routeThroughOutbox: false },
          });
          const context = await indexedDB.resolveProfileAccountContext(nearAccountRef);
          if (!context?.profileId) throw new Error('missing near account context');

          await indexedDB.upsertChainAccount({
            profileId: context.profileId,
            chainIdKey: 'evm:eip155:11155111',
            accountAddress: `0x${'11'.repeat(20)}`,
            accountModel: 'threshold-ecdsa',
            isPrimary: true,
            deployed: false,
          });
          await indexedDB.stageAccountSigner({
            account: {
              profileId: context.profileId,
              chainIdKey: 'evm:eip155:11155111',
              accountAddress: `0x${'11'.repeat(20)}`,
              accountModel: 'threshold-ecdsa',
            },
            signer: {
              signerId: `0x${'aa'.repeat(20)}`,
              signerSlot: 2,
              signerType: 'threshold',
              signerKind: 'threshold-ecdsa',
              signerAuthMethod: 'passkey',
              signerSource: 'passkey_registration',
              metadata: {
                keyHandle: 'add-key-handle-undeployed',
                ecdsaThresholdKeyId: 'ecdsa-key-undeployed',
                thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
                chainTarget: {
                  kind: 'evm',
                  namespace: 'eip155',
                  chainId: 11155111,
                  networkSlug: 'sepolia',
                },
              },
            },
            mutation: { routeThroughOutbox: true },
          });
          await indexedDB.storeKeyMaterial({
            profileId: context.profileId,
            signerSlot: 2,
            chainIdKey: 'evm:eip155:11155111',
            accountAddress: `0x${'11'.repeat(20)}`,
            keyKind: 'threshold_share_v1',
            algorithm: 'webauthn-p256',
            publicKey: `04${'12'.repeat(64)}`,
            signerId: `0x${'aa'.repeat(20)}`,
            payload: {
              wrappedShare: 'ciphertext-b64u',
            },
            timestamp: Date.now(),
            schemaVersion: 1,
          });

          const before = await indexedDB.listSignerOperations();
          const summary = await indexedDB.repairSignerMutationSagas();
          const signer = await indexedDB.getAccountSigner({
            chainIdKey: 'evm:eip155:11155111',
            accountAddress: `0x${'11'.repeat(20)}`,
            signerId: `0x${'aa'.repeat(20)}`,
          });
          const after = await indexedDB.listSignerOperations({
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

  test('confirms deployed add-signer operations when key material exists', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        try {
          const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
            await import(paths.unifiedDb);

          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const seamsWalletDB = new SeamsWalletDBManager();
          seamsWalletDB.setDbName(createSeamsTestWalletDbName(`signer-saga-deployed-${suffix}`));
          const indexedDB = new UnifiedIndexedDBManager({ seamsWalletDB });
          const nearAccountRef = {
            chainIdKey: 'near:testnet',
            accountAddress: 'alice.testnet',
          };
          const profileId = 'profile-near:alice.testnet';

          await indexedDB.upsertProfile({
            profileId,
            defaultSignerSlot: 2,
            passkeyCredential: {
              id: 'cred-id',
              rawId: 'cred-raw-id',
            },
          });
          await indexedDB.upsertChainAccount({
            profileId,
            chainIdKey: nearAccountRef.chainIdKey,
            accountAddress: nearAccountRef.accountAddress,
            accountModel: 'near-native',
            isPrimary: true,
          });
          await indexedDB.activateAccountSigner({
            account: {
              profileId,
              chainIdKey: nearAccountRef.chainIdKey,
              accountAddress: nearAccountRef.accountAddress,
              accountModel: 'near-native',
            },
            signer: {
              signerId: 'ed25519:device-2',
              signerType: 'threshold',
              signerKind: 'threshold-ed25519',
              signerAuthMethod: 'passkey',
              signerSource: 'passkey_registration',
            },
            activationPolicy: { mode: 'fail_if_occupied', signerSlot: 2 },
            preferredSlot: 2,
            mutation: { routeThroughOutbox: false },
          });
          const context = await indexedDB.resolveProfileAccountContext(nearAccountRef);
          if (!context?.profileId) throw new Error('missing near account context');

          await indexedDB.upsertChainAccount({
            profileId: context.profileId,
            chainIdKey: 'evm:eip155:11155111',
            accountAddress: `0x${'22'.repeat(20)}`,
            accountModel: 'threshold-ecdsa',
            isPrimary: true,
            deployed: true,
          });
          await indexedDB.stageAccountSigner({
            account: {
              profileId: context.profileId,
              chainIdKey: 'evm:eip155:11155111',
              accountAddress: `0x${'22'.repeat(20)}`,
              accountModel: 'threshold-ecdsa',
            },
            signer: {
              signerId: `0x${'bb'.repeat(20)}`,
              signerSlot: 2,
              signerType: 'threshold',
              signerKind: 'threshold-ecdsa',
              signerAuthMethod: 'passkey',
              signerSource: 'passkey_registration',
              metadata: {
                keyHandle: 'add-key-handle-deployed',
                ecdsaThresholdKeyId: 'ecdsa-key-deployed',
                thresholdOwnerAddress: `0x${'22'.repeat(20)}`,
                chainTarget: {
                  kind: 'evm',
                  namespace: 'eip155',
                  chainId: 11155111,
                  networkSlug: 'sepolia',
                },
              },
            },
            mutation: { routeThroughOutbox: true },
          });
          await indexedDB.storeKeyMaterial({
            profileId: context.profileId,
            signerSlot: 2,
            chainIdKey: 'evm:eip155:11155111',
            accountAddress: `0x${'22'.repeat(20)}`,
            keyKind: 'threshold_share_v1',
            algorithm: 'webauthn-p256',
            publicKey: `04${'34'.repeat(64)}`,
            signerId: `0x${'bb'.repeat(20)}`,
            payload: {
              wrappedShare: 'ciphertext-b64u',
            },
            timestamp: Date.now(),
            schemaVersion: 1,
          });

          const before = await indexedDB.listSignerOperations();
          const repairNow = Date.now() + 60_000;
          const summary = await indexedDB.repairSignerMutationSagasWithRuntime({
            now: repairNow,
            runtime: {
              resolveOwnerAccountId: async () => 'alice.testnet',
            },
          });
          const signer = await indexedDB.getAccountSigner({
            chainIdKey: 'evm:eip155:11155111',
            accountAddress: `0x${'22'.repeat(20)}`,
            signerId: `0x${'bb'.repeat(20)}`,
          });
          const after = await indexedDB.listSignerOperations({
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
      confirmed: 1,
      failed: 0,
      deadLettered: 0,
    });
    expect(result.signer?.status).toBe('pending');
    expect(result.after).toHaveLength(1);
    expect(result.after[0]?.status).toBe('confirmed');
    expect(result.after[0]?.lastError ?? null).toBeNull();
  });

  test('confirms deployed add-signer operations after key material validation succeeds', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        try {
          const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
            await import(paths.unifiedDb);

          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const seamsWalletDB = new SeamsWalletDBManager();
          seamsWalletDB.setDbName(createSeamsTestWalletDbName(`signer-saga-exec-${suffix}`));
          const indexedDB = new UnifiedIndexedDBManager({ seamsWalletDB });
          const nearAccountRef = {
            chainIdKey: 'near:testnet',
            accountAddress: 'alice.testnet',
          };
          const profileId = 'profile-near:alice.testnet';

          await indexedDB.upsertProfile({
            profileId,
            defaultSignerSlot: 1,
            passkeyCredential: {
              id: 'cred-id',
              rawId: 'cred-raw-id',
            },
          });
          await indexedDB.upsertChainAccount({
            profileId,
            chainIdKey: nearAccountRef.chainIdKey,
            accountAddress: nearAccountRef.accountAddress,
            accountModel: 'near-native',
            isPrimary: true,
          });
          await indexedDB.activateAccountSigner({
            account: {
              profileId,
              chainIdKey: nearAccountRef.chainIdKey,
              accountAddress: nearAccountRef.accountAddress,
              accountModel: 'near-native',
            },
            signer: {
              signerId: 'ed25519:device-1',
              signerType: 'threshold',
              signerKind: 'threshold-ed25519',
              signerAuthMethod: 'passkey',
              signerSource: 'passkey_registration',
            },
            activationPolicy: { mode: 'fail_if_occupied', signerSlot: 1 },
            preferredSlot: 1,
            mutation: { routeThroughOutbox: false },
          });
          const context = await indexedDB.resolveProfileAccountContext(nearAccountRef);
          if (!context?.profileId) throw new Error('missing near account context');

          await indexedDB.upsertChainAccount({
            profileId: context.profileId,
            chainIdKey: 'evm:eip155:11155111',
            accountAddress: `0x${'33'.repeat(20)}`,
            accountModel: 'threshold-ecdsa',
            isPrimary: true,
            deployed: true,
          });
          await indexedDB.stageAccountSigner({
            account: {
              profileId: context.profileId,
              chainIdKey: 'evm:eip155:11155111',
              accountAddress: `0x${'33'.repeat(20)}`,
              accountModel: 'threshold-ecdsa',
            },
            signer: {
              signerId: `0x${'cc'.repeat(20)}`,
              signerSlot: 2,
              signerType: 'threshold',
              signerKind: 'threshold-ecdsa',
              signerAuthMethod: 'passkey',
              signerSource: 'passkey_registration',
              metadata: {
                keyHandle: 'add-key-handle-validated',
                ecdsaThresholdKeyId: 'ecdsa-key-validated',
                thresholdOwnerAddress: `0x${'33'.repeat(20)}`,
                chainTarget: {
                  kind: 'evm',
                  namespace: 'eip155',
                  chainId: 11155111,
                  networkSlug: 'sepolia',
                },
              },
            },
            mutation: { routeThroughOutbox: true },
          });
          await indexedDB.storeKeyMaterial({
            profileId: context.profileId,
            signerSlot: 2,
            chainIdKey: 'evm:eip155:11155111',
            accountAddress: `0x${'33'.repeat(20)}`,
            keyKind: 'threshold_share_v1',
            algorithm: 'webauthn-p256',
            publicKey: `04${'56'.repeat(64)}`,
            signerId: `0x${'cc'.repeat(20)}`,
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
              resolveOwnerAccountId: async () => 'alice.testnet',
              executeDeployedAddSigner: async (input: Record<string, unknown>) => {
                runtimeCalls.push({
                  ownerAccountId: input.ownerAccountId,
                  opType: (input.op as any)?.opType,
                  signerId: (input.signer as any)?.signerId,
                  accountAddress: (input.chainAccount as any)?.accountAddress,
                });
                return { txHash: `0x${'ab'.repeat(32)}` };
              },
            },
          });
          const signer = await indexedDB.getAccountSigner({
            chainIdKey: 'evm:eip155:11155111',
            accountAddress: `0x${'33'.repeat(20)}`,
            signerId: `0x${'cc'.repeat(20)}`,
          });
          const after = await indexedDB.listSignerOperations({
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
    expect(result.runtimeCalls).toEqual([]);
    expect(result.signer?.status).toBe('pending');
    expect(result.after).toHaveLength(1);
    expect(result.after[0]?.status).toBe('confirmed');
    expect(result.after[0]?.txHash ?? null).toBeNull();
  });

  test('confirms deployed revoke-signer operations and deletes local key material', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        try {
          const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
            await import(paths.unifiedDb);

          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const seamsWalletDB = new SeamsWalletDBManager();
          seamsWalletDB.setDbName(createSeamsTestWalletDbName(`signer-saga-revoke-${suffix}`));
          const indexedDB = new UnifiedIndexedDBManager({ seamsWalletDB });
          const nearAccountRef = {
            chainIdKey: 'near:testnet',
            accountAddress: 'alice.testnet',
          };
          const profileId = 'profile-near:alice.testnet';

          await indexedDB.upsertProfile({
            profileId,
            defaultSignerSlot: 1,
            passkeyCredential: {
              id: 'cred-id',
              rawId: 'cred-raw-id',
            },
          });
          await indexedDB.upsertChainAccount({
            profileId,
            chainIdKey: nearAccountRef.chainIdKey,
            accountAddress: nearAccountRef.accountAddress,
            accountModel: 'near-native',
            isPrimary: true,
          });
          await indexedDB.activateAccountSigner({
            account: {
              profileId,
              chainIdKey: nearAccountRef.chainIdKey,
              accountAddress: nearAccountRef.accountAddress,
              accountModel: 'near-native',
            },
            signer: {
              signerId: 'ed25519:device-1',
              signerType: 'threshold',
              signerKind: 'threshold-ed25519',
              signerAuthMethod: 'passkey',
              signerSource: 'passkey_registration',
            },
            activationPolicy: { mode: 'fail_if_occupied', signerSlot: 1 },
            preferredSlot: 1,
            mutation: { routeThroughOutbox: false },
          });
          const context = await indexedDB.resolveProfileAccountContext(nearAccountRef);
          if (!context?.profileId) throw new Error('missing near account context');

          await indexedDB.upsertChainAccount({
            profileId: context.profileId,
            chainIdKey: 'evm:eip155:11155111',
            accountAddress: `0x${'44'.repeat(20)}`,
            accountModel: 'threshold-ecdsa',
            isPrimary: true,
            deployed: true,
          });
          await indexedDB.activateAccountSigner({
            account: {
              profileId: context.profileId,
              chainIdKey: 'evm:eip155:11155111',
              accountAddress: `0x${'44'.repeat(20)}`,
              accountModel: 'threshold-ecdsa',
            },
            signer: {
              signerId: `0x${'dd'.repeat(20)}`,
              signerType: 'threshold',
            signerKind: 'threshold-ecdsa',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            metadata: {
              keyHandle: 'revoke-key-handle',
              ecdsaThresholdKeyId: 'ecdsa-key-revoke',
              thresholdOwnerAddress: `0x${'44'.repeat(20)}`,
              chainTarget: {
                kind: 'evm',
                namespace: 'eip155',
                chainId: 11155111,
                networkSlug: 'sepolia',
              },
            },
          },
            activationPolicy: { mode: 'fail_if_occupied', signerSlot: 2 },
            preferredSlot: 2,
            mutation: { routeThroughOutbox: false },
          });
          await indexedDB.storeKeyMaterial({
            profileId: context.profileId,
            signerSlot: 2,
            chainIdKey: 'evm:eip155:11155111',
            accountAddress: `0x${'44'.repeat(20)}`,
            keyKind: 'threshold_share_v1',
            algorithm: 'webauthn-p256',
            publicKey: `04${'78'.repeat(64)}`,
            signerId: `0x${'dd'.repeat(20)}`,
            payload: {
              wrappedShare: 'ciphertext-b64u',
            },
            timestamp: Date.now(),
            schemaVersion: 1,
          });
          await indexedDB.setAccountSignerStatus({
            chainIdKey: 'evm:eip155:11155111',
            accountAddress: `0x${'44'.repeat(20)}`,
            signerId: `0x${'dd'.repeat(20)}`,
            status: 'revoked',
            removedAt: Date.now(),
          });

          const runtimeCalls: Array<Record<string, unknown>> = [];
          const summary = await indexedDB.repairSignerMutationSagasWithRuntime({
            now: Date.now() + 60_000,
            runtime: {
              resolveOwnerAccountId: async () => 'alice.testnet',
              executeDeployedAddSigner: async () => ({ txHash: null }),
              executeDeployedRemoveSigner: async (input: Record<string, unknown>) => {
                runtimeCalls.push({
                  ownerAccountId: input.ownerAccountId,
                  opType: (input.op as any)?.opType,
                  signerId: (input.signer as any)?.signerId,
                  accountAddress: (input.chainAccount as any)?.accountAddress,
                });
                return { txHash: `0x${'bc'.repeat(32)}` };
              },
            },
          });
          const signer = await indexedDB.getAccountSigner({
            chainIdKey: 'evm:eip155:11155111',
            accountAddress: `0x${'44'.repeat(20)}`,
            signerId: `0x${'dd'.repeat(20)}`,
          });
          const keys = (await indexedDB.listKeyMaterialByProfile(
            context.profileId,
            'evm:eip155:11155111',
          )).filter((record: any) => record.signerSlot === 2);
          const after = await indexedDB.listSignerOperations({
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
    expect(result.runtimeCalls).toEqual([]);
    expect(result.signer?.status).toBe('revoked');
    expect(result.keys).toHaveLength(0);
    expect(result.after).toHaveLength(1);
    expect(result.after[0]?.status).toBe('confirmed');
    expect(result.after[0]?.txHash ?? null).toBeNull();
  });
});
