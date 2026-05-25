import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  accountSignerRepository:
    '/sdk/esm/core/indexedDB/passkeyClientDB/accountSignerRepository.js',
  clientDB: '/sdk/esm/core/indexedDB/passkeyClientDB/manager.js',
  lastProfileStateRepository:
    '/sdk/esm/core/indexedDB/passkeyClientDB/lastProfileStateRepository.js',
  schema: '/sdk/esm/core/indexedDB/passkeyClientDB/schema.js',
} as const;

test.describe('PasskeyClientDB repositories', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('upgrades pre-nonce-store v31 databases with durable nonce stores', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { DB_CONFIG } = await import(paths.schema);
        const dbName = `PasskeyClientDBPreNonceStore-${crypto.randomUUID()}`;

        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.open(dbName, 31);
          request.onupgradeneeded = () => {
            const db = request.result;
            db.createObjectStore(DB_CONFIG.appStateStore, { keyPath: 'key' });
          };
          request.onerror = () => reject(request.error || new Error('open failed'));
          request.onsuccess = () => {
            request.result.close();
            resolve();
          };
        });

        const clientDB = new PasskeyClientDBManager({
          ...DB_CONFIG,
          dbName,
        });
        await clientDB.upsertNonceLaneLeaseRecord({
          v: 1,
          leaseId: 'lease-upgrade-test',
          laneKey: 'evm:testnet:1:0x1111111111111111111111111111111111111111',
          family: 'evm',
          chain: 'evm',
          networkKey: 'testnet',
          chainId: 1,
          sender: '0x1111111111111111111111111111111111111111',
          nonce: '1',
          state: 'reserved',
          operationId: 'op-upgrade-test',
          operationFingerprint: 'fp-upgrade-test',
          reservedAtMs: 1,
          expiresAtMs: Date.now() + 60_000,
          updatedAtMs: Date.now(),
          accountId: 'upgrade.testnet',
        });
        const leases = await clientDB.readNonceLaneLeaseRecords(
          'evm:testnet:1:0x1111111111111111111111111111111111111111',
        );
        const lockResult = await clientDB.withNonceLaneCoordinationLock(
          {
            lockKey: 'nonce-coordinator:upgrade-test',
            ownerId: 'upgrade-test-runtime',
            ttlMs: 1_000,
            waitTimeoutMs: 1_000,
          },
          async () => 'locked',
        );
        await new Promise<void>((resolve) => {
          const request = indexedDB.deleteDatabase(dbName);
          request.onsuccess = () => resolve();
          request.onerror = () => resolve();
          request.onblocked = () => resolve();
        });

        return {
          dbVersion: DB_CONFIG.dbVersion,
          leaseCount: leases.length,
          lockResult,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      dbVersion: 32,
      leaseCount: 1,
      lockResult: 'locked',
    });
  });

  test('account signer repository writes, normalizes, and queries signer rows', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { createAccountSignerRepository } = await import(paths.accountSignerRepository);
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { DB_CONFIG } = await import(paths.schema);

        const db = new PasskeyClientDBManager({
          ...DB_CONFIG,
          dbName: `PasskeyClientDBRepoTest-${crypto.randomUUID()}`,
        });
        const createConstraintError = (
          code: string,
          message: string,
          details?: Record<string, unknown>,
        ) => Object.assign(new Error(message), { code, details });
        const repository = createAccountSignerRepository({
          getDB: () => (db as any).getDB(),
          accountSignersStore: DB_CONFIG.accountSignersStore,
          chainAccountsStore: DB_CONFIG.chainAccountsStore,
          createConstraintError,
        });

        const profileId = 'profile-repo-account-signer';
        await db.upsertProfile({
          profileId,
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-repo', rawId: 'raw-repo' },
        });
        await db.upsertChainAccount({
          profileId,
          chainIdKey: 'NEAR:TESTNET',
          accountAddress: 'RepoUser.TESTNET',
          accountModel: 'near-native',
          isPrimary: true,
        });

        const signer = await repository.upsertAccountSignerDirect({
          profileId,
          chainIdKey: 'NEAR:TESTNET',
          accountAddress: 'RepoUser.TESTNET',
          signerId: 'ed25519:repo-signer',
          signerSlot: 1,
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
          status: 'active',
        });
        const fetched = await repository.getAccountSigner({
          chainIdKey: 'near:testnet',
          accountAddress: 'repouser.testnet',
          signerId: 'ed25519:repo-signer',
        });
        const activeRows = await repository.listAccountSigners({
          chainIdKey: 'near:testnet',
          accountAddress: 'repouser.testnet',
          status: 'active',
        });

        return {
          signer,
          fetched,
          activeCount: activeRows.length,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.signer.chainIdKey).toBe('near:testnet');
    expect(result.signer.accountAddress).toBe('repouser.testnet');
    expect(result.fetched?.signerId).toBe('ed25519:repo-signer');
    expect(result.activeCount).toBe(1);
  });

  test('account signer repository rejects active signers missing canonical metadata', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { createAccountSignerRepository } = await import(paths.accountSignerRepository);
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { DB_CONFIG } = await import(paths.schema);

        const db = new PasskeyClientDBManager({
          ...DB_CONFIG,
          dbName: `PasskeyClientDBRepoTest-${crypto.randomUUID()}`,
        });
        const createConstraintError = (
          code: string,
          message: string,
          details?: Record<string, unknown>,
        ) => Object.assign(new Error(message), { code, details });
        const repository = createAccountSignerRepository({
          getDB: () => (db as any).getDB(),
          accountSignersStore: DB_CONFIG.accountSignersStore,
          chainAccountsStore: DB_CONFIG.chainAccountsStore,
          createConstraintError,
        });

        const profileId = 'profile-repo-metadata';
        await db.upsertProfile({
          profileId,
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-metadata', rawId: 'raw-metadata' },
        });
        await db.upsertChainAccount({
          profileId,
          chainIdKey: 'near:testnet',
          accountAddress: 'metadata.testnet',
          accountModel: 'near-native',
          isPrimary: true,
        });

        try {
          await repository.upsertAccountSignerDirect({
            profileId,
            chainIdKey: 'near:testnet',
            accountAddress: 'metadata.testnet',
            signerId: 'ed25519:missing-metadata',
            signerSlot: 1,
            signerType: 'threshold',
            signerKind: '' as any,
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            status: 'active',
          });
          return { ok: true };
        } catch (error: any) {
          return {
            ok: false,
            code: String(error?.code || ''),
          };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({ ok: false, code: 'MISSING_SIGNER_KIND' });
  });

  test('account signer repository rejects active ECDSA signers missing direct keyHandle', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { createAccountSignerRepository } = await import(paths.accountSignerRepository);
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { DB_CONFIG } = await import(paths.schema);

        const db = new PasskeyClientDBManager({
          ...DB_CONFIG,
          dbName: `PasskeyClientDBRepoTest-${crypto.randomUUID()}`,
        });
        const createConstraintError = (
          code: string,
          message: string,
          details?: Record<string, unknown>,
        ) => Object.assign(new Error(message), { code, details });
        const repository = createAccountSignerRepository({
          getDB: () => (db as any).getDB(),
          accountSignersStore: DB_CONFIG.accountSignersStore,
          chainAccountsStore: DB_CONFIG.chainAccountsStore,
          createConstraintError,
        });

        const profileId = 'profile-repo-ecdsa-strict-key-handle';
        await db.upsertProfile({
          profileId,
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-ecdsa-strict', rawId: 'raw-ecdsa-strict' },
        });
        await db.upsertChainAccount({
          profileId,
          chainIdKey: 'eip155:978',
          accountAddress: '0x1111111111111111111111111111111111111111',
          accountModel: 'threshold-ecdsa',
          isPrimary: true,
        });

        try {
          await repository.upsertAccountSignerDirect({
            profileId,
            chainIdKey: 'eip155:978',
            accountAddress: '0x1111111111111111111111111111111111111111',
            signerId: 'threshold-ecdsa:legacy-identity-only',
            signerSlot: 1,
            signerType: 'threshold',
            signerKind: 'threshold-ecdsa',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            status: 'active',
            metadata: {
              ecdsaThresholdKeyId: 'ehss-legacy-id',
              signingRootId: 'project:dev',
              chainTarget: { chain: 'tempo', chainId: 978 },
            },
          });
          return { ok: true };
        } catch (error: any) {
          return {
            ok: false,
            code: String(error?.code || ''),
            message: String(error?.message || ''),
          };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      ok: false,
      code: 'INVALID_SIGNER_METADATA',
      message: 'Active threshold ECDSA signer requires metadata.keyHandle',
    });
  });

  test('prunes incomplete active ECDSA signer rows as an explicit maintenance action', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { DB_CONFIG } = await import(paths.schema);

        const db = new PasskeyClientDBManager({
          ...DB_CONFIG,
          dbName: `PasskeyClientDBRepoTest-${crypto.randomUUID()}`,
        });
        const profileId = 'profile-repo-ecdsa-prune';
        const chainIdKey = 'eip155:978';
        const accountAddress = '0x2222222222222222222222222222222222222222';
        await db.upsertProfile({
          profileId,
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-ecdsa-prune', rawId: 'raw-ecdsa-prune' },
        });
        await db.upsertChainAccount({
          profileId,
          chainIdKey,
          accountAddress,
          accountModel: 'threshold-ecdsa',
          isPrimary: true,
        });

        const now = 1_800_000_000_000;
        const completeMetadata = {
          keyHandle: 'ecdsa-handle-complete',
          rpId: 'https://app.example',
          chainTarget: { chain: 'tempo', chainId: 978 },
          sharedEvmFamilyKey: {
            walletId: profileId,
            rpId: 'https://app.example',
            ecdsaThresholdKeyId: 'ehss-complete',
            signingRootId: 'signing-root-dev',
            signingRootVersion: '1',
            participantIds: [1, 2],
            thresholdOwnerAddress: accountAddress,
            thresholdEcdsaPublicKeyB64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          },
        };
        await db.upsertAccountSigner({
          profileId,
          chainIdKey,
          accountAddress,
          signerId: 'threshold-ecdsa:complete',
          signerSlot: 1,
          signerType: 'threshold',
          signerKind: 'threshold-ecdsa',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
          status: 'active',
          metadata: completeMetadata,
          mutation: { routeThroughOutbox: false },
        });

        const idb = await (db as any).getDB();
        const tx = idb.transaction(DB_CONFIG.accountSignersStore, 'readwrite');
        const incompleteRows = [
          {
            profileId,
            chainIdKey,
            accountAddress,
            signerId: 'threshold-ecdsa:missing-direct-key-handle',
            signerSlot: 2,
            signerType: 'threshold',
            signerKind: 'threshold-ecdsa',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            status: 'active',
            addedAt: now,
            updatedAt: now,
            metadata: {
              chainTarget: { chain: 'tempo', chainId: 978 },
              sharedEvmFamilyKey: {
                ...completeMetadata.sharedEvmFamilyKey,
                keyHandle: 'nested-only-handle',
              },
            },
          },
          {
            profileId,
            chainIdKey,
            accountAddress,
            signerId: 'threshold-ecdsa:missing-key-facts',
            signerSlot: 3,
            signerType: 'threshold',
            signerKind: 'threshold-ecdsa',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            status: 'active',
            addedAt: now,
            updatedAt: now,
            metadata: {
              keyHandle: 'ecdsa-handle-incomplete',
              rpId: 'https://app.example',
              chainTarget: { chain: 'tempo', chainId: 978 },
              ecdsaThresholdKeyId: 'ehss-incomplete',
            },
          },
        ];
        for (const row of incompleteRows) {
          await tx.store.put(row);
        }
        await tx.done;

        const pruneResult = await db.pruneIncompleteActiveThresholdEcdsaSigners({
          profileId,
          now: now + 1,
        });
        const rows = await db.listAccountSignersByProfile({ profileId });
        return {
          pruneResult,
          rows: rows
            .map((row: any) => ({
              signerId: row.signerId,
              status: row.status,
              ...(row.removedAt != null ? { removedAt: row.removedAt } : {}),
              ...(row.revocationReason ? { revocationReason: row.revocationReason } : {}),
            }))
            .sort((a: any, b: any) => a.signerId.localeCompare(b.signerId)),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.pruneResult).toEqual({
      scanned: 3,
      pruned: 2,
      prunedSignerIds: [
        'threshold-ecdsa:missing-direct-key-handle',
        'threshold-ecdsa:missing-key-facts',
      ],
    });
    expect(result.rows).toEqual([
      {
        signerId: 'threshold-ecdsa:complete',
        status: 'active',
      },
      {
        signerId: 'threshold-ecdsa:missing-direct-key-handle',
        status: 'revoked',
        removedAt: 1_800_000_000_001,
        revocationReason: 'development_prune_incomplete_ecdsa_key_facts',
      },
      {
        signerId: 'threshold-ecdsa:missing-key-facts',
        status: 'revoked',
        removedAt: 1_800_000_000_001,
        revocationReason: 'development_prune_incomplete_ecdsa_key_facts',
      },
    ]);
  });

  test('last-profile-state repository validates active signer slot before writing', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { createLastProfileStateRepository } = await import(paths.lastProfileStateRepository);
        const { DB_CONFIG, LAST_PROFILE_STATE_APP_STATE_KEY } = await import(paths.schema);

        const db = new PasskeyClientDBManager({
          ...DB_CONFIG,
          dbName: `PasskeyClientDBRepoTest-${crypto.randomUUID()}`,
        });
        const createConstraintError = (
          code: string,
          message: string,
          details?: Record<string, unknown>,
        ) => Object.assign(new Error(message), { code, details });
        const repository = createLastProfileStateRepository({
          getDB: () => (db as any).getDB(),
          appStateStore: DB_CONFIG.appStateStore,
          accountSignersStore: DB_CONFIG.accountSignersStore,
          profilesStore: DB_CONFIG.profilesStore,
          lastProfileStateAppStateKey: LAST_PROFILE_STATE_APP_STATE_KEY,
          createConstraintError,
        });

        const profileId = 'profile-repo-last-state';
        await db.upsertProfile({
          profileId,
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-last-state', rawId: 'raw-last-state' },
        });
        await db.upsertChainAccount({
          profileId,
          chainIdKey: 'near:testnet',
          accountAddress: 'last-state.testnet',
          accountModel: 'near-native',
          isPrimary: true,
        });
        await db.upsertAccountSigner({
          profileId,
          chainIdKey: 'near:testnet',
          accountAddress: 'last-state.testnet',
          signerId: 'ed25519:last-state',
          signerSlot: 1,
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
          status: 'active',
          mutation: { routeThroughOutbox: false },
        });

        let invalidCode = '';
        try {
          await repository.setLastProfileState(
            { profileId, activeSignerSlot: 2 },
            'https://app.example',
          );
        } catch (error: any) {
          invalidCode = String(error?.code || '');
        }

        await repository.setLastProfileState(
          { profileId, activeSignerSlot: 1 },
          'https://app.example',
        );
        const stored = await repository.getLastProfileState('https://app.example');

        return { invalidCode, stored };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.invalidCode).toBe('INVALID_LAST_PROFILE_STATE');
    expect(result.stored).toEqual({
      profileId: 'profile-repo-last-state',
      activeSignerSlot: 1,
    });
  });
});
