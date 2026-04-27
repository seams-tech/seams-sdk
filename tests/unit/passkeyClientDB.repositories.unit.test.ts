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
