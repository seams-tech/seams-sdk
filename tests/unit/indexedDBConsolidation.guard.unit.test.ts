import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import {
  LEGACY_INDEXED_DB_NAMES,
  SEAMS_WALLET_DB_NAME,
  SEAMS_WALLET_DB_VERSION,
  SEAMS_WALLET_INDEXES,
  SEAMS_WALLET_SCHEMA_MANIFEST,
  SEAMS_WALLET_STORES,
  assertCanonicalIndexedDBName,
  createSeamsTestWalletDbName,
} from '../../client/src/core/indexedDB/schemaNames';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const CANONICAL_NAME_PATTERN = /^seams_[a-z0-9]+(?:_[a-z0-9]+)*$/;
const SNAKE_CASE_PATTERN = /^[a-z0-9]+(?:_[a-z0-9]+)*$/;

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listSourceFiles(relativeDir: string): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  return fs.readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) return listSourceFiles(relativePath);
    return /\.(ts|tsx)$/.test(entry.name) ? [relativePath] : [];
  });
}

test.describe('IndexedDB consolidation guards', () => {
  test('canonical wallet schema names use one Seams-prefixed DB and unprefixed snake_case stores', () => {
    expect(SEAMS_WALLET_DB_NAME).toBe('seams_wallet');
    expect(SEAMS_WALLET_DB_VERSION).toBe(5);
    expect(Object.values(SEAMS_WALLET_STORES).every((name) => !name.startsWith('seams_'))).toBe(
      true,
    );

    expect(SEAMS_WALLET_DB_NAME).toMatch(CANONICAL_NAME_PATTERN);
    expect(() => assertCanonicalIndexedDBName(SEAMS_WALLET_DB_NAME)).not.toThrow();
    for (const name of Object.values(SEAMS_WALLET_STORES)) {
      expect(name, name).toMatch(SNAKE_CASE_PATTERN);
    }
    for (const name of Object.values(SEAMS_WALLET_INDEXES)) {
      expect(name, name).toMatch(SNAKE_CASE_PATTERN);
    }
  });

  test('test wallet DB names normalize unsafe suffixes', () => {
    expect(createSeamsTestWalletDbName('Case-Heavy UUID 123')).toBe(
      'seams_test_wallet_case_heavy_uuid_123',
    );
    expect(() => createSeamsTestWalletDbName('---')).toThrow(
      'Test wallet IndexedDB name suffix is required',
    );
  });

  test('schema manifest defines every canonical store exactly once', () => {
    const manifestStores = SEAMS_WALLET_SCHEMA_MANIFEST.map((entry) => entry.store);
    expect([...new Set(manifestStores)].sort()).toEqual(Object.values(SEAMS_WALLET_STORES).sort());

    for (const entry of SEAMS_WALLET_SCHEMA_MANIFEST) {
      expect(entry.store, entry.store).toMatch(SNAKE_CASE_PATTERN);
      expect(entry.store, entry.store).not.toMatch(/^seams_/);
      for (const index of entry.indexes) {
        expect(index.name, `${entry.store}:${index.name}`).toMatch(SNAKE_CASE_PATTERN);
      }
    }
  });

  test('Refactor 45 canonical index inventory matches schema constants', () => {
    const doc = readRepoSource('docs/refactor-45-consolidate-indexeddb-tables.md');
    const inventory = doc.match(/canonical index\s+inventory is:\s+```ts\n([\s\S]*?)```/);
    expect(inventory).not.toBeNull();
    const documentedIndexes = (inventory?.[1] || '')
      .split('\n')
      .map((line) => line.trim().replace(/^'|'$/g, ''))
      .filter(Boolean);
    expect([...new Set(documentedIndexes)].sort()).toEqual(
      Object.values(SEAMS_WALLET_INDEXES).sort(),
    );
  });

  test('signing session persistence uses canonical wallet DB constants', () => {
    const sharedSealSource = readRepoSource('shared/src/utils/signingSessionSeal.ts');
    expect(sharedSealSource).not.toMatch(/SIGNING_SESSION_SEAL_DB_NAME/);
    expect(sharedSealSource).not.toMatch(/SIGNING_SESSION_SEAL_DB_VERSION/);
    expect(sharedSealSource).not.toMatch(/SIGNING_SESSION_SEAL_STORE_NAME/);
    expect(sharedSealSource).not.toMatch(/SIGNING_SESSION_RESTORE_LEASE_STORE_NAME/);

    const repositorySource = readRepoSource(
      'client/src/core/indexedDB/seamsWalletDB/signingSessionSeals.ts',
    );
    expect(repositorySource).toContain('SEAMS_WALLET_DB_NAME');
    expect(repositorySource).toContain('SEAMS_WALLET_DB_VERSION');
    expect(repositorySource).toContain('SEAMS_WALLET_STORES.signingSessionSeals');
    expect(repositorySource).toContain('SEAMS_WALLET_STORES.signingSessionRestoreLeases');
    expect(repositorySource).not.toMatch(/SIGNING_SESSION_SEAL_DB_NAME/);
    expect(repositorySource).not.toMatch(/SIGNING_SESSION_SEAL_DB_VERSION/);
  });

  test('fresh seams wallet databases match the schema manifest', async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const manifest = schemaNames.SEAMS_WALLET_SCHEMA_MANIFEST as Array<{
        store: string;
        keyPath: string | string[];
        indexes: Array<{
          name: string;
          keyPath: string | string[];
          unique: boolean;
        }>;
      }>;
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `manifest_${crypto.randomUUID()}`,
      );

      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });

      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const db = await manager.getDB();
      const observed = manifest.map((definition) => {
        const storeNames = Array.from(db.objectStoreNames);
        const tx = db.transaction(definition.store, 'readonly');
        const store = tx.objectStore(definition.store);
        const indexes = definition.indexes.map((expectedIndex) => {
          const index = store.index(expectedIndex.name);
          return {
            name: index.name,
            keyPath: index.keyPath,
            unique: index.unique,
          };
        });
        return {
          storeNames,
          store: definition.store,
          keyPath: store.keyPath,
          indexNames: Array.from(store.indexNames),
          indexes,
        };
      });
      manager.close();
      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });
      return observed;
    });

    const manifestStoreNames = SEAMS_WALLET_SCHEMA_MANIFEST.map((definition) => definition.store);
    for (const observedStore of result) {
      const definition = SEAMS_WALLET_SCHEMA_MANIFEST.find(
        (entry) => entry.store === observedStore.store,
      );
      expect(definition, observedStore.store).toBeDefined();
      expect(observedStore.storeNames.sort()).toEqual([...manifestStoreNames].sort());
      expect(observedStore.keyPath).toEqual(definition!.keyPath);
      expect(observedStore.indexNames.sort()).toEqual(
        definition!.indexes.map((index) => index.name).sort(),
      );
      expect(observedStore.indexes).toEqual(
        definition!.indexes.map((index) => ({
          name: index.name,
          keyPath: index.keyPath,
          unique: index.unique,
        })),
      );
    }
  });

  test('schema upgrade replaces stale unique auth-method identifier index', async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `auth_method_index_upgrade_${crypto.randomUUID()}`,
      );
      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });
      await new Promise<void>((resolve, reject) => {
        const request = indexedDB.open(dbName, 4);
        request.onupgradeneeded = () => {
          const store = request.result.createObjectStore(
            schemaNames.SEAMS_WALLET_STORES.walletAuthMethods,
            { keyPath: 'wallet_auth_method_id' },
          );
          store.createIndex(
            schemaNames.SEAMS_WALLET_INDEXES.kindRpIdAuthIdentifier,
            ['kind', 'rp_id', 'auth_identifier_key'],
            { unique: true },
          );
        };
        request.onsuccess = () => {
          request.result.close();
          resolve();
        };
        request.onerror = () => reject(request.error);
      });

      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const db = await manager.getDB();
      const tx = db.transaction(schemaNames.SEAMS_WALLET_STORES.walletAuthMethods, 'readonly');
      const index = tx
        .objectStore(schemaNames.SEAMS_WALLET_STORES.walletAuthMethods)
        .index(schemaNames.SEAMS_WALLET_INDEXES.kindRpIdAuthIdentifier);
      const observed = {
        version: db.version,
        unique: index.unique,
        keyPath: index.keyPath,
      };
      manager.close();
      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });
      return observed;
    });

    expect(result).toEqual({
      version: SEAMS_WALLET_DB_VERSION,
      unique: false,
      keyPath: ['kind', 'rp_id', 'auth_identifier_key'],
    });
  });

  test('wallet DB manager deletes legacy local databases before opening seams_wallet', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const legacyNames = [...schemaNames.LEGACY_INDEXED_DB_NAMES];
      const walletDbName = schemaNames.createSeamsTestWalletDbName(
        `legacy_cleanup_${crypto.randomUUID()}`,
      );

      const deleteDatabase = async (dbName: string): Promise<void> => {
        await new Promise<void>((resolve) => {
          const request = indexedDB.deleteDatabase(dbName);
          request.onsuccess = () => resolve();
          request.onerror = () => resolve();
          request.onblocked = () => resolve();
        });
      };
      const createLegacyDatabase = async (dbName: string): Promise<void> => {
        await deleteDatabase(dbName);
        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.open(dbName, 1);
          request.onupgradeneeded = () => {
            request.result.createObjectStore('legacy_store');
          };
          request.onsuccess = () => {
            request.result.close();
            resolve();
          };
          request.onerror = () => reject(request.error);
        });
      };
      const databaseNames = async (): Promise<string[]> => {
        const databases = await indexedDB.databases();
        return databases.map((database) => database.name || '').filter(Boolean);
      };

      for (const legacyName of legacyNames) {
        await createLegacyDatabase(legacyName);
      }

      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(walletDbName);
      manager.setLegacyDatabaseCleanup(legacyNames);
      const db = await manager.getDB();
      db.close();
      manager.close();

      const namesAfterOpen = await databaseNames();
      await deleteDatabase(walletDbName);
      return {
        legacyNames,
        namesAfterOpen,
        walletDbName,
      };
    });

    expect(result.namesAfterOpen).toContain(result.walletDbName);
    for (const legacyName of result.legacyNames) {
      expect(result.namesAfterOpen).not.toContain(legacyName);
    }
  });

  test('disabled wallet DB manager does not open seams_wallet or delete legacy databases', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const legacyNames = [...schemaNames.LEGACY_INDEXED_DB_NAMES];
      const walletDbName = schemaNames.createSeamsTestWalletDbName(
        `disabled_cleanup_${crypto.randomUUID()}`,
      );

      const deleteDatabase = async (dbName: string): Promise<void> => {
        await new Promise<void>((resolve) => {
          const request = indexedDB.deleteDatabase(dbName);
          request.onsuccess = () => resolve();
          request.onerror = () => resolve();
          request.onblocked = () => resolve();
        });
      };
      const createLegacyDatabase = async (dbName: string): Promise<void> => {
        await deleteDatabase(dbName);
        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.open(dbName, 1);
          request.onupgradeneeded = () => {
            request.result.createObjectStore('legacy_store');
          };
          request.onsuccess = () => {
            request.result.close();
            resolve();
          };
          request.onerror = () => reject(request.error);
        });
      };
      const databaseNames = async (): Promise<string[]> => {
        const databases = await indexedDB.databases();
        return databases.map((database) => database.name || '').filter(Boolean);
      };

      for (const legacyName of legacyNames) {
        await createLegacyDatabase(legacyName);
      }

      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(walletDbName);
      manager.setLegacyDatabaseCleanup(legacyNames);
      manager.setDisabled(true);
      const errorMessage = await manager
        .getDB()
        .then(() => null)
        .catch((error: unknown) => (error instanceof Error ? error.message : String(error)));

      const namesAfterDisabledOpen = await databaseNames();
      for (const legacyName of legacyNames) {
        await deleteDatabase(legacyName);
      }
      await deleteDatabase(walletDbName);
      return {
        errorMessage,
        legacyNames,
        namesAfterDisabledOpen,
        walletDbName,
      };
    });

    expect(result.errorMessage).toContain('IndexedDB is disabled');
    expect(result.namesAfterDisabledOpen).not.toContain(result.walletDbName);
    for (const legacyName of result.legacyNames) {
      expect(result.namesAfterDisabledOpen).toContain(legacyName);
    }
  });

  test('unified repositories persist profiles, auth-method bindings, chain accounts, app state, recovery email, key material, and nonce leases in seams wallet stores', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule = await import(
        '/sdk/esm/core/indexedDB/seamsWalletDB/repositories.js'
      );
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `repositories_${crypto.randomUUID()}`,
      );

      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });

      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repositories = new repositoryModule.SeamsWalletRepositories(manager);
      await repositories.upsertProfile({
        profileId: 'alice.testnet',
        defaultSignerSlot: 1,
        passkeyCredential: {
          id: 'credential-id',
          rawId: 'credential-raw-id',
        },
        preferences: {
          useRelayer: false,
          useNetwork: 'testnet',
          confirmationConfig: {
            uiMode: 'drawer',
            behavior: 'requireClick',
            autoProceedDelay: 0,
          },
        },
      });
      await repositories.upsertWalletAuthMethod({
        version: 'wallet_auth_method_v1',
        kind: 'passkey',
        status: 'active',
        localStatus: 'synced',
        walletId: 'alice.testnet',
        rpId: 'local',
        credentialIdB64u: 'credential-raw-id',
        credentialPublicKeyB64u: 'AQID',
        counter: 0,
        createdAtMs: 1,
        updatedAtMs: 2,
      });
      await repositories.upsertWalletAuthMethod({
        version: 'wallet_auth_method_v1',
        kind: 'email_otp',
        status: 'active',
        localStatus: 'pending',
        walletId: 'alice.testnet',
        rpId: 'local',
        emailHashHex: 'email-hash-hex',
        challengeId: 'challenge-1',
        createdAtMs: 3,
        updatedAtMs: 4,
      });
      const mixedBindingRejected = await repositories
        .upsertWalletAuthMethod({
          version: 'wallet_auth_method_v1',
          kind: 'passkey',
          status: 'active',
          localStatus: 'synced',
          walletId: 'alice.testnet',
          rpId: 'local',
          credentialIdB64u: 'mixed-credential',
          credentialPublicKeyB64u: 'credential-public-key',
          counter: 0,
          emailHashHex: 'email-hash-hex',
          createdAtMs: 1,
          updatedAtMs: 2,
        } as any)
        .then(() => false)
        .catch(() => true);
      const rejectedFinalizeBatchLeavesNoRows = await repositories
        .persistWalletRegistrationFinalize({
          profiles: [{ profileId: 'atomic-fail.testnet' }],
          initialAuthMethod: {
            version: 'wallet_auth_method_v1',
            kind: 'email_otp',
            status: 'active',
            localStatus: 'synced',
            walletId: 'atomic-fail.testnet',
            rpId: 'local',
            emailHashHex: 'atomic-email-hash',
            challengeId: 'challenge-1',
            credentialIdB64u: 'mixed-credential',
            createdAtMs: 1,
            updatedAtMs: 2,
          } as any,
          authenticators: [],
          signerActivations: [],
          keyMaterials: [],
        })
        .then(() => false)
        .catch(async () => {
          const profile = await repositories.getProfile('atomic-fail.testnet');
          const bindings =
            await repositories.listWalletAuthMethodsForWallet('atomic-fail.testnet');
          return profile === null && bindings.length === 0;
        });
      await repositories.upsertChainAccount({
        profileId: 'alice.testnet',
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
        accountModel: 'near-native',
        isPrimary: true,
      });
      const signerActivation = await repositories.activateAccountSigner({
        account: {
          profileId: 'alice.testnet',
          chainIdKey: 'near:testnet',
          accountAddress: 'alice.testnet',
          accountModel: 'near-native',
        },
        signer: {
          signerId: 'ed25519:alice',
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
        },
        activationPolicy: { mode: 'allocate_next_free' },
        selectAsActive: false,
        mutation: {
          routeThroughOutbox: true,
          opId: 'signer-op-1',
          idempotencyKey: 'signer-op-idempotency-1',
        },
      });
      await repositories.upsertProfileAuthenticator({
        profileId: 'alice.testnet',
        signerSlot: 1,
        credentialId: 'credential-raw-id',
        credentialPublicKey: new Uint8Array([1, 2, 3]),
        transports: ['internal'],
        name: 'Alice device',
        registered: '2026-05-28T00:00:00.000Z',
        syncedAt: '2026-05-28T00:00:00.000Z',
      });
      const updatedPreferences = await repositories.updatePreferences({
        profileId: 'alice.testnet',
        preferences: {
          useRelayer: true,
        },
      });
      await repositories.upsertProfile({
        profileId: 'delete.testnet',
        defaultSignerSlot: 1,
      });
      await repositories.upsertWalletAuthMethod({
        version: 'wallet_auth_method_v1',
        kind: 'email_otp',
        status: 'active',
        localStatus: 'synced',
        walletId: 'delete.testnet',
        rpId: 'local',
        emailHashHex: 'delete-email-hash',
        challengeId: 'delete-challenge',
        createdAtMs: 1,
        updatedAtMs: 2,
      });
      await repositories.upsertChainAccount({
        profileId: 'delete.testnet',
        chainIdKey: 'near:testnet',
        accountAddress: 'delete.testnet',
        accountModel: 'near-native',
        isPrimary: true,
      });
      await repositories.upsertProfileAuthenticator({
        profileId: 'delete.testnet',
        signerSlot: 1,
        credentialId: 'delete-credential',
        credentialPublicKey: new Uint8Array([4, 5, 6]),
        registered: '2026-05-28T00:00:00.000Z',
        syncedAt: '2026-05-28T00:00:00.000Z',
      });
      await repositories.deleteProfileData('delete.testnet');
      await repositories.setAppState('selected-wallet', { walletId: 'alice.testnet' });
      await repositories.setLastProfileStateForProfile('alice.testnet', 2);
      await repositories.setLastProfileStateForProfile(
        'bob.testnet',
        1,
        'https://app.example',
      );
      await repositories.upsertRecoveryEmails('alice.testnet', [
        { hashHex: '0xabc', email: 'alice@example.test' },
      ]);
      await repositories.storeKeyMaterial({
        profileId: 'alice.testnet',
        signerSlot: 1,
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
        keyKind: 'threshold_share_v1',
        algorithm: 'ed25519',
        publicKey: 'ed25519:key',
        signerId: 'signer-1',
        payload: { share: 'sealed' },
        timestamp: 3,
        schemaVersion: 1,
      });
      await repositories.upsertNonceLaneLeaseRecord({
        v: 1,
        family: 'near',
        leaseId: 'lease-1',
        laneKey: 'near:testnet:alice.testnet:ed25519:key',
        networkKey: 'near:testnet',
        nonce: '7',
        state: 'reserved',
        operationId: 'op-1',
        operationFingerprint: 'fp-1',
        reservedAtMs: 1,
        expiresAtMs: 9_999_999,
        updatedAtMs: 2,
        accountId: 'alice.testnet',
        publicKey: 'ed25519:key',
      });
      const profile = await repositories.getProfile('alice.testnet');
      const profiles = await repositories.listProfiles();
      const deletedProfile = await repositories.getProfile('delete.testnet');
      const deletedChainAccounts =
        await repositories.listChainAccountsByProfile('delete.testnet');
      const deletedAuthenticators =
        await repositories.listProfileAuthenticators('delete.testnet');
      const deletedAuthMethods =
        await repositories.listWalletAuthMethodsForWallet('delete.testnet');
      const chainAccount = await repositories.getChainAccount({
        profileId: 'alice.testnet',
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
      });
      const profileChainAccounts =
        await repositories.listChainAccountsByProfile('alice.testnet');
      const accountSigner = await repositories.getAccountSigner({
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
        signerId: 'ed25519:alice',
      });
      const profileSigners = await repositories.listAccountSignersByProfile({
        profileId: 'alice.testnet',
        status: 'active',
      });
      const profileAuthenticators =
        await repositories.listProfileAuthenticators('alice.testnet');
      const authMethods =
        await repositories.listWalletAuthMethodsForWallet('alice.testnet');
      const passkeyAuthMethod = await repositories.getWalletAuthMethod({
        kind: 'passkey',
        rpId: 'local',
        authIdentifierKey: 'credential-raw-id',
      });
      const emailOtpAuthMethod = await repositories.getWalletAuthMethod({
        kind: 'email_otp',
        rpId: 'local',
        authIdentifierKey: 'email-hash-hex',
      });
      const credentialAuthenticator = await repositories.getProfileAuthenticatorByCredentialId(
        'alice.testnet',
        'credential-raw-id',
      );
      const promptSelection = await repositories.selectProfileAuthenticatorsForPrompt({
        profileId: 'alice.testnet',
        authenticators: profileAuthenticators,
      });
      const signerOps = await repositories.listSignerOperations({
        statuses: ['queued'],
        dueBefore: Date.now() + 60_000,
      });
      const submittedSignerOp = await repositories.setSignerOperationStatus({
        opId: 'signer-op-1',
        status: 'submitted',
        attemptDelta: 1,
        nextAttemptAt: Date.now() + 120_000,
      });
      const resolvedAccountContext = await repositories.resolveProfileAccountContext({
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
      });
      const appState = await repositories.getAppState('selected-wallet');
      const lastProfileState = await repositories.getLastProfileState();
      const scopedLastProfileState = await repositories.getLastProfileState('https://app.example');
      const recoveryEmails = await repositories.listRecoveryEmails('alice.testnet');
      const keyMaterial = await repositories.getKeyMaterial(
        'alice.testnet',
        1,
        'near:testnet',
        'threshold_share_v1',
      );
      const nonceLeases = await repositories.readNonceLaneLeaseRecords(
        'near:testnet:alice.testnet:ed25519:key',
      );
      const db = await manager.getDB();
      const tx = db.transaction(
        [
          schemaNames.SEAMS_WALLET_STORES.appState,
          schemaNames.SEAMS_WALLET_STORES.wallets,
          schemaNames.SEAMS_WALLET_STORES.walletAuthMethods,
          schemaNames.SEAMS_WALLET_STORES.walletSigners,
          schemaNames.SEAMS_WALLET_STORES.nearAccountProjections,
          schemaNames.SEAMS_WALLET_STORES.signerOpsOutbox,
          schemaNames.SEAMS_WALLET_STORES.recoveryEmails,
          schemaNames.SEAMS_WALLET_STORES.keyMaterial,
          schemaNames.SEAMS_WALLET_STORES.nonceLaneLeases,
        ],
        'readonly',
      );
      const rawRows = {
        appState: await tx.objectStore(schemaNames.SEAMS_WALLET_STORES.appState).get('selected-wallet'),
        lastProfileState: await tx
          .objectStore(schemaNames.SEAMS_WALLET_STORES.appState)
          .get('lastProfileState'),
        scopedLastProfileState: await tx
          .objectStore(schemaNames.SEAMS_WALLET_STORES.appState)
          .get('lastProfileState::https://app.example'),
        wallet: await tx
          .objectStore(schemaNames.SEAMS_WALLET_STORES.wallets)
          .get('alice.testnet'),
        passkeyAuthMethod: await tx
          .objectStore(schemaNames.SEAMS_WALLET_STORES.walletAuthMethods)
          .get(['alice.testnet', 'passkey', 'local', 'credential-raw-id'].join('\0')),
        emailOtpAuthMethod: await tx
          .objectStore(schemaNames.SEAMS_WALLET_STORES.walletAuthMethods)
          .get(['alice.testnet', 'email_otp', 'local', 'email-hash-hex'].join('\0')),
        chainAccount: await tx
          .objectStore(schemaNames.SEAMS_WALLET_STORES.nearAccountProjections)
          .get(['alice.testnet', ['near:testnet', 'alice.testnet'].join('\0'), 0]),
        walletSigner: await tx
          .objectStore(schemaNames.SEAMS_WALLET_STORES.walletSigners)
          .get(['near:testnet', 'alice.testnet', 'ed25519:alice'].join('\0')),
        walletAuthMethod: await tx
          .objectStore(schemaNames.SEAMS_WALLET_STORES.walletAuthMethods)
          .index(schemaNames.SEAMS_WALLET_INDEXES.passkeyRpIdCredentialId)
          .get(['passkey', 'local', 'credential-raw-id']),
        signerOp: await tx
          .objectStore(schemaNames.SEAMS_WALLET_STORES.signerOpsOutbox)
          .get('signer-op-1'),
        recoveryEmail: await tx
          .objectStore(schemaNames.SEAMS_WALLET_STORES.recoveryEmails)
          .get(['alice.testnet', '0xabc']),
        keyMaterial: await tx
          .objectStore(schemaNames.SEAMS_WALLET_STORES.keyMaterial)
          .get([
            ['near:testnet', 'alice.testnet', 'signer-1'].join('\0'),
            'threshold_share_v1',
          ].join('\0')),
        nonceLease: await tx
          .objectStore(schemaNames.SEAMS_WALLET_STORES.nonceLaneLeases)
          .get('lease-1'),
      };
      await tx.done;
      manager.close();
      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });
      return {
        profile,
        profiles,
        updatedPreferences,
        mixedBindingRejected,
        rejectedFinalizeBatchLeavesNoRows,
        deletedProfile,
        deletedChainAccounts,
        deletedAuthenticators,
        deletedAuthMethods,
        chainAccount,
        profileChainAccounts,
        signerActivation,
        accountSigner,
        profileSigners,
        profileAuthenticators,
        authMethods,
        passkeyAuthMethod,
        emailOtpAuthMethod,
        credentialAuthenticator,
        promptSelection,
        signerOps,
        submittedSignerOp,
        resolvedAccountContext,
        appState,
        lastProfileState,
        scopedLastProfileState,
        recoveryEmails,
        keyMaterial,
        nonceLeases,
        rawRows,
      };
    });

    expect(result.profile).toMatchObject({
      profileId: 'alice.testnet',
      defaultSignerSlot: 1,
      passkeyCredential: {
        id: 'credential-id',
        rawId: 'credential-raw-id',
      },
    });
    expect(result.profiles).toHaveLength(1);
    expect(result.updatedPreferences).toMatchObject({
      useRelayer: true,
      useNetwork: 'testnet',
    });
    expect(result.profile?.preferences).toMatchObject({
      useRelayer: true,
      useNetwork: 'testnet',
    });
    expect(result.deletedProfile).toBeNull();
    expect(result.deletedChainAccounts).toEqual([]);
    expect(result.deletedAuthenticators).toEqual([]);
    expect(result.deletedAuthMethods).toEqual([]);
    expect(result.mixedBindingRejected).toBe(true);
    expect(result.rejectedFinalizeBatchLeavesNoRows).toBe(true);
    expect(result.chainAccount).toMatchObject({
      profileId: 'alice.testnet',
      chainIdKey: 'near:testnet',
      accountAddress: 'alice.testnet',
      accountModel: 'near-native',
      isPrimary: true,
    });
    expect(result.profileChainAccounts).toHaveLength(1);
    expect(result.signerActivation.signer).toMatchObject({
      profileId: 'alice.testnet',
      chainIdKey: 'near:testnet',
      accountAddress: 'alice.testnet',
      signerId: 'ed25519:alice',
      signerSlot: 1,
      status: 'active',
    });
    expect(result.accountSigner?.signerId).toBe('ed25519:alice');
    expect(result.profileSigners).toHaveLength(1);
    expect(result.profileAuthenticators).toHaveLength(1);
    expect(result.authMethods).toHaveLength(2);
    expect(result.passkeyAuthMethod).toMatchObject({
      kind: 'passkey',
      walletId: 'alice.testnet',
      credentialIdB64u: 'credential-raw-id',
      localStatus: 'synced',
    });
    expect(result.emailOtpAuthMethod).toMatchObject({
      kind: 'email_otp',
      walletId: 'alice.testnet',
      emailHashHex: 'email-hash-hex',
      localStatus: 'pending',
    });
    expect(result.credentialAuthenticator).toMatchObject({
      profileId: 'alice.testnet',
      signerSlot: 1,
      credentialId: 'credential-raw-id',
    });
    expect(result.promptSelection.authenticatorsForPrompt).toHaveLength(1);
    expect(result.signerOps[0]).toMatchObject({
      opId: 'signer-op-1',
      idempotencyKey: 'signer-op-idempotency-1',
      status: 'queued',
    });
    expect(result.submittedSignerOp).toMatchObject({
      opId: 'signer-op-1',
      status: 'submitted',
      attemptCount: 1,
    });
    expect(result.resolvedAccountContext).toEqual({
      profileId: 'alice.testnet',
      accountRef: {
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
      },
    });
    expect(result.appState).toEqual({ walletId: 'alice.testnet' });
    expect(result.lastProfileState).toEqual({
      profileId: 'alice.testnet',
      activeSignerSlot: 2,
    });
    expect(result.scopedLastProfileState).toEqual({
      profileId: 'bob.testnet',
      activeSignerSlot: 1,
      scope: 'https://app.example',
    });
    expect(result.recoveryEmails).toEqual([
      {
        profileId: 'alice.testnet',
        hashHex: '0xabc',
        email: 'alice@example.test',
        addedAt: expect.any(Number),
      },
    ]);
    expect(result.nonceLeases).toHaveLength(1);
    expect(result.keyMaterial).toMatchObject({
      profileId: 'alice.testnet',
      signerSlot: 1,
      chainIdKey: 'near:testnet',
      accountAddress: 'alice.testnet',
      keyKind: 'threshold_share_v1',
      signerId: 'signer-1',
      publicKey: 'ed25519:key',
    });
    expect(result.nonceLeases[0]).toMatchObject({
      leaseId: 'lease-1',
      family: 'near',
      accountId: 'alice.testnet',
    });
    expect(result.rawRows.appState.key).toBe('selected-wallet');
    expect(result.rawRows.lastProfileState.value).toEqual({
      profileId: 'alice.testnet',
      activeSignerSlot: 2,
    });
    expect(result.rawRows.scopedLastProfileState.value).toEqual({
      profileId: 'bob.testnet',
      activeSignerSlot: 1,
      scope: 'https://app.example',
    });
    expect(result.rawRows.wallet.wallet_id).toBe('alice.testnet');
    expect(result.rawRows.wallet.record.profileId).toBe('alice.testnet');
    expect(result.rawRows.passkeyAuthMethod.wallet_id).toBe('alice.testnet');
    expect(result.rawRows.passkeyAuthMethod.kind).toBe('passkey');
    expect(result.rawRows.passkeyAuthMethod.auth_identifier_key).toBe('credential-raw-id');
    expect(result.rawRows.passkeyAuthMethod.record.credentialIdB64u).toBe(
      'credential-raw-id',
    );
    expect(result.rawRows.emailOtpAuthMethod.wallet_id).toBe('alice.testnet');
    expect(result.rawRows.emailOtpAuthMethod.kind).toBe('email_otp');
    expect(result.rawRows.emailOtpAuthMethod.auth_identifier_key).toBe('email-hash-hex');
    expect(result.rawRows.emailOtpAuthMethod.record.emailHashHex).toBe('email-hash-hex');
    expect(result.rawRows.chainAccount.wallet_id).toBe('alice.testnet');
    expect(result.rawRows.chainAccount.chain_id_key).toBe('near:testnet');
    expect(result.rawRows.chainAccount.record.accountAddress).toBe('alice.testnet');
    expect(result.rawRows.walletSigner.wallet_id).toBe('alice.testnet');
    expect(result.rawRows.walletSigner.wallet_signer_id).toBe(
      ['near:testnet', 'alice.testnet', 'ed25519:alice'].join('\0'),
    );
    expect(result.rawRows.walletSigner.chain_target_key).toBe(
      ['near:testnet', 'alice.testnet'].join('\0'),
    );
    expect(result.rawRows.walletSigner.record.signerKind).toBe('threshold-ed25519');
    expect(result.rawRows.walletAuthMethod.rp_id).toBe('local');
    expect(result.rawRows.walletAuthMethod.credential_id_b64u).toBe('credential-raw-id');
    expect(result.rawRows.walletAuthMethod.wallet_id).toBe('alice.testnet');
    expect(result.rawRows.walletAuthMethod.authenticator.credentialId).toBe('credential-raw-id');
    expect(result.rawRows.signerOp.op_id).toBe('signer-op-1');
    expect(result.rawRows.signerOp.idempotency_key).toBe('signer-op-idempotency-1');
    expect(result.rawRows.signerOp.status).toBe('submitted');
    expect(result.rawRows.recoveryEmail.wallet_id).toBe('alice.testnet');
    expect(result.rawRows.recoveryEmail.hash_hex).toBe('0xabc');
    expect(result.rawRows.keyMaterial.key_material_id).toBe(
      [['near:testnet', 'alice.testnet', 'signer-1'].join('\0'), 'threshold_share_v1'].join('\0'),
    );
    expect(result.rawRows.keyMaterial.wallet_id).toBe('alice.testnet');
    expect(result.rawRows.keyMaterial.wallet_signer_id).toBe(
      ['near:testnet', 'alice.testnet', 'signer-1'].join('\0'),
    );
    expect(result.rawRows.keyMaterial.chain_target_key).toBe(
      ['near:testnet', 'alice.testnet'].join('\0'),
    );
    expect(result.rawRows.keyMaterial.public_key).toBe('ed25519:key');
    expect(result.rawRows.nonceLease.lease_id).toBe('lease-1');
    expect(result.rawRows.nonceLease.lane_key).toBe('near:testnet:alice.testnet:ed25519:key');
  });

  test('wallet signer rows mirror branch identity fields and ECDSA signers do not create NEAR projections', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoriesModule = await import('/sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `signer_mirrors_${crypto.randomUUID()}`,
      );
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repositories = new repositoriesModule.SeamsWalletRepositories(manager);
      const ecdsaChainTarget = {
        kind: 'evm',
        namespace: 'eip155',
        chainId: 1,
        networkSlug: 'ethereum',
      };

      await repositories.upsertProfile({ profileId: 'wallet_alice' });
      await repositories.activateAccountSigner({
        account: {
          profileId: 'wallet_alice',
          chainIdKey: 'near:testnet',
          accountAddress: 'alice.testnet',
          accountModel: 'near-native',
        },
        signer: {
          signerId: 'credential-1',
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
        },
        activationPolicy: { mode: 'allocate_next_free' },
      });
      await repositories.activateAccountSigner({
        account: {
          profileId: 'wallet_alice',
          chainIdKey: 'evm:eip155:1',
          accountAddress: '0x1111111111111111111111111111111111111111',
          accountModel: 'threshold-ecdsa',
        },
        signer: {
          signerId: '0x1111111111111111111111111111111111111111',
          signerType: 'threshold',
          signerKind: 'threshold-ecdsa',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
          metadata: {
            keyHandle: 'ecdsa-key-handle-1',
            ecdsaThresholdKeyId: 'ecdsa-threshold-key-1',
            thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
            chainTarget: ecdsaChainTarget,
          },
        },
        activationPolicy: { mode: 'allocate_next_free' },
      });

      const duplicateEcdsaKeyHandleRejected = await repositories
        .activateAccountSigner({
          account: {
            profileId: 'wallet_alice',
            chainIdKey: 'evm:eip155:1',
            accountAddress: '0x2222222222222222222222222222222222222222',
            accountModel: 'threshold-ecdsa',
          },
          signer: {
            signerId: '0x2222222222222222222222222222222222222222',
            signerType: 'threshold',
            signerKind: 'threshold-ecdsa',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            metadata: {
              keyHandle: 'ecdsa-key-handle-1',
              ecdsaThresholdKeyId: 'ecdsa-threshold-key-2',
              thresholdOwnerAddress: '0x2222222222222222222222222222222222222222',
              chainTarget: ecdsaChainTarget,
            },
          },
          activationPolicy: { mode: 'allocate_next_free' },
        })
        .then(() => false)
        .catch(() => true);
      const chainTargetDriftRejected = await repositories
        .activateAccountSigner({
          account: {
            profileId: 'wallet_alice',
            chainIdKey: 'evm:eip155:2',
            accountAddress: '0x3333333333333333333333333333333333333333',
            accountModel: 'threshold-ecdsa',
          },
          signer: {
            signerId: '0x3333333333333333333333333333333333333333',
            signerType: 'threshold',
            signerKind: 'threshold-ecdsa',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            metadata: {
              keyHandle: 'ecdsa-key-handle-3',
              ecdsaThresholdKeyId: 'ecdsa-threshold-key-3',
              thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
              chainTarget: ecdsaChainTarget,
            },
          },
          activationPolicy: { mode: 'allocate_next_free' },
        })
        .then(() => false)
        .catch((error: Error) =>
          String(error.message || '').includes('metadata.chainTarget must match chainIdKey'),
        );

      const db = await manager.getDB();
      const rows = (await db.getAll(schemaNames.SEAMS_WALLET_STORES.walletSigners)) as Array<
        Record<string, unknown>
      >;
      const ed25519Row = rows.find((row) => row.kind === 'threshold-ed25519');
      const ecdsaRow = rows.find((row) => row.kind === 'threshold-ecdsa');
      const nearProjections = await repositories.listChainAccountsByProfile('wallet_alice');
      if (ecdsaRow) {
        await db.put(schemaNames.SEAMS_WALLET_STORES.walletSigners, {
          ...ecdsaRow,
          key_handle: 'wrong-key-handle',
        });
      }
      if (ed25519Row) {
        const legacyEd25519Row = { ...ed25519Row };
        delete legacyEd25519Row.chain_target_key;
        delete legacyEd25519Row.near_signer_slot;
        await db.put(schemaNames.SEAMS_WALLET_STORES.walletSigners, legacyEd25519Row);
      }
      const parsedAfterMirrorDrift = await repositories.listAccountSignersByProfile({
        profileId: 'wallet_alice',
      });

      manager.close();
      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });

      return {
        ed25519NearSignerSlot: ed25519Row?.near_signer_slot,
        ed25519KeyHandle: ed25519Row?.key_handle ?? null,
        ecdsaKeyHandle: ecdsaRow?.key_handle,
        ecdsaThresholdKeyId: ecdsaRow?.ecdsa_threshold_key_id,
        ecdsaOwnerAddress: ecdsaRow?.threshold_owner_address,
        ecdsaChainTargetKey: ecdsaRow?.chain_target_key,
        duplicateEcdsaKeyHandleRejected,
        chainTargetDriftRejected,
        nearProjectionModels: nearProjections.map(
          (projection: { accountModel: string }) => projection.accountModel,
        ),
        parsedSignerKindsAfterMirrorDrift: parsedAfterMirrorDrift.map(
          (signer: { signerKind: string }) => signer.signerKind,
        ),
      };
    });

    expect(result).toMatchObject({
      ed25519NearSignerSlot: 1,
      ed25519KeyHandle: null,
      ecdsaKeyHandle: 'ecdsa-key-handle-1',
      ecdsaThresholdKeyId: 'ecdsa-threshold-key-1',
      ecdsaOwnerAddress: '0x1111111111111111111111111111111111111111',
      ecdsaChainTargetKey: 'evm:eip155:1',
      duplicateEcdsaKeyHandleRejected: true,
      chainTargetDriftRejected: true,
      nearProjectionModels: ['near-native'],
      parsedSignerKindsAfterMirrorDrift: ['threshold-ed25519'],
    });
  });

  test('wallet signer finalize rejects missing signer key material atomically', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoriesModule = await import('/sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `missing_key_material_${crypto.randomUUID()}`,
      );
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repositories = new repositoriesModule.SeamsWalletRepositories(manager);

      const rejected = await repositories
        .persistWalletSignerFinalize({
          profiles: [{ profileId: 'wallet_missing_key_material' }],
          signerActivations: [
            {
              account: {
                profileId: 'wallet_missing_key_material',
                chainIdKey: 'near:testnet',
                accountAddress: 'missing-key.testnet',
                accountModel: 'near-native',
              },
              signer: {
                signerId: 'credential-missing-key',
                signerType: 'threshold',
                signerKind: 'threshold-ed25519',
                signerAuthMethod: 'passkey',
                signerSource: 'passkey_registration',
                metadata: {
                  operationalPublicKey: 'ed25519:missing-key',
                },
              },
              activationPolicy: { mode: 'fail_if_occupied', signerSlot: 1 },
              preferredSlot: 1,
              mutation: { routeThroughOutbox: false },
            },
          ],
          keyMaterials: [],
        })
        .then(() => false)
        .catch((error: Error) =>
          String(error.message || '').includes('requires matching threshold key material'),
        );
      const profile = await repositories.getProfile('wallet_missing_key_material');
      const signers = await repositories.listAccountSignersByProfile({
        profileId: 'wallet_missing_key_material',
      });
      manager.close();
      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });
      return {
        rejected,
        profileExists: !!profile,
        signerCount: signers.length,
      };
    });

    expect(result).toEqual({
      rejected: true,
      profileExists: false,
      signerCount: 0,
    });
  });

  test('wallet auth-method rows allow shared Email OTP identifiers and reject passkey duplicates plus scalar drift', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoriesModule = await import('/sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `auth_method_guards_${crypto.randomUUID()}`,
      );
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repositories = new repositoriesModule.SeamsWalletRepositories(manager);

      await repositories.upsertProfile({ profileId: 'wallet_auth_a', defaultSignerSlot: 1 });
      await repositories.upsertProfile({ profileId: 'wallet_auth_b', defaultSignerSlot: 1 });
      await repositories.upsertProfile({ profileId: 'wallet_email_a', defaultSignerSlot: 1 });
      await repositories.upsertProfile({ profileId: 'wallet_email_b', defaultSignerSlot: 1 });
      await repositories.upsertWalletAuthMethod({
        version: 'wallet_auth_method_v1',
        kind: 'passkey',
        status: 'active',
        localStatus: 'synced',
        walletId: 'wallet_auth_a',
        rpId: 'local',
        credentialIdB64u: 'shared-credential',
        credentialPublicKeyB64u: 'AQID',
        counter: 0,
        createdAtMs: 1,
        updatedAtMs: 2,
      });

      const duplicateIdentifierRejected = await repositories
        .upsertWalletAuthMethod({
          version: 'wallet_auth_method_v1',
          kind: 'passkey',
          status: 'active',
          localStatus: 'synced',
          walletId: 'wallet_auth_b',
          rpId: 'local',
          credentialIdB64u: 'shared-credential',
          credentialPublicKeyB64u: 'AQID',
          counter: 0,
          createdAtMs: 3,
          updatedAtMs: 4,
        })
        .then(() => false)
        .catch(() => true);

      const sharedEmailIdentifierWrites = await Promise.all([
        repositories.upsertWalletAuthMethod({
          version: 'wallet_auth_method_v1',
          kind: 'email_otp',
          status: 'active',
          localStatus: 'synced',
          walletId: 'wallet_email_a',
          rpId: 'local',
          emailHashHex: 'same-email-hash',
          challengeId: 'challenge-a',
          createdAtMs: 5,
          updatedAtMs: 6,
        }),
        repositories.upsertWalletAuthMethod({
          version: 'wallet_auth_method_v1',
          kind: 'email_otp',
          status: 'active',
          localStatus: 'synced',
          walletId: 'wallet_email_b',
          rpId: 'local',
          emailHashHex: 'same-email-hash',
          challengeId: 'challenge-b',
          createdAtMs: 7,
          updatedAtMs: 8,
        }),
      ]);
      const ambiguousSharedEmailLookup = await repositories.getWalletAuthMethod({
        kind: 'email_otp',
        rpId: 'local',
        authIdentifierKey: 'same-email-hash',
      });

      const db = await manager.getDB();
      const tx = db.transaction(schemaNames.SEAMS_WALLET_STORES.walletAuthMethods, 'readwrite');
      const store = tx.objectStore(schemaNames.SEAMS_WALLET_STORES.walletAuthMethods);
      const row = await store.get(['wallet_auth_a', 'passkey', 'local', 'shared-credential'].join('\0'));
      await store.put({
        ...row,
        auth_identifier_key: 'drifted-credential',
      });
      await tx.done;

      const lookupByOriginal = await repositories.getWalletAuthMethod({
        kind: 'passkey',
        rpId: 'local',
        authIdentifierKey: 'shared-credential',
      });
      const lookupByDrifted = await repositories.getWalletAuthMethod({
        kind: 'passkey',
        rpId: 'local',
        authIdentifierKey: 'drifted-credential',
      });
      const listed = await repositories.listWalletAuthMethodsForWallet('wallet_auth_a');

      manager.close();
      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });
      return {
        duplicateIdentifierRejected,
        sharedEmailIdentifierWriteCount: sharedEmailIdentifierWrites.length,
        ambiguousSharedEmailLookup: ambiguousSharedEmailLookup === null,
        lookupByOriginal: lookupByOriginal === null,
        lookupByDrifted: lookupByDrifted === null,
        listedCount: listed.length,
      };
    });

    expect(result).toEqual({
      duplicateIdentifierRejected: true,
      sharedEmailIdentifierWriteCount: 2,
      ambiguousSharedEmailLookup: true,
      lookupByOriginal: true,
      lookupByDrifted: true,
      listedCount: 0,
    });
  });

  test('wallet signer finalize rejects existing active signers without key material', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoriesModule = await import('/sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `existing_missing_key_material_${crypto.randomUUID()}`,
      );
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repositories = new repositoriesModule.SeamsWalletRepositories(manager);

      await repositories.upsertProfile({
        profileId: 'wallet_existing_missing_key_material',
        defaultSignerSlot: 1,
      });
      await repositories.activateAccountSigner({
        account: {
          profileId: 'wallet_existing_missing_key_material',
          chainIdKey: 'near:testnet',
          accountAddress: 'existing-missing-key.testnet',
          accountModel: 'near-native',
        },
        signer: {
          signerId: 'ed25519:old-missing-key',
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
          metadata: {
            operationalPublicKey: 'ed25519:old-missing-key',
          },
        },
        activationPolicy: { mode: 'fail_if_occupied', signerSlot: 1 },
        preferredSlot: 1,
        mutation: { routeThroughOutbox: false },
      });

      const rejected = await repositories
        .persistWalletSignerFinalize({
          profiles: [{ profileId: 'wallet_existing_missing_key_material' }],
          signerActivations: [
            {
              account: {
                profileId: 'wallet_existing_missing_key_material',
                chainIdKey: 'near:testnet',
                accountAddress: 'existing-missing-key.testnet',
                accountModel: 'near-native',
              },
              signer: {
                signerId: 'ed25519:new-with-key',
                signerType: 'threshold',
                signerKind: 'threshold-ed25519',
                signerAuthMethod: 'passkey',
                signerSource: 'passkey_registration',
                metadata: {
                  operationalPublicKey: 'ed25519:new-with-key',
                },
              },
              activationPolicy: { mode: 'allocate_next_free' },
              preferredSlot: 2,
              mutation: { routeThroughOutbox: false },
            },
          ],
          keyMaterials: [
            {
              profileId: 'wallet_existing_missing_key_material',
              signerSlot: 2,
              chainIdKey: 'near:testnet',
              accountAddress: 'existing-missing-key.testnet',
              keyKind: 'threshold_share_v1',
              algorithm: 'ed25519',
              publicKey: 'ed25519:new-with-key',
              signerId: 'ed25519:new-with-key',
              payload: {
                relayerKeyId: 'relayer-new',
                keyVersion: 'key-version-new',
              },
              timestamp: 2,
              schemaVersion: 1,
            },
          ],
        })
        .then(() => false)
        .catch((error: Error) =>
          String(error.message || '').includes(
            'ed25519:old-missing-key requires matching threshold key material',
          ),
        );
      const signers = await repositories.listAccountSignersByProfile({
        profileId: 'wallet_existing_missing_key_material',
        status: 'active',
      });
      const newSigner = await repositories.getAccountSigner({
        chainIdKey: 'near:testnet',
        accountAddress: 'existing-missing-key.testnet',
        signerId: 'ed25519:new-with-key',
      });
      manager.close();
      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });
      return {
        rejected,
        activeSignerIds: signers.map((signer: { signerId: string }) => signer.signerId),
        newSignerExists: !!newSigner,
      };
    });

    expect(result).toEqual({
      rejected: true,
      activeSignerIds: ['ed25519:old-missing-key'],
      newSignerExists: false,
    });
  });

  test('key material lookup prefers the active signer row over stale placeholder material', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoriesModule = await import('/sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `key_material_shadow_${crypto.randomUUID()}`,
      );
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repositories = new repositoriesModule.SeamsWalletRepositories(manager);

      await repositories.upsertProfile({
        profileId: 'wallet_key_material_shadow',
        defaultSignerSlot: 1,
      });
      await repositories.activateAccountSigner({
        account: {
          profileId: 'wallet_key_material_shadow',
          chainIdKey: 'near:testnet',
          accountAddress: 'shadow.testnet',
          accountModel: 'near-native',
        },
        signer: {
          signerId: 'ed25519:real-material',
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
          metadata: {
            operationalPublicKey: 'ed25519:real-material',
          },
        },
        activationPolicy: { mode: 'fail_if_occupied', signerSlot: 1 },
        preferredSlot: 1,
        mutation: { routeThroughOutbox: false },
      });
      await repositories.storeKeyMaterial({
        profileId: 'wallet_key_material_shadow',
        signerSlot: 1,
        chainIdKey: 'near:testnet',
        accountAddress: 'shadow.testnet',
        keyKind: 'threshold_share_v1',
        algorithm: 'ed25519',
        publicKey: 'ed25519:placeholder',
        signerId: 'credential-placeholder',
        timestamp: 1,
        schemaVersion: 1,
      });
      await repositories.storeKeyMaterial({
        profileId: 'wallet_key_material_shadow',
        signerSlot: 1,
        chainIdKey: 'near:testnet',
        accountAddress: 'shadow.testnet',
        keyKind: 'threshold_share_v1',
        algorithm: 'ed25519',
        publicKey: 'ed25519:real-material',
        signerId: 'ed25519:real-material',
        payload: {
          relayerKeyId: 'relayer-real',
          keyVersion: 'key-version-real',
        },
        timestamp: 2,
        schemaVersion: 1,
      });

      const keyMaterial = await repositories.getKeyMaterial(
        'wallet_key_material_shadow',
        1,
        'near:testnet',
        'threshold_share_v1',
      );
      manager.close();
      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });
      return {
        signerId: keyMaterial?.signerId,
        publicKey: keyMaterial?.publicKey,
        relayerKeyId: keyMaterial?.payload?.relayerKeyId,
      };
    });

    expect(result).toEqual({
      signerId: 'ed25519:real-material',
      publicKey: 'ed25519:real-material',
      relayerKeyId: 'relayer-real',
    });
  });

  test('legacy database name literals stay isolated to explicit boundary files', () => {
    const allowedLegacyReferences = new Set([
      'client/src/core/indexedDB/index.ts',
      'client/src/core/indexedDB/schemaNames.ts',
      'client/src/core/signingEngine/session/persistence/sealedSessionStore.ts',
      'client/src/core/signingEngine/workerManager/workers/email-otp/deviceEnrollmentEscrowStore.ts',
      'shared/src/utils/signingSessionSeal.ts',
    ]);
    const sourceFiles = [
      ...listSourceFiles('client/src'),
      ...listSourceFiles('shared/src'),
    ].filter((relativePath) => !allowedLegacyReferences.has(relativePath));

    for (const legacyName of LEGACY_INDEXED_DB_NAMES) {
      const literalPattern = new RegExp(
        `['"\`]${legacyName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"\`]`,
      );
      const offenders = sourceFiles.filter((relativePath) =>
        literalPattern.test(readRepoSource(relativePath)),
      );
      expect(offenders, legacyName).toEqual([]);
    }
  });

  test('raw IndexedDB APIs stay behind persistence boundaries', () => {
    const rawIndexedDbPattern =
      /\bIDB(?:Database|Transaction|ObjectStore|Request|OpenDBRequest|Factory|Index|KeyRange)\b|indexedDB\.open\(/;
    const allowedRuntimePrefixes = ['client/src/core/indexedDB/'];
    const sourceFiles = [
      ...listSourceFiles('client/src'),
      ...listSourceFiles('shared/src'),
    ];
    const offenders = sourceFiles.filter((relativePath) => {
      if (allowedRuntimePrefixes.some((prefix) => relativePath.startsWith(prefix))) return false;
      return rawIndexedDbPattern.test(readRepoSource(relativePath));
    });

    expect(offenders).toEqual([]);
  });

  test('runtime code uses the unified manager instead of reaching through to clientDB', () => {
    const directClientDbPattern =
      /\b(?:IndexedDBManager|deps\.indexedDB|args\.indexedDB|args\.deps\.indexedDB|ctx\.indexedDB)\.clientDB\b/;
    const sourceFiles = listSourceFiles('client/src').filter(
      (relativePath) => relativePath !== 'client/src/core/indexedDB/unifiedIndexedDBManager.ts',
    );
    const offenders = sourceFiles.filter((relativePath) =>
      directClientDbPattern.test(readRepoSource(relativePath)),
    );

    expect(offenders).toEqual([]);
  });
});
