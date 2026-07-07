import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import {
  SEAMS_WALLET_DB_NAME,
  SEAMS_WALLET_DB_VERSION,
  SEAMS_WALLET_INDEXES,
  SEAMS_WALLET_SCHEMA_MANIFEST,
  SEAMS_WALLET_STORES,
  assertCanonicalIndexedDBName,
  createSeamsTestWalletDbName,
} from '../../packages/sdk-web/src/core/indexedDB/schemaNames';

const CANONICAL_NAME_PATTERN = /^seams_[a-z0-9]+(?:_[a-z0-9]+)*$/;
const SNAKE_CASE_PATTERN = /^[a-z0-9]+(?:_[a-z0-9]+)*$/;

test.describe('IndexedDB consolidation', () => {
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

  test('fresh seams wallet databases match the schema manifest', async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
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
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
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

  test('unified repositories persist profile, chain account, app state, and recovery email records', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule = await import(
        '/_test-sdk/esm/core/indexedDB/seamsWalletDB/repositories.js'
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
      await repositories.upsertChainAccount({
        profileId: 'alice.testnet',
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
        accountModel: 'near-native',
        isPrimary: true,
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
      await repositories.upsertChainAccount({
        profileId: 'delete.testnet',
        chainIdKey: 'near:testnet',
        accountAddress: 'delete.testnet',
        accountModel: 'near-native',
        isPrimary: true,
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
      const profile = await repositories.getProfile('alice.testnet');
      const profiles = await repositories.listProfiles();
      const deletedProfile = await repositories.getProfile('delete.testnet');
      const deletedChainAccounts =
        await repositories.listChainAccountsByProfile('delete.testnet');
      const chainAccount = await repositories.getChainAccount({
        profileId: 'alice.testnet',
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
      });
      const profileChainAccounts =
        await repositories.listChainAccountsByProfile('alice.testnet');
      const resolvedAccountContext = await repositories.resolveProfileAccountContext({
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
      });
      const appState = await repositories.getAppState('selected-wallet');
      const lastProfileState = await repositories.getLastProfileState();
      const scopedLastProfileState = await repositories.getLastProfileState('https://app.example');
      const recoveryEmails = await repositories.listRecoveryEmails('alice.testnet');
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
        deletedProfile,
        deletedChainAccounts,
        chainAccount,
        profileChainAccounts,
        resolvedAccountContext,
        appState,
        lastProfileState,
        scopedLastProfileState,
        recoveryEmails,
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
    expect(result.chainAccount).toMatchObject({
      profileId: 'alice.testnet',
      chainIdKey: 'near:testnet',
      accountAddress: 'alice.testnet',
      accountModel: 'near-native',
      isPrimary: true,
    });
    expect(result.profileChainAccounts).toHaveLength(1);
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
  });

  test('wallet signer rows mirror branch identity fields and ECDSA signers do not create NEAR projections', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoriesModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
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
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoriesModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
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
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoriesModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
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

      const emailOtpRpIdRejected = await repositories
        .upsertWalletAuthMethod({
          version: 'wallet_auth_method_v1',
          kind: 'email_otp',
          status: 'active',
          localStatus: 'synced',
          walletId: 'wallet_email_a',
          rpId: 'local',
          emailHashHex: 'same-email-hash',
          registrationAuthorityId: 'challenge-a',
          createdAtMs: 5,
          updatedAtMs: 6,
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
          emailHashHex: 'same-email-hash',
          registrationAuthorityId: 'challenge-a',
          createdAtMs: 5,
          updatedAtMs: 6,
        }),
        repositories.upsertWalletAuthMethod({
          version: 'wallet_auth_method_v1',
          kind: 'email_otp',
          status: 'active',
          localStatus: 'synced',
          walletId: 'wallet_email_b',
          emailHashHex: 'same-email-hash',
          registrationAuthorityId: 'challenge-b',
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
        emailOtpRpIdRejected,
        sharedEmailIdentifierWriteCount: sharedEmailIdentifierWrites.length,
        ambiguousSharedEmailLookup: ambiguousSharedEmailLookup === null,
        lookupByOriginal: lookupByOriginal === null,
        lookupByDrifted: lookupByDrifted === null,
        listedCount: listed.length,
      };
    });

    expect(result).toEqual({
      duplicateIdentifierRejected: true,
      emailOtpRpIdRejected: true,
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
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoriesModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
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
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoriesModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
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

});
