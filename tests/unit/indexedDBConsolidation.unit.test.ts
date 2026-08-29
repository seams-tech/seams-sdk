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
} from '../../packages/wallet/src/core/indexedDB/schemaNames';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import {
  buildActiveWalletAuthorityV1,
  buildPendingWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
} from '@shared/authorization/walletAuthority';
import {
  parseDeviceId,
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
  parseWalletSessionAuthorizationId,
} from '@shared/authorization/capabilityKinds';
import { parseExactAdministeredSignerManifestV1 } from '@shared/device-linking/delegatedActivationPlan';
import {
  parseActiveWalletSessionV1,
  parseWalletSessionOperationCredentialV1,
} from '@shared/device-linking';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWalletKeyId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { buildWalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { buildLinkedDevicePasskeyEd25519ExportRootEnvelopeFixture } from './helpers/passkeyCustodyEnvelope.fixtures';
import { parseEcdsaThresholdKeyId } from '@/core/signingEngine/session/keyMaterialBrands';

const CANONICAL_NAME_PATTERN = /^seams_[a-z0-9]+(?:_[a-z0-9]+)*$/;
const SNAKE_CASE_PATTERN = /^[a-z0-9]+(?:_[a-z0-9]+)*$/;

function unwrap<T>(result: { ok: true; value: T } | { ok: false; error: { message: string } }): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function fixtureDigest(fill: number) {
  return parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(fill)));
}

async function buildLocalAuthorityInstallationFixture(
  signerFamily: 'ed25519' | 'both' = 'ed25519',
) {
  const walletId = unwrap(parseWalletId('wallet:r103e-install'));
  const authorityId = unwrap(parseWalletAuthorityId('authority:r103e-install'));
  const authMethodId = unwrap(parseWalletAuthMethodId('auth-method:r103e-install'));
  const deviceId = unwrap(parseDeviceId('device:r103e-install'));
  const walletKeyId = unwrap(parseWalletKeyId('wallet-key:r103e-install'));
  const ecdsaWalletKeyId = unwrap(parseWalletKeyId('wallet-key:r103e-install-ecdsa'));
  const rpId = unwrap(parseWebAuthnRpId('wallet.example.test'));
  const credentialIdB64u = unwrap(parseWebAuthnCredentialIdB64u('credential-r103e-install'));
  const ed25519MaterialActivation = buildMpcMaterialActivationRefFixture('r103e-install');
  const ecdsaMaterialActivation = buildMpcMaterialActivationRefFixture('r103e-install-ecdsa');
  const ed25519Signer = {
    kind: 'exact_administered_ed25519_signer_v1' as const,
    keyFamily: 'ed25519' as const,
    walletId,
    walletKeyId,
    registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(1)),
  };
  const ecdsaSigner = {
    kind: 'exact_administered_ecdsa_signer_v1' as const,
    keyFamily: 'ecdsa_secp256k1' as const,
    walletId,
    walletKeyId: ecdsaWalletKeyId,
    thresholdPublicKey33B64u: base64UrlEncode(new Uint8Array([2, ...new Uint8Array(32).fill(9)])),
    evmAddress: `0x${'1'.repeat(40)}`,
  };
  const signerActivations =
    signerFamily === 'both'
      ? buildWalletSignerActivationSetV1({
          manifest: parseExactAdministeredSignerManifestV1({
            kind: 'exact_administered_signer_manifest_v1',
            keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
            signers: [ed25519Signer, ecdsaSigner],
          }),
          materialActivations: {
            keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
            ed25519: ed25519MaterialActivation,
            ecdsa: ecdsaMaterialActivation,
          },
        })
      : buildWalletSignerActivationSetV1({
          manifest: parseExactAdministeredSignerManifestV1({
            kind: 'exact_administered_signer_manifest_v1',
            keyFamilies: ['ed25519'],
            signers: [ed25519Signer],
          }),
          materialActivations: {
            keyFamilies: ['ed25519'],
            ed25519: ed25519MaterialActivation,
          },
        });
  const signerActivationSetDigestB64u =
    await computeWalletSignerActivationSetDigestB64u(signerActivations);
  const packageSetDigestB64u = fixtureDigest(2);
  const authorityDraft = buildPendingWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId,
    walletId,
    principal: { kind: 'owner_device', deviceId },
    provenance: { kind: 'wallet_registration' },
    permissions: buildFullOwnerPermissionsV1(),
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: fixtureDigest(3),
    revocationEpoch: 0,
    createdAtMs: 10,
    updatedAtMs: 10,
    state: 'pending_local_install',
    localInstallPackageSetDigestB64u: packageSetDigestB64u,
  });
  const authority = buildPendingWalletAuthorityV1({
    kind: authorityDraft.kind,
    authorityId: authorityDraft.authorityId,
    walletId: authorityDraft.walletId,
    principal: authorityDraft.principal,
    provenance: authorityDraft.provenance,
    permissions: authorityDraft.permissions,
    signerActivations: authorityDraft.signerActivations,
    signerActivationSetDigestB64u: authorityDraft.signerActivationSetDigestB64u,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(authorityDraft),
    revocationEpoch: authorityDraft.revocationEpoch,
    createdAtMs: authorityDraft.createdAtMs,
    updatedAtMs: authorityDraft.updatedAtMs,
    state: authorityDraft.state,
    localInstallPackageSetDigestB64u: authorityDraft.localInstallPackageSetDigestB64u,
  });
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: authMethodId,
    walletId,
    walletAuthorityId: authorityId,
    kind: 'passkey',
    status: 'pending_local_install',
    rpId,
    credentialIdB64u,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(4)),
    counter: 0,
    createdAtMs: 10,
    updatedAtMs: 10,
  });
  const ed25519SignerMaterial = {
    kind: 'wallet_authority_signer_material_v1' as const,
    authorityId,
    walletAuthMethodId: authMethodId,
    activationId: ed25519MaterialActivation.activationId,
    keyFamily: 'ed25519' as const,
    materialActivation: ed25519MaterialActivation,
    sealedMaterialB64u: 'sealed-material-r103e',
    sealedMaterialDigestB64u: fixtureDigest(5),
  };
  const ecdsaSignerMaterial = {
    kind: 'wallet_authority_signer_material_v1' as const,
    authorityId,
    walletAuthMethodId: authMethodId,
    activationId: ecdsaMaterialActivation.activationId,
    keyFamily: 'ecdsa_secp256k1' as const,
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId('ecdsa-threshold-key:r103e-install'),
    materialActivation: ecdsaMaterialActivation,
    sealedMaterialB64u: 'sealed-material-r103e-ecdsa',
    sealedMaterialDigestB64u: fixtureDigest(10),
  };
  const signerMaterials =
    signerFamily === 'both'
      ? [ed25519SignerMaterial, ecdsaSignerMaterial]
      : [ed25519SignerMaterial];
  const exportRoot = {
    kind: 'wallet_authority_export_root_v1' as const,
    authorityId,
    walletAuthMethodId: authMethodId,
    walletKeyId,
    envelope: buildLinkedDevicePasskeyEd25519ExportRootEnvelopeFixture({
      tag: 'r103e-install',
      walletId,
      walletKeyId,
      registeredPublicKeyB64u: ed25519Signer.registeredPublicKeyB64u,
      rpId,
      credentialIdB64u,
      deviceId,
      sealedFill: 13,
    }),
  };
  const receipt = {
    kind: 'local_authority_installation_receipt_v1' as const,
    authorityId,
    walletId,
    authMethodId,
    deviceId,
    packageSetDigestB64u,
    installedActivationRefs: signerActivations,
    installedRecordSetDigestB64u: fixtureDigest(6),
    targetFactorVerificationDigestB64u: fixtureDigest(7),
    installedAtMs: 20,
  };
  return {
    walletId,
    authMethodId,
    input: {
      authority,
      authMethod,
      signerMaterials,
      exportRoot,
      receipt,
      expectedLockGeneration: 7,
    },
    selection: {
      wallet_id: walletId,
      wallet_auth_method_id: authMethodId,
      lock_generation: 7,
      lock_state: 'locked',
      updated_at_ms: 1,
      record: {
        kind: 'wallet_selection_v1' as const,
        walletId,
        walletAuthMethodId: authMethodId,
        lockGeneration: 7,
        lockState: 'locked' as const,
        updatedAtMs: 1,
      },
    },
  };
}

type LocalAuthorityInstallationFixture = Awaited<
  ReturnType<typeof buildLocalAuthorityInstallationFixture>
>;

function replayInput(
  fixture: LocalAuthorityInstallationFixture,
  signerMaterials = fixture.input.signerMaterials,
  exportRoot = fixture.input.exportRoot,
  receipt = fixture.input.receipt,
) {
  return {
    authority: fixture.input.authority,
    authMethod: fixture.input.authMethod,
    signerMaterials,
    exportRoot,
    receipt,
    expectedLockGeneration: fixture.input.expectedLockGeneration,
  };
}

test.describe('IndexedDB consolidation', () => {
  test('canonical wallet schema names use one Seams-prefixed DB and unprefixed snake_case stores', () => {
    expect(SEAMS_WALLET_DB_NAME).toBe('seams_wallet');
    expect(SEAMS_WALLET_DB_VERSION).toBe(23);
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
      const dbName = schemaNames.createSeamsTestWalletDbName(`manifest_${crypto.randomUUID()}`);

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

  test('unified repositories persist profile, chain account, and app state', async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoryModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(`repositories_${crypto.randomUUID()}`);

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
      await repositories.setLastProfileStateForProfile('bob.testnet', 1, 'https://app.example');
      const profile = await repositories.getProfile('alice.testnet');
      const profiles = await repositories.listProfiles();
      const deletedProfile = await repositories.getProfile('delete.testnet');
      const deletedChainAccounts = await repositories.listChainAccountsByProfile('delete.testnet');
      const chainAccount = await repositories.getChainAccount({
        profileId: 'alice.testnet',
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
      });
      const profileChainAccounts = await repositories.listChainAccountsByProfile('alice.testnet');
      const resolvedAccountContext = await repositories.resolveProfileAccountContext({
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
      });
      const appState = await repositories.getAppState('selected-wallet');
      const lastProfileState = await repositories.getLastProfileState();
      const scopedLastProfileState = await repositories.getLastProfileState('https://app.example');
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
  });

  test('wallet signer rows mirror branch identity fields and replace duplicate ECDSA key identities', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoriesModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
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
          metadata: {
            nearEd25519SigningKeyId: 'near-key-credential-1',
          },
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

      const duplicateEcdsaKeyHandleReplaced = await repositories
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
        .then(() => true)
        .catch(() => false);
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
        duplicateEcdsaKeyHandleReplaced,
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
      ecdsaThresholdKeyId: 'ecdsa-threshold-key-2',
      ecdsaOwnerAddress: '0x2222222222222222222222222222222222222222',
      ecdsaChainTargetKey: 'evm:eip155:1',
      duplicateEcdsaKeyHandleReplaced: true,
      chainTargetDriftRejected: true,
      nearProjectionModels: ['near-native'],
      parsedSignerKindsAfterMirrorDrift: [],
    });
  });

  test('wallet signer finalize rejects missing signer key material atomically', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoriesModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
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
                  nearEd25519SigningKeyId: 'near-key-missing-key',
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

  test('wallet signer finalize rollback removes only the exact batch and restores selection', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoriesModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `signer_finalize_rollback_${crypto.randomUUID()}`,
      );
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repositories = new repositoriesModule.SeamsWalletRepositories(manager);
      const walletId = 'wallet_rollback';
      const nearProfileId = 'near-profile:rollback.testnet';
      await repositories.upsertProfile({ profileId: walletId, defaultSignerSlot: 1 });
      await repositories.upsertProfile({ profileId: nearProfileId, defaultSignerSlot: 1 });
      await repositories.setLastProfileState({ profileId: walletId, activeSignerSlot: 1 });

      const signerActivations = [
        {
          account: {
            profileId: walletId,
            chainIdKey: 'wallet',
            accountAddress: walletId,
            accountModel: 'wallet',
          },
          signer: {
            signerId: 'ed25519:rollback-public',
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            metadata: { nearEd25519SigningKeyId: 'rollback-signing-key' },
          },
          activationPolicy: { mode: 'fail_if_occupied', signerSlot: 2 },
          preferredSlot: 2,
          mutation: { routeThroughOutbox: false },
        },
        {
          account: {
            profileId: nearProfileId,
            chainIdKey: 'near:testnet',
            accountAddress: 'rollback.testnet',
            accountModel: 'near-native',
          },
          signer: {
            signerId: 'ed25519:rollback-public',
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            metadata: { nearEd25519SigningKeyId: 'rollback-signing-key' },
          },
          activationPolicy: { mode: 'fail_if_occupied', signerSlot: 2 },
          preferredSlot: 2,
          mutation: { routeThroughOutbox: false },
        },
      ];
      const keyMaterials = [
        {
          profileId: walletId,
          signerSlot: 2,
          chainIdKey: 'wallet',
          accountAddress: walletId,
          keyKind: 'threshold_share_v1',
          algorithm: 'ed25519',
          publicKey: 'ed25519:rollback-public',
          signerId: 'ed25519:rollback-public',
          timestamp: 2,
          schemaVersion: 1,
        },
        {
          profileId: nearProfileId,
          signerSlot: 2,
          chainIdKey: 'near:testnet',
          accountAddress: 'rollback.testnet',
          keyKind: 'threshold_share_v1',
          algorithm: 'ed25519',
          publicKey: 'ed25519:rollback-public',
          signerId: 'ed25519:rollback-public',
          timestamp: 2,
          schemaVersion: 1,
        },
      ];
      const persisted = await repositories.persistWalletSignerFinalize({
        profiles: [
          { profileId: walletId, defaultSignerSlot: 2 },
          { profileId: nearProfileId, defaultSignerSlot: 2 },
        ],
        signerActivations,
        keyMaterials,
        lastProfileState: { profileId: walletId, activeSignerSlot: 2 },
      });
      const signerCountBefore = (
        await repositories.listAccountSignersByProfile({ profileId: walletId })
      ).length;
      await repositories.rollbackWalletSignerFinalize(persisted.rollbackReceipt);
      const walletProfile = await repositories.getProfile(walletId);
      const nearProfile = await repositories.getProfile(nearProfileId);
      const signerCountAfter = (
        await repositories.listAccountSignersByProfile({ profileId: walletId })
      ).length;
      const keyMaterialAfter = await repositories.getKeyMaterial(
        walletId,
        2,
        'wallet',
        'threshold_share_v1',
      );
      const lastProfileState = await repositories.getLastProfileState();
      manager.close();
      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });
      return {
        signerCountBefore,
        signerCountAfter,
        keyMaterialAfter,
        walletDefaultSignerSlot: walletProfile?.defaultSignerSlot,
        nearDefaultSignerSlot: nearProfile?.defaultSignerSlot,
        lastProfileState,
      };
    });

    expect(result).toEqual({
      signerCountBefore: 1,
      signerCountAfter: 0,
      keyMaterialAfter: null,
      walletDefaultSignerSlot: 1,
      nearDefaultSignerSlot: 1,
      lastProfileState: { profileId: 'wallet_rollback', activeSignerSlot: 1 },
    });
  });

  test('wallet auth-method rows allow shared Email OTP identifiers and reject passkey duplicates plus scalar drift', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const repositoriesModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
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
          authority: {
            walletId: 'wallet_email_a',
            factor: {
              kind: 'email_otp',
              provider: 'email',
              providerUserId: 'email-a',
            },
            verifier: {
              kind: 'email_otp_wallet_auth_method',
              emailHashHex: 'same-email-hash',
            },
            bindingId: 'email_otp:wallet_email_a:same-email-hash',
          },
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
          authority: {
            walletId: 'wallet_email_a',
            factor: {
              kind: 'email_otp',
              provider: 'email',
              providerUserId: 'email-a',
            },
            verifier: {
              kind: 'email_otp_wallet_auth_method',
              emailHashHex: 'same-email-hash',
            },
            bindingId: 'email_otp:wallet_email_a:same-email-hash',
          },
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
          authority: {
            walletId: 'wallet_email_b',
            factor: {
              kind: 'email_otp',
              provider: 'email',
              providerUserId: 'email-b',
            },
            verifier: {
              kind: 'email_otp_wallet_auth_method',
              emailHashHex: 'same-email-hash',
            },
            bindingId: 'email_otp:wallet_email_b:same-email-hash',
          },
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
      const row = await store.get(
        ['wallet_auth_a', 'passkey', 'local', 'shared-credential'].join('\0'),
      );
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
      const repositoriesModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
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
            nearEd25519SigningKeyId: 'near-key-old-missing-key',
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
                  nearEd25519SigningKeyId: 'near-key-new-with-key',
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
      const repositoriesModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
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
            nearEd25519SigningKeyId: 'near-key-real-material',
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

  test('installs a local authority atomically and resolves the selected V2 method exactly', async ({
    page,
  }) => {
    const fixture = await buildLocalAuthorityInstallationFixture('both');
    const material = fixture.input.signerMaterials[0];
    if (material.keyFamily !== 'ed25519') {
      throw new Error('combined authority fixture must place Ed25519 material first');
    }
    const materialConflictInput = replayInput(fixture, [
      {
        ...material,
        sealedMaterialB64u: 'different-sealed-material-r103e',
      },
      ...fixture.input.signerMaterials.slice(1),
    ]);
    const root = fixture.input.exportRoot;
    if (!root) throw new Error('fixture export root is required');
    if (
      root.envelope.binding.kind !== 'ed25519_yao_client_root_v1' ||
      root.envelope.factor.kind !== 'passkey'
    ) {
      throw new Error('fixture export root must be Passkey-sealed Ed25519 material');
    }
    const exportRootConflictInput = replayInput(fixture, fixture.input.signerMaterials, {
      kind: root.kind,
      authorityId: root.authorityId,
      walletAuthMethodId: root.walletAuthMethodId,
      walletKeyId: root.walletKeyId,
      envelope: buildLinkedDevicePasskeyEd25519ExportRootEnvelopeFixture({
        tag: 'r103e-install',
        walletId: root.envelope.walletId,
        walletKeyId: root.walletKeyId,
        registeredPublicKeyB64u: root.envelope.binding.registeredPublicKeyB64u,
        rpId: root.envelope.factor.rpId,
        credentialIdB64u: root.envelope.factor.credentialIdB64u,
        deviceId: root.envelope.binding.deviceId,
        sealedFill: 14,
      }),
    });
    const receipt = fixture.input.receipt;
    const receiptConflictInput = replayInput(
      fixture,
      fixture.input.signerMaterials,
      fixture.input.exportRoot,
      {
        kind: receipt.kind,
        authorityId: receipt.authorityId,
        walletId: receipt.walletId,
        authMethodId: receipt.authMethodId,
        deviceId: receipt.deviceId,
        packageSetDigestB64u: receipt.packageSetDigestB64u,
        installedActivationRefs: receipt.installedActivationRefs,
        installedRecordSetDigestB64u: fixtureDigest(9),
        targetFactorVerificationDigestB64u: receipt.targetFactorVerificationDigestB64u,
        installedAtMs: receipt.installedAtMs,
      },
    );
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(
      async ({ fixture, materialConflictInput, exportRootConflictInput, receiptConflictInput }) => {
        const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
        const managerModule =
          await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
        const repositoryModule =
          await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
        const dbName = schemaNames.createSeamsTestWalletDbName(
          `authority_install_${crypto.randomUUID()}`,
        );
        const manager = new managerModule.SeamsWalletDBManager();
        manager.setDbName(dbName);
        const repositories = new repositoryModule.SeamsWalletRepositories(manager);
        const db = await manager.getDB();
        await db.put(schemaNames.SEAMS_WALLET_STORES.walletSelections, fixture.selection);

        const installed = await repositories.installLocalAuthority(fixture.input);
        if (installed.kind === 'integrity_error') {
          throw new Error(`local authority fixture install failed: ${installed.reason}`);
        }
        const replayed = await repositories.installLocalAuthority(fixture.input);
        const resolved = await repositories.resolveSelectedWalletAuthority(fixture.walletId);
        const materialConflict = await repositories.installLocalAuthority(materialConflictInput);
        const exportRootConflict =
          await repositories.installLocalAuthority(exportRootConflictInput);
        const receiptConflict = await repositories.installLocalAuthority(receiptConflictInput);
        const storedMaterial = await db.get(
          schemaNames.SEAMS_WALLET_STORES.walletAuthoritySignerMaterials,
          [
            fixture.input.authority.authorityId,
            fixture.input.authMethod.walletAuthMethodId,
            fixture.input.signerMaterials[0].activationId,
          ],
        );
        const storedExportRoot = await db.get(
          schemaNames.SEAMS_WALLET_STORES.walletAuthorityExportRoots,
          [
            fixture.input.exportRoot.authorityId,
            fixture.input.exportRoot.walletAuthMethodId,
            fixture.input.exportRoot.walletKeyId,
          ],
        );
        const storedReceipt = await db.get(
          schemaNames.SEAMS_WALLET_STORES.walletAuthorityInstallationReceipts,
          fixture.input.receipt.authorityId,
        );
        await db.put(schemaNames.SEAMS_WALLET_STORES.walletSelections, {
          wallet_id: fixture.walletId,
          wallet_auth_method_id: fixture.authMethodId,
          lock_generation: 8,
          lock_state: 'locked',
          updated_at_ms: 2,
          record: {
            kind: 'wallet_selection_v1',
            walletId: fixture.walletId,
            walletAuthMethodId: fixture.authMethodId,
            lockGeneration: 8,
            lockState: 'locked',
            updatedAtMs: 2,
          },
        });
        const stale = await repositories.installLocalAuthority(fixture.input);
        const authorityCount = await db.count(schemaNames.SEAMS_WALLET_STORES.walletAuthorities);
        const authMethodCount = await db.count(schemaNames.SEAMS_WALLET_STORES.walletAuthMethods);
        const materialCount = await db.count(
          schemaNames.SEAMS_WALLET_STORES.walletAuthoritySignerMaterials,
        );
        const receiptCount = await db.count(
          schemaNames.SEAMS_WALLET_STORES.walletAuthorityInstallationReceipts,
        );
        const exportRootCount = await db.count(
          schemaNames.SEAMS_WALLET_STORES.walletAuthorityExportRoots,
        );
        const selectionCount = await db.count(schemaNames.SEAMS_WALLET_STORES.walletSelections);
        manager.close();
        await new Promise<void>((resolve) => {
          const request = indexedDB.deleteDatabase(dbName);
          request.onsuccess = () => resolve();
          request.onerror = () => resolve();
          request.onblocked = () => resolve();
        });
        return {
          installed: installed.kind,
          replayed: replayed.kind,
          resolved: resolved.kind,
          resolvedAuthorityId: resolved.kind === 'resolved' ? resolved.authority.authorityId : null,
          resolvedSignerMaterials: resolved.kind === 'resolved' ? resolved.signerMaterials : null,
          materialConflict: materialConflict.kind,
          exportRootConflict: exportRootConflict.kind,
          receiptConflict: receiptConflict.kind,
          storedMaterial: storedMaterial.record.sealedMaterialB64u,
          storedExportRoot: storedExportRoot.record.envelope.sealedCustodySecretB64u,
          storedReceipt: storedReceipt.record.installedRecordSetDigestB64u,
          stale: stale.kind,
          actualLockGeneration:
            stale.kind === 'stale_lock_generation' ? stale.actualLockGeneration : null,
          counts: {
            authorityCount,
            authMethodCount,
            materialCount,
            receiptCount,
            exportRootCount,
            selectionCount,
          },
        };
      },
      { fixture, materialConflictInput, exportRootConflictInput, receiptConflictInput },
    );

    expect(result).toEqual({
      installed: 'installed',
      replayed: 'idempotent_replay',
      resolved: 'resolved',
      resolvedAuthorityId: fixture.input.authority.authorityId,
      resolvedSignerMaterials: [],
      materialConflict: 'integrity_error',
      exportRootConflict: 'integrity_error',
      receiptConflict: 'integrity_error',
      storedMaterial: 'sealed-material-r103e',
      storedExportRoot: fixture.input.exportRoot?.envelope.sealedCustodySecretB64u,
      storedReceipt: fixture.input.receipt.installedRecordSetDigestB64u,
      stale: 'stale_lock_generation',
      actualLockGeneration: 8,
      counts: {
        authorityCount: 1,
        authMethodCount: 1,
        materialCount: 2,
        receiptCount: 1,
        exportRootCount: 1,
        selectionCount: 1,
      },
    });
  });

  test('refuses stale finalization after an explicit lock advances the selection generation', async ({
    page,
  }) => {
    const fixture = await buildLocalAuthorityInstallationFixture();
    const pendingAuthority = fixture.input.authority;
    const activeAuthorityDraft = buildActiveWalletAuthorityV1({
      kind: pendingAuthority.kind,
      authorityId: pendingAuthority.authorityId,
      walletId: pendingAuthority.walletId,
      principal: pendingAuthority.principal,
      provenance: pendingAuthority.provenance,
      permissions: pendingAuthority.permissions,
      signerActivations: pendingAuthority.signerActivations,
      signerActivationSetDigestB64u: pendingAuthority.signerActivationSetDigestB64u,
      authorityDigestB64u: pendingAuthority.authorityDigestB64u,
      revocationEpoch: pendingAuthority.revocationEpoch,
      createdAtMs: pendingAuthority.createdAtMs,
      updatedAtMs: 30,
      state: 'active',
      activatedAtMs: 30,
    });
    const activeAuthority = buildActiveWalletAuthorityV1({
      ...activeAuthorityDraft,
      authorityDigestB64u: await computeWalletAuthorityDigestB64u(activeAuthorityDraft),
    });
    const pendingAuthMethod = fixture.input.authMethod;
    const activeAuthMethod = buildWalletAuthMethodRecordV2({
      ...pendingAuthMethod,
      status: 'active',
      updatedAtMs: 30,
      activatedAtMs: 30,
    });
    const authorizationId = unwrap(
      parseWalletSessionAuthorizationId('wallet-session:r103e-install'),
    );
    const quotaId = unwrap(parseMpcWalletSigningQuotaId('quota:r103e-install'));
    const activeWalletSession = parseActiveWalletSessionV1({
      kind: 'active_wallet_session_v1',
      walletId: fixture.walletId,
      authorityId: activeAuthority.authorityId,
      authMethodId: activeAuthMethod.walletAuthMethodId,
      authorizationId,
      quotaId,
      authorityDigestB64u: activeAuthority.authorityDigestB64u,
      authorityRevocationEpoch: activeAuthority.revocationEpoch,
      capabilitySubjects: [
        {
          kind: 'sign',
          keyFamily: 'ed25519',
          materialActivation: fixture.input.signerMaterials[0].materialActivation,
        },
      ],
      issuedAtMs: 30,
      expiresAtMs: 3_600_030,
    });
    const operationCredential = parseWalletSessionOperationCredentialV1({
      kind: 'opaque_wallet_session_operation_credential_v1',
      token: `wst_${'a'.repeat(43)}`,
      walletSessionId: unwrap(parseWalletSessionId('wallet-session:r103e-install')),
    });
    const unlockedSelection = {
      ...fixture.selection,
      lock_state: 'unlocked' as const,
      record: { ...fixture.selection.record, lockState: 'unlocked' as const },
    };
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(
      async ({
        fixture,
        unlockedSelection,
        activeAuthority,
        activeAuthMethod,
        activeWalletSession,
        operationCredential,
      }) => {
        const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
        const managerModule =
          await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
        const repositoryModule =
          await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
        const dbName = schemaNames.createSeamsTestWalletDbName(
          `authority_finalize_lock_${crypto.randomUUID()}`,
        );
        const manager = new managerModule.SeamsWalletDBManager();
        manager.setDbName(dbName);
        const repositories = new repositoryModule.SeamsWalletRepositories(manager);
        const db = await manager.getDB();
        await db.put(schemaNames.SEAMS_WALLET_STORES.walletSelections, unlockedSelection);
        const installed = await repositories.installLocalAuthority(fixture.input);
        if (installed.kind === 'integrity_error') {
          throw new Error(`local authority fixture install failed: ${installed.reason}`);
        }
        const advancedGeneration = await repositories.advanceWalletLockGeneration({
          walletId: fixture.walletId,
          lockedAtMs: 40,
        });
        const stale = await repositories.finalizeLocalAuthorityActivation({
          authority: activeAuthority,
          authMethod: activeAuthMethod,
          walletSession: activeWalletSession,
          operationCredential,
          expectedLockGeneration: fixture.input.expectedLockGeneration,
        });
        const locked = await repositories.finalizeLocalAuthorityActivation({
          authority: activeAuthority,
          authMethod: activeAuthMethod,
          walletSession: activeWalletSession,
          operationCredential,
          expectedLockGeneration: advancedGeneration,
        });
        const authority = await db.get(
          schemaNames.SEAMS_WALLET_STORES.walletAuthorities,
          fixture.input.authority.authorityId,
        );
        const authMethod = await db.get(
          schemaNames.SEAMS_WALLET_STORES.walletAuthMethods,
          fixture.input.authMethod.walletAuthMethodId,
        );
        const selection = await db.get(
          schemaNames.SEAMS_WALLET_STORES.walletSelections,
          fixture.walletId,
        );
        const session = await db.get(
          schemaNames.SEAMS_WALLET_STORES.walletSessionAuthorizations,
          activeWalletSession.authorizationId,
        );
        manager.close();
        await new Promise<void>((resolve) => {
          const request = indexedDB.deleteDatabase(dbName);
          request.onsuccess = () => resolve();
          request.onerror = () => resolve();
          request.onblocked = () => resolve();
        });
        return {
          advancedGeneration,
          stale,
          locked,
          authorityState: authority?.record?.state,
          authMethodStatus: authMethod?.record?.status,
          selectionGeneration: selection?.lock_generation,
          selectionState: selection?.lock_state,
          sessionPresent: session !== undefined,
        };
      },
      {
        fixture,
        unlockedSelection,
        activeAuthority,
        activeAuthMethod,
        activeWalletSession,
        operationCredential,
      },
    );

    expect(result).toEqual({
      advancedGeneration: 8,
      stale: {
        kind: 'stale_lock_generation',
        expectedLockGeneration: 7,
        actualLockGeneration: 8,
      },
      locked: { kind: 'wallet_locked', lockGeneration: 8 },
      authorityState: 'pending_local_install',
      authMethodStatus: 'pending_local_install',
      selectionGeneration: 8,
      selectionState: 'locked',
      sessionPresent: false,
    });
  });

  test('unlocks only the selected auth method without advancing selection generation', async ({
    page,
  }) => {
    const fixture = await buildLocalAuthorityInstallationFixture();
    const siblingAuthMethodId = unwrap(parseWalletAuthMethodId('auth-method:r103e-sibling'));
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(
      async ({ fixture, siblingAuthMethodId }) => {
        const schemaNames = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
        const managerModule =
          await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
        const repositoryModule =
          await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/repositories.js');
        const dbName = schemaNames.createSeamsTestWalletDbName(
          `selection_unlock_${crypto.randomUUID()}`,
        );
        const manager = new managerModule.SeamsWalletDBManager();
        manager.setDbName(dbName);
        const repositories = new repositoryModule.SeamsWalletRepositories(manager);
        const db = await manager.getDB();
        await db.put(schemaNames.SEAMS_WALLET_STORES.walletSelections, fixture.selection);

        const siblingRejected = await repositories
          .markWalletSelectionUnlocked({
            walletId: fixture.walletId,
            walletAuthMethodId: siblingAuthMethodId,
            unlockedAtMs: 2,
          })
          .then(() => false)
          .catch(() => true);
        const afterSibling = await db.get(
          schemaNames.SEAMS_WALLET_STORES.walletSelections,
          fixture.walletId,
        );
        await repositories.markWalletSelectionUnlocked({
          walletId: fixture.walletId,
          walletAuthMethodId: fixture.authMethodId,
          unlockedAtMs: 3,
        });
        const afterExact = await db.get(
          schemaNames.SEAMS_WALLET_STORES.walletSelections,
          fixture.walletId,
        );
        manager.close();
        await new Promise<void>((resolve) => {
          const request = indexedDB.deleteDatabase(dbName);
          request.onsuccess = () => resolve();
          request.onerror = () => resolve();
          request.onblocked = () => resolve();
        });
        return {
          siblingRejected,
          afterSibling: {
            lockState: afterSibling?.lock_state,
            lockGeneration: afterSibling?.lock_generation,
          },
          afterExact: {
            lockState: afterExact?.lock_state,
            lockGeneration: afterExact?.lock_generation,
          },
        };
      },
      { fixture, siblingAuthMethodId },
    );

    expect(result).toEqual({
      siblingRejected: true,
      afterSibling: { lockState: 'locked', lockGeneration: 7 },
      afterExact: { lockState: 'unlocked', lockGeneration: 7 },
    });
  });
});
