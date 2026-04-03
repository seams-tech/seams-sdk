import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  clientDB: '/sdk/esm/core/indexedDB/passkeyClientDB/manager.js',
  getDeviceNumber: '/sdk/esm/core/signingEngine/signers/webauthn/device/getDeviceNumber.js',
} as const;

test.describe('PasskeyClientDB device selection', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('getLastLoggedInDeviceNumber does not fall back to another account', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { getLastLoggedInDeviceNumber } = await import(paths.getDeviceNumber);

        const db = new PasskeyClientDBManager();
        const seedNearDevice = async (input: {
          nearAccountId: string;
          deviceNumber: number;
          operationalPublicKey: string;
          passkeyCredential: { id: string; rawId: string };
        }) => {
          const accountAddress = String(input.nearAccountId || '').trim().toLowerCase();
          const chainIdKey = accountAddress.endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
          const profileId = `profile-near:${accountAddress}`;
          await db.upsertProfile({
            profileId,
            defaultDeviceNumber: input.deviceNumber,
            passkeyCredential: input.passkeyCredential,
          });
          await db.upsertChainAccount({
            profileId,
            chainIdKey,
            accountAddress,
            accountModel: 'near-native',
            isPrimary: true,
          });
          await db.upsertAccountSigner({
            profileId,
            chainIdKey,
            accountAddress,
            signerId: input.operationalPublicKey,
            signerSlot: input.deviceNumber,
            signerType: 'passkey',
            status: 'active',
            mutation: { routeThroughOutbox: false },
          });
          return { profileId, chainIdKey, accountAddress };
        };
        // Store a different account in DB (this will set lastUser to bob)
        await seedNearDevice({
          nearAccountId: 'bob.testnet',
          deviceNumber: 2,
          operationalPublicKey: 'ed25519:pkbob',
          passkeyCredential: { id: 'c-bob', rawId: 'r-bob' },
        });
        const alice = await seedNearDevice({
          nearAccountId: 'alice.testnet',
          deviceNumber: 1,
          operationalPublicKey: 'ed25519:pkalice',
          passkeyCredential: { id: 'c-alice', rawId: 'r-alice' },
        });
        // Point lastUser back to a different account so bob has no last-user session
        await db.setLastProfileStateForProfile(alice.profileId, 1);

        try {
          await getLastLoggedInDeviceNumber('bob.testnet', db);
          return { threw: false };
        } catch (e: any) {
          return { threw: true, message: String(e?.message || e) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.threw).toBe(true);
    expect(result.message).toContain('No last user session');
  });

  test('selectProfileAuthenticatorsForPrompt filters authenticators to last-user device', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);

        const db = new PasskeyClientDBManager();
        const seedNearDevice = async (input: {
          nearAccountId: string;
          deviceNumber: number;
          operationalPublicKey: string;
          passkeyCredential: { id: string; rawId: string };
        }) => {
          const accountAddress = String(input.nearAccountId || '').trim().toLowerCase();
          const chainIdKey = accountAddress.endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
          const profileId = `profile-near:${accountAddress}`;
          await db.upsertProfile({
            profileId,
            defaultDeviceNumber: input.deviceNumber,
            passkeyCredential: input.passkeyCredential,
          });
          await db.upsertChainAccount({
            profileId,
            chainIdKey,
            accountAddress,
            accountModel: 'near-native',
            isPrimary: true,
          });
          await db.upsertAccountSigner({
            profileId,
            chainIdKey,
            accountAddress,
            signerId: input.operationalPublicKey,
            signerSlot: input.deviceNumber,
            signerType: 'passkey',
            status: 'active',
            mutation: { routeThroughOutbox: false },
          });
          return { profileId, chainIdKey, accountAddress };
        };
        // Store user records for both devices
        const context = await seedNearDevice({
          nearAccountId: 'carol.testnet',
          deviceNumber: 3,
          operationalPublicKey: 'ed25519:pk-3',
          passkeyCredential: { id: 'c-3', rawId: 'r-3' },
        });
        await seedNearDevice({
          nearAccountId: 'carol.testnet',
          deviceNumber: 6,
          operationalPublicKey: 'ed25519:pk-6',
          passkeyCredential: { id: 'c-6', rawId: 'r-6' },
        });
        // Last logged-in device is 6
        await db.setLastProfileStateForProfile(context.profileId, 6);

        const authenticators = [
          {
            credentialId: 'cred-old',
            credentialPublicKey: new Uint8Array([1]),
            deviceNumber: 3,
            nearAccountId: 'carol.testnet',
            registered: '',
            syncedAt: '',
          },
          {
            credentialId: 'cred-new',
            credentialPublicKey: new Uint8Array([2]),
            deviceNumber: 6,
            nearAccountId: 'carol.testnet',
            registered: '',
            syncedAt: '',
          },
        ];

        const projected = authenticators.map((auth: any) => ({
          profileId: context.profileId,
          deviceNumber: auth.deviceNumber,
          credentialId: auth.credentialId,
          credentialPublicKey: auth.credentialPublicKey,
          transports: auth.transports,
          name: auth.name,
          registered: auth.registered,
          syncedAt: auth.syncedAt,
        }));
        const { authenticatorsForPrompt, wrongPasskeyError } =
          await db.selectProfileAuthenticatorsForPrompt({
            profileId: context.profileId,
            authenticators: projected as any,
          });
        return {
          filteredIds: authenticatorsForPrompt.map((a: any) => a.credentialId),
          wrongPasskeyError: wrongPasskeyError || null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.wrongPasskeyError).toBeNull();
    expect(result.filteredIds).toEqual(['cred-new']);
  });

  test('setLastProfileStateForProfile pins deviceNumber when multiple entries exist', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { getLastLoggedInDeviceNumber } = await import(paths.getDeviceNumber);

        const db = new PasskeyClientDBManager();
        const seedNearDevice = async (input: {
          nearAccountId: string;
          deviceNumber: number;
          operationalPublicKey: string;
          passkeyCredential: { id: string; rawId: string };
          lastUpdated?: number;
        }) => {
          const accountAddress = String(input.nearAccountId || '').trim().toLowerCase();
          const chainIdKey = accountAddress.endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
          const profileId = `profile-near:${accountAddress}`;
          await db.upsertProfile({
            profileId,
            defaultDeviceNumber: input.deviceNumber,
            passkeyCredential: input.passkeyCredential,
          });
          await db.upsertChainAccount({
            profileId,
            chainIdKey,
            accountAddress,
            accountModel: 'near-native',
            isPrimary: true,
          });
          await db.upsertAccountSigner({
            profileId,
            chainIdKey,
            accountAddress,
            signerId: input.operationalPublicKey,
            signerSlot: input.deviceNumber,
            signerType: 'passkey',
            status: 'active',
            mutation: { routeThroughOutbox: false },
          });
          return { profileId, chainIdKey, accountAddress };
        };
        const getLastSelectedNearProjection = async () => {
          const lastProfileState = await db.getLastProfileState().catch(() => null);
          if (!lastProfileState?.profileId) return null;
          const chainAccounts = await db.listChainAccountsByProfile(lastProfileState.profileId);
          const nearAccount =
            chainAccounts.find((row: any) => String(row.chainIdKey || '').startsWith('near:')) ||
            null;
          if (!nearAccount) return null;
          return {
            nearAccountId: nearAccount.accountAddress,
            deviceNumber: lastProfileState.deviceNumber,
          };
        };

        // Insert two devices for the same account
        const context = await seedNearDevice({
          nearAccountId: 'dana.testnet',
          deviceNumber: 3,
          operationalPublicKey: 'ed25519:pk-3',
          passkeyCredential: { id: 'c-3', rawId: 'r-3' },
          lastUpdated: 1000,
        });
        await seedNearDevice({
          nearAccountId: 'dana.testnet',
          deviceNumber: 6,
          operationalPublicKey: 'ed25519:pk-6',
          passkeyCredential: { id: 'c-6', rawId: 'r-6' },
          lastUpdated: 2000,
        });

        // Simulate login selecting device 6
        await db.setLastProfileStateForProfile(context.profileId, 6);

        const last = await getLastSelectedNearProjection();
        const deviceFromHelper = await getLastLoggedInDeviceNumber('dana.testnet', db);
        const projected = [
          {
            credentialId: 'c-3',
            credentialPublicKey: new Uint8Array([1]),
            deviceNumber: 3,
            nearAccountId: 'dana.testnet',
            registered: '',
            syncedAt: '',
          },
          {
            credentialId: 'c-6',
            credentialPublicKey: new Uint8Array([2]),
            deviceNumber: 6,
            nearAccountId: 'dana.testnet',
            registered: '',
            syncedAt: '',
          },
        ].map((auth: any) => ({
          profileId: context.profileId,
          deviceNumber: auth.deviceNumber,
          credentialId: auth.credentialId,
          credentialPublicKey: auth.credentialPublicKey,
          transports: auth.transports,
          name: auth.name,
          registered: auth.registered,
          syncedAt: auth.syncedAt,
        }));
        const { authenticatorsForPrompt } = await db.selectProfileAuthenticatorsForPrompt({
          profileId: context.profileId,
          authenticators: projected as any,
        });

        return {
          lastDevice: last?.deviceNumber,
          helperDevice: deviceFromHelper,
          filteredIds: authenticatorsForPrompt.map((a: any) => a.credentialId),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.lastDevice).toBe(6);
    expect(result.helperDevice).toBe(6);
    expect(result.filteredIds).toEqual(['c-6']);
  });

  test('lastProfileState is scoped by parent origin (multi-app wallet origin)', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);

        const db = new PasskeyClientDBManager();
        const originA = 'https://app-a.example';
        const originB = 'https://app-b.example';
        const seedNearDevice = async (input: {
          nearAccountId: string;
          deviceNumber: number;
          operationalPublicKey: string;
          passkeyCredential: { id: string; rawId: string };
        }) => {
          const accountAddress = String(input.nearAccountId || '').trim().toLowerCase();
          const chainIdKey = accountAddress.endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
          const profileId = `profile-near:${accountAddress}`;
          await db.upsertProfile({
            profileId,
            defaultDeviceNumber: input.deviceNumber,
            passkeyCredential: input.passkeyCredential,
          });
          await db.upsertChainAccount({
            profileId,
            chainIdKey,
            accountAddress,
            accountModel: 'near-native',
            isPrimary: true,
          });
          await db.upsertAccountSigner({
            profileId,
            chainIdKey,
            accountAddress,
            signerId: input.operationalPublicKey,
            signerSlot: input.deviceNumber,
            signerType: 'passkey',
            status: 'active',
            mutation: { routeThroughOutbox: false },
          });
          return { profileId };
        };
        const getLastSelectedNearProjection = async () => {
          const lastProfileState = await db.getLastProfileState().catch(() => null);
          if (!lastProfileState?.profileId) return null;
          const chainAccounts = await db.listChainAccountsByProfile(lastProfileState.profileId);
          const nearAccount =
            chainAccounts.find((row: any) => String(row.chainIdKey || '').startsWith('near:')) ||
            null;
          if (!nearAccount) return null;
          return {
            nearAccountId: nearAccount.accountAddress,
            deviceNumber: lastProfileState.deviceNumber,
          };
        };

        db.setLastUserScope(originA);
        const alice = await seedNearDevice({
          nearAccountId: 'alice.testnet',
          deviceNumber: 1,
          operationalPublicKey: 'ed25519:pk-a',
          passkeyCredential: { id: 'c-a', rawId: 'r-a' },
        });
        await db.setLastProfileStateForProfile(alice.profileId, 1);

        db.setLastUserScope(originB);
        const bob = await seedNearDevice({
          nearAccountId: 'bob.testnet',
          deviceNumber: 2,
          operationalPublicKey: 'ed25519:pk-b',
          passkeyCredential: { id: 'c-b', rawId: 'r-b' },
        });
        await db.setLastProfileStateForProfile(bob.profileId, 2);

        db.setLastUserScope(originA);
        const lastA = await getLastSelectedNearProjection();
        db.setLastUserScope(originB);
        const lastB = await getLastSelectedNearProjection();

        return {
          lastA: lastA
            ? { nearAccountId: lastA.nearAccountId, deviceNumber: lastA.deviceNumber }
            : null,
          lastB: lastB
            ? { nearAccountId: lastB.nearAccountId, deviceNumber: lastB.deviceNumber }
            : null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.lastA).toEqual({ nearAccountId: 'alice.testnet', deviceNumber: 1 });
    expect(result.lastB).toEqual({ nearAccountId: 'bob.testnet', deviceNumber: 2 });
  });

  test('scoped last-profile lookup does not fall back to unscoped last-user pointers', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);

        const db = new PasskeyClientDBManager();
        const seedNearDevice = async (input: {
          nearAccountId: string;
          deviceNumber: number;
          operationalPublicKey: string;
          passkeyCredential: { id: string; rawId: string };
        }) => {
          const accountAddress = String(input.nearAccountId || '').trim().toLowerCase();
          const chainIdKey = accountAddress.endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
          const profileId = `profile-near:${accountAddress}`;
          await db.upsertProfile({
            profileId,
            defaultDeviceNumber: input.deviceNumber,
            passkeyCredential: input.passkeyCredential,
          });
          await db.upsertChainAccount({
            profileId,
            chainIdKey,
            accountAddress,
            accountModel: 'near-native',
            isPrimary: true,
          });
          await db.upsertAccountSigner({
            profileId,
            chainIdKey,
            accountAddress,
            signerId: input.operationalPublicKey,
            signerSlot: input.deviceNumber,
            signerType: 'passkey',
            status: 'active',
            mutation: { routeThroughOutbox: false },
          });
          return { profileId };
        };
        const getLastSelectedNearProjection = async () => {
          const lastProfileState = await db.getLastProfileState().catch(() => null);
          if (!lastProfileState?.profileId) return null;
          const chainAccounts = await db.listChainAccountsByProfile(lastProfileState.profileId);
          const nearAccount =
            chainAccounts.find((row: any) => String(row.chainIdKey || '').startsWith('near:')) ||
            null;
          if (!nearAccount) return null;
          return {
            nearAccountId: nearAccount.accountAddress,
            deviceNumber: lastProfileState.deviceNumber,
          };
        };
        // Store without setting a scope (unscoped lastProfileState pointer).
        const erin = await seedNearDevice({
          nearAccountId: 'erin.testnet',
          deviceNumber: 1,
          operationalPublicKey: 'ed25519:pk-e',
          passkeyCredential: { id: 'c-e', rawId: 'r-e' },
        });
        await db.setLastProfileStateForProfile(erin.profileId, 1);

        // Scoped reads are strict: no fallback to unscoped pointers.
        db.setLastUserScope('https://app-legacy.example');
        const last = await getLastSelectedNearProjection();
        return last ? { nearAccountId: last.nearAccountId, deviceNumber: last.deviceNumber } : null;
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toBeNull();
  });
});
