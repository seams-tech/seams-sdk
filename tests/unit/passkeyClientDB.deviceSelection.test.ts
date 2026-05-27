import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  clientDB: '/sdk/esm/core/indexedDB/passkeyClientDB/manager.js',
  accountKeyMaterialDB: '/sdk/esm/core/indexedDB/accountKeyMaterialDB/manager.js',
  nearKeyMaterial: '/sdk/esm/core/accountData/near/keyMaterial.js',
  signerSlot: '/sdk/esm/core/signingEngine/webauthnAuth/device/signerSlot.js',
} as const;

test.describe('PasskeyClientDB device selection', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('getLastLoggedInSignerSlot does not fall back to another account', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { getLastLoggedInSignerSlot } = await import(paths.signerSlot);

        const db = new PasskeyClientDBManager();
        const seedNearSigner = async (input: {
          nearAccountId: string;
          signerSlot: number;
          operationalPublicKey: string;
          passkeyCredential: { id: string; rawId: string };
        }) => {
          const accountAddress = String(input.nearAccountId || '')
            .trim()
            .toLowerCase();
          const chainIdKey = accountAddress.endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
          const profileId = `profile-near:${accountAddress}`;
          await db.upsertProfile({
            profileId,
            defaultSignerSlot: input.signerSlot,
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
            signerSlot: input.signerSlot,
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            status: 'active',
            mutation: { routeThroughOutbox: false },
          });
          return { profileId, chainIdKey, accountAddress };
        };
        // Store a different account in DB (this will set lastUser to bob)
        await seedNearSigner({
          nearAccountId: 'bob.testnet',
          signerSlot: 2,
          operationalPublicKey: 'ed25519:pkbob',
          passkeyCredential: { id: 'c-bob', rawId: 'r-bob' },
        });
        const alice = await seedNearSigner({
          nearAccountId: 'alice.testnet',
          signerSlot: 1,
          operationalPublicKey: 'ed25519:pkalice',
          passkeyCredential: { id: 'c-alice', rawId: 'r-alice' },
        });
        // Point lastUser back to a different account so bob has no last-user session
        await db.setLastProfileStateForProfile(alice.profileId, 1);

        try {
          await getLastLoggedInSignerSlot('bob.testnet', db);
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
        const seedNearSigner = async (input: {
          nearAccountId: string;
          signerSlot: number;
          operationalPublicKey: string;
          passkeyCredential: { id: string; rawId: string };
        }) => {
          const accountAddress = String(input.nearAccountId || '')
            .trim()
            .toLowerCase();
          const chainIdKey = accountAddress.endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
          const profileId = `profile-near:${accountAddress}`;
          await db.upsertProfile({
            profileId,
            defaultSignerSlot: input.signerSlot,
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
            signerSlot: input.signerSlot,
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            status: 'active',
            mutation: { routeThroughOutbox: false },
          });
          return { profileId, chainIdKey, accountAddress };
        };
        // Store user records for both devices
        const context = await seedNearSigner({
          nearAccountId: 'carol.testnet',
          signerSlot: 3,
          operationalPublicKey: 'ed25519:pk-3',
          passkeyCredential: { id: 'c-3', rawId: 'r-3' },
        });
        await seedNearSigner({
          nearAccountId: 'carol.testnet',
          signerSlot: 6,
          operationalPublicKey: 'ed25519:pk-6',
          passkeyCredential: { id: 'c-6', rawId: 'r-6' },
        });
        // Last logged-in device is 6
        await db.setLastProfileStateForProfile(context.profileId, 6);

        const authenticators = [
          {
            credentialId: 'cred-old',
            credentialPublicKey: new Uint8Array([1]),
            signerSlot: 3,
            nearAccountId: 'carol.testnet',
            registered: '',
            syncedAt: '',
          },
          {
            credentialId: 'cred-new',
            credentialPublicKey: new Uint8Array([2]),
            signerSlot: 6,
            nearAccountId: 'carol.testnet',
            registered: '',
            syncedAt: '',
          },
        ];

        const projected = authenticators.map((auth: any) => ({
          profileId: context.profileId,
          signerSlot: auth.signerSlot,
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

  test('setLastProfileStateForProfile pins signerSlot when multiple entries exist', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { getLastLoggedInSignerSlot } = await import(paths.signerSlot);

        const db = new PasskeyClientDBManager();
        const seedNearSigner = async (input: {
          nearAccountId: string;
          signerSlot: number;
          operationalPublicKey: string;
          passkeyCredential: { id: string; rawId: string };
          lastUpdated?: number;
        }) => {
          const accountAddress = String(input.nearAccountId || '')
            .trim()
            .toLowerCase();
          const chainIdKey = accountAddress.endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
          const profileId = `profile-near:${accountAddress}`;
          await db.upsertProfile({
            profileId,
            defaultSignerSlot: input.signerSlot,
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
            signerSlot: input.signerSlot,
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
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
            signerSlot: lastProfileState.activeSignerSlot,
          };
        };

        // Insert two devices for the same account
        const context = await seedNearSigner({
          nearAccountId: 'dana.testnet',
          signerSlot: 3,
          operationalPublicKey: 'ed25519:pk-3',
          passkeyCredential: { id: 'c-3', rawId: 'r-3' },
          lastUpdated: 1000,
        });
        await seedNearSigner({
          nearAccountId: 'dana.testnet',
          signerSlot: 6,
          operationalPublicKey: 'ed25519:pk-6',
          passkeyCredential: { id: 'c-6', rawId: 'r-6' },
          lastUpdated: 2000,
        });

        // Simulate login selecting device 6
        await db.setLastProfileStateForProfile(context.profileId, 6);

        const last = await getLastSelectedNearProjection();
        const signerSlotFromHelper = await getLastLoggedInSignerSlot('dana.testnet', db);
        const projected = [
          {
            credentialId: 'c-3',
            credentialPublicKey: new Uint8Array([1]),
            signerSlot: 3,
            nearAccountId: 'dana.testnet',
            registered: '',
            syncedAt: '',
          },
          {
            credentialId: 'c-6',
            credentialPublicKey: new Uint8Array([2]),
            signerSlot: 6,
            nearAccountId: 'dana.testnet',
            registered: '',
            syncedAt: '',
          },
        ].map((auth: any) => ({
          profileId: context.profileId,
          signerSlot: auth.signerSlot,
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
          lastSignerSlot: last?.signerSlot,
          helperSignerSlot: signerSlotFromHelper,
          filteredIds: authenticatorsForPrompt.map((a: any) => a.credentialId),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.lastSignerSlot).toBe(6);
    expect(result.helperSignerSlot).toBe(6);
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
        const seedNearSigner = async (input: {
          nearAccountId: string;
          signerSlot: number;
          operationalPublicKey: string;
          passkeyCredential: { id: string; rawId: string };
        }) => {
          const accountAddress = String(input.nearAccountId || '')
            .trim()
            .toLowerCase();
          const chainIdKey = accountAddress.endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
          const profileId = `profile-near:${accountAddress}`;
          await db.upsertProfile({
            profileId,
            defaultSignerSlot: input.signerSlot,
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
            signerSlot: input.signerSlot,
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
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
            signerSlot: lastProfileState.activeSignerSlot,
          };
        };

        db.setLastUserScope(originA);
        const alice = await seedNearSigner({
          nearAccountId: 'alice.testnet',
          signerSlot: 1,
          operationalPublicKey: 'ed25519:pk-a',
          passkeyCredential: { id: 'c-a', rawId: 'r-a' },
        });
        await db.setLastProfileStateForProfile(alice.profileId, 1);

        db.setLastUserScope(originB);
        const bob = await seedNearSigner({
          nearAccountId: 'bob.testnet',
          signerSlot: 2,
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
            ? { nearAccountId: lastA.nearAccountId, signerSlot: lastA.signerSlot }
            : null,
          lastB: lastB
            ? { nearAccountId: lastB.nearAccountId, signerSlot: lastB.signerSlot }
            : null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.lastA).toEqual({ nearAccountId: 'alice.testnet', signerSlot: 1 });
    expect(result.lastB).toEqual({ nearAccountId: 'bob.testnet', signerSlot: 2 });
  });

  test('scoped last-profile lookup does not fall back to unscoped last-user pointers', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);

        const db = new PasskeyClientDBManager();
        const seedNearSigner = async (input: {
          nearAccountId: string;
          signerSlot: number;
          operationalPublicKey: string;
          passkeyCredential: { id: string; rawId: string };
        }) => {
          const accountAddress = String(input.nearAccountId || '')
            .trim()
            .toLowerCase();
          const chainIdKey = accountAddress.endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
          const profileId = `profile-near:${accountAddress}`;
          await db.upsertProfile({
            profileId,
            defaultSignerSlot: input.signerSlot,
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
            signerSlot: input.signerSlot,
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
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
            signerSlot: lastProfileState.activeSignerSlot,
          };
        };
        // Store without setting a scope (unscoped lastProfileState pointer).
        const erin = await seedNearSigner({
          nearAccountId: 'erin.testnet',
          signerSlot: 1,
          operationalPublicKey: 'ed25519:pk-e',
          passkeyCredential: { id: 'c-e', rawId: 'r-e' },
        });
        await db.setLastProfileStateForProfile(erin.profileId, 1);

        // Scoped reads are strict: no fallback to unscoped pointers.
        db.setLastUserScope('https://app-legacy.example');
        const last = await getLastSelectedNearProjection();
        return last ? { nearAccountId: last.nearAccountId, signerSlot: last.signerSlot } : null;
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toBeNull();
  });

  test('activateAccountSigner rejects duplicate same-kind registration without replacing signers', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);

        const db = new PasskeyClientDBManager();
        const profileId = 'profile-near:slot-replace.testnet';
        const chainIdKey = 'near:testnet';
        const accountAddress = 'slot-replace.testnet';
        await db.upsertProfile({ profileId, defaultSignerSlot: 1 });
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
          signerId: 'threshold-ed25519:old',
          signerSlot: 1,
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'email_otp',
          signerSource: 'email_otp_registration',
          status: 'active',
          mutation: { routeThroughOutbox: false },
        });
        await db.setLastProfileStateForProfile(profileId, 1);

        let errorCode = '';
        try {
          await db.activateAccountSigner({
            account: {
              profileId,
              chainIdKey,
              accountAddress,
              accountModel: 'near-native',
            },
            signer: {
              signerId: 'threshold-ed25519:new',
              signerType: 'threshold',
              signerKind: 'threshold-ed25519',
              signerAuthMethod: 'email_otp',
              signerSource: 'email_otp_registration',
              metadata: { relayerKeyId: 'new', source: 'email_otp' },
            },
            activationPolicy: {
              mode: 'reuse_existing',
              signerId: 'threshold-ed25519:new',
              materialFingerprint: 'new-material',
            },
            mutation: { routeThroughOutbox: false },
          });
        } catch (e: any) {
          errorCode = String(e?.code || '');
        }

        const oldSigner = await db.getAccountSigner({
          chainIdKey,
          accountAddress,
          signerId: 'threshold-ed25519:old',
        });
        const newSigner = await db.getAccountSigner({
          chainIdKey,
          accountAddress,
          signerId: 'threshold-ed25519:new',
        });
        const lastProfileState = await db.getLastProfileState();
        const activeSigners = await db.listAccountSigners({
          chainIdKey,
          accountAddress,
          status: 'active',
        });

        return {
          errorCode,
          oldSigner: {
            status: oldSigner?.status,
            signerSlot: oldSigner?.signerSlot,
            revocationReason: oldSigner?.revocationReason,
            removedAtType: typeof oldSigner?.removedAt,
          },
          newSigner: {
            status: newSigner?.status,
            signerSlot: newSigner?.signerSlot,
            signerKind: newSigner?.signerKind,
            signerSource: newSigner?.signerSource,
          },
          lastProfileState: {
            profileId: lastProfileState?.profileId,
            activeSignerSlot: lastProfileState?.activeSignerSlot,
          },
          activeSignerIds: activeSigners.map((signer: any) => signer.signerId),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.errorCode).toBe('signer_lifecycle_duplicate_registration');
    expect(result.oldSigner).toEqual({
      status: 'active',
      signerSlot: 1,
      revocationReason: undefined,
      removedAtType: 'undefined',
    });
    expect(result.newSigner).toEqual({
      status: undefined,
      signerSlot: undefined,
      signerKind: undefined,
      signerSource: undefined,
    });
    expect(result.lastProfileState).toEqual({
      profileId: 'profile-near:slot-replace.testnet',
      activeSignerSlot: 1,
    });
    expect(result.activeSignerIds).toEqual(['threshold-ed25519:old']);
  });

  test('activateAccountSigner allocates the next free slot for explicit new signer material', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);

        const db = new PasskeyClientDBManager();
        const profileId = 'profile-near:slot-preserve.testnet';
        const chainIdKey = 'near:testnet';
        const accountAddress = 'slot-preserve.testnet';
        await db.upsertProfile({
          profileId,
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-passkey', rawId: 'raw-passkey' },
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
          signerId: 'ed25519:passkey',
          signerSlot: 1,
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
          status: 'active',
          mutation: { routeThroughOutbox: false },
        });

        const activation = await db.activateAccountSigner({
          account: {
            profileId,
            chainIdKey,
            accountAddress,
            accountModel: 'near-native',
          },
          signer: {
            signerId: 'threshold-ed25519:email',
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'email_otp',
            signerSource: 'email_otp_registration',
          },
          activationPolicy: {
            mode: 'allocate_next_free',
          },
          mutation: { routeThroughOutbox: false },
        });

        const activeSigners = await db.listAccountSigners({
          chainIdKey,
          accountAddress,
          status: 'active',
        });
        const lastProfileState = await db.getLastProfileState();

        return {
          activation: {
            signerSlot: activation.signerSlot,
          },
          activeSigners: activeSigners
            .map((signer: any) => ({
              signerId: signer.signerId,
              signerSlot: signer.signerSlot,
              signerKind: signer.signerKind,
            }))
            .sort((a: any, b: any) => a.signerSlot - b.signerSlot),
          lastProfileState: {
            profileId: lastProfileState?.profileId,
            activeSignerSlot: lastProfileState?.activeSignerSlot,
          },
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.activation).toEqual({
      signerSlot: 2,
    });
    expect(result.activeSigners).toEqual([
      { signerId: 'ed25519:passkey', signerSlot: 1, signerKind: 'threshold-ed25519' },
      {
        signerId: 'threshold-ed25519:email',
        signerSlot: 2,
        signerKind: 'threshold-ed25519',
      },
    ]);
    expect(result.lastProfileState).toEqual({
      profileId: 'profile-near:slot-preserve.testnet',
      activeSignerSlot: 2,
    });
  });

  test('activateAccountSigner can defer active slot cutover', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);

        const db = new PasskeyClientDBManager();
        const profileId = 'profile-near:slot-cutover.testnet';
        const chainIdKey = 'near:testnet';
        const accountAddress = 'slot-cutover.testnet';
        await db.upsertProfile({ profileId, defaultSignerSlot: 1 });
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
          signerId: 'threshold-ed25519:current',
          signerSlot: 1,
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
          status: 'active',
          mutation: { routeThroughOutbox: false },
        });
        await db.setLastProfileStateForProfile(profileId, 1);

        const activation = await db.activateAccountSigner({
          account: {
            profileId,
            chainIdKey,
            accountAddress,
            accountModel: 'near-native',
          },
          signer: {
            signerId: 'threshold-ed25519:rotation-candidate',
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'email_otp',
            signerSource: 'email_otp_registration',
          },
          activationPolicy: {
            mode: 'allocate_next_free',
          },
          selectAsActive: false,
          mutation: { routeThroughOutbox: false },
        });

        const activeSigners = await db.listAccountSigners({
          chainIdKey,
          accountAddress,
          status: 'active',
        });
        const lastProfileState = await db.getLastProfileState();

        return {
          activation: { signerSlot: activation.signerSlot },
          activeSigners: activeSigners
            .map((signer: any) => ({
              signerId: signer.signerId,
              signerSlot: signer.signerSlot,
            }))
            .sort((a: any, b: any) => a.signerSlot - b.signerSlot),
          lastProfileState: {
            profileId: lastProfileState?.profileId,
            activeSignerSlot: lastProfileState?.activeSignerSlot,
          },
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      activation: { signerSlot: 2 },
      activeSigners: [
        { signerId: 'threshold-ed25519:current', signerSlot: 1 },
        { signerId: 'threshold-ed25519:rotation-candidate', signerSlot: 2 },
      ],
      lastProfileState: {
        profileId: 'profile-near:slot-cutover.testnet',
        activeSignerSlot: 1,
      },
    });
  });

  test('activateAccountSigner same-signer retry is idempotent', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);

        const db = new PasskeyClientDBManager();
        const profileId = 'profile-near:slot-idempotent.testnet';
        const chainIdKey = 'near:testnet';
        const accountAddress = 'slot-idempotent.testnet';
        const activate = (label: string) =>
          db.activateAccountSigner({
            account: {
              profileId,
              chainIdKey,
              accountAddress,
              accountModel: 'near-native',
            },
            signer: {
              signerId: 'threshold-ed25519:same',
              signerType: 'threshold',
              signerKind: 'threshold-ed25519',
              signerAuthMethod: 'email_otp',
              signerSource: 'email_otp_registration',
              metadata: { label, signerMaterialFingerprint: 'same-material' },
            },
            activationPolicy: {
              mode: 'reuse_existing',
              signerId: 'threshold-ed25519:same',
              materialFingerprint: 'same-material',
            },
            mutation: { routeThroughOutbox: false },
          });

        await db.upsertProfile({ profileId, defaultSignerSlot: 1 });
        const first = await activate('first');
        const second = await activate('second');

        const activeSigners = await db.listAccountSigners({
          chainIdKey,
          accountAddress,
          status: 'active',
        });
        const signer = await db.getAccountSigner({
          chainIdKey,
          accountAddress,
          signerId: 'threshold-ed25519:same',
        });

        return {
          first: {
            signerSlot: first.signerSlot,
          },
          second: {
            signerSlot: second.signerSlot,
          },
          activeSignerCount: activeSigners.length,
          signerMetadata: signer?.metadata,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      first: {
        signerSlot: 1,
      },
      second: {
        signerSlot: 1,
      },
      activeSignerCount: 1,
      signerMetadata: { label: 'second', signerMaterialFingerprint: 'same-material' },
    });
  });

  test('activateAccountSigner rejects same signer retry with different material', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);

        const db = new PasskeyClientDBManager();
        const profileId = 'profile-near:slot-material-mismatch.testnet';
        const chainIdKey = 'near:testnet';
        const accountAddress = 'slot-material-mismatch.testnet';
        const signerId = 'threshold-ed25519:same-material-id';

        await db.upsertProfile({ profileId, defaultSignerSlot: 1 });
        const first = await db.activateAccountSigner({
          account: {
            profileId,
            chainIdKey,
            accountAddress,
            accountModel: 'near-native',
          },
          signer: {
            signerId,
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'email_otp',
            signerSource: 'email_otp_registration',
            metadata: {
              operationalPublicKey: 'ed25519:first',
              signerMaterialFingerprint: 'first-material',
            },
          },
          activationPolicy: {
            mode: 'reuse_existing',
            signerId,
            materialFingerprint: 'first-material',
          },
          mutation: { routeThroughOutbox: false },
        });

        let errorCode = '';
        try {
          await db.activateAccountSigner({
            account: {
              profileId,
              chainIdKey,
              accountAddress,
              accountModel: 'near-native',
            },
            signer: {
              signerId,
              signerType: 'threshold',
              signerKind: 'threshold-ed25519',
              signerAuthMethod: 'email_otp',
              signerSource: 'email_otp_registration',
              metadata: {
                operationalPublicKey: 'ed25519:second',
                signerMaterialFingerprint: 'second-material',
              },
            },
            activationPolicy: {
              mode: 'reuse_existing',
              signerId,
              materialFingerprint: 'second-material',
            },
            mutation: { routeThroughOutbox: false },
          });
        } catch (e: any) {
          errorCode = String(e?.code || '');
        }

        const signer = await db.getAccountSigner({ chainIdKey, accountAddress, signerId });
        const activeSigners = await db.listAccountSigners({
          chainIdKey,
          accountAddress,
          status: 'active',
        });

        return {
          first: { signerSlot: first.signerSlot },
          errorCode,
          signerMetadata: signer?.metadata,
          activeSignerCount: activeSigners.length,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.first).toEqual({ signerSlot: 1 });
    expect(result.errorCode).toBe('signer_lifecycle_material_mismatch');
    expect(result.signerMetadata).toEqual({
      operationalPublicKey: 'ed25519:first',
      signerMaterialFingerprint: 'first-material',
    });
    expect(result.activeSignerCount).toBe(1);
  });

  test('Email OTP threshold Ed25519 retry repairs missing key material after activation', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { AccountKeyMaterialDBManager } = await import(paths.accountKeyMaterialDB);
        const { getNearThresholdKeyMaterial, storeNearThresholdKeyMaterial } = await import(
          paths.nearKeyMaterial
        );

        const suffix = crypto.randomUUID();
        const db = new PasskeyClientDBManager();
        db.setDbName(`PasskeyClientDB-partial-activation-${suffix}`);
        const accountKeyMaterialDB = new AccountKeyMaterialDBManager();
        accountKeyMaterialDB.setDbName(`PasskeyAccountKeyMaterial-partial-activation-${suffix}`);

        const profileId = 'profile-near:partial-activation.testnet';
        const chainIdKey = 'near:testnet';
        const accountAddress = 'partial-activation.testnet';
        const signerId = 'threshold-ed25519:partial-rk';
        await db.upsertProfile({ profileId, defaultSignerSlot: 1 });
        await db.upsertChainAccount({
          profileId,
          chainIdKey,
          accountAddress,
          accountModel: 'near-native',
          isPrimary: true,
        });

        const activate = (label: string) =>
          db.activateAccountSigner({
            account: {
              profileId,
              chainIdKey,
              accountAddress,
              accountModel: 'near-native',
            },
            signer: {
              signerId,
              signerType: 'threshold',
              signerKind: 'threshold-ed25519',
              signerAuthMethod: 'email_otp',
              signerSource: 'email_otp_registration',
              metadata: {
                label,
                relayerKeyId: 'partial-rk',
                keyVersion: 'threshold-ed25519-hss-v1',
                signerMaterialFingerprint: 'partial-material',
              },
            },
            activationPolicy: {
              mode: 'reuse_existing',
              signerId,
              materialFingerprint: 'partial-material',
            },
            mutation: { routeThroughOutbox: false },
          });

        const first = await activate('before-key-material-write');
        const missingBeforeRetry = await getNearThresholdKeyMaterial(
          { clientDB: db, accountKeyMaterialDB },
          accountAddress,
          first.signerSlot,
        );

        const second = await activate('retry-repairs-key-material');
        await storeNearThresholdKeyMaterial(
          { clientDB: db, accountKeyMaterialDB },
          {
            nearAccountId: accountAddress,
            signerSlot: second.signerSlot,
            publicKey: 'ed25519:partial-public-key',
            relayerKeyId: 'partial-rk',
            keyVersion: 'threshold-ed25519-hss-v1',
            timestamp: Date.now(),
          },
        );

        const materialAfterRetry = await getNearThresholdKeyMaterial(
          { clientDB: db, accountKeyMaterialDB },
          accountAddress,
          second.signerSlot,
        );
        const activeSigners = await db.listAccountSigners({
          chainIdKey,
          accountAddress,
          status: 'active',
        });
        const signer = await db.getAccountSigner({ chainIdKey, accountAddress, signerId });

        return {
          first: {
            signerSlot: first.signerSlot,
          },
          second: {
            signerSlot: second.signerSlot,
          },
          missingBeforeRetry,
          materialAfterRetry,
          activeSignerCount: activeSigners.length,
          signerMetadata: signer?.metadata,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.first).toEqual({
      signerSlot: 1,
    });
    expect(result.second).toEqual({
      signerSlot: 1,
    });
    expect(result.missingBeforeRetry).toBeNull();
    expect(result.activeSignerCount).toBe(1);
    expect(result.signerMetadata).toMatchObject({ label: 'retry-repairs-key-material' });
    expect(result.materialAfterRetry).toMatchObject({
      publicKey: 'ed25519:partial-public-key',
      relayerKeyId: 'partial-rk',
      keyVersion: 'threshold-ed25519-hss-v1',
    });
  });

  test('Email OTP threshold Ed25519 retry after local material write does not collide', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);
        const { AccountKeyMaterialDBManager } = await import(paths.accountKeyMaterialDB);
        const { getNearThresholdKeyMaterial, storeNearThresholdKeyMaterial } = await import(
          paths.nearKeyMaterial
        );

        const suffix = crypto.randomUUID();
        const db = new PasskeyClientDBManager();
        db.setDbName(`PasskeyClientDB-partial-session-${suffix}`);
        const accountKeyMaterialDB = new AccountKeyMaterialDBManager();
        accountKeyMaterialDB.setDbName(`PasskeyAccountKeyMaterial-partial-session-${suffix}`);

        const profileId = 'profile-near:partial-session.testnet';
        const chainIdKey = 'near:testnet';
        const accountAddress = 'partial-session.testnet';
        const signerId = 'threshold-ed25519:session-rk';
        await db.upsertProfile({ profileId, defaultSignerSlot: 1 });
        await db.upsertChainAccount({
          profileId,
          chainIdKey,
          accountAddress,
          accountModel: 'near-native',
          isPrimary: true,
        });

        const activate = (label: string) =>
          db.activateAccountSigner({
            account: {
              profileId,
              chainIdKey,
              accountAddress,
              accountModel: 'near-native',
            },
            signer: {
              signerId,
              signerType: 'threshold',
              signerKind: 'threshold-ed25519',
              signerAuthMethod: 'email_otp',
              signerSource: 'email_otp_registration',
              metadata: {
                label,
                relayerKeyId: 'session-rk',
                keyVersion: 'threshold-ed25519-hss-v1',
                signerMaterialFingerprint: 'session-material',
              },
            },
            activationPolicy: {
              mode: 'reuse_existing',
              signerId,
              materialFingerprint: 'session-material',
            },
            mutation: { routeThroughOutbox: false },
          });

        const first = await activate('before-session-mint-failure');
        await storeNearThresholdKeyMaterial(
          { clientDB: db, accountKeyMaterialDB },
          {
            nearAccountId: accountAddress,
            signerSlot: first.signerSlot,
            publicKey: 'ed25519:session-public-key',
            relayerKeyId: 'session-rk',
            keyVersion: 'threshold-ed25519-hss-v1',
            timestamp: Date.now(),
          },
        );

        const second = await activate('retry-after-session-mint-failure');
        await storeNearThresholdKeyMaterial(
          { clientDB: db, accountKeyMaterialDB },
          {
            nearAccountId: accountAddress,
            signerSlot: second.signerSlot,
            publicKey: 'ed25519:session-public-key',
            relayerKeyId: 'session-rk',
            keyVersion: 'threshold-ed25519-hss-v1',
            timestamp: Date.now(),
          },
        );

        const activeSigners = await db.listAccountSigners({
          chainIdKey,
          accountAddress,
          status: 'active',
        });
        const material = await getNearThresholdKeyMaterial(
          { clientDB: db, accountKeyMaterialDB },
          accountAddress,
          second.signerSlot,
        );
        const lastProfileState = await db.getLastProfileState();
        const signer = await db.getAccountSigner({ chainIdKey, accountAddress, signerId });

        return {
          first: {
            signerSlot: first.signerSlot,
          },
          second: {
            signerSlot: second.signerSlot,
          },
          activeSignerCount: activeSigners.length,
          material,
          lastProfileState: {
            profileId: lastProfileState?.profileId,
            activeSignerSlot: lastProfileState?.activeSignerSlot,
          },
          signerMetadata: signer?.metadata,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.first).toEqual({
      signerSlot: 1,
    });
    expect(result.second).toEqual({
      signerSlot: 1,
    });
    expect(result.activeSignerCount).toBe(1);
    expect(result.lastProfileState).toEqual({
      profileId: 'profile-near:partial-session.testnet',
      activeSignerSlot: 1,
    });
    expect(result.signerMetadata).toMatchObject({
      label: 'retry-after-session-mint-failure',
    });
    expect(result.material).toMatchObject({
      publicKey: 'ed25519:session-public-key',
      relayerKeyId: 'session-rk',
      keyVersion: 'threshold-ed25519-hss-v1',
    });
  });

  test('stageAccountSigner writes pending signer without changing last profile state', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);

        const db = new PasskeyClientDBManager();
        const profileId = 'profile-near:slot-stage.testnet';
        const chainIdKey = 'evm:8453';
        const accountAddress = '0x2222222222222222222222222222222222222222';
        await db.upsertProfile({ profileId, defaultSignerSlot: 1 });

        const staged = await db.stageAccountSigner({
          account: {
            profileId,
            chainIdKey,
            accountAddress,
            accountModel: 'threshold-ecdsa',
          },
          signer: {
            signerId: '0x3333333333333333333333333333333333333333',
            signerSlot: 2,
            signerType: 'threshold',
            signerKind: 'threshold-ecdsa',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            metadata: { relayerKeyId: 'relayer-stage' },
          },
          mutation: { routeThroughOutbox: false },
        });

        const signer = await db.getAccountSigner({
          chainIdKey,
          accountAddress,
          signerId: '0x3333333333333333333333333333333333333333',
        });
        const lastProfileState = await db.getLastProfileState();

        return {
          staged: {
            signerSlot: staged.signerSlot,
          },
          signer: {
            status: signer?.status,
            signerSlot: signer?.signerSlot,
            signerKind: signer?.signerKind,
            signerAuthMethod: signer?.signerAuthMethod,
            signerSource: signer?.signerSource,
            metadata: signer?.metadata,
          },
          lastProfileState,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      staged: {
        signerSlot: 2,
      },
      signer: {
        status: 'pending',
        signerSlot: 2,
        signerKind: 'threshold-ecdsa',
        signerAuthMethod: 'passkey',
        signerSource: 'passkey_registration',
        metadata: { relayerKeyId: 'relayer-stage' },
      },
      lastProfileState: null,
    });
  });

  test('upsertAccountSigner rejects active signers without signerKind', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);

        const db = new PasskeyClientDBManager();
        const profileId = 'profile-near:missing-kind.testnet';
        const chainIdKey = 'near:testnet';
        const accountAddress = 'missing-kind.testnet';
        await db.upsertProfile({ profileId, defaultSignerSlot: 1 });
        await db.upsertChainAccount({
          profileId,
          chainIdKey,
          accountAddress,
          accountModel: 'near-native',
          isPrimary: true,
        });

        try {
          await db.upsertAccountSigner({
            profileId,
            chainIdKey,
            accountAddress,
            signerId: 'ed25519:missing-kind',
            signerSlot: 1,
            signerType: 'threshold',
            status: 'active',
            mutation: { routeThroughOutbox: false },
          } as any);
          return { ok: true };
        } catch (e: any) {
          return {
            ok: false,
            name: String(e?.name || ''),
            code: String(e?.code || ''),
            message: String(e?.message || ''),
          };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      ok: false,
      name: 'DBConstraintError',
      code: 'MISSING_SIGNER_KIND',
      message:
        'Active and pending account signers require signerKind, signerAuthMethod, and signerSource',
    });
  });

  test('same passkey credential can back multiple signer slots for one account', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDB);

        const db = new PasskeyClientDBManager();
        const profileId = 'profile-near:same-passkey.testnet';
        const chainIdKey = 'near:testnet';
        const accountAddress = 'same-passkey.testnet';
        const credentialId = 'shared-credential';

        await db.upsertProfile({
          profileId,
          defaultSignerSlot: 1,
          passkeyCredential: { id: credentialId, rawId: credentialId },
        });
        await db.upsertChainAccount({
          profileId,
          chainIdKey,
          accountAddress,
          accountModel: 'near-native',
          isPrimary: true,
        });

        for (const signerSlot of [1, 2]) {
          await db.upsertProfileAuthenticator({
            profileId,
            signerSlot,
            credentialId,
            credentialPublicKey: new Uint8Array([signerSlot]),
            transports: ['internal'],
            registered: new Date(1_700_000_000_000 + signerSlot).toISOString(),
            syncedAt: new Date(1_700_000_000_000 + signerSlot).toISOString(),
          });
          await db.upsertAccountSigner({
            profileId,
            chainIdKey,
            accountAddress,
            signerId: `threshold-ed25519:slot-${signerSlot}`,
            signerSlot,
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            metadata: { credentialId },
            status: 'active',
            mutation: { routeThroughOutbox: false },
          });
        }

        const authenticators = await db.listProfileAuthenticators(profileId);
        const activeSigners = await db.listAccountSigners({
          chainIdKey,
          accountAddress,
          status: 'active',
        });
        await db.setLastProfileStateForProfile(profileId, 2);
        const promptSelection = await db.selectProfileAuthenticatorsForPrompt({
          profileId,
          authenticators,
          selectedCredentialRawId: credentialId,
          accountLabel: accountAddress,
        });

        return {
          authenticators: authenticators
            .map((auth: any) => ({
              credentialId: auth.credentialId,
              signerSlot: auth.signerSlot,
            }))
            .sort((a: any, b: any) => a.signerSlot - b.signerSlot),
          activeSigners: activeSigners
            .map((signer: any) => ({
              signerId: signer.signerId,
              signerSlot: signer.signerSlot,
              credentialId: signer.metadata?.credentialId,
            }))
            .sort((a: any, b: any) => a.signerSlot - b.signerSlot),
          promptSignerSlots: promptSelection.authenticatorsForPrompt
            .map((auth: any) => auth.signerSlot)
            .sort(),
          wrongPasskeyError: promptSelection.wrongPasskeyError || null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      authenticators: [
        { credentialId: 'shared-credential', signerSlot: 1 },
        { credentialId: 'shared-credential', signerSlot: 2 },
      ],
      activeSigners: [
        {
          signerId: 'threshold-ed25519:slot-1',
          signerSlot: 1,
          credentialId: 'shared-credential',
        },
        {
          signerId: 'threshold-ed25519:slot-2',
          signerSlot: 2,
          credentialId: 'shared-credential',
        },
      ],
      promptSignerSlots: [1, 2],
      wrongPasskeyError: null,
    });
  });
});
