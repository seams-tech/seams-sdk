import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  indexedDB: '/sdk/esm/core/indexedDB/index.js',
} as const;

test.describe('Seams wallet repositories', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('persists durable nonce leases and coordination locks in seams_wallet', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.indexedDB);
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(createSeamsTestWalletDbName(`repo_nonce_${crypto.randomUUID()}`));
        const db = new UnifiedIndexedDBManager({ seamsWalletDB });

        await db.upsertNonceLaneLeaseRecord({
          v: 1,
          leaseId: 'lease-repo-test',
          laneKey: 'evm:testnet:1:0x1111111111111111111111111111111111111111',
          family: 'evm',
          chain: 'evm',
          networkKey: 'testnet',
          chainId: 1,
          sender: '0x1111111111111111111111111111111111111111',
          nonce: '1',
          state: 'reserved',
          operationId: 'op-repo-test',
          operationFingerprint: 'fp-repo-test',
          reservedAtMs: 1,
          expiresAtMs: Date.now() + 60_000,
          updatedAtMs: Date.now(),
          accountId: 'repo.testnet',
        });
        const leases = await db.readNonceLaneLeaseRecords(
          'evm:testnet:1:0x1111111111111111111111111111111111111111',
        );
        const lockResult = await db.withNonceLaneCoordinationLock(
          {
            lockKey: 'nonce-coordinator:repo-test',
            ownerId: 'repo-test-runtime',
            ttlMs: 1_000,
            waitTimeoutMs: 1_000,
          },
          async () => 'locked',
        );

        return {
          leaseCount: leases.length,
          lockResult,
          dbName: seamsWalletDB.getDbName(),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      leaseCount: 1,
      lockResult: 'locked',
      dbName: expect.stringMatching(/^seams_test_wallet_/),
    });
  });

  test('activates, normalizes, and queries signer rows', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.indexedDB);
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(createSeamsTestWalletDbName(`repo_signer_${crypto.randomUUID()}`));
        const db = new UnifiedIndexedDBManager({ seamsWalletDB });

        const profileId = 'profile-repo-account-signer';
        await db.upsertProfile({
          profileId,
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-repo', rawId: 'raw-repo' },
        });

        const activation = await db.activateAccountSigner({
          account: {
            profileId,
            chainIdKey: 'NEAR:TESTNET',
            accountAddress: 'RepoUser.TESTNET',
            accountModel: 'near-native',
          },
          signer: {
            signerId: 'ed25519:repo-signer',
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
          },
          activationPolicy: { mode: 'fail_if_occupied', signerSlot: 1 },
          mutation: { routeThroughOutbox: false },
        });
        const fetched = await db.getAccountSigner({
          chainIdKey: 'near:testnet',
          accountAddress: 'repouser.testnet',
          signerId: 'ed25519:repo-signer',
        });
        const activeRows = await db.listAccountSigners({
          chainIdKey: 'near:testnet',
          accountAddress: 'repouser.testnet',
          status: 'active',
        });

        return {
          signer: activation.signer,
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

  test('rejects active ECDSA signers missing direct keyHandle', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.indexedDB);
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(createSeamsTestWalletDbName(`repo_ecdsa_${crypto.randomUUID()}`));
        const db = new UnifiedIndexedDBManager({ seamsWalletDB });

        const profileId = 'profile-repo-ecdsa-strict-key-handle';
        await db.upsertProfile({
          profileId,
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-ecdsa-strict', rawId: 'raw-ecdsa-strict' },
        });

        try {
          await db.activateAccountSigner({
            account: {
              profileId,
              chainIdKey: 'eip155:978',
              accountAddress: '0x1111111111111111111111111111111111111111',
              accountModel: 'threshold-ecdsa',
            },
            signer: {
              signerId: 'threshold-ecdsa:legacy-identity-only',
              signerType: 'threshold',
              signerKind: 'threshold-ecdsa',
              signerAuthMethod: 'passkey',
              signerSource: 'passkey_registration',
              metadata: {
                ecdsaThresholdKeyId: 'ehss-legacy-id',
                signingRootId: 'project:dev',
                chainTarget: { chain: 'tempo', chainId: 978 },
              },
            },
            activationPolicy: { mode: 'fail_if_occupied', signerSlot: 1 },
            mutation: { routeThroughOutbox: false },
          });
          return { ok: true };
        } catch (error: any) {
          return {
            ok: false,
            name: String(error?.name || ''),
            code: String(error?.code || ''),
            message: String(error?.message || ''),
          };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      ok: false,
      name: 'SeamsWalletDBConstraintError',
      code: 'INVALID_SIGNER_METADATA',
      message: 'Active threshold ECDSA signer requires metadata.keyHandle',
    });
  });

  test('replaces stale ECDSA signer projection with corrected owner for the same key handle', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.indexedDB);
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(
          createSeamsTestWalletDbName(`repo_ecdsa_owner_repair_${crypto.randomUUID()}`),
        );
        const db = new UnifiedIndexedDBManager({ seamsWalletDB });

        const profileId = 'profile-repo-ecdsa-owner-repair';
        const chainTarget = { kind: 'tempo' as const, chainId: 42431, networkSlug: 'tempo-testnet' };
        const keyHandle = 'ehss-owner-repair-key';
        const ecdsaThresholdKeyId = 'ehss-owner-repair-threshold-key';
        const firstOwner = `0x${'11'.repeat(20)}`;
        const repairedOwner = `0x${'22'.repeat(20)}`;
        const activationForOwner = (ownerAddress: string) => ({
          account: {
            profileId,
            chainIdKey: 'tempo:42431',
            accountAddress: ownerAddress,
            accountModel: 'threshold-ecdsa',
          },
          signer: {
            signerId: ownerAddress,
            signerType: 'threshold',
            signerKind: 'threshold-ecdsa',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            metadata: {
              accountModel: 'threshold-ecdsa',
              thresholdOwnerAddress: ownerAddress,
              keyHandle,
              ecdsaThresholdKeyId,
              chainTarget,
            },
          },
          activationPolicy: { mode: 'allocate_next_free' as const },
          preferredSlot: 1,
          selectAsActive: false,
          mutation: { routeThroughOutbox: false },
        });

        await db.upsertProfile({
          profileId,
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-ecdsa-owner-repair', rawId: 'raw-ecdsa-owner-repair' },
        });
        await db.activateAccountSigner(activationForOwner(firstOwner));
        const repaired = await db.activateAccountSigner(activationForOwner(repairedOwner));
        const signers = await db.listAccountSignersByProfile({ profileId });

        return {
          repairedSignerId: repaired.signer.signerId,
          repairedSlot: repaired.signerSlot,
          signers: signers.map(
            (signer: {
              signerId: string;
              accountAddress: string;
              metadata?: Record<string, unknown>;
              status: string;
            }) => ({
              signerId: signer.signerId,
              accountAddress: signer.accountAddress,
              keyHandle: String(signer.metadata?.keyHandle || ''),
              ecdsaThresholdKeyId: String(signer.metadata?.ecdsaThresholdKeyId || ''),
              status: signer.status,
            }),
          ),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      repairedSignerId: `0x${'22'.repeat(20)}`,
      repairedSlot: 1,
      signers: [
        {
          signerId: `0x${'22'.repeat(20)}`,
          accountAddress: `0x${'22'.repeat(20)}`,
          keyHandle: 'ehss-owner-repair-key',
          ecdsaThresholdKeyId: 'ehss-owner-repair-threshold-key',
          status: 'active',
        },
      ],
    });
  });

  test('stores scoped last-profile state through the unified repository', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.indexedDB);
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(createSeamsTestWalletDbName(`repo_last_${crypto.randomUUID()}`));
        const db = new UnifiedIndexedDBManager({ seamsWalletDB });
        const profileId = 'profile-repo-last-state';
        await db.upsertProfile({
          profileId,
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-last-state', rawId: 'raw-last-state' },
        });
        await db.activateAccountSigner({
          account: {
            profileId,
            chainIdKey: 'near:testnet',
            accountAddress: 'last-state.testnet',
            accountModel: 'near-native',
          },
          signer: {
            signerId: 'ed25519:last-state',
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
          },
          activationPolicy: { mode: 'fail_if_occupied', signerSlot: 1 },
          mutation: { routeThroughOutbox: false },
        });

        db.setLastUserScope('https://app.example');
        await db.setLastProfileStateForProfile(profileId, 1);
        const scoped = await db.getLastProfileState();

        db.setLastUserScope('https://other.example');
        const otherScope = await db.getLastProfileState();

        return { scoped, otherScope };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      scoped: {
        profileId: 'profile-repo-last-state',
        activeSignerSlot: 1,
        scope: 'https://app.example',
      },
      otherScope: null,
    });
  });
});
