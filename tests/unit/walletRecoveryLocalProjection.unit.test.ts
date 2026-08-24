import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  indexedDB: '/_test-sdk/esm/core/indexedDB/index.js',
  nearProfileId: '/_test-sdk/esm/core/accountData/near/profileId.js',
  localProjection:
    '/_test-sdk/esm/SeamsWeb/operations/authMethods/passkey/localPasskeyProjection.js',
  walletRecovery: '/_test-sdk/esm/SeamsWeb/operations/recovery/walletRecovery.js',
} as const;

const WALLET_ID = 'alice.testnet';
const RP_ID = 'wallet.example.localhost';
const NEAR_ACCOUNT_ID = 'recovery-alice.testnet';
const SOURCE_CREDENTIAL_ID_B64U = 'c291cmNl';
const REPLACEMENT_CREDENTIAL_ID_B64U = 'cmVwbGFjZW1lbnQ';

test.describe('wallet recovery local continuity', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('replaces the exact local passkey auth-method projection after durable NEAR continuity', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({
        paths,
        walletId,
        rpId,
        sourceCredentialId,
        replacementCredentialId,
        nearAccountId,
      }) => {
        const { IndexedDBManager, createSeamsTestWalletDbName, seamsWalletDB } = await import(
          paths.indexedDB
        );
        const { buildNearProfileId } = await import(paths.nearProfileId);
        const { persistRecoveredPasskeyAuthMethodProjectionV1 } = await import(
          paths.localProjection
        );
        const nearProfileId = String(buildNearProfileId(nearAccountId));
        seamsWalletDB.setDbName(
          createSeamsTestWalletDbName(`recovery_projection_${crypto.randomUUID()}`),
        );
        seamsWalletDB.setDisabled(false);

        await IndexedDBManager.upsertProfile({
          profileId: walletId,
          defaultSignerSlot: 3,
          passkeyCredential: { id: sourceCredentialId, rawId: sourceCredentialId },
        });
        await IndexedDBManager.upsertProfile({
          profileId: nearProfileId,
          defaultSignerSlot: 3,
          passkeyCredential: { id: sourceCredentialId, rawId: sourceCredentialId },
        });
        await IndexedDBManager.upsertWalletAuthMethod({
          version: 'wallet_auth_method_v1',
          kind: 'passkey',
          status: 'active',
          localStatus: 'synced',
          walletId,
          rpId,
          credentialIdB64u: sourceCredentialId,
          credentialPublicKeyB64u: 'AQID',
          counter: 0,
          createdAtMs: 1,
          updatedAtMs: 1,
        });
        await IndexedDBManager.activateAccountSigner({
          account: {
            profileId: nearProfileId,
            chainIdKey: 'near:testnet',
            accountAddress: nearAccountId,
            accountModel: 'near-native',
          },
          signer: {
            signerId: sourceCredentialId,
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            metadata: {
              walletId,
              nearAccountId,
              nearEd25519SigningKeyId: 'near-source',
            },
          },
          activationPolicy: { mode: 'fail_if_occupied', signerSlot: 3 },
          mutation: { routeThroughOutbox: false },
        });

        await persistRecoveredPasskeyAuthMethodProjectionV1({
          kind: 'near',
          walletId,
          walletAuthMethodId: 'wallet-auth-method:replacement',
          walletAuthorityId: 'wallet-authority:recovery',
          rpId,
          credentialIdB64u: replacementCredentialId,
          credentialPublicKeyB64u: 'BAUG',
          counter: 0,
          credential: { id: replacementCredentialId, rawId: replacementCredentialId },
        });

        const profile = await IndexedDBManager.getProfile(walletId);
        const nearProfile = await IndexedDBManager.getProfile(nearProfileId);
        const authenticators = await IndexedDBManager.listProfileAuthenticators(walletId);
        const methods = await IndexedDBManager.listWalletAuthMethodsForWallet(walletId);
        const methodsV2 = await IndexedDBManager.listWalletAuthMethodsV2ForWallet(walletId);
        const signers = await IndexedDBManager.listAccountSignersByProfile({
          profileId: nearProfileId,
        });
        return {
          dbName: seamsWalletDB.getDbName(),
          profile,
          nearProfile,
          authenticators: authenticators.map((authenticator) => ({
            profileId: authenticator.profileId,
            signerSlot: authenticator.signerSlot,
            credentialId: authenticator.credentialId,
            credentialPublicKey: Array.from(authenticator.credentialPublicKey),
          })),
          methods: methods.map((method) => ({
            credentialIdB64u: method.kind === 'passkey' ? method.credentialIdB64u : null,
            credentialPublicKeyB64u:
              method.kind === 'passkey' ? method.credentialPublicKeyB64u : null,
            counter: method.kind === 'passkey' ? method.counter : null,
            status: method.status,
          })),
          methodsV2: methodsV2.map((method) => ({
            walletAuthMethodId: method.walletAuthMethodId,
            walletAuthorityId: method.walletAuthorityId,
            credentialIdB64u: method.kind === 'passkey' ? method.credentialIdB64u : null,
            status: method.status,
          })),
          signers: signers.map((signer) => ({
            signerId: signer.signerId,
            signerSlot: signer.signerSlot,
            status: signer.status,
          })),
        };
      },
      {
        paths: IMPORT_PATHS,
        walletId: WALLET_ID,
        rpId: RP_ID,
        sourceCredentialId: SOURCE_CREDENTIAL_ID_B64U,
        replacementCredentialId: REPLACEMENT_CREDENTIAL_ID_B64U,
        nearAccountId: NEAR_ACCOUNT_ID,
      },
    );

    expect(result.dbName).toMatch(/^seams_test_wallet_/);
    expect(result.profile).toMatchObject({
      profileId: WALLET_ID,
      defaultSignerSlot: 3,
      passkeyCredential: {
        id: SOURCE_CREDENTIAL_ID_B64U,
        rawId: SOURCE_CREDENTIAL_ID_B64U,
      },
    });
    expect(result.nearProfile).toMatchObject({
      profileId: `near-profile:${NEAR_ACCOUNT_ID}`,
      defaultSignerSlot: 3,
      passkeyCredential: {
        id: SOURCE_CREDENTIAL_ID_B64U,
        rawId: SOURCE_CREDENTIAL_ID_B64U,
      },
    });
    expect(result.authenticators).toHaveLength(1);
    expect(result.authenticators[0]).toMatchObject({
      profileId: WALLET_ID,
      signerSlot: 3,
      credentialId: REPLACEMENT_CREDENTIAL_ID_B64U,
      credentialPublicKey: [4, 5, 6],
    });
    expect(result.methods).toEqual(
      expect.arrayContaining([
        {
          credentialIdB64u: SOURCE_CREDENTIAL_ID_B64U,
          credentialPublicKeyB64u: 'AQID',
          counter: 0,
          status: 'revoked',
        },
        {
          credentialIdB64u: REPLACEMENT_CREDENTIAL_ID_B64U,
          credentialPublicKeyB64u: 'BAUG',
          counter: 0,
          status: 'active',
        },
      ]),
    );
    expect(result.methodsV2).toEqual([
      {
        walletAuthMethodId: 'wallet-auth-method:replacement',
        walletAuthorityId: 'wallet-authority:recovery',
        credentialIdB64u: REPLACEMENT_CREDENTIAL_ID_B64U,
        status: 'active',
      },
    ]);
    expect(result.signers).toEqual(
      expect.arrayContaining([
        { signerId: SOURCE_CREDENTIAL_ID_B64U, signerSlot: 3, status: 'active' },
      ]),
    );
  });

  test('reuses the same reservation after a retryable prepare conflict', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { WalletRecoveryCoordinator } = await import(paths.walletRecovery);
        const requestBodies: Array<{ reservationId?: string }> = [];
        const originalFetch = globalThis.fetch;
        globalThis.fetch = async (_input, init) => {
          const body = JSON.parse(String(init?.body || '{}')) as { reservationId?: string };
          requestBodies.push(body);
          return new Response('{}', { status: 409 });
        };
        try {
          const coordinator = new WalletRecoveryCoordinator();
          const context = {
            signingEngine: { getRpId: () => 'wallet.example.localhost' },
          } as never;
          const first = await coordinator.prepareWithCode({
            context,
            relayUrl: 'https://relay.example.test',
            recoveryCode: 'ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345-6789',
            signal: new AbortController().signal,
          });
          const second = await coordinator.prepareWithCode({
            context,
            relayUrl: 'https://relay.example.test',
            recoveryCode: 'ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345-6789',
            signal: new AbortController().signal,
          });
          return {
            first,
            second,
            reservationIds: requestBodies.map((body) => body.reservationId || ''),
          };
        } finally {
          globalThis.fetch = originalFetch;
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.first).toEqual({ kind: 'retryable_conflict' });
    expect(result.second).toEqual({ kind: 'retryable_conflict' });
    expect(result.reservationIds).toHaveLength(2);
    expect(result.reservationIds[0]).toBeTruthy();
    expect(result.reservationIds[0]).toBe(result.reservationIds[1]);
  });

  test('creates the ECDSA-only wallet projection on a fresh browser', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths, walletId, rpId, replacementCredentialId }) => {
        const { IndexedDBManager, createSeamsTestWalletDbName, seamsWalletDB } = await import(
          paths.indexedDB
        );
        const { persistRecoveredPasskeyAuthMethodProjectionV1 } = await import(
          paths.localProjection
        );
        seamsWalletDB.setDbName(
          createSeamsTestWalletDbName(`recovery_wallet_only_${crypto.randomUUID()}`),
        );
        seamsWalletDB.setDisabled(false);

        await persistRecoveredPasskeyAuthMethodProjectionV1({
          kind: 'wallet_only',
          walletId,
          walletAuthMethodId: 'wallet-auth-method:replacement',
          walletAuthorityId: 'wallet-authority:recovery',
          signerSlot: 1,
          rpId,
          credentialIdB64u: replacementCredentialId,
          credentialPublicKeyB64u: 'BAUG',
          counter: 0,
          credential: { id: replacementCredentialId, rawId: replacementCredentialId },
        });

        const profile = await IndexedDBManager.getProfile(walletId);
        const authenticators = await IndexedDBManager.listProfileAuthenticators(walletId);
        const methods = await IndexedDBManager.listWalletAuthMethodsForWallet(walletId);
        const methodsV2 = await IndexedDBManager.listWalletAuthMethodsV2ForWallet(walletId);
        return {
          profile,
          authenticators: authenticators.map((authenticator) => ({
            profileId: authenticator.profileId,
            signerSlot: authenticator.signerSlot,
            credentialId: authenticator.credentialId,
            credentialPublicKey: Array.from(authenticator.credentialPublicKey),
          })),
          methods: methods.map((method) => ({
            credentialIdB64u: method.kind === 'passkey' ? method.credentialIdB64u : null,
            credentialPublicKeyB64u:
              method.kind === 'passkey' ? method.credentialPublicKeyB64u : null,
            counter: method.kind === 'passkey' ? method.counter : null,
            status: method.status,
          })),
          methodsV2: methodsV2.map((method) => ({
            walletAuthMethodId: method.walletAuthMethodId,
            walletAuthorityId: method.walletAuthorityId,
            credentialIdB64u: method.kind === 'passkey' ? method.credentialIdB64u : null,
            status: method.status,
          })),
        };
      },
      {
        paths: IMPORT_PATHS,
        walletId: WALLET_ID,
        rpId: RP_ID,
        replacementCredentialId: REPLACEMENT_CREDENTIAL_ID_B64U,
      },
    );

    expect(result.profile).toMatchObject({
      profileId: WALLET_ID,
      defaultSignerSlot: 1,
      passkeyCredential: {
        id: REPLACEMENT_CREDENTIAL_ID_B64U,
        rawId: REPLACEMENT_CREDENTIAL_ID_B64U,
      },
    });
    expect(result.authenticators).toHaveLength(1);
    expect(result.authenticators[0]).toMatchObject({
      profileId: WALLET_ID,
      signerSlot: 1,
      credentialId: REPLACEMENT_CREDENTIAL_ID_B64U,
      credentialPublicKey: [4, 5, 6],
    });
    expect(result.methods).toEqual([
      {
        credentialIdB64u: REPLACEMENT_CREDENTIAL_ID_B64U,
        credentialPublicKeyB64u: 'BAUG',
        counter: 0,
        status: 'active',
      },
    ]);
    expect(result.methodsV2).toEqual([
      {
        walletAuthMethodId: 'wallet-auth-method:replacement',
        walletAuthorityId: 'wallet-authority:recovery',
        credentialIdB64u: REPLACEMENT_CREDENTIAL_ID_B64U,
        status: 'active',
      },
    ]);
  });
});
