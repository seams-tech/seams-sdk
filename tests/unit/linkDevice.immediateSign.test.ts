import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, handleInfrastructureErrors } from '../setup';

const IMPORT_PATHS = {
  clientDb: '/sdk/esm/core/indexedDB/passkeyClientDB/manager.js',
  accountKeyMaterialDb: '/sdk/esm/core/indexedDB/accountKeyMaterialDB/manager.js',
  thresholdSessionStore:
    '/sdk/esm/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.js',
  signerSlot: '/sdk/esm/core/signingEngine/signers/webauthn/device/signerSlot.js',
  signTxs: '/sdk/esm/core/signingEngine/orchestration/near/transactionsFlow.js',
  signerTypes: '/sdk/esm/core/types/signer-worker.js',
  actions: '/sdk/esm/core/types/actions.js',
} as const;

test.describe('Link device → immediate sign (regression)', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('linkDevice storage leaves account immediately signable', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        try {
          const { PasskeyClientDBManager } = await import(paths.clientDb);
          const { AccountKeyMaterialDBManager } = await import(paths.accountKeyMaterialDb);
          const {
            clearAllStoredThresholdEd25519SessionRecords,
            upsertStoredThresholdEd25519SessionRecord,
          } = await import(paths.thresholdSessionStore);
          const { getLastLoggedInSignerSlot } = await import(paths.signerSlot);
          const { signTransactionsWithActions } = await import(paths.signTxs);
          const { WorkerResponseType } = await import(paths.signerTypes);
          const { ActionType } = await import(paths.actions);

          const nearAccountId = 'linkdev1.w3a-v1.testnet';
          const signerSlot = 2;
          const thresholdSessionId = 'linkdevice-regression';
          const profileId = `profile-near:${nearAccountId.toLowerCase()}`;
          const chainIdKey = nearAccountId.toLowerCase().endsWith('.testnet')
            ? 'near:testnet'
            : 'near:mainnet';

          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const clientDB = new PasskeyClientDBManager();
          clientDB.setDbName(`PasskeyClientDB-linkDeviceImmediateSign-${suffix}`);
          const accountKeyMaterialDB = new AccountKeyMaterialDBManager();
          accountKeyMaterialDB.setDbName(
            `PasskeyAccountKeyMaterial-linkDeviceImmediateSign-${suffix}`,
          );

          const storeUserData = async (userData: any) => {
            const normalizedSignerSlot =
              Number.isFinite(Number(userData?.signerSlot)) && Number(userData.signerSlot) >= 1
                ? Math.floor(Number(userData.signerSlot))
                : 1;
            await clientDB.upsertProfile({
              profileId,
              defaultSignerSlot: normalizedSignerSlot,
              passkeyCredential: userData.passkeyCredential,
            });
            await clientDB.upsertChainAccount({
              profileId,
              chainIdKey,
              accountAddress: nearAccountId,
              accountModel: 'near-native',
              isPrimary: true,
            });
            await clientDB.upsertAccountSigner({
              profileId,
              chainIdKey,
              accountAddress: nearAccountId,
              signerId:
                String(userData?.operationalPublicKey || '').trim() ||
                `signer:${normalizedSignerSlot}`,
              signerSlot: normalizedSignerSlot,
              signerType: 'threshold',
              signerKind: 'threshold-ed25519',
              signerAuthMethod: 'passkey',
              signerSource: 'passkey_registration',
              status: 'active',
              mutation: { routeThroughOutbox: false },
            });
            await clientDB.setLastProfileStateForProfile(profileId, normalizedSignerSlot);
          };

          const storeAuthenticator = async (authenticatorData: any) => {
            await clientDB.upsertProfileAuthenticator({
              profileId,
              signerSlot: authenticatorData.signerSlot ?? 1,
              credentialId: authenticatorData.credentialId,
              credentialPublicKey: authenticatorData.credentialPublicKey,
              transports: authenticatorData.transports,
              name: authenticatorData.name,
              registered: authenticatorData.registered,
              syncedAt: authenticatorData.syncedAt,
            });
          };

          const getLastSelectedNearProjection = async () => {
            const lastProfileState = await clientDB.getLastProfileState().catch(() => null);
            if (!lastProfileState?.profileId) return null;
            const chainAccounts = await clientDB.listChainAccountsByProfile(
              lastProfileState.profileId,
            );
            const nearAccount =
              chainAccounts.find((row: any) => String(row.chainIdKey || '').startsWith('near:')) ||
              null;
            if (!nearAccount) return null;
            return {
              nearAccountId: nearAccount.accountAddress,
              signerSlot: lastProfileState.activeSignerSlot,
            };
          };

          const dummyCredential = {
            id: 'cred-id',
            rawId: 'cred-rawid-b64u',
            type: 'public-key',
            authenticatorAttachment: 'platform',
            response: {
              clientDataJSON: 'clientDataJSON-b64u',
              attestationObject: 'attestationObject-b64u',
              transports: ['internal'],
            },
            clientExtensionResults: { prf: { results: { first: 'BQ', second: undefined } } },
          };

          const signingEngine: any = {
            storeUserData,
            storeAuthenticator,
            extractCosePublicKey: async () => new Uint8Array([1, 2, 3]),
          };

          const deterministicKeysResult = {
            nearPublicKey: 'ed25519:pk-device2',
            credential: dummyCredential,
          };
          const normalizedSignerSlot =
            Number.isFinite(Number(signerSlot)) && Number(signerSlot) >= 1
              ? Math.floor(Number(signerSlot))
              : 1;
          const credentialId = String(
            deterministicKeysResult.credential.rawId || deterministicKeysResult.credential.id || '',
          ).trim();
          const attestationObject = String(
            deterministicKeysResult.credential.response?.attestationObject || '',
          ).trim();
          const credentialPublicKey = await signingEngine.extractCosePublicKey(attestationObject);

          await signingEngine.storeUserData({
            nearAccountId,
            signerSlot: normalizedSignerSlot,
            operationalPublicKey: deterministicKeysResult.nearPublicKey,
            lastUpdated: Date.now(),
            passkeyCredential: {
              id: String(deterministicKeysResult.credential.id || credentialId),
              rawId: credentialId,
            },
            version: 2,
          });
          await signingEngine.storeAuthenticator({
            nearAccountId,
            credentialId,
            credentialPublicKey,
            transports: Array.isArray(deterministicKeysResult.credential.response?.transports)
              ? deterministicKeysResult.credential.response.transports
              : [],
            name: `Passkey for ${nearAccountId}`,
            registered: new Date().toISOString(),
            syncedAt: new Date().toISOString(),
            signerSlot: normalizedSignerSlot,
          });

          await accountKeyMaterialDB.storeKeyMaterial({
            profileId,
            signerSlot: normalizedSignerSlot,
            chainIdKey,
            keyKind: 'local_sk_encrypted_v1',
            algorithm: 'ed25519',
            publicKey: 'ed25519:pk-device2',
            wrapKeySalt: 'wrapKeySalt-b64u',
            payload: {
              encryptedSk: 'ciphertext-b64u',
              chacha20NonceB64u: 'nonce-b64u',
            },
            timestamp: Date.now(),
            schemaVersion: 1,
          });
          await accountKeyMaterialDB.storeKeyMaterial({
            profileId,
            signerSlot: normalizedSignerSlot,
            chainIdKey,
            keyKind: 'threshold_share_v1',
            algorithm: 'ed25519',
            publicKey: 'ed25519:pk-device2',
            payload: {
              relayerKeyId: 'rk-1',
              keyVersion: 'threshold-ed25519-hss-v1',
              participants: [
                { id: 1, role: 'client' },
                { id: 2, role: 'relayer', relayerKeyId: 'rk-1' },
              ],
            },
            timestamp: Date.now(),
            schemaVersion: 1,
          });
          clearAllStoredThresholdEd25519SessionRecords();
          upsertStoredThresholdEd25519SessionRecord({
            nearAccountId,
            rpId: 'example.localhost',
            relayerUrl: 'https://relay-server.localhost',
            relayerKeyId: 'rk-1',
            participantIds: [1, 2],
            runtimePolicyScope: { orgId: 'org-test', projectId: 'project-test', envId: 'dev' },
            xClientBaseB64u: 'cached-x-client-base',
            thresholdSessionKind: 'jwt',
            thresholdSessionId,
            thresholdSessionJwt: 'jwt-linkdevice-regression',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 9,
            source: 'manual-connect',
          });

          const last = await getLastSelectedNearProjection();
          const signerSlotFromHelper = await getLastLoggedInSignerSlot(nearAccountId, clientDB);
          const key = await accountKeyMaterialDB.getKeyMaterial(
            profileId,
            signerSlotFromHelper,
            chainIdKey,
            'local_sk_encrypted_v1',
          );
          const authenticators = await clientDB.listProfileAuthenticators(profileId);

          const signingCtx: any = {
            indexedDB: {
              clientDB,
              accountKeyMaterialDB,
            },
            nearContextFixture: { initializeUser: () => {} },
            touchIdPrompt: { getRpId: () => 'example.localhost' },
            relayerUrl: 'https://relay-server.localhost',
            postWrapKeySeedToSigner: () => {},
            touchConfirm: {
              getWarmSessionStatus: async () => ({
                ok: false as const,
                code: 'not_found',
                message: 'warm-session status missing',
              }),
              claimWarmSessionMaterial: async () => ({
                ok: false as const,
                code: 'not_found',
                message: 'warm-session status missing',
              }),
              clearWarmSessionMaterial: async () => undefined,
              orchestrateSigningConfirmation: async () => ({
                intentDigest: 'intent',
                transactionContext: {
                  nearPublicKeyStr: 'ed25519:pk-device2',
                  nextNonce: '1',
                  txBlockHeight: '1',
                  txBlockHash: 'blockhash',
                  accessKeyInfo: { nonce: 0 },
                },
                credential: dummyCredential,
              }),
            },
            requestWorkerOperation: async () => ({
              type: WorkerResponseType.SignTransactionsWithActionsSuccess,
              payload: {
                success: true,
                signedTransactions: [
                  { transaction: {}, signature: {}, borshBytes: new Uint8Array([1]) },
                ],
                logs: [],
              },
            }),
            sendMessage: async () => ({
              type: WorkerResponseType.SignTransactionsWithActionsSuccess,
              payload: {
                success: true,
                signedTransactions: [
                  { transaction: {}, signature: {}, borshBytes: new Uint8Array([1]) },
                ],
                logs: [],
              },
            }),
          };

          const signed = await signTransactionsWithActions({
            ctx: signingCtx,
            transactions: [
              {
                receiverId: nearAccountId,
                actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
              },
            ],
            rpcCall: { nearAccountId },
            sessionId: thresholdSessionId,
          });

          return {
            success: true,
            lastUser: last
              ? { nearAccountId: last.nearAccountId, signerSlot: last.signerSlot }
              : null,
            signerSlotFromHelper,
            hasEncryptedKey:
              key?.keyKind === 'local_sk_encrypted_v1' && !!(key?.payload as any)?.encryptedSk,
            authenticatorCount: Array.isArray(authenticators) ? authenticators.length : 0,
            signedCount: Array.isArray(signed) ? signed.length : 0,
          } as const;
        } catch (error: any) {
          return { success: false, error: error?.message || String(error) } as const;
        }
      },
      { paths: IMPORT_PATHS },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success, result.error || 'unknown error').toBe(true);
      return;
    }

    expect(result.lastUser?.nearAccountId).toBe('linkdev1.w3a-v1.testnet');
    expect(result.lastUser?.signerSlot).toBe(2);
    expect(result.signerSlotFromHelper).toBe(2);
    expect(result.hasEncryptedKey).toBe(true);
    expect(result.authenticatorCount).toBeGreaterThan(0);
    expect(result.signedCount).toBe(1);
  });

  test('linkDevice storage coerces string signerSlot', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        try {
          const { PasskeyClientDBManager } = await import(paths.clientDb);
          const { AccountKeyMaterialDBManager } = await import(paths.accountKeyMaterialDb);
          const {
            clearAllStoredThresholdEd25519SessionRecords,
            upsertStoredThresholdEd25519SessionRecord,
          } = await import(paths.thresholdSessionStore);
          const { getLastLoggedInSignerSlot } = await import(paths.signerSlot);
          const { signTransactionsWithActions } = await import(paths.signTxs);
          const { WorkerResponseType } = await import(paths.signerTypes);
          const { ActionType } = await import(paths.actions);

          const nearAccountId = 'linkdev2.w3a-v1.testnet';
          const signerSlot: any = '2';
          const thresholdSessionId = 'linkdevice-regression-string-device';
          const profileId = `profile-near:${nearAccountId.toLowerCase()}`;
          const chainIdKey = nearAccountId.toLowerCase().endsWith('.testnet')
            ? 'near:testnet'
            : 'near:mainnet';

          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const clientDB = new PasskeyClientDBManager();
          clientDB.setDbName(`PasskeyClientDB-linkDeviceImmediateSign-${suffix}`);
          const accountKeyMaterialDB = new AccountKeyMaterialDBManager();
          accountKeyMaterialDB.setDbName(
            `PasskeyAccountKeyMaterial-linkDeviceImmediateSign-${suffix}`,
          );

          const storeUserData = async (userData: any) => {
            const normalizedSignerSlot =
              Number.isFinite(Number(userData?.signerSlot)) && Number(userData.signerSlot) >= 1
                ? Math.floor(Number(userData.signerSlot))
                : 1;
            await clientDB.upsertProfile({
              profileId,
              defaultSignerSlot: normalizedSignerSlot,
              passkeyCredential: userData.passkeyCredential,
            });
            await clientDB.upsertChainAccount({
              profileId,
              chainIdKey,
              accountAddress: nearAccountId,
              accountModel: 'near-native',
              isPrimary: true,
            });
            await clientDB.upsertAccountSigner({
              profileId,
              chainIdKey,
              accountAddress: nearAccountId,
              signerId:
                String(userData?.operationalPublicKey || '').trim() ||
                `signer:${normalizedSignerSlot}`,
              signerSlot: normalizedSignerSlot,
              signerType: 'threshold',
              signerKind: 'threshold-ed25519',
              signerAuthMethod: 'passkey',
              signerSource: 'passkey_registration',
              status: 'active',
              mutation: { routeThroughOutbox: false },
            });
            await clientDB.setLastProfileStateForProfile(profileId, normalizedSignerSlot);
          };

          const storeAuthenticator = async (authenticatorData: any) => {
            await clientDB.upsertProfileAuthenticator({
              profileId,
              signerSlot: authenticatorData.signerSlot ?? 1,
              credentialId: authenticatorData.credentialId,
              credentialPublicKey: authenticatorData.credentialPublicKey,
              transports: authenticatorData.transports,
              name: authenticatorData.name,
              registered: authenticatorData.registered,
              syncedAt: authenticatorData.syncedAt,
            });
          };

          const getLastSelectedNearProjection = async () => {
            const lastProfileState = await clientDB.getLastProfileState().catch(() => null);
            if (!lastProfileState?.profileId) return null;
            const chainAccounts = await clientDB.listChainAccountsByProfile(
              lastProfileState.profileId,
            );
            const nearAccount =
              chainAccounts.find((row: any) => String(row.chainIdKey || '').startsWith('near:')) ||
              null;
            if (!nearAccount) return null;
            return {
              nearAccountId: nearAccount.accountAddress,
              signerSlot: lastProfileState.activeSignerSlot,
            };
          };

          const dummyCredential = {
            id: 'cred-id',
            rawId: 'cred-rawid-b64u',
            type: 'public-key',
            authenticatorAttachment: 'platform',
            response: {
              clientDataJSON: 'clientDataJSON-b64u',
              attestationObject: 'attestationObject-b64u',
              transports: ['internal'],
            },
            clientExtensionResults: { prf: { results: { first: 'BQ', second: undefined } } },
          };

          const signingEngine: any = {
            storeUserData,
            storeAuthenticator,
            extractCosePublicKey: async () => new Uint8Array([1, 2, 3]),
          };

          const deterministicKeysResult = {
            nearPublicKey: 'ed25519:pk-device2',
            credential: dummyCredential,
          };
          const normalizedSignerSlot =
            Number.isFinite(Number(signerSlot)) && Number(signerSlot) >= 1
              ? Math.floor(Number(signerSlot))
              : 1;
          const credentialId = String(
            deterministicKeysResult.credential.rawId || deterministicKeysResult.credential.id || '',
          ).trim();
          const attestationObject = String(
            deterministicKeysResult.credential.response?.attestationObject || '',
          ).trim();
          const credentialPublicKey = await signingEngine.extractCosePublicKey(attestationObject);

          await signingEngine.storeUserData({
            nearAccountId,
            signerSlot: normalizedSignerSlot,
            operationalPublicKey: deterministicKeysResult.nearPublicKey,
            lastUpdated: Date.now(),
            passkeyCredential: {
              id: String(deterministicKeysResult.credential.id || credentialId),
              rawId: credentialId,
            },
            version: 2,
          });
          await signingEngine.storeAuthenticator({
            nearAccountId,
            credentialId,
            credentialPublicKey,
            transports: Array.isArray(deterministicKeysResult.credential.response?.transports)
              ? deterministicKeysResult.credential.response.transports
              : [],
            name: `Passkey for ${nearAccountId}`,
            registered: new Date().toISOString(),
            syncedAt: new Date().toISOString(),
            signerSlot: normalizedSignerSlot,
          });

          await accountKeyMaterialDB.storeKeyMaterial({
            profileId,
            signerSlot: 2,
            chainIdKey,
            keyKind: 'local_sk_encrypted_v1',
            algorithm: 'ed25519',
            publicKey: 'ed25519:pk-device2',
            wrapKeySalt: 'wrapKeySalt-b64u',
            payload: {
              encryptedSk: 'ciphertext-b64u',
              chacha20NonceB64u: 'nonce-b64u',
            },
            timestamp: Date.now(),
            schemaVersion: 1,
          });
          await accountKeyMaterialDB.storeKeyMaterial({
            profileId,
            signerSlot: 2,
            chainIdKey,
            keyKind: 'threshold_share_v1',
            algorithm: 'ed25519',
            publicKey: 'ed25519:pk-device2',
            payload: {
              relayerKeyId: 'rk-1',
              keyVersion: 'threshold-ed25519-hss-v1',
              participants: [
                { id: 1, role: 'client' },
                { id: 2, role: 'relayer', relayerKeyId: 'rk-1' },
              ],
            },
            timestamp: Date.now(),
            schemaVersion: 1,
          });
          clearAllStoredThresholdEd25519SessionRecords();
          upsertStoredThresholdEd25519SessionRecord({
            nearAccountId,
            rpId: 'example.localhost',
            relayerUrl: 'https://relay-server.localhost',
            relayerKeyId: 'rk-1',
            participantIds: [1, 2],
            runtimePolicyScope: { orgId: 'org-test', projectId: 'project-test', envId: 'dev' },
            xClientBaseB64u: 'cached-x-client-base',
            thresholdSessionKind: 'jwt',
            thresholdSessionId,
            thresholdSessionJwt: 'jwt-linkdevice-regression-string-device',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 9,
            source: 'manual-connect',
          });

          const last = await getLastSelectedNearProjection();
          const signerSlotFromHelper = await getLastLoggedInSignerSlot(nearAccountId, clientDB);
          const key = await accountKeyMaterialDB.getKeyMaterial(
            profileId,
            signerSlotFromHelper,
            chainIdKey,
            'local_sk_encrypted_v1',
          );
          const authenticators = await clientDB.listProfileAuthenticators(profileId);

          const signingCtx: any = {
            indexedDB: {
              clientDB,
              accountKeyMaterialDB,
            },
            nearContextFixture: { initializeUser: () => {} },
            touchIdPrompt: { getRpId: () => 'example.localhost' },
            relayerUrl: 'https://relay-server.localhost',
            postWrapKeySeedToSigner: () => {},
            touchConfirm: {
              getWarmSessionStatus: async () => ({
                ok: false as const,
                code: 'not_found',
                message: 'warm-session status missing',
              }),
              claimWarmSessionMaterial: async () => ({
                ok: false as const,
                code: 'not_found',
                message: 'warm-session status missing',
              }),
              clearWarmSessionMaterial: async () => undefined,
              orchestrateSigningConfirmation: async () => ({
                intentDigest: 'intent',
                transactionContext: {
                  nearPublicKeyStr: 'ed25519:pk-device2',
                  nextNonce: '1',
                  txBlockHeight: '1',
                  txBlockHash: 'blockhash',
                  accessKeyInfo: { nonce: 0 },
                },
                credential: dummyCredential,
              }),
            },
            requestWorkerOperation: async () => ({
              type: WorkerResponseType.SignTransactionsWithActionsSuccess,
              payload: {
                success: true,
                signedTransactions: [
                  { transaction: {}, signature: {}, borshBytes: new Uint8Array([1]) },
                ],
                logs: [],
              },
            }),
            sendMessage: async () => ({
              type: WorkerResponseType.SignTransactionsWithActionsSuccess,
              payload: {
                success: true,
                signedTransactions: [
                  { transaction: {}, signature: {}, borshBytes: new Uint8Array([1]) },
                ],
                logs: [],
              },
            }),
          };

          const signed = await signTransactionsWithActions({
            ctx: signingCtx,
            transactions: [
              {
                receiverId: nearAccountId,
                actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
              },
            ],
            rpcCall: { nearAccountId },
            sessionId: thresholdSessionId,
          });

          return {
            success: true,
            lastUser: last
              ? { nearAccountId: last.nearAccountId, signerSlot: last.signerSlot }
              : null,
            signerSlotFromHelper,
            hasEncryptedKey:
              key?.keyKind === 'local_sk_encrypted_v1' && !!(key?.payload as any)?.encryptedSk,
            authenticatorCount: Array.isArray(authenticators) ? authenticators.length : 0,
            signedCount: Array.isArray(signed) ? signed.length : 0,
          } as const;
        } catch (error: any) {
          return { success: false, error: error?.message || String(error) } as const;
        }
      },
      { paths: IMPORT_PATHS },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success, result.error || 'unknown error').toBe(true);
      return;
    }

    expect(result.lastUser?.nearAccountId).toBe('linkdev2.w3a-v1.testnet');
    expect(result.lastUser?.signerSlot).toBe(2);
    expect(result.signerSlotFromHelper).toBe(2);
    expect(result.hasEncryptedKey).toBe(true);
    expect(result.authenticatorCount).toBeGreaterThan(0);
    expect(result.signedCount).toBe(1);
  });
});
