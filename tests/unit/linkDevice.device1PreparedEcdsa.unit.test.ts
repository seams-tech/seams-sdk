import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  clientDb: '/sdk/esm/core/indexedDB/passkeyClientDB/manager.js',
  accountKeyMaterialDb: '/sdk/esm/core/indexedDB/accountKeyMaterialDB/manager.js',
  unifiedDb: '/sdk/esm/core/indexedDB/index.js',
  linkDevicePreparedEcdsa: '/sdk/esm/core/TatchiPasskey/near/linkDevicePreparedEcdsa.js',
} as const;

test.describe('link-device prepared ECDSA seeding on device1', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('seeds pending signer rows without routing outbox ops from relay session payload', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        try {
          const { PasskeyClientDBManager } = await import(paths.clientDb);
          const { AccountKeyMaterialDBManager } = await import(paths.accountKeyMaterialDb);
          const { UnifiedIndexedDBManager } = await import(paths.unifiedDb);
          const { persistPreparedLinkDeviceSmartAccountSigners } = await import(
            paths.linkDevicePreparedEcdsa
          );

          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const nearAccountId = 'alice.testnet';
          const clientDB = new PasskeyClientDBManager();
          clientDB.setDbName(`PasskeyClientDB-linkDevicePrepared-${suffix}`);
          const accountKeyMaterialDB = new AccountKeyMaterialDBManager();
          accountKeyMaterialDB.setDbName(`PasskeyAccountKeyMaterial-linkDevicePrepared-${suffix}`);
          const indexedDB = new UnifiedIndexedDBManager({ clientDB, accountKeyMaterialDB });
          const nearAccountRef = {
            chainIdKey: 'near:testnet',
            accountAddress: nearAccountId,
          };
          const profileId = `profile-near:${nearAccountId}`;

          await clientDB.upsertProfile({
            profileId,
            defaultSignerSlot: 1,
            passkeyCredential: {
              id: 'cred-device1',
              rawId: 'cred-device1-b64u',
            },
          });
          await clientDB.upsertChainAccount({
            profileId,
            chainIdKey: nearAccountRef.chainIdKey,
            accountAddress: nearAccountRef.accountAddress,
            accountModel: 'near-native',
            isPrimary: true,
          });
          await clientDB.upsertAccountSigner({
            profileId,
            chainIdKey: nearAccountRef.chainIdKey,
            accountAddress: nearAccountRef.accountAddress,
            signerId: 'ed25519:pk-device1',
            signerSlot: 1,
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            status: 'active',
            mutation: { routeThroughOutbox: false },
          });

          const originalFetch = globalThis.fetch;
          let fetchCalls = 0;
          globalThis.fetch = (async () => {
            fetchCalls += 1;
            return new Response(
              JSON.stringify({
                ok: true,
                session: {
                  preparedThresholdEcdsa: {
                    clientAdditiveShare32B64u: 'client-additive-share-b64u',
                    relayerKeyId: 'rk-evm',
                    thresholdEcdsaPublicKeyB64u: 'group-public-key',
                    ethereumAddress: `0x${'aa'.repeat(20)}`,
                    participantIds: [1, 2],
                  },
                  preparedLinkedAccounts: [
                    {
                      chainIdKey: 'evm:11155111',
                      chain: 'evm',
                      chainId: 11155111,
                      accountAddress: `0x${'11'.repeat(20)}`,
                      accountModel: 'erc4337',
                      factory: `0x${'bb'.repeat(20)}`,
                      entryPoint: `0x${'cc'.repeat(20)}`,
                      salt: '0x1234',
                      counterfactualAddress: `0x${'11'.repeat(20)}`,
                    },
                  ],
                },
              }),
              {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
              },
            );
          }) as typeof fetch;

          try {
            const seeded = await persistPreparedLinkDeviceSmartAccountSigners({
              context: {
                configs: {
                  network: {
                    relayer: {
                      url: 'https://relay.example.test',
                    },
                  },
                },
              } as any,
              indexedDB,
              accountId: nearAccountId,
              sessionId: 'session-123',
              signerSlot: 2,
              pollIntervalMs: 10,
              maxWaitMs: 50,
            });

            const context = await clientDB.resolveProfileAccountContext(nearAccountRef);
            const signers = await indexedDB.listAccountSigners({
              chainIdKey: 'evm:11155111',
              accountAddress: `0x${'11'.repeat(20)}`,
            });
            const outbox = await indexedDB.listSignerOperations({
              limit: 10,
            });
            const chainAccount = await indexedDB.getChainAccount({
              profileId: String(context?.profileId || ''),
              chainIdKey: 'evm:11155111',
              accountAddress: `0x${'11'.repeat(20)}`,
            });

            return {
              seeded,
              fetchCalls,
              signers,
              outbox,
              chainAccount,
            };
          } finally {
            globalThis.fetch = originalFetch;
          }
        } catch (error: any) {
          return { error: error?.message || String(error) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.error).toBeUndefined();
    expect(result.fetchCalls).toBe(1);
    expect(result.seeded?.seededSignerCount).toBe(1);
    expect(result.chainAccount?.accountModel).toBe('erc4337');
    expect(result.signers).toHaveLength(1);
    expect(result.signers[0]?.status).toBe('pending');
    expect(result.signers[0]?.signerId).toBe(`0x${'aa'.repeat(20)}`);
    expect(result.outbox).toHaveLength(0);
  });

  test('keeps the prepared EVM owner pending until an explicit signer mutation is queued', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        try {
          const { PasskeyClientDBManager } = await import(paths.clientDb);
          const { AccountKeyMaterialDBManager } = await import(paths.accountKeyMaterialDb);
          const { UnifiedIndexedDBManager } = await import(paths.unifiedDb);
          const { persistPreparedLinkDeviceSmartAccountSigners } = await import(
            paths.linkDevicePreparedEcdsa
          );

          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const nearAccountId = 'alice.testnet';
          const accountAddress = `0x${'11'.repeat(20)}`;
          const signerId = `0x${'aa'.repeat(20)}`;
          const clientDB = new PasskeyClientDBManager();
          clientDB.setDbName(`PasskeyClientDB-linkDevicePreparedPromote-${suffix}`);
          const accountKeyMaterialDB = new AccountKeyMaterialDBManager();
          accountKeyMaterialDB.setDbName(
            `PasskeyAccountKeyMaterial-linkDevicePreparedPromote-${suffix}`,
          );
          const indexedDB = new UnifiedIndexedDBManager({ clientDB, accountKeyMaterialDB });
          const nearAccountRef = {
            chainIdKey: 'near:testnet',
            accountAddress: nearAccountId,
          };
          const profileId = `profile-near:${nearAccountId}`;

          await clientDB.upsertProfile({
            profileId,
            defaultSignerSlot: 1,
            passkeyCredential: {
              id: 'cred-device1',
              rawId: 'cred-device1-b64u',
            },
          });
          await clientDB.upsertChainAccount({
            profileId,
            chainIdKey: nearAccountRef.chainIdKey,
            accountAddress: nearAccountRef.accountAddress,
            accountModel: 'near-native',
            isPrimary: true,
          });
          await clientDB.upsertAccountSigner({
            profileId,
            chainIdKey: nearAccountRef.chainIdKey,
            accountAddress: nearAccountRef.accountAddress,
            signerId: 'ed25519:pk-device1',
            signerSlot: 1,
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            status: 'active',
            mutation: { routeThroughOutbox: false },
          });
          const initialContext = await clientDB.resolveProfileAccountContext(nearAccountRef);
          if (!initialContext?.profileId) throw new Error('missing near account context');
          await indexedDB.upsertChainAccount({
            profileId: initialContext.profileId,
            chainIdKey: 'evm:11155111',
            accountAddress,
            accountModel: 'erc4337',
            isPrimary: true,
            deployed: true,
          });

          const originalFetch = globalThis.fetch;
          globalThis.fetch = (async () => {
            return new Response(
              JSON.stringify({
                ok: true,
                session: {
                  preparedThresholdEcdsa: {
                    clientAdditiveShare32B64u: 'client-additive-share-b64u',
                    relayerKeyId: 'rk-evm',
                    thresholdEcdsaPublicKeyB64u: 'group-public-key',
                    ethereumAddress: signerId,
                    participantIds: [1, 2],
                  },
                  preparedLinkedAccounts: [
                    {
                      chainIdKey: 'evm:11155111',
                      chain: 'evm',
                      chainId: 11155111,
                      accountAddress,
                      accountModel: 'erc4337',
                      factory: `0x${'bb'.repeat(20)}`,
                      entryPoint: `0x${'cc'.repeat(20)}`,
                      salt: '0x1234',
                      counterfactualAddress: accountAddress,
                    },
                  ],
                },
              }),
              {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
              },
            );
          }) as typeof fetch;

          try {
            const seeded = await persistPreparedLinkDeviceSmartAccountSigners({
              context: {
                configs: {
                  network: {
                    relayer: {
                      url: 'https://relay.example.test',
                    },
                  },
                },
              } as any,
              indexedDB,
              accountId: nearAccountId,
              sessionId: 'session-456',
              signerSlot: 2,
              pollIntervalMs: 10,
              maxWaitMs: 50,
            });

            const context = await clientDB.resolveProfileAccountContext(nearAccountRef);
            if (!context?.profileId) throw new Error('missing near account context');
            await accountKeyMaterialDB.storeKeyMaterial({
              profileId: context.profileId,
              signerSlot: 2,
              chainIdKey: 'evm:11155111',
              keyKind: 'threshold_share_v1',
              algorithm: 'webauthn-p256',
              publicKey: `04${'56'.repeat(64)}`,
              payload: {
                wrappedShare: 'ciphertext-b64u',
              },
              timestamp: Date.now(),
              schemaVersion: 1,
            });
            const outboxBefore = await indexedDB.listSignerOperations({
              limit: 10,
            });

            const runtimeCalls: Array<Record<string, unknown>> = [];
            const summary = await indexedDB.repairSignerMutationSagasWithRuntime({
              now: Date.now() + 60_000,
              runtime: {
                resolveOwnerAccountId: async () => 'alice.testnet',
                executeDeployedAddSigner: async (input: Record<string, unknown>) => {
                  runtimeCalls.push({
                    ownerAccountId: input.ownerAccountId,
                    opType: (input.op as any)?.opType,
                    signerId: (input.signer as any)?.signerId,
                    accountAddress: (input.chainAccount as any)?.accountAddress,
                  });
                  return { txHash: `0x${'ab'.repeat(32)}` };
                },
              },
            });
            const signer = await indexedDB.getAccountSigner({
              chainIdKey: 'evm:11155111',
              accountAddress,
              signerId,
            });
            const outbox = await indexedDB.listSignerOperations({
              statuses: ['queued', 'submitted', 'failed', 'confirmed', 'dead-letter'],
              limit: 10,
            });
            const keyMaterial = await accountKeyMaterialDB.listKeyMaterialByProfileAndSignerSlot(
              context.profileId,
              2,
              'evm:11155111',
            );

            return {
              seeded,
              summary,
              signer,
              outbox,
              outboxBefore,
              keyMaterial,
              runtimeCalls,
            };
          } finally {
            globalThis.fetch = originalFetch;
          }
        } catch (error: any) {
          return { error: error?.message || String(error) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.error).toBeUndefined();
    expect(result.seeded?.seededSignerCount).toBe(1);
    expect(result.summary).toEqual({
      scanned: 0,
      confirmed: 0,
      failed: 0,
      deadLettered: 0,
    });
    expect(result.outboxBefore).toHaveLength(0);
    expect(result.runtimeCalls).toEqual([]);
    expect(result.signer?.status).toBe('pending');
    expect(result.keyMaterial).toHaveLength(1);
  });
});
