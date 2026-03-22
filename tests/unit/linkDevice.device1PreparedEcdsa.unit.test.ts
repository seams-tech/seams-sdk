import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  clientDb: '/sdk/esm/core/indexedDB/passkeyClientDB/manager.js',
  nearKeysDb: '/sdk/esm/core/indexedDB/passkeyNearKeysDB/manager.js',
  unifiedDb: '/sdk/esm/core/indexedDB/index.js',
  linkDevicePreparedEcdsa: '/sdk/esm/core/TatchiPasskey/near/linkDevicePreparedEcdsa.js',
} as const;

test.describe('link-device prepared ECDSA seeding on device1', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('seeds pending signer rows and queues outbox ops from relay session payload', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      try {
        const { PasskeyClientDBManager } = await import(paths.clientDb);
        const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDb);
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
        const nearKeysDB = new PasskeyNearKeysDBManager();
        nearKeysDB.setDbName(`PasskeyNearKeys-linkDevicePrepared-${suffix}`);
        const indexedDB = new UnifiedIndexedDBManager({ clientDB, nearKeysDB });

        await clientDB.upsertNearAccountProjection({
          nearAccountId,
          deviceNumber: 1,
          clientNearPublicKey: 'ed25519:pk-device1',
          lastUpdated: Date.now(),
          passkeyCredential: {
            id: 'cred-device1',
            rawId: 'cred-device1-b64u',
          },
          version: 2,
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
                  relayerKeyId: 'rk-evm',
                  groupPublicKeyB64u: 'group-public-key',
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
            deviceNumber: 2,
            pollIntervalMs: 10,
            maxWaitMs: 50,
          });

          const context = await clientDB.resolveNearAccountContext(nearAccountId);
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
    }, { paths: IMPORT_PATHS });

    expect(result.error).toBeUndefined();
    expect(result.fetchCalls).toBe(1);
    expect(result.seeded?.seededSignerCount).toBe(1);
    expect(result.chainAccount?.accountModel).toBe('erc4337');
    expect(result.signers).toHaveLength(1);
    expect(result.signers[0]?.status).toBe('pending');
    expect(result.signers[0]?.signerId).toBe(`0x${'aa'.repeat(20)}`);
    expect(result.outbox).toHaveLength(1);
    expect(result.outbox[0]?.opType).toBe('add-signer');
    expect(result.outbox[0]?.status).toBe('queued');
  });
});
