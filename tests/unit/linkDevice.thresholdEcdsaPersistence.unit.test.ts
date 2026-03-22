import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  clientDb: '/sdk/esm/core/indexedDB/passkeyClientDB/manager.js',
  nearKeysDb: '/sdk/esm/core/indexedDB/passkeyNearKeysDB/manager.js',
  unifiedDb: '/sdk/esm/core/indexedDB/index.js',
  linkDeviceThresholdEcdsa: '/sdk/esm/core/TatchiPasskey/near/linkDeviceThresholdEcdsa.js',
} as const;

test.describe('link-device threshold-ecdsa persistence', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('persists pending linked-account signers and ECDSA bootstrap lanes', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      try {
        const { PasskeyClientDBManager } = await import(paths.clientDb);
        const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDb);
        const { UnifiedIndexedDBManager } = await import(paths.unifiedDb);
        const { persistLinkDeviceThresholdEcdsaBootstrap } = await import(
          paths.linkDeviceThresholdEcdsa
        );

        const nearAccountId = 'alice.testnet';
        const suffix =
          typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const clientDB = new PasskeyClientDBManager();
        clientDB.setDbName(`PasskeyClientDB-linkDeviceEcdsa-${suffix}`);
        const nearKeysDB = new PasskeyNearKeysDBManager();
        nearKeysDB.setDbName(`PasskeyNearKeys-linkDeviceEcdsa-${suffix}`);
        const indexedDB = new UnifiedIndexedDBManager({ clientDB, nearKeysDB });

        await clientDB.upsertNearAccountProjection({
          nearAccountId,
          deviceNumber: 2,
          clientNearPublicKey: 'ed25519:pk-device2',
          lastUpdated: Date.now(),
          passkeyCredential: {
            id: 'cred-id',
            rawId: 'cred-b64u',
          },
          version: 2,
        });

        const sessionCalls: Array<Record<string, unknown>> = [];
        const chainAccountCalls: Array<Record<string, unknown>> = [];
        const signingEngine = {
          upsertThresholdEcdsaSessionFromBootstrap(args: Record<string, unknown>) {
            sessionCalls.push(args);
          },
          async persistThresholdEcdsaBootstrapChainAccount(args: Record<string, unknown>) {
            chainAccountCalls.push(args);
            const context = await clientDB.resolveNearAccountContext(nearAccountId);
            if (!context?.profileId) throw new Error('missing near account context');
            const chain = String(args.chain || '').trim();
            const smartAccount =
              args.smartAccount && typeof args.smartAccount === 'object'
                ? (args.smartAccount as Record<string, unknown>)
                : {};
            const chainId = Math.floor(Number(smartAccount.chainId));
            const accountAddress = String(
              smartAccount.counterfactualAddress ||
                ((args.bootstrap as any)?.keygen?.ethereumAddress as string) ||
                '',
            ).trim();
            await indexedDB.upsertChainAccount({
              profileId: context.profileId,
              chainIdKey: `${chain}:${chainId}`,
              accountAddress,
              accountModel: chain === 'evm' ? 'erc4337' : 'tempo-native',
              isPrimary: true,
              ...(typeof smartAccount.factory === 'string' ? { factory: smartAccount.factory } : {}),
              ...(typeof smartAccount.entryPoint === 'string'
                ? { entryPoint: smartAccount.entryPoint }
                : {}),
              ...(typeof smartAccount.salt === 'string' ? { salt: smartAccount.salt } : {}),
              ...(typeof smartAccount.counterfactualAddress === 'string'
                ? { counterfactualAddress: smartAccount.counterfactualAddress }
                : {}),
            });
          },
        };

        await persistLinkDeviceThresholdEcdsaBootstrap({
          indexedDB,
          signingEngine,
          nearAccountId,
          relayerUrl: 'https://relay.example.test',
          deviceNumber: 2,
          rpId: 'wallet.example.test',
          credentialIdB64u: 'cred-b64u',
          clientVerifyingShareB64u: 'client-share-b64u',
          thresholdEcdsa: {
            relayerKeyId: 'rk-evm',
            groupPublicKeyB64u: 'group-public-key',
            ethereumAddress: `0x${'aa'.repeat(20)}`,
            relayerVerifyingShareB64u: 'relayer-share-b64u',
            participantIds: [1, 2],
            session: {
              sessionKind: 'jwt',
              sessionId: 'ecdsa-session-1',
              expiresAtMs: Date.now() + 60_000,
              participantIds: [1, 2],
              remainingUses: 5,
              jwt: 'jwt:ecdsa-session-1',
            },
          },
          linkedAccounts: [
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
            {
              chainIdKey: 'tempo:42431',
              chain: 'tempo',
              chainId: 42431,
              accountAddress: `0x${'22'.repeat(20)}`,
              accountModel: 'tempo-native',
              counterfactualAddress: `0x${'22'.repeat(20)}`,
            },
          ],
        });

        const evmSigners = await indexedDB.listAccountSigners({
          chainIdKey: 'evm:11155111',
          accountAddress: `0x${'11'.repeat(20)}`,
        });
        const tempoSigners = await indexedDB.listAccountSigners({
          chainIdKey: 'tempo:42431',
          accountAddress: `0x${'22'.repeat(20)}`,
        });

        return {
          sessionCalls,
          chainAccountCalls,
          evmSigners,
          tempoSigners,
        };
      } catch (error: any) {
        return { error: error?.message || String(error) };
      }
    }, { paths: IMPORT_PATHS });

    expect(result.error).toBeUndefined();
    expect(result.sessionCalls).toHaveLength(2);
    expect(result.chainAccountCalls).toHaveLength(2);
    expect(result.evmSigners).toHaveLength(1);
    expect(result.tempoSigners).toHaveLength(1);
    expect(result.evmSigners[0]?.status).toBe('pending');
    expect(result.evmSigners[0]?.signerId).toBe(`0x${'aa'.repeat(20)}`);
    expect(result.evmSigners[0]?.metadata?.groupPublicKeyB64u).toBe('group-public-key');
    expect(result.tempoSigners[0]?.status).toBe('pending');
  });
});
