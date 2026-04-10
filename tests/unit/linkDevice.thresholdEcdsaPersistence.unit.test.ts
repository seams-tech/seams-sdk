import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  clientDb: '/sdk/esm/core/indexedDB/passkeyClientDB/manager.js',
  accountKeyMaterialDb: '/sdk/esm/core/indexedDB/accountKeyMaterialDB/manager.js',
  unifiedDb: '/sdk/esm/core/indexedDB/index.js',
  linkDeviceThresholdEcdsa: '/sdk/esm/core/TatchiPasskey/evm/linkDeviceThresholdEcdsa.js',
} as const;

test.describe('link-device threshold-ecdsa persistence', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('persists pending linked-account signers and ECDSA bootstrap lanes', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      try {
        const { PasskeyClientDBManager } = await import(paths.clientDb);
        const { AccountKeyMaterialDBManager } = await import(paths.accountKeyMaterialDb);
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
        const accountKeyMaterialDB = new AccountKeyMaterialDBManager();
        accountKeyMaterialDB.setDbName(`PasskeyAccountKeyMaterial-linkDeviceEcdsa-${suffix}`);
        const indexedDB = new UnifiedIndexedDBManager({ clientDB, accountKeyMaterialDB });
        const nearAccountRef = {
          chainIdKey: 'near:testnet',
          accountAddress: nearAccountId,
        };
        const profileId = `profile-near:${nearAccountId}`;

        await clientDB.upsertProfile({
          profileId,
          defaultDeviceNumber: 2,
          passkeyCredential: {
            id: 'cred-id',
            rawId: 'cred-b64u',
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
          signerId: 'ed25519:pk-device2',
          signerSlot: 2,
          signerType: 'passkey',
          status: 'active',
          mutation: { routeThroughOutbox: false },
        });

        const sessionCalls: Array<Record<string, unknown>> = [];
        const chainAccountCalls: Array<Record<string, unknown>> = [];
        const signingEngine = {
          upsertThresholdEcdsaSessionFromBootstrap(args: Record<string, unknown>) {
            sessionCalls.push(args);
          },
          async persistThresholdEcdsaBootstrapChainAccount(args: Record<string, unknown>) {
            chainAccountCalls.push(args);
            const context = await clientDB.resolveProfileAccountContext(nearAccountRef);
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
          thresholdEcdsa: {
            ecdsaThresholdKeyId: 'ehss-link-device-1',
            clientVerifyingShareB64u: 'client-share-b64u',
            clientAdditiveShare32B64u: 'client-additive-share-b64u',
            relayerKeyId: 'rk-evm',
            thresholdEcdsaPublicKeyB64u: 'group-public-key',
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
    expect(result.sessionCalls[0]?.bootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId).toBe(
      'ehss-link-device-1',
    );
    expect(result.evmSigners[0]?.status).toBe('pending');
    expect(result.evmSigners[0]?.signerId).toBe(`0x${'aa'.repeat(20)}`);
    expect(result.evmSigners[0]?.metadata?.ecdsaThresholdKeyId).toBe('ehss-link-device-1');
    expect(result.evmSigners[0]?.metadata?.thresholdEcdsaPublicKeyB64u).toBe('group-public-key');
    expect(result.tempoSigners[0]?.status).toBe('pending');
  });
});
