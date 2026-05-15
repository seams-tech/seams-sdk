import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  indexedDB: '/sdk/esm/core/indexedDB/index.js',
  webAuthnManager: '/sdk/esm/core/signingEngine/SigningEngine.js',
  defaults: '/sdk/esm/core/config/defaultConfigs.js',
} as const;

test.describe('smart-account bootstrap persistence', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('registration/bootstrap persistence stores undeployed smart account row', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { IndexedDBManager } = await import(paths.indexedDB);
        const { SigningEngine } = await import(paths.webAuthnManager);
        const { buildConfigsFromEnv } = await import(paths.defaults);

        const now = Date.now();
        const accountAddress = `0x${'ab'.repeat(20)}`;
        const factory = `0x${'cd'.repeat(20)}`;
        const entryPoint = `0x${'ef'.repeat(20)}`;

        IndexedDBManager.clientDB.setDisabled(false);
        IndexedDBManager.accountKeyMaterialDB.setDisabled(false);
        IndexedDBManager.clientDB.setDbName(
          `PasskeyClientDB-smartacct-bootstrap-${now}-${Math.random().toString(16).slice(2)}`,
        );
        await IndexedDBManager.clientDB.upsertProfile({
          profileId: 'profile-smartacct-bootstrap',
          defaultSignerSlot: 1,
          passkeyCredential: { id: 'cred-bootstrap', rawId: 'raw-bootstrap' },
        });
        await IndexedDBManager.clientDB.upsertChainAccount({
          profileId: 'profile-smartacct-bootstrap',
          chainIdKey: 'near:testnet',
          accountAddress: 'alice.testnet',
          accountModel: 'near-native',
          isPrimary: true,
        });

        const configs = buildConfigsFromEnv({
          relayer: { url: 'https://relayer.example' },
        });
        const manager = new SigningEngine(configs, {} as any);

        await manager.persistThresholdEcdsaBootstrapForWalletTarget({
          walletId: 'alice.testnet',
          chainTarget: {
            kind: 'evm',
            namespace: 'eip155',
            chainId: 11155111,
            networkSlug: 'sepolia',
          },
          bootstrap: {
            keygen: {
              chainId: 11155111,
              counterfactualAddress: accountAddress,
              ethereumAddress: accountAddress,
              factory,
              entryPoint,
              salt: '0x1234',
            },
          },
        });

        const rows = await IndexedDBManager.clientDB.listChainAccountsByProfileAndChain(
          'profile-smartacct-bootstrap',
          'evm:eip155:11155111',
        );
        const persisted = rows.find((row: any) => row.accountAddress === accountAddress) || null;
        return {
          found: !!persisted,
          accountModel: persisted?.accountModel || null,
          chainIdKey: persisted?.chainIdKey || null,
          counterfactualAddress: persisted?.counterfactualAddress || null,
          deployed: typeof persisted?.deployed === 'boolean' ? persisted.deployed : null,
          deploymentTxHash: persisted?.deploymentTxHash || null,
          lastDeploymentCheckAt:
            typeof persisted?.lastDeploymentCheckAt === 'number'
              ? persisted.lastDeploymentCheckAt
              : null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.found).toBe(true);
    expect(result.accountModel).toBe('erc4337');
    expect(result.chainIdKey).toBe('evm:eip155:11155111');
    expect(result.counterfactualAddress).toBe(`0x${'ab'.repeat(20)}`);
    expect(result.deployed).toBe(false);
    expect(result.deploymentTxHash).toBeNull();
    expect(result.lastDeploymentCheckAt).toBeNull();
  });
});
