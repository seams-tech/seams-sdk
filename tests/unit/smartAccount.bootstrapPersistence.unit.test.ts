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
          defaultDeviceNumber: 1,
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

        await manager.persistThresholdEcdsaBootstrapChainAccount({
          nearAccountId: 'alice.testnet',
          chain: 'evm',
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
          'evm:11155111',
        );
        const persisted = rows.find((row: any) => row.accountAddress === accountAddress) || null;
        const mirrorRows = await IndexedDBManager.clientDB.listChainAccountsByProfileAndChain(
          'profile-smartacct-bootstrap',
          'tempo:42431',
        );
        const mirror = mirrorRows.find((row: any) => row.accountAddress === accountAddress) || null;

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
          mirrorFound: !!mirror,
          mirrorChainIdKey: mirror?.chainIdKey || null,
          mirrorAccountModel: mirror?.accountModel || null,
          mirrorCounterfactualAddress: mirror?.counterfactualAddress || null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.found).toBe(true);
    expect(result.accountModel).toBe('erc4337');
    expect(result.chainIdKey).toBe('evm:11155111');
    expect(result.counterfactualAddress).toBe(`0x${'ab'.repeat(20)}`);
    expect(result.deployed).toBe(false);
    expect(result.deploymentTxHash).toBeNull();
    expect(result.lastDeploymentCheckAt).toBeNull();
    expect(result.mirrorFound).toBe(true);
    expect(result.mirrorChainIdKey).toBe('tempo:42431');
    expect(result.mirrorAccountModel).toBe('tempo-native');
    expect(result.mirrorCounterfactualAddress).toBe(`0x${'ab'.repeat(20)}`);
  });
});
