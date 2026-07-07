import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  chains: '/_test-sdk/esm/core/config/chains.js',
  defaults: '/_test-sdk/esm/core/config/defaultConfigs.js',
} as const;

test.describe('chain family naming', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('maps concrete networks to canonical families and predicates', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.chains);
        const sampleNetworks = [
          'near-mainnet',
          'near-testnet',
          'tempo-mainnet',
          'tempo-testnet',
          'arc-mainnet',
          'arc-testnet',
          'ethereum-mainnet',
          'ethereum-sepolia',
        ] as const;

        const mapping = sampleNetworks.map((network) => ({
          network,
          family: mod.chainFamilyFromNetwork(network),
          isNear: mod.isNearChainNetwork(network),
          isTempo: mod.isTempoChainNetwork(network),
          isEvm: mod.isEvmChainNetwork(network),
        }));

        const configuredChains = [
          {
            network: 'near-testnet',
            rpcUrl: 'https://near-rpc.example',
            explorerUrl: 'https://near-explorer.example',
          },
          {
            network: 'arc-mainnet',
            rpcUrl: 'https://arc-rpc.example',
            explorerUrl: 'https://arc-explorer.example',
            chainId: 2415,
          },
          {
            network: 'ethereum-sepolia',
            rpcUrl: 'https://sepolia-rpc.example',
            explorerUrl: 'https://sepolia-explorer.example',
            chainId: 11155111,
          },
        ];

        const evmExplorer = mod.resolvePrimaryExplorerUrl(configuredChains, 'evm');
        const evmExplorerForSepoliaChainId = mod.resolveExplorerUrlForChainFamily({
          chains: configuredChains,
          family: 'evm',
          chainId: 11155111,
        });
        const evmExplorerForArcChainId = mod.resolveExplorerUrlForChainFamily({
          chains: configuredChains,
          family: 'evm',
          chainId: 2415,
        });
        const evmExplorerFallback = mod.resolveExplorerUrlForChainFamily({
          chains: configuredChains,
          family: 'evm',
        });

        return {
          mapping,
          evmExplorer,
          evmExplorerForSepoliaChainId,
          evmExplorerForArcChainId,
          evmExplorerFallback,
        };
      },
      { paths: IMPORT_PATHS },
    );

    const familyByNetwork = new Map(result.mapping.map((entry) => [entry.network, entry.family]));
    expect(familyByNetwork.get('near-mainnet')).toBe('near');
    expect(familyByNetwork.get('near-testnet')).toBe('near');
    expect(familyByNetwork.get('tempo-mainnet')).toBe('tempo');
    expect(familyByNetwork.get('tempo-testnet')).toBe('tempo');
    expect(familyByNetwork.get('arc-mainnet')).toBe('evm');
    expect(familyByNetwork.get('arc-testnet')).toBe('evm');
    expect(familyByNetwork.get('ethereum-mainnet')).toBe('evm');
    expect(familyByNetwork.get('ethereum-sepolia')).toBe('evm');

    const evmPredicates = result.mapping
      .filter((entry) => entry.family === 'evm')
      .map((entry) => ({ network: entry.network, isEvm: entry.isEvm }));
    expect(evmPredicates).toEqual([
      { network: 'arc-mainnet', isEvm: true },
      { network: 'arc-testnet', isEvm: true },
      { network: 'ethereum-mainnet', isEvm: true },
      { network: 'ethereum-sepolia', isEvm: true },
    ]);

    expect(result.evmExplorer).toBe('https://arc-explorer.example');
    expect(result.evmExplorerForSepoliaChainId).toBe('https://sepolia-explorer.example');
    expect(result.evmExplorerForArcChainId).toBe('https://arc-explorer.example');
    expect(result.evmExplorerFallback).toBe('https://arc-explorer.example');
  });

  test('explicit chain config is the authoritative active network set', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const defaultsMod = await import(paths.defaults);
        const defaults = Array.isArray(defaultsMod.PASSKEY_MANAGER_DEFAULT_CONFIGS?.network?.chains)
          ? defaultsMod.PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains
          : [];

        return {
          defaultNetworks: defaults.map((chain: { network: string }) => chain.network),
          builtNetworks: defaultsMod
            .buildConfigsFromEnv({
              relayer: { url: 'https://relay.example' },
              iframeWallet: { walletOrigin: 'https://wallet.example.test' },
              chains: [
                {
                  network: 'near-testnet',
                  rpcUrl: 'https://near-rpc.example',
                  explorerUrl: 'https://near-explorer.example',
                },
                {
                  network: 'arc-testnet',
                  rpcUrl: 'https://arc-rpc.example',
                  explorerUrl: 'https://arc-explorer.example',
                  chainId: 5042002,
                },
              ],
            })
            .network.chains.map((chain: { network: string }) => chain.network),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.defaultNetworks.length).toBeGreaterThan(0);
    expect(result.builtNetworks).toEqual(['near-testnet', 'arc-testnet']);
  });
});
