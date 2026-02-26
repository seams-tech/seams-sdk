import { toTrimmedString } from '@shared/utils/validation';
import type {
  TatchiChainConfig,
  TatchiChainConfigInput,
  TatchiChainFamily,
  TatchiChainNetwork,
} from '../types/tatchi';

type ChainLike = {
  network: TatchiChainNetwork;
  rpcUrl?: string;
  explorerUrl?: string;
  chainId?: number;
};

export const TATCHI_CHAIN_NETWORKS = [
  'near-mainnet',
  'near-testnet',
  'tempo-mainnet',
  'tempo-testnet',
  'arc-mainnet',
  'arc-testnet',
] as const satisfies readonly TatchiChainNetwork[];

const TATCHI_CHAIN_NETWORK_SET: ReadonlySet<string> = new Set<string>(TATCHI_CHAIN_NETWORKS);

export function isTatchiChainNetwork(value: unknown): value is TatchiChainNetwork {
  return typeof value === 'string' && TATCHI_CHAIN_NETWORK_SET.has(value);
}

export function chainFamilyFromNetwork(network: TatchiChainNetwork): TatchiChainFamily {
  if (network.startsWith('near-')) return 'near';
  if (network.startsWith('tempo-')) return 'tempo';
  return 'arc';
}

export function nearNetworkFromChainNetwork(
  network: Extract<TatchiChainNetwork, `near-${string}`>,
): 'testnet' | 'mainnet' {
  return network === 'near-mainnet' ? 'mainnet' : 'testnet';
}

export function findPrimaryChainByFamily<T extends ChainLike>(
  chains: readonly T[] | undefined,
  family: TatchiChainFamily,
): T | undefined {
  if (!Array.isArray(chains)) return undefined;
  return chains.find((chain) => chainFamilyFromNetwork(chain.network) === family);
}

export function requirePrimaryChainByFamily<T extends ChainLike>(
  chains: readonly T[],
  family: TatchiChainFamily,
): T {
  const chain = findPrimaryChainByFamily(chains, family);
  if (!chain) {
    throw new Error(`[configPresets] Missing required config: chains (no ${family} network entry)`);
  }
  return chain;
}

export function resolvePrimaryNearRpcUrl(chains: readonly ChainLike[]): string {
  const chain = requirePrimaryChainByFamily(chains, 'near');
  const rpcUrl = toTrimmedString(chain.rpcUrl);
  if (!rpcUrl) {
    throw new Error(`[configPresets] Missing required config: chains.${chain.network}.rpcUrl`);
  }
  return rpcUrl;
}

export function resolveNearNetwork(chains: readonly ChainLike[]): 'testnet' | 'mainnet' {
  const chain = requirePrimaryChainByFamily(chains, 'near');
  return nearNetworkFromChainNetwork(chain.network as Extract<TatchiChainNetwork, `near-${string}`>);
}

export function resolvePrimaryExplorerUrl(
  chains: readonly ChainLike[],
  family: TatchiChainFamily,
): string | undefined {
  const chain = findPrimaryChainByFamily(chains, family);
  if (!chain) return undefined;
  return toTrimmedString(chain.explorerUrl) || undefined;
}

export function cloneChainConfig(
  chain: TatchiChainConfig | TatchiChainConfigInput,
): TatchiChainConfigInput {
  const maybeChainId = 'chainId' in chain ? chain.chainId : undefined;
  return {
    ...chain,
    ...(typeof maybeChainId === 'number' ? { chainId: maybeChainId } : {}),
  };
}

export function cloneResolvedChainConfig(chain: TatchiChainConfig): TatchiChainConfig {
  const maybeChainId = 'chainId' in chain ? chain.chainId : undefined;
  return {
    ...chain,
    ...(typeof maybeChainId === 'number' ? { chainId: maybeChainId } : {}),
  };
}
