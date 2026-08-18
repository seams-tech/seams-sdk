import { toTrimmedString } from '@shared/utils/validation';
import type {
  SeamsChainConfig,
  SeamsChainConfigInput,
  SeamsChainFamily,
  SeamsChainNetwork,
  SeamsEvmChainNetwork,
  SeamsNearChainNetwork,
  SeamsTempoChainNetwork,
} from '../types/seams';

type ChainLike = {
  network: SeamsChainNetwork;
  rpcUrl?: string;
  explorerUrl?: string;
  chainId?: number;
};

export const SEAMS_CHAIN_NETWORKS = [
  'near-mainnet',
  'near-testnet',
  'tempo-mainnet',
  'tempo-testnet',
  'arc-mainnet',
  'arc-testnet',
  'ethereum-mainnet',
  'ethereum-sepolia',
] as const satisfies readonly SeamsChainNetwork[];

const SEAMS_CHAIN_NETWORK_SET: ReadonlySet<string> = new Set<string>(SEAMS_CHAIN_NETWORKS);

export function isSeamsChainNetwork(value: unknown): value is SeamsChainNetwork {
  return typeof value === 'string' && SEAMS_CHAIN_NETWORK_SET.has(value);
}

export function isNearChainNetwork(value: unknown): value is SeamsNearChainNetwork {
  if (!isSeamsChainNetwork(value)) return false;
  return value.startsWith('near-');
}

export function isTempoChainNetwork(value: unknown): value is SeamsTempoChainNetwork {
  if (!isSeamsChainNetwork(value)) return false;
  return value.startsWith('tempo-');
}

export function isEvmChainNetwork(value: unknown): value is SeamsEvmChainNetwork {
  if (!isSeamsChainNetwork(value)) return false;
  return !isNearChainNetwork(value) && !isTempoChainNetwork(value);
}

export function chainFamilyFromNetwork(network: SeamsChainNetwork): SeamsChainFamily {
  if (isNearChainNetwork(network)) return 'near';
  if (isTempoChainNetwork(network)) return 'tempo';
  return 'evm';
}

export function nearNetworkFromChainNetwork(
  network: SeamsNearChainNetwork,
): 'testnet' | 'mainnet' {
  return network === 'near-mainnet' ? 'mainnet' : 'testnet';
}

export function findPrimaryChainByFamily<T extends ChainLike>(
  chains: readonly T[] | undefined,
  family: SeamsChainFamily,
): T | undefined {
  if (!Array.isArray(chains)) return undefined;
  return chains.find((chain) => chainFamilyFromNetwork(chain.network) === family);
}

export function requirePrimaryChainByFamily<T extends ChainLike>(
  chains: readonly T[],
  family: SeamsChainFamily,
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
  return nearNetworkFromChainNetwork(chain.network as SeamsNearChainNetwork);
}

export function resolvePrimaryExplorerUrl(
  chains: readonly ChainLike[],
  family: SeamsChainFamily,
): string | undefined {
  const chain = findPrimaryChainByFamily(chains, family);
  if (!chain) return undefined;
  return toTrimmedString(chain.explorerUrl) || undefined;
}

function normalizeChainIdToken(chainId: number | bigint | undefined): string | undefined {
  if (typeof chainId === 'bigint') {
    return chainId >= 0n ? chainId.toString() : undefined;
  }
  if (typeof chainId === 'number') {
    if (!Number.isSafeInteger(chainId) || chainId < 0) return undefined;
    return String(chainId);
  }
  return undefined;
}

export function resolveExplorerUrlForChainFamily(args: {
  chains: readonly ChainLike[] | undefined;
  family: SeamsChainFamily;
  chainId?: number | bigint;
}): string | undefined {
  const chains = args.chains;
  if (!Array.isArray(chains) || chains.length === 0) return undefined;

  const normalizedChainId = normalizeChainIdToken(args.chainId);
  if (normalizedChainId) {
    for (const chain of chains) {
      if (chainFamilyFromNetwork(chain.network) !== args.family) continue;
      const configuredChainId = normalizeChainIdToken(chain.chainId);
      if (!configuredChainId || configuredChainId !== normalizedChainId) continue;
      const explorerUrl = toTrimmedString(chain.explorerUrl);
      if (explorerUrl) return explorerUrl;
    }
  }

  return resolvePrimaryExplorerUrl(chains, args.family);
}

export function cloneChainConfig(
  chain: SeamsChainConfig | SeamsChainConfigInput,
): SeamsChainConfigInput {
  const maybeChainId = 'chainId' in chain ? chain.chainId : undefined;
  return {
    ...chain,
    ...(typeof maybeChainId === 'number' ? { chainId: maybeChainId } : {}),
  };
}

export function cloneResolvedChainConfig(chain: SeamsChainConfig): SeamsChainConfig {
  const maybeChainId = 'chainId' in chain ? chain.chainId : undefined;
  return {
    ...chain,
    ...(typeof maybeChainId === 'number' ? { chainId: maybeChainId } : {}),
  };
}
