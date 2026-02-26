import { toTrimmedString } from '@shared/utils/validation';
import type {
  TatchiChainConfig,
  TatchiChainConfigInput,
  TatchiChainFamily,
  TatchiChainNetwork,
  TatchiEvmChainNetwork,
  TatchiNearChainNetwork,
  TatchiTempoChainNetwork,
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
  'ethereum-mainnet',
  'ethereum-sepolia',
] as const satisfies readonly TatchiChainNetwork[];

const TATCHI_CHAIN_NETWORK_SET: ReadonlySet<string> = new Set<string>(TATCHI_CHAIN_NETWORKS);

export function isTatchiChainNetwork(value: unknown): value is TatchiChainNetwork {
  return typeof value === 'string' && TATCHI_CHAIN_NETWORK_SET.has(value);
}

export function isNearChainNetwork(value: unknown): value is TatchiNearChainNetwork {
  if (!isTatchiChainNetwork(value)) return false;
  return value.startsWith('near-');
}

export function isTempoChainNetwork(value: unknown): value is TatchiTempoChainNetwork {
  if (!isTatchiChainNetwork(value)) return false;
  return value.startsWith('tempo-');
}

export function isEvmChainNetwork(value: unknown): value is TatchiEvmChainNetwork {
  if (!isTatchiChainNetwork(value)) return false;
  return !isNearChainNetwork(value) && !isTempoChainNetwork(value);
}

export function chainFamilyFromNetwork(network: TatchiChainNetwork): TatchiChainFamily {
  if (isNearChainNetwork(network)) return 'near';
  if (isTempoChainNetwork(network)) return 'tempo';
  return 'evm';
}

export function nearNetworkFromChainNetwork(
  network: TatchiNearChainNetwork,
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
  return nearNetworkFromChainNetwork(chain.network as TatchiNearChainNetwork);
}

export function resolvePrimaryExplorerUrl(
  chains: readonly ChainLike[],
  family: TatchiChainFamily,
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
  family: TatchiChainFamily;
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
