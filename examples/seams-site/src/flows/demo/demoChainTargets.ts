import { FRONTEND_CONFIG, type FrontendConfig } from '@/config';

type DemoEcdsaChain = 'tempo' | 'evm';

export function resolveDemoThresholdEcdsaChainTarget(
  chain: DemoEcdsaChain,
  chains: FrontendConfig['chains'] = FRONTEND_CONFIG.chains,
) {
  const networkSlug = chain === 'tempo' ? 'tempo-testnet' : 'arc-testnet';
  const chainConfig = chains.find((candidate) => candidate.network === networkSlug);
  const chainId = Number((chainConfig as { chainId?: unknown } | undefined)?.chainId);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) {
    throw new Error(`Demo ${networkSlug} ECDSA chain target is missing a concrete chainId`);
  }
  return chain === 'tempo'
    ? {
        kind: 'tempo' as const,
        chainId,
        networkSlug,
      }
    : {
        kind: 'evm' as const,
        namespace: 'eip155' as const,
        chainId,
        networkSlug,
      };
}
