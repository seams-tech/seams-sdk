export type StablecoinAssetSymbol = 'USDC' | 'USDT';
export type StablecoinSettlementChain = 'Ethereum' | 'Base' | 'Tempo' | 'Arc Circle' | 'NEAR';

export interface ChainFinalityPolicy {
  chain: StablecoinSettlementChain;
  requiredConfirmations: number;
  confirmationTimeoutMinutes: number;
  reorgRiskWindowHours: number;
}

export interface StablecoinAssetSupport {
  asset: StablecoinAssetSymbol;
  chains: ChainFinalityPolicy[];
}

export const CHAIN_FINALITY_POLICY_VERSION = 'v1';

export const SUPPORTED_STABLECOIN_SETTLEMENT_CHAINS: StablecoinSettlementChain[] = [
  'Ethereum',
  'Base',
  'Tempo',
  'Arc Circle',
  'NEAR',
];

export const SUPPORTED_STABLECOIN_ASSETS: StablecoinAssetSymbol[] = ['USDC', 'USDT'];

const CHAIN_FINALITY_POLICIES_V1: Record<
  StablecoinSettlementChain,
  Omit<ChainFinalityPolicy, 'chain'>
> = {
  Ethereum: {
    requiredConfirmations: 12,
    confirmationTimeoutMinutes: 360,
    reorgRiskWindowHours: 24,
  },
  Base: {
    requiredConfirmations: 20,
    confirmationTimeoutMinutes: 120,
    reorgRiskWindowHours: 12,
  },
  Tempo: {
    requiredConfirmations: 20,
    confirmationTimeoutMinutes: 120,
    reorgRiskWindowHours: 12,
  },
  'Arc Circle': {
    requiredConfirmations: 20,
    confirmationTimeoutMinutes: 120,
    reorgRiskWindowHours: 12,
  },
  NEAR: {
    requiredConfirmations: 10,
    confirmationTimeoutMinutes: 60,
    reorgRiskWindowHours: 6,
  },
};

export function listChainFinalityPolicies(): ChainFinalityPolicy[] {
  return SUPPORTED_STABLECOIN_SETTLEMENT_CHAINS.map((chain) => ({
    chain,
    ...CHAIN_FINALITY_POLICIES_V1[chain],
  }));
}

export function listStablecoinAssetSupport(): StablecoinAssetSupport[] {
  const chains = listChainFinalityPolicies();
  return SUPPORTED_STABLECOIN_ASSETS.map((asset) => ({
    asset,
    chains,
  }));
}

export function isStablecoinAssetSymbol(value: string): value is StablecoinAssetSymbol {
  return SUPPORTED_STABLECOIN_ASSETS.includes(value as StablecoinAssetSymbol);
}

export function isStablecoinSettlementChain(value: string): value is StablecoinSettlementChain {
  return SUPPORTED_STABLECOIN_SETTLEMENT_CHAINS.includes(value as StablecoinSettlementChain);
}

export function getChainFinalityPolicy(
  chain: StablecoinSettlementChain,
): ChainFinalityPolicy | null {
  const policy = CHAIN_FINALITY_POLICIES_V1[chain];
  if (!policy) return null;
  return {
    chain,
    ...policy,
  };
}
