export type GasSponsorshipTargetNetworkClass = 'TESTNET' | 'MAINNET';

export interface GasSponsorshipChainTarget {
  id: string;
  chainName: string;
  chainLabel: string;
  chainId: number;
  networkClass: GasSponsorshipTargetNetworkClass;
  spendCapCurrencyCode: string;
  spendCapDisplayDecimals: number;
}

export interface GasSponsorshipChainMatrixRow {
  chainName: string;
  mainnet: GasSponsorshipChainTarget | null;
  testnet: GasSponsorshipChainTarget | null;
}

export const GAS_SPONSORSHIP_CHAIN_MATRIX_ROWS: readonly GasSponsorshipChainMatrixRow[] = [
  {
    chainName: 'Ethereum',
    mainnet: {
      id: 'ethereum-mainnet',
      chainName: 'Ethereum',
      chainLabel: 'Ethereum Mainnet',
      chainId: 1,
      networkClass: 'MAINNET',
      spendCapCurrencyCode: 'ETH',
      spendCapDisplayDecimals: 2,
    },
    testnet: {
      id: 'ethereum-sepolia',
      chainName: 'Ethereum',
      chainLabel: 'Ethereum Testnet',
      chainId: 11_155_111,
      networkClass: 'TESTNET',
      spendCapCurrencyCode: 'ETH',
      spendCapDisplayDecimals: 2,
    },
  },
  {
    chainName: 'Arc Circle',
    mainnet: {
      id: 'arc-mainnet',
      chainName: 'Arc Circle',
      chainLabel: 'Arc Circle Mainnet',
      chainId: 2415,
      networkClass: 'MAINNET',
      spendCapCurrencyCode: 'USDC',
      spendCapDisplayDecimals: 2,
    },
    testnet: {
      id: 'arc-testnet',
      chainName: 'Arc Circle',
      chainLabel: 'Arc Circle Testnet',
      chainId: 5_042_002,
      networkClass: 'TESTNET',
      spendCapCurrencyCode: 'USDC',
      spendCapDisplayDecimals: 2,
    },
  },
  {
    chainName: 'Tempo',
    mainnet: {
      id: 'tempo-mainnet',
      chainName: 'Tempo',
      chainLabel: 'Tempo Mainnet',
      chainId: 4_217,
      networkClass: 'MAINNET',
      spendCapCurrencyCode: 'AlphaUSD',
      spendCapDisplayDecimals: 2,
    },
    testnet: {
      id: 'tempo-testnet',
      chainName: 'Tempo',
      chainLabel: 'Tempo Testnet',
      chainId: 42_431,
      networkClass: 'TESTNET',
      spendCapCurrencyCode: 'AlphaUSD',
      spendCapDisplayDecimals: 2,
    },
  },
] as const;

export const GAS_SPONSORSHIP_CHAIN_TARGETS: readonly GasSponsorshipChainTarget[] =
  GAS_SPONSORSHIP_CHAIN_MATRIX_ROWS.flatMap((row) =>
    [row.mainnet, row.testnet].filter(
      (entry): entry is GasSponsorshipChainTarget => entry !== null,
    ),
  );
