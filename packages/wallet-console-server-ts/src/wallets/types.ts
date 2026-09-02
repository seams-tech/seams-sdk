export type ConsoleWalletChain =
  | 'Multichain'
  | 'Ethereum'
  | 'Base'
  | 'Tempo'
  | 'Arc Circle'
  | 'NEAR';
export type ConsoleWalletType = 'EOA' | 'SMART';
export type ConsoleWalletStatus = 'ACTIVE' | 'FROZEN' | 'ARCHIVED';
export type ConsoleWalletSortBy = 'createdAt' | 'balance' | 'lastActivity';
export type ConsoleWalletSortOrder = 'asc' | 'desc';

export interface ConsoleWalletGasBalances {
  readonly observedAt: string;
  readonly near: {
    readonly accountId: string;
    readonly balanceYocto: string;
  };
  readonly tempo: {
    readonly address: string;
    readonly alphaUsdRaw: string;
  };
  readonly arc: {
    readonly address: string;
    readonly usdcRaw: string;
  };
}

export interface ConsoleWallet {
  id: string;
  orgId: string;
  projectId: string;
  environmentId: string;
  userId: string;
  externalRefId: string;
  address: string;
  chain: ConsoleWalletChain;
  walletType: ConsoleWalletType;
  status: ConsoleWalletStatus;
  policyId: string | null;
  balanceMinor: number;
  funded?: boolean;
  gasBalances?: ConsoleWalletGasBalances;
  lastActivityAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ListConsoleWalletsRequest {
  limit?: number;
  cursor?: string;
  projectId?: string;
  environmentId?: string;
  chain?: ConsoleWalletChain;
  walletType?: ConsoleWalletType;
  status?: ConsoleWalletStatus;
  policyId?: string;
  userId?: string;
  externalRefId?: string;
  sortBy?: ConsoleWalletSortBy;
  sortOrder?: ConsoleWalletSortOrder;
}

export interface SearchConsoleWalletsRequest extends ListConsoleWalletsRequest {
  q: string;
}

export interface ConsoleWalletPage {
  items: ConsoleWallet[];
  nextCursor?: string;
}
