export type ConsoleGasSponsorshipScopeType =
  | 'ORG'
  | 'PROJECT'
  | 'ENVIRONMENT'
  | 'POLICY'
  | 'WALLET_SEGMENT';

export type ConsoleGasSponsorshipNetworkClass = 'ANY' | 'TESTNET' | 'MAINNET';
export type ConsoleGasSponsorshipCallMode = 'ALLOW_ALL' | 'ALLOWLIST';
export type ConsoleGasSponsorshipSpendCapMode = 'NONE' | 'CHAIN_TOTAL' | 'WALLET_CHAIN_TOTAL';
export type ConsoleGasSponsorshipSpendCapPeriod = 'WEEKLY' | 'MONTHLY';

export interface ConsoleGasSponsorshipSpendCapChain {
  chainId: number;
  capMinor: number;
}

export interface ConsoleGasSponsorshipSpendCap {
  mode: ConsoleGasSponsorshipSpendCapMode;
  period: ConsoleGasSponsorshipSpendCapPeriod;
  capsByChain: ConsoleGasSponsorshipSpendCapChain[];
}

export interface ConsoleGasSponsorshipAllowedCall {
  chainId: number;
  to: string;
  selector: string;
}

export interface ConsoleGasSponsorshipTelemetry {
  sponsoredTransactionCount: number;
  failedTransactionCount: number;
  spendMinor: number;
  budgetUtilizationPct: number;
}

export interface ConsoleGasSponsorshipConfig {
  id: string;
  orgId: string;
  scopeType: ConsoleGasSponsorshipScopeType;
  projectId: string | null;
  environmentId: string | null;
  policyId: string | null;
  walletSegmentId: string | null;
  policyName: string;
  templateId: string | null;
  networkClass: ConsoleGasSponsorshipNetworkClass;
  enabled: boolean;
  allowedChainIds: number[];
  callMode: ConsoleGasSponsorshipCallMode;
  spendCap: ConsoleGasSponsorshipSpendCap;
  allowedCalls: ConsoleGasSponsorshipAllowedCall[];
  telemetry: ConsoleGasSponsorshipTelemetry;
  createdAt: string;
  updatedAt: string;
}

export interface ListConsoleGasSponsorshipRequest {
  scopeType?: ConsoleGasSponsorshipScopeType;
  projectId?: string;
  environmentId?: string;
  policyId?: string;
  walletSegmentId?: string;
  templateId?: string;
}

export interface CreateConsoleGasSponsorshipRequest {
  id?: string;
  scopeType: ConsoleGasSponsorshipScopeType;
  projectId?: string;
  environmentId?: string;
  policyId?: string;
  walletSegmentId?: string;
  policyName?: string;
  templateId?: string;
  networkClass?: ConsoleGasSponsorshipNetworkClass;
  enabled?: boolean;
  allowedChainIds?: number[];
  callMode?: ConsoleGasSponsorshipCallMode;
  spendCap?: ConsoleGasSponsorshipSpendCap;
  allowedCalls?: ConsoleGasSponsorshipAllowedCall[];
}

export interface UpdateConsoleGasSponsorshipRequest {
  scopeType?: ConsoleGasSponsorshipScopeType;
  projectId?: string;
  environmentId?: string;
  policyId?: string;
  walletSegmentId?: string;
  policyName?: string;
  templateId?: string;
  networkClass?: ConsoleGasSponsorshipNetworkClass;
  enabled?: boolean;
  allowedChainIds?: number[];
  callMode?: ConsoleGasSponsorshipCallMode;
  spendCap?: ConsoleGasSponsorshipSpendCap;
  allowedCalls?: ConsoleGasSponsorshipAllowedCall[];
}
