export type ConsoleGasSponsorshipScopeType =
  | 'ORG'
  | 'PROJECT'
  | 'ENVIRONMENT'
  | 'POLICY'
  | 'WALLET_SEGMENT';

export type ConsoleGasSponsorshipBudgetPeriod = 'DAILY' | 'WEEKLY' | 'MONTHLY';

export type ConsoleGasSponsorshipPaymasterMode = 'DISABLED' | 'AUTO' | 'FORCED';

export type ConsoleGasSponsorshipFallbackBehavior = 'REJECT' | 'ALLOW_UNSPONSORED';

export type ConsoleGasSponsorshipNetworkClass = 'ANY' | 'TESTNET' | 'MAINNET';

export type ConsoleGasSponsorshipExecutor = 'RELAY_EOA';

export interface ConsoleGasSponsorshipChainBudget {
  chain: string;
  period: ConsoleGasSponsorshipBudgetPeriod;
  budgetMinor: number;
  quotaTransactions: number;
}

export interface ConsoleGasSponsorshipAllowedCall {
  chainId: number;
  to: string;
  selector: string;
  maxGasLimit: string;
  maxValueWei: string;
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
  executor: ConsoleGasSponsorshipExecutor;
  enabled: boolean;
  paymasterMode: ConsoleGasSponsorshipPaymasterMode;
  fallbackBehavior: ConsoleGasSponsorshipFallbackBehavior;
  chainBudgets: ConsoleGasSponsorshipChainBudget[];
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
  executor?: ConsoleGasSponsorshipExecutor;
  enabled?: boolean;
  paymasterMode?: ConsoleGasSponsorshipPaymasterMode;
  fallbackBehavior?: ConsoleGasSponsorshipFallbackBehavior;
  chainBudgets?: ConsoleGasSponsorshipChainBudget[];
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
  executor?: ConsoleGasSponsorshipExecutor;
  enabled?: boolean;
  paymasterMode?: ConsoleGasSponsorshipPaymasterMode;
  fallbackBehavior?: ConsoleGasSponsorshipFallbackBehavior;
  chainBudgets?: ConsoleGasSponsorshipChainBudget[];
  allowedCalls?: ConsoleGasSponsorshipAllowedCall[];
}
