export type ConsoleGasSponsorshipScopeType =
  | 'ORG'
  | 'PROJECT'
  | 'ENVIRONMENT'
  | 'POLICY'
  | 'WALLET_SEGMENT';

export type ConsoleGasSponsorshipBudgetPeriod = 'DAILY' | 'WEEKLY' | 'MONTHLY';

export type ConsoleGasSponsorshipPaymasterMode = 'DISABLED' | 'AUTO' | 'FORCED';

export type ConsoleGasSponsorshipFallbackBehavior = 'REJECT' | 'ALLOW_UNSPONSORED';

export interface ConsoleGasSponsorshipChainBudget {
  chain: string;
  period: ConsoleGasSponsorshipBudgetPeriod;
  budgetMinor: number;
  quotaTransactions: number;
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
  enabled: boolean;
  paymasterMode: ConsoleGasSponsorshipPaymasterMode;
  fallbackBehavior: ConsoleGasSponsorshipFallbackBehavior;
  chainBudgets: ConsoleGasSponsorshipChainBudget[];
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
}

export interface CreateConsoleGasSponsorshipRequest {
  id?: string;
  scopeType: ConsoleGasSponsorshipScopeType;
  projectId?: string;
  environmentId?: string;
  policyId?: string;
  walletSegmentId?: string;
  enabled?: boolean;
  paymasterMode?: ConsoleGasSponsorshipPaymasterMode;
  fallbackBehavior?: ConsoleGasSponsorshipFallbackBehavior;
  chainBudgets?: ConsoleGasSponsorshipChainBudget[];
}

export interface UpdateConsoleGasSponsorshipRequest {
  scopeType?: ConsoleGasSponsorshipScopeType;
  projectId?: string;
  environmentId?: string;
  policyId?: string;
  walletSegmentId?: string;
  enabled?: boolean;
  paymasterMode?: ConsoleGasSponsorshipPaymasterMode;
  fallbackBehavior?: ConsoleGasSponsorshipFallbackBehavior;
  chainBudgets?: ConsoleGasSponsorshipChainBudget[];
}
