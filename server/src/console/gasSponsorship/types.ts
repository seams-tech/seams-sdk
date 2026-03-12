import type {
  ConsoleGasSponsorshipPolicyAllowedCall,
  ConsoleGasSponsorshipPolicyCallMode,
  ConsoleGasSponsorshipPolicyNetworkClass,
  ConsoleGasSponsorshipPolicyScopeType,
  ConsoleGasSponsorshipPolicySpendCap,
  ConsoleGasSponsorshipPolicySpendCapChain,
  ConsoleGasSponsorshipPolicySpendCapMode,
  ConsoleGasSponsorshipPolicySpendCapPeriod,
} from '../policies';

export type ConsoleGasSponsorshipScopeType = ConsoleGasSponsorshipPolicyScopeType;
export type ConsoleGasSponsorshipNetworkClass = ConsoleGasSponsorshipPolicyNetworkClass;
export type ConsoleGasSponsorshipCallMode = ConsoleGasSponsorshipPolicyCallMode;
export type ConsoleGasSponsorshipSpendCapMode = ConsoleGasSponsorshipPolicySpendCapMode;
export type ConsoleGasSponsorshipSpendCapPeriod = ConsoleGasSponsorshipPolicySpendCapPeriod;
export type ConsoleGasSponsorshipSpendCapChain = ConsoleGasSponsorshipPolicySpendCapChain;
export type ConsoleGasSponsorshipSpendCap = ConsoleGasSponsorshipPolicySpendCap;
export type ConsoleGasSponsorshipAllowedCall = ConsoleGasSponsorshipPolicyAllowedCall;

export interface ConsoleGasSponsorshipTelemetry {
  sponsoredTransactionCount: number;
  failedTransactionCount: number;
  spendMinor: number;
  budgetUtilizationPct: number;
}

export interface ConsoleGasSponsorshipPolicyProjection {
  id: string;
  orgId: string;
  scopeType: ConsoleGasSponsorshipScopeType;
  projectId: string | null;
  environmentId: string | null;
  scopePolicyId: string | null;
  scopePolicyName: string | null;
  walletSegmentId: string | null;
  name: string;
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
