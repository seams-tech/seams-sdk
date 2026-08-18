import type {
  ConsoleGasSponsorshipExecutionMode,
  ConsoleGasSponsorshipPolicyEvmAllowedCall,
  ConsoleGasSponsorshipPolicyNetworkClass,
  ConsoleGasSponsorshipPolicyNearAllowedDelegateAction,
  ConsoleGasSponsorshipPolicyRuleKind,
  ConsoleGasSponsorshipPolicyScopeType,
  ConsoleGasSponsorshipPolicySpendCap,
  ConsoleGasSponsorshipPolicySpendCapChain,
  ConsoleGasSponsorshipPolicySpendCapMode,
  ConsoleGasSponsorshipPolicySpendCapPeriod,
} from '../policies';

export type ConsoleGasSponsorshipScopeType = ConsoleGasSponsorshipPolicyScopeType;
export type ConsoleGasSponsorshipNetworkClass = ConsoleGasSponsorshipPolicyNetworkClass;
export type ConsoleGasSponsorshipRuleKind = ConsoleGasSponsorshipPolicyRuleKind;
export type ConsoleGasSponsorshipExecution = ConsoleGasSponsorshipExecutionMode;
export type ConsoleGasSponsorshipSpendCapMode = ConsoleGasSponsorshipPolicySpendCapMode;
export type ConsoleGasSponsorshipSpendCapPeriod = ConsoleGasSponsorshipPolicySpendCapPeriod;
export type ConsoleGasSponsorshipSpendCapChain = ConsoleGasSponsorshipPolicySpendCapChain;
export type ConsoleGasSponsorshipSpendCap = ConsoleGasSponsorshipPolicySpendCap;
export type ConsoleGasSponsorshipAllowedCall = ConsoleGasSponsorshipPolicyEvmAllowedCall;
export type ConsoleGasSponsorshipAllowedDelegateAction =
  ConsoleGasSponsorshipPolicyNearAllowedDelegateAction;

export interface ConsoleGasSponsorshipTelemetry {
  sponsoredTransactionCount: number;
  failedTransactionCount: number;
  spendMinor: number;
  budgetUtilizationPct: number;
}

interface ConsoleGasSponsorshipPolicyProjectionBase {
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
  kind: ConsoleGasSponsorshipRuleKind;
  executionMode: ConsoleGasSponsorshipExecution;
  spendCap: ConsoleGasSponsorshipSpendCap;
  telemetry: ConsoleGasSponsorshipTelemetry;
  createdAt: string;
  updatedAt: string;
}

export interface ConsoleGasSponsorshipEvmPolicyProjection
  extends ConsoleGasSponsorshipPolicyProjectionBase {
  kind: 'evm_call';
  executionMode: 'evm_eoa';
  allowedChainIds: number[];
  allowedCalls: ConsoleGasSponsorshipAllowedCall[];
}

export interface ConsoleGasSponsorshipNearPolicyProjection
  extends ConsoleGasSponsorshipPolicyProjectionBase {
  kind: 'near_delegate';
  executionMode: 'near_delegate';
  allowedDelegateActions: ConsoleGasSponsorshipAllowedDelegateAction[];
}

export type ConsoleGasSponsorshipPolicyProjection =
  | ConsoleGasSponsorshipEvmPolicyProjection
  | ConsoleGasSponsorshipNearPolicyProjection;

interface ResolvedGasSponsorshipPolicyBase {
  policyId: string;
  policyName: string;
  scopePolicyId: string | null;
  scopePolicyName: string | null;
  templateId: string | null;
  networkClass: ConsoleGasSponsorshipNetworkClass;
  executionMode: ConsoleGasSponsorshipExecution;
  spendCap: ConsoleGasSponsorshipSpendCap;
  scopeType: ConsoleGasSponsorshipScopeType;
  projectId: string | null;
  environmentId: string | null;
}

export interface ResolvedGasSponsorshipEvmPolicy extends ResolvedGasSponsorshipPolicyBase {
  kind: 'evm_call';
  executionMode: 'evm_eoa';
  allowedChainIds: number[];
  allowedCalls: ConsoleGasSponsorshipAllowedCall[];
}

export interface ResolvedGasSponsorshipNearPolicy extends ResolvedGasSponsorshipPolicyBase {
  kind: 'near_delegate';
  executionMode: 'near_delegate';
  allowedDelegateActions: ConsoleGasSponsorshipAllowedDelegateAction[];
}

export type ResolvedGasSponsorshipPolicy =
  | ResolvedGasSponsorshipEvmPolicy
  | ResolvedGasSponsorshipNearPolicy;
