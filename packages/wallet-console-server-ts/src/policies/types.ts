export type ConsolePolicyStatus = 'DRAFT' | 'PUBLISHED' | 'ARCHIVED';
export type ConsolePolicyKind = 'TRANSACTION' | 'GAS_SPONSORSHIP';
export type ConsolePolicyDecision = 'ALLOW' | 'DENY';
export type ConsolePolicyAssignmentScopeType = 'ORG' | 'PROJECT' | 'ENVIRONMENT' | 'WALLET';
export type ConsoleGasSponsorshipPolicyScopeType =
  | 'ORG'
  | 'PROJECT'
  | 'ENVIRONMENT'
  | 'POLICY'
  | 'WALLET_SEGMENT';
export type ConsoleGasSponsorshipPolicyNetworkClass = 'ANY' | 'TESTNET' | 'MAINNET';
export type ConsoleGasSponsorshipPolicyRuleKind = 'evm_call' | 'near_delegate';
export type ConsoleGasSponsorshipExecutionMode = 'evm_eoa' | 'near_delegate';
export type ConsoleGasSponsorshipPolicySpendCapMode =
  | 'NONE'
  | 'CHAIN_TOTAL'
  | 'WALLET_CHAIN_TOTAL';
export type ConsoleGasSponsorshipPolicySpendCapPeriod = 'WEEKLY' | 'MONTHLY';
export type ConsolePolicyDenyReasonCode =
  | 'ACTION_BLOCKED'
  | 'CHAIN_NOT_ALLOWED'
  | 'AMOUNT_LIMIT_EXCEEDED'
  | 'CONTRACT_NOT_ALLOWED'
  | 'FUNCTION_NOT_ALLOWED';

export interface ConsolePolicyContractCallRuleInput {
  contractAddress: string;
  functions?: string[];
}

export interface ConsolePolicyContractCallRule {
  contractAddress: string;
  functions: string[];
}

export interface ConsoleGasSponsorshipPolicyEvmAllowedCallInput {
  chainId: number;
  to: string;
  functionSignature: string;
  selector?: string;
  maxGasLimit?: string | number;
  maxValueWei?: string | number;
}

export interface ConsoleGasSponsorshipPolicyEvmAllowedCall {
  chainId: number;
  to: string;
  functionSignature: string;
  selector: string;
  maxGasLimit: string;
  maxValueWei: string;
}

export interface ConsoleGasSponsorshipPolicyNearAllowedDelegateActionInput {
  receiverId: string;
  methods?: string[];
  maxDepositYocto?: string | number;
  allowTransfers?: boolean;
}

export interface ConsoleGasSponsorshipPolicyNearAllowedDelegateAction {
  receiverId: string;
  methods: string[];
  maxDepositYocto: string;
  allowTransfers: boolean;
}

export interface ConsoleGasSponsorshipPolicySpendCapChain {
  chainId: number;
  capMinor: number;
}

export interface ConsoleGasSponsorshipPolicySpendCap {
  mode: ConsoleGasSponsorshipPolicySpendCapMode;
  period: ConsoleGasSponsorshipPolicySpendCapPeriod;
  capsByChain: ConsoleGasSponsorshipPolicySpendCapChain[];
}

export interface ConsoleTransactionPolicyRulesInput {
  schemaVersion?: 1;
  blockedActions?: string[];
  allowedChains?: string[];
  maxAmountMinor?: number;
  allowedContractCalls?: ConsolePolicyContractCallRuleInput[];
}

export interface ConsoleGasSponsorshipPolicyCommonRulesInput {
  schemaVersion?: 1;
  scopeType?: ConsoleGasSponsorshipPolicyScopeType;
  projectId?: string;
  environmentId?: string;
  scopePolicyId?: string;
  walletSegmentId?: string;
  enabled?: boolean;
  templateId?: string;
  networkClass?: ConsoleGasSponsorshipPolicyNetworkClass;
  spendCap?: ConsoleGasSponsorshipPolicySpendCap;
}

export interface ConsoleGasSponsorshipPolicyEvmRulesInput
  extends ConsoleGasSponsorshipPolicyCommonRulesInput {
  kind?: 'evm_call';
  executionMode?: 'evm_eoa';
  allowedCalls?: ConsoleGasSponsorshipPolicyEvmAllowedCallInput[];
}

export interface ConsoleGasSponsorshipPolicyNearRulesInput
  extends ConsoleGasSponsorshipPolicyCommonRulesInput {
  kind: 'near_delegate';
  executionMode?: 'near_delegate';
  allowedDelegateActions?: ConsoleGasSponsorshipPolicyNearAllowedDelegateActionInput[];
}

export type ConsoleGasSponsorshipPolicyRulesInput =
  | ConsoleGasSponsorshipPolicyEvmRulesInput
  | ConsoleGasSponsorshipPolicyNearRulesInput;

export interface ConsoleTransactionPolicyRules {
  schemaVersion: 1;
  blockedActions: string[];
  allowedChains: string[];
  maxAmountMinor?: number;
  allowedContractCalls: ConsolePolicyContractCallRule[];
}

export interface ConsoleGasSponsorshipPolicyCommonRules {
  schemaVersion: 1;
  scopeType: ConsoleGasSponsorshipPolicyScopeType;
  projectId: string | null;
  environmentId: string | null;
  scopePolicyId: string | null;
  walletSegmentId: string | null;
  enabled: boolean;
  templateId: string | null;
  networkClass: ConsoleGasSponsorshipPolicyNetworkClass;
  spendCap: ConsoleGasSponsorshipPolicySpendCap;
}

export interface ConsoleGasSponsorshipPolicyEvmRules
  extends ConsoleGasSponsorshipPolicyCommonRules {
  kind: 'evm_call';
  executionMode: 'evm_eoa';
  allowedCalls: ConsoleGasSponsorshipPolicyEvmAllowedCall[];
}

export interface ConsoleGasSponsorshipPolicyNearRules
  extends ConsoleGasSponsorshipPolicyCommonRules {
  kind: 'near_delegate';
  executionMode: 'near_delegate';
  allowedDelegateActions: ConsoleGasSponsorshipPolicyNearAllowedDelegateAction[];
}

export type ConsoleGasSponsorshipPolicyRules =
  | ConsoleGasSponsorshipPolicyEvmRules
  | ConsoleGasSponsorshipPolicyNearRules;

export type ConsolePolicyRulesInput =
  | ConsoleTransactionPolicyRulesInput
  | ConsoleGasSponsorshipPolicyRulesInput;

export type ConsolePolicyRules =
  | ConsoleTransactionPolicyRules
  | ConsoleGasSponsorshipPolicyRules;

export interface ConsolePolicy {
  id: string;
  orgId: string;
  isSystemDefault: boolean;
  kind: ConsolePolicyKind;
  name: string;
  description: string | null;
  status: ConsolePolicyStatus;
  version: number;
  rules: ConsolePolicyRules;
  createdAt: string;
  updatedAt: string;
  publishedAt: string | null;
}

export interface ConsolePolicyVersion {
  policyId: string;
  kind: ConsolePolicyKind;
  version: number;
  status: ConsolePolicyStatus;
  rules: ConsolePolicyRules;
  publishedAt: string | null;
  createdAt: string;
  actorUserId: string;
}

export interface CreateConsolePolicyAssignmentInput {
  scopeType: ConsolePolicyAssignmentScopeType;
  scopeId: string;
}

export interface CreateConsolePolicyRequest {
  kind?: ConsolePolicyKind;
  name: string;
  description?: string;
  rules?: ConsolePolicyRulesInput;
  assignment?: CreateConsolePolicyAssignmentInput;
}

export interface UpdateConsolePolicyRequest {
  name?: string;
  description?: string;
  rules?: ConsolePolicyRulesInput;
}

export interface SimulateConsolePolicyRequest {
  action: string;
  chain?: string;
  amountMinor?: number;
  contractAddress?: string;
  functionSelector?: string;
  metadata?: Record<string, unknown>;
}

export interface ConsolePolicyDenyReason {
  code: ConsolePolicyDenyReasonCode;
  message: string;
}

export interface SimulateConsolePolicyNormalizedRequest {
  action: string;
  chain: string | null;
  amountMinor: number | null;
  contractAddress: string | null;
  functionSelector: string | null;
}

export interface SimulateConsolePolicyResult {
  policyId: string;
  decision: ConsolePolicyDecision;
  denyReasons: ConsolePolicyDenyReason[];
  evaluatedAt: string;
  policyVersion: number;
  normalizedRequest: SimulateConsolePolicyNormalizedRequest;
}

export interface PublishConsolePolicyResult {
  published: boolean;
  policy: ConsolePolicy;
}

export interface DeleteConsolePolicyResult {
  removed: boolean;
  policy: ConsolePolicy | null;
}

export interface ListConsolePoliciesRequest {
  kind?: ConsolePolicyKind;
}

export interface ConsolePolicyAssignment {
  id: string;
  orgId: string;
  scopeType: ConsolePolicyAssignmentScopeType;
  scopeId: string;
  policyId: string;
  createdAt: string;
  updatedAt: string;
}

export interface ListConsolePolicyAssignmentsRequest {
  scopeType?: ConsolePolicyAssignmentScopeType;
  scopeId?: string;
}

export interface UpsertConsolePolicyAssignmentRequest {
  scopeType: ConsolePolicyAssignmentScopeType;
  scopeId: string;
  policyId: string;
}

export interface ConsolePolicyWalletScopeRef {
  walletId: string;
  projectId?: string;
  environmentId?: string;
  fallbackPolicyId?: string | null;
}
