export type ConsolePolicyStatus = 'DRAFT' | 'PUBLISHED' | 'ARCHIVED';
export type ConsolePolicyDecision = 'ALLOW' | 'DENY';
export type ConsolePolicyAssignmentScopeType = 'ORG' | 'PROJECT' | 'ENVIRONMENT' | 'WALLET';
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

export interface ConsolePolicyRulesInput {
  schemaVersion?: 1;
  blockedActions?: string[];
  allowedChains?: string[];
  maxAmountMinor?: number;
  allowedContractCalls?: ConsolePolicyContractCallRuleInput[];
}

export interface ConsolePolicyRules {
  schemaVersion: 1;
  blockedActions: string[];
  allowedChains: string[];
  maxAmountMinor?: number;
  allowedContractCalls: ConsolePolicyContractCallRule[];
}

export interface ConsolePolicy {
  id: string;
  orgId: string;
  name: string;
  description: string | null;
  status: ConsolePolicyStatus;
  version: number;
  rules: ConsolePolicyRules;
  createdAt: string;
  updatedAt: string;
  publishedAt: string | null;
}

export interface CreateConsolePolicyRequest {
  id?: string;
  name: string;
  description?: string;
  rules?: ConsolePolicyRulesInput;
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
