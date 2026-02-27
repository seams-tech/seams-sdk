export type ConsolePolicyStatus = 'DRAFT' | 'PUBLISHED' | 'ARCHIVED';
export type ConsolePolicyDecision = 'ALLOW' | 'DENY';
export type ConsolePolicyAssignmentScopeType = 'ORG' | 'PROJECT' | 'ENVIRONMENT' | 'WALLET';

export interface ConsolePolicy {
  id: string;
  orgId: string;
  name: string;
  description: string | null;
  status: ConsolePolicyStatus;
  version: number;
  rules: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
  publishedAt: string | null;
}

export interface CreateConsolePolicyRequest {
  id?: string;
  name: string;
  description?: string;
  rules?: Record<string, unknown>;
}

export interface UpdateConsolePolicyRequest {
  name?: string;
  description?: string;
  rules?: Record<string, unknown>;
}

export interface SimulateConsolePolicyRequest {
  action: string;
  chain?: string;
  amountMinor?: number;
  metadata?: Record<string, unknown>;
}

export interface SimulateConsolePolicyResult {
  policyId: string;
  decision: ConsolePolicyDecision;
  reasons: string[];
  evaluatedAt: string;
  policyVersion: number;
}

export interface PublishConsolePolicyResult {
  published: boolean;
  policy: ConsolePolicy;
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
