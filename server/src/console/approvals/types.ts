export type ConsoleApprovalOperationType =
  | 'POLICY_PUBLISH'
  | 'KEY_EXPORT'
  | 'SECURITY_SETTINGS_CHANGE';

export type ConsoleApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'CANCELED';

export type ConsoleApprovalDecision = 'APPROVE' | 'REJECT';

export interface ConsoleApprovalDecisionRecord {
  decision: ConsoleApprovalDecision;
  actorUserId: string;
  reason: string;
  mfaVerified: boolean;
  decidedAt: string;
}

export interface ConsoleApprovalRequestRecord {
  id: string;
  orgId: string;
  operationType: ConsoleApprovalOperationType;
  status: ConsoleApprovalStatus;
  reason: string;
  requestedByUserId: string;
  requiredApprovals: number;
  requireMfa: boolean;
  projectId: string | null;
  environmentId: string | null;
  resourceType: string | null;
  resourceId: string | null;
  metadata: Record<string, unknown>;
  decisions: ConsoleApprovalDecisionRecord[];
  createdAt: string;
  updatedAt: string;
  resolvedAt: string | null;
}

export interface ListConsoleApprovalsRequest {
  status?: ConsoleApprovalStatus;
  operationType?: ConsoleApprovalOperationType;
  projectId?: string;
  environmentId?: string;
}

export interface CreateConsoleApprovalRequest {
  id?: string;
  operationType: ConsoleApprovalOperationType;
  reason: string;
  requiredApprovals?: number;
  requireMfa?: boolean;
  projectId?: string;
  environmentId?: string;
  resourceType?: string;
  resourceId?: string;
  metadata?: Record<string, unknown>;
}

export interface ApproveConsoleApprovalRequest {
  reason: string;
  mfaVerified: boolean;
}

export interface RejectConsoleApprovalRequest {
  reason: string;
}
