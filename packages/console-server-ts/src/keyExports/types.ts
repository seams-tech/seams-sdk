export type ConsoleKeyExportMode = 'DISABLED' | 'APPROVAL_REQUIRED' | 'ALLOWED_WITH_CONSTRAINTS';

export type ConsoleKeyExportStatus =
  | 'PENDING_APPROVAL'
  | 'APPROVED'
  | 'REJECTED'
  | 'EXECUTED'
  | 'CANCELED';

export interface ConsoleKeyExportConstraints {
  roles: string[];
  chains: string[];
  walletTypes: string[];
  environmentIds: string[];
}

export interface ConsoleKeyExportApproval {
  approverUserId: string;
  approvedAt: string;
  reason: string;
  mfaVerified: boolean;
}

export interface ConsoleKeyExportRequestRecord {
  id: string;
  orgId: string;
  environmentId: string;
  walletId: string | null;
  mode: ConsoleKeyExportMode;
  status: ConsoleKeyExportStatus;
  reason: string;
  requestedByUserId: string;
  requiredApprovals: number;
  approvals: ConsoleKeyExportApproval[];
  constraints: ConsoleKeyExportConstraints;
  createdAt: string;
  updatedAt: string;
}

export interface ListConsoleKeyExportsRequest {
  environmentId?: string;
  status?: ConsoleKeyExportStatus;
}

export interface CreateConsoleKeyExportRequest {
  id?: string;
  environmentId: string;
  walletId?: string;
  mode?: ConsoleKeyExportMode;
  reason: string;
  requiredApprovals?: number;
  constraints?: Partial<ConsoleKeyExportConstraints>;
}

export interface ApproveConsoleKeyExportRequest {
  reason: string;
  mfaVerified: boolean;
}
