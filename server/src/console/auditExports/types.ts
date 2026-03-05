export type ConsoleAuditExportDomain = 'POLICY' | 'BILLING' | 'KEY_EXPORT' | 'SECURITY' | 'ALL';

export type ConsoleAuditExportFormat = 'JSONL' | 'CSV';

export type ConsoleAuditExportStatus = 'QUEUED' | 'PROCESSING' | 'READY' | 'FAILED';

export interface ConsoleAuditExportFilters {
  projectId?: string;
  environmentId?: string;
  domain?: ConsoleAuditExportDomain;
  from?: string;
  to?: string;
}

export interface ConsoleAuditExportRecord {
  id: string;
  orgId: string;
  requestedByUserId: string;
  status: ConsoleAuditExportStatus;
  format: ConsoleAuditExportFormat;
  filters: ConsoleAuditExportFilters;
  createdAt: string;
  updatedAt: string;
  readyAt: string | null;
  expiresAt: string | null;
  downloadUrl: string | null;
  failureCode: string | null;
  failureMessage: string | null;
}

export interface ListConsoleAuditExportsRequest {
  status?: ConsoleAuditExportStatus;
  domain?: ConsoleAuditExportDomain;
  limit?: number;
}

export interface CreateConsoleAuditExportRequest {
  id?: string;
  format: ConsoleAuditExportFormat;
  domain?: ConsoleAuditExportDomain;
  projectId?: string;
  environmentId?: string;
  from?: string;
  to?: string;
}
