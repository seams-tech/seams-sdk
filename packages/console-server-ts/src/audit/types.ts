export type ConsoleAuditActorType = 'USER' | 'SYSTEM';

export type ConsoleAuditCategory =
  | 'POLICY'
  | 'SETTINGS'
  | 'KEY_EXPORT'
  | 'BILLING'
  | 'WEBHOOK'
  | 'API_KEY'
  | 'TEAM'
  | 'APPROVAL'
  | 'ORG_PROJECT_ENV'
  | 'RUNTIME_SNAPSHOT'
  | 'SYSTEM';

export type ConsoleAuditOutcome = 'SUCCESS' | 'FAILURE' | 'PENDING';

export type ConsoleAuditEvidenceDomain = 'POLICY' | 'BILLING' | 'KEY_EXPORT' | 'SECURITY';

export type ConsoleAuditEvidenceReferenceKind = 'LOG' | 'EXPORT' | 'PAYMENT' | 'APPROVAL';

export interface ConsoleAuditEvent {
  id: string;
  orgId: string;
  projectId?: string;
  environmentId?: string;
  actorUserId: string;
  actorType: ConsoleAuditActorType;
  category: ConsoleAuditCategory;
  action: string;
  outcome: ConsoleAuditOutcome;
  summary: string;
  metadata: Record<string, unknown>;
  createdAt: string;
}

export interface ConsoleAuditEvidenceReference {
  kind: ConsoleAuditEvidenceReferenceKind;
  referenceId: string;
  label: string;
}

export interface ConsoleAuditEvidenceRecord {
  id: string;
  orgId: string;
  projectId?: string;
  environmentId?: string;
  domain: ConsoleAuditEvidenceDomain;
  title: string;
  summary: string;
  eventIds: string[];
  references: ConsoleAuditEvidenceReference[];
  createdAt: string;
}

export interface ListConsoleAuditEventsRequest {
  projectId?: string;
  environmentId?: string;
  category?: ConsoleAuditCategory;
  actorUserId?: string;
  outcome?: ConsoleAuditOutcome;
  q?: string;
  from?: string;
  to?: string;
  limit?: number;
}

export interface ListConsoleAuditEvidenceRequest {
  projectId?: string;
  environmentId?: string;
  domain?: ConsoleAuditEvidenceDomain;
  from?: string;
  to?: string;
  limit?: number;
}

export interface AppendConsoleAuditEventRequest {
  id?: string;
  projectId?: string;
  environmentId?: string;
  actorUserId?: string;
  actorType?: ConsoleAuditActorType;
  category: ConsoleAuditCategory;
  action: string;
  outcome: ConsoleAuditOutcome;
  summary: string;
  metadata?: Record<string, unknown>;
}

export interface AppendConsoleAuditEvidenceRequest {
  id?: string;
  projectId?: string;
  environmentId?: string;
  domain: ConsoleAuditEvidenceDomain;
  title: string;
  summary: string;
  eventIds?: string[];
  references?: ConsoleAuditEvidenceReference[];
}
