export type ConsoleEnterpriseIsolationMode = 'SHARED' | 'DEDICATED';

export type ConsoleEnterpriseIsolationStatus = 'SHARED' | 'REQUESTED' | 'MIGRATING' | 'ISOLATED' | 'FAILED';

export type ConsoleEnterpriseIsolationTrigger = 'MANUAL' | 'SLA_BREACH' | 'COMPLIANCE';

export type ConsoleEnterpriseIsolationScope = 'ORG' | 'PROJECT' | 'ENVIRONMENT';

export interface ConsoleEnterpriseIsolationSla {
  availabilityTargetPercent: string;
  rpoMinutes: number;
  rtoHours: number;
}

export interface ConsoleEnterpriseIsolationState {
  orgId: string;
  scope: ConsoleEnterpriseIsolationScope;
  projectId: string | null;
  environmentId: string | null;
  mode: ConsoleEnterpriseIsolationMode;
  status: ConsoleEnterpriseIsolationStatus;
  trigger: ConsoleEnterpriseIsolationTrigger | null;
  requestedByUserId: string | null;
  requestedAt: string | null;
  activatedAt: string | null;
  reason: string | null;
  ticketId: string | null;
  sla: ConsoleEnterpriseIsolationSla;
  createdAt: string;
  updatedAt: string;
}

export interface GetConsoleEnterpriseIsolationRequest {
  scope?: ConsoleEnterpriseIsolationScope;
  projectId?: string;
  environmentId?: string;
}

export interface TriggerConsoleEnterpriseIsolationRequest {
  scope?: ConsoleEnterpriseIsolationScope;
  projectId?: string;
  environmentId?: string;
  trigger?: ConsoleEnterpriseIsolationTrigger;
  reason: string;
  ticketId?: string;
}
