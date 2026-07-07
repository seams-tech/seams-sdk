import type { ConsoleEnvironment, ConsoleOrganization, ConsoleProject } from '../orgProjectEnv';

export interface GetConsoleOnboardingStateRequest {}

export type ConsoleOnboardingStep = 'organization' | 'project' | 'complete';
export type ConsoleOnboardingTelemetryOperation = 'state' | 'organization' | 'project';

export interface GetConsoleOnboardingTelemetryRequest {
  windowMinutes?: number;
}

export interface ConsoleOnboardingOrgInput {
  name: string;
  slug?: string;
}

export interface ConsoleOnboardingProjectInput {
  id?: string;
  name: string;
}

export interface CreateConsoleOnboardingOrganizationRequest {
  org: ConsoleOnboardingOrgInput;
}

export interface CreateConsoleOnboardingProjectRequest {
  project: ConsoleOnboardingProjectInput;
  environment?: {
    id?: string;
    name?: string;
  };
}

export interface ConsoleOnboardingState {
  orgId: string;
  organization: ConsoleOrganization | null;
  activeProjectCount: number;
  activeEnvironmentCount: number;
  activeApiKeyCount: number;
  hasOrganization: boolean;
  hasProject: boolean;
  hasEnvironment: boolean;
  hasApiKey: boolean;
  accountReady: boolean;
  organizationReady: boolean;
  billingReady: boolean;
  projectReady: boolean;
  onboardingComplete: boolean;
  currentStep: ConsoleOnboardingStep;
  complete: boolean;
  selectedProjectId: string | null;
  selectedEnvironmentId: string | null;
}

export interface ConsoleOnboardingOperationTelemetrySnapshot {
  operation: ConsoleOnboardingTelemetryOperation;
  requestCount: number;
  successCount: number;
  errorCount: number;
  errorRatePercent: number;
  latencyAvgMs: number;
  latencyP50Ms: number;
  latencyP95Ms: number;
  latencyMaxMs: number;
  slo: {
    p95LatencyMsThreshold: number;
    errorRatePercentThreshold: number;
    p95LatencyOk: boolean;
    errorRateOk: boolean;
  };
}

export type ConsoleOnboardingTelemetryAlertCode =
  | 'onboarding_latency_slo_breached'
  | 'onboarding_error_rate_slo_breached';

export interface ConsoleOnboardingTelemetryAlert {
  code: ConsoleOnboardingTelemetryAlertCode;
  operation: ConsoleOnboardingTelemetryOperation;
  severity: 'WARN' | 'CRITICAL';
  message: string;
}

export interface ConsoleOnboardingTelemetrySnapshot {
  orgId: string;
  generatedAt: string;
  windowMinutes: number;
  operations: ConsoleOnboardingOperationTelemetrySnapshot[];
  alerts: ConsoleOnboardingTelemetryAlert[];
}

export interface CreateConsoleOnboardingProjectResult {
  project: ConsoleProject;
  environment: ConsoleEnvironment;
  created: {
    project: boolean;
    environment: boolean;
  };
  state: ConsoleOnboardingState;
}

export interface CreateConsoleOnboardingOrganizationResult {
  organization: ConsoleOrganization;
  created: {
    organization: boolean;
    owner: boolean;
  };
  state: ConsoleOnboardingState;
}
