import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  normalizeConsoleFetchError,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export type DashboardOnboardingStep = 'organization' | 'project' | 'complete';
export type DashboardOnboardingTelemetryOperation = 'state' | 'organization' | 'project';
export type DashboardOnboardingTelemetryAlertCode =
  | 'onboarding_latency_slo_breached'
  | 'onboarding_error_rate_slo_breached';

export interface DashboardOnboardingState {
  orgId: string;
  organization: {
    id: string;
    name: string;
    slug: string;
    status: string;
  } | null;
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
  currentStep: DashboardOnboardingStep;
  complete: boolean;
  selectedProjectId: string | null;
  selectedEnvironmentId: string | null;
}

export interface DashboardOnboardingTelemetryOperationSnapshot {
  operation: DashboardOnboardingTelemetryOperation;
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

export interface DashboardOnboardingTelemetryAlert {
  code: DashboardOnboardingTelemetryAlertCode;
  operation: DashboardOnboardingTelemetryOperation;
  severity: 'WARN' | 'CRITICAL';
  message: string;
}

export interface DashboardOnboardingTelemetrySnapshot {
  orgId: string;
  generatedAt: string;
  windowMinutes: number;
  operations: DashboardOnboardingTelemetryOperationSnapshot[];
  alerts: DashboardOnboardingTelemetryAlert[];
}

export interface DashboardCreateOnboardingProjectInput {
  project: {
    id?: string;
    name: string;
  };
  environment?: {
    id?: string;
    name?: string;
  };
}

export interface DashboardCreateOnboardingOrganizationInput {
  org: {
    name: string;
    slug?: string;
  };
}

export interface DashboardCreateOnboardingProjectResult {
  project: {
    id: string;
    name: string;
    slug: string;
    status: string;
  };
  environment: {
    id: string;
    projectId: string;
    key: string;
    name: string;
    status: string;
  };
  created: {
    project: boolean;
    environment: boolean;
  };
  state: DashboardOnboardingState;
}

export interface DashboardCreateOnboardingOrganizationResult {
  organization: {
    id: string;
    name: string;
    slug: string;
    status: string;
  };
  created: {
    organization: boolean;
    owner: boolean;
  };
  state: DashboardOnboardingState;
}

interface ConsoleOnboardingStateResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  state?: unknown;
}

interface ConsoleOnboardingProjectResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  result?: unknown;
}

interface ConsoleOnboardingOrganizationResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  result?: unknown;
}

interface ConsoleOnboardingTelemetryResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  telemetry?: unknown;
}

export class DashboardConsoleApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(input: { status: number; code?: string; message: string }) {
    super(input.message);
    this.name = 'DashboardConsoleApiError';
    this.status = input.status;
    this.code = String(input.code || '').trim();
  }
}

function toTrimmedString(raw: unknown): string {
  return String(raw || '').trim();
}

function toSafeBoolean(raw: unknown): boolean {
  return raw === true;
}

function toSafeCount(raw: unknown): number {
  const count = Number(raw || 0);
  if (!Number.isFinite(count) || count < 0) return 0;
  return Math.floor(count);
}

function decodeOrganization(raw: unknown): DashboardOnboardingState['organization'] {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = toTrimmedString(row.id);
  if (!id) return null;
  return {
    id,
    name: toTrimmedString(row.name) || id,
    slug: toTrimmedString(row.slug),
    status: toTrimmedString(row.status) || 'ACTIVE',
  };
}

function decodeOnboardingState(raw: unknown): DashboardOnboardingState | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const orgId = toTrimmedString(row.orgId);
  if (!orgId) return null;
  const hasOrganization = toSafeBoolean(row.hasOrganization);
  const hasProject = toSafeBoolean(row.hasProject);
  const hasEnvironment = toSafeBoolean(row.hasEnvironment);
  const hasApiKey = toSafeBoolean(row.hasApiKey);
  const accountReady = row.accountReady === undefined ? true : toSafeBoolean(row.accountReady);
  const organizationReady =
    row.organizationReady === undefined ? hasOrganization : toSafeBoolean(row.organizationReady);
  const billingReady = toSafeBoolean(row.billingReady);
  const projectReady =
    row.projectReady === undefined ? hasProject && hasEnvironment : toSafeBoolean(row.projectReady);
  const complete = toSafeBoolean(row.complete);
  const onboardingComplete =
    row.onboardingComplete === undefined ? complete : toSafeBoolean(row.onboardingComplete);
  const rawCurrentStep = toTrimmedString(row.currentStep).toLowerCase();
  const currentStep: DashboardOnboardingStep =
    rawCurrentStep === 'organization' ||
    rawCurrentStep === 'project' ||
    rawCurrentStep === 'complete'
      ? (rawCurrentStep as DashboardOnboardingStep)
      : onboardingComplete
        ? 'complete'
        : !organizationReady
          ? 'organization'
          : 'project';
  return {
    orgId,
    organization: decodeOrganization(row.organization),
    activeProjectCount: toSafeCount(row.activeProjectCount),
    activeEnvironmentCount: toSafeCount(row.activeEnvironmentCount),
    activeApiKeyCount: toSafeCount(row.activeApiKeyCount),
    hasOrganization,
    hasProject,
    hasEnvironment,
    hasApiKey,
    accountReady,
    organizationReady,
    billingReady,
    projectReady,
    onboardingComplete,
    currentStep,
    complete,
    selectedProjectId: toTrimmedString(row.selectedProjectId) || null,
    selectedEnvironmentId: toTrimmedString(row.selectedEnvironmentId) || null,
  };
}

function decodeTelemetryOperation(raw: unknown): DashboardOnboardingTelemetryOperation {
  const operation = toTrimmedString(raw).toLowerCase();
  if (operation === 'organization') return 'organization';
  if (operation === 'project') return 'project';
  return 'state';
}

function decodeTelemetryOperationSnapshot(
  raw: unknown,
): DashboardOnboardingTelemetryOperationSnapshot | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const sloRaw = row.slo && typeof row.slo === 'object' && !Array.isArray(row.slo)
    ? (row.slo as Record<string, unknown>)
    : {};
  return {
    operation: decodeTelemetryOperation(row.operation),
    requestCount: toSafeCount(row.requestCount),
    successCount: toSafeCount(row.successCount),
    errorCount: toSafeCount(row.errorCount),
    errorRatePercent: Number(row.errorRatePercent || 0),
    latencyAvgMs: Number(row.latencyAvgMs || 0),
    latencyP50Ms: Number(row.latencyP50Ms || 0),
    latencyP95Ms: Number(row.latencyP95Ms || 0),
    latencyMaxMs: Number(row.latencyMaxMs || 0),
    slo: {
      p95LatencyMsThreshold: Number(sloRaw.p95LatencyMsThreshold || 0),
      errorRatePercentThreshold: Number(sloRaw.errorRatePercentThreshold || 0),
      p95LatencyOk: toSafeBoolean(sloRaw.p95LatencyOk),
      errorRateOk: toSafeBoolean(sloRaw.errorRateOk),
    },
  };
}

function decodeTelemetryAlert(raw: unknown): DashboardOnboardingTelemetryAlert | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const codeRaw = toTrimmedString(row.code) as DashboardOnboardingTelemetryAlertCode;
  const code: DashboardOnboardingTelemetryAlertCode =
    codeRaw === 'onboarding_error_rate_slo_breached'
      ? 'onboarding_error_rate_slo_breached'
      : 'onboarding_latency_slo_breached';
  const severityRaw = toTrimmedString(row.severity).toUpperCase();
  return {
    code,
    operation: decodeTelemetryOperation(row.operation),
    severity: severityRaw === 'CRITICAL' ? 'CRITICAL' : 'WARN',
    message: toTrimmedString(row.message),
  };
}

function decodeOnboardingTelemetry(raw: unknown): DashboardOnboardingTelemetrySnapshot | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const orgId = toTrimmedString(row.orgId);
  if (!orgId) return null;
  const operationsRaw = Array.isArray(row.operations) ? row.operations : [];
  const alertsRaw = Array.isArray(row.alerts) ? row.alerts : [];
  return {
    orgId,
    generatedAt: toTrimmedString(row.generatedAt),
    windowMinutes: Math.max(1, Number(row.windowMinutes || 15)),
    operations: operationsRaw
      .map((entry) => decodeTelemetryOperationSnapshot(entry))
      .filter((entry): entry is DashboardOnboardingTelemetryOperationSnapshot => entry !== null),
    alerts: alertsRaw
      .map((entry) => decodeTelemetryAlert(entry))
      .filter((entry): entry is DashboardOnboardingTelemetryAlert => entry !== null),
  };
}

function decodeCreateProjectResult(raw: unknown): DashboardCreateOnboardingProjectResult | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const state = decodeOnboardingState(row.state);
  const projectRow =
    row.project && typeof row.project === 'object' && !Array.isArray(row.project)
      ? (row.project as Record<string, unknown>)
      : null;
  const environmentRow =
    row.environment && typeof row.environment === 'object' && !Array.isArray(row.environment)
      ? (row.environment as Record<string, unknown>)
      : null;
  const createdRow =
    row.created && typeof row.created === 'object' && !Array.isArray(row.created)
      ? (row.created as Record<string, unknown>)
      : null;
  if (!state || !projectRow || !environmentRow || !createdRow) return null;
  const projectId = toTrimmedString(projectRow.id);
  const environmentId = toTrimmedString(environmentRow.id);
  if (!projectId || !environmentId) return null;
  return {
    project: {
      id: projectId,
      name: toTrimmedString(projectRow.name) || projectId,
      slug: toTrimmedString(projectRow.slug),
      status: toTrimmedString(projectRow.status) || 'ACTIVE',
    },
    environment: {
      id: environmentId,
      projectId: toTrimmedString(environmentRow.projectId),
      key: toTrimmedString(environmentRow.key),
      name: toTrimmedString(environmentRow.name) || environmentId,
      status: toTrimmedString(environmentRow.status) || 'ACTIVE',
    },
    created: {
      project: toSafeBoolean(createdRow.project),
      environment: toSafeBoolean(createdRow.environment),
    },
    state,
  };
}

function decodeCreateOrganizationResult(
  raw: unknown,
): DashboardCreateOnboardingOrganizationResult | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const state = decodeOnboardingState(row.state);
  const organizationRow =
    row.organization && typeof row.organization === 'object' && !Array.isArray(row.organization)
      ? (row.organization as Record<string, unknown>)
      : null;
  const createdRow =
    row.created && typeof row.created === 'object' && !Array.isArray(row.created)
      ? (row.created as Record<string, unknown>)
      : null;
  if (!state || !organizationRow || !createdRow) return null;
  const organizationId = toTrimmedString(organizationRow.id);
  if (!organizationId) return null;
  return {
    organization: {
      id: organizationId,
      name: toTrimmedString(organizationRow.name) || organizationId,
      slug: toTrimmedString(organizationRow.slug),
      status: toTrimmedString(organizationRow.status) || 'ACTIVE',
    },
    created: {
      organization: toSafeBoolean(createdRow.organization),
      owner: toSafeBoolean(createdRow.owner),
    },
    state,
  };
}

function buildApiError(response: Response, body: any, fallback: string): DashboardConsoleApiError {
  const code = toTrimmedString(body?.code);
  const apiMessage = toTrimmedString(body?.message);
  return new DashboardConsoleApiError({
    status: response.status,
    code,
    message: apiMessage || `${fallback} (${response.status})`,
  });
}

export function isDashboardConsoleApiErrorCode(error: unknown, code: string): boolean {
  if (!(error instanceof DashboardConsoleApiError)) return false;
  return error.code === code;
}

export async function getDashboardOnboardingState(): Promise<DashboardOnboardingState> {
  const base = requireConsoleBaseUrl();
  let response: Response;
  try {
    response = await fetch(`${base}/console/onboarding/state`, {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    });
  } catch (error: unknown) {
    throw normalizeConsoleFetchError({
      error,
      baseUrl: base,
      path: '/console/onboarding/state',
      operation: 'Onboarding state request',
    });
  }
  const body = (await parseConsoleJson(response)) as ConsoleOnboardingStateResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw buildApiError(response, body, 'Onboarding state request failed');
  }
  const state = decodeOnboardingState(body.state);
  if (!state) {
    throw new Error('Onboarding state response was invalid');
  }
  return state;
}

export async function createDashboardOnboardingProject(
  input: DashboardCreateOnboardingProjectInput,
): Promise<DashboardCreateOnboardingProjectResult> {
  const base = requireConsoleBaseUrl();
  let response: Response;
  try {
    response = await fetch(`${base}/console/onboarding/project`, {
      method: 'POST',
      headers: buildConsoleJsonHeaders(),
      credentials: 'include',
      cache: 'no-store',
      body: JSON.stringify(input),
    });
  } catch (error: unknown) {
    throw normalizeConsoleFetchError({
      error,
      baseUrl: base,
      path: '/console/onboarding/project',
      operation: 'Onboarding project request',
    });
  }
  const body = (await parseConsoleJson(response)) as ConsoleOnboardingProjectResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw buildApiError(response, body, 'Onboarding project request failed');
  }
  const result = decodeCreateProjectResult(body.result);
  if (!result) {
    throw new Error('Onboarding project response was invalid');
  }
  return result;
}

export async function createDashboardOnboardingOrganization(
  input: DashboardCreateOnboardingOrganizationInput,
): Promise<DashboardCreateOnboardingOrganizationResult> {
  const base = requireConsoleBaseUrl();
  let response: Response;
  try {
    response = await fetch(`${base}/console/onboarding/organization`, {
      method: 'POST',
      headers: buildConsoleJsonHeaders(),
      credentials: 'include',
      cache: 'no-store',
      body: JSON.stringify(input),
    });
  } catch (error: unknown) {
    throw normalizeConsoleFetchError({
      error,
      baseUrl: base,
      path: '/console/onboarding/organization',
      operation: 'Onboarding organization request',
    });
  }
  const body = (await parseConsoleJson(response)) as ConsoleOnboardingOrganizationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw buildApiError(response, body, 'Onboarding organization request failed');
  }
  const result = decodeCreateOrganizationResult(body.result);
  if (!result) {
    throw new Error('Onboarding organization response was invalid');
  }
  return result;
}

export async function getDashboardOnboardingTelemetry(input?: {
  windowMinutes?: number;
}): Promise<DashboardOnboardingTelemetrySnapshot> {
  const base = requireConsoleBaseUrl();
  const url = new URL(`${base}/console/onboarding/telemetry`);
  if (Number.isFinite(Number(input?.windowMinutes)) && Number(input?.windowMinutes) > 0) {
    url.searchParams.set('windowMinutes', String(Math.floor(Number(input?.windowMinutes))));
  }
  let response: Response;
  try {
    response = await fetch(url.toString(), {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    });
  } catch (error: unknown) {
    throw normalizeConsoleFetchError({
      error,
      baseUrl: base,
      path: '/console/onboarding/telemetry',
      operation: 'Onboarding telemetry request',
    });
  }
  const body = (await parseConsoleJson(response)) as ConsoleOnboardingTelemetryResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw buildApiError(response, body, 'Onboarding telemetry request failed');
  }
  const telemetry = decodeOnboardingTelemetry(body.telemetry);
  if (!telemetry) {
    throw new Error('Onboarding telemetry response was invalid');
  }
  return telemetry;
}
