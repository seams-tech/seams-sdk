import type { ConsoleApiKey, ConsoleApiKeyService } from '../apiKeys';
import { type ConsoleBillingService } from '../billing';
import { normalizeLogger, type Logger } from '../../core/logger';
import type {
  ConsoleEnvironment,
  ConsoleOrgProjectEnvService,
  ConsoleOrganization,
  ConsoleProject,
} from '../orgProjectEnv';
import { isConsoleTeamRbacError, type ConsoleTeamRbacService } from '../teamRbac';
import { ConsoleOnboardingError } from './errors';
import type {
  ConsoleOnboardingState,
  ConsoleOnboardingStep,
  ConsoleOnboardingTelemetryAlert,
  ConsoleOnboardingTelemetryOperation,
  ConsoleOnboardingTelemetrySnapshot,
  ConsoleOnboardingOperationTelemetrySnapshot,
  CreateConsoleOnboardingOrganizationRequest,
  CreateConsoleOnboardingOrganizationResult,
  CreateConsoleOnboardingProjectRequest,
  CreateConsoleOnboardingProjectResult,
  GetConsoleOnboardingStateRequest,
  GetConsoleOnboardingTelemetryRequest,
} from './types';

export interface ConsoleOnboardingContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
  projectId?: string;
  environmentId?: string;
}

export interface ConsoleOnboardingService {
  getOnboardingState(
    ctx: ConsoleOnboardingContext,
    request?: GetConsoleOnboardingStateRequest,
  ): Promise<ConsoleOnboardingState>;
  getOnboardingTelemetry(
    ctx: ConsoleOnboardingContext,
    request?: GetConsoleOnboardingTelemetryRequest,
  ): Promise<ConsoleOnboardingTelemetrySnapshot>;
  createOnboardingOrganization(
    ctx: ConsoleOnboardingContext,
    request: CreateConsoleOnboardingOrganizationRequest,
  ): Promise<CreateConsoleOnboardingOrganizationResult>;
  createOnboardingProject(
    ctx: ConsoleOnboardingContext,
    request: CreateConsoleOnboardingProjectRequest,
  ): Promise<CreateConsoleOnboardingProjectResult>;
}

export interface InMemoryConsoleOnboardingServiceOptions {
  orgProjectEnv: ConsoleOrgProjectEnvService;
  apiKeys: ConsoleApiKeyService;
  billing?: ConsoleBillingService | null;
  teamRbac?: ConsoleTeamRbacService | null;
  logger?: Logger | null;
  telemetry?: {
    windowMinutes?: number;
    retentionMinutes?: number;
    p95LatencyMs?: Partial<Record<ConsoleOnboardingTelemetryOperation, number>>;
    errorRatePercentThreshold?: number;
  };
}

interface ResolveProjectInput {
  id?: string;
  name: string;
}

interface ResolveEnvironmentInput {
  id?: string;
  projectId?: string;
  key: 'dev' | 'staging' | 'prod';
  name?: string;
}

function normalizeString(raw: unknown): string {
  return String(raw || '').trim();
}

function toOrgProjectEnvContext(ctx: ConsoleOnboardingContext): {
  orgId: string;
  actorUserId: string;
  roles: string[];
  projectId?: string;
  environmentId?: string;
} {
  return {
    orgId: ctx.orgId,
    actorUserId: ctx.actorUserId,
    roles: ctx.roles,
    ...(ctx.projectId ? { projectId: ctx.projectId } : {}),
    ...(ctx.environmentId ? { environmentId: ctx.environmentId } : {}),
  };
}

function toApiKeyContext(ctx: ConsoleOnboardingContext): {
  orgId: string;
  actorUserId: string;
  roles: string[];
} {
  return {
    orgId: ctx.orgId,
    actorUserId: ctx.actorUserId,
    roles: ctx.roles,
  };
}

function toBillingContext(ctx: ConsoleOnboardingContext): {
  orgId: string;
  actorUserId: string;
  roles: string[];
} {
  return {
    orgId: ctx.orgId,
    actorUserId: ctx.actorUserId,
    roles: ctx.roles,
  };
}

function toTeamRbacContext(ctx: ConsoleOnboardingContext): {
  orgId: string;
  actorUserId: string;
  roles: string[];
  projectId?: string;
} {
  return {
    orgId: ctx.orgId,
    actorUserId: ctx.actorUserId,
    roles: ctx.roles,
    ...(ctx.projectId ? { projectId: ctx.projectId } : {}),
  };
}

function isActiveStatus(value: unknown): boolean {
  return normalizeString(value).toUpperCase() === 'ACTIVE';
}

function readErrorCode(error: unknown): string {
  if (!error || typeof error !== 'object') return '';
  if (!('code' in error)) return '';
  return normalizeString((error as { code?: unknown }).code);
}

function resolveCurrentStep(input: {
  organizationReady: boolean;
  projectReady: boolean;
}): ConsoleOnboardingStep {
  if (!input.organizationReady) return 'organization';
  if (!input.projectReady) return 'project';
  return 'complete';
}

function requireActiveProject(project: ConsoleProject | undefined, projectId: string): ConsoleProject {
  if (!project) {
    throw new ConsoleOnboardingError(
      'project_not_found',
      404,
      `Project ${projectId} was not found for onboarding`,
    );
  }
  if (!isActiveStatus(project.status)) {
    throw new ConsoleOnboardingError(
      'project_archived',
      409,
      `Project ${projectId} is archived and cannot be used for onboarding`,
    );
  }
  return project;
}

function requireActiveEnvironment(
  environment: ConsoleEnvironment | undefined,
  environmentId: string,
): ConsoleEnvironment {
  if (!environment) {
    throw new ConsoleOnboardingError(
      'environment_not_found',
      404,
      `Environment ${environmentId} was not found for onboarding`,
    );
  }
  if (!isActiveStatus(environment.status)) {
    throw new ConsoleOnboardingError(
      'environment_archived',
      409,
      `Environment ${environmentId} is archived and cannot be used for onboarding`,
    );
  }
  return environment;
}

const DEFAULT_TELEMETRY_WINDOW_MINUTES = 15;
const DEFAULT_TELEMETRY_RETENTION_MINUTES = 24 * 60;
const MIN_TELEMETRY_WINDOW_MINUTES = 1;
const MAX_TELEMETRY_WINDOW_MINUTES = 24 * 60;
const DEFAULT_TELEMETRY_ERROR_RATE_THRESHOLD_PERCENT = 5;
const CRITICAL_BREACH_MULTIPLIER = 2;
const ONBOARDING_TELEMETRY_OPERATIONS: ConsoleOnboardingTelemetryOperation[] = [
  'state',
  'organization',
  'project',
];

const DEFAULT_TELEMETRY_P95_TARGETS: Record<ConsoleOnboardingTelemetryOperation, number> = {
  state: 400,
  organization: 1200,
  project: 1800,
};

interface OnboardingTelemetrySample {
  atMs: number;
  durationMs: number;
  ok: boolean;
  errorCode?: string;
}

interface OrgOnboardingTelemetryStore {
  samples: Record<ConsoleOnboardingTelemetryOperation, OnboardingTelemetrySample[]>;
  lastAlertSignature: string;
}

function coerceIntegerInRange(input: {
  value: number | undefined;
  fallback: number;
  min: number;
  max: number;
}): number {
  const numeric = Number(input.value);
  if (!Number.isFinite(numeric) || !Number.isInteger(numeric)) return input.fallback;
  if (numeric < input.min || numeric > input.max) return input.fallback;
  return numeric;
}

function coercePositiveNumber(value: number | undefined, fallback: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return fallback;
  return numeric;
}

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}

function percentileFromSorted(sorted: number[], percentile: number): number {
  if (sorted.length === 0) return 0;
  if (sorted.length === 1) return sorted[0];
  const p = Math.max(0, Math.min(1, percentile));
  const index = Math.ceil(sorted.length * p) - 1;
  const bounded = Math.max(0, Math.min(sorted.length - 1, index));
  return sorted[bounded];
}

function createEmptyTelemetrySamples(): Record<ConsoleOnboardingTelemetryOperation, OnboardingTelemetrySample[]> {
  return {
    state: [],
    organization: [],
    project: [],
  };
}

function telemetryDurationMs(startMs: number, endMs: number): number {
  const duration = endMs - startMs;
  if (!Number.isFinite(duration) || duration < 0) return 0;
  return duration;
}

function buildOperationTelemetrySnapshot(input: {
  operation: ConsoleOnboardingTelemetryOperation;
  samples: OnboardingTelemetrySample[];
  nowMs: number;
  windowMinutes: number;
  p95LatencyMsThreshold: number;
  errorRatePercentThreshold: number;
}): ConsoleOnboardingOperationTelemetrySnapshot {
  const windowMs = input.windowMinutes * 60_000;
  const floorMs = input.nowMs - windowMs;
  const windowSamples = input.samples.filter((entry) => entry.atMs >= floorMs);
  const requestCount = windowSamples.length;
  const successCount = windowSamples.filter((entry) => entry.ok).length;
  const errorCount = requestCount - successCount;
  const errorRatePercent = requestCount > 0 ? round2((errorCount / requestCount) * 100) : 0;
  const latencies = windowSamples.map((entry) => entry.durationMs).sort((a, b) => a - b);
  const latencyMaxMs = latencies.length > 0 ? latencies[latencies.length - 1] : 0;
  const latencyAvgMs =
    latencies.length > 0
      ? round2(latencies.reduce((sum, value) => sum + value, 0) / latencies.length)
      : 0;
  const latencyP50Ms = round2(percentileFromSorted(latencies, 0.5));
  const latencyP95Ms = round2(percentileFromSorted(latencies, 0.95));
  const p95LatencyOk = latencyP95Ms <= input.p95LatencyMsThreshold;
  const errorRateOk = errorRatePercent <= input.errorRatePercentThreshold;
  return {
    operation: input.operation,
    requestCount,
    successCount,
    errorCount,
    errorRatePercent,
    latencyAvgMs,
    latencyP50Ms,
    latencyP95Ms,
    latencyMaxMs,
    slo: {
      p95LatencyMsThreshold: input.p95LatencyMsThreshold,
      errorRatePercentThreshold: input.errorRatePercentThreshold,
      p95LatencyOk,
      errorRateOk,
    },
  };
}

function buildSloAlerts(input: {
  operation: ConsoleOnboardingTelemetryOperation;
  snapshot: ConsoleOnboardingOperationTelemetrySnapshot;
}): ConsoleOnboardingTelemetryAlert[] {
  if (input.snapshot.requestCount <= 0) return [];
  const alerts: ConsoleOnboardingTelemetryAlert[] = [];
  const latencyThreshold = input.snapshot.slo.p95LatencyMsThreshold;
  const errorRateThreshold = input.snapshot.slo.errorRatePercentThreshold;

  if (!input.snapshot.slo.p95LatencyOk) {
    const severity: 'WARN' | 'CRITICAL' =
      input.snapshot.latencyP95Ms >
      latencyThreshold * CRITICAL_BREACH_MULTIPLIER
        ? 'CRITICAL'
        : 'WARN';
    alerts.push({
      code: 'onboarding_latency_slo_breached',
      operation: input.operation,
      severity,
      message: `p95 latency ${input.snapshot.latencyP95Ms}ms exceeds SLO target ${latencyThreshold}ms`,
    });
  }
  if (!input.snapshot.slo.errorRateOk) {
    const severity: 'WARN' | 'CRITICAL' =
      input.snapshot.errorRatePercent >
      errorRateThreshold * CRITICAL_BREACH_MULTIPLIER
        ? 'CRITICAL'
        : 'WARN';
    alerts.push({
      code: 'onboarding_error_rate_slo_breached',
      operation: input.operation,
      severity,
      message: `Error rate ${input.snapshot.errorRatePercent}% exceeds SLO target ${errorRateThreshold}%`,
    });
  }
  return alerts;
}

function alertSignature(alerts: ConsoleOnboardingTelemetryAlert[]): string {
  if (alerts.length === 0) return '';
  return alerts
    .map((entry) => `${entry.code}:${entry.operation}:${entry.severity}`)
    .sort()
    .join('|');
}

export function createInMemoryConsoleOnboardingService(
  opts: InMemoryConsoleOnboardingServiceOptions,
): ConsoleOnboardingService {
  const orgProjectEnv = opts.orgProjectEnv;
  const apiKeys = opts.apiKeys;
  const billing = opts.billing ?? null;
  const teamRbac = opts.teamRbac ?? null;
  const logger = normalizeLogger(opts.logger);
  const telemetryWindowMinutes = coerceIntegerInRange({
    value: opts.telemetry?.windowMinutes,
    fallback: DEFAULT_TELEMETRY_WINDOW_MINUTES,
    min: MIN_TELEMETRY_WINDOW_MINUTES,
    max: MAX_TELEMETRY_WINDOW_MINUTES,
  });
  const telemetryRetentionMinutes = coerceIntegerInRange({
    value: opts.telemetry?.retentionMinutes,
    fallback: DEFAULT_TELEMETRY_RETENTION_MINUTES,
    min: telemetryWindowMinutes,
    max: MAX_TELEMETRY_WINDOW_MINUTES,
  });
  const telemetryErrorRatePercentThreshold = coercePositiveNumber(
    opts.telemetry?.errorRatePercentThreshold,
    DEFAULT_TELEMETRY_ERROR_RATE_THRESHOLD_PERCENT,
  );
  const telemetryP95LatencyMsThresholds: Record<ConsoleOnboardingTelemetryOperation, number> = {
    state: coercePositiveNumber(
      opts.telemetry?.p95LatencyMs?.state,
      DEFAULT_TELEMETRY_P95_TARGETS.state,
    ),
    organization: coercePositiveNumber(
      opts.telemetry?.p95LatencyMs?.organization,
      DEFAULT_TELEMETRY_P95_TARGETS.organization,
    ),
    project: coercePositiveNumber(
      opts.telemetry?.p95LatencyMs?.project,
      DEFAULT_TELEMETRY_P95_TARGETS.project,
    ),
  };
  const telemetryByOrg = new Map<string, OrgOnboardingTelemetryStore>();
  if (!orgProjectEnv) {
    throw new Error('Missing orgProjectEnv dependency for onboarding service');
  }
  if (!apiKeys) {
    throw new Error('Missing apiKeys dependency for onboarding service');
  }

  function resolveTelemetryWindowMinutes(
    request: GetConsoleOnboardingTelemetryRequest | undefined,
  ): number {
    const requestedWindow = request?.windowMinutes;
    return coerceIntegerInRange({
      value: requestedWindow,
      fallback: telemetryWindowMinutes,
      min: MIN_TELEMETRY_WINDOW_MINUTES,
      max: MAX_TELEMETRY_WINDOW_MINUTES,
    });
  }

  function resolveOrgTelemetryStore(orgId: string): OrgOnboardingTelemetryStore {
    const existing = telemetryByOrg.get(orgId);
    if (existing) return existing;
    const created: OrgOnboardingTelemetryStore = {
      samples: createEmptyTelemetrySamples(),
      lastAlertSignature: '',
    };
    telemetryByOrg.set(orgId, created);
    return created;
  }

  function pruneTelemetrySamples(store: OrgOnboardingTelemetryStore, nowMs: number): void {
    const retentionFloorMs = nowMs - telemetryRetentionMinutes * 60_000;
    for (const operation of ONBOARDING_TELEMETRY_OPERATIONS) {
      store.samples[operation] = store.samples[operation].filter(
        (entry) => entry.atMs >= retentionFloorMs,
      );
    }
  }

  function buildTelemetrySnapshot(input: {
    orgId: string;
    nowMs: number;
    windowMinutes: number;
  }): ConsoleOnboardingTelemetrySnapshot {
    const store = resolveOrgTelemetryStore(input.orgId);
    pruneTelemetrySamples(store, input.nowMs);
    const operations: ConsoleOnboardingOperationTelemetrySnapshot[] =
      ONBOARDING_TELEMETRY_OPERATIONS.map((operation) =>
        buildOperationTelemetrySnapshot({
          operation,
          samples: store.samples[operation],
          nowMs: input.nowMs,
          windowMinutes: input.windowMinutes,
          p95LatencyMsThreshold: telemetryP95LatencyMsThresholds[operation],
          errorRatePercentThreshold: telemetryErrorRatePercentThreshold,
        }),
      );
    const alerts = operations.flatMap((snapshot) =>
      buildSloAlerts({
        operation: snapshot.operation,
        snapshot,
      }),
    );
    return {
      orgId: input.orgId,
      generatedAt: new Date(input.nowMs).toISOString(),
      windowMinutes: input.windowMinutes,
      operations,
      alerts,
    };
  }

  function logTelemetryAlerts(input: {
    orgId: string;
    snapshot: ConsoleOnboardingTelemetrySnapshot;
    store: OrgOnboardingTelemetryStore;
  }): void {
    const nextSignature = alertSignature(input.snapshot.alerts);
    if (nextSignature === input.store.lastAlertSignature) return;

    if (!nextSignature && input.store.lastAlertSignature) {
      logger.info('[console-onboarding][telemetry] onboarding SLO alerts resolved', {
        orgId: input.orgId,
      });
      input.store.lastAlertSignature = '';
      return;
    }

    for (const alert of input.snapshot.alerts) {
      logger.warn('[console-onboarding][telemetry] onboarding SLO alert', {
        orgId: input.orgId,
        code: alert.code,
        operation: alert.operation,
        severity: alert.severity,
        message: alert.message,
      });
    }
    input.store.lastAlertSignature = nextSignature;
  }

  function recordTelemetrySample(input: {
    ctx: ConsoleOnboardingContext;
    operation: ConsoleOnboardingTelemetryOperation;
    startedAtMs: number;
    endedAtMs: number;
    ok: boolean;
    errorCode?: string;
  }): void {
    const store = resolveOrgTelemetryStore(input.ctx.orgId);
    pruneTelemetrySamples(store, input.endedAtMs);
    store.samples[input.operation].push({
      atMs: input.endedAtMs,
      durationMs: telemetryDurationMs(input.startedAtMs, input.endedAtMs),
      ok: input.ok,
      ...(input.errorCode ? { errorCode: input.errorCode } : {}),
    });
    const snapshot = buildTelemetrySnapshot({
      orgId: input.ctx.orgId,
      nowMs: input.endedAtMs,
      windowMinutes: telemetryWindowMinutes,
    });
    logTelemetryAlerts({
      orgId: input.ctx.orgId,
      snapshot,
      store,
    });
  }

  async function withTelemetry<T>(input: {
    ctx: ConsoleOnboardingContext;
    operation: ConsoleOnboardingTelemetryOperation;
    run: () => Promise<T>;
  }): Promise<T> {
    const startedAtMs = Date.now();
    try {
      const result = await input.run();
      recordTelemetrySample({
        ctx: input.ctx,
        operation: input.operation,
        startedAtMs,
        endedAtMs: Date.now(),
        ok: true,
      });
      return result;
    } catch (error: unknown) {
      recordTelemetrySample({
        ctx: input.ctx,
        operation: input.operation,
        startedAtMs,
        endedAtMs: Date.now(),
        ok: false,
        errorCode: readErrorCode(error) || 'unknown_error',
      });
      throw error;
    }
  }

  async function ensureOwner(ctx: ConsoleOnboardingContext): Promise<{ created: boolean }> {
    if (!teamRbac) return { created: false };
    try {
      const teamCtx = toTeamRbacContext(ctx);
      const actorUserId = normalizeString(ctx.actorUserId);
      const beforeMembers = await teamRbac.listMembers(teamCtx, { status: 'ACTIVE' });
      const actorHadOwnerBefore = beforeMembers.some(
        (member) =>
          normalizeString(member.userId) === actorUserId &&
          member.roles.some((role) => role.scope === 'ORG' && role.role === 'owner'),
      );
      const member = await teamRbac.bootstrapOwner(teamCtx);
      const hasOwner = member.roles.some((role) => role.scope === 'ORG' && role.role === 'owner');
      return { created: hasOwner && !actorHadOwnerBefore };
    } catch (error: unknown) {
      if (isConsoleTeamRbacError(error)) {
        throw new ConsoleOnboardingError(error.code, error.status, error.message, error.details);
      }
      throw error;
    }
  }

  async function upsertOrganizationProfile(
    ctx: ConsoleOnboardingContext,
    request: {
      name?: string;
      slug?: string;
    },
  ): Promise<{ organization: ConsoleOrganization; created: boolean }> {
    const orgCtx = toOrgProjectEnvContext(ctx);
    let existing: ConsoleOrganization | null = null;
    try {
      existing = await orgProjectEnv.getOrganization(orgCtx);
    } catch (error: unknown) {
      if (readErrorCode(error) !== 'organization_not_found') {
        throw error;
      }
    }
    const organization = await orgProjectEnv.upsertOrganization(orgCtx, request);
    return {
      organization,
      created: existing == null,
    };
  }

  async function resolveState(ctx: ConsoleOnboardingContext): Promise<{
    organization: ConsoleOrganization | null;
    activeProjects: ConsoleProject[];
    activeEnvironments: ConsoleEnvironment[];
    activeApiKeys: ConsoleApiKey[];
    state: ConsoleOnboardingState;
  }> {
    const orgCtx = toOrgProjectEnvContext(ctx);
    const apiCtx = toApiKeyContext(ctx);
    let organization: ConsoleOrganization | null = null;
    try {
      organization = await orgProjectEnv.getOrganization(orgCtx);
    } catch (error: unknown) {
      if (readErrorCode(error) !== 'organization_not_found') {
        throw error;
      }
    }

    const projects = await orgProjectEnv.listProjects(orgCtx);
    const environments = await orgProjectEnv.listEnvironments(orgCtx);
    const keyRows = await apiKeys.listApiKeys(apiCtx);
    const paymentMethods = billing ? await billing.listPaymentMethods(toBillingContext(ctx)) : [];

    const activeProjects = projects.filter((entry) => isActiveStatus(entry.status));
    const activeEnvironments = environments.filter((entry) => isActiveStatus(entry.status));
    const activeApiKeys = keyRows.filter((entry) => isActiveStatus(entry.status));

    const requestedProjectId = normalizeString(ctx.projectId);
    const requestedEnvironmentId = normalizeString(ctx.environmentId);
    const selectedProjectId =
      activeProjects.find((entry) => entry.id === requestedProjectId)?.id ||
      activeProjects[0]?.id ||
      null;
    const selectedEnvironmentId =
      activeEnvironments.find((entry) => entry.id === requestedEnvironmentId)?.id ||
      (selectedProjectId
        ? activeEnvironments.find((entry) => entry.projectId === selectedProjectId)?.id
        : undefined) ||
      activeEnvironments[0]?.id ||
      null;

    const hasOrganization = Boolean(normalizeString(organization?.id));
    const hasProject = activeProjects.length > 0;
    const hasEnvironment = activeEnvironments.length > 0;
    const hasApiKey = activeApiKeys.length > 0;

    const accountReady = true;
    const organizationReady = hasOrganization;
    const billingReady = paymentMethods.length > 0;
    const projectReady = hasProject && hasEnvironment;
    const onboardingComplete = accountReady && organizationReady && projectReady;
    const currentStep = resolveCurrentStep({
      organizationReady,
      projectReady,
    });

    const state: ConsoleOnboardingState = {
      orgId: ctx.orgId,
      organization,
      activeProjectCount: activeProjects.length,
      activeEnvironmentCount: activeEnvironments.length,
      activeApiKeyCount: activeApiKeys.length,
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
      complete: hasOrganization && hasProject && hasEnvironment && hasApiKey,
      selectedProjectId,
      selectedEnvironmentId,
    };

    return {
      organization,
      activeProjects,
      activeEnvironments,
      activeApiKeys,
      state,
    };
  }

  async function ensureProject(
    ctx: ConsoleOnboardingContext,
    request: ResolveProjectInput,
  ): Promise<{ project: ConsoleProject; created: boolean }> {
    const orgCtx = toOrgProjectEnvContext(ctx);
    const requestedProjectId = normalizeString(request.id);
    const existingProjects = await orgProjectEnv.listProjects(orgCtx);
    if (requestedProjectId) {
      const existing = existingProjects.find((entry) => entry.id === requestedProjectId);
      if (existing) {
        return {
          project: requireActiveProject(existing, requestedProjectId),
          created: false,
        };
      }
    }

    const liveEnvironmentsEnabled = billing
      ? (await billing.listPaymentMethods(toBillingContext(ctx))).length > 0
      : false;

    try {
      const createdProject = await orgProjectEnv.createProject(orgCtx, {
        ...(requestedProjectId ? { id: requestedProjectId } : {}),
        name: request.name,
        liveEnvironmentsEnabled,
      });
      return {
        project: createdProject,
        created: true,
      };
    } catch (error: unknown) {
      const code = readErrorCode(error);
      if (code === 'project_already_exists' && requestedProjectId) {
        const projects = await orgProjectEnv.listProjects(orgCtx);
        const existing = projects.find((entry) => entry.id === requestedProjectId);
        return {
          project: requireActiveProject(existing, requestedProjectId),
          created: false,
        };
      }
      throw error;
    }
  }

  async function ensureEnvironment(
    ctx: ConsoleOnboardingContext,
    project: ConsoleProject,
    request: ResolveEnvironmentInput,
  ): Promise<{ environment: ConsoleEnvironment; created: boolean }> {
    const orgCtx = toOrgProjectEnvContext(ctx);
    const requestedProjectId = normalizeString(request.projectId);
    if (requestedProjectId && requestedProjectId !== project.id) {
      throw new ConsoleOnboardingError(
        'invalid_body',
        400,
        'environment.projectId must match the resolved onboarding project',
      );
    }

    const requestedEnvironmentId = normalizeString(request.id);
    const existingEnvironments = await orgProjectEnv.listEnvironments(orgCtx, {
      projectId: project.id,
    });
    if (requestedEnvironmentId) {
      const existing = existingEnvironments.find((entry) => entry.id === requestedEnvironmentId);
      if (existing) {
        return {
          environment: requireActiveEnvironment(existing, requestedEnvironmentId),
          created: false,
        };
      }
      const existingByKey = existingEnvironments.find(
        (entry) => entry.key === request.key && isActiveStatus(entry.status),
      );
      if (existingByKey) {
        return {
          environment: existingByKey,
          created: false,
        };
      }
    } else {
      const existingByKey = existingEnvironments.find(
        (entry) => entry.key === request.key && isActiveStatus(entry.status),
      );
      if (existingByKey) {
        return {
          environment: existingByKey,
          created: false,
        };
      }
    }

    try {
      const createdEnvironment = await orgProjectEnv.createEnvironment(orgCtx, {
        ...(requestedEnvironmentId ? { id: requestedEnvironmentId } : {}),
        projectId: project.id,
        key: request.key,
        ...(request.name ? { name: request.name } : {}),
      });
      return {
        environment: createdEnvironment,
        created: true,
      };
    } catch (error: unknown) {
      const code = readErrorCode(error);
      if (code === 'environment_already_exists' || code === 'environment_key_conflict') {
        const environments = await orgProjectEnv.listEnvironments(orgCtx, {
          projectId: project.id,
        });
        if (requestedEnvironmentId) {
          const existing = environments.find((entry) => entry.id === requestedEnvironmentId);
          if (existing) {
            return {
              environment: requireActiveEnvironment(existing, requestedEnvironmentId),
              created: false,
            };
          }
          const existingByKey = environments.find(
            (entry) => entry.key === request.key && isActiveStatus(entry.status),
          );
          if (existingByKey) {
            return {
              environment: existingByKey,
              created: false,
            };
          }
        }
        const existingByKey = environments.find(
          (entry) => entry.key === request.key && isActiveStatus(entry.status),
        );
        if (existingByKey) {
          return {
            environment: existingByKey,
            created: false,
          };
        }
      }
      throw error;
    }
  }

  return {
    async getOnboardingState(
      ctx: ConsoleOnboardingContext,
      _request: GetConsoleOnboardingStateRequest = {},
    ): Promise<ConsoleOnboardingState> {
      return withTelemetry({
        ctx,
        operation: 'state',
        run: async () => (await resolveState(ctx)).state,
      });
    },

    async getOnboardingTelemetry(
      ctx: ConsoleOnboardingContext,
      request: GetConsoleOnboardingTelemetryRequest = {},
    ): Promise<ConsoleOnboardingTelemetrySnapshot> {
      const nowMs = Date.now();
      return buildTelemetrySnapshot({
        orgId: ctx.orgId,
        nowMs,
        windowMinutes: resolveTelemetryWindowMinutes(request),
      });
    },

    async createOnboardingOrganization(
      ctx: ConsoleOnboardingContext,
      request: CreateConsoleOnboardingOrganizationRequest,
    ): Promise<CreateConsoleOnboardingOrganizationResult> {
      return withTelemetry({
        ctx,
        operation: 'organization',
        run: async () => {
          const owner = await ensureOwner(ctx);
          const { organization, created } = await upsertOrganizationProfile(ctx, request.org);
          return {
            organization,
            created: {
              organization: created,
              owner: owner.created,
            },
            state: (await resolveState(ctx)).state,
          };
        },
      });
    },

    async createOnboardingProject(
      ctx: ConsoleOnboardingContext,
      request: CreateConsoleOnboardingProjectRequest,
    ): Promise<CreateConsoleOnboardingProjectResult> {
      return withTelemetry({
        ctx,
        operation: 'project',
        run: async () => {
          const currentState = (await resolveState(ctx)).state;
          if (!currentState.organizationReady) {
            throw new ConsoleOnboardingError(
              'organization_required',
              409,
              'Organization step must be completed before creating a project',
            );
          }
          await ensureOwner(ctx);
          const { project, created: createdProject } = await ensureProject(ctx, request.project);
          const { environment, created: createdEnvironment } = await ensureEnvironment(
            ctx,
            project,
            {
              ...(request.environment?.id ? { id: request.environment.id } : {}),
              projectId: project.id,
              key: 'dev',
              ...(request.environment?.name ? { name: request.environment.name } : {}),
            },
          );
          return {
            project,
            environment,
            created: {
              project: createdProject,
              environment: createdEnvironment,
            },
            state: (await resolveState(ctx)).state,
          };
        },
      });
    },
  };
}
