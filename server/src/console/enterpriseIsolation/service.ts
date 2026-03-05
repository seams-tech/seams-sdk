import type {
  ConsoleEnterpriseIsolationScope,
  ConsoleEnterpriseIsolationState,
  GetConsoleEnterpriseIsolationRequest,
  TriggerConsoleEnterpriseIsolationRequest,
} from './types';

export interface ConsoleEnterpriseIsolationContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
  projectId?: string;
  environmentId?: string;
}

export interface ConsoleEnterpriseIsolationService {
  getIsolationState(
    ctx: ConsoleEnterpriseIsolationContext,
    request?: GetConsoleEnterpriseIsolationRequest,
  ): Promise<ConsoleEnterpriseIsolationState>;
  triggerIsolation(
    ctx: ConsoleEnterpriseIsolationContext,
    request: TriggerConsoleEnterpriseIsolationRequest,
  ): Promise<ConsoleEnterpriseIsolationState>;
}

export interface InMemoryConsoleEnterpriseIsolationServiceOptions {
  now?: () => Date;
}

const DEFAULT_SLA = {
  availabilityTargetPercent: '99.95',
  rpoMinutes: 15,
  rtoHours: 4,
} as const;

function toIso(date: Date): string {
  return date.toISOString();
}

function normalizeString(value: unknown): string | null {
  const out = String(value || '').trim();
  return out || null;
}

function toScopeKey(orgId: string, scope: ConsoleEnterpriseIsolationScope, projectId?: string, environmentId?: string): string {
  const project = normalizeString(projectId) || '-';
  const environment = normalizeString(environmentId) || '-';
  return `${orgId}:${scope}:${project}:${environment}`;
}

function cloneState(input: ConsoleEnterpriseIsolationState): ConsoleEnterpriseIsolationState {
  return {
    orgId: input.orgId,
    scope: input.scope,
    projectId: input.projectId,
    environmentId: input.environmentId,
    mode: input.mode,
    status: input.status,
    trigger: input.trigger,
    requestedByUserId: input.requestedByUserId,
    requestedAt: input.requestedAt,
    activatedAt: input.activatedAt,
    reason: input.reason,
    ticketId: input.ticketId,
    sla: {
      availabilityTargetPercent: input.sla.availabilityTargetPercent,
      rpoMinutes: input.sla.rpoMinutes,
      rtoHours: input.sla.rtoHours,
    },
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
  };
}

export function createInMemoryConsoleEnterpriseIsolationService(
  opts: InMemoryConsoleEnterpriseIsolationServiceOptions = {},
): ConsoleEnterpriseIsolationService {
  const now = opts.now || (() => new Date());
  const states = new Map<string, ConsoleEnterpriseIsolationState>();

  function resolveScopeFromRequest(
    request: GetConsoleEnterpriseIsolationRequest | TriggerConsoleEnterpriseIsolationRequest | undefined,
  ): {
    scope: ConsoleEnterpriseIsolationScope;
    projectId: string | null;
    environmentId: string | null;
  } {
    const scope = request?.scope || 'ORG';
    const projectId = normalizeString(request?.projectId);
    const environmentId = normalizeString(request?.environmentId);
    return { scope, projectId, environmentId };
  }

  function resolveOrCreateState(
    ctx: ConsoleEnterpriseIsolationContext,
    request: GetConsoleEnterpriseIsolationRequest | TriggerConsoleEnterpriseIsolationRequest | undefined,
  ): ConsoleEnterpriseIsolationState {
    const scope = resolveScopeFromRequest(request);
    const key = toScopeKey(ctx.orgId, scope.scope, scope.projectId || undefined, scope.environmentId || undefined);
    let row = states.get(key);
    if (!row) {
      const ts = now();
      const iso = toIso(ts);
      row = {
        orgId: ctx.orgId,
        scope: scope.scope,
        projectId: scope.projectId,
        environmentId: scope.environmentId,
        mode: 'SHARED',
        status: 'SHARED',
        trigger: null,
        requestedByUserId: null,
        requestedAt: null,
        activatedAt: null,
        reason: null,
        ticketId: null,
        sla: { ...DEFAULT_SLA },
        createdAt: iso,
        updatedAt: iso,
      };
      states.set(key, row);
    }
    return row;
  }

  return {
    async getIsolationState(
      ctx: ConsoleEnterpriseIsolationContext,
      request: GetConsoleEnterpriseIsolationRequest = {},
    ): Promise<ConsoleEnterpriseIsolationState> {
      return cloneState(resolveOrCreateState(ctx, request));
    },

    async triggerIsolation(
      ctx: ConsoleEnterpriseIsolationContext,
      request: TriggerConsoleEnterpriseIsolationRequest,
    ): Promise<ConsoleEnterpriseIsolationState> {
      const row = resolveOrCreateState(ctx, request);
      const ts = now();
      const iso = toIso(ts);
      row.mode = 'DEDICATED';
      row.status = 'REQUESTED';
      row.trigger = request.trigger || 'MANUAL';
      row.requestedByUserId = ctx.actorUserId;
      row.requestedAt = iso;
      row.reason = normalizeString(request.reason);
      row.ticketId = normalizeString(request.ticketId);
      row.updatedAt = iso;
      return cloneState(row);
    },
  };
}
