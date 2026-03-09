import type {
  ConsoleObservabilityEventsPage,
  ConsoleObservabilityModuleState,
  ConsoleObservabilityModuleStatus,
  ConsoleObservabilityServicesView,
  ConsoleObservabilitySummary,
  ConsoleObservabilityTimeseries,
  GetConsoleObservabilitySummaryRequest,
  GetConsoleObservabilityTimeseriesRequest,
  ListConsoleObservabilityEventsRequest,
  ListConsoleObservabilityServicesRequest,
} from './types';

export interface ConsoleObservabilityContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
  projectId?: string;
  environmentId?: string;
}

export interface InMemoryConsoleObservabilityServiceOptions {
  now?: () => Date;
  defaultStatusState?: ConsoleObservabilityModuleState;
  defaultStatusCode?: string;
  defaultStatusMessage?: string;
}

export interface ConsoleObservabilityService {
  getSummary(
    ctx: ConsoleObservabilityContext,
    request?: GetConsoleObservabilitySummaryRequest,
  ): Promise<ConsoleObservabilitySummary>;
  listEvents(
    ctx: ConsoleObservabilityContext,
    request?: ListConsoleObservabilityEventsRequest,
  ): Promise<ConsoleObservabilityEventsPage>;
  getTimeseries(
    ctx: ConsoleObservabilityContext,
    request?: GetConsoleObservabilityTimeseriesRequest,
  ): Promise<ConsoleObservabilityTimeseries>;
  listServices(
    ctx: ConsoleObservabilityContext,
    request?: ListConsoleObservabilityServicesRequest,
  ): Promise<ConsoleObservabilityServicesView>;
}

function buildStatus(opts: InMemoryConsoleObservabilityServiceOptions): ConsoleObservabilityModuleStatus {
  const state = opts.defaultStatusState || 'not_configured';
  return {
    state,
    ...(opts.defaultStatusCode ? { code: opts.defaultStatusCode } : {}),
    ...(opts.defaultStatusMessage ? { message: opts.defaultStatusMessage } : {}),
  };
}

export function createInMemoryConsoleObservabilityService(
  opts: InMemoryConsoleObservabilityServiceOptions = {},
): ConsoleObservabilityService {
  const now = opts.now || (() => new Date());
  const status = buildStatus(opts);

  return {
    async getSummary(
      _ctx: ConsoleObservabilityContext,
      _request: GetConsoleObservabilitySummaryRequest = {},
    ): Promise<ConsoleObservabilitySummary> {
      return {
        generatedAt: now().toISOString(),
        status,
        errorRate: 0,
        p95LatencyMs: 0,
        failingServices: 0,
        deadLetterCount: 0,
      };
    },

    async listEvents(
      _ctx: ConsoleObservabilityContext,
      _request: ListConsoleObservabilityEventsRequest = {},
    ): Promise<ConsoleObservabilityEventsPage> {
      return {
        status,
        events: [],
        totalPages: 1,
      };
    },

    async getTimeseries(
      _ctx: ConsoleObservabilityContext,
      _request: GetConsoleObservabilityTimeseriesRequest = {},
    ): Promise<ConsoleObservabilityTimeseries> {
      return {
        status,
        buckets: [],
      };
    },

    async listServices(
      _ctx: ConsoleObservabilityContext,
      _request: ListConsoleObservabilityServicesRequest = {},
    ): Promise<ConsoleObservabilityServicesView> {
      return {
        status,
        services: [],
      };
    },
  };
}
