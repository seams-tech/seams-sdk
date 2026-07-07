import {
  parseGetConsoleObservabilitySummaryRequest,
  parseGetConsoleObservabilityTimeseriesRequest,
  parseListConsoleObservabilityEventsRequest,
  parseListConsoleObservabilityServicesRequest,
} from '@seams-internal/console-server/observability/requests';
import type { ConsoleObservabilityService } from '@seams-internal/console-server/observability/service';
import type { ConsoleAuthClaims } from '@seams/sdk-server/internal/router/consoleAuth';

export interface CloudflareConsoleObservabilityRouteContext {
  method: string;
  pathname: string;
  url: URL;
  observability: ConsoleObservabilityService | null;
}

export interface CloudflareConsoleObservabilityRouteDeps<
  TContext extends CloudflareConsoleObservabilityRouteContext,
> {
  json: (body: unknown, init?: ResponseInit) => Response;
  isConsoleObservabilityPath: (pathname: string) => boolean;
  requireConsoleAuth: (
    ctx: TContext,
  ) => Promise<{ ok: true; claims: ConsoleAuthClaims } | { ok: false; response: Response }>;
  requireConsoleRoutePolicy: (ctx: TContext, claims: ConsoleAuthClaims) => Response | null;
  requireObservabilityService: (ctx: TContext) => ConsoleObservabilityService | Response;
  toAuditContext: (
    claims: ConsoleAuthClaims,
  ) => Parameters<ConsoleObservabilityService['getSummary']>[0];
  sendObservabilityError: (error: unknown) => Response;
}

export async function handleConsoleObservabilityRoutes<
  TContext extends CloudflareConsoleObservabilityRouteContext,
>(
  ctx: TContext,
  deps: CloudflareConsoleObservabilityRouteDeps<TContext>,
): Promise<Response | null> {
  if (!deps.isConsoleObservabilityPath(ctx.pathname)) return null;

  const auth = await deps.requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const roleRequired = deps.requireConsoleRoutePolicy(ctx, auth.claims);
  if (roleRequired) return roleRequired;

  const observabilityOrResponse = deps.requireObservabilityService(ctx);
  if (observabilityOrResponse instanceof Response) return observabilityOrResponse;
  const observability = observabilityOrResponse;

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/observability/summary') {
      const request = parseGetConsoleObservabilitySummaryRequest({
        from: ctx.url.searchParams.get('from') || undefined,
        to: ctx.url.searchParams.get('to') || undefined,
        projectId: ctx.url.searchParams.get('projectId') || undefined,
        environmentId: ctx.url.searchParams.get('environmentId') || undefined,
      });
      const summary = await observability.getSummary(deps.toAuditContext(auth.claims), request);
      return deps.json({ ok: true, summary }, { status: 200 });
    }

    if (ctx.method === 'GET' && ctx.pathname === '/console/observability/events') {
      const request = parseListConsoleObservabilityEventsRequest({
        from: ctx.url.searchParams.get('from') || undefined,
        to: ctx.url.searchParams.get('to') || undefined,
        query: ctx.url.searchParams.get('query') || undefined,
        level: ctx.url.searchParams.get('level') || undefined,
        service: ctx.url.searchParams.get('service') || undefined,
        component: ctx.url.searchParams.get('component') || undefined,
        eventType: ctx.url.searchParams.get('eventType') || undefined,
        projectId: ctx.url.searchParams.get('projectId') || undefined,
        environmentId: ctx.url.searchParams.get('environmentId') || undefined,
        cursor: ctx.url.searchParams.get('cursor') || undefined,
        limit: ctx.url.searchParams.get('limit') || undefined,
      });
      const page = await observability.listEvents(deps.toAuditContext(auth.claims), request);
      return deps.json(
        {
          ok: true,
          status: page.status,
          events: page.events,
          totalPages: page.totalPages,
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        },
        { status: 200 },
      );
    }

    if (ctx.method === 'GET' && ctx.pathname === '/console/observability/timeseries') {
      const request = parseGetConsoleObservabilityTimeseriesRequest({
        from: ctx.url.searchParams.get('from') || undefined,
        to: ctx.url.searchParams.get('to') || undefined,
        service: ctx.url.searchParams.get('service') || undefined,
        eventType: ctx.url.searchParams.get('eventType') || undefined,
        projectId: ctx.url.searchParams.get('projectId') || undefined,
        environmentId: ctx.url.searchParams.get('environmentId') || undefined,
        bucketMinutes: ctx.url.searchParams.get('bucketMinutes') || undefined,
      });
      const timeseries = await observability.getTimeseries(deps.toAuditContext(auth.claims), request);
      return deps.json(
        {
          ok: true,
          status: timeseries.status,
          buckets: timeseries.buckets,
        },
        { status: 200 },
      );
    }

    if (ctx.method === 'GET' && ctx.pathname === '/console/observability/services') {
      const request = parseListConsoleObservabilityServicesRequest({
        from: ctx.url.searchParams.get('from') || undefined,
        to: ctx.url.searchParams.get('to') || undefined,
        projectId: ctx.url.searchParams.get('projectId') || undefined,
        environmentId: ctx.url.searchParams.get('environmentId') || undefined,
        limit: ctx.url.searchParams.get('limit') || undefined,
      });
      const services = await observability.listServices(deps.toAuditContext(auth.claims), request);
      return deps.json(
        {
          ok: true,
          status: services.status,
          services: services.services,
        },
        { status: 200 },
      );
    }
  } catch (error: unknown) {
    return deps.sendObservabilityError(error);
  }

  return new Response('Not Found', { status: 404 });
}
