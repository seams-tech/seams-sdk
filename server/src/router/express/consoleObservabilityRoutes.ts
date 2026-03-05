import type { Request, Response, Router as ExpressRouter } from 'express';
import {
  parseGetConsoleObservabilitySummaryRequest,
  parseGetConsoleObservabilityTimeseriesRequest,
  parseListConsoleObservabilityEventsRequest,
  parseListConsoleObservabilityServicesRequest,
  type ConsoleObservabilityService,
} from '../../console/observability';
import type { ConsoleAuthClaims } from '../console';

export interface ExpressConsoleObservabilityRouteContext {
  observability: ConsoleObservabilityService | null;
}

export interface ExpressConsoleObservabilityRouteDeps<
  TContext extends ExpressConsoleObservabilityRouteContext,
> {
  requireConsoleAuth: (
    req: Request,
    res: Response,
    ctx: TContext,
  ) => Promise<ConsoleAuthClaims | null>;
  requireObservabilityReadRole: (claims: ConsoleAuthClaims, res: Response) => boolean;
  requireObservabilityService: (
    res: Response,
    ctx: TContext,
  ) => ConsoleObservabilityService | null;
  toAuditContext: (
    claims: ConsoleAuthClaims,
  ) => Parameters<ConsoleObservabilityService['getSummary']>[0];
  sendObservabilityError: (res: Response, error: unknown) => void;
}

export function registerConsoleObservabilityRoutes<
  TContext extends ExpressConsoleObservabilityRouteContext,
>(
  router: ExpressRouter,
  ctx: TContext,
  deps: ExpressConsoleObservabilityRouteDeps<TContext>,
): void {
  router.get('/console/observability/summary', async (req: Request, res: Response) => {
    const claims = await deps.requireConsoleAuth(req, res, ctx);
    if (!claims || !deps.requireObservabilityReadRole(claims, res)) return;
    const observability = deps.requireObservabilityService(res, ctx);
    if (!observability) return;
    try {
      const request = parseGetConsoleObservabilitySummaryRequest((req as any).query || {});
      const summary = await observability.getSummary(deps.toAuditContext(claims), request);
      res.status(200).json({ ok: true, summary });
    } catch (error: unknown) {
      deps.sendObservabilityError(res, error);
    }
  });

  router.get('/console/observability/events', async (req: Request, res: Response) => {
    const claims = await deps.requireConsoleAuth(req, res, ctx);
    if (!claims || !deps.requireObservabilityReadRole(claims, res)) return;
    const observability = deps.requireObservabilityService(res, ctx);
    if (!observability) return;
    try {
      const request = parseListConsoleObservabilityEventsRequest((req as any).query || {});
      const page = await observability.listEvents(deps.toAuditContext(claims), request);
      res.status(200).json({
        ok: true,
        status: page.status,
        events: page.events,
        ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
      });
    } catch (error: unknown) {
      deps.sendObservabilityError(res, error);
    }
  });

  router.get('/console/observability/timeseries', async (req: Request, res: Response) => {
    const claims = await deps.requireConsoleAuth(req, res, ctx);
    if (!claims || !deps.requireObservabilityReadRole(claims, res)) return;
    const observability = deps.requireObservabilityService(res, ctx);
    if (!observability) return;
    try {
      const request = parseGetConsoleObservabilityTimeseriesRequest((req as any).query || {});
      const timeseries = await observability.getTimeseries(deps.toAuditContext(claims), request);
      res.status(200).json({
        ok: true,
        status: timeseries.status,
        buckets: timeseries.buckets,
      });
    } catch (error: unknown) {
      deps.sendObservabilityError(res, error);
    }
  });

  router.get('/console/observability/services', async (req: Request, res: Response) => {
    const claims = await deps.requireConsoleAuth(req, res, ctx);
    if (!claims || !deps.requireObservabilityReadRole(claims, res)) return;
    const observability = deps.requireObservabilityService(res, ctx);
    if (!observability) return;
    try {
      const request = parseListConsoleObservabilityServicesRequest((req as any).query || {});
      const services = await observability.listServices(deps.toAuditContext(claims), request);
      res.status(200).json({
        ok: true,
        status: services.status,
        services: services.services,
      });
    } catch (error: unknown) {
      deps.sendObservabilityError(res, error);
    }
  });
}
