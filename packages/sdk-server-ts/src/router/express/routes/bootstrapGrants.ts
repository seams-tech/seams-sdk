import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRouterApiContext } from '../createRouterApiRouter';
import { handleRouterApiBootstrapGrant } from '../../routerApiBootstrapGrant';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { sendExpressRouteResponse } from '../../routeResponses';

export function registerBootstrapGrantRoutes(
  router: ExpressRouter,
  ctx: ExpressRouterApiContext,
): void {
  const route = findRouteDefinitionById(ctx.routeDefinitions, 'registration_bootstrap_grants');
  if (!route) {
    throw new Error('Missing route definition for registration_bootstrap_grants');
  }

  router.post(route.path, async (req: Request, res: Response) => {
    const response = await handleRouterApiBootstrapGrant({
      body: req.body,
      headers: (req.headers || {}) as Record<string, string | string[] | undefined>,
      logger: ctx.logger,
      origin: String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined,
      route,
      services: {
        bootstrapGrantBroker: ctx.opts.bootstrapGrantBroker,
      },
    });
    sendExpressRouteResponse(res, response);
  });
}
