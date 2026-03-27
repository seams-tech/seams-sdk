import type { Request, Response, Router as ExpressRouter } from 'express';
import { handleRelayRegistrationRecoveryShare } from '../../relayRegistrationRecoveryShare';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { sendExpressRouteResponse } from '../../routeResponses';
import type { ExpressRelayContext } from '../createRelayRouter';

export function registerRegistrationRecoveryShareRoutes(
  router: ExpressRouter,
  ctx: ExpressRelayContext,
): void {
  const backendProxyRoute = findRouteDefinitionById(ctx.routeDefinitions, 'registration_recovery_share');
  const managedRoute = findRouteDefinitionById(
    ctx.routeDefinitions,
    'registration_recovery_share_managed',
  );
  if (!backendProxyRoute || !managedRoute) {
    throw new Error('Missing route definition for registration recovery share');
  }

  for (const route of [backendProxyRoute, managedRoute]) {
    router.post(route.path, async (req: Request, res: Response) => {
      const response = await handleRelayRegistrationRecoveryShare({
        body: req.body,
        headers: (req.headers || {}) as Record<string, string | string[] | undefined>,
        logger: ctx.logger,
        origin: String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined,
        route,
        services: {
          authService: ctx.service,
          publishableKeyAuth: ctx.opts.publishableKeyAuth,
        },
      });
      sendExpressRouteResponse(res, response);
    });
  }
}
