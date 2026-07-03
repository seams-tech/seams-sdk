import type { Request, Response, Router as ExpressRouter } from 'express';
import { handleRouterApiSignedDelegate } from '../../routerApiSignedDelegate';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { sendExpressRouteResponse } from '../../routeResponses';
import type { ExpressRouterApiContext } from '../createRouterApiRouter';

export function registerSignedDelegateRoutes(
  router: ExpressRouter,
  ctx: ExpressRouterApiContext,
): void {
  const route = findRouteDefinitionById(ctx.routeDefinitions, 'signed_delegate');
  if (!route) return;
  const signedDelegate = ctx.opts.signedDelegate;
  if (!signedDelegate) return;

  router.post(route.path, async (req: Request, res: Response) => {
    const response = await handleRouterApiSignedDelegate({
      body: req.body,
      headers: (req.headers || {}) as Record<string, string | string[] | undefined>,
      logger: ctx.logger,
      origin: String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined,
      route,
      services: {
        signedDelegateAuth: signedDelegate.authService,
        billing: signedDelegate.billing,
        observabilityIngestion: ctx.opts.observabilityIngestion || null,
        prepaidReservations: ctx.opts.sponsorship?.prepaidReservations || null,
        pricing: ctx.opts.sponsorship?.pricing || null,
        publishableKeyAuth: ctx.opts.publishableKeyAuth,
        runtimeSnapshots: signedDelegate.runtimeSnapshots || null,
        spendCaps: ctx.opts.sponsorship?.spendCaps || null,
        sponsoredCalls: signedDelegate.ledger,
        webhooks: ctx.opts.routerApiWebhooks?.service || null,
        webhookActorUserId: ctx.opts.routerApiWebhooks?.actorUserId,
        webhookRoles: ctx.opts.routerApiWebhooks?.roles,
      },
    });
    sendExpressRouteResponse(res, response);
  });
}
