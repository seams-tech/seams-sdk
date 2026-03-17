import type { Request, Response, Router as ExpressRouter } from 'express';
import { handleRelaySignedDelegate } from '../../relaySignedDelegate';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { sendExpressRouteResponse } from '../../routeResponses';
import type { ExpressRelayContext } from '../createRelayRouter';

export function registerSignedDelegateRoutes(
  router: ExpressRouter,
  ctx: ExpressRelayContext,
): void {
  const route = findRouteDefinitionById(ctx.routeDefinitions, 'signed_delegate');
  if (!route) return;

  router.post(route.path, async (req: Request, res: Response) => {
    const response = await handleRelaySignedDelegate({
      body: req.body,
      headers: (req.headers || {}) as Record<string, string | string[] | undefined>,
      logger: ctx.logger,
      origin: String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined,
      route,
    services: {
      authService: ctx.service,
      billing: ctx.opts.signedDelegate?.billing,
      pricing: ctx.opts.sponsorship?.pricing || null,
      publishableKeyAuth: ctx.opts.publishableKeyAuth,
      runtimeSnapshots: ctx.opts.signedDelegate?.runtimeSnapshots || null,
      spendCaps: ctx.opts.sponsorship?.spendCaps || null,
      sponsoredCalls: ctx.opts.signedDelegate?.ledger,
    },
  });
    sendExpressRouteResponse(res, response);
  });
}
