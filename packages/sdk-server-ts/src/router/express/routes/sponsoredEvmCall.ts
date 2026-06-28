import type { Request, Response, Router as ExpressRouter } from 'express';
import { handleRouterApiSponsoredEvmCall } from '../../routerApiSponsoredEvmCall';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { sendExpressRouteResponse } from '../../routeResponses';
import type { ExpressRouterApiContext } from '../createRouterApiRouter';
import { resolveSponsoredEvmExecutionAdapter } from '../../../sponsorship/evmExecutionAdapter';

export function registerSponsoredEvmCallRoutes(
  router: ExpressRouter,
  ctx: ExpressRouterApiContext,
): void {
  const route = findRouteDefinitionById(ctx.routeDefinitions, 'sponsored_evm_call');
  if (!route) return;

  const options = ctx.opts.sponsoredEvmCall;
  if (!options) return;

  const routerApiSponsoredEvmCall = {
    billing: options.billing,
    config: options.config,
    corsOrigins: (ctx.opts.corsOrigins || []).map((entry) => String(entry || '').trim()).filter(Boolean),
    resolveExecutionAdapter: options.resolveExecutionAdapter || resolveSponsoredEvmExecutionAdapter,
    observabilityIngestion: ctx.opts.observabilityIngestion || null,
    prepaidReservations: ctx.opts.sponsorship?.prepaidReservations || null,
    publishableKeyAuth: options.publishableKeyAuth,
    pricing: ctx.opts.sponsorship?.pricing || null,
    runtimeSnapshots: options.runtimeSnapshots,
    spendCaps: ctx.opts.sponsorship?.spendCaps || null,
    sponsoredCalls: options.ledger,
    webhooks: ctx.opts.routerApiWebhooks?.service || null,
    webhookActorUserId: ctx.opts.routerApiWebhooks?.actorUserId,
    webhookRoles: ctx.opts.routerApiWebhooks?.roles,
  } as const;

  router.post(route.path, async (req: Request, res: Response) => {
    const response = await handleRouterApiSponsoredEvmCall({
      body: req.body,
      headers: (req.headers || {}) as Record<string, string | string[] | undefined>,
      logger: ctx.logger,
      origin: String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined,
      route,
      services: {
        routerApiSponsoredEvmCall,
      },
    });
    sendExpressRouteResponse(res, response);
  });
}
