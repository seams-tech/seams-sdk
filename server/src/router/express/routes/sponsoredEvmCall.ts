import type { Request, Response, Router as ExpressRouter } from 'express';
import { createRelayPublishableKeyAuthAdapter } from '../../relayApiKeyAuth';
import { handleRelaySponsoredEvmCall } from '../../relaySponsoredEvmCall';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { sendExpressRouteResponse } from '../../routeResponses';
import type { ExpressRelayContext } from '../createRelayRouter';

export function registerSponsoredEvmCallRoutes(
  router: ExpressRouter,
  ctx: ExpressRelayContext,
): void {
  const route = findRouteDefinitionById(ctx.routeDefinitions, 'sponsored_evm_call');
  if (!route) return;

  const options = ctx.opts.sponsoredEvmCall;
  if (!options) return;

  const publishableKeyAuth =
    typeof options.apiKeys.authenticatePublishableKey === 'function'
      ? createRelayPublishableKeyAuthAdapter(options.apiKeys)
      : null;
  const relaySponsoredEvmCall = {
    billing: options.billing,
    config: options.config,
    corsOrigins: (ctx.opts.corsOrigins || []).map((entry) => String(entry || '').trim()).filter(Boolean),
    observabilityIngestion: ctx.opts.observabilityIngestion || null,
    prepaidReservations: ctx.opts.sponsorship?.prepaidReservations || null,
    publishableKeyAuth,
    pricing: ctx.opts.sponsorship?.pricing || null,
    runtimeSnapshots: options.runtimeSnapshots,
    spendCaps: ctx.opts.sponsorship?.spendCaps || null,
    sponsoredCalls: options.ledger,
    webhooks: ctx.opts.relayWebhooks?.service || null,
    webhookActorUserId: ctx.opts.relayWebhooks?.actorUserId,
    webhookRoles: ctx.opts.relayWebhooks?.roles,
  } as const;

  router.post(route.path, async (req: Request, res: Response) => {
    const response = await handleRelaySponsoredEvmCall({
      body: req.body,
      headers: (req.headers || {}) as Record<string, string | string[] | undefined>,
      logger: ctx.logger,
      origin: String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined,
      route,
      services: {
        relaySponsoredEvmCall,
      },
    });
    sendExpressRouteResponse(res, response);
  });
}
