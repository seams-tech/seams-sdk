import { handleRouterApiSponsoredEvmCall } from '../../routerApiSponsoredEvmCall';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { toFetchRouteResponse } from '../../routeResponses';
import { readJson } from '../http';
import type { CloudflareRouterApiContext } from '../createCloudflareRouter';

export async function handleSponsoredEvmCall(
  ctx: CloudflareRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, 'sponsored_evm_call');
  if (!route) return null;
  if (ctx.method !== route.method || ctx.pathname !== route.path) return null;

  const options = ctx.opts.sponsoredEvmCall;
  if (!options) return null;

  const response = await handleRouterApiSponsoredEvmCall({
    body: await readJson(ctx.request),
    headers: Object.fromEntries(ctx.request.headers.entries()),
    logger: ctx.logger,
    origin:
      String(ctx.request.headers.get('origin') || ctx.request.headers.get('Origin') || '').trim() ||
      undefined,
    route,
    services: {
      routerApiSponsoredEvmCall: {
        billing: options.billing,
        config: options.config,
        corsOrigins: (ctx.opts.corsOrigins || []).map((entry) => String(entry || '').trim()).filter(Boolean),
        resolveExecutionAdapter: options.resolveExecutionAdapter || null,
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
      },
    },
  });
  return toFetchRouteResponse(response);
}
