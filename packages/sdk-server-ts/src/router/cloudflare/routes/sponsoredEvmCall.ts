import { handleRouterApiSponsoredEvmCall } from '../../routerApiSponsoredEvmCall';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { routeJson, toFetchRouteResponse } from '../../routeResponses';
import { readJson } from '../http';
import type { CloudflareRouterApiContext } from '../createCloudflareRouter';

const SPONSORED_EVM_MVP_DISABLED_MESSAGE =
  'EVM gas sponsorship pricing is not configured on this server.';

export async function handleSponsoredEvmCall(
  ctx: CloudflareRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, 'sponsored_evm_call');
  if (!route) return null;
  if (ctx.method !== route.method || ctx.pathname !== route.path) return null;

  const options = ctx.opts.sponsoredEvmCall;
  if (!options) return null;
  if (!ctx.opts.sponsorship?.pricing) {
    ctx.logger.warn('[sponsored-evm-call][pricing-unconfigured]', {
      path: ctx.pathname,
      reason: SPONSORED_EVM_MVP_DISABLED_MESSAGE,
    });
    return toFetchRouteResponse(
      routeJson(503, {
        ok: false,
        code: 'sponsorship_pricing_unavailable',
        message: SPONSORED_EVM_MVP_DISABLED_MESSAGE,
      }),
    );
  }

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
