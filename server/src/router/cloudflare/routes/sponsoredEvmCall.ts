import { createRelayPublishableKeyAuthAdapter } from '../../relayApiKeyAuth';
import { handleRelaySponsoredEvmCall } from '../../relaySponsoredEvmCall';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { toFetchRouteResponse } from '../../routeResponses';
import { readJson } from '../http';
import type { CloudflareRelayContext } from '../createCloudflareRouter';

export async function handleSponsoredEvmCall(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, 'sponsored_evm_call');
  if (!route) return null;
  if (ctx.method !== route.method || ctx.pathname !== route.path) return null;

  const options = ctx.opts.sponsoredEvmCall;
  if (!options) return null;

  const publishableKeyAuth =
    typeof options.apiKeys.authenticatePublishableKey === 'function'
      ? createRelayPublishableKeyAuthAdapter(options.apiKeys)
      : null;

  const response = await handleRelaySponsoredEvmCall({
    body: await readJson(ctx.request),
    headers: Object.fromEntries(ctx.request.headers.entries()),
    logger: ctx.logger,
    origin:
      String(ctx.request.headers.get('origin') || ctx.request.headers.get('Origin') || '').trim() ||
      undefined,
    route,
    services: {
      relaySponsoredEvmCall: {
        billing: options.billing,
        config: options.config,
        corsOrigins: (ctx.opts.corsOrigins || []).map((entry) => String(entry || '').trim()).filter(Boolean),
        publishableKeyAuth,
        pricing: ctx.opts.sponsorship?.pricing || null,
        runtimeSnapshots: options.runtimeSnapshots,
        spendCaps: ctx.opts.sponsorship?.spendCaps || null,
        sponsoredCalls: options.ledger,
      },
    },
  });
  return toFetchRouteResponse(response);
}
