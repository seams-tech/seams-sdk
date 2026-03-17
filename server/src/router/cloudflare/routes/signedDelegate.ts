import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { handleRelaySignedDelegate } from '../../relaySignedDelegate';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { toFetchRouteResponse } from '../../routeResponses';
import { readJson } from '../http';

export async function handleSignedDelegate(ctx: CloudflareRelayContext): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, 'signed_delegate');
  if (!route) return null;
  if (ctx.method !== route.method || ctx.pathname !== route.path) return null;

  const response = await handleRelaySignedDelegate({
    body: await readJson(ctx.request),
    headers: Object.fromEntries(ctx.request.headers.entries()),
    logger: ctx.logger,
    origin:
      String(ctx.request.headers.get('origin') || ctx.request.headers.get('Origin') || '').trim() ||
      undefined,
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
  return toFetchRouteResponse(response);
}
