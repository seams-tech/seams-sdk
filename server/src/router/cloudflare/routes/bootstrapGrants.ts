import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { toFetchRouteResponse } from '../../routeResponses';
import { handleRelayBootstrapGrant } from '../../relayBootstrapGrant';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { readJson } from '../http';

export async function handleBootstrapGrant(ctx: CloudflareRelayContext): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, 'registration_bootstrap_grants');
  if (!route) {
    throw new Error('Missing route definition for registration_bootstrap_grants');
  }
  if (ctx.method !== route.method || ctx.pathname !== route.path) return null;

  const response = await handleRelayBootstrapGrant({
    body: await readJson(ctx.request),
    headers: Object.fromEntries(ctx.request.headers.entries()),
    logger: ctx.logger,
    origin:
      String(ctx.request.headers.get('origin') || ctx.request.headers.get('Origin') || '').trim() ||
      undefined,
    route,
    services: {
      bootstrapGrantBroker: ctx.opts.bootstrapGrantBroker,
    },
  });
  return toFetchRouteResponse(response);
}
