import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { handleRelayRegistrationRecoveryShare } from '../../relayRegistrationRecoveryShare';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { toFetchRouteResponse } from '../../routeResponses';
import { readJson } from '../http';

export async function handleRegistrationRecoveryShare(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  const backendProxyRoute = findRouteDefinitionById(ctx.routeDefinitions, 'registration_recovery_share');
  const managedRoute = findRouteDefinitionById(
    ctx.routeDefinitions,
    'registration_recovery_share_managed',
  );
  if (!backendProxyRoute || !managedRoute) {
    throw new Error('Missing route definition for registration recovery share');
  }
  const route =
    ctx.method === managedRoute.method && ctx.pathname === managedRoute.path
      ? managedRoute
      : ctx.method === backendProxyRoute.method && ctx.pathname === backendProxyRoute.path
        ? backendProxyRoute
        : null;
  if (!route) return null;

  const response = await handleRelayRegistrationRecoveryShare({
    body: await readJson(ctx.request),
    headers: Object.fromEntries(ctx.request.headers.entries()),
    logger: ctx.logger,
    origin: String(ctx.request.headers.get('origin') || ctx.request.headers.get('Origin') || '').trim() || undefined,
    route,
    services: {
      authService: ctx.service,
      publishableKeyAuth: ctx.opts.publishableKeyAuth,
    },
  });
  return toFetchRouteResponse(response);
}
