import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { handleRelayRegistrationBootstrap } from '../../relayRegistrationBootstrap';
import { resolveSourceIpFromFetchHeaders } from '../../relayApiKeyAuth';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { toFetchRouteResponse } from '../../routeResponses';
import { readJson } from '../http';

export async function handleCreateAccountAndRegisterUser(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, 'registration_bootstrap');
  if (!route) {
    throw new Error('Missing route definition for registration_bootstrap');
  }
  if (ctx.method !== route.method || ctx.pathname !== route.path) return null;

  const response = await handleRelayRegistrationBootstrap({
    body: await readJson(ctx.request),
    headers: Object.fromEntries(ctx.request.headers.entries()),
    logger: ctx.logger,
    origin: String(ctx.request.headers.get('origin') || ctx.request.headers.get('Origin') || '').trim() || undefined,
    route,
    services: {
      authService: ctx.service,
      apiKeyAuth: ctx.opts.apiKeyAuth,
      apiKeyUsageMeter: ctx.opts.apiKeyUsageMeter,
      bootstrapTokenStore: ctx.opts.bootstrapTokenStore,
      orgProjectEnv: ctx.opts.orgProjectEnv,
      session: ctx.opts.session,
      smartAccountDeploy: ctx.opts.smartAccountDeploy,
    },
    sourceIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
  });
  return toFetchRouteResponse(response);
}
