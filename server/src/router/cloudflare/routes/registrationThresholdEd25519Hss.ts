import { findRouteDefinitionById } from '../../routeDefinitions';
import { toFetchRouteResponse } from '../../routeResponses';
import {
  handleRelayRegistrationThresholdEd25519HssFinalize,
  handleRelayRegistrationThresholdEd25519HssPrepare,
  handleRelayRegistrationThresholdEd25519HssRespond,
} from '../../relayRegistrationThresholdEd25519Hss';
import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { readJson } from '../http';
import { resolveSourceIpFromFetchHeaders } from '../../relayApiKeyAuth';

export async function handleRegistrationThresholdEd25519Hss(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  const prepareRoute = findRouteDefinitionById(
    ctx.routeDefinitions,
    'registration_threshold_ed25519_hss_prepare',
  );
  const finalizeRoute = findRouteDefinitionById(
    ctx.routeDefinitions,
    'registration_threshold_ed25519_hss_finalize',
  );
  const respondRoute = findRouteDefinitionById(
    ctx.routeDefinitions,
    'registration_threshold_ed25519_hss_respond',
  );
  if (!prepareRoute || !respondRoute || !finalizeRoute) {
    throw new Error('Missing route definition for registration threshold-ed25519 HSS routes');
  }

  if (ctx.method === prepareRoute.method && ctx.pathname === prepareRoute.path) {
    const response = await handleRelayRegistrationThresholdEd25519HssPrepare({
      body: await readJson(ctx.request),
      headers: Object.fromEntries(ctx.request.headers.entries()),
      logger: ctx.logger,
      origin:
        String(
          ctx.request.headers.get('origin') || ctx.request.headers.get('Origin') || '',
        ).trim() || undefined,
      route: prepareRoute,
      services: {
        authService: ctx.service,
        apiKeyAuth: ctx.opts.apiKeyAuth,
        bootstrapTokenStore: ctx.opts.bootstrapTokenStore,
        orgProjectEnv: ctx.opts.orgProjectEnv,
        session: ctx.opts.session,
      },
      sourceIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    });
    return toFetchRouteResponse(response);
  }

  if (ctx.method === finalizeRoute.method && ctx.pathname === finalizeRoute.path) {
    const response = await handleRelayRegistrationThresholdEd25519HssFinalize({
      body: await readJson(ctx.request),
      headers: Object.fromEntries(ctx.request.headers.entries()),
      logger: ctx.logger,
      origin:
        String(
          ctx.request.headers.get('origin') || ctx.request.headers.get('Origin') || '',
        ).trim() || undefined,
      route: finalizeRoute,
      services: {
        authService: ctx.service,
        apiKeyAuth: ctx.opts.apiKeyAuth,
        bootstrapTokenStore: ctx.opts.bootstrapTokenStore,
        orgProjectEnv: ctx.opts.orgProjectEnv,
        session: ctx.opts.session,
      },
      sourceIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    });
    return toFetchRouteResponse(response);
  }

  if (ctx.method === respondRoute.method && ctx.pathname === respondRoute.path) {
    const response = await handleRelayRegistrationThresholdEd25519HssRespond({
      body: await readJson(ctx.request),
      headers: Object.fromEntries(ctx.request.headers.entries()),
      logger: ctx.logger,
      origin:
        String(
          ctx.request.headers.get('origin') || ctx.request.headers.get('Origin') || '',
        ).trim() || undefined,
      route: respondRoute,
      services: {
        authService: ctx.service,
        apiKeyAuth: ctx.opts.apiKeyAuth,
        bootstrapTokenStore: ctx.opts.bootstrapTokenStore,
        orgProjectEnv: ctx.opts.orgProjectEnv,
        session: ctx.opts.session,
      },
      sourceIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    });
    return toFetchRouteResponse(response);
  }

  return null;
}
