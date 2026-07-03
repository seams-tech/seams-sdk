import type { CloudflareRouterApiContext } from '../createCloudflareRouter';
import { handleRouterApiSignedDelegate } from '../../routerApiSignedDelegate';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { toFetchRouteResponse } from '../../routeResponses';
import { readJson } from '../http';

export async function handleSignedDelegate(ctx: CloudflareRouterApiContext): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, 'signed_delegate');
  if (!route) return null;
  if (ctx.method !== route.method || ctx.pathname !== route.path) return null;
  const signedDelegate = ctx.opts.signedDelegate;
  if (!signedDelegate) return null;

  const response = await handleRouterApiSignedDelegate({
    body: await readJson(ctx.request),
    headers: Object.fromEntries(ctx.request.headers.entries()),
    logger: ctx.logger,
    origin:
      String(ctx.request.headers.get('origin') || ctx.request.headers.get('Origin') || '').trim() ||
      undefined,
    route,
    services: {
      signedDelegateAuth: signedDelegate.authService,
      billing: signedDelegate.billing,
      observabilityIngestion: ctx.opts.observabilityIngestion || null,
      prepaidReservations: ctx.opts.sponsorship?.prepaidReservations || null,
      pricing: ctx.opts.sponsorship?.pricing || null,
      publishableKeyAuth: ctx.opts.publishableKeyAuth,
      runtimeSnapshots: signedDelegate.runtimeSnapshots || null,
      spendCaps: ctx.opts.sponsorship?.spendCaps || null,
      sponsoredCalls: signedDelegate.ledger,
      webhooks: ctx.opts.routerApiWebhooks?.service || null,
      webhookActorUserId: ctx.opts.routerApiWebhooks?.actorUserId,
      webhookRoles: ctx.opts.routerApiWebhooks?.roles,
    },
  });
  return toFetchRouteResponse(response);
}
