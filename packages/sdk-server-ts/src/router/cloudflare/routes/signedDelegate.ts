import type { CloudflareRelayContext } from '../createCloudflareRouter';
import {
  handleRelaySignedDelegate,
  type SignedDelegateRelayAuthService,
} from '../../relaySignedDelegate';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { routeJson, toFetchRouteResponse } from '../../routeResponses';
import { readJson } from '../http';

function hasSignedDelegateAuthService(service: unknown): service is SignedDelegateRelayAuthService {
  if (!service || typeof service !== 'object') return false;
  const candidate = service as Record<string, unknown>;
  return (
    typeof candidate.executeSignedDelegate === 'function' &&
    typeof candidate.getRelayerAccount === 'function'
  );
}

export async function handleSignedDelegate(ctx: CloudflareRelayContext): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, 'signed_delegate');
  if (!route) return null;
  if (ctx.method !== route.method || ctx.pathname !== route.path) return null;
  if (!hasSignedDelegateAuthService(ctx.service)) {
    return toFetchRouteResponse(
      routeJson(501, {
        ok: false,
        code: 'signed_delegate_auth_unavailable',
        message: 'Signed-delegate execution is not configured for this Cloudflare router',
      }),
    );
  }

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
      observabilityIngestion: ctx.opts.observabilityIngestion || null,
      prepaidReservations: ctx.opts.sponsorship?.prepaidReservations || null,
      pricing: ctx.opts.sponsorship?.pricing || null,
      publishableKeyAuth: ctx.opts.publishableKeyAuth,
      runtimeSnapshots: ctx.opts.signedDelegate?.runtimeSnapshots || null,
      spendCaps: ctx.opts.sponsorship?.spendCaps || null,
      sponsoredCalls: ctx.opts.signedDelegate?.ledger,
      webhooks: ctx.opts.relayWebhooks?.service || null,
      webhookActorUserId: ctx.opts.relayWebhooks?.actorUserId,
      webhookRoles: ctx.opts.relayWebhooks?.roles,
    },
  });
  return toFetchRouteResponse(response);
}
