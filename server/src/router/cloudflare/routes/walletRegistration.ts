import type { CloudflareRelayContext } from '../createCloudflareRouter';
import {
  handleRelayWalletAddSignerFinalize,
  handleRelayWalletAddSignerHssRespond,
  handleRelayWalletAddSignerIntent,
  handleRelayWalletAddSignerStart,
  handleRelayWalletRegistrationFinalize,
  handleRelayWalletRegistrationHssRespond,
  handleRelayWalletRegistrationIntent,
  handleRelayWalletRegistrationStart,
  handleRelayWalletSubjectEcdsaKeyFactsInventory,
} from '../../relayWalletRegistration';
import { resolveSourceIpFromFetchHeaders } from '../../relayApiKeyAuth';
import type { RouteResponse } from '../../routeExecutionContext';
import {
  findRouteDefinitionById,
  matchesRouteDefinitionRequest,
  type RouteDefinition,
} from '../../routeDefinitions';
import { toFetchRouteResponse } from '../../routeResponses';
import { readJson } from '../http';

const ROUTE_IDS = [
  'wallet_registration_intent',
  'wallet_registration_start',
  'wallet_registration_hss_respond',
  'wallet_registration_finalize',
  'wallet_add_signer_intent',
  'wallet_add_signer_start',
  'wallet_add_signer_hss_respond',
  'wallet_add_signer_finalize',
  'wallet_subject_ecdsa_key_facts_inventory',
] as const;

function readWalletSubjectIdFromPath(route: RouteDefinition, pathname: string): string | undefined {
  const routeSegments = route.path.split('/').filter(Boolean);
  const pathSegments = pathname.split('/').filter(Boolean);
  const index = routeSegments.indexOf(':walletSubjectId');
  if (index < 0) return undefined;
  const segment = pathSegments[index];
  return segment ? decodeURIComponent(segment) : undefined;
}

function resolveWalletRegistrationRoute(ctx: CloudflareRelayContext): RouteDefinition | null {
  for (const routeId of ROUTE_IDS) {
    const route = findRouteDefinitionById(ctx.routeDefinitions, routeId);
    if (!route) throw new Error(`Missing route definition for ${routeId}`);
    if (matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return route;
  }
  return null;
}

export async function handleWalletRegistration(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  const route = resolveWalletRegistrationRoute(ctx);
  if (!route) return null;

  const body = await readJson(ctx.request);
  const common = {
    body,
    headers: Object.fromEntries(ctx.request.headers.entries()),
    logger: ctx.logger,
    origin:
      String(ctx.request.headers.get('origin') || ctx.request.headers.get('Origin') || '').trim() ||
      undefined,
    pathParams: {
      walletSubjectId: readWalletSubjectIdFromPath(route, ctx.pathname),
    },
    route,
    services: {
      authService: ctx.service,
      apiKeyAuth: ctx.opts.apiKeyAuth,
      bootstrapTokenStore: ctx.opts.bootstrapTokenStore,
      orgProjectEnv: ctx.opts.orgProjectEnv,
      session: ctx.opts.session,
    },
    sourceIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
  };
  const response: RouteResponse<unknown> =
    route.id === 'wallet_registration_intent'
      ? await handleRelayWalletRegistrationIntent(common)
      : route.id === 'wallet_registration_start'
        ? await handleRelayWalletRegistrationStart(common)
        : route.id === 'wallet_registration_hss_respond'
          ? await handleRelayWalletRegistrationHssRespond(common)
          : route.id === 'wallet_registration_finalize'
            ? await handleRelayWalletRegistrationFinalize(common)
            : route.id === 'wallet_add_signer_intent'
              ? await handleRelayWalletAddSignerIntent(common)
              : route.id === 'wallet_add_signer_start'
                ? await handleRelayWalletAddSignerStart(common)
                : route.id === 'wallet_add_signer_hss_respond'
                  ? await handleRelayWalletAddSignerHssRespond(common)
                  : route.id === 'wallet_add_signer_finalize'
                    ? await handleRelayWalletAddSignerFinalize(common)
                    : await handleRelayWalletSubjectEcdsaKeyFactsInventory(common);
  return toFetchRouteResponse(response);
}
