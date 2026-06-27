import type { CloudflareRelayContext } from '../createCloudflareRouter';
import {
  handleRelayWalletAddAuthMethodFinalize,
  handleRelayWalletAddAuthMethodIntent,
  handleRelayWalletRevokeAuthMethod,
  handleRelayWalletAddAuthMethodStart,
  handleRelayWalletAddSignerFinalize,
  handleRelayWalletAddSignerHssRespond,
  handleRelayWalletAddSignerIntent,
  handleRelayWalletAddSignerStart,
  handleRelayWalletRegistrationFinalize,
  handleRelayWalletRegistrationHssRespond,
  handleRelayWalletRegistrationIntent,
  handleRelayWalletRegistrationPrepare,
  handleRelayWalletRegistrationStart,
  handleRelayWalletEcdsaKeyFactsInventory,
} from '../../walletRegistrationRoutes';
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
  'wallet_registration_prepare',
  'wallet_registration_start',
  'wallet_registration_hss_respond',
  'wallet_registration_finalize',
  'wallet_add_signer_intent',
  'wallet_add_signer_start',
  'wallet_add_signer_hss_respond',
  'wallet_add_signer_finalize',
  'wallet_add_auth_method_intent',
  'wallet_add_auth_method_start',
  'wallet_add_auth_method_finalize',
  'wallet_revoke_auth_method',
  'wallet_ecdsa_key_facts_inventory',
] as const;

type WalletRegistrationRouteId = (typeof ROUTE_IDS)[number];

function isOptionalWalletRegistrationRouteId(routeId: WalletRegistrationRouteId): boolean {
  return routeId === 'wallet_registration_prepare';
}

function readWalletIdFromPath(route: RouteDefinition, pathname: string): string | undefined {
  const routeSegments = route.path.split('/').filter(Boolean);
  const pathSegments = pathname.split('/').filter(Boolean);
  const index = routeSegments.indexOf(':walletId');
  if (index < 0) return undefined;
  const segment = pathSegments[index];
  return segment ? decodeURIComponent(segment) : undefined;
}

function resolveWalletRegistrationRoute(ctx: CloudflareRelayContext): RouteDefinition | null {
  for (const routeId of ROUTE_IDS) {
    const route = findRouteDefinitionById(ctx.routeDefinitions, routeId);
    if (!route) {
      if (isOptionalWalletRegistrationRouteId(routeId)) continue;
      throw new Error(`Missing route definition for ${routeId}`);
    }
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
      walletId: readWalletIdFromPath(route, ctx.pathname),
    },
    route,
    services: {
      authService: ctx.service,
      apiKeyAuth: ctx.opts.apiKeyAuth,
      bootstrapTokenStore: ctx.opts.bootstrapTokenStore,
      orgProjectEnv: ctx.opts.orgProjectEnv,
      routerAbPublicKeyset: ctx.opts.routerAbPublicKeyset,
      session: ctx.opts.session,
    },
    sourceIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
  };
  const response: RouteResponse<unknown> =
    route.id === 'wallet_registration_intent'
      ? await handleRelayWalletRegistrationIntent(common)
      : route.id === 'wallet_registration_prepare'
        ? await handleRelayWalletRegistrationPrepare(common)
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
                  : route.id === 'wallet_add_auth_method_intent'
                    ? await handleRelayWalletAddAuthMethodIntent(common)
                    : route.id === 'wallet_add_auth_method_start'
                      ? await handleRelayWalletAddAuthMethodStart(common)
                      : route.id === 'wallet_add_auth_method_finalize'
                        ? await handleRelayWalletAddAuthMethodFinalize(common)
                        : route.id === 'wallet_revoke_auth_method'
                          ? await handleRelayWalletRevokeAuthMethod(common)
                  : await handleRelayWalletEcdsaKeyFactsInventory(common);
  return toFetchRouteResponse(response);
}
