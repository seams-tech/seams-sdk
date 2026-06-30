import type { CloudflareRouterApiContext } from '../createCloudflareRouter';
import {
  handleRouterApiWalletAddAuthMethodFinalize,
  handleRouterApiWalletAddAuthMethodIntent,
  handleRouterApiWalletRevokeAuthMethod,
  handleRouterApiWalletAddAuthMethodStart,
  handleRouterApiWalletAddSignerFinalize,
  handleRouterApiWalletAddSignerHssRespond,
  handleRouterApiWalletAddSignerIntent,
  handleRouterApiWalletAddSignerStart,
  handleRouterApiWalletRegistrationFinalize,
  handleRouterApiWalletRegistrationHssRespond,
  handleRouterApiWalletRegistrationIntent,
  handleRouterApiWalletRegistrationPrepare,
  handleRouterApiWalletRegistrationStart,
  handleRouterApiWalletEcdsaKeyFactsInventory,
  handleRouterApiWalletNearImplicitAccountFund,
} from '../../walletRegistrationRoutes';
import { resolveSourceIpFromFetchHeaders } from '../../routerApiKeyAuth';
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
  'wallet_near_implicit_account_fund',
] as const;

type WalletRegistrationRouteId = (typeof ROUTE_IDS)[number];
type RegistrationPrepareAuthService = NonNullable<
  CloudflareRouterApiContext['opts']['ed25519RegistrationPrepare']
>['authService'];

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

function resolveWalletRegistrationRoute(ctx: CloudflareRouterApiContext): RouteDefinition | null {
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

function requireRegistrationPrepareAuthService(
  ctx: CloudflareRouterApiContext,
): RegistrationPrepareAuthService {
  const prepare = ctx.opts.ed25519RegistrationPrepare;
  if (!prepare) {
    throw new Error('wallet_registration_prepare route registered without prepare auth service');
  }
  return prepare.authService;
}

export async function handleWalletRegistration(
  ctx: CloudflareRouterApiContext,
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
      ? await handleRouterApiWalletRegistrationIntent(common)
      : route.id === 'wallet_registration_prepare'
        ? await handleRouterApiWalletRegistrationPrepare({
            ...common,
            services: {
              ...common.services,
              registrationPrepareAuthService: requireRegistrationPrepareAuthService(ctx),
            },
          })
        : route.id === 'wallet_registration_start'
          ? await handleRouterApiWalletRegistrationStart(common)
          : route.id === 'wallet_registration_hss_respond'
            ? await handleRouterApiWalletRegistrationHssRespond(common)
            : route.id === 'wallet_registration_finalize'
              ? await handleRouterApiWalletRegistrationFinalize(common)
              : route.id === 'wallet_add_signer_intent'
                ? await handleRouterApiWalletAddSignerIntent(common)
                : route.id === 'wallet_add_signer_start'
                  ? await handleRouterApiWalletAddSignerStart(common)
                  : route.id === 'wallet_add_signer_hss_respond'
                    ? await handleRouterApiWalletAddSignerHssRespond(common)
                    : route.id === 'wallet_add_signer_finalize'
                      ? await handleRouterApiWalletAddSignerFinalize(common)
                      : route.id === 'wallet_add_auth_method_intent'
                        ? await handleRouterApiWalletAddAuthMethodIntent(common)
                        : route.id === 'wallet_add_auth_method_start'
                          ? await handleRouterApiWalletAddAuthMethodStart(common)
                          : route.id === 'wallet_add_auth_method_finalize'
                            ? await handleRouterApiWalletAddAuthMethodFinalize(common)
                            : route.id === 'wallet_revoke_auth_method'
                              ? await handleRouterApiWalletRevokeAuthMethod(common)
                              : route.id === 'wallet_ecdsa_key_facts_inventory'
                                ? await handleRouterApiWalletEcdsaKeyFactsInventory(common)
                                : await handleRouterApiWalletNearImplicitAccountFund(common);
  return toFetchRouteResponse(response);
}
