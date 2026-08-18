import type { FetchRouterApiContext } from '../createFetchRouter';
import {
  handleRouterApiWalletAddAuthMethodFinalize,
  handleRouterApiWalletAddAuthMethodIntent,
  handleRouterApiWalletRevokeAuthMethod,
  handleRouterApiWalletAddAuthMethodStart,
  handleRouterApiWalletAddSignerFinalize,
  handleRouterApiWalletAddSignerEcdsaDerivationRespond,
  handleRouterApiWalletAddSignerEcdsaActivation,
  handleRouterApiWalletAddSignerIntent,
  handleRouterApiWalletAddSignerStart,
  handleRouterApiWalletRegistrationActivate,
  handleRouterApiWalletRegistrationNearProvisioning,
  handleRouterApiWalletRegistrationRespond,
  handleRouterApiWalletRegistrationSetup,
  handleRouterApiWalletEcdsaKeyFactsInventory,
  handleRouterApiWalletNearImplicitAccountFund,
} from '../../../domains/walletRegistration/walletRegistrationRoutes';
import { routerApiWalletRegistrationRouteService } from '../../../framework/authServicePort';
import { resolveSourceIpFromFetchHeaders } from '../../../auth/routerApiKeyAuth';
import type { RouteResponse } from '../../../framework/routeExecutionContext';
import {
  findRouteDefinitionById,
  matchesRouteDefinitionRequest,
  type RouteDefinition,
} from '../../../framework/routeDefinitions';
import { toFetchRouteResponse } from '../../../framework/routeResponses';
import { readJson } from '../../../framework/http';

const ROUTE_IDS = [
  'wallet_registration_setup',
  'wallet_registration_respond',
  'wallet_registration_activate',
  'wallet_registration_near_provisioning',
  'wallet_add_signer_intent',
  'wallet_add_signer_start',
  'wallet_add_signer_ecdsa_derivation_respond',
  'wallet_add_signer_ecdsa_activation',
  'wallet_add_signer_finalize',
  'wallet_add_auth_method_intent',
  'wallet_add_auth_method_start',
  'wallet_add_auth_method_finalize',
  'wallet_revoke_auth_method',
  'wallet_ecdsa_key_facts_inventory',
  'wallet_near_implicit_account_fund',
] as const;

type WalletRegistrationRouteId = (typeof ROUTE_IDS)[number];

function readWalletIdFromPath(route: RouteDefinition, pathname: string): string | undefined {
  const routeSegments = route.path.split('/').filter(Boolean);
  const pathSegments = pathname.split('/').filter(Boolean);
  const index = routeSegments.indexOf(':walletId');
  if (index < 0) return undefined;
  const segment = pathSegments[index];
  return segment ? decodeURIComponent(segment) : undefined;
}

function resolveWalletRegistrationRoute(ctx: FetchRouterApiContext): RouteDefinition | null {
  for (const routeId of ROUTE_IDS) {
    const route = findRouteDefinitionById(ctx.routeDefinitions, routeId);
    if (!route) {
      throw new Error(`Missing route definition for ${routeId}`);
    }
    if (matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return route;
  }
  return null;
}

export async function handleWalletRegistration(
  ctx: FetchRouterApiContext,
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
      walletRegistration: routerApiWalletRegistrationRouteService(ctx.service),
      authorizationSessions: ctx.service.authorizationSessions,
      apiKeyAuth: ctx.opts.apiKeyAuth,
      orgProjectEnv: ctx.opts.orgProjectEnv,
      routerAbPublicKeyset: ctx.opts.routerAbPublicKeyset,
      session: ctx.opts.session,
      publishableKeyAuth: ctx.opts.publishableKeyAuth,
    },
    sourceIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
  };
  const response: RouteResponse<unknown> =
    route.id === 'wallet_registration_setup'
      ? await handleRouterApiWalletRegistrationSetup(common)
      : route.id === 'wallet_registration_respond'
        ? await handleRouterApiWalletRegistrationRespond(common)
        : route.id === 'wallet_registration_activate'
          ? await handleRouterApiWalletRegistrationActivate(common)
          : route.id === 'wallet_registration_near_provisioning'
            ? await handleRouterApiWalletRegistrationNearProvisioning(common)
            : route.id === 'wallet_add_signer_intent'
                    ? await handleRouterApiWalletAddSignerIntent(common)
                    : route.id === 'wallet_add_signer_start'
                      ? await handleRouterApiWalletAddSignerStart(common)
                      : route.id === 'wallet_add_signer_ecdsa_derivation_respond'
                        ? await handleRouterApiWalletAddSignerEcdsaDerivationRespond(common)
                        : route.id === 'wallet_add_signer_ecdsa_activation'
                          ? await handleRouterApiWalletAddSignerEcdsaActivation(common)
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
