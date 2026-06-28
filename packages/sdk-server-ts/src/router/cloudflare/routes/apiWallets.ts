import {
  handleRouterApiWalletGet,
  handleRouterApiWalletList,
  handleRouterApiWalletSearch,
} from '../../routerApiWallets';
import { resolveSourceIpFromFetchHeaders } from '../../routerApiKeyAuth';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { toFetchRouteResponse } from '../../routeResponses';
import type { CloudflareRouterApiContext } from '../createCloudflareRouter';

const API_WALLET_DETAIL_PREFIX = '/v1/wallets/';

export async function handleApiWallets(
  ctx: CloudflareRouterApiContext,
): Promise<Response | null> {
  const listRoute = findRouteDefinitionById(ctx.routeDefinitions, 'api_wallets_list');
  const searchRoute = findRouteDefinitionById(ctx.routeDefinitions, 'api_wallets_search');
  const getRoute = findRouteDefinitionById(ctx.routeDefinitions, 'api_wallets_get');
  if (!listRoute || !searchRoute || !getRoute) {
    throw new Error('Missing API wallet route definitions');
  }

  const common = {
    headers: Object.fromEntries(ctx.request.headers.entries()),
    logger: ctx.logger,
    services: {
      apiKeyAuth: ctx.opts.apiKeyAuth,
      wallets: ctx.opts.wallets,
    },
    sourceIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
  } as const;

  if (ctx.method === listRoute.method && ctx.pathname === listRoute.path) {
    const response = await handleRouterApiWalletList({
      ...common,
      query: Object.fromEntries(ctx.url.searchParams.entries()),
      route: listRoute,
    });
    return toFetchRouteResponse(response);
  }

  if (ctx.method === searchRoute.method && ctx.pathname === searchRoute.path) {
    const response = await handleRouterApiWalletSearch({
      ...common,
      query: Object.fromEntries(ctx.url.searchParams.entries()),
      route: searchRoute,
    });
    return toFetchRouteResponse(response);
  }

  if (
    ctx.method === getRoute.method &&
    ctx.pathname.startsWith(API_WALLET_DETAIL_PREFIX) &&
    ctx.pathname !== searchRoute.path
  ) {
    const walletId = decodeURIComponent(ctx.pathname.slice(API_WALLET_DETAIL_PREFIX.length));
    if (walletId && !walletId.includes('/')) {
      const response = await handleRouterApiWalletGet({
        ...common,
        route: getRoute,
        walletId,
      });
      return toFetchRouteResponse(response);
    }
  }

  return null;
}
