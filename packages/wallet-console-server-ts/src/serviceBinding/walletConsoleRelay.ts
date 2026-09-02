import {
  coerceRouterLogger,
  getRouterApiRouteExtensionRoutes,
  matchesRouteDefinitionRequest,
  type CfExecutionContext,
  type RouterApiRouteExtension,
} from '@seams/wallet-server/cloud-host';
import { walletConsoleRelayRouteDefinitions } from '../router/routeExtensions';
import { WALLET_CONSOLE_SERVICE_ORIGIN_V1 } from './walletConsoleOps';
import type { WalletConsoleServiceBinding } from './walletConsoleOpsClient';

export function createWalletConsoleRelayProxyExtension(
  binding: WalletConsoleServiceBinding,
): RouterApiRouteExtension {
  return {
    kind: 'fetch_route_extension',
    id: 'wallet_console_relay_proxy',
    routes: walletConsoleRelayRouteDefinitions(),
    async handleFetchRoute(input): Promise<Response> {
      const sourceUrl = new URL(input.request.url);
      const targetUrl = new URL(
        `${sourceUrl.pathname}${sourceUrl.search}`,
        WALLET_CONSOLE_SERVICE_ORIGIN_V1,
      );
      return await binding.fetch(new Request(targetUrl, input.request));
    },
  };
}

export function createWalletConsoleRelayHandler(
  extensions: readonly RouterApiRouteExtension[],
): (request: Request, ctx?: CfExecutionContext) => Promise<Response | null> {
  const logger = coerceRouterLogger(undefined);
  return async function handleWalletConsoleRelayRequest(
    request: Request,
    ctx?: CfExecutionContext,
  ): Promise<Response | null> {
    const url = new URL(request.url);
    if (url.origin !== WALLET_CONSOLE_SERVICE_ORIGIN_V1) return null;
    for (const extension of extensions) {
      const routes = getRouterApiRouteExtensionRoutes(extension, 'fetch');
      const route = routes.find((candidate) =>
        matchesRouteDefinitionRequest(candidate, request.method, url.pathname),
      );
      if (!route) continue;
      return await extension.handleFetchRoute({
        request,
        route,
        pathname: url.pathname,
        method: request.method,
        logger,
        runtime: ctx
          ? { kind: 'background', waitUntil: ctx.waitUntil.bind(ctx) }
          : { kind: 'inline' },
      });
    }
    return null;
  };
}
