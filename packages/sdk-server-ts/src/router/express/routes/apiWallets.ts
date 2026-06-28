import type { Request, Response, Router as ExpressRouter } from 'express';
import {
  handleRouterApiWalletGet,
  handleRouterApiWalletList,
  handleRouterApiWalletSearch,
} from '../../routerApiWallets';
import { resolveSourceIpFromExpressRequest } from '../../routerApiKeyAuth';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { sendExpressRouteResponse } from '../../routeResponses';
import type { ExpressRouterApiContext } from '../createRouterApiRouter';

export function registerApiWalletRoutes(
  router: ExpressRouter,
  ctx: ExpressRouterApiContext,
): void {
  const listRoute = findRouteDefinitionById(ctx.routeDefinitions, 'api_wallets_list');
  const searchRoute = findRouteDefinitionById(ctx.routeDefinitions, 'api_wallets_search');
  const getRoute = findRouteDefinitionById(ctx.routeDefinitions, 'api_wallets_get');
  if (!listRoute || !searchRoute || !getRoute) {
    throw new Error('Missing API wallet route definitions');
  }

  router.get(listRoute.path, async (req: Request, res: Response) => {
    const headers = (req.headers || {}) as Record<string, string | string[] | undefined>;
    const response = await handleRouterApiWalletList({
      headers,
      logger: ctx.logger,
      query: (req as any).query || {},
      route: listRoute,
      services: {
        apiKeyAuth: ctx.opts.apiKeyAuth,
        wallets: ctx.opts.wallets,
      },
      sourceIp:
        resolveSourceIpFromExpressRequest({
          headers: headers as Record<string, unknown>,
          ip: (req as any).ip as string | undefined,
        }) || undefined,
    });
    sendExpressRouteResponse(res, response);
  });

  router.get(searchRoute.path, async (req: Request, res: Response) => {
    const headers = (req.headers || {}) as Record<string, string | string[] | undefined>;
    const response = await handleRouterApiWalletSearch({
      headers,
      logger: ctx.logger,
      query: (req as any).query || {},
      route: searchRoute,
      services: {
        apiKeyAuth: ctx.opts.apiKeyAuth,
        wallets: ctx.opts.wallets,
      },
      sourceIp:
        resolveSourceIpFromExpressRequest({
          headers: headers as Record<string, unknown>,
          ip: (req as any).ip as string | undefined,
        }) || undefined,
    });
    sendExpressRouteResponse(res, response);
  });

  router.get(getRoute.path, async (req: Request, res: Response) => {
    const headers = (req.headers || {}) as Record<string, string | string[] | undefined>;
    const params = req as Request & { params?: { id?: string } };
    const response = await handleRouterApiWalletGet({
      headers,
      logger: ctx.logger,
      route: getRoute,
      services: {
        apiKeyAuth: ctx.opts.apiKeyAuth,
        wallets: ctx.opts.wallets,
      },
      sourceIp:
        resolveSourceIpFromExpressRequest({
          headers: headers as Record<string, unknown>,
          ip: (req as any).ip as string | undefined,
        }) || undefined,
      walletId: String(params.params?.id || '').trim() || undefined,
    });
    sendExpressRouteResponse(res, response);
  });
}
