import type { Request, Response, Router as ExpressRouter } from 'express';
import {
  handleRelayMachineWalletGet,
  handleRelayMachineWalletList,
  handleRelayMachineWalletSearch,
} from '../../relayMachineWallets';
import { resolveSourceIpFromExpressRequest } from '../../relayApiKeyAuth';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { sendExpressRouteResponse } from '../../routeResponses';
import type { ExpressRelayContext } from '../createRelayRouter';

export function registerMachineWalletRoutes(
  router: ExpressRouter,
  ctx: ExpressRelayContext,
): void {
  const listRoute = findRouteDefinitionById(ctx.routeDefinitions, 'machine_wallets_list');
  const searchRoute = findRouteDefinitionById(ctx.routeDefinitions, 'machine_wallets_search');
  const getRoute = findRouteDefinitionById(ctx.routeDefinitions, 'machine_wallets_get');
  if (!listRoute || !searchRoute || !getRoute) {
    throw new Error('Missing machine wallet route definitions');
  }

  router.get(listRoute.path, async (req: Request, res: Response) => {
    const headers = (req.headers || {}) as Record<string, string | string[] | undefined>;
    const response = await handleRelayMachineWalletList({
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
    const response = await handleRelayMachineWalletSearch({
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
    const response = await handleRelayMachineWalletGet({
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
