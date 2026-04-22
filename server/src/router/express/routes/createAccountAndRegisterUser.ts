import type { Request, Response, Router as ExpressRouter } from 'express';
import { handleRelayRegistrationBootstrap } from '../../relayRegistrationBootstrap';
import { resolveSourceIpFromExpressRequest } from '../../relayApiKeyAuth';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { sendExpressRouteResponse } from '../../routeResponses';
import type { ExpressRelayContext } from '../createRelayRouter';

export function registerCreateAccountAndRegisterUser(
  router: ExpressRouter,
  ctx: ExpressRelayContext,
): void {
  const route = findRouteDefinitionById(ctx.routeDefinitions, 'registration_bootstrap');
  if (!route) {
    throw new Error('Missing route definition for registration_bootstrap');
  }

  router.post(route.path, async (req: Request, res: Response) => {
    try {
      const headers = (req.headers || {}) as Record<string, string | string[] | undefined>;
      const response = await handleRelayRegistrationBootstrap({
        body: req.body,
        headers,
        logger: ctx.logger,
        origin: String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined,
        route,
        services: {
          authService: ctx.service,
          apiKeyAuth: ctx.opts.apiKeyAuth,
          apiKeyUsageMeter: ctx.opts.apiKeyUsageMeter,
          bootstrapTokenStore: ctx.opts.bootstrapTokenStore,
          orgProjectEnv: ctx.opts.orgProjectEnv,
          session: ctx.opts.session,
          smartAccountDeploy: ctx.opts.smartAccountDeploy,
        },
        sourceIp:
          resolveSourceIpFromExpressRequest({
            headers: headers as Record<string, unknown>,
            ip: (req as any).ip as string | undefined,
          }) || undefined,
      });
      sendExpressRouteResponse(res, response);
    } catch (error: unknown) {
      const message =
        error && typeof error === 'object' && 'message' in error
          ? String((error as { message?: unknown }).message || 'internal error')
          : 'internal error';
      sendExpressRouteResponse(res, {
        status: 500,
        body: { ok: false, code: 'internal', message },
      });
    }
  });
}
