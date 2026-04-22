import type { Request, Response, Router as ExpressRouter } from 'express';
import {
  handleRelayRegistrationThresholdEd25519HssFinalize,
  handleRelayRegistrationThresholdEd25519HssPrepare,
  handleRelayRegistrationThresholdEd25519HssRespond,
} from '../../relayRegistrationThresholdEd25519Hss';
import { resolveSourceIpFromExpressRequest } from '../../relayApiKeyAuth';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { sendExpressRouteResponse } from '../../routeResponses';
import type { ExpressRelayContext } from '../createRelayRouter';

export function registerRegistrationThresholdEd25519HssRoutes(
  router: ExpressRouter,
  ctx: ExpressRelayContext,
): void {
  const prepareRoute = findRouteDefinitionById(
    ctx.routeDefinitions,
    'registration_threshold_ed25519_hss_prepare',
  );
  const finalizeRoute = findRouteDefinitionById(
    ctx.routeDefinitions,
    'registration_threshold_ed25519_hss_finalize',
  );
  const respondRoute = findRouteDefinitionById(
    ctx.routeDefinitions,
    'registration_threshold_ed25519_hss_respond',
  );
  if (!prepareRoute || !respondRoute || !finalizeRoute) {
    throw new Error('Missing route definition for registration threshold-ed25519 HSS routes');
  }

  router.post(prepareRoute.path, async (req: Request, res: Response) => {
    try {
      const headers = (req.headers || {}) as Record<string, string | string[] | undefined>;
      const response = await handleRelayRegistrationThresholdEd25519HssPrepare({
        body: req.body,
        headers,
        logger: ctx.logger,
        origin: String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined,
        route: prepareRoute,
        services: {
          authService: ctx.service,
          apiKeyAuth: ctx.opts.apiKeyAuth,
          bootstrapTokenStore: ctx.opts.bootstrapTokenStore,
          orgProjectEnv: ctx.opts.orgProjectEnv,
          session: ctx.opts.session,
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

  router.post(finalizeRoute.path, async (req: Request, res: Response) => {
    try {
      const headers = (req.headers || {}) as Record<string, string | string[] | undefined>;
      const response = await handleRelayRegistrationThresholdEd25519HssFinalize({
        body: req.body,
        headers,
        logger: ctx.logger,
        origin: String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined,
        route: finalizeRoute,
        services: {
          authService: ctx.service,
          apiKeyAuth: ctx.opts.apiKeyAuth,
          bootstrapTokenStore: ctx.opts.bootstrapTokenStore,
          orgProjectEnv: ctx.opts.orgProjectEnv,
          session: ctx.opts.session,
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

  router.post(respondRoute.path, async (req: Request, res: Response) => {
    try {
      const headers = (req.headers || {}) as Record<string, string | string[] | undefined>;
      const response = await handleRelayRegistrationThresholdEd25519HssRespond({
        body: req.body,
        headers,
        logger: ctx.logger,
        origin: String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined,
        route: respondRoute,
        services: {
          authService: ctx.service,
          apiKeyAuth: ctx.opts.apiKeyAuth,
          bootstrapTokenStore: ctx.opts.bootstrapTokenStore,
          orgProjectEnv: ctx.opts.orgProjectEnv,
          session: ctx.opts.session,
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
