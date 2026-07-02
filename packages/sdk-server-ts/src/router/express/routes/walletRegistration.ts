import type { Request, Response, Router as ExpressRouter } from 'express';
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
import type { RouteResponse } from '../../routeExecutionContext';
import { resolveSourceIpFromExpressRequest } from '../../routerApiKeyAuth';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { sendExpressRouteResponse } from '../../routeResponses';
import type { ExpressRouterApiContext } from '../createRouterApiRouter';

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

export function registerWalletRegistrationRoutes(
  router: ExpressRouter,
  ctx: ExpressRouterApiContext,
): void {
  for (const routeId of ROUTE_IDS) {
    const route = findRouteDefinitionById(ctx.routeDefinitions, routeId);
    if (!route) {
      throw new Error(`Missing route definition for ${routeId}`);
    }
    router.post(route.path, async (req: Request, res: Response) => {
      try {
        const headers = (req.headers || {}) as Record<string, string | string[] | undefined>;
        const params = (req as { params?: Record<string, string | undefined> }).params || {};
        const common = {
          body: req.body,
          headers,
          logger: ctx.logger,
          origin: String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined,
          pathParams: {
            walletId: typeof params.walletId === 'string' ? params.walletId : undefined,
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
          sourceIp:
            resolveSourceIpFromExpressRequest({
              headers: headers as Record<string, unknown>,
              ip: (req as any).ip as string | undefined,
            }) || undefined,
        };
        const response: RouteResponse<unknown> =
          routeId === 'wallet_registration_intent'
            ? await handleRouterApiWalletRegistrationIntent(common)
            : routeId === 'wallet_registration_prepare'
              ? await handleRouterApiWalletRegistrationPrepare(common)
              : routeId === 'wallet_registration_start'
                ? await handleRouterApiWalletRegistrationStart(common)
                : routeId === 'wallet_registration_hss_respond'
                  ? await handleRouterApiWalletRegistrationHssRespond(common)
                  : routeId === 'wallet_registration_finalize'
                    ? await handleRouterApiWalletRegistrationFinalize(common)
                    : routeId === 'wallet_add_signer_intent'
                      ? await handleRouterApiWalletAddSignerIntent(common)
                      : routeId === 'wallet_add_signer_start'
                        ? await handleRouterApiWalletAddSignerStart(common)
                        : routeId === 'wallet_add_signer_hss_respond'
                          ? await handleRouterApiWalletAddSignerHssRespond(common)
                          : routeId === 'wallet_add_signer_finalize'
                            ? await handleRouterApiWalletAddSignerFinalize(common)
                            : routeId === 'wallet_add_auth_method_intent'
                              ? await handleRouterApiWalletAddAuthMethodIntent(common)
                              : routeId === 'wallet_add_auth_method_start'
                                ? await handleRouterApiWalletAddAuthMethodStart(common)
                                : routeId === 'wallet_add_auth_method_finalize'
                                  ? await handleRouterApiWalletAddAuthMethodFinalize(common)
                                  : routeId === 'wallet_revoke_auth_method'
                                    ? await handleRouterApiWalletRevokeAuthMethod(common)
                                    : routeId === 'wallet_ecdsa_key_facts_inventory'
                                      ? await handleRouterApiWalletEcdsaKeyFactsInventory(common)
                                      : await handleRouterApiWalletNearImplicitAccountFund(common);
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
}
