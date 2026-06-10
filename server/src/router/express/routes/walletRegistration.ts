import type { Request, Response, Router as ExpressRouter } from 'express';
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
} from '../../relayWalletRegistration';
import type { RouteResponse } from '../../routeExecutionContext';
import { resolveSourceIpFromExpressRequest } from '../../relayApiKeyAuth';
import { findRouteDefinitionById } from '../../routeDefinitions';
import { sendExpressRouteResponse } from '../../routeResponses';
import type { ExpressRelayContext } from '../createRelayRouter';

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

export function registerWalletRegistrationRoutes(
  router: ExpressRouter,
  ctx: ExpressRelayContext,
): void {
  for (const routeId of ROUTE_IDS) {
    const route = findRouteDefinitionById(ctx.routeDefinitions, routeId);
    if (!route) throw new Error(`Missing route definition for ${routeId}`);
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
            walletId:
              typeof params.walletId === 'string' ? params.walletId : undefined,
          },
          route,
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
        };
        const response: RouteResponse<unknown> =
          routeId === 'wallet_registration_intent'
            ? await handleRelayWalletRegistrationIntent(common)
            : routeId === 'wallet_registration_prepare'
              ? await handleRelayWalletRegistrationPrepare(common)
            : routeId === 'wallet_registration_start'
              ? await handleRelayWalletRegistrationStart(common)
              : routeId === 'wallet_registration_hss_respond'
                ? await handleRelayWalletRegistrationHssRespond(common)
                : routeId === 'wallet_registration_finalize'
                  ? await handleRelayWalletRegistrationFinalize(common)
                  : routeId === 'wallet_add_signer_intent'
                    ? await handleRelayWalletAddSignerIntent(common)
                    : routeId === 'wallet_add_signer_start'
                      ? await handleRelayWalletAddSignerStart(common)
                      : routeId === 'wallet_add_signer_hss_respond'
                        ? await handleRelayWalletAddSignerHssRespond(common)
                        : routeId === 'wallet_add_signer_finalize'
                          ? await handleRelayWalletAddSignerFinalize(common)
                          : routeId === 'wallet_add_auth_method_intent'
                            ? await handleRelayWalletAddAuthMethodIntent(common)
                            : routeId === 'wallet_add_auth_method_start'
                              ? await handleRelayWalletAddAuthMethodStart(common)
                              : routeId === 'wallet_add_auth_method_finalize'
                                ? await handleRelayWalletAddAuthMethodFinalize(common)
                                : routeId === 'wallet_revoke_auth_method'
                                  ? await handleRelayWalletRevokeAuthMethod(common)
                          : await handleRelayWalletEcdsaKeyFactsInventory(common);
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
