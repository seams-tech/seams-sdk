import type { Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import {
  DEFAULT_SPONSORED_EVM_CALL_ROUTE,
  registerSponsoredEvmCallRoute,
} from '../../../sponsorship/evmRelay';

export function registerSponsoredEvmCallRoutes(
  router: ExpressRouter,
  ctx: ExpressRelayContext,
): void {
  const options = ctx.opts.sponsoredEvmCall;
  if (!options) return;
  registerSponsoredEvmCallRoute({
    router,
    apiKeys: options.apiKeys,
    billing: options.billing,
    ledger: options.ledger,
    runtimeSnapshots: options.runtimeSnapshots,
    corsOrigins: (ctx.opts.corsOrigins || []).map((entry) => String(entry || '').trim()).filter(Boolean),
    config: options.config,
    route: options.route || DEFAULT_SPONSORED_EVM_CALL_ROUTE,
    logger: ctx.logger,
  });
}
