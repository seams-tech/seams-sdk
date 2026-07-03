import type { Router as ExpressRouter } from 'express';
import express from 'express';
import type { RouterApiOptions } from '../routerApi';
import type { RouterApiServiceBag } from '../authServicePort';
import type { NormalizedRouterLogger } from '../logger';
import { coerceRouterLogger } from '../logger';
import { installCors } from './cors';
import { registerBootstrapGrantRoutes } from './routes/bootstrapGrants';
import { registerApiWalletRoutes } from './routes/apiWallets';
import { registerEmailRecoveryRoutes } from './routes/emailRecovery';
import { registerHealthRoutes } from './routes/health';
import { registerRecoverEmailRoute } from './routes/recoverEmail';
import { registerWalletRegistrationRoutes } from './routes/walletRegistration';
import { registerSessionRoutes } from './routes/sessions';
import { registerSignedDelegateRoutes } from './routes/signedDelegate';
import { registerSyncAccountRoutes } from './routes/syncAccount';
import { registerThresholdEd25519Routes } from './routes/thresholdEd25519';
import { registerThresholdEcdsaRoutes } from './routes/thresholdEcdsa';
import { registerWebAuthnAuthenticatorRoutes } from './routes/webauthnAuthenticators';
import { registerAuthRoutes } from './routes/auth';
import { registerNearPublicKeysRoutes } from './routes/nearPublicKeys';
import { registerSponsoredEvmCallRoutes } from './routes/sponsoredEvmCall';
import { registerWellKnownRoutes } from './routes/wellKnown';
import { resolveThresholdOption } from '../routerOptions';
import { validateRouterApiRorOptions } from '../ror/provider';
import { registerSigningSessionSealRoutes } from '../../threshold/session/signingSessionSeal';
import { DEFAULT_SESSION_COOKIE_NAME } from '../routerApi';
import {
  attachRouterApiRouteSurface,
  isEmailRecoveryPrepareRoutesEnabled,
  isRecoverEmailRouteEnabled,
  resolveRouterApiRouteSurface,
} from '../routerApiRouteSurface';
import type { RouteDefinition } from '../routeDefinitions';
import {
  getRouterApiRouteExtensionRoutes,
  getRouterApiRouteExtensionsForTransport,
} from '../routeExtensions';
import { resolveRouterApiModuleRouteExtensions } from '../modules';

export interface ExpressRouterApiContext {
  service: RouterApiServiceBag;
  opts: RouterApiOptions;
  logger: NormalizedRouterLogger;
  mePath: string;
  routeDefinitions: readonly RouteDefinition[];
  signedDelegatePath: string;
}

export function createRouterApiRouter(
  service: RouterApiServiceBag,
  opts: RouterApiOptions = {},
): ExpressRouter {
  const router = express.Router();

  const threshold = resolveThresholdOption(service, opts);
  const sessionCookieName =
    String(opts.sessionCookieName || '').trim() || DEFAULT_SESSION_COOKIE_NAME;
  const routeExtensions = resolveRouterApiModuleRouteExtensions(opts);
  const effectiveOpts: RouterApiOptions = {
    ...opts,
    threshold,
    sessionCookieName,
    routeExtensions,
    modules: [],
  };
  if (effectiveOpts.ror) {
    validateRouterApiRorOptions(effectiveOpts.ror);
  }

  const logger = coerceRouterLogger(effectiveOpts.logger);
  const routeSurface = resolveRouterApiRouteSurface(effectiveOpts, { transport: 'express' });
  const { mePath, routeDefinitions, signedDelegatePath } = routeSurface;
  const emailRecoveryPrepareRoutesEnabled = isEmailRecoveryPrepareRoutesEnabled(effectiveOpts);
  const recoverEmailRouteEnabled = isRecoverEmailRouteEnabled(effectiveOpts);
  const expressRouteExtensions = getRouterApiRouteExtensionsForTransport(
    routeExtensions,
    'express',
  );

  installCors(router, effectiveOpts);

  const ctx: ExpressRouterApiContext = {
    service,
    opts: effectiveOpts,
    logger,
    mePath,
    routeDefinitions,
    signedDelegatePath,
  };

  registerBootstrapGrantRoutes(router, ctx);
  registerWalletRegistrationRoutes(router, ctx);
  registerApiWalletRoutes(router, ctx);
  registerSponsoredEvmCallRoutes(router, ctx);
  registerSignedDelegateRoutes(router, ctx);
  registerAuthRoutes(router, ctx);
  registerSyncAccountRoutes(router, ctx);
  if (emailRecoveryPrepareRoutesEnabled) {
    registerEmailRecoveryRoutes(router, ctx);
  }
  registerThresholdEd25519Routes(router, ctx);
  registerThresholdEcdsaRoutes(router, ctx);
  registerSigningSessionSealRoutes(router, {
    logger: ctx.logger,
    session: ctx.opts.session,
    options: ctx.opts.signingSessionSeal,
  });
  registerWebAuthnAuthenticatorRoutes(router, ctx);
  registerNearPublicKeysRoutes(router, ctx);
  registerSessionRoutes(router, ctx);
  if (recoverEmailRouteEnabled) {
    registerRecoverEmailRoute(router, ctx);
  }
  for (const extension of expressRouteExtensions) {
    extension.registerExpressRoutes({
      router,
      routes: getRouterApiRouteExtensionRoutes(extension, 'express'),
    });
  }
  registerHealthRoutes(router, ctx);
  registerWellKnownRoutes(router, ctx);

  return attachRouterApiRouteSurface(router, routeSurface);
}
