import type { Router as ExpressRouter } from 'express';
import express from 'express';
import type { AuthService } from '../../core/AuthService';
import type { DelegateActionPolicy } from '../../delegateAction';
import { ensureLeadingSlash } from '@shared/utils/validation';
import type { RelayRouterOptions } from '../relay';
import type { NormalizedRouterLogger } from '../logger';
import { coerceRouterLogger } from '../logger';
import { installCors } from './cors';
import { registerBootstrapGrantRoutes } from './routes/bootstrapGrants';
import { registerCreateAccountAndRegisterUser } from './routes/createAccountAndRegisterUser';
import { registerEmailRecoveryRoutes } from './routes/emailRecovery';
import { registerHealthRoutes } from './routes/health';
import { registerLinkDeviceRoutes } from './routes/linkDevice';
import { registerRecoverEmailRoute } from './routes/recoverEmail';
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
import { registerSmartAccountDeployRoute } from './routes/smartAccountDeploy';
import { resolveThresholdOption } from '../routerOptions';
import { validateRelayRouterRorOptions } from '../ror/provider';
import { registerPrfSessionSealRoutes } from '../../threshold/session/prfSessionSeal';
import { DEFAULT_SESSION_COOKIE_NAME } from '../relay';

export interface ExpressRelayContext {
  service: AuthService;
  opts: RelayRouterOptions;
  logger: NormalizedRouterLogger;
  mePath: string;
  signedDelegatePath: string;
  signedDelegatePolicy?: DelegateActionPolicy;
}

export function createRelayRouter(
  service: AuthService,
  opts: RelayRouterOptions = {},
): ExpressRouter {
  const router = express.Router();

  const threshold = resolveThresholdOption(service, opts);
  const sessionCookieName =
    String(opts.sessionCookieName || '').trim() || DEFAULT_SESSION_COOKIE_NAME;
  const effectiveOpts: RelayRouterOptions = { ...opts, threshold, sessionCookieName };
  if (effectiveOpts.ror) {
    validateRelayRouterRorOptions(effectiveOpts.ror);
  }

  const mePath = effectiveOpts.sessionRoutes?.state || '/session/state';
  const logger = coerceRouterLogger(effectiveOpts.logger);
  let signedDelegatePath = '';
  if (effectiveOpts.signedDelegate) {
    signedDelegatePath =
      ensureLeadingSlash(effectiveOpts.signedDelegate.route) || '/signed-delegate';
  }
  const signedDelegatePolicy = effectiveOpts.signedDelegate?.policy;

  installCors(router, effectiveOpts);

  const ctx: ExpressRelayContext = {
    service,
    opts: effectiveOpts,
    logger,
    mePath,
    signedDelegatePath,
    signedDelegatePolicy,
  };

  registerBootstrapGrantRoutes(router, ctx);
  registerCreateAccountAndRegisterUser(router, ctx);
  registerSponsoredEvmCallRoutes(router, ctx);
  registerSignedDelegateRoutes(router, ctx);
  registerAuthRoutes(router, ctx);
  registerSmartAccountDeployRoute(router, ctx);
  registerSyncAccountRoutes(router, ctx);
  registerLinkDeviceRoutes(router, ctx);
  registerEmailRecoveryRoutes(router, ctx);
  registerThresholdEd25519Routes(router, ctx);
  registerThresholdEcdsaRoutes(router, ctx);
  registerPrfSessionSealRoutes(router, {
    logger: ctx.logger,
    session: ctx.opts.session,
    options: ctx.opts.prfSessionSeal,
  });
  registerWebAuthnAuthenticatorRoutes(router, ctx);
  registerNearPublicKeysRoutes(router, ctx);
  registerSessionRoutes(router, ctx);
  registerRecoverEmailRoute(router, ctx);
  registerHealthRoutes(router, ctx);
  registerWellKnownRoutes(router, ctx);

  return router;
}
