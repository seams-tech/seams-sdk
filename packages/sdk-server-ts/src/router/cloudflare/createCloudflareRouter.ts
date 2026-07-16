import type { RouterApiServiceBag } from '../authServicePort';
import type { RouterApiOptions } from '../routerApi';
import type { NormalizedRouterLogger } from '../logger';
import { coerceRouterLogger } from '../logger';
import type { CfEnv, CfExecutionContext, FetchHandler } from './cloudflare.types';
import { json, withCors } from './http';
import { handleEmailRecoveryPrepare } from './routes/emailRecovery';
import { handleHealth, handleReady } from './routes/health';
import { handleRecoverEmail } from './routes/recoverEmail';
import { handleWalletRegistration } from './routes/walletRegistration';
import {
  handleSessionState,
  handleSessionExchange,
  handleSigningBudgetStatus,
  handleSessionRefresh,
  handleSessionRevoke,
  handleWalletLock,
  handleWalletEmailOtpRegistrationChallenge,
  handleWalletEmailOtpRegistrationSeal,
  handleWalletEmailOtpRegistrationFinalize,
  handleWalletEmailOtpLoginChallenge,
  handleWalletEmailOtpDeviceRecoveryChallenge,
  handleWalletEmailOtpSigningSessionChallenge,
  handleWalletEmailOtpDevCleanupGoogleRegistration,
  handleWalletEmailOtpDevOtpOutbox,
  handleWalletEmailOtpUnseal,
  handleWalletEmailOtpSigningSessionUnseal,
  handleWalletEmailOtpLoginVerify,
  handleWalletEmailOtpLoginVerifyAndUnseal,
  handleWalletEmailOtpRecoveryKeyAttemptFailed,
  handleWalletEmailOtpRecoveryKeyConsume,
  handleWalletEmailOtpRecoveryKeyRotate,
  handleWalletEmailOtpRecoveryKeyStatus,
  handleWalletEmailOtpRecoveryWrappedEscrows,
  handleWalletEmailOtpSigningSessionVerify,
  handleWalletState,
  handleWalletUnlockChallenge,
  handleWalletUnlockVerify,
} from './routes/sessions';
import { handleSyncAccount } from './routes/syncAccount';
import { handleThresholdEd25519 } from './routes/thresholdEd25519';
import { handleThresholdEcdsa } from './routes/thresholdEcdsa';
import { handleWebAuthnAuthenticators } from './routes/webauthnAuthenticators';
import { handleAuth } from './routes/auth';
import { handleNearPublicKeys } from './routes/nearPublicKeys';
import { handleWellKnown } from './routes/wellKnown';
import { validateRouterApiRorOptions } from '../ror/provider';
import { handleSigningSessionSealRoutes } from '../../threshold/session/signingSessionSeal/transport/cloudflare';
import { DEFAULT_SESSION_COOKIE_NAME } from '../routerApi';
import {
  attachRouterApiRouteSurface,
  isEmailRecoveryPrepareRoutesEnabled,
  isRecoverEmailRouteEnabled,
  resolveRouterApiRouteSurface,
} from '../routerApiRouteSurface';
import { findRouteDefinitionForRequest, type RouteDefinition } from '../routeDefinitions';
import {
  getRouterApiRouteExtensionRoutes,
  getRouterApiRouteExtensionsForTransport,
} from '../routeExtensions';
import { resolveRouterApiModuleRouteExtensions } from '../modules';

export interface CloudflareRouterApiContext {
  request: Request;
  url: URL;
  pathname: string;
  method: string;
  env?: CfEnv;
  cfCtx?: CfExecutionContext;

  service: RouterApiServiceBag;
  opts: RouterApiOptions;
  logger: NormalizedRouterLogger;

  mePath: string;
  routeDefinitions: readonly RouteDefinition[];
}

export function createCloudflareRouter(
  service: RouterApiServiceBag,
  opts: RouterApiOptions = {},
): FetchHandler {
  const notFound = () => new Response('Not Found', { status: 404 });

  const sessionCookieName =
    String(opts.sessionCookieName || '').trim() || DEFAULT_SESSION_COOKIE_NAME;
  const routeExtensions = resolveRouterApiModuleRouteExtensions(opts);
  const effectiveOpts: RouterApiOptions = {
    ...opts,
    sessionCookieName,
    routeExtensions,
    modules: [],
  };
  if (effectiveOpts.ror) {
    validateRouterApiRorOptions(effectiveOpts.ror);
  }

  const logger = coerceRouterLogger(effectiveOpts.logger);
  const routeSurface = resolveRouterApiRouteSurface(effectiveOpts, { transport: 'cloudflare' });
  const { mePath, routeDefinitions } = routeSurface;
  const emailRecoveryPrepareRoutesEnabled = isEmailRecoveryPrepareRoutesEnabled(effectiveOpts);
  const recoverEmailRouteEnabled = isRecoverEmailRouteEnabled(effectiveOpts);
  const cloudflareRouteExtensions = getRouterApiRouteExtensionsForTransport(
    routeExtensions,
    'cloudflare',
  );

  const handlers: Array<(c: CloudflareRouterApiContext) => Promise<Response | null>> = [
    handleWellKnown,
    handleWalletRegistration,
    handleAuth,
    handleSyncAccount,
    ...(emailRecoveryPrepareRoutesEnabled ? [handleEmailRecoveryPrepare] : []),
    handleThresholdEd25519,
    handleThresholdEcdsa,
    async (c: CloudflareRouterApiContext) =>
      await handleSigningSessionSealRoutes({
        request: c.request,
        pathname: c.pathname,
        method: c.method,
        logger: c.logger,
        session: c.opts.session,
        options: c.opts.signingSessionSeal,
      }),
    handleWebAuthnAuthenticators,
    handleNearPublicKeys,
    handleSessionState,
    handleSessionExchange,
    handleSessionRevoke,
    handleSigningBudgetStatus,
    handleSessionRefresh,
    handleWalletUnlockChallenge,
    handleWalletUnlockVerify,
    handleWalletEmailOtpRegistrationChallenge,
    handleWalletEmailOtpRegistrationSeal,
    handleWalletEmailOtpRegistrationFinalize,
    handleWalletEmailOtpLoginChallenge,
    handleWalletEmailOtpDeviceRecoveryChallenge,
    handleWalletEmailOtpSigningSessionChallenge,
    handleWalletEmailOtpLoginVerify,
    handleWalletEmailOtpLoginVerifyAndUnseal,
    handleWalletEmailOtpRecoveryWrappedEscrows,
    handleWalletEmailOtpRecoveryKeyStatus,
    handleWalletEmailOtpRecoveryKeyRotate,
    handleWalletEmailOtpRecoveryKeyAttemptFailed,
    handleWalletEmailOtpRecoveryKeyConsume,
    handleWalletEmailOtpSigningSessionVerify,
    handleWalletEmailOtpUnseal,
    handleWalletEmailOtpSigningSessionUnseal,
    handleWalletEmailOtpDevCleanupGoogleRegistration,
    handleWalletEmailOtpDevOtpOutbox,
    handleWalletState,
    handleWalletLock,
    ...cloudflareRouteExtensions.map((extension) => {
      const extensionRoutes = getRouterApiRouteExtensionRoutes(extension, 'cloudflare');
      return async (c: CloudflareRouterApiContext): Promise<Response | null> => {
        const route = findRouteDefinitionForRequest(extensionRoutes, c.method, c.pathname);
        if (!route) return null;
        return await extension.handleCloudflareRoute({
          request: c.request,
          route,
          pathname: c.pathname,
          method: c.method,
          logger: c.logger,
          env: c.env,
          cfCtx: c.cfCtx,
        });
      };
    }),
    ...(recoverEmailRouteEnabled ? [handleRecoverEmail] : []),
    handleHealth,
    handleReady,
  ];

  const handler: FetchHandler = async function handler(
    request: Request,
    env?: CfEnv,
    cfCtx?: CfExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method.toUpperCase();

    // Preflight CORS
    if (method === 'OPTIONS') {
      const res = new Response(null, { status: 204 });
      withCors(res.headers, effectiveOpts, request);
      return res;
    }

    const baseCtx: Omit<CloudflareRouterApiContext, 'request' | 'url' | 'pathname' | 'method'> = {
      env,
      cfCtx,
      service,
      opts: effectiveOpts,
      logger,
      mePath,
      routeDefinitions,
    };

    const ctx: CloudflareRouterApiContext = {
      ...baseCtx,
      request,
      url,
      pathname,
      method,
    };

    try {
      for (const fn of handlers) {
        const res = await fn(ctx);
        if (res) {
          withCors(res.headers, effectiveOpts, request);
          return res;
        }
      }

      return notFound();
    } catch (e: unknown) {
      const res = json(
        { code: 'internal', message: e instanceof Error ? e.message : String(e) },
        { status: 500 },
      );
      withCors(res.headers, effectiveOpts, request);
      return res;
    }
  };
  return attachRouterApiRouteSurface(handler, routeSurface);
}
