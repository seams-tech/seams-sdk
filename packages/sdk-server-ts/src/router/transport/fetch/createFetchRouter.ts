import { coerceRouterLogger } from '../../framework/logger';
import { json, withCors } from '../../framework/http';
import { handleEmailRecoveryPrepare } from './routes/emailRecovery';
import { handleHealth, handleReady } from './routes/health';
import { handleRecoverEmail } from './routes/recoverEmail';
import { handleWalletRegistration } from './routes/walletRegistration';
import {
  handlePasskeyCustody,
  handleWalletCustodyCredentialsList,
  handleWalletCustodyCredentialLabel,
  handleWalletRecoveryBackupAcknowledge,
  handleWalletRecoveryRotate,
  handleWalletRecoveryRead,
  handleWalletRecoveryStatus,
  handleWalletRecoveryFinalize,
  handleWalletRecoveryPrepare,
} from './routes/passkeyCustody';
import {
  handleSessionState,
  handleSessionExchange,
  handleReusableWalletSessionStatus,
  handleSessionRefresh,
  handleSessionRevoke,
  handleWalletLock,
  handleWalletEmailOtpRegistrationChallenge,
  handleWalletEmailOtpRegistrationSeal,
  handleWalletEmailOtpRegistrationFinalize,
  handleWalletEmailOtpLoginChallenge,
  handleWalletEmailOtpRecoveryBootstrapChallenge,
  handleWalletEmailOtpRecoveryBootstrapVerify,
  handleWalletEmailOtpSigningSessionChallenge,
  handleWalletEmailOtpDevCleanupGoogleRegistration,
  handleWalletEmailOtpDevOtpOutbox,
  handleWalletEmailOtpFactorRelease,
  handleWalletEmailOtpLoginVerify,
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
import { handleDeviceLinking } from './routes/deviceLinking';
import {
  handleDeviceManagement,
  LINKED_DEVICE_MANAGEMENT_BASE_V1,
} from './routes/deviceManagement';
import { validateRouterApiRorOptions } from '../../framework/ror/provider';
import { handleSigningSessionSealRoutes } from '../../../threshold/session/signingSessionSeal/transport/fetch';
import { DEFAULT_SESSION_COOKIE_NAME } from '../../framework/routerApi';
import {
  attachRouterApiRouteSurface,
  isEmailRecoveryPrepareRoutesEnabled,
  isRecoverEmailRouteEnabled,
  resolveRouterApiRouteSurface,
} from '../../framework/routerApiRouteSurface';
import { findRouteDefinitionForRequest } from '../../framework/routeDefinitions';
import {
  getRouterApiRouteExtensionRoutes,
  getRouterApiRouteExtensionsForTransport,
} from '../../framework/routeExtensions';
import { resolveRouterApiModuleRouteExtensions } from '../../framework/modules';
import type { RouterApiServiceBag } from '../../framework/authServicePort';
import type { RouterApiOptions } from '../../framework/routerApi';
import type {
  FetchRouterApiContext,
  FetchRouterHandler,
  FetchRouterRuntime,
} from './fetchRouter.types';

export type {
  FetchRouterApiContext,
  FetchRouterHandler,
  FetchRouterRuntime,
} from './fetchRouter.types';

export function createFetchRouter(
  service: RouterApiServiceBag,
  opts: RouterApiOptions,
  runtime: FetchRouterRuntime,
): FetchRouterHandler {
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
  const routeSurface = resolveRouterApiRouteSurface(effectiveOpts, { transport: 'fetch' });
  const { mePath, routeDefinitions } = routeSurface;
  const emailRecoveryPrepareRoutesEnabled = isEmailRecoveryPrepareRoutesEnabled(effectiveOpts);
  const recoverEmailRouteEnabled = isRecoverEmailRouteEnabled(effectiveOpts);
  const fetchRouteExtensions = getRouterApiRouteExtensionsForTransport(routeExtensions, 'fetch');

  const handlers: Array<(c: FetchRouterApiContext) => Promise<Response | null>> = [
    handleWellKnown,
    handleWalletRegistration,
    handleDeviceLinking,
    async (context: FetchRouterApiContext) => {
      if (!context.pathname.startsWith(LINKED_DEVICE_MANAGEMENT_BASE_V1)) return null;
      const service = context.service.deviceManagement;
      if (!service) {
        return json(
          {
            ok: false,
            code: 'not_supported',
            message: 'Linked-device management is not configured',
          },
          { status: 501 },
        );
      }
      return await handleDeviceManagement(context, service);
    },
    handlePasskeyCustody,
    handleWalletCustodyCredentialsList,
    handleWalletCustodyCredentialLabel,
    handleWalletRecoveryPrepare,
    handleWalletRecoveryFinalize,
    handleWalletRecoveryBackupAcknowledge,
    handleWalletRecoveryRotate,
    handleWalletRecoveryRead,
    handleWalletRecoveryStatus,
    handleAuth,
    handleSyncAccount,
    ...(emailRecoveryPrepareRoutesEnabled ? [handleEmailRecoveryPrepare] : []),
    handleThresholdEd25519,
    handleThresholdEcdsa,
    async (c: FetchRouterApiContext) =>
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
    handleReusableWalletSessionStatus,
    handleSessionRefresh,
    handleWalletUnlockChallenge,
    handleWalletUnlockVerify,
    handleWalletEmailOtpRegistrationChallenge,
    handleWalletEmailOtpRegistrationSeal,
    handleWalletEmailOtpRegistrationFinalize,
    handleWalletEmailOtpLoginChallenge,
    handleWalletEmailOtpRecoveryBootstrapChallenge,
    handleWalletEmailOtpRecoveryBootstrapVerify,
    handleWalletEmailOtpSigningSessionChallenge,
    handleWalletEmailOtpLoginVerify,
    handleWalletEmailOtpSigningSessionVerify,
    handleWalletEmailOtpFactorRelease,
    handleWalletEmailOtpDevCleanupGoogleRegistration,
    handleWalletEmailOtpDevOtpOutbox,
    handleWalletState,
    handleWalletLock,
    ...fetchRouteExtensions.map((extension) => {
      const extensionRoutes = getRouterApiRouteExtensionRoutes(extension, 'fetch');
      return async (c: FetchRouterApiContext): Promise<Response | null> => {
        const route = findRouteDefinitionForRequest(extensionRoutes, c.method, c.pathname);
        if (!route) return null;
        return await extension.handleFetchRoute({
          request: c.request,
          route,
          pathname: c.pathname,
          method: c.method,
          logger: c.logger,
          runtime: c.runtime,
        });
      };
    }),
    ...(recoverEmailRouteEnabled ? [handleRecoverEmail] : []),
    handleHealth,
    handleReady,
  ];

  const handler: FetchRouterHandler = async function handler(
    request: Request,
    requestRuntime: FetchRouterRuntime = runtime,
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

    const baseCtx: Omit<FetchRouterApiContext, 'request' | 'url' | 'pathname' | 'method'> = {
      runtime: requestRuntime,
      service,
      opts: effectiveOpts,
      logger,
      mePath,
      routeDefinitions,
    };

    const ctx: FetchRouterApiContext = {
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

      const res = notFound();
      withCors(res.headers, effectiveOpts, request);
      return res;
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
