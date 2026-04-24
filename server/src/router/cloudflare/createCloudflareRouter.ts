import type { AuthService } from '../../core/AuthService';
import type { RelayRouterOptions } from '../relay';
import type { NormalizedRouterLogger } from '../logger';
import { coerceRouterLogger } from '../logger';
import type { CfEnv, CfExecutionContext, FetchHandler } from './types';
import { json, withCors } from './http';
import { handleApiWallets } from './routes/apiWallets';
import { handleBootstrapGrant } from './routes/bootstrapGrants';
import { handleCreateAccountAndRegisterUser } from './routes/createAccountAndRegisterUser';
import { handleEmailRecoveryPrepare } from './routes/emailRecovery';
import { handleHealth, handleReady } from './routes/health';
import { handleLinkDevice } from './routes/linkDevice';
import { handleRecoverEmail } from './routes/recoverEmail';
import { handleRegistrationThresholdEd25519Hss } from './routes/registrationThresholdEd25519Hss';
import { handleSmartAccountDeployment } from './routes/smartAccountDeployment';
import { handleSponsoredEvmCall } from './routes/sponsoredEvmCall';
import {
  handleSessionState,
  handleSessionExchange,
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
  handleWalletEmailOtpRecoveryKeyConsume,
  handleWalletEmailOtpRecoveryWrappedEscrows,
  handleWalletEmailOtpSigningSessionVerify,
  handleWalletState,
  handleWalletUnlockChallenge,
  handleWalletUnlockVerify,
} from './routes/sessions';
import { handleSignedDelegate } from './routes/signedDelegate';
import { handleSyncAccount } from './routes/syncAccount';
import { handleThresholdEd25519 } from './routes/thresholdEd25519';
import { handleThresholdEcdsa } from './routes/thresholdEcdsa';
import { handleWebAuthnAuthenticators } from './routes/webauthnAuthenticators';
import { handleAuth } from './routes/auth';
import { handleNearPublicKeys } from './routes/nearPublicKeys';
import { handleWellKnown } from './routes/wellKnown';
import { resolveThresholdOption } from '../routerOptions';
import { validateRelayRouterRorOptions } from '../ror/provider';
import { handleSigningSessionSealRoutes } from '../../threshold/session/signingSessionSeal';
import { DEFAULT_SESSION_COOKIE_NAME } from '../relay';
import { attachRelayRouteSurface, resolveRelayRouteSurface } from '../relayRouteSurface';
import type { RouteDefinition } from '../routeDefinitions';

export interface CloudflareRelayContext {
  request: Request;
  url: URL;
  pathname: string;
  method: string;
  env?: CfEnv;
  cfCtx?: CfExecutionContext;

  service: AuthService;
  opts: RelayRouterOptions;
  logger: NormalizedRouterLogger;

  mePath: string;
  routeDefinitions: readonly RouteDefinition[];
  signedDelegatePath: string;
}

export function createCloudflareRouter(
  service: AuthService,
  opts: RelayRouterOptions = {},
): FetchHandler {
  const notFound = () => new Response('Not Found', { status: 404 });

  const threshold = resolveThresholdOption(service, opts);
  const sessionCookieName =
    String(opts.sessionCookieName || '').trim() || DEFAULT_SESSION_COOKIE_NAME;
  const effectiveOpts: RelayRouterOptions = { ...opts, threshold, sessionCookieName };
  if (effectiveOpts.ror) {
    validateRelayRouterRorOptions(effectiveOpts.ror);
  }

  const logger = coerceRouterLogger(effectiveOpts.logger);
  const routeSurface = resolveRelayRouteSurface(effectiveOpts);
  const { mePath, routeDefinitions, signedDelegatePath } = routeSurface;

  const handlers: Array<(c: CloudflareRelayContext) => Promise<Response | null>> = [
    handleWellKnown,
    handleBootstrapGrant,
    handleRegistrationThresholdEd25519Hss,
    handleCreateAccountAndRegisterUser,
    handleApiWallets,
    handleSponsoredEvmCall,
    handleSignedDelegate,
    handleAuth,
    handleSyncAccount,
    handleSmartAccountDeployment,
    handleLinkDevice,
    handleEmailRecoveryPrepare,
    handleThresholdEd25519,
    handleThresholdEcdsa,
    async (c: CloudflareRelayContext) =>
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
    handleWalletEmailOtpRecoveryKeyConsume,
    handleWalletEmailOtpSigningSessionVerify,
    handleWalletEmailOtpUnseal,
    handleWalletEmailOtpSigningSessionUnseal,
    handleWalletEmailOtpDevCleanupGoogleRegistration,
    handleWalletEmailOtpDevOtpOutbox,
    handleWalletState,
    handleWalletLock,
    handleRecoverEmail,
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

    const baseCtx: Omit<CloudflareRelayContext, 'request' | 'url' | 'pathname' | 'method'> = {
      env,
      cfCtx,
      service,
      opts: effectiveOpts,
      logger,
      mePath,
      routeDefinitions,
      signedDelegatePath,
    };

    const ctx: CloudflareRelayContext = {
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
  return attachRelayRouteSurface(handler, routeSurface);
}
