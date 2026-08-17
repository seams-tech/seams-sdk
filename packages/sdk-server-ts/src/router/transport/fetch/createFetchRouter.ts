import { coerceRouterLogger } from '../../framework/logger';
import { json, withCors } from '../../framework/http';
import { handleHealth, handleReady } from './routes/health';
import { handleWalletRegistration } from './routes/walletRegistration';
import {
  handlePasskeyCustody,
  handleWalletCustodyEmailOtpChallenge,
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
  handleReusableWalletSessionStatus,
  handleWalletEmailOtpRecoveryBootstrapChallenge,
  handleWalletEmailOtpRecoveryBootstrapVerify,
  handleWalletEmailOtpChallenge,
  handleWalletEmailOtpFactorRelease,
  handleWalletEmailOtpDevCleanupGoogleRegistration,
  handleWalletEmailOtpDevOutbox,
  handleWalletEmailOtpRegistrationSeal,
  handleHostedWalletSessionExchangeIssue,
  handleHostedWalletSessionExchangeRedeem,
  handleWalletUnlockChallenge,
  handleWalletUnlockVerify,
} from './routes/sessions';
import { handleSyncAccount } from './routes/syncAccount';
import { handleThresholdEd25519 } from './routes/thresholdEd25519';
import { handleThresholdEcdsa } from './routes/thresholdEcdsa';
import { handleOwnerWalletExecutionLanePreflight } from './routes/walletExecutionLanePreflight';
import { handleWebAuthnAuthenticators } from './routes/webauthnAuthenticators';
import { handleAuth } from './routes/auth';
import { handleNearPublicKeys } from './routes/nearPublicKeys';
import { handleWellKnown } from './routes/wellKnown';
import { handleDeviceLinking } from './routes/deviceLinking';
import {
  handleDeviceManagement,
  LINKED_DEVICE_MANAGEMENT_BASE_V1,
} from './routes/deviceManagement';
import {
  handleDeviceLinkingGatewayCompletion,
  LINKED_DEVICE_GATEWAY_COMPLETION_BASE_V1,
} from './routes/deviceLinkingGateway';
import { handleDeviceLinkingOwnerAuthorization } from './routes/deviceLinkingOwnerAuthorization';
import { handleDeviceLinkingLaneGateway } from './routes/deviceLinkingLaneGateway';
import { validateRouterApiRorOptions } from '../../framework/ror/provider';
import { handleSigningSessionSealRoutes } from '../../../threshold/session/signingSessionSeal/transport/fetch';
import type {
  SigningSessionSealAuthorizeInput,
  SigningSessionSealAuthorizeResult,
  SigningSessionSealCurve,
  SigningSessionSealLinkedDeviceWalletSessionRecord,
  SigningSessionSealThresholdSessionRecord,
} from '../../../threshold/session/signingSessionSeal/signingSessionSeal.types';
import { parseEcdsaKeyHandle } from '../../../core/keyMaterialBrands';
import { extractBearerCredential } from '../../auth/routerApiKeyAuth';
import { resolveOpaqueOwnerWalletSessionAdmission } from '../../auth/commonRouterUtils';
import { parseLinkedDeviceWalletSession } from '../../domains/signingOperations/linkedDeviceNormalSigning';
import { DEFAULT_SESSION_COOKIE_NAME } from '../../framework/routerApi';
import {
  attachRouterApiRouteSurface,
  resolveRouterApiRouteSurface,
} from '../../framework/routerApiRouteSurface';
import { findRouteDefinitionForRequest } from '../../framework/routeDefinitions';
import {
  getRouterApiRouteExtensionRoutes,
  getRouterApiRouteExtensionsForTransport,
} from '../../framework/routeExtensions';
import { resolveRouterApiModuleRouteExtensions } from '../../framework/modules';
import type {
  RouterApiAuthorizationSessionService,
  RouterApiServiceBag,
} from '../../framework/authServicePort';
import type { RouterApiOptions } from '../../framework/routerApi';
import type {
  FetchRouterApiContext,
  FetchRouterHandler,
  FetchRouterRuntime,
} from './fetchRouter.types';

const SIGNING_SESSION_SEAL_OWNER_CURVES = {
  ecdsa: 'ecdsa',
  ed25519: 'ed25519',
} as const satisfies Record<SigningSessionSealCurve, SigningSessionSealCurve>;

export type {
  FetchRouterApiContext,
  FetchRouterHandler,
  FetchRouterRuntime,
} from './fetchRouter.types';

function signingSessionSealRecordFromAdmission(
  admission: NonNullable<
    Awaited<ReturnType<typeof resolveOpaqueOwnerWalletSessionAdmission>>
  >,
): SigningSessionSealThresholdSessionRecord {
  switch (admission.curve) {
    case 'ecdsa':
      return {
        kind: 'owner_threshold_session',
        curve: 'ecdsa',
        thresholdSessionId: admission.binding.thresholdSessionId,
        userId: admission.binding.walletId,
        expiresAtMs: admission.binding.thresholdExpiresAtMs,
        relayerKeyId: admission.binding.relayerKeyId,
        participantIds: admission.binding.participantIds,
        keyHandle: parseEcdsaKeyHandle(admission.binding.keyHandle),
      };
    case 'ed25519':
      return {
        kind: 'owner_threshold_session',
        curve: 'ed25519',
        thresholdSessionId: admission.binding.thresholdSessionId,
        userId: admission.binding.walletId,
        expiresAtMs: admission.binding.thresholdExpiresAtMs,
        relayerKeyId: admission.binding.relayerKeyId,
        participantIds: admission.binding.participantIds,
        authorityScope: admission.binding.authorityScope,
      };
  }
}

async function authorizeSigningSessionSealWithOpaqueWalletSession(
  authorizationSessions: RouterApiAuthorizationSessionService | null | undefined,
  session: RouterApiOptions['session'],
  input: SigningSessionSealAuthorizeInput,
): Promise<SigningSessionSealAuthorizeResult> {
  if (!authorizationSessions) {
    return {
      ok: false,
      code: 'sessions_disabled',
      message: 'Opaque Wallet Sessions are not configured',
      status: 501,
    };
  }
  const token = extractBearerCredential(input.headers);
  if (!token) {
    return {
      ok: false,
      code: 'wallet_session_missing',
      message: 'Wallet Session is missing',
      status: 401,
    };
  }
  for (const curve of Object.values(SIGNING_SESSION_SEAL_OWNER_CURVES)) {
    const admission = await resolveOpaqueOwnerWalletSessionAdmission({
      authorizationSessions,
      token,
      curve,
      nowMs: Date.now(),
    });
    if (!admission) continue;
    const thresholdSession = signingSessionSealRecordFromAdmission(admission);
    if (thresholdSession.thresholdSessionId !== input.thresholdSessionId) {
      return {
        ok: false,
        code: 'wallet_session_scope_mismatch',
        message: 'Wallet Session does not match the requested threshold session',
        status: 403,
      };
    }
    return { ok: true, auth: { userId: thresholdSession.userId, session: thresholdSession } };
  }
  const linked = await parseLinkedDeviceWalletSession({
    session,
    headers: input.headers,
  });
  if (linked.kind === 'linked_device') {
    if (String(linked.claims.walletSessionId) !== input.thresholdSessionId) {
      return {
        ok: false,
        code: 'wallet_session_scope_mismatch',
        message: 'Wallet Session does not match the requested linked-device session',
        status: 403,
      };
    }
    const persisted = await authorizationSessions.readLinkedDeviceWalletSessionAuthorization({
      tenantId: linked.claims.tenantId,
      deviceId: linked.claims.deviceId,
      authorizationId: linked.claims.authorizationId,
      walletSessionId: linked.claims.walletSessionId,
      quotaId: linked.claims.quotaId,
      nowMs: Date.now(),
    });
    const authorization = persisted?.authorization;
    if (
      !authorization ||
      authorization.walletId !== linked.claims.walletId ||
      authorization.enrollmentId !== linked.claims.enrollmentId ||
      authorization.deviceId !== linked.claims.deviceId ||
      authorization.keyManifestDigestB64u !== linked.claims.keyManifestDigestB64u ||
      authorization.revocationEpoch !== linked.claims.revocationEpoch
    ) {
      return {
        ok: false,
        code: 'wallet_session_unavailable',
        message: 'Linked-device Wallet Session is unavailable',
        status: 401,
      };
    }
    const linkedSession: SigningSessionSealLinkedDeviceWalletSessionRecord = {
      kind: 'linked_device_wallet_session',
      userId: String(linked.claims.walletId),
      walletSessionId: String(linked.claims.walletSessionId),
      deviceId: String(linked.claims.deviceId),
      enrollmentId: String(linked.claims.enrollmentId),
      expiresAtMs: Math.min(linked.claims.expiresAtMs, persisted.quota.expiresAtMs),
      remainingUses: persisted.quota.remainingUses,
    };
    return { ok: true, auth: { userId: linkedSession.userId, session: linkedSession } };
  }
  return {
    ok: false,
    code: 'wallet_session_unavailable',
    message: 'Wallet Session is unavailable',
    status: 401,
  };
}

async function handleOpaqueWalletSigningSessionSeal(
  context: FetchRouterApiContext,
): Promise<Response | null> {
  return await handleSigningSessionSealRoutes({
    request: context.request,
    pathname: context.pathname,
    method: context.method,
    logger: context.logger,
    authorize: authorizeSigningSessionSealWithOpaqueWalletSession.bind(
      undefined,
      context.service.authorizationSessions,
      context.opts.session,
    ),
    options: context.opts.signingSessionSeal,
  });
}

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
  const { routeDefinitions } = routeSurface;
  const fetchRouteExtensions = getRouterApiRouteExtensionsForTransport(routeExtensions, 'fetch');

  const handlers: Array<(c: FetchRouterApiContext) => Promise<Response | null>> = [
    handleWellKnown,
    handleWalletRegistration,
    async (context: FetchRouterApiContext) => {
      if (!context.pathname.startsWith(LINKED_DEVICE_GATEWAY_COMPLETION_BASE_V1)) return null;
      const service = context.service.deviceLinkingGateway;
      if (!service) {
        return json(
          {
            ok: false,
            code: 'not_supported',
            message: 'Linked-device Gateway completion is not configured',
          },
          { status: 501 },
        );
      }
      return await handleDeviceLinkingGatewayCompletion(context, service);
    },
    async (context: FetchRouterApiContext) =>
      await handleDeviceLinkingOwnerAuthorization(
        context,
        context.service.deviceLinkingOwnerAuthorization,
      ),
    async (context: FetchRouterApiContext) =>
      await handleDeviceLinkingLaneGateway(context, context.service.deviceLinkingLaneGateway),
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
    handleWalletCustodyEmailOtpChallenge,
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
    handleOwnerWalletExecutionLanePreflight,
    handleThresholdEd25519,
    handleThresholdEcdsa,
    handleOpaqueWalletSigningSessionSeal,
    handleWebAuthnAuthenticators,
    handleNearPublicKeys,
    handleReusableWalletSessionStatus,
    handleHostedWalletSessionExchangeIssue,
    handleHostedWalletSessionExchangeRedeem,
    handleWalletUnlockChallenge,
    handleWalletUnlockVerify,
    handleWalletEmailOtpChallenge,
    handleWalletEmailOtpFactorRelease,
    handleWalletEmailOtpRecoveryBootstrapChallenge,
    handleWalletEmailOtpRecoveryBootstrapVerify,
    handleWalletEmailOtpDevCleanupGoogleRegistration,
    handleWalletEmailOtpRegistrationSeal,
    handleWalletEmailOtpDevOutbox,
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
