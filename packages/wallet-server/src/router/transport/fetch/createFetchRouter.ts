import { coerceRouterLogger } from '../../framework/logger';
import { json, withCors } from '../../framework/http';
import { handleHealth, handleReady } from './routes/health';
import { handleWalletRegistration } from './routes/walletRegistration';
import {
  handlePasskeyCustody,
  handleWalletCustodyEmailOtpChallenge,
  handleWalletCustodyCredentialsList,
  handleWalletCustodyCredentialLabel,
  handleWalletCustodyEnvelopeOwnershipUpgrade,
  handleWalletRecoveryBackupAcknowledge,
  handleWalletRecoveryRotate,
  handleWalletRecoveryRead,
  handleWalletRecoveryStatus,
  handleWalletRecoveryFinalize,
  handleWalletRecoveryPrepare,
  handleWalletRecoveryGoogleVerify,
  handleWalletRecoveryEmailOtpVerify,
  handleWalletRecoveryEmailOtpRelease,
  handleWalletRecoveryGoogleEmailOtpFinalize,
} from './routes/passkeyCustody';
import {
  handleExactWalletSessionStatus,
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
import { handleDeviceLinkingOwnerAuthorization } from './routes/deviceLinkingOwnerAuthorization';
import { validateRouterApiRorOptions } from '../../framework/ror/provider';
import { handleSigningSessionSealRoutes } from '../../../threshold/session/signingSessionSeal/transport/fetch';
import type {
  SigningSessionSealAuthorizeInput,
  SigningSessionSealAuthorizeResult,
  SigningSessionSealThresholdSessionRecord,
} from '../../../threshold/session/signingSessionSeal/signingSessionSeal.types';
import { extractBearerCredential } from '../../auth/routerApiKeyAuth';
import {
  resolveWalletSessionOperationCredentialAdmissionFromContext,
  type WalletSessionOperationCredentialAdmission,
} from '../../auth/commonRouterUtils';
import {
  EVM_ECDSA_MPC_OPERATION_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
} from '@shared/authorization/capabilityKinds';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  routerAbMpcMaterialActivationRefToWire,
  sameRouterAbMpcMaterialActivationRef,
} from '@shared/utils/routerAbNormalSigningIdentity';
import { routerAbEcdsaDerivationActiveStateId } from '@shared/utils/routerAbEcdsaDerivation';
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
  RouterApiWalletRegistrationService,
} from '../../framework/authServicePort';
import type { RouterApiOptions } from '../../framework/routerApi';
import type {
  FetchRouterApiContext,
  FetchRouterHandler,
  FetchRouterRuntime,
} from './fetchRouter.types';

const SIGNING_SESSION_SEAL_OPERATIONS = [
  {
    keyFamily: 'ed25519',
    operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
  },
  {
    keyFamily: 'ecdsa_secp256k1',
    operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
  },
] as const;

export type {
  FetchRouterApiContext,
  FetchRouterHandler,
  FetchRouterRuntime,
} from './fetchRouter.types';

type SigningSessionSealRecordResolution =
  | { readonly kind: 'resolved'; readonly record: SigningSessionSealThresholdSessionRecord }
  | { readonly kind: 'inactive' }
  | { readonly kind: 'unavailable' };

async function signingSessionSealRecordFromExactAdmission(input: {
  readonly admission: WalletSessionOperationCredentialAdmission;
  readonly walletRegistration: RouterApiWalletRegistrationService;
}): Promise<SigningSessionSealRecordResolution> {
  const admission = input.admission;
  const walletId = String(admission.context.authorization.session.walletId);
  const expiresAtMs = admission.context.authorization.session.expiresAtMs;
  const materialActivation = routerAbMpcMaterialActivationRefToWire(
    admission.admission.materialActivation,
  );
  switch (admission.curve) {
    case 'ecdsa': {
      const active = await input.walletRegistration.resolveEcdsaMaterialActivation({
        walletId,
        materialActivation,
      });
      if (!active.ok) {
        return { kind: active.code === 'internal' ? 'unavailable' : 'inactive' };
      }
      const normalSigning = active.routerAbEcdsaDerivationNormalSigning;
      if (
        normalSigning.scope.wallet_id !== walletId ||
        normalSigning.scope.public_identity.threshold_public_key33_b64u !==
          admission.admission.signer.thresholdPublicKey33B64u ||
        !sameRouterAbMpcMaterialActivationRef(active.materialActivation, materialActivation) ||
        !sameRouterAbMpcMaterialActivationRef(
          normalSigning.scope.material_activation,
          materialActivation,
        )
      ) {
        return { kind: 'inactive' };
      }
      return {
        kind: 'resolved',
        record: {
          kind: 'exact_wallet_session_operation_credential',
          curve: 'ecdsa',
          thresholdSessionId: routerAbEcdsaDerivationActiveStateId(normalSigning),
          userId: walletId,
          expiresAtMs,
        },
      };
    }
    case 'ed25519': {
      const active = await input.walletRegistration.resolveEd25519MaterialActivation({
        walletId,
        materialActivation,
      });
      if (!active.ok) {
        return { kind: active.code === 'internal' ? 'unavailable' : 'inactive' };
      }
      const identity = active.exportIdentity;
      if (
        identity.scope.account_id !== walletId ||
        identity.application_binding.wallet_id !== walletId ||
        base64UrlEncode(Uint8Array.from(identity.registered_public_key)) !==
          admission.admission.signer.registeredPublicKeyB64u ||
        !sameRouterAbMpcMaterialActivationRef(active.materialActivation, materialActivation) ||
        !sameRouterAbMpcMaterialActivationRef(
          identity.scope.material_activation,
          materialActivation,
        )
      ) {
        return { kind: 'inactive' };
      }
      return {
        kind: 'resolved',
        record: {
          kind: 'exact_wallet_session_operation_credential',
          curve: 'ed25519',
          thresholdSessionId: identity.scope.threshold_session_id,
          userId: walletId,
          expiresAtMs,
        },
      };
    }
  }
}

export async function authorizeSigningSessionSealWithExactWalletSession(
  authorizationSessions: RouterApiAuthorizationSessionService | null | undefined,
  walletRegistration: RouterApiWalletRegistrationService,
  input: SigningSessionSealAuthorizeInput,
): Promise<SigningSessionSealAuthorizeResult> {
  if (!authorizationSessions) {
    return {
      ok: false,
      code: 'sessions_disabled',
      message: 'Wallet Sessions are not configured',
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
  const nowMs = Date.now();
  let context: Awaited<
    ReturnType<
      RouterApiAuthorizationSessionService['readWalletSessionAuthorizationV2ByOperationCredential']
    >
  >;
  try {
    context = await authorizationSessions.readWalletSessionAuthorizationV2ByOperationCredential({
      tenantId: authorizationSessions.tenantId,
      token,
      nowMs,
    });
  } catch {
    return {
      ok: false,
      code: 'wallet_session_unavailable',
      message: 'Wallet Session is unavailable',
      status: 503,
    };
  }
  if (!context) {
    return {
      ok: false,
      code: 'wallet_session_invalid',
      message: 'Wallet Session is invalid',
      status: 401,
    };
  }
  const matchingRecords: SigningSessionSealThresholdSessionRecord[] = [];
  let admitted = false;
  try {
    for (const operation of SIGNING_SESSION_SEAL_OPERATIONS) {
      const resolution = resolveWalletSessionOperationCredentialAdmissionFromContext({
        context,
        nowMs,
        operation,
      });
      if (resolution.kind !== 'admitted') continue;
      admitted = true;
      const record = await signingSessionSealRecordFromExactAdmission({
        admission: resolution.admission,
        walletRegistration,
      });
      if (record.kind === 'unavailable') {
        return {
          ok: false,
          code: 'wallet_session_unavailable',
          message: 'Wallet Session is unavailable',
          status: 503,
        };
      }
      if (
        record.kind === 'resolved' &&
        record.record.thresholdSessionId === input.thresholdSessionId
      ) {
        matchingRecords.push(record.record);
      }
    }
  } catch {
    return {
      ok: false,
      code: 'wallet_session_unavailable',
      message: 'Wallet Session is unavailable',
      status: 503,
    };
  }
  if (matchingRecords.length === 1) {
    const thresholdSession = matchingRecords[0];
    return { ok: true, auth: { userId: thresholdSession.userId, session: thresholdSession } };
  }
  if (admitted) {
    return {
      ok: false,
      code: 'wallet_session_scope_mismatch',
      message: 'Wallet Session does not match the requested threshold session',
      status: 403,
    };
  }
  return {
    ok: false,
    code: 'wallet_session_invalid',
    message: 'Wallet Session is invalid',
    status: 401,
  };
}

async function handleExactWalletSigningSessionSeal(
  context: FetchRouterApiContext,
): Promise<Response | null> {
  return await handleSigningSessionSealRoutes({
    request: context.request,
    pathname: context.pathname,
    method: context.method,
    logger: context.logger,
    authorize: authorizeSigningSessionSealWithExactWalletSession.bind(
      undefined,
      context.service.authorizationSessions,
      context.service.walletRegistration,
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
    async (context: FetchRouterApiContext) =>
      await handleDeviceLinkingOwnerAuthorization(
        context,
        context.service.deviceLinkingOwnerAuthorization,
      ),
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
    handleWalletCustodyEnvelopeOwnershipUpgrade,
    handleWalletRecoveryPrepare,
    handleWalletRecoveryGoogleVerify,
    handleWalletRecoveryEmailOtpVerify,
    handleWalletRecoveryEmailOtpRelease,
    handleWalletRecoveryGoogleEmailOtpFinalize,
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
    handleExactWalletSigningSessionSeal,
    handleWebAuthnAuthenticators,
    handleNearPublicKeys,
    handleExactWalletSessionStatus,
    handleHostedWalletSessionExchangeIssue,
    handleHostedWalletSessionExchangeRedeem,
    handleWalletUnlockChallenge,
    handleWalletUnlockVerify,
    handleWalletEmailOtpChallenge,
    handleWalletEmailOtpFactorRelease,
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
