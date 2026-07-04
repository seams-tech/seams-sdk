import type { CloudflareRouterApiContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import { thresholdEd25519StatusCode } from '../../../threshold/statusCodes';
import {
  ROUTER_AB_ED25519_HEALTH_PATH,
  ROUTER_AB_ED25519_HSS_FINALIZE_PATH,
  ROUTER_AB_ED25519_HSS_PREPARE_PATH,
  ROUTER_AB_ED25519_HSS_RESPOND_PATH,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PATH,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH,
  ROUTER_AB_ED25519_WALLET_SESSION_PATH,
} from '@shared/utils/signingSessionSeal';
import { resolveThresholdScheme } from '../../routerApi';
import {
  resolveThresholdRuntimePolicyScope,
  signRouterAbEd25519WalletSessionJwt,
  validateRouterAbEd25519WalletSessionTokenInputs,
} from '../../commonRouterUtils';
import {
  normalizeThresholdEd25519ParticipantIds,
  THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
} from '@shared/threshold/participants';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '../../../core/ThresholdService/schemes/schemeIds';
import {
  parseAppSessionClaims,
  parseRouterAbEcdsaHssWalletSessionClaims,
  thresholdEd25519AuthorityScopeFromWalletAuthAuthority,
} from '../../../core/ThresholdService/validation';
import { normalizeCorsOrigin } from '../../../core/SessionService';
import {
  handleRouterAbEd25519NormalSigningRouteCore,
  ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS,
  type RouterAbEd25519PrivateSigningPath,
} from '../../routerAbPrivateSigningWorker';
import {
  parseThresholdEd25519HssFinalizeWithSessionRouteRequest,
  parseThresholdEd25519HssPrepareWithSessionRouteRequest,
  parseThresholdEd25519HssRespondWithSessionRouteRequest,
  parseThresholdEd25519SessionRouteRequest,
} from '../../thresholdEd25519RequestValidation';
import { buildThresholdEd25519VerifiedWalletAuth } from '../../thresholdEd25519VerifiedWalletAuth';

function publicEd25519WalletSessionResult<T extends { thresholdSessionId?: string }>(result: T): T {
  return result;
}

async function handleRouterAbEd25519NormalSigningRoute(input: {
  ctx: CloudflareRouterApiContext;
  body: Record<string, unknown>;
  privatePath: RouterAbEd25519PrivateSigningPath;
  phase: 'prepare' | 'presign-pool-prepare' | 'finalize';
}): Promise<Response> {
  const result = await handleRouterAbEd25519NormalSigningRouteCore({
    body: input.body,
    rawBody: input.body,
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    session: input.ctx.opts.session,
    getThreshold: () => input.ctx.service.thresholdRuntime.getThresholdSigningService(),
    admissionAdapter: input.ctx.opts.routerAbNormalSigningAdmission,
    privatePath: input.privatePath,
    phase: input.phase,
  });
  return json(result.body, { status: result.status });
}

export async function handleThresholdEd25519(
  ctx: CloudflareRouterApiContext,
): Promise<Response | null> {
  if (ctx.method === 'GET' && ctx.pathname === ROUTER_AB_ED25519_HEALTH_PATH) {
    const resolved = resolveThresholdScheme(
      ctx.opts.threshold,
      THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
      {
        notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
      },
    );
    if (!resolved.ok) {
      const body = { ...resolved, configured: false };
      return json(body, { status: thresholdEd25519StatusCode(body) });
    }
    return json({ ok: true, configured: true }, { status: 200 });
  }

  if (ctx.method !== 'POST') return null;

  const pathname = ctx.pathname;
  if (
    pathname !== ROUTER_AB_ED25519_WALLET_SESSION_PATH &&
    pathname !== ROUTER_AB_ED25519_HSS_PREPARE_PATH &&
    pathname !== ROUTER_AB_ED25519_HSS_FINALIZE_PATH &&
    pathname !== ROUTER_AB_ED25519_HSS_RESPOND_PATH &&
    pathname !== ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH &&
    pathname !== ROUTER_AB_ED25519_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH &&
    pathname !== ROUTER_AB_ED25519_NORMAL_SIGNING_PATH
  ) {
    return null;
  }

  const bodyUnknown = await readJson(ctx.request);
  const body =
    bodyUnknown && typeof bodyUnknown === 'object' && !Array.isArray(bodyUnknown)
      ? (bodyUnknown as Record<string, unknown>)
      : {};

  switch (pathname) {
    case ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH:
      return handleRouterAbEd25519NormalSigningRoute({
        ctx,
        body,
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare,
        phase: 'prepare',
      });

    case ROUTER_AB_ED25519_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH:
      return handleRouterAbEd25519NormalSigningRoute({
        ctx,
        body,
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.presignPoolPrepare,
        phase: 'presign-pool-prepare',
      });

    case ROUTER_AB_ED25519_NORMAL_SIGNING_PATH:
      return handleRouterAbEd25519NormalSigningRoute({
        ctx,
        body,
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.finalize,
        phase: 'finalize',
      });
  }

  const resolved = resolveThresholdScheme(
    ctx.opts.threshold,
    THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
    {
      notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
    },
  );
  if (!resolved.ok) {
    return json(resolved, { status: thresholdEd25519StatusCode(resolved) });
  }
  const ed25519 = resolved.scheme;

  switch (pathname) {
    case ROUTER_AB_ED25519_WALLET_SESSION_PATH: {
      const session = ctx.opts.session;
      if (!session) {
        ctx.logger.warn('[threshold-ed25519] request', {
          route: pathname,
          method: ctx.method,
          sessions: false,
        });
        return json(
          {
            ok: false,
            code: 'sessions_disabled',
            message: 'Sessions are not configured on this server',
          },
          { status: 501 },
        );
      }

      const parsedBody = parseThresholdEd25519SessionRouteRequest(body);
      if (!parsedBody.ok) {
        return json(parsedBody.body, { status: thresholdEd25519StatusCode(parsedBody.body) });
      }
      const b = parsedBody.request;
      let appSessionClaims: ReturnType<typeof parseAppSessionClaims> = null;
      let ecdsaSessionClaims: ReturnType<typeof parseRouterAbEcdsaHssWalletSessionClaims> = null;
      const parsedSession = session
        ? await session.parse(Object.fromEntries(ctx.request.headers.entries()))
        : null;
      if (parsedSession?.ok) {
        appSessionClaims = parseAppSessionClaims(parsedSession.claims);
        if (appSessionClaims) {
          const validated = await ctx.service.sessionVersions.validateAppSessionVersion({
            userId: appSessionClaims.sub,
            appSessionVersion: appSessionClaims.appSessionVersion,
          });
          if (!validated.ok) appSessionClaims = null;
        }
        if (!appSessionClaims) {
          ecdsaSessionClaims = parseRouterAbEcdsaHssWalletSessionClaims(parsedSession.claims);
        }
      }
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        relayerKeyId: typeof b.relayerKeyId === 'string' ? b.relayerKeyId : undefined,
        sessionPolicy: b.sessionPolicy ? { version: b.sessionPolicy.version } : undefined,
      });

      const inheritedRuntimePolicyScope =
        appSessionClaims?.runtimePolicyScope || ecdsaSessionClaims?.runtimePolicyScope;
      const runtimePolicyScopeResolution = await resolveThresholdRuntimePolicyScope({
        explicitScopeRaw: inheritedRuntimePolicyScope ?? b.sessionPolicy?.runtimePolicyScope,
        projectEnvironmentIdRaw: b.projectEnvironmentId,
        headers: ctx.request.headers,
        origin: ctx.request.headers.get('origin'),
        publishableKeyAuth: ctx.opts.publishableKeyAuth || null,
        orgProjectEnv: ctx.opts.orgProjectEnv || null,
      });
      if (!runtimePolicyScopeResolution.ok) {
        return json(
          {
            ok: false,
            code: runtimePolicyScopeResolution.code,
            message: runtimePolicyScopeResolution.message,
          },
          { status: runtimePolicyScopeResolution.status },
        );
      }
      const runtimePolicyScope = runtimePolicyScopeResolution.scope;
      const expectedOrigin = normalizeCorsOrigin(ctx.request.headers.get('origin') || undefined);

      const verifiedWalletAuth = buildThresholdEd25519VerifiedWalletAuth({
        appSessionClaims,
        ecdsaSessionClaims,
      });
      if (verifiedWalletAuth && b.routeAuth.kind === 'passkey') {
        return json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'Provide either signed session auth or WebAuthn authentication, not both',
          },
          { status: 400 },
        );
      }
      if (!verifiedWalletAuth && b.routeAuth.kind === 'signed_session_header') {
        return json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'webauthn_authentication is required without signed session auth',
          },
          { status: 400 },
        );
      }
      if (b.routeAuth.kind === 'passkey' && !expectedOrigin) {
        return json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'expected_origin is required for WebAuthn authentication verification',
          },
          { status: 400 },
        );
      }
      const sessionAuth = verifiedWalletAuth
        ? { kind: 'verified_wallet' as const, walletAuth: verifiedWalletAuth }
        : b.routeAuth.kind === 'passkey'
          ? {
              kind: 'passkey' as const,
              webauthn_authentication: b.routeAuth.webauthnAuthentication,
              expected_origin: expectedOrigin || '',
            }
          : null;
      if (!sessionAuth) {
        return json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'threshold-ed25519 session auth is required',
          },
          { status: 400 },
        );
      }
      const result = await ed25519.session({
        relayerKeyId: b.relayerKeyId,
        sessionPolicy: b.sessionPolicy,
        ...(b.projectEnvironmentId ? { projectEnvironmentId: b.projectEnvironmentId } : {}),
        ...(b.sessionKind ? { sessionKind: b.sessionKind } : {}),
        auth: sessionAuth,
      });
      const status = thresholdEd25519StatusCode(result);
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status,
        ok: result.ok,
        ...('code' in result && result.code ? { code: result.code } : {}),
      });
      if (!result.ok) return json(result, { status });

      const thresholdSessionId = String(result.thresholdSessionId || '').trim();
      if (!thresholdSessionId) {
        return json(
          {
            ok: false,
            code: 'internal',
            message: 'threshold session missing thresholdSessionId',
          },
          { status: 500 },
        );
      }
      const walletId = String(result.walletId || '').trim();
      const nearAccountId = String(result.nearAccountId || '').trim();
      const nearEd25519SigningKeyId = String(result.nearEd25519SigningKeyId || '').trim();
      const relayerKeyId = String(b.relayerKeyId || '').trim();
      const thresholdExpiresAtMs = (() => {
        const ms =
          typeof (result as any).expiresAtMs === 'number'
            ? (result as any).expiresAtMs
            : result.expiresAt
              ? Date.parse(result.expiresAt)
              : NaN;
        return Number.isFinite(ms) && ms > 0 ? ms : undefined;
      })();
      if (!walletId || !nearAccountId || !nearEd25519SigningKeyId) {
        return json(
          {
            ok: false,
            code: 'internal',
            message: 'threshold session missing walletId/nearAccountId/nearEd25519SigningKeyId',
          },
          { status: 500 },
        );
      }
      if (!relayerKeyId) {
        return json(
          { ok: false, code: 'internal', message: 'threshold session missing relayerKeyId' },
          { status: 500 },
        );
      }
      if (thresholdExpiresAtMs === undefined) {
        return json(
          { ok: false, code: 'internal', message: 'threshold session missing expiresAtMs' },
          { status: 500 },
        );
      }
      const participantIds = normalizeThresholdEd25519ParticipantIds(
        b.sessionPolicy?.participantIds,
      ) || [...THRESHOLD_ED25519_2P_PARTICIPANT_IDS];
      const signed = await signRouterAbEd25519WalletSessionJwt({
        session,
        userId: walletId,
        authority: b.sessionPolicy.authority,
        relayerKeyId,
        sessionInfo: {
          sessionKind: 'jwt',
          walletId,
          nearAccountId,
          nearEd25519SigningKeyId,
          thresholdSessionId,
          signingGrantId: result.signingGrantId,
          expiresAtMs: thresholdExpiresAtMs,
          participantIds,
          runtimePolicyScope,
          routerAbNormalSigning: result.routerAbNormalSigning,
        },
        fallbackParticipantIds: participantIds,
        requireJwtErrorMessage: 'threshold_ed25519.session_kind must be jwt',
        invalidPayloadErrorMessage: 'invalid thresholdEd25519 session payload for jwt signing',
      });
      if (!signed.ok) {
        return json(
          { ok: false, code: signed.code, message: signed.message },
          { status: signed.status },
        );
      }
      const res = json(
        {
          ...publicEd25519WalletSessionResult(result),
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          jwt: signed.jwt,
        },
        { status: 200 },
      );
      return res;
    }
    case ROUTER_AB_ED25519_HSS_PREPARE_PATH: {
      const startedAt = Date.now();
      const b = (body || {}) as Record<string, unknown>;
      const parsedBody = parseThresholdEd25519HssPrepareWithSessionRouteRequest(body);
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        relayerKeyId: typeof b.relayerKeyId === 'string' ? b.relayerKeyId : undefined,
        keyPurpose:
          b.context && typeof b.context === 'object' && !Array.isArray(b.context)
            ? (b.context as Record<string, unknown>).keyPurpose
            : undefined,
        keyVersion:
          b.context && typeof b.context === 'object' && !Array.isArray(b.context)
            ? (b.context as Record<string, unknown>).keyVersion
            : undefined,
      });
      const threshold = ctx.opts.threshold;
      if (!threshold || !threshold.ed25519Hss) {
        const result = {
          ok: false,
          code: 'threshold_disabled',
          message: 'Threshold Ed25519 HSS is not configured on this server',
        };
        return json(result, { status: 501 });
      }
      if (!parsedBody.ok) {
        return json(parsedBody.body, { status: thresholdEd25519StatusCode(parsedBody.body) });
      }
      const validated = await validateRouterAbEd25519WalletSessionTokenInputs({
        body,
        headers: Object.fromEntries(ctx.request.headers.entries()),
        session: ctx.opts.session,
      });
      if (!validated.ok) return json(validated, { status: thresholdEd25519StatusCode(validated) });
      const result = await threshold.ed25519Hss.prepareWithSession({
        claims: validated.claims,
        request: parsedBody.request,
      });
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status: thresholdEd25519StatusCode(result),
        ok: result.ok,
        durationMs: Date.now() - startedAt,
        ...('code' in result && result.code ? { code: result.code } : {}),
      });
      return json(result, { status: thresholdEd25519StatusCode(result) });
    }
    case ROUTER_AB_ED25519_HSS_FINALIZE_PATH: {
      const startedAt = Date.now();
      const b = (body || {}) as Record<string, unknown>;
      const parsedBody = parseThresholdEd25519HssFinalizeWithSessionRouteRequest(body);
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        relayerKeyId: typeof b.relayerKeyId === 'string' ? b.relayerKeyId : undefined,
        keyPurpose:
          b.context && typeof b.context === 'object' && !Array.isArray(b.context)
            ? (b.context as Record<string, unknown>).keyPurpose
            : undefined,
        keyVersion:
          b.context && typeof b.context === 'object' && !Array.isArray(b.context)
            ? (b.context as Record<string, unknown>).keyVersion
            : undefined,
      });
      const threshold = ctx.opts.threshold;
      if (!threshold || !threshold.ed25519Hss) {
        const result = {
          ok: false,
          code: 'threshold_disabled',
          message: 'Threshold Ed25519 HSS is not configured on this server',
        };
        return json(result, { status: 501 });
      }
      if (!parsedBody.ok) {
        return json(parsedBody.body, { status: thresholdEd25519StatusCode(parsedBody.body) });
      }
      const validated = await validateRouterAbEd25519WalletSessionTokenInputs({
        body,
        headers: Object.fromEntries(ctx.request.headers.entries()),
        session: ctx.opts.session,
      });
      if (!validated.ok) return json(validated, { status: thresholdEd25519StatusCode(validated) });
      const result = await threshold.ed25519Hss.finalizeWithSession({
        claims: validated.claims,
        request: parsedBody.request,
      });
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status: thresholdEd25519StatusCode(result),
        ok: result.ok,
        durationMs: Date.now() - startedAt,
        ...('code' in result && result.code ? { code: result.code } : {}),
      });
      return json(result, { status: thresholdEd25519StatusCode(result) });
    }
    case ROUTER_AB_ED25519_HSS_RESPOND_PATH: {
      const startedAt = Date.now();
      const b = (body || {}) as Record<string, unknown>;
      const parsedBody = parseThresholdEd25519HssRespondWithSessionRouteRequest(body);
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        ceremonyHandle: typeof b.ceremonyHandle === 'string' ? b.ceremonyHandle : undefined,
      });
      const threshold = ctx.opts.threshold;
      if (!threshold || !threshold.ed25519Hss) {
        const result = {
          ok: false,
          code: 'threshold_disabled',
          message: 'Threshold Ed25519 HSS is not configured on this server',
        };
        return json(result, { status: 501 });
      }
      if (!parsedBody.ok) {
        return json(parsedBody.body, { status: thresholdEd25519StatusCode(parsedBody.body) });
      }
      const validated = await validateRouterAbEd25519WalletSessionTokenInputs({
        body,
        headers: Object.fromEntries(ctx.request.headers.entries()),
        session: ctx.opts.session,
      });
      if (!validated.ok) return json(validated, { status: thresholdEd25519StatusCode(validated) });
      const result = await threshold.ed25519Hss.respondWithSession({
        claims: validated.claims,
        request: parsedBody.request,
      });
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status: thresholdEd25519StatusCode(result),
        ok: result.ok,
        durationMs: Date.now() - startedAt,
        ...('code' in result && result.code ? { code: result.code } : {}),
      });
      return json(result, { status: thresholdEd25519StatusCode(result) });
    }
    default:
      return null;
  }
}
