import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRouterApiContext } from '../createRouterApiRouter';
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
import { thresholdEd25519StatusCode } from '../../../threshold/statusCodes';
import { resolveThresholdScheme } from '../../routerApi';
import {
  resolveThresholdRuntimePolicyScope,
  signRouterAbEd25519WalletSessionJwt,
  validateRouterAbEd25519WalletSessionTokenInputs,
} from '../../commonRouterUtils';
import {
  parseAppSessionClaims,
  parseRouterAbEcdsaHssWalletSessionClaims,
  thresholdEd25519AuthorityScopeFromWalletAuthAuthority,
} from '../../../core/ThresholdService/validation';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '../../../core/ThresholdService/schemes/schemeIds';
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

function errMessage(e: unknown): string {
  if (e && typeof e === 'object' && 'message' in e)
    return String((e as { message?: unknown }).message || 'Internal error');
  return String(e || 'Internal error');
}

function publicEd25519WalletSessionResult<T extends { thresholdSessionId?: string }>(result: T): T {
  return result;
}

async function handle<T extends { ok: boolean; code?: string; message?: string }>(
  ctx: ExpressRouterApiContext,
  req: Request,
  res: Response,
  route: string,
  requestMeta: Record<string, unknown>,
  fn: () => Promise<T>,
): Promise<void> {
  const startedAt = Date.now();
  try {
    ctx.logger.info('[threshold-ed25519] request', {
      route,
      method: req.method,
      ...(requestMeta || {}),
    });
    const result = await fn();
    const status = thresholdEd25519StatusCode(result);
    ctx.logger.info('[threshold-ed25519] response', {
      route,
      status,
      ok: result.ok,
      durationMs: Date.now() - startedAt,
      ...(result.code ? { code: result.code } : {}),
      ...(!result.ok && result.message ? { message: result.message } : {}),
    });
    res.status(status).json(result);
  } catch (e: unknown) {
    ctx.logger.error('[threshold-ed25519] error', {
      route,
      message: errMessage(e),
      durationMs: Date.now() - startedAt,
      ...(requestMeta || {}),
    });
    res.status(500).json({ ok: false, code: 'internal', message: errMessage(e) });
  }
}

async function handleRouterAbEd25519NormalSigningRoute(
  ctx: ExpressRouterApiContext,
  req: Request,
  res: Response,
  publicPath: string,
  privatePath: RouterAbEd25519PrivateSigningPath,
  phase: 'prepare' | 'presign-pool-prepare' | 'finalize',
): Promise<void> {
  const startedAt = Date.now();
  const bodyUnknown = (req.body || {}) as unknown;
  const body =
    bodyUnknown && typeof bodyUnknown === 'object' && !Array.isArray(bodyUnknown)
      ? (bodyUnknown as Record<string, unknown>)
      : {};
  try {
    ctx.logger.info('[router-ab-ed25519-signing] request', {
      route: publicPath,
      method: req.method,
    });
    const result = await handleRouterAbEd25519NormalSigningRouteCore({
      body,
      rawBody: bodyUnknown,
      headers: req.headers || {},
      session: ctx.opts.session,
      getThreshold: () => ctx.service.thresholdRuntime.getThresholdSigningService(),
      admissionAdapter: ctx.opts.routerAbNormalSigningAdmission,
      privatePath,
      phase,
    });
    const resultBody =
      result.body && typeof result.body === 'object' && !Array.isArray(result.body)
        ? (result.body as Record<string, unknown>)
        : {};
    const ok =
      typeof resultBody.ok === 'boolean'
        ? resultBody.ok
        : result.status >= 200 && result.status < 400;
    const code = typeof resultBody.code === 'string' ? resultBody.code : undefined;
    const responseLog = {
      route: publicPath,
      status: result.status,
      ok,
      ...(code ? { code } : {}),
      durationMs: Date.now() - startedAt,
    };
    if (ok) {
      ctx.logger.info('[router-ab-ed25519-signing] response', responseLog);
    } else if (result.status >= 500) {
      ctx.logger.error('[router-ab-ed25519-signing] response', responseLog);
    } else {
      ctx.logger.warn('[router-ab-ed25519-signing] response', responseLog);
    }
    res.status(result.status).json(result.body);
  } catch (error) {
    ctx.logger.error('[router-ab-ed25519-signing] error', {
      route: publicPath,
      message: errMessage(error),
      durationMs: Date.now() - startedAt,
    });
    res.status(500).json({ ok: false, code: 'internal', message: errMessage(error) });
  }
}

export function registerThresholdEd25519Routes(
  router: ExpressRouter,
  ctx: ExpressRouterApiContext,
): void {
  ctx.logger.info('[threshold-ed25519] routes', {
    enabled: Boolean(ctx.opts.threshold),
  });

  router.get(ROUTER_AB_ED25519_HEALTH_PATH, async (req: Request, res: Response) => {
    await handle(ctx, req, res, ROUTER_AB_ED25519_HEALTH_PATH, {}, async () => {
      const resolved = resolveThresholdScheme(
        ctx.opts.threshold,
        THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
        {
          notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
        },
      );
      if (!resolved.ok) {
        return { ...resolved, configured: false };
      }
      return { ok: true, configured: true };
    });
  });

  router.post(ROUTER_AB_ED25519_WALLET_SESSION_PATH, async (req: Request, res: Response) => {
    const parsedBody = parseThresholdEd25519SessionRouteRequest(req.body);
    const body = parsedBody.ok ? parsedBody.request : null;
    await handle(
      ctx,
      req,
      res,
      ROUTER_AB_ED25519_WALLET_SESSION_PATH,
      {
        relayerKeyId: body?.relayerKeyId,
        sessionPolicy: body?.sessionPolicy ? { version: body.sessionPolicy.version } : undefined,
      },
      async () => {
        if (!parsedBody.ok) return parsedBody.body;
        const request = parsedBody.request;
        const resolved = resolveThresholdScheme(
          ctx.opts.threshold,
          THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
          {
            notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
          },
        );
        if (!resolved.ok) return resolved;

        const session = ctx.opts.session;
        if (!session) {
          return {
            ok: false,
            code: 'sessions_disabled',
            message: 'Sessions are not configured on this server',
          };
        }
        let appSessionClaims: ReturnType<typeof parseAppSessionClaims> = null;
        let ecdsaSessionClaims: ReturnType<typeof parseRouterAbEcdsaHssWalletSessionClaims> = null;
        if (session) {
          const parsedSession = await session.parse(req.headers || {});
          if (parsedSession.ok) {
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
        }

        const inheritedRuntimePolicyScope =
          appSessionClaims?.runtimePolicyScope || ecdsaSessionClaims?.runtimePolicyScope;
        const runtimePolicyScopeResolution = await resolveThresholdRuntimePolicyScope({
          explicitScopeRaw: inheritedRuntimePolicyScope ?? request.sessionPolicy.runtimePolicyScope,
          projectEnvironmentIdRaw: request.projectEnvironmentId,
          headers: req.headers || {},
          origin: Array.isArray(req.headers?.origin) ? req.headers.origin[0] : req.headers?.origin,
          publishableKeyAuth: ctx.opts.publishableKeyAuth || null,
          orgProjectEnv: ctx.opts.orgProjectEnv || null,
        });
        if (!runtimePolicyScopeResolution.ok) {
          return {
            ok: false,
            code: runtimePolicyScopeResolution.code,
            message: runtimePolicyScopeResolution.message,
          };
        }
        const runtimePolicyScope = runtimePolicyScopeResolution.scope;
        const expectedOrigin = normalizeCorsOrigin(
          Array.isArray(req.headers?.origin) ? req.headers.origin[0] : req.headers?.origin,
        );
        const verifiedWalletAuth = buildThresholdEd25519VerifiedWalletAuth({
          appSessionClaims,
          ecdsaSessionClaims,
        });
        if (verifiedWalletAuth && request.routeAuth.kind === 'passkey') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Provide either signed session auth or WebAuthn authentication, not both',
          };
        }
        if (!verifiedWalletAuth && request.routeAuth.kind === 'signed_session_header') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'webauthn_authentication is required without signed session auth',
          };
        }
        if (request.routeAuth.kind === 'passkey' && !expectedOrigin) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'expected_origin is required for WebAuthn authentication verification',
          };
        }
        const sessionAuth = verifiedWalletAuth
          ? { kind: 'verified_wallet' as const, walletAuth: verifiedWalletAuth }
          : request.routeAuth.kind === 'passkey'
            ? {
                kind: 'passkey' as const,
                webauthn_authentication: request.routeAuth.webauthnAuthentication,
                expected_origin: expectedOrigin || '',
              }
            : null;
        if (!sessionAuth) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'threshold-ed25519 session auth is required',
          };
        }
        const result = await resolved.scheme.session({
          relayerKeyId: request.relayerKeyId,
          sessionPolicy: request.sessionPolicy,
          ...(request.projectEnvironmentId
            ? { projectEnvironmentId: request.projectEnvironmentId }
            : {}),
          ...(request.sessionKind ? { sessionKind: request.sessionKind } : {}),
          auth: sessionAuth,
        });
        if (!result.ok) return result;

        const thresholdSessionId = String(result.thresholdSessionId || '').trim();
        if (!thresholdSessionId) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold session missing thresholdSessionId',
          };
        }

        const walletId = String(result.walletId || '').trim();
        const nearAccountId = String(result.nearAccountId || '').trim();
        const nearEd25519SigningKeyId = String(result.nearEd25519SigningKeyId || '').trim();
        if (!walletId || !nearAccountId || !nearEd25519SigningKeyId) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold session missing walletId/nearAccountId/nearEd25519SigningKeyId',
          };
        }
        const relayerKeyId = String((body as any).relayerKeyId || '').trim();
        if (!relayerKeyId) {
          return { ok: false, code: 'internal', message: 'threshold session missing relayerKeyId' };
        }
        const thresholdExpiresAtMs = Number(result.expiresAtMs);
        if (!Number.isFinite(thresholdExpiresAtMs) || thresholdExpiresAtMs <= 0) {
          return { ok: false, code: 'internal', message: 'threshold session missing expiresAtMs' };
        }
        const participantIds = Array.isArray(result.participantIds) ? result.participantIds : null;
        if (!participantIds || participantIds.length < 2) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold session missing participantIds',
          };
        }
        const signed = await signRouterAbEd25519WalletSessionJwt({
          session,
          userId: walletId,
          authority: request.sessionPolicy.authority,
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
          return { ok: false, code: signed.code, message: signed.message };
        }

        return {
          ...publicEd25519WalletSessionResult(result),
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          jwt: signed.jwt,
        };
      },
    );
  });

  router.post(
    ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH,
    async (req: Request, res: Response) => {
      await handleRouterAbEd25519NormalSigningRoute(
        ctx,
        req,
        res,
        ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH,
        ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare,
        'prepare',
      );
    },
  );

  router.post(
    ROUTER_AB_ED25519_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH,
    async (req: Request, res: Response) => {
      await handleRouterAbEd25519NormalSigningRoute(
        ctx,
        req,
        res,
        ROUTER_AB_ED25519_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH,
        ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.presignPoolPrepare,
        'presign-pool-prepare',
      );
    },
  );

  router.post(ROUTER_AB_ED25519_NORMAL_SIGNING_PATH, async (req: Request, res: Response) => {
    await handleRouterAbEd25519NormalSigningRoute(
      ctx,
      req,
      res,
      ROUTER_AB_ED25519_NORMAL_SIGNING_PATH,
      ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.finalize,
      'finalize',
    );
  });

  router.post(ROUTER_AB_ED25519_HSS_PREPARE_PATH, async (req: Request, res: Response) => {
    const bodyUnknown = (req.body || {}) as unknown;
    const body = (bodyUnknown || {}) as Record<string, unknown>;
    const parsedBody = parseThresholdEd25519HssPrepareWithSessionRouteRequest(bodyUnknown);
    await handle(
      ctx,
      req,
      res,
      ROUTER_AB_ED25519_HSS_PREPARE_PATH,
      {
        relayerKeyId: typeof body.relayerKeyId === 'string' ? body.relayerKeyId : undefined,
        keyPurpose:
          body.context && typeof body.context === 'object' && !Array.isArray(body.context)
            ? (body.context as Record<string, unknown>).keyPurpose
            : undefined,
        keyVersion:
          body.context && typeof body.context === 'object' && !Array.isArray(body.context)
            ? (body.context as Record<string, unknown>).keyVersion
            : undefined,
      },
      async () => {
        if (!parsedBody.ok) return parsedBody.body;
        const threshold = ctx.opts.threshold;
        if (!threshold || !threshold.ed25519Hss) {
          return {
            ok: false,
            code: 'threshold_disabled',
            message: 'Threshold Ed25519 HSS is not configured on this server',
          };
        }
        const validated = await validateRouterAbEd25519WalletSessionTokenInputs({
          body: bodyUnknown,
          headers: req.headers || {},
          session: ctx.opts.session,
        });
        if (!validated.ok) return validated;
        return threshold.ed25519Hss.prepareWithSession({
          claims: validated.claims,
          request: parsedBody.request,
        });
      },
    );
  });

  router.post(ROUTER_AB_ED25519_HSS_FINALIZE_PATH, async (req: Request, res: Response) => {
    const bodyUnknown = (req.body || {}) as unknown;
    const body = (bodyUnknown || {}) as Record<string, unknown>;
    const parsedBody = parseThresholdEd25519HssFinalizeWithSessionRouteRequest(bodyUnknown);
    await handle(
      ctx,
      req,
      res,
      ROUTER_AB_ED25519_HSS_FINALIZE_PATH,
      {
        relayerKeyId: typeof body.relayerKeyId === 'string' ? body.relayerKeyId : undefined,
        keyPurpose:
          body.context && typeof body.context === 'object' && !Array.isArray(body.context)
            ? (body.context as Record<string, unknown>).keyPurpose
            : undefined,
        keyVersion:
          body.context && typeof body.context === 'object' && !Array.isArray(body.context)
            ? (body.context as Record<string, unknown>).keyVersion
            : undefined,
      },
      async () => {
        if (!parsedBody.ok) return parsedBody.body;
        const threshold = ctx.opts.threshold;
        if (!threshold || !threshold.ed25519Hss) {
          return {
            ok: false,
            code: 'threshold_disabled',
            message: 'Threshold Ed25519 HSS is not configured on this server',
          };
        }
        const validated = await validateRouterAbEd25519WalletSessionTokenInputs({
          body: bodyUnknown,
          headers: req.headers || {},
          session: ctx.opts.session,
        });
        if (!validated.ok) return validated;
        return threshold.ed25519Hss.finalizeWithSession({
          claims: validated.claims,
          request: parsedBody.request,
        });
      },
    );
  });

  router.post(ROUTER_AB_ED25519_HSS_RESPOND_PATH, async (req: Request, res: Response) => {
    const bodyUnknown = (req.body || {}) as unknown;
    const body = (bodyUnknown || {}) as Record<string, unknown>;
    const parsedBody = parseThresholdEd25519HssRespondWithSessionRouteRequest(bodyUnknown);
    await handle(
      ctx,
      req,
      res,
      ROUTER_AB_ED25519_HSS_RESPOND_PATH,
      {
        ceremonyHandle: typeof body.ceremonyHandle === 'string' ? body.ceremonyHandle : undefined,
      },
      async () => {
        if (!parsedBody.ok) return parsedBody.body;
        const threshold = ctx.opts.threshold;
        if (!threshold || !threshold.ed25519Hss) {
          return {
            ok: false,
            code: 'threshold_disabled',
            message: 'Threshold Ed25519 HSS is not configured on this server',
          };
        }
        const validated = await validateRouterAbEd25519WalletSessionTokenInputs({
          body: bodyUnknown,
          headers: req.headers || {},
          session: ctx.opts.session,
        });
        if (!validated.ok) return validated;
        return threshold.ed25519Hss.respondWithSession({
          claims: validated.claims,
          request: parsedBody.request,
        });
      },
    );
  });
}
