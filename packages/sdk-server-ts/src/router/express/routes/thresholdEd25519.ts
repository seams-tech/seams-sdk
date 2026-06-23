import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import type {
  ThresholdEd25519HssFinalizeWithSessionRequest,
  ThresholdEd25519HssPrepareWithSessionRequest,
  ThresholdEd25519HssRespondWithSessionRequest,
  ThresholdEd25519SessionRequest,
} from '../../../core/types';
import {
  ROUTER_AB_ED25519_HEALTH_PATH_V2,
  ROUTER_AB_ED25519_HSS_FINALIZE_PATH_V2,
  ROUTER_AB_ED25519_HSS_PREPARE_PATH_V2,
  ROUTER_AB_ED25519_HSS_RESPOND_PATH_V2,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PATH_V2,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH_V2,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V2,
  ROUTER_AB_ED25519_WALLET_SESSION_PATH_V2,
} from '@shared/utils/signingSessionSeal';
import { thresholdEd25519StatusCode } from '../../../threshold/statusCodes';
import { parseSessionKind, resolveThresholdScheme } from '../../relay';
import {
  resolveThresholdRuntimePolicyScope,
  signRouterAbEd25519WalletSessionJwt,
  validateRouterAbEd25519WalletSessionTokenInputs,
} from '../../commonRouterUtils';
import {
  parseAppSessionClaims,
  parseRouterAbEcdsaHssWalletSessionClaims,
} from '../../../core/ThresholdService/validation';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '../../../core/ThresholdService/schemes/schemeIds';
import { normalizeCorsOrigin } from '../../../core/SessionService';
import {
  handleRouterAbEd25519NormalSigningRouteCore,
  ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS,
  type RouterAbEd25519PrivateSigningPath,
} from '../../routerAbPrivateSigningWorker';

function errMessage(e: unknown): string {
  if (e && typeof e === 'object' && 'message' in e)
    return String((e as { message?: unknown }).message || 'Internal error');
  return String(e || 'Internal error');
}

function isEmailOtpRegistrationHssRequest(body: Record<string, unknown>): boolean {
  return (
    body.kind === 'email_otp_registration' &&
    typeof body.registrationAttemptId === 'string' &&
    typeof body.new_account_id === 'string' &&
    typeof body.rp_id === 'string'
  );
}

function rejectLegacyEmailOtpRegistrationHssRequest(): {
  ok: false;
  code: 'invalid_body';
  message: string;
} {
  return {
    ok: false,
    code: 'invalid_body',
    message:
      'Router A/B email_otp_registration HSS requests are no longer supported; use wallet registration with explicit accountProvisioning.',
  };
}

function publicEd25519WalletSessionResult<T extends { thresholdSessionId?: string }>(result: T): T {
  return result;
}

async function handle<T extends { ok: boolean; code?: string; message?: string }>(
  ctx: ExpressRelayContext,
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
  ctx: ExpressRelayContext,
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
      getThreshold: () => ctx.service.getThresholdSigningService(),
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
  ctx: ExpressRelayContext,
): void {
  ctx.logger.info('[threshold-ed25519] routes', {
    enabled: Boolean(ctx.opts.threshold),
  });

  // Threshold Ed25519 (2-party) routes (scaffolding).
  // These routes establish the relayer as a co-signer and will eventually run a 2-round FROST flow.
  router.get(ROUTER_AB_ED25519_HEALTH_PATH_V2, async (req: Request, res: Response) => {
    await handle(ctx, req, res, ROUTER_AB_ED25519_HEALTH_PATH_V2, {}, async () => {
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

  router.post(ROUTER_AB_ED25519_WALLET_SESSION_PATH_V2, async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEd25519SessionRequest;
    await handle(
      ctx,
      req,
      res,
      ROUTER_AB_ED25519_WALLET_SESSION_PATH_V2,
      {
        relayerKeyId: typeof body.relayerKeyId === 'string' ? body.relayerKeyId : undefined,
        sessionPolicy: body.sessionPolicy ? { version: body.sessionPolicy.version } : undefined,
      },
      async () => {
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
        const sessionKind = parseSessionKind(body);
        if (sessionKind !== 'jwt') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Router A/B Ed25519 Wallet Session issuance requires sessionKind=jwt',
          };
        }

        let appSessionClaims: ReturnType<typeof parseAppSessionClaims> = null;
        let ecdsaSessionClaims: ReturnType<typeof parseRouterAbEcdsaHssWalletSessionClaims> = null;
        if (session) {
          const parsedSession = await session.parse(req.headers || {});
          if (parsedSession.ok) {
            appSessionClaims = parseAppSessionClaims(parsedSession.claims);
            if (appSessionClaims) {
              const validated = await ctx.service.validateAppSessionVersion({
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
          explicitScopeRaw: inheritedRuntimePolicyScope ?? body.sessionPolicy?.runtimePolicyScope,
          runtimeEnvironmentIdRaw: (body as { runtimeEnvironmentId?: unknown })
            .runtimeEnvironmentId,
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
        if ((body as any).webauthn_authentication && !expectedOrigin) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'expected_origin is required for WebAuthn authentication verification',
          };
        }

        const result = await resolved.scheme.session({
          ...body,
          expected_origin: expectedOrigin || '',
          ...(appSessionClaims ? { appSessionClaims } : {}),
          ...(ecdsaSessionClaims ? { ecdsaSessionClaims } : {}),
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
        const ed25519KeyScopeId = String(result.ed25519KeyScopeId || '').trim();
        if (!walletId || !nearAccountId || !ed25519KeyScopeId) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold session missing walletId/nearAccountId/ed25519KeyScopeId',
          };
        }
        const rpId = String((body as any).sessionPolicy?.rpId || '').trim();
        if (!rpId) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold session missing sessionPolicy.rpId',
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
          rpId,
          relayerKeyId,
          sessionInfo: {
            sessionKind: 'jwt',
            walletId,
            nearAccountId,
            ed25519KeyScopeId,
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
    ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH_V2,
    async (req: Request, res: Response) => {
      await handleRouterAbEd25519NormalSigningRoute(
        ctx,
        req,
        res,
        ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH_V2,
        ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare,
        'prepare',
      );
    },
  );

  router.post(
    ROUTER_AB_ED25519_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V2,
    async (req: Request, res: Response) => {
      await handleRouterAbEd25519NormalSigningRoute(
        ctx,
        req,
        res,
        ROUTER_AB_ED25519_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V2,
        ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.presignPoolPrepare,
        'presign-pool-prepare',
      );
    },
  );

  router.post(ROUTER_AB_ED25519_NORMAL_SIGNING_PATH_V2, async (req: Request, res: Response) => {
    await handleRouterAbEd25519NormalSigningRoute(
      ctx,
      req,
      res,
      ROUTER_AB_ED25519_NORMAL_SIGNING_PATH_V2,
      ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.finalize,
      'finalize',
    );
  });

  router.post(ROUTER_AB_ED25519_HSS_PREPARE_PATH_V2, async (req: Request, res: Response) => {
    const bodyUnknown = (req.body || {}) as unknown;
    const body = (bodyUnknown || {}) as Record<string, unknown>;
    await handle(
      ctx,
      req,
      res,
      ROUTER_AB_ED25519_HSS_PREPARE_PATH_V2,
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
        const threshold = ctx.opts.threshold;
        if (!threshold || !threshold.ed25519Hss) {
          return {
            ok: false,
            code: 'threshold_disabled',
            message: 'Threshold Ed25519 HSS is not configured on this server',
          };
        }
        if (isEmailOtpRegistrationHssRequest(body)) {
          return rejectLegacyEmailOtpRegistrationHssRequest();
        }
        if (parseSessionKind(body) === 'cookie') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Router A/B Ed25519 HSS requires sessionKind=jwt',
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
          request: validated.body as unknown as ThresholdEd25519HssPrepareWithSessionRequest,
        });
      },
    );
  });

  router.post(ROUTER_AB_ED25519_HSS_FINALIZE_PATH_V2, async (req: Request, res: Response) => {
    const bodyUnknown = (req.body || {}) as unknown;
    const body = (bodyUnknown || {}) as Record<string, unknown>;
    await handle(
      ctx,
      req,
      res,
      ROUTER_AB_ED25519_HSS_FINALIZE_PATH_V2,
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
        const threshold = ctx.opts.threshold;
        if (!threshold || !threshold.ed25519Hss) {
          return {
            ok: false,
            code: 'threshold_disabled',
            message: 'Threshold Ed25519 HSS is not configured on this server',
          };
        }
        if (isEmailOtpRegistrationHssRequest(body)) {
          return rejectLegacyEmailOtpRegistrationHssRequest();
        }
        if (parseSessionKind(body) === 'cookie') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Router A/B Ed25519 HSS requires sessionKind=jwt',
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
          request: validated.body as unknown as ThresholdEd25519HssFinalizeWithSessionRequest,
        });
      },
    );
  });

  router.post(ROUTER_AB_ED25519_HSS_RESPOND_PATH_V2, async (req: Request, res: Response) => {
    const bodyUnknown = (req.body || {}) as unknown;
    const body = (bodyUnknown || {}) as Record<string, unknown>;
    await handle(
      ctx,
      req,
      res,
      ROUTER_AB_ED25519_HSS_RESPOND_PATH_V2,
      {
        ceremonyHandle: typeof body.ceremonyHandle === 'string' ? body.ceremonyHandle : undefined,
      },
      async () => {
        const threshold = ctx.opts.threshold;
        if (!threshold || !threshold.ed25519Hss) {
          return {
            ok: false,
            code: 'threshold_disabled',
            message: 'Threshold Ed25519 HSS is not configured on this server',
          };
        }
        if (isEmailOtpRegistrationHssRequest(body)) {
          return rejectLegacyEmailOtpRegistrationHssRequest();
        }
        if (parseSessionKind(body) === 'cookie') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Router A/B Ed25519 HSS requires sessionKind=jwt',
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
          request: validated.body as unknown as ThresholdEd25519HssRespondWithSessionRequest,
        });
      },
    );
  });
}
