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

async function resolveEmailOtpRegistrationHssAuth(args: {
  ctx: ExpressRelayContext;
  headers: Request['headers'];
  body: Record<string, unknown>;
}): Promise<
  | {
      ok: true;
      appSessionClaims: NonNullable<ReturnType<typeof parseAppSessionClaims>>;
      runtimePolicyScope: NonNullable<
        NonNullable<ReturnType<typeof parseAppSessionClaims>>['runtimePolicyScope']
      >;
    }
  | { ok: false; code: string; message: string }
> {
  const session = args.ctx.opts.session;
  if (!session) return { ok: false, code: 'sessions_disabled', message: 'Sessions are disabled' };
  const parsed = await session.parse(args.headers || {});
  if (!parsed.ok) return { ok: false, code: 'unauthorized', message: 'Missing app session' };
  const appSessionClaims = parseAppSessionClaims(parsed.claims);
  if (!appSessionClaims) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'Email OTP registration requires app session auth',
    };
  }
  if (appSessionClaims.exp !== undefined && appSessionClaims.exp * 1000 <= Date.now()) {
    return { ok: false, code: 'unauthorized', message: 'App session is expired' };
  }
  const validated = await args.ctx.service.validateAppSessionVersion({
    userId: appSessionClaims.sub,
    appSessionVersion: appSessionClaims.appSessionVersion,
  });
  if (!validated.ok) return { ok: false, code: 'unauthorized', message: validated.message };

  const walletId = String(args.body.new_account_id || '').trim();
  const registrationAttemptId = String(args.body.registrationAttemptId || '').trim();
  if (String(appSessionClaims.walletId || '').trim() !== walletId) {
    return { ok: false, code: 'unauthorized', message: 'Email OTP registration wallet mismatch' };
  }
  if (
    String(appSessionClaims.googleEmailOtpRegistrationAttemptId || '').trim() !==
    registrationAttemptId
  ) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'Email OTP registration attempt mismatch',
    };
  }
  const runtimePolicyScope = appSessionClaims.runtimePolicyScope;
  if (!runtimePolicyScope?.orgId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration requires runtime policy scope',
    };
  }
  return { ok: true, appSessionClaims, runtimePolicyScope };
}

async function signEmailOtpRegistrationEd25519SessionJwt(args: {
  ctx: ExpressRelayContext;
  nearAccountId: string;
  rpId: string;
  relayerKeyId: string;
  sessionResult: Record<string, unknown>;
  participantIds: number[];
  runtimePolicyScope: NonNullable<ReturnType<typeof parseAppSessionClaims>>['runtimePolicyScope'];
}): Promise<string> {
  const sessionId = String(args.sessionResult.sessionId || '').trim();
  const signingGrantId = String(args.sessionResult.signingGrantId || '').trim();
  const expiresAtMs = Number(args.sessionResult.expiresAtMs);
  if (!sessionId || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error('threshold-ed25519 session bootstrap returned incomplete session state');
  }
  const signed = await signRouterAbEd25519WalletSessionJwt({
    session: args.ctx.opts.session,
    userId: args.nearAccountId,
    rpId: args.rpId,
    relayerKeyId: args.relayerKeyId,
    sessionInfo: {
      sessionKind: 'jwt',
      sessionId,
      signingGrantId,
      expiresAtMs,
      participantIds: args.participantIds,
      runtimePolicyScope: args.runtimePolicyScope,
      routerAbNormalSigning: args.sessionResult.routerAbNormalSigning,
    },
    fallbackParticipantIds: args.participantIds,
    requireJwtErrorMessage: 'threshold_ed25519.session_kind must be jwt',
    invalidPayloadErrorMessage: 'invalid thresholdEd25519 session payload for jwt signing',
  });
  if (!signed.ok) throw new Error(signed.message);
  return signed.jwt;
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

        const sessionId = String(result.sessionId || '').trim();
        if (!sessionId) {
          return { ok: false, code: 'internal', message: 'threshold session missing sessionId' };
        }

        const userId = String((body as any).sessionPolicy?.nearAccountId || '').trim();
        if (!userId) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold session missing sessionPolicy.nearAccountId',
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
          userId,
          rpId,
          relayerKeyId,
          sessionInfo: {
            sessionKind: 'jwt',
            sessionId,
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
          ...result,
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
          const auth = await resolveEmailOtpRegistrationHssAuth({
            ctx,
            headers: req.headers,
            body,
          });
          if (!auth.ok) return auth;
          return (threshold.ed25519Hss as any).prepareForRegistration({
            orgId: auth.runtimePolicyScope.orgId,
            signingRootId:
              body.context && typeof body.context === 'object' && !Array.isArray(body.context)
                ? String((body.context as Record<string, unknown>).signingRootId || '').trim()
                : undefined,
            signingRootVersion: auth.runtimePolicyScope.signingRootVersion,
            request: body as any,
          });
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
          const auth = await resolveEmailOtpRegistrationHssAuth({
            ctx,
            headers: req.headers,
            body,
          });
          if (!auth.ok) return auth;
          const finalized = await (threshold.ed25519Hss as any).finalizeForRegistration({
            orgId: auth.runtimePolicyScope.orgId,
            request: body as any,
          });
          if (!finalized.ok) return finalized;
          const nearAccountId = String(body.new_account_id || '').trim();
          const rpId = String(body.rp_id || '').trim();
          const publicKey = String(finalized.publicKey || '').trim();
          const created = await ctx.service.createAccount({
            accountId: nearAccountId,
            publicKey,
          });
          if (!created.success) {
            return {
              ok: false,
              code: 'account_creation_failed',
              message: created.error || created.message || 'Failed to create NEAR account',
            };
          }
          const keyVersion =
            body.context && typeof body.context === 'object' && !Array.isArray(body.context)
              ? String((body.context as Record<string, unknown>).keyVersion || '').trim()
              : '';
          const participantIds =
            body.context && typeof body.context === 'object' && !Array.isArray(body.context)
              ? ((body.context as Record<string, unknown>).participantIds as number[] | undefined)
              : undefined;
          let sessionResult: Record<string, unknown> | null = null;
          const sessionPolicy = body.sessionPolicy as Record<string, unknown> | undefined;
          if (sessionPolicy) {
            const minted = await (threshold as any).mintEd25519SessionFromRegistration({
              nearAccountId,
              rpId,
              relayerKeyId: finalized.relayerKeyId,
              sessionPolicy: {
                ...sessionPolicy,
                nearAccountId,
                rpId,
                relayerKeyId: finalized.relayerKeyId,
                runtimePolicyScope: auth.runtimePolicyScope,
              },
            });
            if (!minted.ok) return minted;
            const jwt = await signEmailOtpRegistrationEd25519SessionJwt({
              ctx,
              nearAccountId,
              rpId,
              relayerKeyId: finalized.relayerKeyId,
              sessionResult: minted as Record<string, unknown>,
              participantIds: Array.isArray(minted.participantIds)
                ? minted.participantIds
                : Array.isArray(participantIds)
                  ? participantIds
                  : [],
              runtimePolicyScope: auth.runtimePolicyScope,
            });
            sessionResult = {
              ...minted,
              sessionKind: 'jwt',
              jwt,
              runtimePolicyScope: auth.runtimePolicyScope,
            };
          }
          const recorded = await ctx.service.recordGoogleEmailOtpRegistrationAttemptPublicKey({
            registrationAttemptId: body.registrationAttemptId,
            walletId: nearAccountId,
            finalizedPublicKey: publicKey,
          });
          if (!recorded.ok) return recorded;
          return {
            ok: true,
            publicKey,
            relayerKeyId: finalized.relayerKeyId,
            finalizedReport: finalized.finalizedReport,
            keyVersion,
            recoveryExportCapable: true,
            ...(sessionResult ? { session: sessionResult } : {}),
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
          const auth = await resolveEmailOtpRegistrationHssAuth({
            ctx,
            headers: req.headers,
            body,
          });
          if (!auth.ok) return auth;
          return (threshold.ed25519Hss as any).respondForRegistration({
            orgId: auth.runtimePolicyScope.orgId,
            request: body as any,
          });
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
