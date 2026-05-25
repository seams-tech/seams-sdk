import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import type {
  ThresholdEd25519CosignFinalizeRequest,
  ThresholdEd25519CosignInitRequest,
  ThresholdEd25519HssFinalizeWithSessionRequest,
  ThresholdEd25519HssPrepareWithSessionRequest,
  ThresholdEd25519HssRespondWithSessionRequest,
  ThresholdEd25519SignFinalizeRequest,
  ThresholdEd25519SignInitRequest,
  ThresholdEd25519SessionRequest,
} from '../../../core/types';
import { thresholdEd25519StatusCode } from '../../../threshold/statusCodes';
import { parseSessionKind, resolveThresholdScheme } from '../../relay';
import {
  resolveThresholdRuntimePolicyScope,
  validateThresholdEd25519AuthorizeInputs,
  validateThresholdEd25519SessionTokenInputs,
} from '../../commonRouterUtils';
import {
  parseAppSessionClaims,
  parseThresholdEcdsaSessionClaims,
} from '../../../core/ThresholdService/validation';
import { validateRuntimeSnapshotExpectation } from '../../runtimeSnapshotConsumer';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '../../../core/ThresholdService/schemes/schemeIds';

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
    return { ok: false, code: 'unauthorized', message: 'Email OTP registration requires app session auth' };
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
    String(
      (appSessionClaims as { googleEmailOtpRegistrationAttemptId?: unknown })
        .googleEmailOtpRegistrationAttemptId || '',
    ).trim() !== registrationAttemptId
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
  const session = args.ctx.opts.session;
  if (!session) throw new Error('Sessions are disabled');
  const sessionId = String(args.sessionResult.sessionId || '').trim();
  const walletSigningSessionId = String(args.sessionResult.walletSigningSessionId || '').trim();
  const expiresAtMs = Number(args.sessionResult.expiresAtMs);
  if (!sessionId || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error('threshold-ed25519 session bootstrap returned incomplete session state');
  }
  const nowSec = Math.floor(Date.now() / 1000);
  return await session.signJwt(args.nearAccountId, {
    kind: 'threshold_ed25519_session_v1',
    walletId: args.nearAccountId,
    sessionId,
    ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
    relayerKeyId: args.relayerKeyId,
    rpId: args.rpId,
    participantIds: args.participantIds,
    thresholdExpiresAtMs: expiresAtMs,
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    iat: nowSec,
    exp: Math.floor(expiresAtMs / 1000),
  });
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

export function registerThresholdEd25519Routes(
  router: ExpressRouter,
  ctx: ExpressRelayContext,
): void {
  ctx.logger.info('[threshold-ed25519] routes', {
    enabled: Boolean(ctx.opts.threshold),
  });

  // Threshold Ed25519 (2-party) routes (scaffolding).
  // These routes establish the relayer as a co-signer and will eventually run a 2-round FROST flow.
  router.get('/threshold-ed25519/healthz', async (req: Request, res: Response) => {
    await handle(ctx, req, res, '/threshold-ed25519/healthz', {}, async () => {
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

  router.post('/threshold-ed25519/session', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEd25519SessionRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ed25519/session',
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

        let appSessionClaims: ReturnType<typeof parseAppSessionClaims> = null;
        let ecdsaSessionClaims: ReturnType<typeof parseThresholdEcdsaSessionClaims> = null;
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
              ecdsaSessionClaims = parseThresholdEcdsaSessionClaims(parsedSession.claims);
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

        const result = await resolved.scheme.session({
          ...body,
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
        const nowSec = Math.floor(Date.now() / 1000);
        const expSec = Math.floor(thresholdExpiresAtMs / 1000);
        const token = await session.signJwt(userId, {
          kind: 'threshold_ed25519_session_v1',
          walletId: userId,
          sessionId,
          ...(result.walletSigningSessionId
            ? { walletSigningSessionId: result.walletSigningSessionId }
            : {}),
          relayerKeyId,
          rpId,
          participantIds,
          thresholdExpiresAtMs,
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          iat: nowSec,
          exp: expSec,
        });

        const sessionKind = parseSessionKind(body);
        if (sessionKind === 'cookie') {
          res.set('Set-Cookie', session.buildSetCookie(token));
          const { jwt: _omit, ...rest } = result;
          return { ...rest, ok: true, ...(runtimePolicyScope ? { runtimePolicyScope } : {}) };
        }

        return { ...result, ...(runtimePolicyScope ? { runtimePolicyScope } : {}), jwt: token };
      },
    );
  });

  router.post('/threshold-ed25519/authorize', async (req: Request, res: Response) => {
    const bodyUnknown = (req.body || {}) as unknown;
    const body = (bodyUnknown || {}) as Record<string, unknown>;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ed25519/authorize',
      {
        relayerKeyId: typeof body.relayerKeyId === 'string' ? body.relayerKeyId : undefined,
        purpose: typeof body.purpose === 'string' ? body.purpose : undefined,
        signing_digest_32_len: Array.isArray(body.signing_digest_32)
          ? body.signing_digest_32.length
          : undefined,
      },
      async () => {
        const threshold = ctx.opts.threshold;
        if (!threshold) {
          return {
            ok: false,
            code: 'threshold_disabled',
            message: 'Threshold signing is not configured on this server',
          };
        }

        const validated = await validateThresholdEd25519AuthorizeInputs({
          body: bodyUnknown,
          headers: req.headers || {},
          session: ctx.opts.session,
        });
        if (!validated.ok) return validated;
        const runtimeSnapshotValidation = await validateRuntimeSnapshotExpectation({
          runtimeSnapshots: ctx.opts.runtimeSnapshots,
          scope: validated.claims.runtimePolicyScope,
          expectationRaw: (validated.request as unknown as Record<string, unknown>).runtimeSnapshot,
        });
        if (!runtimeSnapshotValidation.ok) return runtimeSnapshotValidation;

        const resolved = resolveThresholdScheme(
          ctx.opts.threshold,
          THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
          {
            notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
          },
        );
        if (!resolved.ok) return resolved;

        return resolved.scheme.authorize({ claims: validated.claims, request: validated.request });
      },
    );
  });

  router.post('/threshold-ed25519/hss/prepare', async (req: Request, res: Response) => {
    const bodyUnknown = (req.body || {}) as unknown;
    const body = (bodyUnknown || {}) as Record<string, unknown>;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ed25519/hss/prepare',
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
        const validated = await validateThresholdEd25519SessionTokenInputs({
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

  router.post('/threshold-ed25519/hss/finalize', async (req: Request, res: Response) => {
    const bodyUnknown = (req.body || {}) as unknown;
    const body = (bodyUnknown || {}) as Record<string, unknown>;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ed25519/hss/finalize',
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
        const validated = await validateThresholdEd25519SessionTokenInputs({
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

  router.post('/threshold-ed25519/hss/respond', async (req: Request, res: Response) => {
    const bodyUnknown = (req.body || {}) as unknown;
    const body = (bodyUnknown || {}) as Record<string, unknown>;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ed25519/hss/respond',
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
        const validated = await validateThresholdEd25519SessionTokenInputs({
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

  router.post('/threshold-ed25519/sign/init', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEd25519SignInitRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ed25519/sign/init',
      {
        mpcSessionId: typeof body.mpcSessionId === 'string' ? body.mpcSessionId : undefined,
        relayerKeyId: typeof body.relayerKeyId === 'string' ? body.relayerKeyId : undefined,
        nearAccountId: typeof body.nearAccountId === 'string' ? body.nearAccountId : undefined,
        signingDigestB64u_len:
          typeof body.signingDigestB64u === 'string' ? body.signingDigestB64u.length : undefined,
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
        return resolved.scheme.protocol.signInit(body);
      },
    );
  });

  router.post('/threshold-ed25519/sign/finalize', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEd25519SignFinalizeRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ed25519/sign/finalize',
      {
        signingSessionId:
          typeof body.signingSessionId === 'string' ? body.signingSessionId : undefined,
        clientSignatureShareB64u_len:
          typeof body.clientSignatureShareB64u === 'string'
            ? body.clientSignatureShareB64u.length
            : undefined,
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
        return resolved.scheme.protocol.signFinalize(body);
      },
    );
  });

  // Low-level cosign continuation route. It is intentionally auth-free and
  // relies on threshold protocol state plus the coordinator grant payload.
  router.post('/threshold-ed25519/internal/cosign/init', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEd25519CosignInitRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ed25519/internal/cosign/init',
      {
        coordinatorGrant_len:
          typeof body.coordinatorGrant === 'string' ? body.coordinatorGrant.length : undefined,
        signingSessionId:
          typeof body.signingSessionId === 'string' ? body.signingSessionId : undefined,
        cosignerShareB64u_len:
          typeof body.cosignerShareB64u === 'string' ? body.cosignerShareB64u.length : undefined,
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

        const cosignInit = resolved.scheme.protocol.internalCosignInit;
        if (!cosignInit) {
          return {
            ok: false,
            code: 'not_found',
            message: 'threshold-ed25519 cosigner endpoints are not enabled on this server',
          };
        }
        return cosignInit(body);
      },
    );
  });

  router.post(
    '/threshold-ed25519/internal/cosign/finalize',
    async (req: Request, res: Response) => {
      const body = (req.body || {}) as ThresholdEd25519CosignFinalizeRequest;
      await handle(
        ctx,
        req,
        res,
        '/threshold-ed25519/internal/cosign/finalize',
        {
          coordinatorGrant_len:
            typeof body.coordinatorGrant === 'string' ? body.coordinatorGrant.length : undefined,
          signingSessionId:
            typeof body.signingSessionId === 'string' ? body.signingSessionId : undefined,
          cosignerIds_len: Array.isArray(body.cosignerIds) ? body.cosignerIds.length : undefined,
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

          const cosignFinalize = resolved.scheme.protocol.internalCosignFinalize;
          if (!cosignFinalize) {
            return {
              ok: false,
              code: 'not_found',
              message: 'threshold-ed25519 cosigner endpoints are not enabled on this server',
            };
          }
          return cosignFinalize(body);
        },
      );
    },
  );
}
