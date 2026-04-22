import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import type {
  ThresholdEcdsaAuthorizeWithSessionRequest,
  ThresholdEcdsaCosignFinalizeRequest,
  ThresholdEcdsaCosignInitRequest,
  ThresholdEcdsaHssFinalizeRequest,
  ThresholdEcdsaHssPrepareRequest,
  ThresholdEcdsaHssRespondRequest,
  ThresholdEcdsaPresignInitRequest,
  ThresholdEcdsaPresignStepRequest,
  ThresholdEcdsaSignFinalizeRequest,
  ThresholdEcdsaSignInitRequest,
} from '../../../core/types';
import {
  parseAppSessionClaims,
  parseThresholdEcdsaSessionClaims,
  parseThresholdEd25519SessionClaims,
} from '../../../core/ThresholdService/validation';
import { THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID } from '../../../core/ThresholdService/schemes/schemeIds';
import { thresholdEcdsaStatusCode } from '../../../threshold/statusCodes';
import { parseSessionKind, resolveThresholdScheme } from '../../relay';
import {
  resolveThresholdRuntimePolicyScope,
  signThresholdSessionJwt,
  validateThresholdEcdsaAuthorizeInputs,
  validateThresholdEcdsaSessionInputs,
} from '../../commonRouterUtils';
import { validateRuntimeSnapshotExpectation } from '../../runtimeSnapshotConsumer';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';

type EcdsaRuntimePolicyScope = NonNullable<
  ThresholdEcdsaHssPrepareRequest['sessionPolicy']
>['runtimePolicyScope'];

const NOT_IMPLEMENTED = {
  ok: false,
  code: 'not_implemented',
  message: 'threshold-ecdsa is not implemented',
} as const;

type PresignTrafficClass = 'foreground' | 'background';

type PresignPriorityTicket = {
  waitedMs: number;
  queuedDepth: number;
  release: () => void;
};

const PRESIGN_FORWARD_HOP_HEADER = 'x-threshold-ecdsa-presign-forward-hop';
const PRESIGN_FORWARDED_BY_HEADER = 'x-threshold-ecdsa-presign-forwarded-by';

class PresignPriorityGate {
  private foregroundInFlight = 0;
  private backgroundInFlight = 0;
  private readonly backgroundQueue: Array<{
    enqueuedAtMs: number;
    queuedDepth: number;
    resolve: (ticket: PresignPriorityTicket) => void;
  }> = [];

  async acquire(trafficClass: PresignTrafficClass): Promise<PresignPriorityTicket> {
    if (trafficClass === 'foreground') {
      this.foregroundInFlight += 1;
      return this.createTicket('foreground', 0, 0);
    }
    if (this.canRunBackgroundNow()) {
      this.backgroundInFlight += 1;
      return this.createTicket('background', 0, 0);
    }
    const enqueuedAtMs = Date.now();
    const queuedDepth = this.backgroundQueue.length + 1;
    return await new Promise((resolve) => {
      this.backgroundQueue.push({ enqueuedAtMs, queuedDepth, resolve });
    });
  }

  private createTicket(
    trafficClass: PresignTrafficClass,
    waitedMs: number,
    queuedDepth: number,
  ): PresignPriorityTicket {
    let released = false;
    return {
      waitedMs,
      queuedDepth,
      release: () => {
        if (released) return;
        released = true;
        if (trafficClass === 'foreground') {
          this.foregroundInFlight = Math.max(0, this.foregroundInFlight - 1);
        } else {
          this.backgroundInFlight = Math.max(0, this.backgroundInFlight - 1);
        }
        this.drainBackgroundQueue();
      },
    };
  }

  private canRunBackgroundNow(): boolean {
    return this.foregroundInFlight === 0 && this.backgroundInFlight === 0;
  }

  private drainBackgroundQueue(): void {
    if (!this.canRunBackgroundNow()) return;
    const next = this.backgroundQueue.shift();
    if (!next) return;
    this.backgroundInFlight += 1;
    const waitedMs = Math.max(0, Date.now() - next.enqueuedAtMs);
    next.resolve(this.createTicket('background', waitedMs, next.queuedDepth));
  }
}

function errMessage(e: unknown): string {
  if (e && typeof e === 'object' && 'message' in e)
    return String((e as { message?: unknown }).message || 'Internal error');
  return String(e || 'Internal error');
}

function parsePresignRequestTag(body: unknown): string | undefined {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return undefined;
  const tag = String((body as { requestTag?: unknown }).requestTag || '').trim();
  return tag || undefined;
}

function resolvePresignLogLabel(requestTag: string | undefined): string | undefined {
  if (requestTag === 'background_presign_pool_refill') {
    return 'background presign pool refill';
  }
  return undefined;
}

function resolvePresignTrafficClass(requestTag: string | undefined): PresignTrafficClass {
  return requestTag === 'background_presign_pool_refill' ? 'background' : 'foreground';
}

function toOptionalHeaderString(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) {
    for (const entry of value) {
      const trimmed = String(entry || '').trim();
      if (trimmed) return trimmed;
    }
    return undefined;
  }
  const trimmed = String(value || '').trim();
  return trimmed || undefined;
}

function normalizeEcdsaRuntimePolicyScope(raw: unknown): EcdsaRuntimePolicyScope | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const scope = raw as {
    orgId?: unknown;
    envId?: unknown;
    projectId?: unknown;
    signingRootVersion?: unknown;
  };
  const orgId = String(scope.orgId || '').trim();
  const envId = String(scope.envId || '').trim();
  const projectId = String(scope.projectId || '').trim();
  const signingRootVersion = String(scope.signingRootVersion || '').trim();
  if (!orgId || !projectId || !envId || !signingRootVersion) return undefined;
  return {
    orgId,
    projectId,
    envId,
    signingRootVersion,
  };
}

function resolveEcdsaRuntimePolicyScopeFromClaims(input: {
  appSessionClaims: ReturnType<typeof parseAppSessionClaims>;
  ed25519SessionClaims: ReturnType<typeof parseThresholdEd25519SessionClaims>;
  ecdsaSessionClaims: ReturnType<typeof parseThresholdEcdsaSessionClaims>;
}): EcdsaRuntimePolicyScope | undefined {
  return (
    normalizeEcdsaRuntimePolicyScope(input.ed25519SessionClaims?.runtimePolicyScope) ||
    normalizeEcdsaRuntimePolicyScope(input.appSessionClaims?.runtimePolicyScope) ||
    normalizeEcdsaRuntimePolicyScope(input.ecdsaSessionClaims?.runtimePolicyScope)
  );
}

function applyEcdsaRuntimePolicyScope(
  body: ThresholdEcdsaHssPrepareRequest,
  runtimePolicyScope: EcdsaRuntimePolicyScope | undefined,
): ThresholdEcdsaHssPrepareRequest {
  if (!runtimePolicyScope || !body.sessionPolicy) return body;
  return {
    ...body,
    sessionPolicy: {
      ...body.sessionPolicy,
      runtimePolicyScope,
    },
  };
}

async function resolveEmailOtpEnrollmentClaimsForThresholdEcdsa(
  ctx: ExpressRelayContext,
  body: ThresholdEcdsaHssPrepareRequest,
  appSessionClaims: ReturnType<typeof parseAppSessionClaims>,
  ed25519SessionClaims: ReturnType<typeof parseThresholdEd25519SessionClaims>,
  ecdsaSessionClaims: ReturnType<typeof parseThresholdEcdsaSessionClaims>,
): Promise<ThresholdEcdsaHssPrepareRequest['emailOtpEnrollmentClaims'] | undefined> {
  if (body.operation !== 'email_otp_bootstrap') return undefined;
  const sessionClaims = appSessionClaims || ed25519SessionClaims || ecdsaSessionClaims;
  if (!sessionClaims) return undefined;
  const userId = String(body.userId || '').trim();
  const sessionWalletId = String(
    appSessionClaims ? appSessionClaims.walletId || '' : sessionClaims.walletId || '',
  ).trim();
  if (!sessionWalletId || !userId || sessionWalletId !== userId) return undefined;
  const sessionOrgId =
    appSessionClaims?.runtimePolicyScope?.orgId ||
    ed25519SessionClaims?.runtimePolicyScope?.orgId ||
    ecdsaSessionClaims?.runtimePolicyScope?.orgId;
  const enrollment = await ctx.service.readActiveEmailOtpEnrollment({
    walletId: userId,
    orgId: String(sessionOrgId || '').trim() || undefined,
    providerUserId: appSessionClaims ? appSessionClaims.sub : undefined,
  });
  if (!enrollment.ok) return undefined;
  const verifier = String(
    enrollment.enrollment.thresholdEcdsaClientVerifyingShareB64u || '',
  ).trim();
  // App-session auth is scoped to the provider subject. Threshold-session auth
  // is scoped to the wallet id, so its `sub` is not comparable to providerUserId.
  if (
    (appSessionClaims && enrollment.enrollment.providerUserId !== appSessionClaims.sub) ||
    !verifier
  ) {
    return undefined;
  }
  return {
    walletId: enrollment.enrollment.walletId,
    userId: enrollment.enrollment.providerUserId,
    otpChannel: EMAIL_OTP_CHANNEL,
    thresholdEcdsaClientVerifyingShareB64u: verifier,
  };
}

function parseForwardHop(value: string | undefined): number {
  const n = Math.floor(Number(value));
  if (!Number.isFinite(n) || n < 0) return 0;
  return n;
}

const presignPriorityGate = new PresignPriorityGate();

async function handle<T extends { ok: boolean; code?: string; message?: string }>(
  ctx: ExpressRelayContext,
  req: Request,
  res: Response,
  route: string,
  requestMeta: Record<string, unknown>,
  fn: () => Promise<T>,
): Promise<void> {
  const startedAtMs = Date.now();
  try {
    ctx.logger.info('[threshold-ecdsa] request', {
      route,
      method: req.method,
      ...(requestMeta || {}),
    });
    const result = await fn();
    const status = thresholdEcdsaStatusCode(result);
    ctx.logger.info('[threshold-ecdsa] response', {
      route,
      status,
      ok: result.ok,
      durationMs: Math.max(0, Date.now() - startedAtMs),
      ...(result.code ? { code: result.code } : {}),
    });
    res.status(status).json(result);
  } catch (e: unknown) {
    ctx.logger.error('[threshold-ecdsa] error', {
      route,
      message: errMessage(e),
      durationMs: Math.max(0, Date.now() - startedAtMs),
      ...(requestMeta || {}),
    });
    res.status(500).json({ ok: false, code: 'internal', message: errMessage(e) });
  }
}

export function registerThresholdEcdsaRoutes(
  router: ExpressRouter,
  ctx: ExpressRelayContext,
): void {
  ctx.logger.info('[threshold-ecdsa] routes', { enabled: Boolean(ctx.opts.threshold) });

  router.get('/threshold-ecdsa/healthz', async (req: Request, res: Response) => {
    await handle(ctx, req, res, '/threshold-ecdsa/healthz', {}, async () => {
      const resolved = resolveThresholdScheme(
        ctx.opts.threshold,
        THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
        {
          notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
        },
      );
      if (!resolved.ok)
        return { ok: false, configured: false, code: resolved.code, message: resolved.message };
      const scheme = resolved.scheme;
      const health = await scheme.healthz();
      if (health.ok) return { ok: true, configured: true };
      return { ...(health.code ? health : NOT_IMPLEMENTED), configured: true };
    });
  });

  router.post('/threshold-ecdsa/hss/prepare', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaHssPrepareRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ecdsa/hss/prepare',
      {
        userId: typeof body.userId === 'string' ? body.userId : undefined,
        rpId: typeof body.rpId === 'string' ? body.rpId : undefined,
        operation: typeof body.operation === 'string' ? body.operation : undefined,
      },
      async () => {
        const resolved = resolveThresholdScheme(
          ctx.opts.threshold,
          THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
          {
            notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
          },
        );
        if (!resolved.ok) return resolved;
        const scheme = resolved.scheme;
        if (!scheme.hss) {
          return {
            ok: false,
            code: 'not_implemented',
            message: 'threshold-ecdsa hss prepare is not implemented on this server',
          };
        }
        const session = ctx.opts.session;
        let appSessionClaims: ReturnType<typeof parseAppSessionClaims> = null;
        let ed25519SessionClaims: ReturnType<typeof parseThresholdEd25519SessionClaims> = null;
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
              if (!validated.ok) {
                appSessionClaims = null;
              }
            }
            ed25519SessionClaims = parseThresholdEd25519SessionClaims(parsedSession.claims);
            ecdsaSessionClaims = parseThresholdEcdsaSessionClaims(parsedSession.claims);
          }
        }
        const emailOtpEnrollmentClaims = await resolveEmailOtpEnrollmentClaimsForThresholdEcdsa(
          ctx,
          body,
          appSessionClaims,
          ed25519SessionClaims,
          ecdsaSessionClaims,
        );
        const inheritedRuntimePolicyScope = resolveEcdsaRuntimePolicyScopeFromClaims({
          appSessionClaims,
          ed25519SessionClaims,
          ecdsaSessionClaims,
        });
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
        const scopedBody = applyEcdsaRuntimePolicyScope(body, runtimePolicyScope);
        const request: ThresholdEcdsaHssPrepareRequest = {
          ...scopedBody,
          appSessionClaims: appSessionClaims || undefined,
          emailOtpEnrollmentClaims,
          ed25519SessionClaims: ed25519SessionClaims || undefined,
          ecdsaSessionClaims: ecdsaSessionClaims || undefined,
        };
        return await scheme.hss.prepare(request);
      },
    );
  });

  router.post('/threshold-ecdsa/hss/respond', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaHssRespondRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ecdsa/hss/respond',
      {
        ceremonyId: typeof body.ceremonyId === 'string' ? body.ceremonyId : undefined,
        requestMessageB64u_len:
          typeof body.requestMessageB64u === 'string' ? body.requestMessageB64u.length : undefined,
      },
      async () => {
        const resolved = resolveThresholdScheme(
          ctx.opts.threshold,
          THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
          {
            notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
          },
        );
        if (!resolved.ok) return resolved;
        const scheme = resolved.scheme;
        if (!scheme.hss) {
          return {
            ok: false,
            code: 'not_implemented',
            message: 'threshold-ecdsa hss respond is not implemented on this server',
          };
        }
        return await scheme.hss.respond(body);
      },
    );
  });

  router.post('/threshold-ecdsa/hss/finalize', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaHssFinalizeRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ecdsa/hss/finalize',
      {
        ceremonyId: typeof body.ceremonyId === 'string' ? body.ceremonyId : undefined,
        clientFinalizeMessageB64u_len:
          typeof body.clientFinalizeMessageB64u === 'string'
            ? body.clientFinalizeMessageB64u.length
            : undefined,
      },
      async () => {
        const resolved = resolveThresholdScheme(
          ctx.opts.threshold,
          THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
          {
            notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
          },
        );
        if (!resolved.ok) return resolved;
        const scheme = resolved.scheme;
        if (!scheme.hss) {
          return {
            ok: false,
            code: 'not_implemented',
            message: 'threshold-ecdsa hss finalize is not implemented on this server',
          };
        }
        const result = await scheme.hss.finalize(body);
        if (!result.ok) return result;
        if (!result.sessionId || !result.sessionJwtUserId || !result.sessionJwtRpId) {
          return result;
        }
        const signed = await signThresholdSessionJwt({
          session: ctx.opts.session,
          kind: 'threshold_ecdsa_session_v1',
          userId: result.sessionJwtUserId,
          rpId: result.sessionJwtRpId,
          relayerKeyId: result.relayerKeyId,
          allowedSessionKinds: ['jwt', 'cookie'],
          sessionInfo: {
            sessionKind: result.sessionKind,
            sessionId: result.sessionId,
            walletSigningSessionId: result.walletSigningSessionId,
            expiresAtMs: result.expiresAtMs,
            participantIds: result.participantIds,
            ...(result.runtimePolicyScope
              ? { runtimePolicyScope: result.runtimePolicyScope }
              : {}),
          },
          fallbackParticipantIds: result.participantIds,
          requireJwtErrorMessage:
            'threshold-ecdsa hss finalize requires sessionKind "jwt" or "cookie"',
          invalidPayloadErrorMessage:
            'threshold-ecdsa hss finalize returned invalid session payload',
          sessionsDisabledMessage: 'Sessions are not configured on this server',
        });
        if (!signed.ok) {
          return {
            ok: false,
            code: signed.code,
            message: signed.message,
          };
        }
        const {
          sessionJwtUserId: _sessionJwtUserId,
          sessionJwtRpId: _sessionJwtRpId,
          jwt: _rawJwt,
          ...rest
        } = result;
        if (result.sessionKind === 'cookie') {
          res.set('Set-Cookie', ctx.opts.session!.buildSetCookie(signed.jwt));
          return {
            ...rest,
            jwt: undefined,
          };
        }
        return {
          ...rest,
          jwt: signed.jwt,
        };
      },
    );
  });

  router.post('/threshold-ecdsa/authorize', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaAuthorizeWithSessionRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ecdsa/authorize',
      {
        ecdsaThresholdKeyId:
          typeof body.ecdsaThresholdKeyId === 'string' ? body.ecdsaThresholdKeyId : undefined,
        purpose: typeof body.purpose === 'string' ? body.purpose : undefined,
        signing_digest_32_len: Array.isArray(body.signing_digest_32)
          ? body.signing_digest_32.length
          : undefined,
      },
      async () => {
        const resolved = resolveThresholdScheme(
          ctx.opts.threshold,
          THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
          {
            notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
          },
        );
        if (!resolved.ok) return resolved;
        const scheme = resolved.scheme;

        const validated = await validateThresholdEcdsaAuthorizeInputs({
          body: req.body,
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

        return scheme.authorize({ claims: validated.claims, request: validated.request });
      },
    );
  });

  router.post('/threshold-ecdsa/presign/init', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaPresignInitRequest;
    const requestTag = parsePresignRequestTag(body);
    const label = resolvePresignLogLabel(requestTag);
    const trafficClass = resolvePresignTrafficClass(requestTag);
    const gateTicket = await presignPriorityGate.acquire(trafficClass);
    try {
      await handle(
        ctx,
        req,
        res,
        '/threshold-ecdsa/presign/init',
        {
          ecdsaThresholdKeyId:
            typeof body.ecdsaThresholdKeyId === 'string' ? body.ecdsaThresholdKeyId : undefined,
          count: typeof (body as any).count === 'number' ? (body as any).count : undefined,
          ...(requestTag ? { requestTag } : {}),
          ...(label ? { label } : {}),
          presignTrafficClass: trafficClass,
          gateWaitMs: gateTicket.waitedMs,
          gateQueuedDepth: gateTicket.queuedDepth,
        },
        async () => {
          const resolved = resolveThresholdScheme(
            ctx.opts.threshold,
            THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
            {
              notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
            },
          );
          if (!resolved.ok) return resolved;
          const scheme = resolved.scheme;

          const validated = await validateThresholdEcdsaSessionInputs({
            body: req.body,
            headers: req.headers || {},
            session: ctx.opts.session,
          });
          if (!validated.ok) return validated;

          return scheme.presign.init({ claims: validated.claims, request: body });
        },
      );
    } finally {
      gateTicket.release();
    }
  });

  router.post('/threshold-ecdsa/presign/step', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaPresignStepRequest;
    const requestTag = parsePresignRequestTag(body);
    const label = resolvePresignLogLabel(requestTag);
    const trafficClass = resolvePresignTrafficClass(requestTag);
    const gateTicket = await presignPriorityGate.acquire(trafficClass);
    try {
      await handle(
        ctx,
        req,
        res,
        '/threshold-ecdsa/presign/step',
        {
          presignSessionId:
            typeof body.presignSessionId === 'string' ? body.presignSessionId : undefined,
          stage: typeof (body as any).stage === 'string' ? (body as any).stage : undefined,
          outgoingMessagesB64u_len: Array.isArray((body as any).outgoingMessagesB64u)
            ? (body as any).outgoingMessagesB64u.length
            : undefined,
          ...(requestTag ? { requestTag } : {}),
          ...(label ? { label } : {}),
          presignTrafficClass: trafficClass,
          gateWaitMs: gateTicket.waitedMs,
          gateQueuedDepth: gateTicket.queuedDepth,
        },
        async () => {
          const resolved = resolveThresholdScheme(
            ctx.opts.threshold,
            THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
            {
              notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
            },
          );
          if (!resolved.ok) return resolved;
          const scheme = resolved.scheme;

          const validated = await validateThresholdEcdsaSessionInputs({
            body: req.body,
            headers: req.headers || {},
            session: ctx.opts.session,
          });
          if (!validated.ok) return validated;

          const headers = req.headers || {};
          const authorizationHeader = toOptionalHeaderString(headers.authorization);
          const cookieHeader = toOptionalHeaderString(headers.cookie);
          const forwardedHop = parseForwardHop(
            toOptionalHeaderString(headers[PRESIGN_FORWARD_HOP_HEADER]),
          );
          const forwardedByInstanceId = toOptionalHeaderString(
            headers[PRESIGN_FORWARDED_BY_HEADER],
          );
          return scheme.presign.step({
            claims: validated.claims,
            request: body,
            transport: {
              ...(authorizationHeader ? { authorizationHeader } : {}),
              ...(cookieHeader ? { cookieHeader } : {}),
              ...(forwardedHop > 0 ? { forwardedHop } : {}),
              ...(forwardedByInstanceId ? { forwardedByInstanceId } : {}),
            },
          });
        },
      );
    } finally {
      gateTicket.release();
    }
  });

  router.post('/threshold-ecdsa/sign/init', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaSignInitRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ecdsa/sign/init',
      {
        mpcSessionId: typeof body.mpcSessionId === 'string' ? body.mpcSessionId : undefined,
        relayerKeyId: typeof body.relayerKeyId === 'string' ? body.relayerKeyId : undefined,
        signingDigestB64u_len:
          typeof body.signingDigestB64u === 'string' ? body.signingDigestB64u.length : undefined,
      },
      async () => {
        const resolved = resolveThresholdScheme(
          ctx.opts.threshold,
          THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
          {
            notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
          },
        );
        if (!resolved.ok) return resolved;
        return resolved.scheme.protocol.signInit(body);
      },
    );
  });

  router.post('/threshold-ecdsa/sign/finalize', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaSignFinalizeRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ecdsa/sign/finalize',
      {
        signingSessionId:
          typeof body.signingSessionId === 'string' ? body.signingSessionId : undefined,
      },
      async () => {
        const resolved = resolveThresholdScheme(
          ctx.opts.threshold,
          THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
          {
            notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
          },
        );
        if (!resolved.ok) return resolved;
        return resolved.scheme.protocol.signFinalize(body);
      },
    );
  });

  router.post('/threshold-ecdsa/internal/cosign/init', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaCosignInitRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ecdsa/internal/cosign/init',
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
          THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
          {
            notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
          },
        );
        if (!resolved.ok) return resolved;
        const cosignInit = resolved.scheme.protocol.internalCosignInit;
        if (!cosignInit) {
          return {
            ok: false,
            code: 'not_found',
            message: 'threshold-ecdsa cosigner endpoints are not enabled on this server',
          };
        }
        return cosignInit(body);
      },
    );
  });

  router.post('/threshold-ecdsa/internal/cosign/finalize', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaCosignFinalizeRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ecdsa/internal/cosign/finalize',
      {
        coordinatorGrant_len:
          typeof body.coordinatorGrant === 'string' ? body.coordinatorGrant.length : undefined,
        signingSessionId:
          typeof body.signingSessionId === 'string' ? body.signingSessionId : undefined,
        groupPublicKey_len:
          typeof body.groupPublicKey === 'string' ? body.groupPublicKey.length : undefined,
        cosignerIds_len: Array.isArray(body.cosignerIds) ? body.cosignerIds.length : undefined,
      },
      async () => {
        const resolved = resolveThresholdScheme(
          ctx.opts.threshold,
          THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
          {
            notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
          },
        );
        if (!resolved.ok) return resolved;
        const cosignFinalize = resolved.scheme.protocol.internalCosignFinalize;
        if (!cosignFinalize) {
          return {
            ok: false,
            code: 'not_found',
            message: 'threshold-ecdsa cosigner endpoints are not enabled on this server',
          };
        }
        return cosignFinalize(body);
      },
    );
  });
}
