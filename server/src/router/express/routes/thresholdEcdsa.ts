import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import type {
  ThresholdEcdsaAuthorizeWithSessionRequest,
  ThresholdEcdsaBootstrapRequest,
  ThresholdEcdsaCosignFinalizeRequest,
  ThresholdEcdsaCosignInitRequest,
  ThresholdEcdsaPresignInitRequest,
  ThresholdEcdsaPresignStepRequest,
  ThresholdEcdsaSignFinalizeRequest,
  ThresholdEcdsaSignInitRequest,
} from '../../../core/types';
import { THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID } from '../../../core/ThresholdService/schemes/schemeIds';
import { thresholdEcdsaStatusCode } from '../../../threshold/statusCodes';
import { parseSessionKind, resolveThresholdScheme } from '../../relay';
import { validateThresholdEcdsaAuthorizeInputs, validateThresholdEcdsaSessionInputs } from '../../commonRouterUtils';

const NOT_IMPLEMENTED = { ok: false, code: 'not_implemented', message: 'threshold-ecdsa is not implemented' } as const;

function errMessage(e: unknown): string {
  if (e && typeof e === 'object' && 'message' in e) return String((e as { message?: unknown }).message || 'Internal error');
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

async function handle<T extends { ok: boolean; code?: string; message?: string }>(
  ctx: ExpressRelayContext,
  req: Request,
  res: Response,
  route: string,
  requestMeta: Record<string, unknown>,
  fn: () => Promise<T>
): Promise<void> {
  const startedAtMs = Date.now();
  try {
    ctx.logger.info('[threshold-ecdsa] request', { route, method: req.method, ...(requestMeta || {}) });
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

export function registerThresholdEcdsaRoutes(router: ExpressRouter, ctx: ExpressRelayContext): void {
  ctx.logger.info('[threshold-ecdsa] routes', { enabled: Boolean(ctx.opts.threshold) });

  router.get('/threshold-ecdsa/healthz', async (req: Request, res: Response) => {
    await handle(ctx, req, res, '/threshold-ecdsa/healthz', {}, async () => {
      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
      });
      if (!resolved.ok) return { ok: false, configured: false, code: resolved.code, message: resolved.message };
      const scheme = resolved.scheme;
      const health = await scheme.healthz();
      if (health.ok) return { ok: true, configured: true };
      return { ...(health.code ? health : NOT_IMPLEMENTED), configured: true };
    });
  });

  router.post('/threshold-ecdsa/bootstrap', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaBootstrapRequest;
    await handle(ctx, req, res, '/threshold-ecdsa/bootstrap', {
      userId: typeof body.userId === 'string' ? body.userId : undefined,
      rpId: typeof body.rpId === 'string' ? body.rpId : undefined,
      keygenSessionId: typeof body.keygenSessionId === 'string' ? body.keygenSessionId : undefined,
      clientVerifyingShareB64u_len: typeof body.clientVerifyingShareB64u === 'string' ? body.clientVerifyingShareB64u.length : undefined,
      sessionPolicyVersion: body.sessionPolicy ? body.sessionPolicy.version : undefined,
    }, async () => {
      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
      });
      if (!resolved.ok) return resolved;
      const scheme = resolved.scheme;
      if (!scheme.bootstrap) {
        return { ok: false, code: 'not_implemented', message: 'threshold-ecdsa bootstrap is not implemented on this server' };
      }

      const session = ctx.opts.session;
      if (!session) {
        return { ok: false, code: 'sessions_disabled', message: 'Sessions are not configured on this server' };
      }

      const result = await scheme.bootstrap(body);
      if (!result.ok) return result;

      const sessionId = String(result.sessionId || '').trim();
      if (!sessionId) return { ok: false, code: 'internal', message: 'threshold bootstrap missing sessionId' };

      const userId = String(body.userId || body.sessionPolicy?.userId || '').trim();
      const rpId = String(body.rpId || body.sessionPolicy?.rpId || '').trim();
      const relayerKeyId = String(result.relayerKeyId || '').trim();
      const thresholdExpiresAtMs = Number(result.expiresAtMs);
      if (!userId) return { ok: false, code: 'internal', message: 'threshold bootstrap missing userId' };
      if (!rpId) return { ok: false, code: 'internal', message: 'threshold bootstrap missing rpId' };
      if (!relayerKeyId) return { ok: false, code: 'internal', message: 'threshold bootstrap missing relayerKeyId' };
      if (!Number.isFinite(thresholdExpiresAtMs) || thresholdExpiresAtMs <= 0) {
        return { ok: false, code: 'internal', message: 'threshold bootstrap missing expiresAtMs' };
      }

      const participantIds = Array.isArray(result.participantIds) ? result.participantIds : undefined;
      const nowSec = Math.floor(Date.now() / 1000);
      const expSec = Math.floor(thresholdExpiresAtMs / 1000);
      const token = await session.signJwt(userId, {
        kind: 'threshold_ecdsa_session_v1',
        sessionId,
        relayerKeyId,
        rpId,
        ...(participantIds ? { participantIds } : {}),
        thresholdExpiresAtMs,
        iat: nowSec,
        exp: expSec,
      });

      const sessionKind = parseSessionKind(body);
      if (sessionKind === 'cookie') {
        res.set('Set-Cookie', session.buildSetCookie(token));
        const { jwt: _omit, ...rest } = result;
        return { ...rest, ok: true };
      }

      return { ...result, jwt: token };
    });
  });

  router.post('/threshold-ecdsa/authorize', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaAuthorizeWithSessionRequest;
    await handle(ctx, req, res, '/threshold-ecdsa/authorize', {
      relayerKeyId: typeof body.relayerKeyId === 'string' ? body.relayerKeyId : undefined,
      clientVerifyingShareB64u_len: typeof body.clientVerifyingShareB64u === 'string' ? body.clientVerifyingShareB64u.length : undefined,
      purpose: typeof body.purpose === 'string' ? body.purpose : undefined,
      signing_digest_32_len: Array.isArray(body.signing_digest_32) ? body.signing_digest_32.length : undefined,
    }, async () => {
      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
      });
      if (!resolved.ok) return resolved;
      const scheme = resolved.scheme;

      const validated = await validateThresholdEcdsaAuthorizeInputs({
        body: req.body,
        headers: req.headers || {},
        session: ctx.opts.session,
      });
      if (!validated.ok) return validated;

      return scheme.authorize({ claims: validated.claims, request: validated.request });
    });
  });

  router.post('/threshold-ecdsa/presign/init', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaPresignInitRequest;
    const requestTag = parsePresignRequestTag(body);
    const label = resolvePresignLogLabel(requestTag);
    await handle(ctx, req, res, '/threshold-ecdsa/presign/init', {
      relayerKeyId: typeof body.relayerKeyId === 'string' ? body.relayerKeyId : undefined,
      clientVerifyingShareB64u_len: typeof body.clientVerifyingShareB64u === 'string' ? body.clientVerifyingShareB64u.length : undefined,
      count: typeof (body as any).count === 'number' ? (body as any).count : undefined,
      ...(requestTag ? { requestTag } : {}),
      ...(label ? { label } : {}),
    }, async () => {
      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
      });
      if (!resolved.ok) return resolved;
      const scheme = resolved.scheme;

      const validated = await validateThresholdEcdsaSessionInputs({
        body: req.body,
        headers: req.headers || {},
        session: ctx.opts.session,
      });
      if (!validated.ok) return validated;

      return scheme.presign.init({ claims: validated.claims, request: body });
    });
  });

  router.post('/threshold-ecdsa/presign/step', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaPresignStepRequest;
    const requestTag = parsePresignRequestTag(body);
    const label = resolvePresignLogLabel(requestTag);
    await handle(ctx, req, res, '/threshold-ecdsa/presign/step', {
      presignSessionId: typeof body.presignSessionId === 'string' ? body.presignSessionId : undefined,
      stage: typeof (body as any).stage === 'string' ? (body as any).stage : undefined,
      outgoingMessagesB64u_len: Array.isArray((body as any).outgoingMessagesB64u) ? (body as any).outgoingMessagesB64u.length : undefined,
      ...(requestTag ? { requestTag } : {}),
      ...(label ? { label } : {}),
    }, async () => {
      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
      });
      if (!resolved.ok) return resolved;
      const scheme = resolved.scheme;

      const validated = await validateThresholdEcdsaSessionInputs({
        body: req.body,
        headers: req.headers || {},
        session: ctx.opts.session,
      });
      if (!validated.ok) return validated;

      return scheme.presign.step({ claims: validated.claims, request: body });
    });
  });

  router.post('/threshold-ecdsa/sign/init', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaSignInitRequest;
    await handle(ctx, req, res, '/threshold-ecdsa/sign/init', {
      mpcSessionId: typeof body.mpcSessionId === 'string' ? body.mpcSessionId : undefined,
      relayerKeyId: typeof body.relayerKeyId === 'string' ? body.relayerKeyId : undefined,
      signingDigestB64u_len: typeof body.signingDigestB64u === 'string' ? body.signingDigestB64u.length : undefined,
    }, async () => {
      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
      });
      if (!resolved.ok) return resolved;
      return resolved.scheme.protocol.signInit(body);
    });
  });

  router.post('/threshold-ecdsa/sign/finalize', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaSignFinalizeRequest;
    await handle(ctx, req, res, '/threshold-ecdsa/sign/finalize', {
      signingSessionId: typeof body.signingSessionId === 'string' ? body.signingSessionId : undefined,
    }, async () => {
      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
      });
      if (!resolved.ok) return resolved;
      return resolved.scheme.protocol.signFinalize(body);
    });
  });

  router.post('/threshold-ecdsa/internal/cosign/init', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaCosignInitRequest;
    await handle(ctx, req, res, '/threshold-ecdsa/internal/cosign/init', {
      coordinatorGrant_len: typeof body.coordinatorGrant === 'string' ? body.coordinatorGrant.length : undefined,
      signingSessionId: typeof body.signingSessionId === 'string' ? body.signingSessionId : undefined,
      cosignerShareB64u_len: typeof body.cosignerShareB64u === 'string' ? body.cosignerShareB64u.length : undefined,
    }, async () => {
      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
      });
      if (!resolved.ok) return resolved;
      const cosignInit = resolved.scheme.protocol.internalCosignInit;
      if (!cosignInit) {
        return { ok: false, code: 'not_found', message: 'threshold-ecdsa cosigner endpoints are not enabled on this server' };
      }
      return cosignInit(body);
    });
  });

  router.post('/threshold-ecdsa/internal/cosign/finalize', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaCosignFinalizeRequest;
    await handle(ctx, req, res, '/threshold-ecdsa/internal/cosign/finalize', {
      coordinatorGrant_len: typeof body.coordinatorGrant === 'string' ? body.coordinatorGrant.length : undefined,
      signingSessionId: typeof body.signingSessionId === 'string' ? body.signingSessionId : undefined,
      groupPublicKey_len: typeof body.groupPublicKey === 'string' ? body.groupPublicKey.length : undefined,
      cosignerIds_len: Array.isArray(body.cosignerIds) ? body.cosignerIds.length : undefined,
    }, async () => {
      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
      });
      if (!resolved.ok) return resolved;
      const cosignFinalize = resolved.scheme.protocol.internalCosignFinalize;
      if (!cosignFinalize) {
        return { ok: false, code: 'not_found', message: 'threshold-ecdsa cosigner endpoints are not enabled on this server' };
      }
      return cosignFinalize(body);
    });
  });
}
