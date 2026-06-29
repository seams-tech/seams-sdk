import type { Request, Response, Router as ExpressRouter } from 'express';
import type { NormalizedLogger } from '../../../../core/logger';
import type { SessionAdapter } from '../../../../router/routerApi';
import {
  buildSigningSessionSealApplyPath,
  buildSigningSessionSealRemovePath,
  authorizeSigningSessionSealRequest,
  parseSigningSessionSealApplyBody,
  parseSigningSessionSealRemoveBody,
  signingSessionSealAuthorizeStatusCode,
  signingSessionSealStatusCode,
  resolveSigningSessionSealBasePath,
} from './shared';
import type { SigningSessionSealRoutesOptions } from '../signingSessionSeal.types';

type ExpressSigningSessionSealContext = {
  logger: NormalizedLogger;
  session: SessionAdapter | null | undefined;
  options: SigningSessionSealRoutesOptions | null | undefined;
};

function errMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || 'Internal error');
}

export function registerSigningSessionSealRoutes(
  router: ExpressRouter,
  ctx: ExpressSigningSessionSealContext,
): void {
  const options = ctx.options;
  ctx.logger.info('[threshold-signing-session-seal] routes', { enabled: Boolean(options) });
  if (!options) return;

  const basePath = resolveSigningSessionSealBasePath(options.basePath);
  const applyPath = buildSigningSessionSealApplyPath(basePath);
  const removePath = buildSigningSessionSealRemovePath(basePath);

  router.post(applyPath, async (req: Request, res: Response) => {
    const startedAtMs = Date.now();
    try {
      ctx.logger.info('[threshold-signing-session-seal] request', {
        route: applyPath,
        operation: 'apply-server-seal',
      });
      const parsed = parseSigningSessionSealApplyBody(req.body || {});
      if (!parsed.ok) {
        ctx.logger.warn('[threshold-signing-session-seal] invalid_body', {
          route: applyPath,
          operation: 'apply-server-seal',
          code: parsed.code,
          message: parsed.message,
          durationMs: Math.max(0, Date.now() - startedAtMs),
        });
        res.status(400).json({ ok: false, code: parsed.code, message: parsed.message });
        return;
      }

      const authorized = await authorizeSigningSessionSealRequest({
        options,
        headers: req.headers || {},
        session: ctx.session,
        thresholdSessionId: parsed.value.thresholdSessionId,
      });
      if (!authorized.ok) {
        ctx.logger.warn('[threshold-signing-session-seal] unauthorized', {
          route: applyPath,
          operation: 'apply-server-seal',
          code: authorized.code || 'unauthorized',
          message: authorized.message || 'Unauthorized',
          durationMs: Math.max(0, Date.now() - startedAtMs),
        });
        res.status(signingSessionSealAuthorizeStatusCode(authorized)).json({
          ok: false,
          code: authorized.code || 'unauthorized',
          message: authorized.message || 'Unauthorized',
        });
        return;
      }

      const result = await options.service.applyServerSeal(parsed.value, authorized.auth);
      const status = signingSessionSealStatusCode(result);
      res.status(status).json(result);
      ctx.logger.info('[threshold-signing-session-seal] response', {
        route: applyPath,
        status,
        ok: result.ok,
        durationMs: Math.max(0, Date.now() - startedAtMs),
        userId: authorized.auth.userId,
      });
    } catch (error: unknown) {
      const message = errMessage(error);
      ctx.logger.error('[threshold-signing-session-seal] error', {
        route: applyPath,
        message,
        durationMs: Math.max(0, Date.now() - startedAtMs),
      });
      res.status(500).json({ ok: false, code: 'internal', message });
    }
  });

  router.post(removePath, async (req: Request, res: Response) => {
    const startedAtMs = Date.now();
    try {
      ctx.logger.info('[threshold-signing-session-seal] request', {
        route: removePath,
        operation: 'remove-server-seal',
      });
      const parsed = parseSigningSessionSealRemoveBody(req.body || {});
      if (!parsed.ok) {
        ctx.logger.warn('[threshold-signing-session-seal] invalid_body', {
          route: removePath,
          operation: 'remove-server-seal',
          code: parsed.code,
          message: parsed.message,
          durationMs: Math.max(0, Date.now() - startedAtMs),
        });
        res.status(400).json({ ok: false, code: parsed.code, message: parsed.message });
        return;
      }

      const authorized = await authorizeSigningSessionSealRequest({
        options,
        headers: req.headers || {},
        session: ctx.session,
        thresholdSessionId: parsed.value.thresholdSessionId,
      });
      if (!authorized.ok) {
        ctx.logger.warn('[threshold-signing-session-seal] unauthorized', {
          route: removePath,
          operation: 'remove-server-seal',
          code: authorized.code || 'unauthorized',
          message: authorized.message || 'Unauthorized',
          durationMs: Math.max(0, Date.now() - startedAtMs),
        });
        res.status(signingSessionSealAuthorizeStatusCode(authorized)).json({
          ok: false,
          code: authorized.code || 'unauthorized',
          message: authorized.message || 'Unauthorized',
        });
        return;
      }

      const result = await options.service.removeServerSeal(parsed.value, authorized.auth);
      const status = signingSessionSealStatusCode(result);
      res.status(status).json(result);
      ctx.logger.info('[threshold-signing-session-seal] response', {
        route: removePath,
        status,
        ok: result.ok,
        durationMs: Math.max(0, Date.now() - startedAtMs),
        userId: authorized.auth.userId,
      });
    } catch (error: unknown) {
      const message = errMessage(error);
      ctx.logger.error('[threshold-signing-session-seal] error', {
        route: removePath,
        message,
        durationMs: Math.max(0, Date.now() - startedAtMs),
      });
      res.status(500).json({ ok: false, code: 'internal', message });
    }
  });
}
