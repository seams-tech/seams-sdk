import type { Request, Response, Router as ExpressRouter } from 'express';
import type { NormalizedLogger } from '../../../../core/logger';
import type { SessionAdapter } from '../../../../router/relay';
import {
  buildPrfSessionSealApplyPath,
  buildPrfSessionSealRemovePath,
  authorizePrfSessionSealRequest,
  parsePrfSessionSealApplyBody,
  parsePrfSessionSealRemoveBody,
  prfSessionSealAuthorizeStatusCode,
  prfSessionSealStatusCode,
  resolvePrfSessionSealBasePath,
} from './shared';
import type { PrfSessionSealRoutesOptions } from '../types';

type ExpressPrfSessionSealContext = {
  logger: NormalizedLogger;
  session: SessionAdapter | null | undefined;
  options: PrfSessionSealRoutesOptions | null | undefined;
};

function errMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || 'Internal error');
}

export function registerPrfSessionSealRoutes(
  router: ExpressRouter,
  ctx: ExpressPrfSessionSealContext,
): void {
  const options = ctx.options;
  const enabled = Boolean(options && options.enabled !== false);
  ctx.logger.info('[threshold-ecdsa-prf-seal] routes', { enabled });
  if (!options || options.enabled === false) return;

  const basePath = resolvePrfSessionSealBasePath(options.basePath);
  const applyPath = buildPrfSessionSealApplyPath(basePath);
  const removePath = buildPrfSessionSealRemovePath(basePath);

  router.post(applyPath, async (req: Request, res: Response) => {
    const startedAtMs = Date.now();
    try {
      const parsed = parsePrfSessionSealApplyBody(req.body || {});
      if (!parsed.ok) {
        res.status(400).json({ ok: false, code: parsed.code, message: parsed.message });
        return;
      }

      const authorized = await authorizePrfSessionSealRequest({
        options,
        headers: req.headers || {},
        session: ctx.session,
      });
      if (!authorized.ok) {
        res.status(prfSessionSealAuthorizeStatusCode(authorized)).json({
          ok: false,
          code: authorized.code || 'unauthorized',
          message: authorized.message || 'Unauthorized',
        });
        return;
      }

      const result = await options.service.applyServerSeal(parsed.value, authorized.auth);
      const status = prfSessionSealStatusCode(result);
      res.status(status).json(result);
      ctx.logger.info('[threshold-ecdsa-prf-seal] response', {
        route: applyPath,
        status,
        ok: result.ok,
        durationMs: Math.max(0, Date.now() - startedAtMs),
        userId: authorized.auth.userId,
      });
    } catch (error: unknown) {
      const message = errMessage(error);
      ctx.logger.error('[threshold-ecdsa-prf-seal] error', {
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
      const parsed = parsePrfSessionSealRemoveBody(req.body || {});
      if (!parsed.ok) {
        res.status(400).json({ ok: false, code: parsed.code, message: parsed.message });
        return;
      }

      const authorized = await authorizePrfSessionSealRequest({
        options,
        headers: req.headers || {},
        session: ctx.session,
      });
      if (!authorized.ok) {
        res.status(prfSessionSealAuthorizeStatusCode(authorized)).json({
          ok: false,
          code: authorized.code || 'unauthorized',
          message: authorized.message || 'Unauthorized',
        });
        return;
      }

      const result = await options.service.removeServerSeal(parsed.value, authorized.auth);
      const status = prfSessionSealStatusCode(result);
      res.status(status).json(result);
      ctx.logger.info('[threshold-ecdsa-prf-seal] response', {
        route: removePath,
        status,
        ok: result.ok,
        durationMs: Math.max(0, Date.now() - startedAtMs),
        userId: authorized.auth.userId,
      });
    } catch (error: unknown) {
      const message = errMessage(error);
      ctx.logger.error('[threshold-ecdsa-prf-seal] error', {
        route: removePath,
        message,
        durationMs: Math.max(0, Date.now() - startedAtMs),
      });
      res.status(500).json({ ok: false, code: 'internal', message });
    }
  });
}
