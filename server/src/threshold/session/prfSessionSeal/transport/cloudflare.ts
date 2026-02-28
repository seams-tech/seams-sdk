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

type CloudflarePrfSessionSealContext = {
  request: Request;
  pathname: string;
  method: string;
  logger: NormalizedLogger;
  session: SessionAdapter | null | undefined;
  options: PrfSessionSealRoutesOptions | null | undefined;
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

async function readJsonSafe(request: Request): Promise<unknown> {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function headersToRecord(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key] = value;
  });
  return out;
}

function errMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || 'Internal error');
}

export async function handlePrfSessionSealRoutes(
  ctx: CloudflarePrfSessionSealContext,
): Promise<Response | null> {
  const options = ctx.options;
  if (!options || options.enabled === false) return null;

  const basePath = resolvePrfSessionSealBasePath(options.basePath);
  const applyPath = buildPrfSessionSealApplyPath(basePath);
  const removePath = buildPrfSessionSealRemovePath(basePath);

  const isApply = ctx.method === 'POST' && ctx.pathname === applyPath;
  const isRemove = ctx.method === 'POST' && ctx.pathname === removePath;
  if (!isApply && !isRemove) return null;

  const startedAtMs = Date.now();
  const operation = isApply ? 'apply-server-seal' : 'remove-server-seal';
  try {
    ctx.logger.info('[threshold-ecdsa-prf-seal] request', {
      route: isApply ? applyPath : removePath,
      operation,
    });
    const body = await readJsonSafe(ctx.request);
    const parsed = isApply
      ? parsePrfSessionSealApplyBody(body)
      : parsePrfSessionSealRemoveBody(body);
    if (!parsed.ok) {
      ctx.logger.warn('[threshold-ecdsa-prf-seal] invalid_body', {
        route: isApply ? applyPath : removePath,
        operation,
        code: parsed.code,
        message: parsed.message,
        durationMs: Math.max(0, Date.now() - startedAtMs),
      });
      return json({ ok: false, code: parsed.code, message: parsed.message }, 400);
    }

    const authorized = await authorizePrfSessionSealRequest({
      options,
      headers: headersToRecord(ctx.request.headers),
      session: ctx.session,
    });
    if (!authorized.ok) {
      ctx.logger.warn('[threshold-ecdsa-prf-seal] unauthorized', {
        route: isApply ? applyPath : removePath,
        operation,
        code: authorized.code || 'unauthorized',
        message: authorized.message || 'Unauthorized',
        durationMs: Math.max(0, Date.now() - startedAtMs),
      });
      return json(
        {
          ok: false,
          code: authorized.code || 'unauthorized',
          message: authorized.message || 'Unauthorized',
        },
        prfSessionSealAuthorizeStatusCode(authorized),
      );
    }

    const result = isApply
      ? await options.service.applyServerSeal(parsed.value, authorized.auth)
      : await options.service.removeServerSeal(parsed.value, authorized.auth);
    const status = prfSessionSealStatusCode(result);
    ctx.logger.info('[threshold-ecdsa-prf-seal] response', {
      route: isApply ? applyPath : removePath,
      operation,
      status,
      ok: result.ok,
      durationMs: Math.max(0, Date.now() - startedAtMs),
      userId: authorized.auth.userId,
    });
    return json(result, status);
  } catch (error: unknown) {
    const message = errMessage(error);
    ctx.logger.error('[threshold-ecdsa-prf-seal] error', {
      route: isApply ? applyPath : removePath,
      message,
      durationMs: Math.max(0, Date.now() - startedAtMs),
    });
    return json({ ok: false, code: 'internal', message }, 500);
  }
}
