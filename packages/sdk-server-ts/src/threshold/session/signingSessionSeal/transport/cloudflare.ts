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

type CloudflareSigningSessionSealContext = {
  request: Request;
  pathname: string;
  method: string;
  logger: NormalizedLogger;
  session: SessionAdapter | null | undefined;
  options: SigningSessionSealRoutesOptions | null | undefined;
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

export async function handleSigningSessionSealRoutes(
  ctx: CloudflareSigningSessionSealContext,
): Promise<Response | null> {
  const options = ctx.options;
  if (!options) return null;

  const basePath = resolveSigningSessionSealBasePath(options.basePath);
  const applyPath = buildSigningSessionSealApplyPath(basePath);
  const removePath = buildSigningSessionSealRemovePath(basePath);

  const isApply = ctx.method === 'POST' && ctx.pathname === applyPath;
  const isRemove = ctx.method === 'POST' && ctx.pathname === removePath;
  if (!isApply && !isRemove) return null;

  const startedAtMs = Date.now();
  const operation = isApply ? 'apply-server-seal' : 'remove-server-seal';
  try {
    ctx.logger.info('[threshold-signing-session-seal] request', {
      route: isApply ? applyPath : removePath,
      operation,
    });
    const body = await readJsonSafe(ctx.request);
    const parsed = isApply
      ? parseSigningSessionSealApplyBody(body)
      : parseSigningSessionSealRemoveBody(body);
    if (!parsed.ok) {
      ctx.logger.warn('[threshold-signing-session-seal] invalid_body', {
        route: isApply ? applyPath : removePath,
        operation,
        code: parsed.code,
        message: parsed.message,
        durationMs: Math.max(0, Date.now() - startedAtMs),
      });
      return json({ ok: false, code: parsed.code, message: parsed.message }, 400);
    }

    const authorized = await authorizeSigningSessionSealRequest({
      options,
      headers: headersToRecord(ctx.request.headers),
      session: ctx.session,
      thresholdSessionId: parsed.value.thresholdSessionId,
    });
    if (!authorized.ok) {
      ctx.logger.warn('[threshold-signing-session-seal] unauthorized', {
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
        signingSessionSealAuthorizeStatusCode(authorized),
      );
    }

    const result = isApply
      ? await options.service.applyServerSeal(parsed.value, authorized.auth)
      : await options.service.removeServerSeal(parsed.value, authorized.auth);
    const status = signingSessionSealStatusCode(result);
    ctx.logger.info('[threshold-signing-session-seal] response', {
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
    ctx.logger.error('[threshold-signing-session-seal] error', {
      route: isApply ? applyPath : removePath,
      message,
      durationMs: Math.max(0, Date.now() - startedAtMs),
    });
    return json({ ok: false, code: 'internal', message }, 500);
  }
}
