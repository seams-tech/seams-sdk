import type { Router as ExpressRouter } from 'express';
import { DEFAULT_SESSION_COOKIE_NAME } from '../../routerApi';
import { emitRouterApiWebhookEvent } from '../../routerApiWebhooks';
import type { ExpressRouterApiContext } from '../createRouterApiRouter';

export function registerWebAuthnAuthenticatorRoutes(
  router: ExpressRouter,
  ctx: ExpressRouterApiContext,
): void {
  const sessionCookieName =
    String(ctx.opts.sessionCookieName || '').trim() || DEFAULT_SESSION_COOKIE_NAME;

  const headerHasCookieName = (cookieHeader: string, cookieName: string): boolean => {
    for (const part of cookieHeader.split(';')) {
      const chunk = String(part || '').trim();
      if (!chunk) continue;
      const equalsIndex = chunk.indexOf('=');
      const name = (equalsIndex >= 0 ? chunk.slice(0, equalsIndex) : chunk).trim();
      if (name === cookieName) return true;
    }
    return false;
  };

  const hasBearerSessionSignal = (
    headers: Record<string, string | string[] | undefined>,
  ): boolean => {
    const value = headers.authorization ?? headers.Authorization;
    if (typeof value === 'string') {
      return value.trim().toLowerCase().startsWith('bearer ');
    }
    if (Array.isArray(value)) {
      return value.some((entry) => String(entry || '').trim().toLowerCase().startsWith('bearer '));
    }
    return false;
  };

  const hasCookieSessionSignal = (
    headers: Record<string, string | string[] | undefined>,
  ): boolean => {
    const value = headers.cookie ?? headers.Cookie;
    if (typeof value === 'string') return headerHasCookieName(value, sessionCookieName);
    if (Array.isArray(value)) {
      return value.some((entry) => headerHasCookieName(String(entry || ''), sessionCookieName));
    }
    return false;
  };

  const maybeEmitWarmExpired = async (input: {
    code: string;
    message: string;
    claims?: Record<string, unknown>;
    userId?: string;
    appSessionVersion?: string;
    hadBearerSessionSignal?: boolean;
    hadCookieSessionSignal?: boolean;
  }): Promise<void> => {
    const code = String(input.code || '').trim();
    const shouldEmit =
      code === 'invalid_session_version' ||
      (code === 'unauthorized' &&
        (Boolean(input.hadBearerSessionSignal) || Boolean(input.hadCookieSessionSignal)));
    if (!shouldEmit) return;

    await emitRouterApiWebhookEvent({
      logger: ctx.logger,
      webhooks: ctx.opts.routerApiWebhooks,
      eventType: 'session.warm.expired',
      claims: input.claims,
      userId: input.userId,
      payload: {
        expired: true,
        source: 'webauthn.authenticators',
        reason: input.message || 'Session expired',
        sessionKind: 'jwt',
        code,
        ...(input.appSessionVersion ? { appSessionVersion: input.appSessionVersion } : {}),
      },
    });
  };

  router.get('/webauthn/authenticators', async (req: any, res: any) => {
    try {
      const session = ctx.opts.session;
      if (!session) {
        res
          .status(501)
          .json({ ok: false, code: 'sessions_disabled', message: 'Sessions are not configured' });
        return;
      }

      const parsed = await session.parse(req.headers || {});
      if (!parsed.ok) {
        await maybeEmitWarmExpired({
          code: 'unauthorized',
          message: 'No valid session',
          hadBearerSessionSignal: hasBearerSessionSignal(req.headers || {}),
          hadCookieSessionSignal: hasCookieSessionSignal(req.headers || {}),
        });
        res.status(401).json({ ok: false, code: 'unauthorized', message: 'No valid session' });
        return;
      }

      const claims: any = (parsed as any).claims || {};
      const kindRaw = (claims as any).kind;
      const kind = typeof kindRaw === 'string' ? kindRaw.trim() : '';
      if (kind !== 'app_session_v1') {
        res.status(401).json({ ok: false, code: 'unauthorized', message: 'No valid app session' });
        return;
      }
      const userId = String(claims.sub || '').trim();
      const appSessionVersion =
        typeof claims.appSessionVersion === 'string' ? claims.appSessionVersion.trim() : '';
      if (!userId || !appSessionVersion) {
        res.status(401).json({ ok: false, code: 'unauthorized', message: 'Invalid app session' });
        return;
      }
      const validated = await ctx.service.validateAppSessionVersion({ userId, appSessionVersion });
      if (!validated.ok) {
        await maybeEmitWarmExpired({
          code: validated.code,
          message: validated.message,
          claims,
          userId,
          appSessionVersion,
        });
        res
          .status(validated.code === 'internal' ? 500 : 401)
          .json({ ok: false, code: validated.code, message: validated.message });
        return;
      }

      const rpIdFromQuery = String((req.query?.rpId ?? req.query?.rp_id ?? '') || '').trim();
      const rpId = rpIdFromQuery || String(claims.rpId || '').trim();

      const result = await ctx.service.listWebAuthnAuthenticatorsForUser({
        userId,
        ...(rpId ? { rpId } : {}),
      });
      if (!result.ok) {
        const status =
          result.code === 'not_supported' ? 501 : result.code === 'invalid_args' ? 400 : 500;
        res.status(status).json(result);
        return;
      }

      res.status(200).json(result);
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });
}
