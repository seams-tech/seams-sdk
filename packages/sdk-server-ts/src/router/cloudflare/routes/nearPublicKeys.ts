import { DEFAULT_SESSION_COOKIE_NAME } from '../../routerApi';
import { emitRouterApiWebhookEvent } from '../../routerApiWebhooks';
import type { CloudflareRouterApiContext } from '../createCloudflareRouter';
import { json } from '../http';

export async function handleNearPublicKeys(
  ctx: CloudflareRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'GET') return null;
  if (ctx.pathname !== '/near/public-keys') return null;

  try {
    const hasBearerSessionSignal = (): boolean => {
      const authorization = String(ctx.request.headers.get('authorization') || '').trim();
      return authorization.toLowerCase().startsWith('bearer ');
    };

    const hasCookieSessionSignal = (): boolean => {
      const cookie = String(ctx.request.headers.get('cookie') || '').trim();
      if (!cookie) return false;
      const cookieName =
        String(ctx.opts.sessionCookieName || '').trim() || DEFAULT_SESSION_COOKIE_NAME;
      for (const part of cookie.split(';')) {
        const chunk = String(part || '').trim();
        if (!chunk) continue;
        const equalsIndex = chunk.indexOf('=');
        const name = (equalsIndex >= 0 ? chunk.slice(0, equalsIndex) : chunk).trim();
        if (name === cookieName) return true;
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
          source: 'near.public-keys',
          reason: input.message || 'Session expired',
          sessionKind: 'jwt',
          code,
          ...(input.appSessionVersion ? { appSessionVersion: input.appSessionVersion } : {}),
        },
      });
    };

    const session = ctx.opts.session;
    if (!session) {
      return json(
        { ok: false, code: 'sessions_disabled', message: 'Sessions are not configured' },
        { status: 501 },
      );
    }

    const headersObj: Record<string, string | string[] | undefined> = {};
    try {
      ctx.request.headers.forEach((v, k) => {
        headersObj[k] = v;
      });
    } catch {}

    const parsed = await session.parse(headersObj as any);
    if (!parsed.ok) {
      await maybeEmitWarmExpired({
        code: 'unauthorized',
        message: 'No valid session',
        hadBearerSessionSignal: hasBearerSessionSignal(),
        hadCookieSessionSignal: hasCookieSessionSignal(),
      });
      return json(
        { ok: false, code: 'unauthorized', message: 'No valid session' },
        { status: 401 },
      );
    }

    const claims: any = (parsed as any).claims || {};
    const kindRaw = (claims as any).kind;
    const kind = typeof kindRaw === 'string' ? kindRaw.trim() : '';
    if (kind !== 'app_session_v1') {
      return json(
        { ok: false, code: 'unauthorized', message: 'No valid app session' },
        { status: 401 },
      );
    }
    const userId = String(claims.sub || '').trim();
    const appSessionVersion =
      typeof claims.appSessionVersion === 'string' ? claims.appSessionVersion.trim() : '';
    if (!userId || !appSessionVersion) {
      return json(
        { ok: false, code: 'unauthorized', message: 'Invalid app session' },
        { status: 401 },
      );
    }
    const validated = await ctx.service.sessionVersions.validateAppSessionVersion({
      userId,
      appSessionVersion,
    });
    if (!validated.ok) {
      await maybeEmitWarmExpired({
        code: validated.code,
        message: validated.message,
        claims,
        userId,
        appSessionVersion,
      });
      return json(
        { ok: false, code: validated.code, message: validated.message },
        { status: validated.code === 'internal' ? 500 : 401 },
      );
    }

    const result = await ctx.service.nearFunding.listNearPublicKeysForUser({ userId });
    if (!result.ok) {
      const status =
        result.code === 'not_supported' ? 501 : result.code === 'invalid_args' ? 400 : 500;
      return json(result, { status });
    }

    return json(result, { status: 200 });
  } catch (e: any) {
    return json(
      { ok: false, code: 'internal', message: e?.message || 'Internal error' },
      { status: 500 },
    );
  }
}
