import { DEFAULT_SESSION_COOKIE_NAME } from '../../routerApi';
import { emitRouterApiWebhookEvent } from '../../routerApiWebhooks';
import type { CloudflareRouterApiContext } from '../createCloudflareRouter';
import { headersToRecord, json, readJson } from '../http';
import {
  parseAuthIdentityMutationRequest,
  parseAuthProviderActionPath,
  parseGoogleLoginVerifyRequest,
  parsePasskeyLoginOptionsRequest,
  parsePasskeyLoginVerifyRequest,
  type AuthPasskeyStepUpRequest,
} from '../../authRequestValidation';

function assertNeverAuthProviderAction(route: never): never {
  throw new Error(`Unsupported auth provider action: ${String((route as any)?.kind || '')}`);
}

function assertNeverAuthIdentityMutation(route: never): never {
  throw new Error(`Unsupported auth identity mutation: ${String((route as any)?.kind || '')}`);
}

export async function handleAuth(ctx: CloudflareRouterApiContext): Promise<Response | null> {
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
    source: string;
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
        source: input.source,
        reason: input.message || 'Session expired',
        sessionKind: 'jwt',
        code,
        ...(input.appSessionVersion ? { appSessionVersion: input.appSessionVersion } : {}),
      },
    });
  };

  async function requireAppSession(input: {
    source: string;
  }): Promise<{ ok: true; userId: string; claims: any } | { ok: false; response: Response }> {
    const session = ctx.opts.session;
    if (!session) {
      return {
        ok: false,
        response: json(
          { ok: false, code: 'sessions_disabled', message: 'Sessions are not configured' },
          { status: 501 },
        ),
      };
    }
    const parsed = await session.parse(headersToRecord(ctx.request.headers));
    if (!parsed.ok) {
      await maybeEmitWarmExpired({
        code: 'unauthorized',
        message: 'No valid session',
        source: input.source,
        hadBearerSessionSignal: hasBearerSessionSignal(),
        hadCookieSessionSignal: hasCookieSessionSignal(),
      });
      return {
        ok: false,
        response: json(
          { ok: false, code: 'unauthorized', message: 'No valid session' },
          { status: 401 },
        ),
      };
    }
    const claims: any = (parsed as any).claims || {};
    const kindRaw = (claims as any).kind;
    const kind = typeof kindRaw === 'string' ? kindRaw.trim() : '';
    if (kind !== 'app_session_v1') {
      return {
        ok: false,
        response: json(
          { ok: false, code: 'unauthorized', message: 'No valid app session' },
          { status: 401 },
        ),
      };
    }
    const userId = String((claims as any).sub || '').trim();
    if (!userId) {
      return {
        ok: false,
        response: json(
          { ok: false, code: 'unauthorized', message: 'Invalid session' },
          { status: 401 },
        ),
      };
    }

    const appSessionVersion =
      typeof (claims as any).appSessionVersion === 'string'
        ? String((claims as any).appSessionVersion).trim()
        : '';
    if (!appSessionVersion) {
      return {
        ok: false,
        response: json(
          { ok: false, code: 'unauthorized', message: 'Invalid app session' },
          { status: 401 },
        ),
      };
    }
    const validated = await ctx.service.sessionVersions.validateAppSessionVersion({
      userId,
      appSessionVersion,
    });
    if (!validated.ok) {
      await maybeEmitWarmExpired({
        code: validated.code,
        message: validated.message,
        source: input.source,
        claims,
        userId,
        appSessionVersion,
      });
      return {
        ok: false,
        response: json(
          { ok: false, code: validated.code, message: validated.message },
          { status: validated.code === 'internal' ? 500 : 401 },
        ),
      };
    }

    return { ok: true, userId, claims };
  }

  async function requirePasskeyStepUp(input: {
    userId: string;
    stepUp: AuthPasskeyStepUpRequest;
  }): Promise<{ ok: true } | { ok: false; response: Response }> {
    const result = await ctx.service.webAuthn.verifyWebAuthnLogin(input.stepUp);
    if (!result.ok || !result.verified || !result.userId) {
      return {
        ok: false,
        response: json(result, { status: result.code === 'internal' ? 500 : 400 }),
      };
    }
    if (String(result.userId).trim() !== input.userId) {
      return {
        ok: false,
        response: json(
          { ok: false, code: 'forbidden', message: 'Step-up user mismatch' },
          { status: 403 },
        ),
      };
    }
    return { ok: true };
  }

  if (ctx.method === 'GET' && ctx.pathname === '/auth/identities') {
    const sess = await requireAppSession({ source: 'auth.identities' });
    if (!sess.ok) return sess.response;
    const out = await ctx.service.identity.listIdentities({ userId: sess.userId });
    return json(out, { status: out.ok ? 200 : out.code === 'internal' ? 500 : 400 });
  }

  if (ctx.method === 'POST' && (ctx.pathname === '/auth/link' || ctx.pathname === '/auth/unlink')) {
    const body = await readJson(ctx.request);
    const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;
    const parsed = parseAuthIdentityMutationRequest({ pathname: ctx.pathname, body, origin });
    if (!parsed) return null;
    if (!parsed.ok) {
      return json(parsed.body, { status: parsed.status });
    }

    const command = parsed.request;
    const sess = await requireAppSession({ source: command.source });
    if (!sess.ok) return sess.response;

    const stepUpRequest = command.request.stepUp;
    const stepUp = await requirePasskeyStepUp({ userId: sess.userId, stepUp: stepUpRequest });
    if (!stepUp.ok) return stepUp.response;
    await ctx.service.emailOtp.markEmailOtpStrongAuthSatisfied({ walletId: sess.userId });

    switch (command.kind) {
      case 'link': {
        const verified = await ctx.service.identity.verifyGoogleLogin({
          idToken: command.request.idToken,
        });
        if (!verified.ok || !verified.verified || !verified.providerSubject) {
          return json(verified, { status: verified.code === 'internal' ? 500 : 400 });
        }
        const subject = verified.providerSubject;

        const linked = await ctx.service.identity.linkIdentity({
          userId: sess.userId,
          subject,
          allowMoveIfSoleIdentity: true,
        });
        if (!linked.ok) {
          return json(linked, { status: linked.code === 'internal' ? 500 : 400 });
        }
        const identities = await ctx.service.identity.listIdentities({ userId: sess.userId });
        return json(
          {
            ok: true,
            linked: true,
            subject,
            ...(linked.movedFromUserId ? { movedFromUserId: linked.movedFromUserId } : {}),
            ...(identities.ok ? { identities: identities.subjects } : {}),
          },
          { status: 200 },
        );
      }
      case 'unlink':
        break;
      default:
        assertNeverAuthIdentityMutation(command);
    }

    const subject = command.request.subject;
    if (subject.startsWith('near:')) {
      return json(
        { ok: false, code: 'not_supported', message: 'near: subjects cannot be unlinked' },
        { status: 400 },
      );
    }
    const out = await ctx.service.identity.unlinkIdentity({ userId: sess.userId, subject });
    if (!out.ok) {
      return json(out, { status: out.code === 'internal' ? 500 : 400 });
    }
    const identities = await ctx.service.identity.listIdentities({ userId: sess.userId });

    const rotated = await ctx.service.sessionVersions.rotateAppSessionVersion({
      userId: sess.userId,
    });
    if (!rotated.ok) {
      return json(
        { ok: false, code: rotated.code, message: rotated.message },
        { status: rotated.code === 'internal' ? 500 : 400 },
      );
    }

    const session = ctx.opts.session;
    if (!session) {
      return json(
        {
          ok: true,
          unlinked: true,
          subject,
          ...(identities.ok ? { identities: identities.subjects } : {}),
        },
        { status: 200 },
      );
    }

    const authHeader = String(ctx.request.headers.get('authorization') || '').trim();
    const cookieHeader = String(ctx.request.headers.get('cookie') || '').trim();
    const rawKind = command.request.session_kind;
    const requestedKind = rawKind === 'cookie' ? 'cookie' : rawKind === 'jwt' ? 'jwt' : null;
    const inferredKind =
      requestedKind ||
      (authHeader && /^Bearer\s+/i.test(authHeader) ? 'jwt' : cookieHeader ? 'cookie' : 'jwt');

    const preserved: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(sess.claims || {})) {
      if (
        k === 'sub' ||
        k === 'exp' ||
        k === 'iat' ||
        k === 'nbf' ||
        k === 'jti' ||
        k === 'iss' ||
        k === 'aud' ||
        k === 'kind' ||
        k === 'appSessionVersion'
      )
        continue;
      preserved[k] = v;
    }

    const token = await session.signJwt(sess.userId, {
      ...preserved,
      kind: 'app_session_v1',
      appSessionVersion: rotated.appSessionVersion,
    });

    const baseBody = {
      ok: true,
      unlinked: true,
      subject,
      ...(identities.ok ? { identities: identities.subjects } : {}),
    };
    if (inferredKind === 'cookie') {
      return json(baseBody, {
        status: 200,
        headers: { 'Set-Cookie': session.buildSetCookie(token) },
      });
    }

    return json({ ...baseBody, jwt: token }, { status: 200 });
  }

  if (ctx.method !== 'POST') return null;

  const parsedRoute = parseAuthProviderActionPath(ctx.pathname);
  if (!parsedRoute) return null;
  const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;

  switch (parsedRoute.kind) {
    case 'passkey_options': {
      const parsed = parsePasskeyLoginOptionsRequest(await readJson(ctx.request));
      if (!parsed.ok) return json(parsed.body, { status: parsed.status });
      const result = await ctx.service.webAuthn.createWebAuthnLoginOptions(parsed.request);
      return json(result, { status: result.ok ? 200 : result.code === 'internal' ? 500 : 400 });
    }
    case 'passkey_verify': {
      const parsed = parsePasskeyLoginVerifyRequest({
        body: await readJson(ctx.request),
        origin,
      });
      if (!parsed.ok) return json(parsed.body, { status: parsed.status });
      const result = await ctx.service.webAuthn.verifyWebAuthnLogin(parsed.request);
      if (!result.ok || !result.verified) {
        return json(result, { status: result.code === 'internal' ? 500 : 400 });
      }

      return json({ ok: true, verified: true }, { status: 200 });
    }
    case 'google_options': {
      const publicConfig = ctx.service.identity.getGoogleOidcPublicConfig();
      return json({ ok: true, ...publicConfig }, { status: 200 });
    }
    case 'google_verify': {
      const parsed = parseGoogleLoginVerifyRequest(await readJson(ctx.request));
      if (!parsed.ok) return json(parsed.body, { status: parsed.status });
      const result = await ctx.service.identity.verifyGoogleLogin(parsed.request);
      if (!result.ok || !result.verified || !result.userId) {
        return json(result, { status: result.code === 'internal' ? 500 : 400 });
      }

      const baseBody = {
        ok: true,
        verified: true,
        ...(result.email ? { email: result.email } : {}),
      };
      return json(baseBody, { status: 200 });
    }
    default:
      return assertNeverAuthProviderAction(parsedRoute);
  }
}
