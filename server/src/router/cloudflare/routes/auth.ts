import { DEFAULT_SESSION_COOKIE_NAME } from '../../relay';
import { emitRelayWebhookEvent } from '../../relayWebhooks';
import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { headersToRecord, isObject, json, readJson } from '../http';

type ProviderId = 'passkey' | 'google';
type ActionId = 'options' | 'verify';

function parseAuthPath(pathname: string): { provider: ProviderId; action: ActionId } | null {
  const parts = String(pathname || '')
    .split('/')
    .filter(Boolean);
  if (parts.length !== 3) return null;
  if (parts[0] !== 'auth') return null;
  const provider = parts[1] as ProviderId;
  const action = parts[2] as ActionId;
  if (
    (provider !== 'passkey' && provider !== 'google') ||
    (action !== 'options' && action !== 'verify')
  )
    return null;
  return { provider, action };
}

export async function handleAuth(ctx: CloudflareRelayContext): Promise<Response | null> {
  const hasBearerSessionSignal = (): boolean => {
    const authorization = String(ctx.request.headers.get('authorization') || '').trim();
    return authorization.toLowerCase().startsWith('bearer ');
  };

  const hasCookieSessionSignal = (): boolean => {
    const cookie = String(ctx.request.headers.get('cookie') || '').trim();
    if (!cookie) return false;
    const cookieName = String(ctx.opts.sessionCookieName || '').trim() || DEFAULT_SESSION_COOKIE_NAME;
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

    await emitRelayWebhookEvent({
      logger: ctx.logger,
      webhooks: ctx.opts.relayWebhooks,
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

  async function requireAppSession(input: { source: string }): Promise<
    { ok: true; userId: string; claims: any } | { ok: false; response: Response }
  > {
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
    const validated = await ctx.service.validateAppSessionVersion({ userId, appSessionVersion });
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

  async function requirePasskeyStepUp(
    body: any,
    input: { userId: string; origin?: string },
  ): Promise<{ ok: true } | { ok: false; response: Response }> {
    const challengeId = String(
      body?.stepUpChallengeId ??
        body?.step_up_challenge_id ??
        body?.challengeId ??
        body?.challenge_id ??
        '',
    ).trim();
    if (!challengeId) {
      return {
        ok: false,
        response: json(
          { ok: false, code: 'invalid_body', message: 'stepUpChallengeId is required' },
          { status: 400 },
        ),
      };
    }
    const webauthnAuthentication =
      body?.webauthn_authentication ??
      body?.stepUpWebauthnAuthentication ??
      body?.step_up_webauthn_authentication;
    if (!isObject(webauthnAuthentication)) {
      return {
        ok: false,
        response: json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'webauthn_authentication is required for step-up',
          },
          { status: 400 },
        ),
      };
    }

    const result = await ctx.service.verifyWebAuthnLogin({
      challengeId,
      webauthn_authentication: webauthnAuthentication as any,
      expected_origin: input.origin,
    });
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
    const out = await ctx.service.listIdentities({ userId: sess.userId });
    return json(out, { status: out.ok ? 200 : out.code === 'internal' ? 500 : 400 });
  }

  if (ctx.method === 'POST' && (ctx.pathname === '/auth/link' || ctx.pathname === '/auth/unlink')) {
    const body = await readJson(ctx.request);
    if (!isObject(body)) {
      return json(
        { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
        { status: 400 },
      );
    }
    const sess = await requireAppSession({
      source: ctx.pathname === '/auth/link' ? 'auth.link' : 'auth.unlink',
    });
    if (!sess.ok) return sess.response;

    const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;
    const stepUp = await requirePasskeyStepUp(body, { userId: sess.userId, origin });
    if (!stepUp.ok) return stepUp.response;
    await ctx.service.markEmailOtpStrongAuthSatisfied({ walletId: sess.userId });

    if (ctx.pathname === '/auth/link') {
      const provider = String((body as any).provider || '').trim();
      let subject = '';
      if (provider === 'google') {
        const idToken = String((body as any).idToken ?? (body as any).id_token ?? '').trim();
        const verified = await ctx.service.verifyGoogleLogin({ idToken });
        if (!verified.ok || !verified.verified || !verified.providerSubject) {
          return json(verified, { status: verified.code === 'internal' ? 500 : 400 });
        }
        subject = verified.providerSubject;
      } else {
        return json(
          { ok: false, code: 'invalid_body', message: 'provider must be: google' },
          { status: 400 },
        );
      }

      const linked = await ctx.service.linkIdentity({
        userId: sess.userId,
        subject,
        allowMoveIfSoleIdentity: true,
      });
      if (!linked.ok) {
        return json(linked, { status: linked.code === 'internal' ? 500 : 400 });
      }
      const identities = await ctx.service.listIdentities({ userId: sess.userId });
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

    // /auth/unlink
    const subject = String((body as any).subject || '').trim();
    if (!subject) {
      return json(
        { ok: false, code: 'invalid_body', message: 'subject is required' },
        { status: 400 },
      );
    }
    if (subject.startsWith('near:')) {
      return json(
        { ok: false, code: 'not_supported', message: 'near: subjects cannot be unlinked' },
        { status: 400 },
      );
    }
    const out = await ctx.service.unlinkIdentity({ userId: sess.userId, subject });
    if (!out.ok) {
      return json(out, { status: out.code === 'internal' ? 500 : 400 });
    }
    const identities = await ctx.service.listIdentities({ userId: sess.userId });

    const rotated = await ctx.service.rotateAppSessionVersion({ userId: sess.userId });
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
    const rawKind = (body as any).sessionKind ?? (body as any).session_kind;
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

  const parsedPath = parseAuthPath(ctx.pathname);
  if (!parsedPath) return null;

  const body = await readJson(ctx.request);
  if (!isObject(body)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
      { status: 400 },
    );
  }

  const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;

  const providers: Record<ProviderId, Record<ActionId, () => Promise<Response>>> = {
    passkey: {
      options: async () => {
        const result = await ctx.service.createWebAuthnLoginOptions(body as any);
        return json(result, { status: result.ok ? 200 : result.code === 'internal' ? 500 : 400 });
      },
      verify: async () => {
        const challengeId = String(
          (body as any).challengeId ?? (body as any).challenge_id ?? '',
        ).trim();
        if (!challengeId) {
          return json(
            { ok: false, code: 'invalid_body', message: 'challengeId is required' },
            { status: 400 },
          );
        }
        if (!isObject((body as any).webauthn_authentication)) {
          return json(
            { ok: false, code: 'invalid_body', message: 'webauthn_authentication is required' },
            { status: 400 },
          );
        }

        const result = await ctx.service.verifyWebAuthnLogin({
          challengeId,
          webauthn_authentication: (body as any).webauthn_authentication,
          expected_origin: origin,
        });
        if (!result.ok || !result.verified) {
          return json(result, { status: result.code === 'internal' ? 500 : 400 });
        }

        return json({ ok: true, verified: true }, { status: 200 });
      },
    },
    google: {
      options: async () => {
        const configured = ctx.service.isGoogleOidcConfigured();
        return json({ ok: true, configured }, { status: 200 });
      },
      verify: async () => {
        const idToken = String((body as any).idToken ?? (body as any).id_token ?? '').trim();
        if (!idToken) {
          return json(
            { ok: false, code: 'invalid_body', message: 'id_token is required' },
            { status: 400 },
          );
        }

        const result = await ctx.service.verifyGoogleLogin({ idToken });
        if (!result.ok || !result.verified || !result.userId) {
          return json(result, { status: result.code === 'internal' ? 500 : 400 });
        }

        const baseBody = {
          ok: true,
          verified: true,
          ...(result.email ? { email: result.email } : {}),
        };
        return json(baseBody, { status: 200 });
      },
    },
  };

  const handler = providers[parsedPath.provider]?.[parsedPath.action];
  if (!handler) return null;
  return handler();
}
