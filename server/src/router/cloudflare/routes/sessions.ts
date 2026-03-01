import { DEFAULT_SESSION_COOKIE_NAME, deriveJwtExpiresAtIso, parseSessionKind } from '../../relay';
import { emitRelayWebhookEvent } from '../../relayWebhooks';
import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { headersToRecord, json, readJson } from '../http';

async function emitSessionExchangeFailed(
  ctx: CloudflareRelayContext,
  input: {
    code: string;
    message: string;
    status: number;
    exchangeType?: string;
    sessionKind?: string;
    userId?: string;
  },
): Promise<void> {
  await emitRelayWebhookEvent({
    logger: ctx.logger,
    webhooks: ctx.opts.relayWebhooks,
    eventType: 'session.exchange.failed',
    userId: input.userId,
    payload: {
      code: input.code,
      message: input.message,
      status: input.status,
      exchangeType: input.exchangeType || 'unknown',
      sessionKind: input.sessionKind || 'jwt',
    },
  });
}

function hasBearerSessionSignal(ctx: CloudflareRelayContext): boolean {
  const authorization = String(ctx.request.headers.get('authorization') || '').trim();
  return authorization.toLowerCase().startsWith('bearer ');
}

function hasCookieSessionSignal(ctx: CloudflareRelayContext): boolean {
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
}

async function readAndValidateAppSession(
  ctx: CloudflareRelayContext,
): Promise<
  | { ok: true; claims: any; userId: string; appSessionVersion: string }
  | {
      ok: false;
      response: Response;
      code?: string;
      message?: string;
      claims?: any;
      userId?: string;
      appSessionVersion?: string;
      hadBearerSessionSignal?: boolean;
      hadCookieSessionSignal?: boolean;
    }
> {
  const session = ctx.opts.session;
  if (!session) {
    return {
      ok: false,
      code: 'sessions_disabled',
      message: 'Sessions are not configured',
      response: json(
        { authenticated: false, code: 'sessions_disabled', message: 'Sessions are not configured' },
        { status: 501 },
      ),
    };
  }

  const parsed = await session.parse(headersToRecord(ctx.request.headers));
  if (!parsed.ok) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'No valid session',
      hadBearerSessionSignal: hasBearerSessionSignal(ctx),
      hadCookieSessionSignal: hasCookieSessionSignal(ctx),
      response: json(
        { authenticated: false, code: 'unauthorized', message: 'No valid session' },
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
      code: 'unauthorized',
      message: 'No valid app session',
      response: json(
        { authenticated: false, code: 'unauthorized', message: 'No valid app session' },
        { status: 401 },
      ),
    };
  }
  const userId = String((claims as any).sub || '').trim();
  const appSessionVersion =
    typeof (claims as any).appSessionVersion === 'string'
      ? String((claims as any).appSessionVersion).trim()
      : '';
  if (!userId || !appSessionVersion) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'Invalid app session',
      response: json(
        { authenticated: false, code: 'unauthorized', message: 'Invalid app session' },
        { status: 401 },
      ),
    };
  }
  const validated = await ctx.service.validateAppSessionVersion({ userId, appSessionVersion });
  if (!validated.ok) {
    return {
      ok: false,
      code: validated.code,
      message: validated.message,
      claims,
      userId,
      appSessionVersion,
      response: json(
        { authenticated: false, code: validated.code, message: validated.message },
        { status: validated.code === 'internal' ? 500 : 401 },
      ),
    };
  }
  return { ok: true, claims, userId, appSessionVersion };
}

async function maybeEmitWarmExpiredFromValidationFailure(input: {
  ctx: CloudflareRelayContext;
  validated:
    | { ok: true; claims: any; userId: string; appSessionVersion: string }
    | {
        ok: false;
        response: Response;
        code?: string;
        message?: string;
        claims?: any;
        userId?: string;
        appSessionVersion?: string;
        hadBearerSessionSignal?: boolean;
        hadCookieSessionSignal?: boolean;
      };
  source: string;
  sessionKind?: string;
}): Promise<void> {
  if (input.validated.ok) return;
  const code = String(input.validated.code || '').trim();
  const shouldEmit =
    code === 'invalid_session_version' ||
    (code === 'unauthorized' &&
      (Boolean(input.validated.hadBearerSessionSignal) ||
        Boolean(input.validated.hadCookieSessionSignal)));
  if (!shouldEmit) return;
  await emitRelayWebhookEvent({
    logger: input.ctx.logger,
    webhooks: input.ctx.opts.relayWebhooks,
    eventType: 'session.warm.expired',
    claims: input.validated.claims,
    userId: input.validated.userId,
    payload: {
      expired: true,
      source: input.source,
      reason: String(input.validated.message || 'Session expired'),
      sessionKind: input.sessionKind || 'jwt',
      code,
      ...(input.validated.appSessionVersion
        ? { appSessionVersion: input.validated.appSessionVersion }
        : {}),
    },
  });
}

export async function handleSessionState(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'GET') return null;
  if (ctx.pathname !== ctx.mePath && ctx.pathname !== '/session/state') return null;

  try {
    const validated = await readAndValidateAppSession(ctx);
    if (!validated.ok) {
      await maybeEmitWarmExpiredFromValidationFailure({
        ctx,
        validated,
        source: 'session.state',
      });
      return validated.response;
    }
    return json({ authenticated: true, claims: validated.claims }, { status: 200 });
  } catch (e: any) {
    return json(
      { authenticated: false, code: 'internal', message: e?.message || 'Internal error' },
      { status: 500 },
    );
  }
}

export async function handleSessionExchange(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/session/exchange') return null;

  try {
    const body = await readJson(ctx.request);
    const parsedBody = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
    const sessionKind = parseSessionKind(parsedBody);
    const exchange =
      parsedBody &&
      typeof (parsedBody as any).exchange === 'object' &&
      !Array.isArray((parsedBody as any).exchange)
        ? ((parsedBody as any).exchange as Record<string, unknown>)
        : null;
    const exchangeType = String(exchange?.type || '')
      .trim()
      .toLowerCase();
    if (!exchange || (exchangeType !== 'oidc_jwt' && exchangeType !== 'passkey_assertion')) {
      await emitSessionExchangeFailed(ctx, {
        status: 400,
        code: 'invalid_body',
        message: 'exchange.type must be one of: oidc_jwt, passkey_assertion',
        exchangeType,
        sessionKind,
      });
      return json(
        {
          ok: false,
          code: 'invalid_body',
          message: 'exchange.type must be one of: oidc_jwt, passkey_assertion',
        },
        { status: 400 },
      );
    }

    const session = ctx.opts.session;
    if (!session) {
      await emitSessionExchangeFailed(ctx, {
        status: 501,
        code: 'sessions_disabled',
        message: 'Sessions are not configured',
        exchangeType,
        sessionKind,
      });
      return json(
        { ok: false, code: 'sessions_disabled', message: 'Sessions are not configured' },
        { status: 501 },
      );
    }

    let userId = '';
    let provider: 'oidc' | 'passkey' = 'oidc';
    let providerSubject: string | undefined;
    let oidcIssuer: string | undefined;
    let oidcSub: string | undefined;
    let oidcAud: string[] | undefined;
    let passkeyChallengeId: string | undefined;

    if (exchangeType === 'oidc_jwt') {
      const verified = await ctx.service.verifyOidcJwtExchange({ token: exchange.token });
      if (!verified.ok || !verified.verified || !verified.userId) {
        const code = verified.code || 'not_verified';
        const status =
          code === 'internal'
            ? 500
            : code === 'not_configured' || code === 'unsupported'
              ? 501
              : code === 'invalid_body'
                ? 400
                : 401;
        await emitSessionExchangeFailed(ctx, {
          status,
          code,
          message: verified.message || 'OIDC exchange failed',
          exchangeType,
          sessionKind,
        });
        return json(
          { ok: false, code, message: verified.message || 'OIDC exchange failed' },
          { status },
        );
      }
      userId = String(verified.userId || '').trim();
      provider = 'oidc';
      providerSubject = verified.providerSubject;
      oidcIssuer = verified.iss;
      oidcSub = verified.sub;
      oidcAud = Array.isArray(verified.aud) ? verified.aud : undefined;
    } else {
      const challengeId = String(
        exchange.challengeId ?? exchange.challenge_id ?? '',
      ).trim();
      if (!challengeId) {
        await emitSessionExchangeFailed(ctx, {
          status: 400,
          code: 'invalid_body',
          message: 'exchange.challengeId is required for passkey_assertion',
          exchangeType,
          sessionKind,
        });
        return json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'exchange.challengeId is required for passkey_assertion',
          },
          { status: 400 },
        );
      }
      const webauthnAuthentication = exchange.webauthn_authentication;
      if (
        !webauthnAuthentication ||
        typeof webauthnAuthentication !== 'object' ||
        Array.isArray(webauthnAuthentication)
      ) {
        await emitSessionExchangeFailed(ctx, {
          status: 400,
          code: 'invalid_body',
          message: 'exchange.webauthn_authentication is required for passkey_assertion',
          exchangeType,
          sessionKind,
        });
        return json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'exchange.webauthn_authentication is required for passkey_assertion',
          },
          { status: 400 },
        );
      }
      const expectedOrigin = (() => {
        const explicitOrigin = String(
          exchange.expected_origin ?? exchange.expectedOrigin ?? '',
        ).trim();
        if (explicitOrigin) return explicitOrigin;
        const headerOrigin = String(ctx.request.headers.get('origin') || '').trim();
        return headerOrigin || undefined;
      })();
      const verified = await ctx.service.verifyWebAuthnLogin({
        challengeId,
        webauthn_authentication: webauthnAuthentication,
        expected_origin: expectedOrigin,
      });
      if (!verified.ok || !verified.verified || !verified.userId) {
        const code = verified.code || 'not_verified';
        const status = code === 'internal' ? 500 : code === 'invalid_body' ? 400 : 401;
        await emitSessionExchangeFailed(ctx, {
          status,
          code,
          message: verified.message || 'Passkey assertion exchange failed',
          exchangeType,
          sessionKind,
        });
        return json(
          { ok: false, code, message: verified.message || 'Passkey assertion exchange failed' },
          { status },
        );
      }
      userId = String(verified.userId || '').trim();
      provider = 'passkey';
      passkeyChallengeId = challengeId;
    }

    if (!userId) {
      await emitSessionExchangeFailed(ctx, {
        status: 500,
        code: 'internal',
        message: 'Exchange did not resolve userId',
        exchangeType,
        sessionKind,
      });
      return json(
        { ok: false, code: 'internal', message: 'Exchange did not resolve userId' },
        { status: 500 },
      );
    }

    const appVersion = await ctx.service.getOrCreateAppSessionVersion({ userId });
    if (!appVersion.ok) {
      await emitSessionExchangeFailed(ctx, {
        status: appVersion.code === 'internal' ? 500 : 400,
        code: appVersion.code,
        message: appVersion.message,
        exchangeType,
        sessionKind,
        userId,
      });
      return json(
        { ok: false, code: appVersion.code, message: appVersion.message },
        { status: appVersion.code === 'internal' ? 500 : 400 },
      );
    }

    const jwt = await session.signJwt(userId, {
      kind: 'app_session_v1',
      appSessionVersion: appVersion.appSessionVersion,
      provider,
      ...(providerSubject ? { providerSubject } : {}),
      ...(oidcIssuer ? { oidcIssuer } : {}),
      ...(oidcSub ? { oidcSub } : {}),
      ...(oidcAud?.length ? { oidcAud } : {}),
    });
    const sessionExpiresAt = deriveJwtExpiresAtIso(jwt);
    const responseBody = {
      ok: true,
      session: {
        kind: 'app_session_v1',
        userId,
        ...(sessionExpiresAt ? { expiresAt: sessionExpiresAt } : {}),
      },
    };
    await emitRelayWebhookEvent({
      logger: ctx.logger,
      webhooks: ctx.opts.relayWebhooks,
      eventType: 'session.warm.created',
      userId,
      payload: {
        kind: 'app_session_v1',
        provider,
        sessionKind,
        appSessionVersion: appVersion.appSessionVersion,
      },
    });
    if (provider === 'passkey') {
      await emitRelayWebhookEvent({
        logger: ctx.logger,
        webhooks: ctx.opts.relayWebhooks,
        eventType: 'wallet.unlocked',
        userId,
        eventId: passkeyChallengeId,
        payload: {
          unlocked: true,
          method: 'passkey',
          ...(passkeyChallengeId ? { challengeId: passkeyChallengeId } : {}),
        },
      });
    }
    if (sessionKind === 'cookie') {
      return json(responseBody, {
        status: 200,
        headers: { 'Set-Cookie': session.buildSetCookie(jwt) },
      });
    }
    return json({ ...responseBody, jwt }, { status: 200 });
  } catch (error: unknown) {
    await emitSessionExchangeFailed(ctx, {
      status: 500,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    });
    return json(
      {
        ok: false,
        code: 'internal',
        message: error instanceof Error ? error.message : 'Internal error',
      },
      { status: 500 },
    );
  }
}

export async function handleSessionRevoke(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/session/revoke') return null;

  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'session.revoke',
    });
    return validated.response;
  }

  const rotated = await ctx.service.rotateAppSessionVersion({ userId: validated.userId });
  if (!rotated.ok) {
    return json(
      { ok: false, code: rotated.code, message: rotated.message },
      { status: rotated.code === 'internal' ? 500 : 400 },
    );
  }

  const session = ctx.opts.session;
  await emitRelayWebhookEvent({
    logger: ctx.logger,
    webhooks: ctx.opts.relayWebhooks,
    eventType: 'session.revoked',
    claims: validated.claims,
    userId: validated.userId,
    payload: {
      revoked: true,
      appSessionVersion: validated.appSessionVersion,
    },
  });
  return json(
    { ok: true, revoked: true, userId: validated.userId },
    {
      status: 200,
      ...(session ? { headers: { 'Set-Cookie': session.buildClearCookie() } } : {}),
    },
  );
}

export async function handleSessionRefresh(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/session/refresh') return null;

  const body = await readJson(ctx.request);
  const sessionKind = parseSessionKind(body);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'session.refresh',
      sessionKind,
    });
    const payload = await validated.response.clone().json().catch(() => ({}));
    return json(
      {
        code: String((payload as any)?.code || 'unauthorized'),
        message: String((payload as any)?.message || 'No valid app session'),
      },
      { status: validated.response.status },
    );
  }
  const session = ctx.opts.session;
  if (!session) {
    return json(
      { code: 'sessions_disabled', message: 'Sessions are not configured' },
      { status: 501 },
    );
  }
  const out = await session.refresh(Object.fromEntries(ctx.request.headers.entries()));
  if (!out.ok || !out.jwt) {
    if ((out.code || 'not_eligible') === 'unauthorized') {
      await emitRelayWebhookEvent({
        logger: ctx.logger,
        webhooks: ctx.opts.relayWebhooks,
        eventType: 'session.warm.expired',
        claims: validated.claims,
        userId: validated.userId,
        payload: {
          expired: true,
          source: 'session.refresh',
          reason: out.message || 'Refresh not eligible',
          sessionKind,
        },
      });
    }
    return json(
      { code: out.code || 'not_eligible', message: out.message || 'Refresh not eligible' },
      { status: out.code === 'unauthorized' ? 401 : 400 },
    );
  }
  await emitRelayWebhookEvent({
    logger: ctx.logger,
    webhooks: ctx.opts.relayWebhooks,
    eventType: 'session.warm.refreshed',
    claims: validated.claims,
    userId: validated.userId,
    payload: {
      refreshed: true,
      sessionKind,
    },
  });
  const res = json(sessionKind === 'cookie' ? { ok: true } : { ok: true, jwt: out.jwt }, {
    status: 200,
  });
  if (sessionKind === 'cookie' && out.jwt) {
    try {
      res.headers.set('Set-Cookie', session.buildSetCookie(out.jwt));
    } catch {}
  }
  return res;
}

export async function handleWalletUnlockOptions(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/unlock/options') return null;
  const body = await readJson(ctx.request);
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
      { status: 400 },
    );
  }
  const result = await ctx.service.createWebAuthnLoginOptions(body as any);
  return json(result, { status: result.ok ? 200 : result.code === 'internal' ? 500 : 400 });
}

export async function handleWalletUnlockVerify(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/unlock/verify') return null;
  const body = await readJson(ctx.request);
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
      { status: 400 },
    );
  }

  const challengeId = String((body as any).challengeId ?? (body as any).challenge_id ?? '').trim();
  if (!challengeId) {
    return json(
      { ok: false, code: 'invalid_body', message: 'challengeId is required' },
      { status: 400 },
    );
  }
  const webauthnAuthentication = (body as any).webauthn_authentication;
  if (!webauthnAuthentication || typeof webauthnAuthentication !== 'object') {
    return json(
      { ok: false, code: 'invalid_body', message: 'webauthn_authentication is required' },
      { status: 400 },
    );
  }

  const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;
  const result = await ctx.service.verifyWebAuthnLogin({
    challengeId,
    webauthn_authentication: webauthnAuthentication,
    expected_origin: origin,
  });
  if (!result.ok || !result.verified) {
    return json(result, { status: result.code === 'internal' ? 500 : 400 });
  }
  await emitRelayWebhookEvent({
    logger: ctx.logger,
    webhooks: ctx.opts.relayWebhooks,
    eventType: 'wallet.unlocked',
    userId: result.userId,
    eventId: challengeId,
    payload: {
      unlocked: true,
      method: 'passkey',
      challengeId,
    },
  });
  return json(
    {
      ok: true,
      unlocked: true,
      ...(result.userId ? { userId: result.userId } : {}),
    },
    { status: 200 },
  );
}

export async function handleWalletState(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'GET' || ctx.pathname !== '/wallet/state') return null;
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.state',
    });
    const payload = await validated.response.clone().json().catch(() => ({}));
    return json(
      {
        ok: false,
        locked: true,
        code: String((payload as any)?.code || 'unauthorized'),
        message: String((payload as any)?.message || 'No valid app session'),
      },
      { status: validated.response.status },
    );
  }
  return json({ ok: true, locked: false, userId: validated.userId }, { status: 200 });
}

export async function handleWalletLock(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/lock') return null;
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.lock',
    });
    const payload = await validated.response.clone().json().catch(() => ({}));
    return json(
      {
        ok: false,
        locked: true,
        code: String((payload as any)?.code || 'unauthorized'),
        message: String((payload as any)?.message || 'No valid app session'),
      },
      { status: validated.response.status },
    );
  }

  const rotated = await ctx.service.rotateAppSessionVersion({ userId: validated.userId });
  if (!rotated.ok) {
    return json(
      { ok: false, locked: true, code: rotated.code, message: rotated.message },
      { status: rotated.code === 'internal' ? 500 : 400 },
    );
  }

  const session = ctx.opts.session;
  await emitRelayWebhookEvent({
    logger: ctx.logger,
    webhooks: ctx.opts.relayWebhooks,
    eventType: 'wallet.locked',
    claims: validated.claims,
    userId: validated.userId,
    payload: {
      locked: true,
      appSessionVersion: validated.appSessionVersion,
    },
  });
  return json(
    { ok: true, locked: true, userId: validated.userId },
    {
      status: 200,
      ...(session ? { headers: { 'Set-Cookie': session.buildClearCookie() } } : {}),
    },
  );
}
