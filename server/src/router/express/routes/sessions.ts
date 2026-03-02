import type { Router as ExpressRouter } from 'express';
import { DEFAULT_SESSION_COOKIE_NAME, deriveJwtExpiresAtIso, parseSessionKind } from '../../relay';
import { emitRelayWebhookEvent } from '../../relayWebhooks';
import type { ExpressRelayContext } from '../createRelayRouter';

export function registerSessionRoutes(router: ExpressRouter, ctx: ExpressRelayContext): void {
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

  const emitSessionExchangeFailed = async (input: {
    code: string;
    message: string;
    status: number;
    exchangeType?: string;
    sessionKind?: string;
    userId?: string;
  }): Promise<void> => {
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
  };

  const readAndValidateAppSession = async (
    headers: Record<string, string | string[] | undefined>,
  ): Promise<
    | { ok: true; claims: any; userId: string; appSessionVersion: string }
    | {
        ok: false;
        status: number;
        body: Record<string, unknown>;
        claims?: any;
        userId?: string;
        appSessionVersion?: string;
        hadBearerSessionSignal?: boolean;
        hadCookieSessionSignal?: boolean;
      }
  > => {
    const session = ctx.opts.session;
    if (!session) {
      return {
        ok: false,
        status: 501,
        body: {
          authenticated: false,
          code: 'sessions_disabled',
          message: 'Sessions are not configured',
        },
      };
    }
    const parsed = await session.parse(headers || {});
    if (!parsed.ok) {
      return {
        ok: false,
        status: 401,
        body: { authenticated: false, code: 'unauthorized', message: 'No valid session' },
        hadBearerSessionSignal: hasBearerSessionSignal(headers || {}),
        hadCookieSessionSignal: hasCookieSessionSignal(headers || {}),
      };
    }
    const claims: any = (parsed as any).claims || {};
    const kindRaw = (claims as any).kind;
    const kind = typeof kindRaw === 'string' ? kindRaw.trim() : '';
    if (kind !== 'app_session_v1') {
      return {
        ok: false,
        status: 401,
        body: { authenticated: false, code: 'unauthorized', message: 'No valid app session' },
      };
    }
    const userId = String(claims.sub || '').trim();
    const appSessionVersion =
      typeof claims.appSessionVersion === 'string' ? claims.appSessionVersion.trim() : '';
    if (!userId || !appSessionVersion) {
      return {
        ok: false,
        status: 401,
        body: { authenticated: false, code: 'unauthorized', message: 'Invalid app session' },
      };
    }
    const validated = await ctx.service.validateAppSessionVersion({ userId, appSessionVersion });
    if (!validated.ok) {
      return {
        ok: false,
        status: validated.code === 'internal' ? 500 : 401,
        body: { authenticated: false, code: validated.code, message: validated.message },
        claims,
        userId,
        appSessionVersion,
      };
    }
    return { ok: true, claims, userId, appSessionVersion };
  };

  const maybeEmitWarmExpiredFromValidationFailure = async (input: {
    validated:
      | { ok: true; claims: any; userId: string; appSessionVersion: string }
      | {
          ok: false;
          status: number;
          body: Record<string, unknown>;
          claims?: any;
          userId?: string;
          appSessionVersion?: string;
          hadBearerSessionSignal?: boolean;
          hadCookieSessionSignal?: boolean;
        };
    source: string;
    sessionKind?: string;
  }): Promise<void> => {
    if (input.validated.ok) return;
    const code = String((input.validated.body as any)?.code || '').trim();
    const shouldEmit =
      code === 'invalid_session_version' ||
      (code === 'unauthorized' &&
        (Boolean(input.validated.hadBearerSessionSignal) ||
          Boolean(input.validated.hadCookieSessionSignal)));
    if (!shouldEmit) return;
    await emitRelayWebhookEvent({
      logger: ctx.logger,
      webhooks: ctx.opts.relayWebhooks,
      eventType: 'session.warm.expired',
      claims: input.validated.claims,
      userId: input.validated.userId,
      payload: {
        expired: true,
        source: input.source,
        reason: String((input.validated.body as any)?.message || 'Session expired'),
        sessionKind: input.sessionKind || 'jwt',
        code,
        ...(input.validated.appSessionVersion
          ? { appSessionVersion: input.validated.appSessionVersion }
          : {}),
      },
    });
  };

  const handleSessionState = async (req: any, res: any): Promise<void> => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'session.state',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      res.status(200).json({ authenticated: true, claims: validated.claims });
    } catch (e: any) {
      res
        .status(500)
        .json({ authenticated: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  };

  // Session: read current claims via bearer token or cookie.
  const sessionStatePaths = Array.from(new Set([ctx.mePath, '/session/state']));
  for (const path of sessionStatePaths) {
    if (!path || typeof path !== 'string') continue;
    router.get(path, handleSessionState);
  }

  // Session: exchange external auth assertion into app session.
  router.post('/session/exchange', async (req: any, res: any) => {
    try {
      const body =
        req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
      const sessionKind = parseSessionKind(body);
      const exchange =
        body.exchange && typeof body.exchange === 'object' && !Array.isArray(body.exchange)
          ? body.exchange
          : null;
      const exchangeType = String((exchange as any)?.type || '')
        .trim()
        .toLowerCase();
      if (!exchange || (exchangeType !== 'oidc_jwt' && exchangeType !== 'passkey_assertion')) {
        await emitSessionExchangeFailed({
          status: 400,
          code: 'invalid_body',
          message: 'exchange.type must be one of: oidc_jwt, passkey_assertion',
          exchangeType,
          sessionKind,
        });
        res.status(400).json({
          ok: false,
          code: 'invalid_body',
          message: 'exchange.type must be one of: oidc_jwt, passkey_assertion',
        });
        return;
      }

      const session = ctx.opts.session;
      if (!session) {
        await emitSessionExchangeFailed({
          status: 501,
          code: 'sessions_disabled',
          message: 'Sessions are not configured',
          exchangeType,
          sessionKind,
        });
        res.status(501).json({
          ok: false,
          code: 'sessions_disabled',
          message: 'Sessions are not configured',
        });
        return;
      }

      let userId = '';
      let provider: 'oidc' | 'passkey' = 'oidc';
      let providerSubject: string | undefined;
      let oidcIssuer: string | undefined;
      let oidcSub: string | undefined;
      let oidcAud: string[] | undefined;
      let passkeyChallengeId: string | undefined;

      if (exchangeType === 'oidc_jwt') {
        const verified = await ctx.service.verifyOidcJwtExchange({
          token: (exchange as any).token,
        });
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
          await emitSessionExchangeFailed({
            status,
            code,
            message: verified.message || 'OIDC exchange failed',
            exchangeType,
            sessionKind,
          });
          res
            .status(status)
            .json({ ok: false, code, message: verified.message || 'OIDC exchange failed' });
          return;
        }
        userId = String(verified.userId || '').trim();
        provider = 'oidc';
        providerSubject = verified.providerSubject;
        oidcIssuer = verified.iss;
        oidcSub = verified.sub;
        oidcAud = Array.isArray(verified.aud) ? verified.aud : undefined;
      } else {
        const challengeId = String(
          (exchange as any).challengeId ?? (exchange as any).challenge_id ?? '',
        ).trim();
        if (!challengeId) {
          await emitSessionExchangeFailed({
            status: 400,
            code: 'invalid_body',
            message: 'exchange.challengeId is required for passkey_assertion',
            exchangeType,
            sessionKind,
          });
          res.status(400).json({
            ok: false,
            code: 'invalid_body',
            message: 'exchange.challengeId is required for passkey_assertion',
          });
          return;
        }
        const webauthnAuthentication = (exchange as any).webauthn_authentication;
        if (
          !webauthnAuthentication ||
          typeof webauthnAuthentication !== 'object' ||
          Array.isArray(webauthnAuthentication)
        ) {
          await emitSessionExchangeFailed({
            status: 400,
            code: 'invalid_body',
            message: 'exchange.webauthn_authentication is required for passkey_assertion',
            exchangeType,
            sessionKind,
          });
          res.status(400).json({
            ok: false,
            code: 'invalid_body',
            message: 'exchange.webauthn_authentication is required for passkey_assertion',
          });
          return;
        }
        const expectedOrigin = (() => {
          const explicitOrigin = String(
            (exchange as any).expected_origin ?? (exchange as any).expectedOrigin ?? '',
          ).trim();
          if (explicitOrigin) return explicitOrigin;
          const originRaw = req.headers?.origin ?? req.headers?.Origin;
          return typeof originRaw === 'string' ? originRaw.trim() || undefined : undefined;
        })();
        const verified = await ctx.service.verifyWebAuthnLogin({
          challengeId,
          webauthn_authentication: webauthnAuthentication,
          expected_origin: expectedOrigin,
        });
        if (!verified.ok || !verified.verified || !verified.userId) {
          const code = verified.code || 'not_verified';
          const status = code === 'internal' ? 500 : code === 'invalid_body' ? 400 : 401;
          await emitSessionExchangeFailed({
            status,
            code,
            message: verified.message || 'Passkey assertion exchange failed',
            exchangeType,
            sessionKind,
          });
          res.status(status).json({
            ok: false,
            code,
            message: verified.message || 'Passkey assertion exchange failed',
          });
          return;
        }
        userId = String(verified.userId || '').trim();
        provider = 'passkey';
        passkeyChallengeId = challengeId;
      }

      if (!userId) {
        await emitSessionExchangeFailed({
          status: 500,
          code: 'internal',
          message: 'Exchange did not resolve userId',
          exchangeType,
          sessionKind,
        });
        res
          .status(500)
          .json({ ok: false, code: 'internal', message: 'Exchange did not resolve userId' });
        return;
      }

      const appVersion = await ctx.service.getOrCreateAppSessionVersion({ userId });
      if (!appVersion.ok) {
        await emitSessionExchangeFailed({
          status: appVersion.code === 'internal' ? 500 : 400,
          code: appVersion.code,
          message: appVersion.message,
          exchangeType,
          sessionKind,
          userId,
        });
        res.status(appVersion.code === 'internal' ? 500 : 400).json({
          ok: false,
          code: appVersion.code,
          message: appVersion.message,
        });
        return;
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
      const sessionBody = {
        kind: 'app_session_v1',
        userId,
        ...(sessionExpiresAt ? { expiresAt: sessionExpiresAt } : {}),
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
        res.set('Set-Cookie', session.buildSetCookie(jwt));
        res.status(200).json({ ok: true, session: sessionBody });
        return;
      }
      res.status(200).json({ ok: true, session: sessionBody, jwt });
    } catch (e: any) {
      await emitSessionExchangeFailed({
        status: 500,
        code: 'internal',
        message: e?.message || 'Internal error',
      });
      res.status(500).json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  // Session: revoke current app session scope (version rotation).
  router.post('/session/revoke', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'session.revoke',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      const rotated = await ctx.service.rotateAppSessionVersion({ userId: validated.userId });
      if (!rotated.ok) {
        res.status(rotated.code === 'internal' ? 500 : 400).json({
          ok: false,
          code: rotated.code,
          message: rotated.message,
        });
        return;
      }
      const session = ctx.opts.session;
      if (session) res.set('Set-Cookie', session.buildClearCookie());
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
      res.status(200).json({ ok: true, revoked: true, userId: validated.userId });
    } catch (e: any) {
      res.status(500).json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  // Session: refresh (sliding expiration)
  router.post('/session/refresh', async (req: any, res: any) => {
    try {
      const sessionKind = parseSessionKind(req.body || {});
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'session.refresh',
          sessionKind,
        });
        res.status(validated.status).json({
          code: (validated.body as any).code || 'unauthorized',
          message: (validated.body as any).message || 'No valid app session',
        });
        return;
      }
      const session = ctx.opts.session;
      if (!session) {
        res.status(501).json({ code: 'sessions_disabled', message: 'Sessions are not configured' });
        return;
      }
      const out = await session.refresh(req.headers || {});
      if (!out.ok || !out.jwt) {
        const code = out.code || 'not_eligible';
        const message = out.message || 'Refresh not eligible';
        if (code === 'unauthorized') {
          await emitRelayWebhookEvent({
            logger: ctx.logger,
            webhooks: ctx.opts.relayWebhooks,
            eventType: 'session.warm.expired',
            claims: validated.claims,
            userId: validated.userId,
            payload: {
              expired: true,
              source: 'session.refresh',
              reason: message,
              sessionKind,
            },
          });
        }
        res.status(code === 'unauthorized' ? 401 : 400).json({ code, message });
        return;
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
      if (sessionKind === 'cookie') {
        res.set('Set-Cookie', session.buildSetCookie(out.jwt));
        res.status(200).json({ ok: true });
      } else {
        res.status(200).json({ ok: true, jwt: out.jwt });
      }
    } catch (e: any) {
      res.status(500).json({ code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  // Wallet: unlock challenge (passkey challenge issuance)
  router.post('/wallet/unlock/challenge', async (req: any, res: any) => {
    try {
      if (!req?.body) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const result = await ctx.service.createWebAuthnLoginOptions(req.body);
      res.status(result.ok ? 200 : result.code === 'internal' ? 500 : 400).json(result);
    } catch (e: any) {
      res.status(500).json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  // Wallet: unlock verify (passkey assertion)
  router.post('/wallet/unlock/verify', async (req: any, res: any) => {
    try {
      if (!req?.body) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const body = req.body;
      const challengeId = String(body.challengeId ?? body.challenge_id ?? '').trim();
      if (!challengeId) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'challengeId is required' });
        return;
      }
      if (!body.webauthn_authentication || typeof body.webauthn_authentication !== 'object') {
        res.status(400).json({
          ok: false,
          code: 'invalid_body',
          message: 'webauthn_authentication is required',
        });
        return;
      }

      const originRaw = req.headers?.origin ?? req.headers?.Origin;
      const origin = typeof originRaw === 'string' ? originRaw.trim() || undefined : undefined;
      const result = await ctx.service.verifyWebAuthnLogin({
        challengeId,
        webauthn_authentication: body.webauthn_authentication,
        expected_origin: origin,
      });
      if (!result.ok || !result.verified) {
        res.status(result.code === 'internal' ? 500 : 400).json(result);
        return;
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

      res.status(200).json({
        ok: true,
        unlocked: true,
        ...(result.userId ? { userId: result.userId } : {}),
      });
    } catch (e: any) {
      res.status(500).json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  // Wallet: current lock state
  router.get('/wallet/state', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.state',
        });
        res.status(validated.status).json({
          ok: false,
          locked: true,
          code: (validated.body as any).code || 'unauthorized',
          message: (validated.body as any).message || 'No valid app session',
        });
        return;
      }
      res.status(200).json({ ok: true, locked: false, userId: validated.userId });
    } catch (e: any) {
      res.status(500).json({ ok: false, locked: true, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  // Wallet: lock (alias semantic on top of app-session revoke primitive)
  router.post('/wallet/lock', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.lock',
        });
        res.status(validated.status).json({
          ok: false,
          locked: true,
          code: (validated.body as any).code || 'unauthorized',
          message: (validated.body as any).message || 'No valid app session',
        });
        return;
      }
      const rotated = await ctx.service.rotateAppSessionVersion({ userId: validated.userId });
      if (!rotated.ok) {
        res.status(rotated.code === 'internal' ? 500 : 400).json({
          ok: false,
          locked: true,
          code: rotated.code,
          message: rotated.message,
        });
        return;
      }
      const session = ctx.opts.session;
      if (session) res.set('Set-Cookie', session.buildClearCookie());
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
      res.status(200).json({ ok: true, locked: true, userId: validated.userId });
    } catch (e: any) {
      res.status(500).json({ ok: false, locked: true, code: 'internal', message: e?.message || 'Internal error' });
    }
  });
}
