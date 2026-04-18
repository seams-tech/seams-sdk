import type { Router as ExpressRouter } from 'express';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalRecordString } from '@shared/utils/validation';
import { DEFAULT_SESSION_COOKIE_NAME, deriveJwtExpiresAtIso, parseSessionKind } from '../../relay';
import { emitRelayWebhookEvent } from '../../relayWebhooks';
import { resolveSourceIpFromExpressRequest } from '../../relayApiKeyAuth';
import type { ExpressRelayContext } from '../createRelayRouter';
import { resolveThresholdRuntimePolicyScope } from '../../commonRouterUtils';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  parseWalletEmailOtpChannel,
  parseWalletEmailOtpLoginOperation,
  parseWalletUnlockBackend,
  type WalletEmailOtpChannel,
} from '../../emailOtpRequestValidation';
import {
  authorizeEmailOtpExportPolicy,
  emailOtpExportPolicyAuditPayload,
} from '../../emailOtpExportPolicy';
import {
  emailOtpStatusCode,
  emailOtpChallengeResponseBody,
  getSessionWalletId,
  isGoogleOidcEmailOtpSession,
  parseOidcAccountMode,
} from '../../emailOtpSessionRouteHelpers';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
} from '@shared/utils/emailOtpDomain';

export function registerSessionRoutes(router: ExpressRouter, ctx: ExpressRelayContext): void {
  const hasBearerSessionSignal = (
    headers: Record<string, string | string[] | undefined>,
  ): boolean => {
    const value = headers.authorization ?? headers.Authorization;
    if (typeof value === 'string') {
      return value.trim().toLowerCase().startsWith('bearer ');
    }
    if (Array.isArray(value)) {
      return value.some((entry) =>
        String(entry || '')
          .trim()
          .toLowerCase()
          .startsWith('bearer '),
      );
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

  const emitEmailOtpWebhookEvent = async (input: {
    eventType: string;
    claims?: Record<string, unknown> | null;
    userId: string;
    walletId?: string;
    eventId?: string;
    payload?: Record<string, unknown>;
  }): Promise<void> => {
    await emitRelayWebhookEvent({
      logger: ctx.logger,
      webhooks: ctx.opts.relayWebhooks,
      eventType: input.eventType,
      claims: input.claims || undefined,
      userId: input.userId,
      ...(input.eventId ? { eventId: input.eventId } : {}),
      payload: {
        ...(input.walletId ? { walletId: input.walletId } : {}),
        ...(input.payload || {}),
      },
    });
  };

  const emitEmailOtpFailureWebhookEvents = async (input: {
    claims?: Record<string, unknown> | null;
    userId: string;
    walletId: string;
    source: 'registration_finalize' | 'login_challenge' | 'login_verify' | 'unlock_verify';
    code: string;
    message: string;
    challengeId?: string;
    otpChannel?: WalletEmailOtpChannel;
    operation?: string;
    lockedUntilMs?: number;
  }): Promise<void> => {
    const payload = {
      source: input.source,
      code: input.code,
      message: input.message,
      ...(input.challengeId ? { challengeId: input.challengeId } : {}),
      ...(input.otpChannel ? { otpChannel: input.otpChannel } : {}),
      ...(input.operation ? { operation: input.operation } : {}),
      ...(typeof input.lockedUntilMs === 'number' ? { lockedUntilMs: input.lockedUntilMs } : {}),
    };
    await emitEmailOtpWebhookEvent({
      eventType: 'wallet.email_otp.failed',
      claims: input.claims,
      userId: input.userId,
      walletId: input.walletId,
      ...(input.challengeId ? { eventId: input.challengeId } : {}),
      payload,
    });
    if (input.code !== 'otp_locked_out' && input.code !== 'otp_attempts_exhausted') return;
    await emitEmailOtpWebhookEvent({
      eventType: 'wallet.email_otp.locked',
      claims: input.claims,
      userId: input.userId,
      walletId: input.walletId,
      ...(input.challengeId ? { eventId: input.challengeId } : {}),
      payload,
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

  const hashAppSessionClaims = async (claims: Record<string, unknown>): Promise<string> => {
    const json = alphabetizeStringify(claims);
    return base64UrlEncode(await sha256BytesUtf8(json));
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
      let oidcEmail: string | undefined;
      let oidcName: string | undefined;
      let oidcGivenName: string | undefined;
      let oidcFamilyName: string | undefined;
      let oidcProvider: string | undefined;
      let oidcAccountMode: 'register' | 'login' | undefined;
      let passkeyChallengeId: string | undefined;
      let walletId: string | undefined;
      let googleEmailOtpResolution:
        | {
            mode: 'existing_wallet' | 'register_started';
            registrationAttemptId?: string;
            expiresAtMs?: number;
          }
        | undefined;
      let runtimePolicyScope: RuntimePolicyScope | undefined;

      if (exchangeType === 'oidc_jwt') {
        oidcProvider = String((exchange as any).provider || '')
          .trim()
          .toLowerCase();
        oidcAccountMode = parseOidcAccountMode((exchange as any).account_mode);
        if (oidcProvider === 'google' && !oidcAccountMode) {
          await emitSessionExchangeFailed({
            status: 400,
            code: 'invalid_body',
            message: 'exchange.account_mode must be register or login for Google Email OTP',
            exchangeType,
            sessionKind,
          });
          res.status(400).json({
            ok: false,
            code: 'invalid_body',
            message: 'exchange.account_mode must be register or login for Google Email OTP',
          });
          return;
        }
        const verified =
          oidcProvider === 'google'
            ? await ctx.service.verifyGoogleLogin({ idToken: (exchange as any).token })
            : await ctx.service.verifyOidcJwtExchange({
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
        oidcIssuer =
          oidcProvider === 'google' ? 'https://accounts.google.com' : (verified as any).iss;
        oidcSub = verified.sub;
        oidcAud = Array.isArray((verified as any).aud) ? (verified as any).aud : undefined;
        oidcEmail =
          typeof verified.email === 'string' && verified.email.trim()
            ? verified.email.trim().toLowerCase()
            : undefined;
        oidcName =
          typeof (verified as any).name === 'string' && (verified as any).name.trim()
            ? (verified as any).name.trim()
            : undefined;
        oidcGivenName =
          typeof (verified as any).given_name === 'string' && (verified as any).given_name.trim()
            ? (verified as any).given_name.trim()
            : undefined;
        oidcFamilyName =
          typeof (verified as any).family_name === 'string' && (verified as any).family_name.trim()
            ? (verified as any).family_name.trim()
            : undefined;
        if (oidcProvider === 'google' && oidcAccountMode === 'register' && !oidcEmail) {
          await emitSessionExchangeFailed({
            status: 400,
            code: 'invalid_claims',
            message: 'Google id_token must include email for Email OTP registration',
            exchangeType,
            sessionKind,
            userId,
          });
          res.status(400).json({
            ok: false,
            code: 'invalid_claims',
            message: 'Google id_token must include email for Email OTP registration',
          });
          return;
        }
        try {
          if (oidcProvider === 'google') {
            const runtimePolicyScopeResolution = await resolveThresholdRuntimePolicyScope({
              explicitScopeRaw: undefined,
              runtimeEnvironmentIdRaw: (body as { runtimeEnvironmentId?: unknown })
                .runtimeEnvironmentId,
              headers: req.headers || {},
              origin: Array.isArray(req.headers?.origin)
                ? req.headers.origin[0]
                : req.headers?.origin,
              publishableKeyAuth: ctx.opts.publishableKeyAuth || null,
              orgProjectEnv: ctx.opts.orgProjectEnv || null,
            });
            if (!runtimePolicyScopeResolution.ok) {
              await emitSessionExchangeFailed({
                status: runtimePolicyScopeResolution.status,
                code: runtimePolicyScopeResolution.code,
                message: runtimePolicyScopeResolution.message,
                exchangeType,
                sessionKind,
                userId,
              });
              res.status(runtimePolicyScopeResolution.status).json({
                ok: false,
                code: runtimePolicyScopeResolution.code,
                message: runtimePolicyScopeResolution.message,
              });
              return;
            }
            runtimePolicyScope = runtimePolicyScopeResolution.scope;
            const resolution = await ctx.service.resolveGoogleEmailOtpSession({
              providerSubject,
              sub: oidcSub,
              email: oidcEmail,
              accountMode: oidcAccountMode,
              runtimePolicyScope,
              forceNewDevWallet:
                (exchange as any).force_new_dev_wallet === true ||
                (exchange as any).forceNewDevWallet === true,
            });
            if (!resolution.ok) {
              const status = resolution.code === 'wallet_id_collision' ? 409 : 409;
              await emitSessionExchangeFailed({
                status,
                code: resolution.code,
                message: resolution.message,
                exchangeType,
                sessionKind,
                userId,
              });
              res.status(status).json(resolution);
              return;
            }
            walletId = resolution.walletId;
            googleEmailOtpResolution = {
              mode: resolution.mode,
              ...(resolution.mode === 'register_started'
                ? {
                    registrationAttemptId: resolution.registrationAttemptId,
                    expiresAtMs: resolution.expiresAtMs,
                  }
                : {}),
            };
          } else {
            walletId = await ctx.service.resolveOidcWalletId({
              providerSubject,
              sub: oidcSub,
              email: oidcEmail,
              accountMode: oidcAccountMode,
            });
          }
        } catch (e: any) {
          const code = typeof e?.code === 'string' && e.code ? e.code : 'internal';
          const status = code === 'not_found' ? 404 : code === 'invalid_body' ? 400 : 500;
          const message = e?.message || 'Failed to resolve OIDC wallet id';
          await emitSessionExchangeFailed({
            status,
            code,
            message,
            exchangeType,
            sessionKind,
            userId,
          });
          res.status(status).json({ ok: false, code, message });
          return;
        }
        if (oidcProvider === 'google' && oidcAccountMode === 'login') {
          const enrollment = await ctx.service.readEmailOtpEnrollment({ walletId });
          if (!enrollment.ok) {
            const status = emailOtpStatusCode(enrollment.code);
            await emitSessionExchangeFailed({
              status,
              code: enrollment.code,
              message: enrollment.message,
              exchangeType,
              sessionKind,
              userId,
            });
            res.status(status).json(enrollment);
            return;
          }
        }
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

      if (!runtimePolicyScope) {
        const runtimePolicyScopeResolution = await resolveThresholdRuntimePolicyScope({
          explicitScopeRaw: undefined,
          runtimeEnvironmentIdRaw: (body as { runtimeEnvironmentId?: unknown })
            .runtimeEnvironmentId,
          headers: req.headers || {},
          origin: Array.isArray(req.headers?.origin) ? req.headers.origin[0] : req.headers?.origin,
          publishableKeyAuth: ctx.opts.publishableKeyAuth || null,
          orgProjectEnv: ctx.opts.orgProjectEnv || null,
        });
        if (!runtimePolicyScopeResolution.ok) {
          await emitSessionExchangeFailed({
            status: runtimePolicyScopeResolution.status,
            code: runtimePolicyScopeResolution.code,
            message: runtimePolicyScopeResolution.message,
            exchangeType,
            sessionKind,
            userId,
          });
          res.status(runtimePolicyScopeResolution.status).json({
            ok: false,
            code: runtimePolicyScopeResolution.code,
            message: runtimePolicyScopeResolution.message,
          });
          return;
        }
        runtimePolicyScope = runtimePolicyScopeResolution.scope;
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
        ...(walletId ? { walletId } : {}),
        ...(googleEmailOtpResolution?.registrationAttemptId
          ? { googleEmailOtpRegistrationAttemptId: googleEmailOtpResolution.registrationAttemptId }
          : {}),
        ...(googleEmailOtpResolution?.mode
          ? { googleEmailOtpResolutionMode: googleEmailOtpResolution.mode }
          : {}),
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        ...(oidcProvider ? { oidcProvider } : {}),
        ...(providerSubject ? { providerSubject } : {}),
        ...(oidcIssuer ? { oidcIssuer } : {}),
        ...(oidcSub ? { oidcSub } : {}),
        ...(oidcAud?.length ? { oidcAud } : {}),
        ...(oidcEmail ? { email: oidcEmail } : {}),
        ...(oidcName ? { name: oidcName } : {}),
        ...(oidcGivenName ? { given_name: oidcGivenName } : {}),
        ...(oidcFamilyName ? { family_name: oidcFamilyName } : {}),
      });
      const sessionExpiresAt = deriveJwtExpiresAtIso(jwt);
      const sessionBody = {
        kind: 'app_session_v1',
        userId,
        ...(walletId ? { walletId } : {}),
        ...(googleEmailOtpResolution
          ? {
              googleEmailOtpResolution: {
                mode: googleEmailOtpResolution.mode,
                ...(googleEmailOtpResolution.registrationAttemptId
                  ? { registrationAttemptId: googleEmailOtpResolution.registrationAttemptId }
                  : {}),
                ...(googleEmailOtpResolution.expiresAtMs
                  ? { expiresAt: new Date(googleEmailOtpResolution.expiresAtMs).toISOString() }
                  : {}),
              },
            }
          : {}),
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        ...(sessionExpiresAt ? { expiresAt: sessionExpiresAt } : {}),
        ...(oidcEmail ? { email: oidcEmail } : {}),
        ...(oidcName ? { name: oidcName } : {}),
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
        await ctx.service.markEmailOtpStrongAuthSatisfied({ walletId: userId });
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
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
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
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
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

  // Wallet: unlock challenge (backend-neutral route)
  router.post('/wallet/unlock/challenge', async (req: any, res: any) => {
    try {
      if (!req?.body) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const body = req.body;
      const unlockBackend = parseWalletUnlockBackend(body.unlockBackend);
      if (!unlockBackend) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'unlockBackend is required' });
        return;
      }
      const result =
        unlockBackend === 'passkey'
          ? await ctx.service.createWebAuthnLoginOptions({
              userId: body.userId,
              rpId: body.rpId,
              ttlMs: body.ttlMs,
            })
          : await ctx.service.createEmailOtpUnlockChallenge({
              walletId: body.walletId,
              ttlMs: body.ttlMs,
            });
      res.status(result.ok ? 200 : result.code === 'internal' ? 500 : 400).json({
        ...result,
        unlockBackend,
      });
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  // Wallet: unlock verify (backend-neutral route)
  router.post('/wallet/unlock/verify', async (req: any, res: any) => {
    try {
      if (!req?.body) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const body = req.body;
      const unlockBackend = parseWalletUnlockBackend(body.unlockBackend);
      if (!unlockBackend) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'unlockBackend is required' });
        return;
      }
      const challengeId = String(body.challengeId || '').trim();
      if (!challengeId) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'challengeId is required' });
        return;
      }
      const result =
        unlockBackend === 'passkey'
          ? await (async () => {
              if (!body.webauthnAuthentication || typeof body.webauthnAuthentication !== 'object') {
                return {
                  ok: false,
                  verified: false,
                  code: 'invalid_body',
                  message: 'webauthnAuthentication is required',
                } as const;
              }
              const originRaw = req.headers?.origin ?? req.headers?.Origin;
              const origin =
                typeof originRaw === 'string' ? originRaw.trim() || undefined : undefined;
              return ctx.service.verifyWebAuthnLogin({
                challengeId,
                webauthn_authentication: body.webauthnAuthentication,
                expected_origin: origin,
              });
            })()
          : await ctx.service.verifyEmailOtpUnlockProof({
              walletId: body.walletId,
              challengeId,
              unlockProof: body.unlockProof,
            });
      if (!result.ok || !result.verified) {
        if (unlockBackend === EMAIL_OTP_CHANNEL) {
          const walletId = String(body.walletId || '').trim();
          if (walletId) {
            await emitEmailOtpFailureWebhookEvents({
              userId: walletId,
              walletId,
              source: 'unlock_verify',
              code: String(result.code || 'unlock_verify_failed'),
              message: String(result.message || 'Email OTP unlock verification failed'),
              challengeId,
            });
          }
        }
        res.status(result.code === 'internal' ? 500 : 400).json({ ...result, unlockBackend });
        return;
      }
      if (unlockBackend === 'passkey') {
        await ctx.service.markEmailOtpStrongAuthSatisfied({ walletId: result.userId });
      }
      await emitRelayWebhookEvent({
        logger: ctx.logger,
        webhooks: ctx.opts.relayWebhooks,
        eventType: 'wallet.unlocked',
        userId: result.userId,
        eventId: challengeId,
        payload: {
          unlocked: true,
          unlockBackend,
          challengeId,
        },
      });
      if (unlockBackend === EMAIL_OTP_CHANNEL) {
        const recoveredWalletId = String(
          (result as { walletId?: unknown }).walletId || body.walletId || '',
        ).trim();
        const recoveredUserId = String(result.userId || recoveredWalletId).trim();
        await emitEmailOtpWebhookEvent({
          eventType: 'wallet.email_otp.logged_in',
          userId: recoveredUserId,
          ...(recoveredWalletId ? { walletId: recoveredWalletId } : {}),
          eventId: challengeId,
          payload: {
            otpChannel: EMAIL_OTP_CHANNEL,
            unlockBackend,
            challengeId,
          },
        });
      }

      res.status(200).json({
        ok: true,
        unlocked: true,
        unlockBackend,
        ...(result.userId ? { userId: result.userId } : {}),
      });
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/wallet/email-otp/registration/challenge', async (req: any, res: any) => {
    try {
      if (!req?.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.registration.challenge',
        });
        res.status(validated.status).json(validated.body);
        return;
      }

      const body = req.body;
      const walletId = String(body.walletId || '').trim();
      if (!walletId) {
        res.status(400).json({ ok: false, code: 'invalid_body', message: 'walletId is required' });
        return;
      }
      if (walletId !== getSessionWalletId(validated.claims, validated.userId)) {
        res.status(403).json({
          ok: false,
          code: 'wallet_identity_mismatch',
          message: 'walletId must match the current app session wallet',
        });
        return;
      }
      const otpChannel = parseWalletEmailOtpChannel(body.otpChannel);
      if (!otpChannel) {
        res.status(400).json({
          ok: false,
          code: 'invalid_body',
          message: 'otpChannel must be email_otp',
        });
        return;
      }
      if (!isGoogleOidcEmailOtpSession(validated.claims)) {
        const strongAuthGate = await ctx.service.isEmailOtpStrongAuthRequired({ walletId });
        if (!strongAuthGate.ok) {
          res.status(emailOtpStatusCode(strongAuthGate.code)).json(strongAuthGate);
          return;
        }
        if (strongAuthGate.required) {
          res.status(403).json({
            ok: false,
            code: 'stronger_auth_required',
            message: 'Passkey authentication is required before modifying Email OTP enrollment',
            ...(strongAuthGate.lastEmailOtpLoginAtMs
              ? { lastEmailOtpLoginAtMs: strongAuthGate.lastEmailOtpLoginAtMs }
              : {}),
            ...(strongAuthGate.lastStrongAuthAtMs
              ? { lastStrongAuthAtMs: strongAuthGate.lastStrongAuthAtMs }
              : {}),
          });
          return;
        }
      }
      const email =
        typeof validated.claims.email === 'string'
          ? validated.claims.email.trim().toLowerCase()
          : '';
      const sessionHash = await hashAppSessionClaims(validated.claims);
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const result = await ctx.service.createEmailOtpEnrollmentChallenge({
        userId: validated.userId,
        walletId,
        orgId: (validated.claims as any).orgId,
        email,
        otpChannel: otpChannel,
        sessionHash,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
      });
      res
        .status(result.ok ? 200 : emailOtpStatusCode(result.code))
        .json(emailOtpChallengeResponseBody(result));
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/wallet/email-otp/registration/seal', async (req: any, res: any) => {
    try {
      if (!req?.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.registration.seal',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      const body = req.body;
      const walletId = String(body.walletId || '').trim();
      if (!walletId) {
        res.status(400).json({ ok: false, code: 'invalid_body', message: 'walletId is required' });
        return;
      }
      if (walletId !== getSessionWalletId(validated.claims, validated.userId)) {
        res.status(403).json({
          ok: false,
          code: 'wallet_identity_mismatch',
          message: 'walletId must match the current app session wallet',
        });
        return;
      }
      const wrappedCiphertext = String(body.wrappedCiphertext || '').trim();
      if (!wrappedCiphertext) {
        res.status(400).json({
          ok: false,
          code: 'invalid_body',
          message: 'wrappedCiphertext is required',
        });
        return;
      }
      if (!isGoogleOidcEmailOtpSession(validated.claims)) {
        const strongAuthGate = await ctx.service.isEmailOtpStrongAuthRequired({ walletId });
        if (!strongAuthGate.ok) {
          res.status(emailOtpStatusCode(strongAuthGate.code)).json(strongAuthGate);
          return;
        }
        if (strongAuthGate.required) {
          res.status(403).json({
            ok: false,
            code: 'stronger_auth_required',
            message: 'Passkey authentication is required before modifying Email OTP enrollment',
            ...(strongAuthGate.lastEmailOtpLoginAtMs
              ? { lastEmailOtpLoginAtMs: strongAuthGate.lastEmailOtpLoginAtMs }
              : {}),
            ...(strongAuthGate.lastStrongAuthAtMs
              ? { lastStrongAuthAtMs: strongAuthGate.lastStrongAuthAtMs }
              : {}),
          });
          return;
        }
      }
      const result = await ctx.service.applyEmailOtpServerSeal({
        wrappedCiphertext,
      });
      res.status(result.ok ? 200 : emailOtpStatusCode(result.code)).json(
        result.ok
          ? {
              ok: true,
              walletId,
              ciphertext: result.ciphertext,
              emailOtpKeyVersion: result.emailOtpKeyVersion,
            }
          : result,
      );
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/wallet/email-otp/registration/finalize', async (req: any, res: any) => {
    try {
      if (!req?.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.registration.finalize',
        });
        res.status(validated.status).json(validated.body);
        return;
      }

      const body = req.body;
      const walletId = String(body.walletId || '').trim();
      if (!walletId) {
        res.status(400).json({ ok: false, code: 'invalid_body', message: 'walletId is required' });
        return;
      }
      if (walletId !== getSessionWalletId(validated.claims, validated.userId)) {
        res.status(403).json({
          ok: false,
          code: 'wallet_identity_mismatch',
          message: 'walletId must match the current app session wallet',
        });
        return;
      }
      const challengeId = String(body.challengeId || '').trim();
      if (!challengeId) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'challengeId is required' });
        return;
      }
      const otpCode = String(body.otpCode || '').trim();
      if (!otpCode) {
        res.status(400).json({ ok: false, code: 'invalid_body', message: 'otpCode is required' });
        return;
      }
      const otpChannel = parseWalletEmailOtpChannel(body.otpChannel);
      if (!otpChannel) {
        res.status(400).json({
          ok: false,
          code: 'invalid_body',
          message: 'otpChannel must be email_otp',
        });
        return;
      }
      if (!isGoogleOidcEmailOtpSession(validated.claims)) {
        const strongAuthGate = await ctx.service.isEmailOtpStrongAuthRequired({ walletId });
        if (!strongAuthGate.ok) {
          res.status(emailOtpStatusCode(strongAuthGate.code)).json(strongAuthGate);
          return;
        }
        if (strongAuthGate.required) {
          res.status(403).json({
            ok: false,
            code: 'stronger_auth_required',
            message: 'Passkey authentication is required before modifying Email OTP enrollment',
            ...(strongAuthGate.lastEmailOtpLoginAtMs
              ? { lastEmailOtpLoginAtMs: strongAuthGate.lastEmailOtpLoginAtMs }
              : {}),
            ...(strongAuthGate.lastStrongAuthAtMs
              ? { lastStrongAuthAtMs: strongAuthGate.lastStrongAuthAtMs }
              : {}),
          });
          return;
        }
      }
      const sessionHash = await hashAppSessionClaims(validated.claims);
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const result = await ctx.service.verifyEmailOtpEnrollment({
        userId: validated.userId,
        walletId,
        orgId: (validated.claims as any).orgId,
        enrollmentDeviceId: (validated.claims as any).deviceId,
        challengeId,
        otpCode,
        otpChannel: otpChannel,
        sessionHash,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
        emailOtpEscrowBlob: body.emailOtpEscrowBlob,
        emailOtpKeyVersion: body.emailOtpKeyVersion,
        unlockPublicKey: body.unlockPublicKey,
        unlockKeyVersion: body.unlockKeyVersion,
        thresholdEcdsaClientVerifyingShareB64u: body.thresholdEcdsaClientVerifyingShareB64u,
      });
      res.status(result.ok ? 200 : emailOtpStatusCode(result.code)).json(
        result.ok
          ? {
              ok: true,
              walletId: result.walletId,
              otpChannel: result.otpChannel,
              enrollment: {
                createdAt: new Date(result.enrollment.createdAtMs).toISOString(),
                updatedAt: new Date(result.enrollment.updatedAtMs).toISOString(),
                emailOtpKeyVersion: result.enrollment.emailOtpKeyVersion,
                unlockKeyVersion: result.enrollment.unlockKeyVersion,
              },
            }
          : result,
      );
      if (result.ok) {
        await emitEmailOtpWebhookEvent({
          eventType: 'wallet.email_otp.enrolled',
          claims: validated.claims,
          userId: validated.userId,
          walletId: result.walletId,
          eventId: challengeId,
          payload: {
            otpChannel: result.otpChannel,
            emailOtpKeyVersion: result.enrollment.emailOtpKeyVersion,
            unlockKeyVersion: result.enrollment.unlockKeyVersion,
          },
        });
      } else {
        await emitEmailOtpFailureWebhookEvents({
          claims: validated.claims,
          userId: validated.userId,
          walletId,
          source: 'registration_finalize',
          code: result.code,
          message: result.message,
          challengeId,
          otpChannel: otpChannel,
          lockedUntilMs:
            typeof (result as { lockedUntilMs?: unknown }).lockedUntilMs === 'number'
              ? Number((result as { lockedUntilMs?: unknown }).lockedUntilMs)
              : undefined,
        });
      }
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/wallet/email-otp/login/challenge', async (req: any, res: any) => {
    try {
      if (!req?.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.login.challenge',
        });
        res.status(validated.status).json(validated.body);
        return;
      }

      const body = req.body;
      const walletId = String(body.walletId || '').trim();
      if (!walletId) {
        res.status(400).json({ ok: false, code: 'invalid_body', message: 'walletId is required' });
        return;
      }
      if (walletId !== getSessionWalletId(validated.claims, validated.userId)) {
        res.status(403).json({
          ok: false,
          code: 'wallet_identity_mismatch',
          message: 'walletId must match the current app session wallet',
        });
        return;
      }
      const otpChannel = parseWalletEmailOtpChannel(body.otpChannel);
      if (!otpChannel) {
        res.status(400).json({
          ok: false,
          code: 'invalid_body',
          message: 'otpChannel must be email_otp',
        });
        return;
      }
      const email =
        typeof validated.claims.email === 'string'
          ? validated.claims.email.trim().toLowerCase()
          : '';
      const parsedOperation = parseWalletEmailOtpLoginOperation(body.operation);
      if (!parsedOperation.ok) {
        res.status(400).json(parsedOperation);
        return;
      }
      const sessionHash = await hashAppSessionClaims(validated.claims);
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const exportPolicy =
        parsedOperation.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
          ? await authorizeEmailOtpExportPolicy(ctx.opts, {
              operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
              phase: 'challenge',
              userId: validated.userId,
              walletId,
              orgId: toOptionalRecordString(validated.claims, 'orgId'),
              projectId: toOptionalRecordString(validated.claims, 'projectId'),
              environmentId: toOptionalRecordString(validated.claims, 'environmentId'),
              appSessionVersion: validated.appSessionVersion,
              sourceIp: clientIp,
            })
          : null;
      if (exportPolicy && !exportPolicy.ok) {
        await emitEmailOtpWebhookEvent({
          eventType: 'wallet.email_otp.export_denied',
          claims: validated.claims,
          userId: validated.userId,
          walletId,
          payload: {
            ...emailOtpExportPolicyAuditPayload({
              source: 'login_challenge',
              decision: exportPolicy,
              otpChannel,
            }),
            code: exportPolicy.code,
            message: exportPolicy.message,
          },
        });
        res.status(403).json({
          ok: false,
          code: exportPolicy.code,
          message: exportPolicy.message,
        });
        return;
      }
      const result = await ctx.service.createEmailOtpChallenge({
        userId: validated.userId,
        walletId,
        orgId: (validated.claims as any).orgId,
        email,
        otpChannel: otpChannel,
        sessionHash,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
        operation: parsedOperation.operation,
      });
      res
        .status(result.ok ? 200 : emailOtpStatusCode(result.code))
        .json(emailOtpChallengeResponseBody(result));
      if (result.ok && exportPolicy) {
        await emitEmailOtpWebhookEvent({
          eventType: 'wallet.email_otp.export_challenge_issued',
          claims: validated.claims,
          userId: validated.userId,
          walletId,
          eventId: result.challenge.challengeId,
          payload: emailOtpExportPolicyAuditPayload({
            source: 'login_challenge',
            decision: exportPolicy,
            challengeId: result.challenge.challengeId,
            otpChannel,
          }),
        });
      }
      if (!result.ok && result.code === 'otp_locked_out') {
        await emitEmailOtpFailureWebhookEvents({
          claims: validated.claims,
          userId: validated.userId,
          walletId,
          source: 'login_challenge',
          code: result.code,
          message: result.message,
          otpChannel: otpChannel,
          operation: parsedOperation.operation,
          lockedUntilMs:
            typeof (result as { lockedUntilMs?: unknown }).lockedUntilMs === 'number'
              ? Number((result as { lockedUntilMs?: unknown }).lockedUntilMs)
              : undefined,
        });
      }
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/wallet/email-otp/login/verify', async (req: any, res: any) => {
    try {
      if (!req?.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.login.verify',
        });
        res.status(validated.status).json(validated.body);
        return;
      }

      const body = req.body;
      const walletId = String(body.walletId || '').trim();
      if (!walletId) {
        res.status(400).json({ ok: false, code: 'invalid_body', message: 'walletId is required' });
        return;
      }
      if (walletId !== getSessionWalletId(validated.claims, validated.userId)) {
        res.status(403).json({
          ok: false,
          code: 'wallet_identity_mismatch',
          message: 'walletId must match the current app session wallet',
        });
        return;
      }
      const challengeId = String(body.challengeId || '').trim();
      if (!challengeId) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'challengeId is required' });
        return;
      }
      const otpCode = String(body.otpCode || '').trim();
      if (!otpCode) {
        res.status(400).json({ ok: false, code: 'invalid_body', message: 'otpCode is required' });
        return;
      }
      const otpChannel = parseWalletEmailOtpChannel(body.otpChannel);
      if (!otpChannel) {
        res.status(400).json({
          ok: false,
          code: 'invalid_body',
          message: 'otpChannel must be email_otp',
        });
        return;
      }
      const parsedOperation = parseWalletEmailOtpLoginOperation(body.operation);
      if (!parsedOperation.ok) {
        res.status(400).json(parsedOperation);
        return;
      }
      const sessionHash = await hashAppSessionClaims(validated.claims);
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const exportPolicy =
        parsedOperation.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
          ? await authorizeEmailOtpExportPolicy(ctx.opts, {
              operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
              phase: 'verify',
              userId: validated.userId,
              walletId,
              orgId: toOptionalRecordString(validated.claims, 'orgId'),
              projectId: toOptionalRecordString(validated.claims, 'projectId'),
              environmentId: toOptionalRecordString(validated.claims, 'environmentId'),
              appSessionVersion: validated.appSessionVersion,
              challengeId,
              sourceIp: clientIp,
            })
          : null;
      if (exportPolicy && !exportPolicy.ok) {
        await emitEmailOtpWebhookEvent({
          eventType: 'wallet.email_otp.export_denied',
          claims: validated.claims,
          userId: validated.userId,
          walletId,
          eventId: challengeId,
          payload: {
            ...emailOtpExportPolicyAuditPayload({
              source: 'login_verify',
              decision: exportPolicy,
              challengeId,
              otpChannel,
            }),
            code: exportPolicy.code,
            message: exportPolicy.message,
          },
        });
        res.status(403).json({
          ok: false,
          code: exportPolicy.code,
          message: exportPolicy.message,
        });
        return;
      }
      const result = await ctx.service.verifyEmailOtpChallenge({
        userId: validated.userId,
        walletId,
        orgId: (validated.claims as any).orgId,
        challengeId,
        otpCode,
        otpChannel: otpChannel,
        sessionHash,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
        operation: parsedOperation.operation,
      });
      if (result.ok) {
        if (exportPolicy) {
          await emitEmailOtpWebhookEvent({
            eventType: 'wallet.email_otp.export_approved',
            claims: validated.claims,
            userId: validated.userId,
            walletId,
            eventId: result.challengeId,
            payload: emailOtpExportPolicyAuditPayload({
              source: 'login_verify',
              decision: exportPolicy,
              challengeId: result.challengeId,
              otpChannel,
            }),
          });
        }
        const enrollment = await ctx.service.readEmailOtpEnrollment({ walletId });
        if (!enrollment.ok) {
          res.status(emailOtpStatusCode(enrollment.code)).json(enrollment);
          return;
        }
        res.status(200).json({
          ok: true,
          challengeId: result.challengeId,
          loginGrant: result.loginGrant,
          grantExpiresAt: new Date(result.grantExpiresAtMs).toISOString(),
          otpChannel: result.otpChannel,
          emailOtpEscrowBlob: enrollment.enrollment.emailOtpEscrowBlob,
        });
      } else {
        res.status(emailOtpStatusCode(result.code)).json(result);
      }
      if (!result.ok) {
        await emitEmailOtpFailureWebhookEvents({
          claims: validated.claims,
          userId: validated.userId,
          walletId,
          source: 'login_verify',
          code: result.code,
          message: result.message,
          challengeId,
          otpChannel: otpChannel,
          operation: parsedOperation.operation,
          lockedUntilMs:
            typeof (result as { lockedUntilMs?: unknown }).lockedUntilMs === 'number'
              ? Number((result as { lockedUntilMs?: unknown }).lockedUntilMs)
              : undefined,
        });
        if (exportPolicy) {
          await emitEmailOtpWebhookEvent({
            eventType: 'wallet.email_otp.export_denied',
            claims: validated.claims,
            userId: validated.userId,
            walletId,
            eventId: challengeId,
            payload: {
              ...emailOtpExportPolicyAuditPayload({
                source: 'login_verify',
                decision: {
                  ok: false,
                  decision: 'DENY',
                  code: result.code,
                  message: result.message,
                  policySource: exportPolicy.policySource,
                  ...(exportPolicy.policyId ? { policyId: exportPolicy.policyId } : {}),
                  ...(exportPolicy.approvalId ? { approvalId: exportPolicy.approvalId } : {}),
                },
                challengeId,
                otpChannel,
              }),
              code: result.code,
              message: result.message,
            },
          });
        }
      }
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/wallet/email-otp/unseal', async (req: any, res: any) => {
    try {
      if (!req?.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.unseal',
        });
        res.status(validated.status).json(validated.body);
        return;
      }

      const body = req.body;
      const loginGrant = String(body.loginGrant || '').trim();
      if (!loginGrant) {
        res.status(400).json({
          ok: false,
          code: 'invalid_body',
          message: 'loginGrant is required',
        });
        return;
      }
      const wrappedCiphertext = String(body.wrappedCiphertext || '').trim();
      if (!wrappedCiphertext) {
        res.status(400).json({
          ok: false,
          code: 'invalid_body',
          message: 'wrappedCiphertext is required',
        });
        return;
      }

      const sessionHash = await hashAppSessionClaims(validated.claims);
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const sessionWalletId = getSessionWalletId(validated.claims, validated.userId);
      const grant = await ctx.service.consumeEmailOtpGrant({
        loginGrant: loginGrant,
        userId: validated.userId,
        walletId: sessionWalletId,
        orgId: (validated.claims as any).orgId,
        otpChannel: EMAIL_OTP_CHANNEL,
        sessionHash,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
      });
      if (!grant.ok) {
        res.status(emailOtpStatusCode(grant.code)).json(grant);
        return;
      }

      const result = await ctx.service.removeEmailOtpServerSeal({
        wrappedCiphertext,
      });
      if (!result.ok) {
        res.status(emailOtpStatusCode(result.code)).json(result);
        return;
      }
      const enrollment = await ctx.service.readEmailOtpEnrollment({ walletId: sessionWalletId });
      const currentDeviceId =
        typeof (validated.claims as any).deviceId === 'string'
          ? String((validated.claims as any).deviceId).trim()
          : '';
      const enrolledDeviceId =
        enrollment.ok && typeof enrollment.enrollment.enrollmentDeviceId === 'string'
          ? String(enrollment.enrollment.enrollmentDeviceId).trim()
          : '';
      if (currentDeviceId && enrolledDeviceId && currentDeviceId !== enrolledDeviceId) {
        await emitEmailOtpWebhookEvent({
          eventType: 'wallet.email_otp.new_device',
          claims: validated.claims,
          userId: validated.userId,
          walletId: sessionWalletId,
          eventId: grant.challengeId,
          payload: {
            otpChannel: grant.otpChannel,
            challengeId: grant.challengeId,
            enrolledDeviceId,
            currentDeviceId,
          },
        });
      }

      res.status(200).json({
        ok: true,
        ciphertext: result.ciphertext,
        emailOtpKeyVersion: result.emailOtpKeyVersion,
      });
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/wallet/email-otp/dev/cleanup-google-registration', async (req: any, res: any) => {
    try {
      const body = req.body || {};
      const verified = await ctx.service.verifyGoogleLogin({
        idToken: (body as any).idToken ?? (body as any).id_token,
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
        res
          .status(status)
          .json({ ok: false, code, message: verified.message || 'Google login failed' });
        return;
      }

      const result = await ctx.service.cleanupGoogleEmailOtpDevRegistrationState({
        providerSubject: verified.providerSubject || verified.userId,
        walletId: (body as any).walletId,
      });
      res.status(result.ok ? 200 : emailOtpStatusCode(result.code)).json(result);
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.get('/wallet/email-otp/dev/otp-outbox', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.dev_outbox',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      const challengeId = String(req?.query?.challengeId || '').trim();
      const sessionWalletId = getSessionWalletId(validated.claims, validated.userId);
      const walletId = String(req?.query?.walletId || sessionWalletId).trim();
      if (walletId !== getSessionWalletId(validated.claims, validated.userId)) {
        res.status(403).json({
          ok: false,
          code: 'wallet_identity_mismatch',
          message: 'walletId must match the current app session wallet',
        });
        return;
      }
      const result = await ctx.service.readEmailOtpOutboxEntry({
        challengeId,
        userId: validated.userId,
        walletId,
      });
      res
        .status(
          result.ok
            ? 200
            : result.code === 'internal'
              ? 500
              : result.code === 'not_found'
                ? 404
                : 400,
        )
        .json(
          result.ok
            ? {
                ok: true,
                challengeId: result.challengeId,
                walletId: result.walletId,
                userId: result.userId,
                otpChannel: result.otpChannel,
                emailHint: result.emailHint,
                otpCode: result.otpCode,
                expiresAt: new Date(result.expiresAtMs).toISOString(),
              }
            : result,
        );
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
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
      res.status(500).json({
        ok: false,
        locked: true,
        code: 'internal',
        message: e?.message || 'Internal error',
      });
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
      res.status(500).json({
        ok: false,
        locked: true,
        code: 'internal',
        message: e?.message || 'Internal error',
      });
    }
  });
}
