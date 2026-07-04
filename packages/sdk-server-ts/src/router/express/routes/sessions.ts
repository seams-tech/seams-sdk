import type { Router as ExpressRouter } from 'express';
import {
  DEFAULT_SESSION_COOKIE_NAME,
  deriveJwtExpiresAtIso,
  parseSessionKind,
} from '../../routerApi';
import { emitRouterApiWebhookEvent } from '../../routerApiWebhooks';
import { resolveSourceIpFromExpressRequest } from '../../routerApiKeyAuth';
import type { ExpressRouterApiContext } from '../createRouterApiRouter';
import { resolveThresholdRuntimePolicyScope } from '../../commonRouterUtils';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  handleWalletUnlockChallengeRoute,
  handleWalletUnlockVerifyRoute,
} from '../../walletUnlockRouteHandlers';
import {
  routerApiEmailOtpRouteService,
  routerApiWalletUnlockRouteService,
} from '../../authServicePort';
import {
  handleEmailOtpDevCleanupGoogleRegistrationRoute,
  handleEmailOtpDevOtpOutboxRoute,
  handleEmailOtpDeviceRecoveryChallengeRoute,
  handleEmailOtpLoginChallengeRoute,
  handleEmailOtpLoginVerifyAndUnsealRoute,
  handleEmailOtpRecoveryKeyAttemptFailedRoute,
  handleEmailOtpRecoveryKeyConsumeRoute,
  handleEmailOtpRecoveryKeyRotateRoute,
  handleEmailOtpRecoveryKeyStatusRoute,
  handleEmailOtpRecoveryWrappedEscrowsRoute,
  handleEmailOtpSigningSessionChallengeRoute,
  handleEmailOtpLoginVerifyRoute,
  handleEmailOtpSigningSessionVerifyRoute,
  handleEmailOtpRegistrationChallengeRoute,
  handleEmailOtpRegistrationFinalizeRoute,
  handleEmailOtpRegistrationSealRoute,
  handleEmailOtpUnsealRoute,
  handleEmailOtpSigningSessionUnsealRoute,
} from '../../emailOtpRouteHandlers';
import {
  emailOtpChallengeResponseBody,
  emailOtpStatusCode,
  emailOtpFailureAuditPayload,
  emailOtpInternalErrorBody,
  emailOtpAppSessionClaimsForSubject,
  hashEmailOtpAppSessionClaims,
} from '../../emailOtpSessionRouteHelpers';
import { parseSessionExchangeRouteCommand } from '../../sessionExchangeRequestValidation';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import {
  parseWalletSigningBudgetStatusExpectations,
  parseWalletSigningBudgetStatusRequest,
  type ParseWalletSigningBudgetStatusResult,
} from '../../signingBudgetStatus';
import { parseGoogleProviderSubject, parseVerifiedGoogleEmail } from '@shared/utils/domainIds';

type VerifiedSigningBudgetStatus = Extract<
  ParseWalletSigningBudgetStatusResult,
  { ok: true }
>['walletBudgetStatus'];

export function registerSessionRoutes(router: ExpressRouter, ctx: ExpressRouterApiContext): void {
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
    await emitRouterApiWebhookEvent({
      logger: ctx.logger,
      webhooks: ctx.opts.routerApiWebhooks,
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
    await emitRouterApiWebhookEvent({
      logger: ctx.logger,
      webhooks: ctx.opts.routerApiWebhooks,
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

  const emitEmailOtpWebhookDescriptor = async (input: {
    descriptor: { eventType: string; eventId?: string; payload: Record<string, unknown> };
    claims?: Record<string, unknown> | null;
    userId: string;
    walletId?: string;
  }): Promise<void> => {
    await emitEmailOtpWebhookEvent({
      eventType: input.descriptor.eventType,
      claims: input.claims,
      userId: input.userId,
      walletId: input.walletId,
      ...(input.descriptor.eventId ? { eventId: input.descriptor.eventId } : {}),
      payload: input.descriptor.payload,
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
    const validated = await ctx.service.sessionVersions.validateAppSessionVersion({
      userId,
      appSessionVersion,
    });
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
    return hashEmailOtpAppSessionClaims(claims);
  };

  const readAndValidateEmailOtpSigningSession = async (
    headers: Record<string, string | string[] | undefined>,
  ): Promise<
    | {
        ok: true;
        claims: Record<string, unknown>;
        userId: string;
        appSessionVersion: string;
        sessionHash: string;
        thresholdSessionId: string;
        signingGrantId: string;
        walletBudgetStatus: VerifiedSigningBudgetStatus;
      }
    | { ok: false; status: number; body: Record<string, unknown> }
  > => {
    const validated = await parseWalletSigningBudgetStatusRequest({
      headers: headers || {},
      session: ctx.opts.session,
      sessionPolicy: ctx.opts.signingSessionSeal?.sessionPolicy,
    });
    if (!validated.ok) {
      return validated;
    }
    const { request } = validated;
    return {
      ok: true,
      claims: validated.claims,
      userId: validated.userId,
      appSessionVersion: validated.appSessionVersion,
      sessionHash: validated.sessionHash,
      thresholdSessionId: request.thresholdSessionId,
      signingGrantId: request.signingGrantId,
      walletBudgetStatus: validated.walletBudgetStatus,
    };
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
    await emitRouterApiWebhookEvent({
      logger: ctx.logger,
      webhooks: ctx.opts.routerApiWebhooks,
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
      const parsedExchange = parseSessionExchangeRouteCommand(req.body);
      if (!parsedExchange.ok) {
        await emitSessionExchangeFailed({
          status: 400,
          code: parsedExchange.body.code,
          message: parsedExchange.body.message,
          exchangeType: parsedExchange.exchangeType,
          sessionKind: parsedExchange.sessionKind,
        });
        res.status(400).json(parsedExchange.body);
        return;
      }
      const command = parsedExchange.command;
      const sessionKind = command.sessionKind;
      const exchangeType = command.kind;

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
      let oidcRestartRegistrationOffer = false;
      let passkeyChallengeId: string | undefined;
      let walletId: string | undefined;
      let googleEmailOtpResolution:
        | {
            mode: 'existing_wallet' | 'register_started';
            registrationAttemptId?: string;
            expiresAtMs?: number;
            offer?: {
              offerId: string;
              selectedCandidateId: string;
              candidates: readonly { candidateId: string; walletId: string }[];
            };
            loginChallenge?:
              | {
                  delivery: 'sent' | 'reused';
                  challengeId: string;
                  emailHint?: string;
                  expiresAtMs: number;
                }
              | {
                  delivery: 'rate_limited';
                  retryAfterMs?: number;
                  resetAtMs?: number;
                };
          }
        | undefined;
      let runtimePolicyScope: RuntimePolicyScope | undefined;
      let appSessionVersion = '';
      let isGoogleEmailOtpExchange = false;

      const resolveRuntimePolicyScopeForExchange = async (
        failureUserId?: string,
      ): Promise<{ ok: true; scope?: RuntimePolicyScope } | { ok: false }> => {
        const runtimePolicyScopeResolution = await resolveThresholdRuntimePolicyScope({
          explicitScopeRaw: undefined,
          projectEnvironmentIdRaw: command.projectEnvironmentId,
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
            userId: failureUserId,
          });
          res.status(runtimePolicyScopeResolution.status).json({
            ok: false,
            code: runtimePolicyScopeResolution.code,
            message: runtimePolicyScopeResolution.message,
          });
          return { ok: false };
        }
        return { ok: true, scope: runtimePolicyScopeResolution.scope };
      };

      const requireRuntimePolicyScopeForOidcWallet = async (): Promise<boolean> => {
        if (!runtimePolicyScope) {
          const resolution = await resolveRuntimePolicyScopeForExchange(userId);
          if (!resolution.ok) return false;
          runtimePolicyScope = resolution.scope;
        }
        if (runtimePolicyScope) return true;
        await emitSessionExchangeFailed({
          status: 400,
          code: 'invalid_body',
          message: 'session/exchange OIDC wallet derivation requires projectEnvironmentId',
          exchangeType,
          sessionKind,
          userId,
        });
        res.status(400).json({
          ok: false,
          code: 'invalid_body',
          message: 'session/exchange OIDC wallet derivation requires projectEnvironmentId',
        });
        return false;
      };

      if (command.kind === 'oidc_jwt') {
        oidcProvider = command.provider;
        oidcAccountMode = command.accountMode;
        oidcRestartRegistrationOffer = command.restartRegistrationOffer;
        isGoogleEmailOtpExchange = oidcProvider === 'google' && Boolean(oidcAccountMode);
        const verified =
          oidcProvider === 'google'
            ? await ctx.service.identity.verifyGoogleLogin({ idToken: command.token })
            : await ctx.service.identity.verifyOidcJwtExchange({
                token: command.token,
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
        if (
          isGoogleEmailOtpExchange &&
          oidcAccountMode === 'register' &&
          (!oidcEmail || (verified as { emailVerified?: boolean }).emailVerified !== true)
        ) {
          await emitSessionExchangeFailed({
            status: 400,
            code: 'invalid_claims',
            message: 'Google id_token must include verified email for Email OTP registration',
            exchangeType,
            sessionKind,
            userId,
          });
          res.status(400).json({
            ok: false,
            code: 'invalid_claims',
            message: 'Google id_token must include verified email for Email OTP registration',
          });
          return;
        }
        if (isGoogleEmailOtpExchange && oidcAccountMode === 'register') {
          const googleProviderSubject = parseGoogleProviderSubject(providerSubject);
          const verifiedGoogleEmail = parseVerifiedGoogleEmail(oidcEmail);
          if (!googleProviderSubject.ok || !verifiedGoogleEmail.ok) {
            let message = 'Invalid Google registration claims';
            if (!googleProviderSubject.ok) {
              message = googleProviderSubject.error.message;
            } else if (!verifiedGoogleEmail.ok) {
              message = verifiedGoogleEmail.error.message;
            }
            await emitSessionExchangeFailed({
              status: 400,
              code: 'invalid_claims',
              message,
              exchangeType,
              sessionKind,
              userId,
            });
            res.status(400).json({ ok: false, code: 'invalid_claims', message });
            return;
          }
          providerSubject = googleProviderSubject.value;
          oidcEmail = verifiedGoogleEmail.value;
        }
        try {
          if (isGoogleEmailOtpExchange) {
            if (!(await requireRuntimePolicyScopeForOidcWallet())) return;
            if (oidcAccountMode === 'register') {
              const appVersion = await ctx.service.sessionVersions.getOrCreateAppSessionVersion({
                userId,
              });
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
              appSessionVersion = appVersion.appSessionVersion;
            }
            if (oidcAccountMode === 'register') {
              const rateLimit =
                await ctx.service.identity.consumeGoogleEmailOtpRegistrationAttemptRateLimit({
                  providerSubject,
                  email: oidcEmail,
                  accountMode: oidcAccountMode,
                  restartRegistrationOffer: oidcRestartRegistrationOffer,
                  runtimePolicyScope,
                  appSessionUserId: userId,
                  clientIp:
                    resolveSourceIpFromExpressRequest({
                      headers: req.headers,
                      ip: req.ip,
                    }) || undefined,
                });
              if (!rateLimit.ok) {
                const status = emailOtpStatusCode(rateLimit.code);
                await emitSessionExchangeFailed({
                  status,
                  code: rateLimit.code,
                  message: rateLimit.message,
                  exchangeType,
                  sessionKind,
                  userId,
                });
                res.status(status).json(rateLimit);
                return;
              }
            }
            const resolution = await ctx.service.identity.resolveGoogleEmailOtpSession({
              providerSubject,
              sub: oidcSub,
              email: oidcEmail,
              accountMode: oidcAccountMode,
              restartRegistrationOffer: oidcRestartRegistrationOffer,
              ...(appSessionVersion ? { appSessionVersion } : {}),
              runtimePolicyScope,
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
                    offer: resolution.offer,
                  }
                : {}),
            };
          } else if (oidcProvider !== 'google') {
            if (!(await requireRuntimePolicyScopeForOidcWallet())) return;
            walletId = await ctx.service.identity.resolveOidcWalletId({
              providerSubject,
              sub: oidcSub,
              email: oidcEmail,
              accountMode: oidcAccountMode,
              runtimePolicyScope,
            });
          }
        } catch (e: any) {
          const code = typeof e?.code === 'string' && e.code ? e.code : 'internal';
          const status =
            code === 'not_found'
              ? 404
              : code === 'invalid_body'
                ? 400
                : code === 'already_linked' || code === 'stale_identity_mapping'
                  ? 409
                  : 500;
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
        if (isGoogleEmailOtpExchange && oidcAccountMode === 'login') {
          const enrollment = await ctx.service.emailOtp.readEmailOtpEnrollment({
            walletId,
            orgId: runtimePolicyScope?.orgId,
          });
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
        const challengeId = command.challengeId;
        const webauthnAuthentication = command.webauthnAuthentication;
        const expectedOrigin = (() => {
          if (command.expectedOrigin) return command.expectedOrigin;
          const originRaw = req.headers?.origin ?? req.headers?.Origin;
          return typeof originRaw === 'string' ? originRaw.trim() || undefined : undefined;
        })();
        const verified = await ctx.service.webAuthn.verifyWebAuthnLogin({
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
        const resolution = await resolveRuntimePolicyScopeForExchange(userId);
        if (!resolution.ok) return;
        runtimePolicyScope = resolution.scope;
      }

      if (!appSessionVersion) {
        const appVersion = await ctx.service.sessionVersions.getOrCreateAppSessionVersion({
          userId,
        });
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
        appSessionVersion = appVersion.appSessionVersion;
      }

      const sessionClaims = {
        kind: 'app_session_v1',
        appSessionVersion,
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
      };
      const jwt = await session.signJwt(userId, sessionClaims);
      const sessionExpiresAt = deriveJwtExpiresAtIso(jwt);
      if (
        isGoogleEmailOtpExchange &&
        oidcAccountMode === 'login' &&
        googleEmailOtpResolution?.mode === 'existing_wallet' &&
        walletId &&
        providerSubject &&
        runtimePolicyScope?.orgId
      ) {
        const challengeResult = await ctx.service.emailOtp.createEmailOtpChallenge({
          userId: providerSubject,
          walletId,
          orgId: runtimePolicyScope.orgId,
          email: oidcEmail,
          otpChannel: EMAIL_OTP_CHANNEL,
          sessionHash: await hashEmailOtpAppSessionClaims(
            emailOtpAppSessionClaimsForSubject({
              userId,
              claims: sessionClaims,
            }),
          ),
          appSessionVersion,
          reuseActiveChallenge: true,
          clientIp:
            resolveSourceIpFromExpressRequest({
              headers: req.headers,
              ip: req.ip,
            }) || undefined,
        });
        if (challengeResult.ok) {
          googleEmailOtpResolution.loginChallenge = {
            delivery: challengeResult.delivery.status,
            challengeId: challengeResult.challenge.challengeId,
            ...(challengeResult.delivery.emailHint
              ? { emailHint: challengeResult.delivery.emailHint }
              : {}),
            expiresAtMs: challengeResult.challenge.expiresAtMs,
          };
        } else if (challengeResult.code === 'rate_limited') {
          googleEmailOtpResolution.loginChallenge = {
            delivery: 'rate_limited',
            ...(typeof (challengeResult as { retryAfterMs?: unknown }).retryAfterMs === 'number'
              ? {
                  retryAfterMs: Number(
                    (challengeResult as { retryAfterMs?: unknown }).retryAfterMs,
                  ),
                }
              : {}),
            ...(typeof (challengeResult as { resetAtMs?: unknown }).resetAtMs === 'number'
              ? { resetAtMs: Number((challengeResult as { resetAtMs?: unknown }).resetAtMs) }
              : {}),
          };
        } else {
          const status = emailOtpStatusCode(challengeResult.code);
          res.status(status).json(emailOtpChallengeResponseBody(challengeResult));
          return;
        }
      }
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
                  ? {
                      expiresAt: new Date(googleEmailOtpResolution.expiresAtMs).toISOString(),
                      expiresAtMs: googleEmailOtpResolution.expiresAtMs,
                    }
                  : {}),
                ...(googleEmailOtpResolution.offer
                  ? { offer: googleEmailOtpResolution.offer }
                  : {}),
                ...(googleEmailOtpResolution.loginChallenge
                  ? {
                      loginChallenge:
                        googleEmailOtpResolution.loginChallenge.delivery === 'sent' ||
                        googleEmailOtpResolution.loginChallenge.delivery === 'reused'
                          ? {
                              delivery: googleEmailOtpResolution.loginChallenge.delivery,
                              challengeId: googleEmailOtpResolution.loginChallenge.challengeId,
                              ...(googleEmailOtpResolution.loginChallenge.emailHint
                                ? { emailHint: googleEmailOtpResolution.loginChallenge.emailHint }
                                : {}),
                              expiresAt: new Date(
                                googleEmailOtpResolution.loginChallenge.expiresAtMs,
                              ).toISOString(),
                              expiresAtMs: googleEmailOtpResolution.loginChallenge.expiresAtMs,
                            }
                          : googleEmailOtpResolution.loginChallenge,
                    }
                  : {}),
              },
            }
          : {}),
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        ...(sessionExpiresAt ? { expiresAt: sessionExpiresAt } : {}),
        ...(oidcEmail ? { email: oidcEmail } : {}),
        ...(oidcName ? { name: oidcName } : {}),
      };
      const responseBody = {
        ok: true,
        session: sessionBody,
      };
      await emitRouterApiWebhookEvent({
        logger: ctx.logger,
        webhooks: ctx.opts.routerApiWebhooks,
        eventType: 'session.warm.created',
        userId,
        payload: {
          kind: 'app_session_v1',
          provider,
          sessionKind,
          appSessionVersion,
        },
      });
      if (provider === 'passkey') {
        await ctx.service.emailOtp.markEmailOtpStrongAuthSatisfied({ walletId: userId });
        await emitRouterApiWebhookEvent({
          logger: ctx.logger,
          webhooks: ctx.opts.routerApiWebhooks,
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
        res.status(200).json(responseBody);
        return;
      }
      res.status(200).json({ ...responseBody, jwt });
    } catch (e: any) {
      await emitSessionExchangeFailed({
        status: 500,
        code: 'internal',
        message: e?.message || 'Internal error',
      });
      res.status(500).json(emailOtpInternalErrorBody(e));
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
      const rotated = await ctx.service.sessionVersions.rotateAppSessionVersion({
        userId: validated.userId,
      });
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
      await emitRouterApiWebhookEvent({
        logger: ctx.logger,
        webhooks: ctx.opts.routerApiWebhooks,
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
          await emitRouterApiWebhookEvent({
            logger: ctx.logger,
            webhooks: ctx.opts.routerApiWebhooks,
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
      await emitRouterApiWebhookEvent({
        logger: ctx.logger,
        webhooks: ctx.opts.routerApiWebhooks,
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

  // Session: authoritative signing grant budget status.
  //
  // This route intentionally authenticates with a Wallet Session JWT and
  // returns only the wallet-level budget projection. Client runtime and
  // IndexedDB remaining-use counters are material hints; this server store is
  // the budget authority.
  router.post('/router-ab/wallet-budget/status', async (req: any, res: any) => {
    try {
      const { signingGrantId: expectedSigningGrantId, thresholdSessionId } =
        parseWalletSigningBudgetStatusExpectations(req.body);
      const expectedThresholdSessionId = thresholdSessionId || '';
      const validated = await readAndValidateEmailOtpSigningSession(req.headers || {});
      if (!validated.ok) {
        if (expectedSigningGrantId && validated.status === 401) {
          res.status(200).json({
            ok: true,
            signingGrantId: expectedSigningGrantId,
            ...(expectedThresholdSessionId
              ? { thresholdSessionId: expectedThresholdSessionId }
              : {}),
            status: 'not_found',
            statusCode: 'unauthorized',
          });
          return;
        }
        res.status(validated.status).json(validated.body);
        return;
      }
      if (expectedSigningGrantId && expectedSigningGrantId !== validated.signingGrantId) {
        res.status(403).json({
          ok: false,
          code: 'wallet_signing_session_mismatch',
          message: 'Signing grant status token does not match requested wallet session',
        });
        return;
      }
      if (
        expectedThresholdSessionId &&
        expectedThresholdSessionId !== validated.thresholdSessionId
      ) {
        res.status(403).json({
          ok: false,
          code: 'threshold_session_mismatch',
          message: 'Signing grant status token does not match requested threshold session',
        });
        return;
      }
      const committedRemainingUses = Math.max(
        0,
        Math.floor(Number(validated.walletBudgetStatus.committedRemainingUses) || 0),
      );
      const reservedUses = Math.max(
        0,
        Math.floor(Number(validated.walletBudgetStatus.reservedUses) || 0),
      );
      const availableUses = Math.max(
        0,
        Math.floor(Number(validated.walletBudgetStatus.availableUses) || 0),
      );
      res.status(200).json({
        ok: true,
        signingGrantId: validated.signingGrantId,
        thresholdSessionId: validated.thresholdSessionId,
        status: availableUses > 0 ? 'active' : 'exhausted',
        committedRemainingUses,
        reservedUses,
        availableUses,
        remainingUses: availableUses,
        expiresAtMs: validated.walletBudgetStatus.expiresAtMs,
        projectionVersion: [
          'wallet-budget',
          validated.signingGrantId,
          validated.walletBudgetStatus.expiresAtMs,
          committedRemainingUses,
          reservedUses,
          availableUses,
        ].join(':'),
      });
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  // Wallet: unlock challenge (backend-neutral route)
  router.post('/wallet/unlock/challenge', async (req: any, res: any) => {
    try {
      const response = await handleWalletUnlockChallengeRoute({
        body: req?.body,
        service: routerApiWalletUnlockRouteService(ctx.service),
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  // Wallet: unlock verify (backend-neutral route)
  router.post('/wallet/unlock/verify', async (req: any, res: any) => {
    try {
      const originRaw = req.headers?.origin ?? req.headers?.Origin;
      const origin = typeof originRaw === 'string' ? originRaw.trim() || undefined : undefined;
      const response = await handleWalletUnlockVerifyRoute({
        body: req?.body,
        origin,
        service: routerApiWalletUnlockRouteService(ctx.service),
        emitRouterApiWebhook: async (event) => {
          await emitRouterApiWebhookEvent({
            logger: ctx.logger,
            webhooks: ctx.opts.routerApiWebhooks,
            eventType: event.eventType,
            userId: event.userId,
            eventId: event.eventId,
            payload: event.payload,
          });
        },
        emitEmailOtpWebhook: async (event) => {
          await emitEmailOtpWebhookDescriptor({
            descriptor: event.descriptor,
            userId: event.userId,
            ...(event.walletId ? { walletId: event.walletId } : {}),
          });
        },
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/wallet/email-otp/registration/challenge', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.registration.challenge',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const response = await handleEmailOtpRegistrationChallengeRoute({
        body: req?.body,
        claims: validated.claims,
        userId: validated.userId,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
        service: routerApiEmailOtpRouteService(ctx.service),
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res.status(500).json(emailOtpInternalErrorBody(e));
    }
  });

  router.post('/wallet/email-otp/registration/seal', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.registration.seal',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      const response = await handleEmailOtpRegistrationSealRoute({
        body: req?.body,
        claims: validated.claims,
        userId: validated.userId,
        service: routerApiEmailOtpRouteService(ctx.service),
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res.status(500).json(emailOtpInternalErrorBody(e));
    }
  });

  router.post('/wallet/email-otp/registration/finalize', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.registration.finalize',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const response = await handleEmailOtpRegistrationFinalizeRoute({
        body: req?.body,
        claims: validated.claims,
        userId: validated.userId,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
        service: routerApiEmailOtpRouteService(ctx.service),
        emitWebhook: async (event) => {
          await emitEmailOtpWebhookDescriptor({
            descriptor: event.descriptor,
            claims: event.claims,
            userId: event.userId,
            ...(event.walletId ? { walletId: event.walletId } : {}),
          });
        },
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res.status(500).json(emailOtpInternalErrorBody(e));
    }
  });

  router.post('/wallet/email-otp/login/challenge', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.login.challenge',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const response = await handleEmailOtpLoginChallengeRoute({
        body: req?.body,
        claims: validated.claims,
        userId: validated.userId,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
        service: routerApiEmailOtpRouteService(ctx.service),
        opts: ctx.opts,
        emitWebhook: async (event) => {
          await emitEmailOtpWebhookDescriptor({
            descriptor: event.descriptor,
            claims: event.claims,
            userId: event.userId,
            ...(event.walletId ? { walletId: event.walletId } : {}),
          });
        },
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res.status(500).json(emailOtpInternalErrorBody(e));
    }
  });

  router.post('/wallet/email-otp/recovery-challenge', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.recovery_challenge',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const response = await handleEmailOtpDeviceRecoveryChallengeRoute({
        body: req?.body,
        claims: validated.claims,
        userId: validated.userId,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
        service: routerApiEmailOtpRouteService(ctx.service),
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res.status(500).json(emailOtpInternalErrorBody(e));
    }
  });

  router.post('/wallet/email-otp/signing-session/challenge', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateEmailOtpSigningSession(req.headers || {});
      if (!validated.ok) {
        res.status(validated.status).json(validated.body);
        return;
      }
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const response = await handleEmailOtpSigningSessionChallengeRoute({
        body: req?.body,
        claims: validated.claims,
        userId: validated.userId,
        appSessionVersion: validated.appSessionVersion,
        sessionHash: validated.sessionHash,
        clientIp,
        service: routerApiEmailOtpRouteService(ctx.service),
        opts: ctx.opts,
        emitWebhook: async (event) => {
          await emitEmailOtpWebhookDescriptor({
            descriptor: event.descriptor,
            claims: event.claims,
            userId: event.userId,
            ...(event.walletId ? { walletId: event.walletId } : {}),
          });
        },
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res.status(500).json(emailOtpInternalErrorBody(e));
    }
  });

  router.post('/wallet/email-otp/login/verify', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.login.verify',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const response = await handleEmailOtpLoginVerifyRoute({
        body: req?.body,
        claims: validated.claims,
        userId: validated.userId,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
        service: routerApiEmailOtpRouteService(ctx.service),
        opts: ctx.opts,
        emitWebhook: async (event) => {
          await emitEmailOtpWebhookDescriptor({
            descriptor: event.descriptor,
            claims: event.claims,
            userId: event.userId,
            ...(event.walletId ? { walletId: event.walletId } : {}),
          });
        },
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res.status(500).json(emailOtpInternalErrorBody(e));
    }
  });

  router.post('/wallet/email-otp/login/verify-and-unseal', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.login.verify_and_unseal',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const response = await handleEmailOtpLoginVerifyAndUnsealRoute({
        body: req?.body,
        claims: validated.claims,
        userId: validated.userId,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
        service: routerApiEmailOtpRouteService(ctx.service),
        opts: ctx.opts,
        emitWebhook: async (event) => {
          await emitEmailOtpWebhookDescriptor({
            descriptor: event.descriptor,
            claims: event.claims,
            userId: event.userId,
            ...(event.walletId ? { walletId: event.walletId } : {}),
          });
        },
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res.status(500).json(emailOtpInternalErrorBody(e));
    }
  });

  router.post('/wallet/email-otp/recovery-wrapped-escrows', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.recovery_wrapped_escrows',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const response = await handleEmailOtpRecoveryWrappedEscrowsRoute({
        body: req?.body,
        claims: validated.claims,
        userId: validated.userId,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
        service: routerApiEmailOtpRouteService(ctx.service),
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res.status(500).json(emailOtpInternalErrorBody(e));
    }
  });

  router.post('/wallet/email-otp/recovery-key/consume', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.recovery_key.consume',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const response = await handleEmailOtpRecoveryKeyConsumeRoute({
        body: req?.body,
        claims: validated.claims,
        userId: validated.userId,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
        service: routerApiEmailOtpRouteService(ctx.service),
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res.status(500).json(emailOtpInternalErrorBody(e));
    }
  });

  router.post('/wallet/email-otp/recovery-key/status', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.recovery_key.status',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const response = await handleEmailOtpRecoveryKeyStatusRoute({
        body: req?.body,
        claims: validated.claims,
        userId: validated.userId,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
        service: routerApiEmailOtpRouteService(ctx.service),
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res.status(500).json(emailOtpInternalErrorBody(e));
    }
  });

  router.post('/wallet/email-otp/recovery-key/rotate', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.recovery_key.rotate',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const response = await handleEmailOtpRecoveryKeyRotateRoute({
        body: req?.body,
        claims: validated.claims,
        userId: validated.userId,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
        service: routerApiEmailOtpRouteService(ctx.service),
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res.status(500).json(emailOtpInternalErrorBody(e));
    }
  });

  router.post('/wallet/email-otp/recovery-key/attempt-failed', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.recovery_key.attempt_failed',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const response = await handleEmailOtpRecoveryKeyAttemptFailedRoute({
        body: req?.body,
        claims: validated.claims,
        userId: validated.userId,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
        service: routerApiEmailOtpRouteService(ctx.service),
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res.status(500).json(emailOtpInternalErrorBody(e));
    }
  });

  router.post('/wallet/email-otp/signing-session/verify', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateEmailOtpSigningSession(req.headers || {});
      if (!validated.ok) {
        res.status(validated.status).json(validated.body);
        return;
      }
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const response = await handleEmailOtpSigningSessionVerifyRoute({
        body: req?.body,
        claims: validated.claims,
        userId: validated.userId,
        appSessionVersion: validated.appSessionVersion,
        sessionHash: validated.sessionHash,
        clientIp,
        service: routerApiEmailOtpRouteService(ctx.service),
        opts: ctx.opts,
        emitWebhook: async (event) => {
          await emitEmailOtpWebhookDescriptor({
            descriptor: event.descriptor,
            claims: event.claims,
            userId: event.userId,
            ...(event.walletId ? { walletId: event.walletId } : {}),
          });
        },
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res.status(500).json(emailOtpInternalErrorBody(e));
    }
  });

  router.post('/wallet/email-otp/unseal', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateAppSession(req.headers || {});
      if (!validated.ok) {
        await maybeEmitWarmExpiredFromValidationFailure({
          validated,
          source: 'wallet.email_otp.unseal',
        });
        res.status(validated.status).json(validated.body);
        return;
      }
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const response = await handleEmailOtpUnsealRoute({
        body: req?.body,
        claims: validated.claims,
        userId: validated.userId,
        appSessionVersion: validated.appSessionVersion,
        clientIp,
        service: routerApiEmailOtpRouteService(ctx.service),
        emitWebhook: async (event) => {
          await emitEmailOtpWebhookDescriptor({
            descriptor: event.descriptor,
            claims: event.claims,
            userId: event.userId,
            ...(event.walletId ? { walletId: event.walletId } : {}),
          });
        },
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res.status(500).json(emailOtpInternalErrorBody(e));
    }
  });

  router.post('/wallet/email-otp/signing-session/unseal', async (req: any, res: any) => {
    try {
      const validated = await readAndValidateEmailOtpSigningSession(req.headers || {});
      if (!validated.ok) {
        res.status(validated.status).json(validated.body);
        return;
      }
      const clientIp =
        resolveSourceIpFromExpressRequest({ headers: req.headers || {}, ip: req.ip }) || undefined;
      const response = await handleEmailOtpSigningSessionUnsealRoute({
        body: req?.body,
        claims: validated.claims,
        userId: validated.userId,
        appSessionVersion: validated.appSessionVersion,
        sessionHash: validated.sessionHash,
        clientIp,
        service: routerApiEmailOtpRouteService(ctx.service),
        emitWebhook: async (event) => {
          await emitEmailOtpWebhookDescriptor({
            descriptor: event.descriptor,
            claims: event.claims,
            userId: event.userId,
            ...(event.walletId ? { walletId: event.walletId } : {}),
          });
        },
      });
      res.status(response.status).json(response.body);
    } catch (e: any) {
      res.status(500).json(emailOtpInternalErrorBody(e));
    }
  });

  router.post('/wallet/email-otp/dev/cleanup-google-registration', async (req: any, res: any) => {
    try {
      const response = await handleEmailOtpDevCleanupGoogleRegistrationRoute({
        body: req.body,
        service: routerApiEmailOtpRouteService(ctx.service),
      });
      res.status(response.status).json(response.body);
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
      const response = await handleEmailOtpDevOtpOutboxRoute({
        challengeId: String(req?.query?.challengeId || ''),
        walletId: String(req?.query?.walletId || ''),
        claims: validated.claims,
        userId: validated.userId,
        service: routerApiEmailOtpRouteService(ctx.service),
      });
      res.status(response.status).json(response.body);
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
      const rotated = await ctx.service.sessionVersions.rotateAppSessionVersion({
        userId: validated.userId,
      });
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
      await emitRouterApiWebhookEvent({
        logger: ctx.logger,
        webhooks: ctx.opts.routerApiWebhooks,
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
