import { toOptionalRecordString } from '@shared/utils/validation';
import { DEFAULT_SESSION_COOKIE_NAME, deriveJwtExpiresAtIso, parseSessionKind } from '../../relay';
import { resolveSourceIpFromFetchHeaders } from '../../relayApiKeyAuth';
import { emitRelayWebhookEvent } from '../../relayWebhooks';
import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { headersToRecord, json, readJson } from '../http';
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
  hashEmailOtpAppSessionClaims,
  isGoogleOidcEmailOtpSession,
  parseOidcAccountMode,
} from '../../emailOtpSessionRouteHelpers';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
} from '@shared/utils/emailOtpDomain';

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

async function emitEmailOtpWebhookEvent(
  ctx: CloudflareRelayContext,
  input: {
    eventType: string;
    claims?: Record<string, unknown> | null;
    userId: string;
    walletId?: string;
    eventId?: string;
    payload?: Record<string, unknown>;
  },
): Promise<void> {
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
}

async function emitEmailOtpFailureWebhookEvents(
  ctx: CloudflareRelayContext,
  input: {
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
  },
): Promise<void> {
  const payload = {
    source: input.source,
    code: input.code,
    message: input.message,
    ...(input.challengeId ? { challengeId: input.challengeId } : {}),
    ...(input.otpChannel ? { otpChannel: input.otpChannel } : {}),
    ...(input.operation ? { operation: input.operation } : {}),
    ...(typeof input.lockedUntilMs === 'number' ? { lockedUntilMs: input.lockedUntilMs } : {}),
  };
  await emitEmailOtpWebhookEvent(ctx, {
    eventType: 'wallet.email_otp.failed',
    claims: input.claims,
    userId: input.userId,
    walletId: input.walletId,
    ...(input.challengeId ? { eventId: input.challengeId } : {}),
    payload,
  });
  if (input.code !== 'otp_locked_out' && input.code !== 'otp_attempts_exhausted') return;
  await emitEmailOtpWebhookEvent(ctx, {
    eventType: 'wallet.email_otp.locked',
    claims: input.claims,
    userId: input.userId,
    walletId: input.walletId,
    ...(input.challengeId ? { eventId: input.challengeId } : {}),
    payload,
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

async function readAndValidateAppSession(ctx: CloudflareRelayContext): Promise<
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

async function hashAppSessionClaims(claims: Record<string, unknown>): Promise<string> {
  return hashEmailOtpAppSessionClaims(claims);
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
      oidcProvider = String(exchange.provider || '')
        .trim()
        .toLowerCase();
      oidcAccountMode = parseOidcAccountMode(exchange.account_mode);
      if (oidcProvider === 'google' && !oidcAccountMode) {
        await emitSessionExchangeFailed(ctx, {
          status: 400,
          code: 'invalid_body',
          message: 'exchange.account_mode must be register or login for Google Email OTP',
          exchangeType,
          sessionKind,
        });
        return json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'exchange.account_mode must be register or login for Google Email OTP',
          },
          { status: 400 },
        );
      }
      const verified =
        oidcProvider === 'google'
          ? await ctx.service.verifyGoogleLogin({ idToken: exchange.token })
          : await ctx.service.verifyOidcJwtExchange({ token: exchange.token });
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
        await emitSessionExchangeFailed(ctx, {
          status: 400,
          code: 'invalid_claims',
          message: 'Google id_token must include email for Email OTP registration',
          exchangeType,
          sessionKind,
          userId,
        });
        return json(
          {
            ok: false,
            code: 'invalid_claims',
            message: 'Google id_token must include email for Email OTP registration',
          },
          { status: 400 },
        );
      }
      try {
        if (oidcProvider === 'google') {
          const runtimePolicyScopeResolution = await resolveThresholdRuntimePolicyScope({
            explicitScopeRaw: undefined,
            runtimeEnvironmentIdRaw: (parsedBody as { runtimeEnvironmentId?: unknown })
              .runtimeEnvironmentId,
            headers: ctx.request.headers,
            origin: ctx.request.headers.get('origin'),
            publishableKeyAuth: ctx.opts.publishableKeyAuth || null,
            orgProjectEnv: ctx.opts.orgProjectEnv || null,
          });
          if (!runtimePolicyScopeResolution.ok) {
            await emitSessionExchangeFailed(ctx, {
              status: runtimePolicyScopeResolution.status,
              code: runtimePolicyScopeResolution.code,
              message: runtimePolicyScopeResolution.message,
              exchangeType,
              sessionKind,
              userId,
            });
            return json(
              {
                ok: false,
                code: runtimePolicyScopeResolution.code,
                message: runtimePolicyScopeResolution.message,
              },
              { status: runtimePolicyScopeResolution.status },
            );
          }
          runtimePolicyScope = runtimePolicyScopeResolution.scope;
          const resolution = await ctx.service.resolveGoogleEmailOtpSession({
            providerSubject,
            sub: oidcSub,
            email: oidcEmail,
            accountMode: oidcAccountMode,
            runtimePolicyScope,
          });
          if (!resolution.ok) {
            const status = resolution.code === 'wallet_id_collision' ? 409 : 409;
            await emitSessionExchangeFailed(ctx, {
              status,
              code: resolution.code,
              message: resolution.message,
              exchangeType,
              sessionKind,
              userId,
            });
            return json(resolution, { status });
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
        await emitSessionExchangeFailed(ctx, {
          status,
          code,
          message,
          exchangeType,
          sessionKind,
          userId,
        });
        return json({ ok: false, code, message }, { status });
      }
      if (oidcProvider === 'google' && oidcAccountMode === 'login') {
        const enrollment = await ctx.service.readEmailOtpEnrollment({ walletId });
        if (!enrollment.ok) {
          const status = emailOtpStatusCode(enrollment.code);
          await emitSessionExchangeFailed(ctx, {
            status,
            code: enrollment.code,
            message: enrollment.message,
            exchangeType,
            sessionKind,
            userId,
          });
          return json(enrollment, { status });
        }
      }
    } else {
      const challengeId = String(exchange.challengeId ?? exchange.challenge_id ?? '').trim();
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

    if (!runtimePolicyScope) {
      const runtimePolicyScopeResolution = await resolveThresholdRuntimePolicyScope({
        explicitScopeRaw: undefined,
        runtimeEnvironmentIdRaw: (parsedBody as { runtimeEnvironmentId?: unknown })
          .runtimeEnvironmentId,
        headers: ctx.request.headers,
        origin: ctx.request.headers.get('origin'),
        publishableKeyAuth: ctx.opts.publishableKeyAuth || null,
        orgProjectEnv: ctx.opts.orgProjectEnv || null,
      });
      if (!runtimePolicyScopeResolution.ok) {
        await emitSessionExchangeFailed(ctx, {
          status: runtimePolicyScopeResolution.status,
          code: runtimePolicyScopeResolution.code,
          message: runtimePolicyScopeResolution.message,
          exchangeType,
          sessionKind,
          userId,
        });
        return json(
          {
            ok: false,
            code: runtimePolicyScopeResolution.code,
            message: runtimePolicyScopeResolution.message,
          },
          { status: runtimePolicyScopeResolution.status },
        );
      }
      runtimePolicyScope = runtimePolicyScopeResolution.scope;
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
    const responseBody = {
      ok: true,
      session: {
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
    const payload = await validated.response
      .clone()
      .json()
      .catch(() => ({}));
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

export async function handleWalletUnlockChallenge(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/unlock/challenge') return null;
  const body = await readJson(ctx.request);
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
      { status: 400 },
    );
  }
  const unlockBackend = parseWalletUnlockBackend((body as any).unlockBackend);
  if (!unlockBackend) {
    return json(
      { ok: false, code: 'invalid_body', message: 'unlockBackend is required' },
      { status: 400 },
    );
  }
  const result =
    unlockBackend === 'passkey'
      ? await ctx.service.createWebAuthnLoginOptions({
          userId: (body as any).userId,
          rpId: (body as any).rpId,
          ttlMs: (body as any).ttlMs,
        })
      : await ctx.service.createEmailOtpUnlockChallenge({
          walletId: (body as any).walletId,
          ttlMs: (body as any).ttlMs,
        });
  return json(
    {
      ...result,
      unlockBackend,
    },
    { status: result.ok ? 200 : result.code === 'internal' ? 500 : 400 },
  );
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

  const unlockBackend = parseWalletUnlockBackend((body as any).unlockBackend);
  if (!unlockBackend) {
    return json(
      { ok: false, code: 'invalid_body', message: 'unlockBackend is required' },
      { status: 400 },
    );
  }
  const challengeId = String((body as any).challengeId || '').trim();
  if (!challengeId) {
    return json(
      { ok: false, code: 'invalid_body', message: 'challengeId is required' },
      { status: 400 },
    );
  }
  const result =
    unlockBackend === 'passkey'
      ? await (async () => {
          const webauthnAuthentication = (body as any).webauthnAuthentication;
          if (!webauthnAuthentication || typeof webauthnAuthentication !== 'object') {
            return {
              ok: false,
              verified: false,
              code: 'invalid_body',
              message: 'webauthnAuthentication is required',
            } as const;
          }
          const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;
          return ctx.service.verifyWebAuthnLogin({
            challengeId,
            webauthn_authentication: webauthnAuthentication,
            expected_origin: origin,
          });
        })()
      : await ctx.service.verifyEmailOtpUnlockProof({
          walletId: (body as any).walletId,
          challengeId,
          unlockProof: (body as any).unlockProof,
        });
  if (!result.ok || !result.verified) {
    if (unlockBackend === EMAIL_OTP_CHANNEL) {
      const walletId = String((body as any).walletId || '').trim();
      if (walletId) {
        await emitEmailOtpFailureWebhookEvents(ctx, {
          userId: walletId,
          walletId,
          source: 'unlock_verify',
          code: String(result.code || 'unlock_verify_failed'),
          message: String(result.message || 'Email OTP unlock verification failed'),
          challengeId,
        });
      }
    }
    return json({ ...result, unlockBackend }, { status: result.code === 'internal' ? 500 : 400 });
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
      (result as { walletId?: unknown }).walletId || (body as any).walletId || '',
    ).trim();
    const recoveredUserId = String(result.userId || recoveredWalletId).trim();
    await emitEmailOtpWebhookEvent(ctx, {
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
  return json(
    {
      ok: true,
      unlocked: true,
      unlockBackend,
      ...(result.userId ? { userId: result.userId } : {}),
    },
    { status: 200 },
  );
}

export async function handleWalletEmailOtpRegistrationChallenge(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/registration/challenge')
    return null;
  const body = await readJson(ctx.request);
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
      { status: 400 },
    );
  }
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.registration.challenge',
    });
    return validated.response;
  }

  const walletId = String((body as any).walletId || '').trim();
  if (!walletId) {
    return json(
      { ok: false, code: 'invalid_body', message: 'walletId is required' },
      { status: 400 },
    );
  }
  if (walletId !== getSessionWalletId(validated.claims, validated.userId)) {
    return json(
      {
        ok: false,
        code: 'wallet_identity_mismatch',
        message: 'walletId must match the current app session wallet',
      },
      { status: 403 },
    );
  }
  const otpChannel = parseWalletEmailOtpChannel((body as any).otpChannel);
  if (!otpChannel) {
    return json(
      { ok: false, code: 'invalid_body', message: 'otpChannel must be email_otp' },
      { status: 400 },
    );
  }
  if (!isGoogleOidcEmailOtpSession(validated.claims)) {
    const strongAuthGate = await ctx.service.isEmailOtpStrongAuthRequired({ walletId });
    if (!strongAuthGate.ok) {
      return json(strongAuthGate, { status: emailOtpStatusCode(strongAuthGate.code) });
    }
    if (strongAuthGate.required) {
      return json(
        {
          ok: false,
          code: 'stronger_auth_required',
          message: 'Passkey authentication is required before modifying Email OTP enrollment',
          ...(strongAuthGate.lastEmailOtpLoginAtMs
            ? { lastEmailOtpLoginAtMs: strongAuthGate.lastEmailOtpLoginAtMs }
            : {}),
          ...(strongAuthGate.lastStrongAuthAtMs
            ? { lastStrongAuthAtMs: strongAuthGate.lastStrongAuthAtMs }
            : {}),
        },
        { status: 403 },
      );
    }
  }
  const email =
    typeof (validated.claims as any).email === 'string'
      ? String((validated.claims as any).email)
          .trim()
          .toLowerCase()
      : '';
  const sessionHash = await hashAppSessionClaims(validated.claims);
  const clientIp = resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined;
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
  return json(emailOtpChallengeResponseBody(result), {
    status: result.ok ? 200 : emailOtpStatusCode(result.code),
  });
}

export async function handleWalletEmailOtpRegistrationFinalize(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/registration/finalize')
    return null;
  const body = await readJson(ctx.request);
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
      { status: 400 },
    );
  }
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.registration.finalize',
    });
    return validated.response;
  }

  const walletId = String((body as any).walletId || '').trim();
  if (!walletId) {
    return json(
      { ok: false, code: 'invalid_body', message: 'walletId is required' },
      { status: 400 },
    );
  }
  if (walletId !== getSessionWalletId(validated.claims, validated.userId)) {
    return json(
      {
        ok: false,
        code: 'wallet_identity_mismatch',
        message: 'walletId must match the current app session wallet',
      },
      { status: 403 },
    );
  }
  const challengeId = String((body as any).challengeId || '').trim();
  if (!challengeId) {
    return json(
      { ok: false, code: 'invalid_body', message: 'challengeId is required' },
      { status: 400 },
    );
  }
  const otpCode = String((body as any).otpCode || '').trim();
  if (!otpCode) {
    return json(
      { ok: false, code: 'invalid_body', message: 'otpCode is required' },
      { status: 400 },
    );
  }
  const otpChannel = parseWalletEmailOtpChannel((body as any).otpChannel);
  if (!otpChannel) {
    return json(
      { ok: false, code: 'invalid_body', message: 'otpChannel must be email_otp' },
      { status: 400 },
    );
  }
  if (!isGoogleOidcEmailOtpSession(validated.claims)) {
    const strongAuthGate = await ctx.service.isEmailOtpStrongAuthRequired({ walletId });
    if (!strongAuthGate.ok) {
      return json(strongAuthGate, { status: emailOtpStatusCode(strongAuthGate.code) });
    }
    if (strongAuthGate.required) {
      return json(
        {
          ok: false,
          code: 'stronger_auth_required',
          message: 'Passkey authentication is required before modifying Email OTP enrollment',
          ...(strongAuthGate.lastEmailOtpLoginAtMs
            ? { lastEmailOtpLoginAtMs: strongAuthGate.lastEmailOtpLoginAtMs }
            : {}),
          ...(strongAuthGate.lastStrongAuthAtMs
            ? { lastStrongAuthAtMs: strongAuthGate.lastStrongAuthAtMs }
            : {}),
        },
        { status: 403 },
      );
    }
  }
  const sessionHash = await hashAppSessionClaims(validated.claims);
  const clientIp = resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined;
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
    emailOtpEscrowBlob: (body as any).emailOtpEscrowBlob,
    emailOtpKeyVersion: (body as any).emailOtpKeyVersion,
    unlockPublicKey: (body as any).unlockPublicKey,
    unlockKeyVersion: (body as any).unlockKeyVersion,
    thresholdEcdsaClientVerifyingShareB64u: (body as any).thresholdEcdsaClientVerifyingShareB64u,
  });
  if (result.ok) {
    await emitEmailOtpWebhookEvent(ctx, {
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
    await emitEmailOtpFailureWebhookEvents(ctx, {
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
  return json(
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
    { status: result.ok ? 200 : emailOtpStatusCode(result.code) },
  );
}

export async function handleWalletEmailOtpRegistrationSeal(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/registration/seal') return null;
  const body = await readJson(ctx.request);
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
      { status: 400 },
    );
  }
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.registration.seal',
    });
    return validated.response;
  }

  const walletId = String((body as any).walletId || '').trim();
  if (!walletId) {
    return json(
      { ok: false, code: 'invalid_body', message: 'walletId is required' },
      { status: 400 },
    );
  }
  if (walletId !== getSessionWalletId(validated.claims, validated.userId)) {
    return json(
      {
        ok: false,
        code: 'wallet_identity_mismatch',
        message: 'walletId must match the current app session wallet',
      },
      { status: 403 },
    );
  }
  const wrappedCiphertext = String((body as any).wrappedCiphertext || '').trim();
  if (!wrappedCiphertext) {
    return json(
      { ok: false, code: 'invalid_body', message: 'wrappedCiphertext is required' },
      { status: 400 },
    );
  }
  if (!isGoogleOidcEmailOtpSession(validated.claims)) {
    const strongAuthGate = await ctx.service.isEmailOtpStrongAuthRequired({ walletId });
    if (!strongAuthGate.ok) {
      return json(strongAuthGate, { status: emailOtpStatusCode(strongAuthGate.code) });
    }
    if (strongAuthGate.required) {
      return json(
        {
          ok: false,
          code: 'stronger_auth_required',
          message: 'Passkey authentication is required before modifying Email OTP enrollment',
          ...(strongAuthGate.lastEmailOtpLoginAtMs
            ? { lastEmailOtpLoginAtMs: strongAuthGate.lastEmailOtpLoginAtMs }
            : {}),
          ...(strongAuthGate.lastStrongAuthAtMs
            ? { lastStrongAuthAtMs: strongAuthGate.lastStrongAuthAtMs }
            : {}),
        },
        { status: 403 },
      );
    }
  }
  const result = await ctx.service.applyEmailOtpServerSeal({
    wrappedCiphertext,
  });
  return json(
    result.ok
      ? {
          ok: true,
          walletId,
          ciphertext: result.ciphertext,
          emailOtpKeyVersion: result.emailOtpKeyVersion,
        }
      : result,
    { status: result.ok ? 200 : emailOtpStatusCode(result.code) },
  );
}

export async function handleWalletEmailOtpLoginChallenge(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/login/challenge') return null;
  const body = await readJson(ctx.request);
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
      { status: 400 },
    );
  }
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.login.challenge',
    });
    return validated.response;
  }

  const walletId = String((body as any).walletId || '').trim();
  if (!walletId) {
    return json(
      { ok: false, code: 'invalid_body', message: 'walletId is required' },
      { status: 400 },
    );
  }
  if (walletId !== getSessionWalletId(validated.claims, validated.userId)) {
    return json(
      {
        ok: false,
        code: 'wallet_identity_mismatch',
        message: 'walletId must match the current app session wallet',
      },
      { status: 403 },
    );
  }
  const otpChannel = parseWalletEmailOtpChannel((body as any).otpChannel);
  if (!otpChannel) {
    return json(
      { ok: false, code: 'invalid_body', message: 'otpChannel must be email_otp' },
      { status: 400 },
    );
  }
  const email =
    typeof (validated.claims as any).email === 'string'
      ? String((validated.claims as any).email)
          .trim()
          .toLowerCase()
      : '';
  const parsedOperation = parseWalletEmailOtpLoginOperation((body as any).operation);
  if (!parsedOperation.ok) return json(parsedOperation, { status: 400 });
  const sessionHash = await hashAppSessionClaims(validated.claims);
  const clientIp = resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined;
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
    await emitEmailOtpWebhookEvent(ctx, {
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
    return json(
      {
        ok: false,
        code: exportPolicy.code,
        message: exportPolicy.message,
      },
      { status: 403 },
    );
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
  if (!result.ok && result.code === 'otp_locked_out') {
    await emitEmailOtpFailureWebhookEvents(ctx, {
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
  if (result.ok && exportPolicy) {
    await emitEmailOtpWebhookEvent(ctx, {
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
  return json(emailOtpChallengeResponseBody(result), {
    status: result.ok ? 200 : emailOtpStatusCode(result.code),
  });
}

export async function handleWalletEmailOtpLoginVerify(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/login/verify') return null;
  const body = await readJson(ctx.request);
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
      { status: 400 },
    );
  }
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.login.verify',
    });
    return validated.response;
  }

  const walletId = String((body as any).walletId || '').trim();
  if (!walletId) {
    return json(
      { ok: false, code: 'invalid_body', message: 'walletId is required' },
      { status: 400 },
    );
  }
  if (walletId !== getSessionWalletId(validated.claims, validated.userId)) {
    return json(
      {
        ok: false,
        code: 'wallet_identity_mismatch',
        message: 'walletId must match the current app session wallet',
      },
      { status: 403 },
    );
  }
  const challengeId = String((body as any).challengeId || '').trim();
  if (!challengeId) {
    return json(
      { ok: false, code: 'invalid_body', message: 'challengeId is required' },
      { status: 400 },
    );
  }
  const otpCode = String((body as any).otpCode || '').trim();
  if (!otpCode) {
    return json(
      { ok: false, code: 'invalid_body', message: 'otpCode is required' },
      { status: 400 },
    );
  }
  const otpChannel = parseWalletEmailOtpChannel((body as any).otpChannel);
  if (!otpChannel) {
    return json(
      { ok: false, code: 'invalid_body', message: 'otpChannel must be email_otp' },
      { status: 400 },
    );
  }
  const parsedOperation = parseWalletEmailOtpLoginOperation((body as any).operation);
  if (!parsedOperation.ok) return json(parsedOperation, { status: 400 });
  const sessionHash = await hashAppSessionClaims(validated.claims);
  const clientIp = resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined;
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
    await emitEmailOtpWebhookEvent(ctx, {
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
    return json(
      {
        ok: false,
        code: exportPolicy.code,
        message: exportPolicy.message,
      },
      { status: 403 },
    );
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
      await emitEmailOtpWebhookEvent(ctx, {
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
      return json(enrollment, { status: emailOtpStatusCode(enrollment.code) });
    }
    return json(
      {
        ok: true,
        challengeId: result.challengeId,
        loginGrant: result.loginGrant,
        grantExpiresAt: new Date(result.grantExpiresAtMs).toISOString(),
        otpChannel: result.otpChannel,
        emailOtpEscrowBlob: enrollment.enrollment.emailOtpEscrowBlob,
      },
      { status: 200 },
    );
  }
  if (!result.ok) {
    await emitEmailOtpFailureWebhookEvents(ctx, {
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
      await emitEmailOtpWebhookEvent(ctx, {
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
  return json(result, { status: emailOtpStatusCode(result.code) });
}

export async function handleWalletEmailOtpUnseal(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/unseal') return null;
  const body = await readJson(ctx.request);
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
      { status: 400 },
    );
  }
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.unseal',
    });
    return validated.response;
  }

  const loginGrant = String((body as any).loginGrant || '').trim();
  if (!loginGrant) {
    return json(
      { ok: false, code: 'invalid_body', message: 'loginGrant is required' },
      { status: 400 },
    );
  }
  const wrappedCiphertext = String((body as any).wrappedCiphertext || '').trim();
  if (!wrappedCiphertext) {
    return json(
      { ok: false, code: 'invalid_body', message: 'wrappedCiphertext is required' },
      { status: 400 },
    );
  }

  const sessionHash = await hashAppSessionClaims(validated.claims);
  const clientIp = resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined;
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
    return json(grant, { status: emailOtpStatusCode(grant.code) });
  }

  const result = await ctx.service.removeEmailOtpServerSeal({
    wrappedCiphertext,
  });
  if (result.ok) {
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
      await emitEmailOtpWebhookEvent(ctx, {
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
  }
  return json(
    result.ok
      ? {
          ok: true,
          ciphertext: result.ciphertext,
          emailOtpKeyVersion: result.emailOtpKeyVersion,
        }
      : result,
    {
      status: result.ok ? 200 : emailOtpStatusCode(result.code),
    },
  );
}

export async function handleWalletEmailOtpDevCleanupGoogleRegistration(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (
    ctx.method !== 'POST' ||
    ctx.pathname !== '/wallet/email-otp/dev/cleanup-google-registration'
  ) {
    return null;
  }

  const body = await readJson(ctx.request);
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
    return json(
      { ok: false, code, message: verified.message || 'Google login failed' },
      { status },
    );
  }

  const result = await ctx.service.cleanupGoogleEmailOtpDevRegistrationState({
    providerSubject: verified.providerSubject || verified.userId,
    walletId: (body as any).walletId,
  });
  return json(result, { status: result.ok ? 200 : emailOtpStatusCode(result.code) });
}

export async function handleWalletEmailOtpDevOtpOutbox(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'GET' || ctx.pathname !== '/wallet/email-otp/dev/otp-outbox') return null;
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.dev_outbox',
    });
    return validated.response;
  }

  const challengeId = String(ctx.url.searchParams.get('challengeId') || '').trim();
  const sessionWalletId = getSessionWalletId(validated.claims, validated.userId);
  const walletId = String(ctx.url.searchParams.get('walletId') || sessionWalletId).trim();
  if (walletId !== getSessionWalletId(validated.claims, validated.userId)) {
    return json(
      {
        ok: false,
        code: 'wallet_identity_mismatch',
        message: 'walletId must match the current app session wallet',
      },
      { status: 403 },
    );
  }
  const result = await ctx.service.readEmailOtpOutboxEntry({
    challengeId,
    userId: validated.userId,
    walletId,
  });
  return json(
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
    {
      status: result.ok
        ? 200
        : result.code === 'internal'
          ? 500
          : result.code === 'not_found'
            ? 404
            : 400,
    },
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
    const payload = await validated.response
      .clone()
      .json()
      .catch(() => ({}));
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
    const payload = await validated.response
      .clone()
      .json()
      .catch(() => ({}));
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
