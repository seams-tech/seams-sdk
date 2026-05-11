import { DEFAULT_SESSION_COOKIE_NAME, deriveJwtExpiresAtIso, parseSessionKind } from '../../relay';
import { resolveSourceIpFromFetchHeaders } from '../../relayApiKeyAuth';
import { emitRelayWebhookEvent } from '../../relayWebhooks';
import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { headersToRecord, json, readJson } from '../http';
import { resolveThresholdRuntimePolicyScope } from '../../commonRouterUtils';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  handleWalletUnlockChallengeRoute,
  handleWalletUnlockVerifyRoute,
} from '../../walletUnlockRouteHandlers';
import {
  handleEmailOtpDevCleanupGoogleRegistrationRoute,
  handleEmailOtpDevOtpOutboxRoute,
  handleEmailOtpDeviceRecoveryChallengeRoute,
  handleEmailOtpLoginChallengeRoute,
  handleEmailOtpLoginVerifyAndUnsealRoute,
  handleEmailOtpRecoveryKeyAttemptFailedRoute,
  handleEmailOtpRecoveryKeyConsumeRoute,
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
  emailOtpStatusCode,
  emailOtpFailureAuditPayload,
  hashEmailOtpAppSessionClaims,
  parseOidcAccountMode,
} from '../../emailOtpSessionRouteHelpers';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import {
  parseWalletSigningBudgetStatusExpectations,
  parseWalletSigningBudgetStatusRequest,
} from '../../signingBudgetStatus';

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

async function emitEmailOtpWebhookDescriptor(
  ctx: CloudflareRelayContext,
  input: {
    descriptor: { eventType: string; eventId?: string; payload: Record<string, unknown> };
    claims?: Record<string, unknown> | null;
    userId: string;
    walletId?: string;
  },
): Promise<void> {
  await emitEmailOtpWebhookEvent(ctx, {
    eventType: input.descriptor.eventType,
    claims: input.claims,
    userId: input.userId,
    walletId: input.walletId,
    ...(input.descriptor.eventId ? { eventId: input.descriptor.eventId } : {}),
    payload: input.descriptor.payload,
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

async function readAndValidateEmailOtpSigningSession(ctx: CloudflareRelayContext): Promise<
  | {
      ok: true;
      claims: Record<string, unknown>;
      userId: string;
      appSessionVersion: string;
      sessionHash: string;
      thresholdSessionId: string;
      walletSigningSessionId: string;
      walletBudgetStatus: {
        expiresAtMs: number;
        remainingUses: number;
      };
    }
  | { ok: false; response: Response }
> {
  const validated = await parseWalletSigningBudgetStatusRequest({
    headers: headersToRecord(ctx.request.headers),
    session: ctx.opts.session,
    sessionPolicy: ctx.opts.signingSessionSeal?.sessionPolicy,
  });
  if (!validated.ok) {
    return {
      ok: false,
      response: json(validated.body, { status: validated.status }),
    };
  }
  const { request } = validated;
  return {
    ok: true,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    sessionHash: validated.sessionHash,
    thresholdSessionId: request.thresholdSessionId,
    walletSigningSessionId: request.walletSigningSessionId,
    walletBudgetStatus: validated.walletBudgetStatus,
  };
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
    let isGoogleEmailOtpExchange = false;

    const resolveRuntimePolicyScopeForExchange = async (
      failureUserId?: string,
    ): Promise<{ ok: true; scope?: RuntimePolicyScope } | { ok: false; response: Response }> => {
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
          userId: failureUserId,
        });
        return {
          ok: false,
          response: json(
            {
              ok: false,
              code: runtimePolicyScopeResolution.code,
              message: runtimePolicyScopeResolution.message,
            },
            { status: runtimePolicyScopeResolution.status },
          ),
        };
      }
      return { ok: true, scope: runtimePolicyScopeResolution.scope };
    };

    const requireRuntimePolicyScopeForOidcWallet = async (): Promise<
      { ok: true } | { ok: false; response: Response }
    > => {
      if (!runtimePolicyScope) {
        const resolution = await resolveRuntimePolicyScopeForExchange(userId);
        if (!resolution.ok) return resolution;
        runtimePolicyScope = resolution.scope;
      }
      if (runtimePolicyScope) return { ok: true };
      await emitSessionExchangeFailed(ctx, {
        status: 400,
        code: 'invalid_body',
        message: 'session/exchange OIDC wallet derivation requires runtimeEnvironmentId',
        exchangeType,
        sessionKind,
        userId,
      });
      return {
        ok: false,
        response: json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'session/exchange OIDC wallet derivation requires runtimeEnvironmentId',
          },
          { status: 400 },
        ),
      };
    };

    if (exchangeType === 'oidc_jwt') {
      oidcProvider = String(exchange.provider || '')
        .trim()
        .toLowerCase();
      const oidcAccountModeRaw = exchange.account_mode ?? exchange.accountMode;
      const hasOidcAccountMode =
        Object.prototype.hasOwnProperty.call(exchange, 'account_mode') ||
        Object.prototype.hasOwnProperty.call(exchange, 'accountMode');
      oidcAccountMode = parseOidcAccountMode(oidcAccountModeRaw);
      isGoogleEmailOtpExchange = oidcProvider === 'google' && Boolean(oidcAccountMode);
      if (oidcProvider === 'google' && hasOidcAccountMode && !oidcAccountMode) {
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
      if (isGoogleEmailOtpExchange && oidcAccountMode === 'register' && !oidcEmail) {
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
        if (isGoogleEmailOtpExchange) {
          const scoped = await requireRuntimePolicyScopeForOidcWallet();
          if (!scoped.ok) return scoped.response;
          const resolution = await ctx.service.resolveGoogleEmailOtpSession({
            providerSubject,
            sub: oidcSub,
            email: oidcEmail,
            accountMode: oidcAccountMode,
            rerollRegistrationAttempt: exchange.reroll_registration_attempt,
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
        } else if (oidcProvider !== 'google') {
          const scoped = await requireRuntimePolicyScopeForOidcWallet();
          if (!scoped.ok) return scoped.response;
          walletId = await ctx.service.resolveOidcWalletId({
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
      if (isGoogleEmailOtpExchange && oidcAccountMode === 'login') {
        const enrollment = await ctx.service.readEmailOtpEnrollment({
          walletId,
          orgId: runtimePolicyScope?.orgId,
        });
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
      const resolution = await resolveRuntimePolicyScopeForExchange(userId);
      if (!resolution.ok) return resolution.response;
      runtimePolicyScope = resolution.scope;
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

export async function handleSigningBudgetStatus(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/session/signing-budget/status') return null;
  try {
    const { walletSigningSessionId: expectedWalletSigningSessionId, thresholdSessionId } =
      parseWalletSigningBudgetStatusExpectations(await readJson(ctx.request));
    const expectedThresholdSessionId = thresholdSessionId || '';
    const validated = await readAndValidateEmailOtpSigningSession(ctx);
    if (!validated.ok) {
      if (expectedWalletSigningSessionId && validated.response.status === 401) {
        return json(
          {
            ok: true,
            walletSigningSessionId: expectedWalletSigningSessionId,
            ...(expectedThresholdSessionId
              ? { thresholdSessionId: expectedThresholdSessionId }
              : {}),
            status: 'not_found',
            statusCode: 'unauthorized',
          },
          { status: 200 },
        );
      }
      return validated.response;
    }
    if (
      expectedWalletSigningSessionId &&
      expectedWalletSigningSessionId !== validated.walletSigningSessionId
    ) {
      return json(
        {
          ok: false,
          code: 'wallet_signing_session_mismatch',
          message: 'Wallet signing-session status token does not match requested wallet session',
        },
        { status: 403 },
      );
    }
    const remainingUses = Math.max(
      0,
      Math.floor(Number(validated.walletBudgetStatus.remainingUses) || 0),
    );
    return json(
      {
        ok: true,
        walletSigningSessionId: validated.walletSigningSessionId,
        thresholdSessionId: validated.thresholdSessionId,
        status: remainingUses > 0 ? 'active' : 'exhausted',
        remainingUses,
        expiresAtMs: validated.walletBudgetStatus.expiresAtMs,
        projectionVersion: [
          'wallet-budget',
          validated.walletSigningSessionId,
          validated.walletBudgetStatus.expiresAtMs,
          remainingUses,
        ].join(':'),
      },
      { status: 200 },
    );
  } catch (e: any) {
    return json(
      { ok: false, code: 'internal', message: e?.message || 'Internal error' },
      { status: 500 },
    );
  }
}

export async function handleWalletUnlockChallenge(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/unlock/challenge') return null;
  const body = await readJson(ctx.request);
  const response = await handleWalletUnlockChallengeRoute({
    body,
    service: ctx.service,
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletUnlockVerify(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/unlock/verify') return null;
  const body = await readJson(ctx.request);
  const response = await handleWalletUnlockVerifyRoute({
    body,
    origin: String(ctx.request.headers.get('origin') || '').trim() || undefined,
    service: ctx.service,
    emitRelayWebhook: async (event) => {
      await emitRelayWebhookEvent({
        logger: ctx.logger,
        webhooks: ctx.opts.relayWebhooks,
        eventType: event.eventType,
        userId: event.userId,
        eventId: event.eventId,
        payload: event.payload,
      });
    },
    emitEmailOtpWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpRegistrationChallenge(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/registration/challenge')
    return null;
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.registration.challenge',
    });
    return validated.response;
  }
  const response = await handleEmailOtpRegistrationChallengeRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: ctx.service,
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpRegistrationFinalize(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/registration/finalize')
    return null;
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.registration.finalize',
    });
    return validated.response;
  }
  const response = await handleEmailOtpRegistrationFinalizeRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: ctx.service,
    emitWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        claims: event.claims,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpRegistrationSeal(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/registration/seal') return null;
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.registration.seal',
    });
    return validated.response;
  }
  const response = await handleEmailOtpRegistrationSealRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    service: ctx.service,
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpLoginChallenge(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/login/challenge') return null;
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.login.challenge',
    });
    return validated.response;
  }
  const response = await handleEmailOtpLoginChallengeRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: ctx.service,
    opts: ctx.opts,
    emitWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        claims: event.claims,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpSigningSessionChallenge(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/signing-session/challenge') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateEmailOtpSigningSession(ctx);
  if (!validated.ok) return validated.response;
  const response = await handleEmailOtpSigningSessionChallengeRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    sessionHash: validated.sessionHash,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: ctx.service,
    opts: ctx.opts,
    emitWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        claims: event.claims,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpDeviceRecoveryChallenge(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/recovery-challenge') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.recovery_challenge',
    });
    return validated.response;
  }
  const response = await handleEmailOtpDeviceRecoveryChallengeRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: ctx.service,
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpLoginVerify(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/login/verify') return null;
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.login.verify',
    });
    return validated.response;
  }
  const response = await handleEmailOtpLoginVerifyRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: ctx.service,
    opts: ctx.opts,
    emitWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        claims: event.claims,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpLoginVerifyAndUnseal(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/login/verify-and-unseal') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.login.verify_and_unseal',
    });
    return validated.response;
  }
  const response = await handleEmailOtpLoginVerifyAndUnsealRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: ctx.service,
    opts: ctx.opts,
    emitWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        claims: event.claims,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpSigningSessionVerify(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/signing-session/verify') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateEmailOtpSigningSession(ctx);
  if (!validated.ok) return validated.response;
  const response = await handleEmailOtpSigningSessionVerifyRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    sessionHash: validated.sessionHash,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: ctx.service,
    opts: ctx.opts,
    emitWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        claims: event.claims,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpRecoveryWrappedEscrows(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/recovery-wrapped-escrows') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.recovery_wrapped_escrows',
    });
    return validated.response;
  }
  const response = await handleEmailOtpRecoveryWrappedEscrowsRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: ctx.service,
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpRecoveryKeyConsume(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/recovery-key/consume') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.recovery_key.consume',
    });
    return validated.response;
  }
  const response = await handleEmailOtpRecoveryKeyConsumeRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: ctx.service,
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpRecoveryKeyAttemptFailed(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/recovery-key/attempt-failed') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.recovery_key.attempt_failed',
    });
    return validated.response;
  }
  const response = await handleEmailOtpRecoveryKeyAttemptFailedRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: ctx.service,
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpUnseal(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/unseal') return null;
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.unseal',
    });
    return validated.response;
  }
  const response = await handleEmailOtpUnsealRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: ctx.service,
    emitWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        claims: event.claims,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpSigningSessionUnseal(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/signing-session/unseal') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateEmailOtpSigningSession(ctx);
  if (!validated.ok) return validated.response;
  const response = await handleEmailOtpSigningSessionUnsealRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    sessionHash: validated.sessionHash,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: ctx.service,
    emitWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        claims: event.claims,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
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
  const response = await handleEmailOtpDevCleanupGoogleRegistrationRoute({
    body,
    service: ctx.service,
  });
  return json(response.body, { status: response.status });
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

  const response = await handleEmailOtpDevOtpOutboxRoute({
    challengeId: String(ctx.url.searchParams.get('challengeId') || ''),
    walletId: String(ctx.url.searchParams.get('walletId') || ''),
    claims: validated.claims,
    userId: validated.userId,
    service: ctx.service,
  });
  return json(response.body, { status: response.status });
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
