import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import { thresholdEd25519StatusCode } from '../../../threshold/statusCodes';
import type {
  ThresholdEd25519AuthorizeResponse,
  ThresholdEd25519CosignFinalizeRequest,
  ThresholdEd25519CosignInitRequest,
  ThresholdEd25519HssFinalizeWithSessionRequest,
  ThresholdEd25519HssPrepareWithSessionRequest,
  ThresholdEd25519SignFinalizeRequest,
  ThresholdEd25519SignInitRequest,
  ThresholdEd25519SessionRequest,
} from '../../../core/types';
import { parseSessionKind, resolveThresholdScheme } from '../../relay';
import {
  resolveThresholdRuntimePolicyScope,
  validateThresholdEd25519AuthorizeInputs,
  validateThresholdEd25519SessionTokenInputs,
} from '../../commonRouterUtils';
import { validateRuntimeSnapshotExpectation } from '../../runtimeSnapshotConsumer';
import {
  normalizeThresholdEd25519ParticipantIds,
  THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
} from '@shared/threshold/participants';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '../../../core/ThresholdService/schemes/schemeIds';
import {
  parseAppSessionClaims,
  parseThresholdEcdsaSessionClaims,
} from '../../../core/ThresholdService/validation';

function isEmailOtpRegistrationHssRequest(body: Record<string, unknown>): boolean {
  return (
    body.kind === 'email_otp_registration' &&
    typeof body.registrationAttemptId === 'string' &&
    typeof body.new_account_id === 'string' &&
    typeof body.rp_id === 'string'
  );
}

async function resolveEmailOtpRegistrationHssAuth(args: {
  ctx: CloudflareRelayContext;
  body: Record<string, unknown>;
}): Promise<
  | {
      ok: true;
      appSessionClaims: NonNullable<ReturnType<typeof parseAppSessionClaims>>;
      runtimePolicyScope: NonNullable<
        NonNullable<ReturnType<typeof parseAppSessionClaims>>['runtimePolicyScope']
      >;
    }
  | { ok: false; code: string; message: string }
> {
  const session = args.ctx.opts.session;
  if (!session) return { ok: false, code: 'sessions_disabled', message: 'Sessions are disabled' };
  const parsed = await session.parse(Object.fromEntries(args.ctx.request.headers.entries()));
  if (!parsed.ok) return { ok: false, code: 'unauthorized', message: 'Missing app session' };
  const appSessionClaims = parseAppSessionClaims(parsed.claims);
  if (!appSessionClaims) {
    return { ok: false, code: 'unauthorized', message: 'Email OTP registration requires app session auth' };
  }
  if (appSessionClaims.exp !== undefined && appSessionClaims.exp * 1000 <= Date.now()) {
    return { ok: false, code: 'unauthorized', message: 'App session is expired' };
  }
  const validated = await args.ctx.service.validateAppSessionVersion({
    userId: appSessionClaims.sub,
    appSessionVersion: appSessionClaims.appSessionVersion,
  });
  if (!validated.ok) return { ok: false, code: 'unauthorized', message: validated.message };

  const walletId = String(args.body.new_account_id || '').trim();
  const registrationAttemptId = String(args.body.registrationAttemptId || '').trim();
  if (String(appSessionClaims.walletId || '').trim() !== walletId) {
    return { ok: false, code: 'unauthorized', message: 'Email OTP registration wallet mismatch' };
  }
  if (
    String(
      (appSessionClaims as { googleEmailOtpRegistrationAttemptId?: unknown })
        .googleEmailOtpRegistrationAttemptId || '',
    ).trim() !== registrationAttemptId
  ) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'Email OTP registration attempt mismatch',
    };
  }
  const runtimePolicyScope = appSessionClaims.runtimePolicyScope;
  if (!runtimePolicyScope?.orgId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration requires runtime policy scope',
    };
  }
  return { ok: true, appSessionClaims, runtimePolicyScope };
}

async function signEmailOtpRegistrationEd25519SessionJwt(args: {
  ctx: CloudflareRelayContext;
  nearAccountId: string;
  rpId: string;
  relayerKeyId: string;
  sessionResult: Record<string, unknown>;
  participantIds: number[];
  runtimePolicyScope: NonNullable<ReturnType<typeof parseAppSessionClaims>>['runtimePolicyScope'];
}): Promise<string> {
  const session = args.ctx.opts.session;
  if (!session) throw new Error('Sessions are disabled');
  const sessionId = String(args.sessionResult.sessionId || '').trim();
  const walletSigningSessionId = String(args.sessionResult.walletSigningSessionId || '').trim();
  const expiresAtMs = Number(args.sessionResult.expiresAtMs);
  if (!sessionId || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error('threshold-ed25519 session bootstrap returned incomplete session state');
  }
  const nowSec = Math.floor(Date.now() / 1000);
  return await session.signJwt(args.nearAccountId, {
    kind: 'threshold_ed25519_session_v1',
    walletId: args.nearAccountId,
    sessionId,
    ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
    relayerKeyId: args.relayerKeyId,
    rpId: args.rpId,
    participantIds: args.participantIds,
    thresholdExpiresAtMs: expiresAtMs,
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    iat: nowSec,
    exp: Math.floor(expiresAtMs / 1000),
  });
}

export async function handleThresholdEd25519(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method === 'GET' && ctx.pathname === '/threshold-ed25519/healthz') {
    const resolved = resolveThresholdScheme(
      ctx.opts.threshold,
      THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
      {
        notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
      },
    );
    if (!resolved.ok) {
      const body = { ...resolved, configured: false };
      return json(body, { status: thresholdEd25519StatusCode(body) });
    }
    return json({ ok: true, configured: true }, { status: 200 });
  }

  if (ctx.method !== 'POST') return null;

  const pathname = ctx.pathname;
  if (
    pathname !== '/threshold-ed25519/session' &&
    pathname !== '/threshold-ed25519/authorize' &&
    pathname !== '/threshold-ed25519/hss/prepare' &&
    pathname !== '/threshold-ed25519/hss/finalize' &&
    pathname !== '/threshold-ed25519/hss/respond' &&
    pathname !== '/threshold-ed25519/sign/init' &&
    pathname !== '/threshold-ed25519/sign/finalize' &&
    pathname !== '/threshold-ed25519/internal/cosign/init' &&
    pathname !== '/threshold-ed25519/internal/cosign/finalize'
  ) {
    return null;
  }

  const body = await readJson(ctx.request);
  const resolved = resolveThresholdScheme(
    ctx.opts.threshold,
    THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
    {
      notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
    },
  );
  if (!resolved.ok) {
    return json(resolved, { status: thresholdEd25519StatusCode(resolved) });
  }
  const ed25519 = resolved.scheme;

  switch (pathname) {
    case '/threshold-ed25519/session': {
      const session = ctx.opts.session;
      if (!session) {
        ctx.logger.warn('[threshold-ed25519] request', {
          route: pathname,
          method: ctx.method,
          sessions: false,
        });
        return json(
          {
            ok: false,
            code: 'sessions_disabled',
            message: 'Sessions are not configured on this server',
          },
          { status: 501 },
        );
      }

      const b = (body || {}) as ThresholdEd25519SessionRequest;
      let appSessionClaims: ReturnType<typeof parseAppSessionClaims> = null;
      let ecdsaSessionClaims: ReturnType<typeof parseThresholdEcdsaSessionClaims> = null;
      const parsedSession = session
        ? await session.parse(Object.fromEntries(ctx.request.headers.entries()))
        : null;
      if (parsedSession?.ok) {
        appSessionClaims = parseAppSessionClaims(parsedSession.claims);
        if (appSessionClaims) {
          const validated = await ctx.service.validateAppSessionVersion({
            userId: appSessionClaims.sub,
            appSessionVersion: appSessionClaims.appSessionVersion,
          });
          if (!validated.ok) appSessionClaims = null;
        }
        if (!appSessionClaims) {
          ecdsaSessionClaims = parseThresholdEcdsaSessionClaims(parsedSession.claims);
        }
      }
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        relayerKeyId: typeof b.relayerKeyId === 'string' ? b.relayerKeyId : undefined,
        sessionPolicy: b.sessionPolicy ? { version: b.sessionPolicy.version } : undefined,
      });

      const inheritedRuntimePolicyScope =
        appSessionClaims?.runtimePolicyScope || ecdsaSessionClaims?.runtimePolicyScope;
      const runtimePolicyScopeResolution = await resolveThresholdRuntimePolicyScope({
        explicitScopeRaw: inheritedRuntimePolicyScope ?? b.sessionPolicy?.runtimePolicyScope,
        runtimeEnvironmentIdRaw: (b as { runtimeEnvironmentId?: unknown }).runtimeEnvironmentId,
        headers: ctx.request.headers,
        origin: ctx.request.headers.get('origin'),
        publishableKeyAuth: ctx.opts.publishableKeyAuth || null,
        orgProjectEnv: ctx.opts.orgProjectEnv || null,
      });
      if (!runtimePolicyScopeResolution.ok) {
        return json(
          {
            ok: false,
            code: runtimePolicyScopeResolution.code,
            message: runtimePolicyScopeResolution.message,
          },
          { status: runtimePolicyScopeResolution.status },
        );
      }
      const runtimePolicyScope = runtimePolicyScopeResolution.scope;

      const result = await ed25519.session({
        ...b,
        ...(appSessionClaims ? { appSessionClaims } : {}),
        ...(ecdsaSessionClaims ? { ecdsaSessionClaims } : {}),
      });
      const status = thresholdEd25519StatusCode(result);
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status,
        ok: result.ok,
        ...(result.code ? { code: result.code } : {}),
      });
      if (!result.ok) return json(result, { status });

      const sessionId = String(result.sessionId || '').trim();
      if (!sessionId) {
        return json(
          { ok: false, code: 'internal', message: 'threshold session missing sessionId' },
          { status: 500 },
        );
      }
      const userId = String(b.sessionPolicy?.nearAccountId || '').trim();
      const rpId = String(b.sessionPolicy?.rpId || '').trim();
      const relayerKeyId = String(b.relayerKeyId || '').trim();
      const thresholdExpiresAtMs = (() => {
        const ms =
          typeof (result as any).expiresAtMs === 'number'
            ? (result as any).expiresAtMs
            : result.expiresAt
              ? Date.parse(result.expiresAt)
              : NaN;
        return Number.isFinite(ms) && ms > 0 ? ms : undefined;
      })();
      if (!userId) {
        return json(
          {
            ok: false,
            code: 'internal',
            message: 'threshold session missing sessionPolicy.nearAccountId',
          },
          { status: 500 },
        );
      }
      if (!rpId) {
        return json(
          { ok: false, code: 'internal', message: 'threshold session missing sessionPolicy.rpId' },
          { status: 500 },
        );
      }
      if (!relayerKeyId) {
        return json(
          { ok: false, code: 'internal', message: 'threshold session missing relayerKeyId' },
          { status: 500 },
        );
      }
      if (thresholdExpiresAtMs === undefined) {
        return json(
          { ok: false, code: 'internal', message: 'threshold session missing expiresAtMs' },
          { status: 500 },
        );
      }
      const exp = thresholdExpiresAtMs ? Math.floor(thresholdExpiresAtMs / 1000) : undefined;
      const iat = Math.floor(Date.now() / 1000);
      const participantIds = normalizeThresholdEd25519ParticipantIds(
        b.sessionPolicy?.participantIds,
      ) || [...THRESHOLD_ED25519_2P_PARTICIPANT_IDS];
      const token = await session.signJwt(userId, {
        kind: 'threshold_ed25519_session_v1',
        walletId: userId,
        sessionId,
        ...(result.walletSigningSessionId
          ? { walletSigningSessionId: result.walletSigningSessionId }
          : {}),
        relayerKeyId,
        rpId,
        ...(thresholdExpiresAtMs !== undefined ? { thresholdExpiresAtMs } : {}),
        ...(exp !== undefined ? { exp } : {}),
        iat,
        participantIds,
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      });
      const sessionKind = parseSessionKind(b);

      const res = json(
        sessionKind === 'cookie'
          ? { ...result, ...(runtimePolicyScope ? { runtimePolicyScope } : {}), jwt: undefined }
          : { ...result, ...(runtimePolicyScope ? { runtimePolicyScope } : {}), jwt: token },
        { status: 200 },
      );
      if (sessionKind === 'cookie') {
        res.headers.set('Set-Cookie', session.buildSetCookie(token));
      }
      return res;
    }
    case '/threshold-ed25519/authorize': {
      const b = (body || {}) as Record<string, unknown>;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        relayerKeyId: typeof b.relayerKeyId === 'string' ? b.relayerKeyId : undefined,
        purpose: typeof b.purpose === 'string' ? b.purpose : undefined,
        signing_digest_32_len: Array.isArray(b.signing_digest_32)
          ? b.signing_digest_32.length
          : undefined,
      });

      const respond = (result: ThresholdEd25519AuthorizeResponse): Response => {
        ctx.logger.info('[threshold-ed25519] response', {
          route: pathname,
          status: thresholdEd25519StatusCode(result),
          ok: result.ok,
          ...(result.code ? { code: result.code } : {}),
        });
        return json(result, { status: thresholdEd25519StatusCode(result) });
      };

      const validated = await validateThresholdEd25519AuthorizeInputs({
        body,
        headers: Object.fromEntries(ctx.request.headers.entries()),
        session: ctx.opts.session,
      });
      if (!validated.ok) return respond(validated);
      const runtimeSnapshotValidation = await validateRuntimeSnapshotExpectation({
        runtimeSnapshots: ctx.opts.runtimeSnapshots,
        scope: validated.claims.runtimePolicyScope,
        expectationRaw: (validated.request as unknown as Record<string, unknown>).runtimeSnapshot,
      });
      if (!runtimeSnapshotValidation.ok) return respond(runtimeSnapshotValidation);

      const result = await ed25519.authorize({
        claims: validated.claims,
        request: validated.request,
      });
      return respond(result);
    }
    case '/threshold-ed25519/hss/prepare': {
      const startedAt = Date.now();
      const b = (body || {}) as Record<string, unknown>;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        relayerKeyId: typeof b.relayerKeyId === 'string' ? b.relayerKeyId : undefined,
        keyPurpose:
          b.context && typeof b.context === 'object' && !Array.isArray(b.context)
            ? (b.context as Record<string, unknown>).keyPurpose
            : undefined,
        keyVersion:
          b.context && typeof b.context === 'object' && !Array.isArray(b.context)
            ? (b.context as Record<string, unknown>).keyVersion
            : undefined,
      });
      const threshold = ctx.opts.threshold;
      if (!threshold || !threshold.ed25519Hss) {
        const result = {
          ok: false,
          code: 'threshold_disabled',
          message: 'Threshold Ed25519 HSS is not configured on this server',
        };
        return json(result, { status: 501 });
      }
      if (isEmailOtpRegistrationHssRequest(b)) {
        const auth = await resolveEmailOtpRegistrationHssAuth({ ctx, body: b });
        if (!auth.ok) return json(auth, { status: thresholdEd25519StatusCode(auth) });
        const result = await (threshold.ed25519Hss as any).prepareForRegistration({
          orgId: auth.runtimePolicyScope.orgId,
          signingRootId:
            b.context && typeof b.context === 'object' && !Array.isArray(b.context)
              ? String((b.context as Record<string, unknown>).signingRootId || '').trim()
              : undefined,
          signingRootVersion: auth.runtimePolicyScope.signingRootVersion,
          request: b as any,
        });
        return json(result, { status: thresholdEd25519StatusCode(result) });
      }
      const validated = await validateThresholdEd25519SessionTokenInputs({
        body,
        headers: Object.fromEntries(ctx.request.headers.entries()),
        session: ctx.opts.session,
      });
      if (!validated.ok) return json(validated, { status: thresholdEd25519StatusCode(validated) });
      const result = await threshold.ed25519Hss.prepareWithSession({
        claims: validated.claims,
        request: validated.body as unknown as ThresholdEd25519HssPrepareWithSessionRequest,
      });
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status: thresholdEd25519StatusCode(result),
        ok: result.ok,
        durationMs: Date.now() - startedAt,
        ...('code' in result && result.code ? { code: result.code } : {}),
      });
      return json(result, { status: thresholdEd25519StatusCode(result) });
    }
    case '/threshold-ed25519/hss/finalize': {
      const startedAt = Date.now();
      const b = (body || {}) as Record<string, unknown>;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        relayerKeyId: typeof b.relayerKeyId === 'string' ? b.relayerKeyId : undefined,
        keyPurpose:
          b.context && typeof b.context === 'object' && !Array.isArray(b.context)
            ? (b.context as Record<string, unknown>).keyPurpose
            : undefined,
        keyVersion:
          b.context && typeof b.context === 'object' && !Array.isArray(b.context)
            ? (b.context as Record<string, unknown>).keyVersion
            : undefined,
      });
      const threshold = ctx.opts.threshold;
      if (!threshold || !threshold.ed25519Hss) {
        const result = {
          ok: false,
          code: 'threshold_disabled',
          message: 'Threshold Ed25519 HSS is not configured on this server',
        };
        return json(result, { status: 501 });
      }
      if (isEmailOtpRegistrationHssRequest(b)) {
        const auth = await resolveEmailOtpRegistrationHssAuth({ ctx, body: b });
        if (!auth.ok) return json(auth, { status: thresholdEd25519StatusCode(auth) });
        const finalized = await (threshold.ed25519Hss as any).finalizeForRegistration({
          orgId: auth.runtimePolicyScope.orgId,
          request: b as any,
        });
        if (!finalized.ok) return json(finalized, { status: thresholdEd25519StatusCode(finalized) });
        const nearAccountId = String(b.new_account_id || '').trim();
        const rpId = String(b.rp_id || '').trim();
        const publicKey = String(finalized.publicKey || '').trim();
        const created = await ctx.service.createAccount({
          accountId: nearAccountId,
          publicKey,
        });
        if (!created.success) {
          const result = {
            ok: false,
            code: 'account_creation_failed',
            message: created.error || created.message || 'Failed to create NEAR account',
          };
          return json(result, { status: thresholdEd25519StatusCode(result) });
        }
        const keyVersion =
          b.context && typeof b.context === 'object' && !Array.isArray(b.context)
            ? String((b.context as Record<string, unknown>).keyVersion || '').trim()
            : '';
        const participantIds =
          b.context && typeof b.context === 'object' && !Array.isArray(b.context)
            ? ((b.context as Record<string, unknown>).participantIds as number[] | undefined)
            : undefined;
        let sessionResult: Record<string, unknown> | null = null;
        const sessionPolicy = b.sessionPolicy as Record<string, unknown> | undefined;
        if (sessionPolicy) {
          const minted = await (threshold as any).mintEd25519SessionFromRegistration({
            nearAccountId,
            rpId,
            relayerKeyId: finalized.relayerKeyId,
            sessionPolicy: {
              ...sessionPolicy,
              nearAccountId,
              rpId,
              relayerKeyId: finalized.relayerKeyId,
              runtimePolicyScope: auth.runtimePolicyScope,
            },
          });
          if (!minted.ok) return json(minted, { status: thresholdEd25519StatusCode(minted) });
          const jwt = await signEmailOtpRegistrationEd25519SessionJwt({
            ctx,
            nearAccountId,
            rpId,
            relayerKeyId: finalized.relayerKeyId,
            sessionResult: minted as Record<string, unknown>,
            participantIds: Array.isArray(minted.participantIds)
              ? minted.participantIds
              : Array.isArray(participantIds)
                ? participantIds
                : [],
            runtimePolicyScope: auth.runtimePolicyScope,
          });
          sessionResult = {
            ...minted,
            sessionKind: 'jwt',
            jwt,
            runtimePolicyScope: auth.runtimePolicyScope,
          };
        }
        const recorded = await ctx.service.recordGoogleEmailOtpRegistrationAttemptPublicKey({
          registrationAttemptId: b.registrationAttemptId,
          walletId: nearAccountId,
          finalizedPublicKey: publicKey,
        });
        if (!recorded.ok) return json(recorded, { status: thresholdEd25519StatusCode(recorded) });
        const result = {
          ok: true,
          publicKey,
          relayerKeyId: finalized.relayerKeyId,
          keyVersion,
          recoveryExportCapable: true,
          ...(sessionResult ? { session: sessionResult } : {}),
        };
        return json(result, { status: 200 });
      }
      const validated = await validateThresholdEd25519SessionTokenInputs({
        body,
        headers: Object.fromEntries(ctx.request.headers.entries()),
        session: ctx.opts.session,
      });
      if (!validated.ok) return json(validated, { status: thresholdEd25519StatusCode(validated) });
      const result = await threshold.ed25519Hss.finalizeWithSession({
        claims: validated.claims,
        request: validated.body as unknown as ThresholdEd25519HssFinalizeWithSessionRequest,
      });
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status: thresholdEd25519StatusCode(result),
        ok: result.ok,
        durationMs: Date.now() - startedAt,
        ...('code' in result && result.code ? { code: result.code } : {}),
      });
      return json(result, { status: thresholdEd25519StatusCode(result) });
    }
    case '/threshold-ed25519/hss/respond': {
      const startedAt = Date.now();
      const b = (body || {}) as Record<string, unknown>;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        ceremonyHandle: typeof b.ceremonyHandle === 'string' ? b.ceremonyHandle : undefined,
      });
      const threshold = ctx.opts.threshold;
      if (!threshold || !threshold.ed25519Hss) {
        const result = {
          ok: false,
          code: 'threshold_disabled',
          message: 'Threshold Ed25519 HSS is not configured on this server',
        };
        return json(result, { status: 501 });
      }
      if (isEmailOtpRegistrationHssRequest(b)) {
        const auth = await resolveEmailOtpRegistrationHssAuth({ ctx, body: b });
        if (!auth.ok) return json(auth, { status: thresholdEd25519StatusCode(auth) });
        const result = await (threshold.ed25519Hss as any).respondForRegistration({
          orgId: auth.runtimePolicyScope.orgId,
          request: b as any,
        });
        return json(result, { status: thresholdEd25519StatusCode(result) });
      }
      const validated = await validateThresholdEd25519SessionTokenInputs({
        body,
        headers: Object.fromEntries(ctx.request.headers.entries()),
        session: ctx.opts.session,
      });
      if (!validated.ok) return json(validated, { status: thresholdEd25519StatusCode(validated) });
      const result = await threshold.ed25519Hss.respondWithSession({
        claims: validated.claims,
        request: validated.body as any,
      });
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status: thresholdEd25519StatusCode(result),
        ok: result.ok,
        durationMs: Date.now() - startedAt,
        ...('code' in result && result.code ? { code: result.code } : {}),
      });
      return json(result, { status: thresholdEd25519StatusCode(result) });
    }
    case '/threshold-ed25519/sign/init': {
      const b = (body || {}) as ThresholdEd25519SignInitRequest;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        mpcSessionId: typeof b.mpcSessionId === 'string' ? b.mpcSessionId : undefined,
        relayerKeyId: typeof b.relayerKeyId === 'string' ? b.relayerKeyId : undefined,
        nearAccountId: typeof b.nearAccountId === 'string' ? b.nearAccountId : undefined,
        signingDigestB64u_len:
          typeof b.signingDigestB64u === 'string' ? b.signingDigestB64u.length : undefined,
      });
      const result = await ed25519.protocol.signInit(b);
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status: thresholdEd25519StatusCode(result),
        ok: result.ok,
        ...(result.code ? { code: result.code } : {}),
      });
      return json(result, { status: thresholdEd25519StatusCode(result) });
    }
    case '/threshold-ed25519/sign/finalize': {
      const b = (body || {}) as ThresholdEd25519SignFinalizeRequest;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        signingSessionId: typeof b.signingSessionId === 'string' ? b.signingSessionId : undefined,
        clientSignatureShareB64u_len:
          typeof b.clientSignatureShareB64u === 'string'
            ? b.clientSignatureShareB64u.length
            : undefined,
      });
      const result = await ed25519.protocol.signFinalize(b);
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status: thresholdEd25519StatusCode(result),
        ok: result.ok,
        ...(result.code ? { code: result.code } : {}),
      });
      return json(result, { status: thresholdEd25519StatusCode(result) });
    }
    case '/threshold-ed25519/internal/cosign/init': {
      const cosignInit = ed25519.protocol.internalCosignInit;
      if (!cosignInit) {
        const result = {
          ok: false,
          code: 'not_found',
          message: 'threshold-ed25519 cosigner endpoints are not enabled on this server',
        };
        return json(result, { status: thresholdEd25519StatusCode(result) });
      }
      const b = (body || {}) as ThresholdEd25519CosignInitRequest;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        coordinatorGrant_len:
          typeof b.coordinatorGrant === 'string' ? b.coordinatorGrant.length : undefined,
        signingSessionId: typeof b.signingSessionId === 'string' ? b.signingSessionId : undefined,
        cosignerShareB64u_len:
          typeof b.cosignerShareB64u === 'string' ? b.cosignerShareB64u.length : undefined,
      });
      const result = await cosignInit(b);
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status: thresholdEd25519StatusCode(result),
        ok: result.ok,
        ...(result.code ? { code: result.code } : {}),
      });
      return json(result, { status: thresholdEd25519StatusCode(result) });
    }
    case '/threshold-ed25519/internal/cosign/finalize': {
      const cosignFinalize = ed25519.protocol.internalCosignFinalize;
      if (!cosignFinalize) {
        const result = {
          ok: false,
          code: 'not_found',
          message: 'threshold-ed25519 cosigner endpoints are not enabled on this server',
        };
        return json(result, { status: thresholdEd25519StatusCode(result) });
      }
      const b = (body || {}) as ThresholdEd25519CosignFinalizeRequest;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        coordinatorGrant_len:
          typeof b.coordinatorGrant === 'string' ? b.coordinatorGrant.length : undefined,
        signingSessionId: typeof b.signingSessionId === 'string' ? b.signingSessionId : undefined,
        cosignerIds_len: Array.isArray(b.cosignerIds) ? b.cosignerIds.length : undefined,
      });
      const result = await cosignFinalize(b);
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status: thresholdEd25519StatusCode(result),
        ok: result.ok,
        ...(result.code ? { code: result.code } : {}),
      });
      return json(result, { status: thresholdEd25519StatusCode(result) });
    }
    default:
      return null;
  }
}
