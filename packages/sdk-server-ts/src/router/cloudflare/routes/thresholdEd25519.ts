import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import { thresholdEd25519StatusCode } from '../../../threshold/statusCodes';
import type {
  ThresholdEd25519HssFinalizeWithSessionRequest,
  ThresholdEd25519HssPrepareWithSessionRequest,
  ThresholdEd25519SessionRequest,
} from '../../../core/types';
import {
  ROUTER_AB_ED25519_HEALTH_PATH_V2,
  ROUTER_AB_ED25519_HSS_FINALIZE_PATH_V2,
  ROUTER_AB_ED25519_HSS_PREPARE_PATH_V2,
  ROUTER_AB_ED25519_HSS_RESPOND_PATH_V2,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PATH_V2,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH_V2,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V2,
  ROUTER_AB_ED25519_WALLET_SESSION_PATH_V2,
} from '@shared/utils/signingSessionSeal';
import { parseSessionKind, resolveThresholdScheme } from '../../relay';
import {
  resolveThresholdRuntimePolicyScope,
  signRouterAbEd25519WalletSessionJwt,
  validateRouterAbEd25519WalletSessionTokenInputs,
} from '../../commonRouterUtils';
import {
  normalizeThresholdEd25519ParticipantIds,
  THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
} from '@shared/threshold/participants';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '../../../core/ThresholdService/schemes/schemeIds';
import {
  parseAppSessionClaims,
  parseRouterAbEcdsaHssWalletSessionClaims,
} from '../../../core/ThresholdService/validation';
import { normalizeCorsOrigin } from '../../../core/SessionService';
import {
  handleRouterAbEd25519NormalSigningRouteCore,
  ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS,
  type RouterAbEd25519PrivateSigningPath,
} from '../../routerAbPrivateSigningWorker';

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
    return {
      ok: false,
      code: 'unauthorized',
      message: 'Email OTP registration requires app session auth',
    };
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
    String(appSessionClaims.googleEmailOtpRegistrationAttemptId || '').trim() !==
    registrationAttemptId
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
  const sessionId = String(args.sessionResult.sessionId || '').trim();
  const signingGrantId = String(args.sessionResult.signingGrantId || '').trim();
  const expiresAtMs = Number(args.sessionResult.expiresAtMs);
  if (!sessionId || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error('threshold-ed25519 session bootstrap returned incomplete session state');
  }
  const signed = await signRouterAbEd25519WalletSessionJwt({
    session: args.ctx.opts.session,
    userId: args.nearAccountId,
    rpId: args.rpId,
    relayerKeyId: args.relayerKeyId,
    sessionInfo: {
      sessionKind: 'jwt',
      thresholdSessionId: sessionId,
      signingGrantId,
      expiresAtMs,
      participantIds: args.participantIds,
      runtimePolicyScope: args.runtimePolicyScope,
      routerAbNormalSigning: args.sessionResult.routerAbNormalSigning,
    },
    fallbackParticipantIds: args.participantIds,
    requireJwtErrorMessage: 'threshold_ed25519.session_kind must be jwt',
    invalidPayloadErrorMessage: 'invalid thresholdEd25519 session payload for jwt signing',
  });
  if (!signed.ok) throw new Error(signed.message);
  return signed.jwt;
}

async function handleRouterAbEd25519NormalSigningRoute(input: {
  ctx: CloudflareRelayContext;
  body: Record<string, unknown>;
  privatePath: RouterAbEd25519PrivateSigningPath;
  phase: 'prepare' | 'presign-pool-prepare' | 'finalize';
}): Promise<Response> {
  const result = await handleRouterAbEd25519NormalSigningRouteCore({
    body: input.body,
    rawBody: input.body,
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    session: input.ctx.opts.session,
    getThreshold: () => input.ctx.service.getThresholdSigningService(),
    admissionAdapter: input.ctx.opts.routerAbNormalSigningAdmission,
    privatePath: input.privatePath,
    phase: input.phase,
  });
  return json(result.body, { status: result.status });
}

export async function handleThresholdEd25519(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method === 'GET' && ctx.pathname === ROUTER_AB_ED25519_HEALTH_PATH_V2) {
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
    pathname !== ROUTER_AB_ED25519_WALLET_SESSION_PATH_V2 &&
    pathname !== ROUTER_AB_ED25519_HSS_PREPARE_PATH_V2 &&
    pathname !== ROUTER_AB_ED25519_HSS_FINALIZE_PATH_V2 &&
    pathname !== ROUTER_AB_ED25519_HSS_RESPOND_PATH_V2 &&
    pathname !== ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH_V2 &&
    pathname !== ROUTER_AB_ED25519_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V2 &&
    pathname !== ROUTER_AB_ED25519_NORMAL_SIGNING_PATH_V2
  ) {
    return null;
  }

  const bodyUnknown = await readJson(ctx.request);
  const body =
    bodyUnknown && typeof bodyUnknown === 'object' && !Array.isArray(bodyUnknown)
      ? (bodyUnknown as Record<string, unknown>)
      : {};

  switch (pathname) {
    case ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH_V2:
      return handleRouterAbEd25519NormalSigningRoute({
        ctx,
        body,
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare,
        phase: 'prepare',
      });

    case ROUTER_AB_ED25519_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V2:
      return handleRouterAbEd25519NormalSigningRoute({
        ctx,
        body,
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.presignPoolPrepare,
        phase: 'presign-pool-prepare',
      });

    case ROUTER_AB_ED25519_NORMAL_SIGNING_PATH_V2:
      return handleRouterAbEd25519NormalSigningRoute({
        ctx,
        body,
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.finalize,
        phase: 'finalize',
      });
  }

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
    case ROUTER_AB_ED25519_WALLET_SESSION_PATH_V2: {
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

      const b = (body || {}) as unknown as ThresholdEd25519SessionRequest;
      const sessionKind = parseSessionKind(b);
      if (sessionKind !== 'jwt') {
        const result = {
          ok: false,
          code: 'invalid_body',
          message: 'Router A/B Ed25519 Wallet Session issuance requires sessionKind=jwt',
        };
        return json(result, { status: thresholdEd25519StatusCode(result) });
      }
      let appSessionClaims: ReturnType<typeof parseAppSessionClaims> = null;
      let ecdsaSessionClaims: ReturnType<typeof parseRouterAbEcdsaHssWalletSessionClaims> = null;
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
          ecdsaSessionClaims = parseRouterAbEcdsaHssWalletSessionClaims(parsedSession.claims);
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
      const expectedOrigin = normalizeCorsOrigin(ctx.request.headers.get('origin') || undefined);
      if ((b as any).webauthn_authentication && !expectedOrigin) {
        return json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'expected_origin is required for WebAuthn authentication verification',
          },
          { status: 400 },
        );
      }

      const result = await ed25519.session({
        ...b,
        expected_origin: expectedOrigin || '',
        ...(appSessionClaims ? { appSessionClaims } : {}),
        ...(ecdsaSessionClaims ? { ecdsaSessionClaims } : {}),
      });
      const status = thresholdEd25519StatusCode(result);
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status,
        ok: result.ok,
        ...('code' in result && result.code ? { code: result.code } : {}),
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
      const participantIds = normalizeThresholdEd25519ParticipantIds(
        b.sessionPolicy?.participantIds,
      ) || [...THRESHOLD_ED25519_2P_PARTICIPANT_IDS];
      const signed = await signRouterAbEd25519WalletSessionJwt({
        session,
        userId,
        rpId,
        relayerKeyId,
        sessionInfo: {
          sessionKind: 'jwt',
          thresholdSessionId: sessionId,
          signingGrantId: result.signingGrantId,
          expiresAtMs: thresholdExpiresAtMs,
          participantIds,
          runtimePolicyScope,
          routerAbNormalSigning: result.routerAbNormalSigning,
        },
        fallbackParticipantIds: participantIds,
        requireJwtErrorMessage: 'threshold_ed25519.session_kind must be jwt',
        invalidPayloadErrorMessage: 'invalid thresholdEd25519 session payload for jwt signing',
      });
      if (!signed.ok) {
        return json(
          { ok: false, code: signed.code, message: signed.message },
          { status: signed.status },
        );
      }
      const res = json(
        { ...result, ...(runtimePolicyScope ? { runtimePolicyScope } : {}), jwt: signed.jwt },
        { status: 200 },
      );
      return res;
    }
    case ROUTER_AB_ED25519_HSS_PREPARE_PATH_V2: {
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
      const validated = await validateRouterAbEd25519WalletSessionTokenInputs({
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
    case ROUTER_AB_ED25519_HSS_FINALIZE_PATH_V2: {
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
        if (!finalized.ok)
          return json(finalized, { status: thresholdEd25519StatusCode(finalized) });
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
          finalizedReport: finalized.finalizedReport,
          keyVersion,
          recoveryExportCapable: true,
          ...(sessionResult ? { session: sessionResult } : {}),
        };
        return json(result, { status: 200 });
      }
      const validated = await validateRouterAbEd25519WalletSessionTokenInputs({
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
    case ROUTER_AB_ED25519_HSS_RESPOND_PATH_V2: {
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
      const validated = await validateRouterAbEd25519WalletSessionTokenInputs({
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
    default:
      return null;
  }
}
