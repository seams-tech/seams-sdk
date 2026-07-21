import type { CloudflareRouterApiContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import { thresholdEd25519StatusCode } from '../../../threshold/statusCodes';
import {
  ROUTER_AB_ED25519_HEALTH_PATH,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PATH,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH,
  ROUTER_AB_ED25519_WALLET_SESSION_PATH,
} from '@shared/utils/signingSessionSeal';
import { resolveThresholdRuntimePolicyScope } from '../../commonRouterUtils';
import { normalizeCorsOrigin } from '../../../core/SessionService';
import {
  handleRouterAbEd25519NormalSigningRouteCore,
  ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS,
  type RouterAbEd25519PrivateSigningPath,
} from '../../routerAbPrivateSigningWorker';
import { parseThresholdEd25519SessionRouteRequest } from '../../thresholdEd25519RequestValidation';
import {
  isPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { isPlainObject } from '@shared/utils/validation';
import {
  parseAppSessionClaims,
  resolveAppSessionWalletIdForWalletScope,
} from '../../../core/ThresholdService/validation';
import type {
  RouterAbEd25519YaoBudgetRefreshAuthorizationV1,
  RouterAbEd25519YaoSessionRouteCommandV1,
} from '../../routerAbEd25519YaoWalletSession';

type PasskeyEd25519AuthorizationResult =
  | {
      ok: true;
      authorization: Extract<
        RouterAbEd25519YaoBudgetRefreshAuthorizationV1,
        {
          kind:
            | 'verified_passkey_assertion_router_ab_ed25519_yao_budget_refresh_v1'
            | 'verified_passkey_app_session_router_ab_ed25519_yao_budget_refresh_v1';
        }
      >;
    }
  | { ok: false; response: Response };

async function validatePasskeyEd25519SessionAuthorization(input: {
  ctx: CloudflareRouterApiContext;
  request: RouterAbEd25519YaoSessionRouteCommandV1;
  authority: PasskeyWalletAuthAuthority;
}): Promise<PasskeyEd25519AuthorizationResult> {
  const credential = input.request.routeAuth;
  if (credential.kind !== 'passkey') {
    throw new Error('validatePasskeyEd25519SessionAuthorization requires passkey route auth');
  }
  const credentialIdB64u = String(
    credential.webauthnAuthentication.rawId || credential.webauthnAuthentication.id || '',
  ).trim();
  if (!credentialIdB64u || credentialIdB64u !== input.authority.factor.credentialIdB64u) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'unauthorized',
          message: 'WebAuthn proof does not match the active Ed25519 Wallet Session authority',
        },
        { status: 401 },
      ),
    };
  }
  const expectedOrigin = normalizeCorsOrigin(input.ctx.request.headers.get('origin') || undefined);
  if (!expectedOrigin) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn authentication verification',
        },
        { status: 400 },
      ),
    };
  }
  const expectedChallenge = base64UrlEncode(
    await sha256BytesUtf8(alphabetizeStringify(input.request.sessionPolicy)),
  );
  const verified = await input.ctx.service.webAuthn.verifyWebAuthnAuthenticationLite({
    userId: input.authority.walletId,
    rpId: input.authority.verifier.rpId,
    expectedChallenge,
    expected_origin: expectedOrigin,
    webauthn_authentication: credential.webauthnAuthentication,
  });
  if (verified.success && verified.verified) {
    return {
      ok: true,
      authorization: {
        kind: 'verified_passkey_assertion_router_ab_ed25519_yao_budget_refresh_v1',
        authority: input.authority,
      },
    };
  }
  return {
    ok: false,
    response: json(
      {
        ok: false,
        code: verified.code || 'not_verified',
        message: verified.message || 'WebAuthn authentication verification failed',
      },
      { status: 401 },
    ),
  };
}

async function validateSignedEd25519SessionAuthorization(input: {
  ctx: CloudflareRouterApiContext;
  request: RouterAbEd25519YaoSessionRouteCommandV1;
  authority: PasskeyWalletAuthAuthority;
}): Promise<PasskeyEd25519AuthorizationResult> {
  if (input.request.routeAuth.kind !== 'signed_session') {
    throw new Error('validateSignedEd25519SessionAuthorization requires signed-session route auth');
  }
  const session = input.ctx.opts.session;
  if (!session) {
    return {
      ok: false,
      response: json(
        { ok: false, code: 'unauthorized', message: 'Signed session authorization is unavailable' },
        { status: 401 },
      ),
    };
  }
  const parsedSession = await session.parse(
    Object.fromEntries(input.ctx.request.headers.entries()),
  );
  if (!parsedSession.ok) {
    return {
      ok: false,
      response: json(
        { ok: false, code: 'unauthorized', message: 'Signed session authorization is required' },
        { status: 401 },
      ),
    };
  }
  let appSessionClaims = parseAppSessionClaims(parsedSession.claims);
  if (
    appSessionClaims &&
    (!isPlainObject(parsedSession.claims) || parsedSession.claims.provider !== 'passkey')
  ) {
    appSessionClaims = null;
  }
  if (appSessionClaims) {
    const version = await input.ctx.service.sessionVersions.validateAppSessionVersion({
      userId: appSessionClaims.sub,
      appSessionVersion: appSessionClaims.appSessionVersion,
    });
    if (!version.ok) appSessionClaims = null;
  }
  const appSessionWalletId = resolveAppSessionWalletIdForWalletScope(
    appSessionClaims,
    input.authority.walletId,
  );
  if (!appSessionClaims || appSessionWalletId !== input.authority.walletId) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'unauthorized',
          message: 'Passkey app session does not authorize the active Ed25519 wallet',
        },
        { status: 401 },
      ),
    };
  }
  const expectedAuthorityRef = await walletAuthAuthorityRef({ authority: input.authority });
  const signedAuthorityRef = appSessionClaims.walletAuthAuthorityRef;
  if (
    !signedAuthorityRef ||
    signedAuthorityRef.walletId !== expectedAuthorityRef.walletId ||
    signedAuthorityRef.authorityDigest !== expectedAuthorityRef.authorityDigest
  ) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'unauthorized',
          message: 'Passkey app session authority does not match the active Ed25519 authority',
        },
        { status: 401 },
      ),
    };
  }
  const signedRuntimePolicyScope = appSessionClaims.runtimePolicyScope;
  if (
    !signedRuntimePolicyScope ||
    alphabetizeStringify(signedRuntimePolicyScope) !==
      alphabetizeStringify(input.request.sessionPolicy.runtimePolicyScope)
  ) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'scope_mismatch',
          message: 'Passkey app session runtime scope does not match the Ed25519 session policy',
        },
        { status: 403 },
      ),
    };
  }
  return {
    ok: true,
    authorization: {
      kind: 'verified_passkey_app_session_router_ab_ed25519_yao_budget_refresh_v1',
      authority: input.authority,
      authorityRef: signedAuthorityRef,
      runtimePolicyScope: signedRuntimePolicyScope,
    },
  };
}

async function handleRouterAbEd25519NormalSigningRoute(input: {
  ctx: CloudflareRouterApiContext;
  body: Record<string, unknown>;
  privatePath: RouterAbEd25519PrivateSigningPath;
  phase: 'prepare' | 'finalize';
}): Promise<Response> {
  const result = await handleRouterAbEd25519NormalSigningRouteCore({
    body: input.body,
    rawBody: input.body,
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    session: input.ctx.opts.session,
    runtime: input.ctx.service.thresholdRuntime.getRouterAbNormalSigningRuntime(),
    admissionAdapter: input.ctx.opts.routerAbNormalSigningAdmission,
    privatePath: input.privatePath,
    phase: input.phase,
  });
  return json(result.body, { status: result.status });
}

export async function handleThresholdEd25519(
  ctx: CloudflareRouterApiContext,
): Promise<Response | null> {
  if (ctx.method === 'GET' && ctx.pathname === ROUTER_AB_ED25519_HEALTH_PATH) {
    if (!ctx.service.thresholdRuntime.getRouterAbNormalSigningRuntime()) {
      const body = {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B Ed25519 signing runtime is not configured on this server',
        configured: false,
      };
      return json(body, { status: thresholdEd25519StatusCode(body) });
    }
    return json({ ok: true, configured: true }, { status: 200 });
  }

  if (ctx.method !== 'POST') return null;

  const pathname = ctx.pathname;
  if (
    pathname !== ROUTER_AB_ED25519_WALLET_SESSION_PATH &&
    pathname !== ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH &&
    pathname !== ROUTER_AB_ED25519_NORMAL_SIGNING_PATH
  ) {
    return null;
  }

  const bodyUnknown = await readJson(ctx.request);
  const body =
    bodyUnknown && typeof bodyUnknown === 'object' && !Array.isArray(bodyUnknown)
      ? (bodyUnknown as Record<string, unknown>)
      : {};

  switch (pathname) {
    case ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH:
      return handleRouterAbEd25519NormalSigningRoute({
        ctx,
        body,
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare,
        phase: 'prepare',
      });

    case ROUTER_AB_ED25519_NORMAL_SIGNING_PATH:
      return handleRouterAbEd25519NormalSigningRoute({
        ctx,
        body,
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.finalize,
        phase: 'finalize',
      });
  }

  switch (pathname) {
    case ROUTER_AB_ED25519_WALLET_SESSION_PATH: {
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

      const parsedBody = parseThresholdEd25519SessionRouteRequest(body);
      if (!parsedBody.ok) {
        return json(parsedBody.body, { status: thresholdEd25519StatusCode(parsedBody.body) });
      }
      const b = parsedBody.request;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        relayerKeyId: typeof b.relayerKeyId === 'string' ? b.relayerKeyId : undefined,
        sessionPolicy: b.sessionPolicy ? { version: b.sessionPolicy.version } : undefined,
      });

      const authority = b.sessionPolicy.authority;
      if (!isPasskeyWalletAuthAuthority(authority)) {
        return json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'Ed25519 Yao WebAuthn budget refresh requires passkey authority',
          },
          { status: 400 },
        );
      }
      if (b.relayerKeyId !== b.sessionPolicy.relayerKeyId) {
        return json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'relayerKeyId must match the Ed25519 Yao session policy',
          },
          { status: 400 },
        );
      }

      const runtimePolicyScopeResolution = await resolveThresholdRuntimePolicyScope({
        explicitScopeRaw: b.sessionPolicy.runtimePolicyScope,
        projectEnvironmentIdRaw: b.projectEnvironmentId,
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
      if (
        !runtimePolicyScope ||
        alphabetizeStringify(runtimePolicyScope) !==
          alphabetizeStringify(b.sessionPolicy.runtimePolicyScope)
      ) {
        return json(
          {
            ok: false,
            code: 'scope_mismatch',
            message: 'Ed25519 Yao runtime policy scope does not match the active environment',
          },
          { status: 403 },
        );
      }
      const authorization =
        b.routeAuth.kind === 'passkey'
          ? await validatePasskeyEd25519SessionAuthorization({
              ctx,
              request: b,
              authority,
            })
          : await validateSignedEd25519SessionAuthorization({
              ctx,
              request: b,
              authority,
            });
      if (!authorization.ok) return authorization.response;

      const result = await ctx.service.walletRegistration.refreshEd25519YaoWalletSession({
        kind: 'router_ab_ed25519_yao_budget_refresh_v1',
        sessionPolicy: b.sessionPolicy,
        authorization: authorization.authorization,
      });
      const status = thresholdEd25519StatusCode(result);
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status,
        ok: result.ok,
        ...('code' in result && result.code ? { code: result.code } : {}),
      });
      return json(result, { status });
    }
    default:
      return null;
  }
}
