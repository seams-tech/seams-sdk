import type { FetchRouterApiContext } from '../createFetchRouter';
import { json, readJson } from '../../../framework/http';
import { extractBearerCredential } from '../../../auth/routerApiKeyAuth';
import { resolveThresholdRuntimePolicyScope } from '../../../auth/commonRouterUtils';
import {
  parseAuthIdentityMutationRequest,
  parseAuthProviderActionPath,
  parseGoogleLoginVerifyRequest,
  parsePasskeyLoginOptionsRequest,
  parsePasskeyLoginVerifyRequest,
  type AuthPasskeyStepUpRequest,
} from '../../../auth/authRequestValidation';

function assertNeverAuthProviderAction(route: never): never {
  throw new Error(`Unsupported auth provider action: ${String((route as any)?.kind || '')}`);
}

function assertNeverAuthIdentityMutation(route: never): never {
  throw new Error(`Unsupported auth identity mutation: ${String((route as any)?.kind || '')}`);
}

export async function handleAuth(ctx: FetchRouterApiContext): Promise<Response | null> {
  const requireWalletSession = async (): Promise<
    { ok: true; walletId: string } | { ok: false; response: Response }
  > => {
    const token = extractBearerCredential(ctx.request.headers);
    if (!token) {
      return {
        ok: false,
        response: json(
          { ok: false, code: 'unauthorized', message: 'No valid Wallet Session' },
          { status: 401 },
        ),
      };
    }
    try {
      const nowMs = Date.now();
      const ecdsa = await ctx.service.authorizationSessions.resolveOpaqueWalletSessionToken({
        tenantId: ctx.service.authorizationSessions.tenantId,
        token,
        curve: 'ecdsa',
        nowMs,
      });
      const resolved =
        ecdsa ??
        (await ctx.service.authorizationSessions.resolveOpaqueWalletSessionToken({
          tenantId: ctx.service.authorizationSessions.tenantId,
          token,
          curve: 'ed25519',
          nowMs,
        }));
      if (!resolved) {
        return {
          ok: false,
          response: json(
            { ok: false, code: 'unauthorized', message: 'No valid Wallet Session' },
            { status: 401 },
          ),
        };
      }
      return { ok: true, walletId: resolved.authorization.walletId };
    } catch {
      return {
        ok: false,
        response: json(
          { ok: false, code: 'wallet_session_unavailable', message: 'Wallet Session is unavailable' },
          { status: 503 },
        ),
      };
    }
  };

  async function requirePasskeyStepUp(input: {
    walletId: string;
    stepUp: AuthPasskeyStepUpRequest;
  }): Promise<{ ok: true } | { ok: false; response: Response }> {
    const result = await ctx.service.webAuthn.verifyWebAuthnLogin(input.stepUp);
    if (!result.ok) {
      return {
        ok: false,
        response: json(result, { status: result.code === 'internal' ? 500 : 400 }),
      };
    }
    if (String(result.userId).trim() !== input.walletId) {
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
    const sess = await requireWalletSession();
    if (!sess.ok) return sess.response;
    const out = await ctx.service.identity.listIdentities({ userId: sess.walletId });
    return json(out, { status: out.ok ? 200 : out.code === 'internal' ? 500 : 400 });
  }

  if (ctx.method === 'POST' && (ctx.pathname === '/auth/link' || ctx.pathname === '/auth/unlink')) {
    const body = await readJson(ctx.request);
    const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;
    const parsed = parseAuthIdentityMutationRequest({ pathname: ctx.pathname, body, origin });
    if (!parsed) return null;
    if (!parsed.ok) {
      return json(parsed.body, { status: parsed.status });
    }

    const command = parsed.request;
    const sess = await requireWalletSession();
    if (!sess.ok) return sess.response;

    const stepUpRequest = command.request.stepUp;
    const stepUp = await requirePasskeyStepUp({ walletId: sess.walletId, stepUp: stepUpRequest });
    if (!stepUp.ok) return stepUp.response;
    await ctx.service.emailOtp.markEmailOtpStrongAuthSatisfied({ walletId: sess.walletId });

    switch (command.kind) {
      case 'link': {
        const verified = await ctx.service.identity.verifyGoogleLogin({
          idToken: command.request.idToken,
        });
        if (!verified.ok || !verified.verified || !verified.providerSubject) {
          return json(verified, { status: verified.code === 'internal' ? 500 : 400 });
        }
        const subject = verified.providerSubject;

        const linked = await ctx.service.identity.linkIdentity({
          userId: sess.walletId,
          subject,
          allowMoveIfSoleIdentity: true,
        });
        if (!linked.ok) {
          return json(linked, { status: linked.code === 'internal' ? 500 : 400 });
        }
        const identities = await ctx.service.identity.listIdentities({ userId: sess.walletId });
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
      case 'unlink':
        break;
      default:
        assertNeverAuthIdentityMutation(command);
    }

    const subject = command.request.subject;
    if (subject.startsWith('near:')) {
      return json(
        { ok: false, code: 'not_supported', message: 'near: subjects cannot be unlinked' },
        { status: 400 },
      );
    }
    const out = await ctx.service.identity.unlinkIdentity({ userId: sess.walletId, subject });
    if (!out.ok) {
      return json(out, { status: out.code === 'internal' ? 500 : 400 });
    }
    const identities = await ctx.service.identity.listIdentities({ userId: sess.walletId });
    const baseBody = {
      ok: true,
      unlinked: true,
      subject,
      ...(identities.ok ? { identities: identities.subjects } : {}),
    };
    return json(baseBody, { status: 200 });
  }

  if (ctx.method !== 'POST') return null;

  const parsedRoute = parseAuthProviderActionPath(ctx.pathname);
  if (!parsedRoute) return null;
  const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;

  switch (parsedRoute.kind) {
    case 'passkey_options': {
      const parsed = parsePasskeyLoginOptionsRequest(await readJson(ctx.request));
      if (!parsed.ok) return json(parsed.body, { status: parsed.status });
      const result = await ctx.service.webAuthn.createWebAuthnLoginOptions(parsed.request);
      return json(result, { status: result.ok ? 200 : result.code === 'internal' ? 500 : 400 });
    }
    case 'passkey_verify': {
      const parsed = parsePasskeyLoginVerifyRequest({
        body: await readJson(ctx.request),
        origin,
      });
      if (!parsed.ok) return json(parsed.body, { status: parsed.status });
      const result = await ctx.service.webAuthn.verifyWebAuthnLogin(parsed.request);
      if (!result.ok || !result.verified) {
        return json(result, { status: result.code === 'internal' ? 500 : 400 });
      }

      return json({ ok: true, verified: true }, { status: 200 });
    }
    case 'google_options': {
      const publicConfig = ctx.service.identity.getGoogleOidcPublicConfig();
      return json({ ok: true, ...publicConfig }, { status: 200 });
    }
    case 'github_options': {
      const publicConfig = ctx.service.identity.getGithubOAuthPublicConfig();
      return json({ ok: true, ...publicConfig }, { status: 200 });
    }
    case 'google_verify': {
      const parsed = parseGoogleLoginVerifyRequest(await readJson(ctx.request));
      if (!parsed.ok) return json(parsed.body, { status: parsed.status });
      const runtimePolicyScope = await resolveThresholdRuntimePolicyScope({
        explicitScopeRaw: undefined,
        projectEnvironmentIdRaw: parsed.request.projectEnvironmentId,
        headers: ctx.request.headers,
        origin,
        publishableKeyAuth: ctx.opts.publishableKeyAuth,
        orgProjectEnv: ctx.opts.orgProjectEnv,
      });
      if (!runtimePolicyScope.ok) {
        return json(
          { ok: false, code: runtimePolicyScope.code, message: runtimePolicyScope.message },
          { status: runtimePolicyScope.status },
        );
      }
      if (!runtimePolicyScope.scope) {
        return json(
          {
            ok: false,
            code: 'runtime_policy_scope_unavailable',
            message: 'Google Email OTP requires an active managed runtime policy scope',
          },
          { status: 500 },
        );
      }
      const result = await ctx.service.identity.verifyGoogleLogin(parsed.request);
      if (!result.ok || !result.verified || !result.providerSubject) {
        return json(result, { status: result.code === 'internal' ? 500 : 400 });
      }
      const resolution = await ctx.service.identity.resolveGoogleEmailOtpSession({
        providerSubject: result.providerSubject,
        email: result.email,
        accountMode: parsed.request.accountMode,
        runtimePolicyScope: runtimePolicyScope.scope,
        restartRegistrationOffer: parsed.request.restartRegistrationOffer,
      });
      return json(resolution, {
        status: resolution.ok ? 200 : resolution.code === 'wallet_id_collision' ? 409 : 400,
      });
    }
    default:
      return assertNeverAuthProviderAction(parsedRoute);
  }
}
