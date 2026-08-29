import type { FetchRouterApiContext } from '../createFetchRouter';
import { json } from '../../../framework/http';
import { extractBearerCredential } from '../../../auth/routerApiKeyAuth';

export async function handleWebAuthnAuthenticators(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'GET') return null;
  if (ctx.pathname !== '/webauthn/authenticators') return null;

  try {
    const token = extractBearerCredential(ctx.request.headers);
    if (!token) {
      return json(
        { ok: false, code: 'unauthorized', message: 'No valid Wallet Session' },
        { status: 401 },
      );
    }
    const nowMs = Date.now();
    const exact =
      await ctx.service.authorizationSessions.readWalletSessionAuthorizationV2ByOperationCredential(
        {
          tenantId: ctx.service.authorizationSessions.tenantId,
          token,
          nowMs,
        },
      );
    if (!exact) {
      return json(
        { ok: false, code: 'unauthorized', message: 'No valid Wallet Session' },
        { status: 401 },
      );
    }

    const rpIdFromQuery = String(
      ctx.url.searchParams.get('rpId') || ctx.url.searchParams.get('rp_id') || '',
    ).trim();

    const result = await ctx.service.webAuthn.listWebAuthnAuthenticatorsForUser({
      userId: String(exact.authorization.session.walletId),
      ...(rpIdFromQuery ? { rpId: rpIdFromQuery } : {}),
    });
    if (!result.ok) {
      const status =
        result.code === 'not_supported' ? 501 : result.code === 'invalid_args' ? 400 : 500;
      return json(result, { status });
    }

    return json(result, { status: 200 });
  } catch (e: any) {
    return json(
      { ok: false, code: 'internal', message: e?.message || 'Internal error' },
      { status: 500 },
    );
  }
}
