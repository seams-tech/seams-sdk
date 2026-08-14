import type { FetchRouterApiContext } from '../createFetchRouter';
import { json } from '../../../framework/http';
import { extractBearerCredential } from '../../../auth/routerApiKeyAuth';

export async function handleNearPublicKeys(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'GET') return null;
  if (ctx.pathname !== '/near/public-keys') return null;

  try {
    const token = extractBearerCredential(ctx.request.headers);
    if (!token) {
      return json(
        { ok: false, code: 'unauthorized', message: 'No valid Wallet Session' },
        { status: 401 },
      );
    }
    const nowMs = Date.now();
    const ecdsa = await ctx.service.authorizationSessions.resolveOpaqueWalletSessionToken({
      tenantId: ctx.service.authorizationSessions.tenantId,
      token,
      curve: 'ecdsa',
      nowMs,
    });
    const walletSession =
      ecdsa ??
      (await ctx.service.authorizationSessions.resolveOpaqueWalletSessionToken({
        tenantId: ctx.service.authorizationSessions.tenantId,
        token,
        curve: 'ed25519',
        nowMs,
      }));
    if (!walletSession) {
      return json(
        { ok: false, code: 'unauthorized', message: 'No valid Wallet Session' },
        { status: 401 },
      );
    }

    const result = await ctx.service.nearFunding.listNearPublicKeysForUser({
      userId: walletSession.authorization.walletId,
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
