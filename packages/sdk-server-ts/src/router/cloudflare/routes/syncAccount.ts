import type { CloudflareRouterApiContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import {
  parseRouterAbEd25519BootstrapSessionJwtSessionInfo,
  signRouterAbEd25519WalletSessionJwt,
} from '../../commonRouterUtils';
import {
  parseSyncAccountOptionsRequest,
  parseSyncAccountVerifyRequest,
} from '../../syncAccountRequestValidation';

export async function handleSyncAccount(ctx: CloudflareRouterApiContext): Promise<Response | null> {
  if (ctx.method !== 'POST') return null;

  if (ctx.pathname === '/sync-account/options') {
    const body = await readJson(ctx.request);
    const parsed = parseSyncAccountOptionsRequest(body);
    if (!parsed.ok) return json(parsed.body, { status: parsed.status });
    const result = await ctx.service.createWebAuthnSyncAccountOptions(parsed.request);
    return json(result, { status: result.ok ? 200 : result.code === 'internal' ? 500 : 400 });
  }

  if (ctx.pathname === '/sync-account/verify') {
    const body = await readJson(ctx.request);
    const parsed = parseSyncAccountVerifyRequest({
      body,
      origin: ctx.request.headers.get('origin'),
    });
    if (!parsed.ok) return json(parsed.body, { status: parsed.status });
    const result = await ctx.service.verifyWebAuthnSyncAccount(parsed.request);
    if (result.ok && result.verified && result.thresholdEd25519?.session) {
      if (result.thresholdEd25519.session.sessionKind !== 'jwt') {
        return json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'threshold_ed25519.session_kind must be jwt',
          },
          { status: 400 },
        );
      }
      const sessionInfo = parseRouterAbEd25519BootstrapSessionJwtSessionInfo(
        result.thresholdEd25519.session,
      );
      if (!sessionInfo) {
        return json(
          {
            ok: false,
            code: 'internal',
            message: 'invalid thresholdEd25519 session payload for jwt signing',
          },
          { status: 500 },
        );
      }
      const signed = await signRouterAbEd25519WalletSessionJwt({
        session: ctx.opts.session,
        userId: sessionInfo.walletId,
        authorityScope: { kind: 'passkey_rp', rpId: result.rpId },
        relayerKeyId: result.thresholdEd25519.relayerKeyId,
        sessionInfo,
        fallbackParticipantIds: result.thresholdEd25519.participantIds,
        requireJwtErrorMessage: 'threshold_ed25519.session_kind must be jwt',
        invalidPayloadErrorMessage: 'invalid thresholdEd25519 session payload for jwt signing',
      });
      if (!signed.ok) {
        return json(
          { ok: false, code: signed.code, message: signed.message },
          { status: signed.status },
        );
      }
      result.thresholdEd25519.session.jwt = signed.jwt;
    }
    return json(result, {
      status: result.ok && result.verified ? 200 : result.code === 'internal' ? 500 : 400,
    });
  }

  return null;
}
