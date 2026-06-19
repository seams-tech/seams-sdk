import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { isObject, json, readJson } from '../http';
import {
  parseRouterAbEd25519WalletSessionJwtSessionInfo,
  signRouterAbEd25519WalletSessionJwt,
} from '../../commonRouterUtils';

export async function handleEmailRecoveryPrepare(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (
    ctx.method !== 'POST' ||
    (ctx.pathname !== '/email-recovery/prepare' &&
      ctx.pathname !== '/email-recovery/ecdsa/respond')
  ) {
    return null;
  }

  const body = await readJson(ctx.request);
  if (!isObject(body)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
      { status: 400 },
    );
  }

  const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;
  const result =
    ctx.pathname === '/email-recovery/prepare'
      ? await ctx.service.prepareEmailRecovery({
          ...(body as any),
          ...(origin ? { expected_origin: origin } : {}),
        })
      : await ctx.service.respondEmailRecoveryEcdsa(body as any);
  if (result.ok && result.thresholdEd25519?.session) {
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
    const sessionInfo = parseRouterAbEd25519WalletSessionJwtSessionInfo(
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
      userId: result.accountId,
      rpId:
        ctx.pathname === '/email-recovery/prepare'
          ? (body as Record<string, unknown>).rp_id
          : (result as any).ecdsa?.bootstrap?.rpId,
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
  return json(result, { status: result.ok ? 200 : result.code === 'internal' ? 500 : 400 });
}
