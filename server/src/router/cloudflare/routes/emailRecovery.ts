import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { isObject, json, readJson } from '../http';
import { signThresholdSessionAuthToken } from '../../commonRouterUtils';

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
    const signed = await signThresholdSessionAuthToken({
      session: ctx.opts.session,
      kind: 'threshold_ed25519_session_v1',
      userId: result.accountId,
      rpId:
        ctx.pathname === '/email-recovery/prepare'
          ? (body as Record<string, unknown>).rp_id
          : (result as any).ecdsa?.bootstrap?.rpId,
      relayerKeyId: result.thresholdEd25519.relayerKeyId,
      sessionInfo: result.thresholdEd25519.session,
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
