import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { isObject, json, readJson } from '../http';
import { signThresholdSessionJwt } from '../../commonRouterUtils';

export async function handleLinkDevice(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method === 'GET' && ctx.pathname.startsWith('/link-device/session/')) {
    const sessionId = ctx.pathname.slice('/link-device/session/'.length);
    const result = await ctx.service.getLinkDeviceSession({ sessionId });
    const status = result.ok
      ? 200
      : result.code === 'not_found'
        ? 404
        : result.code === 'internal'
          ? 500
          : 400;
    return json(result, { status });
  }

  if (ctx.method === 'POST' && ctx.pathname === '/link-device/session') {
    const body = await readJson(ctx.request);
    if (!isObject(body)) {
      return json(
        { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
        { status: 400 },
      );
    }
    const result = await ctx.service.registerLinkDeviceSession(body as any);
    const status = result.ok ? 200 : result.code === 'internal' ? 500 : 400;
    return json(result, { status });
  }

  if (ctx.method === 'POST' && ctx.pathname === '/link-device/session/claim') {
    const body = await readJson(ctx.request);
    if (!isObject(body)) {
      return json(
        { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
        { status: 400 },
      );
    }
    const result = await ctx.service.claimLinkDeviceSession(body as any);
    const status = result.ok
      ? 200
      : result.code === 'not_found'
        ? 404
        : result.code === 'internal'
          ? 500
          : 400;
    return json(result, { status });
  }

  if (ctx.method !== 'POST' || ctx.pathname !== '/link-device/prepare') return null;

  const body = await readJson(ctx.request);
  if (!isObject(body)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
      { status: 400 },
    );
  }

  const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;
  const result = await ctx.service.prepareLinkDevice({
    ...(body as any),
    ...(origin ? { expected_origin: origin } : {}),
  });
  if (result.ok && result.thresholdEd25519?.session) {
    const signed = await signThresholdSessionJwt({
      session: ctx.opts.session,
      kind: 'threshold_ed25519_session_v1',
      userId: result.accountId,
      rpId: (body as Record<string, unknown>).rp_id,
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
  if (result.ok && result.thresholdEcdsa?.session) {
    const signed = await signThresholdSessionJwt({
      session: ctx.opts.session,
      kind: 'threshold_ecdsa_session_v1',
      userId: result.accountId,
      rpId: (body as Record<string, unknown>).rp_id,
      relayerKeyId: result.thresholdEcdsa.relayerKeyId,
      sessionInfo: result.thresholdEcdsa.session,
      fallbackParticipantIds: result.thresholdEcdsa.participantIds,
      requireJwtErrorMessage: 'threshold_ecdsa.session_kind must be jwt',
      invalidPayloadErrorMessage: 'invalid thresholdEcdsa session payload for jwt signing',
    });
    if (!signed.ok) {
      return json(
        { ok: false, code: signed.code, message: signed.message },
        { status: signed.status },
      );
    }
    result.thresholdEcdsa.session.jwt = signed.jwt;
  }
  return json(result, { status: result.ok ? 200 : result.code === 'internal' ? 500 : 400 });
}
