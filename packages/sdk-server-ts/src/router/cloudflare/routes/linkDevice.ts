import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import {
  parseRouterAbEd25519BootstrapSessionJwtSessionInfo,
  signRouterAbEd25519WalletSessionJwt,
} from '../../commonRouterUtils';
import {
  parseClaimLinkDeviceSessionRequest,
  parsePrepareLinkDeviceRequest,
  parseRegisterLinkDeviceSessionRequest,
  parseRespondLinkDeviceEcdsaRequest,
} from '../../linkDeviceRequestValidation';

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
    const parsed = parseRegisterLinkDeviceSessionRequest(body);
    if (!parsed.ok) return json(parsed.body, { status: parsed.status });
    const result = await ctx.service.registerLinkDeviceSession(parsed.request);
    const status = result.ok ? 200 : result.code === 'internal' ? 500 : 400;
    return json(result, { status });
  }

  if (ctx.method === 'POST' && ctx.pathname === '/link-device/session/claim') {
    const body = await readJson(ctx.request);
    const parsed = parseClaimLinkDeviceSessionRequest(body);
    if (!parsed.ok) return json(parsed.body, { status: parsed.status });
    const result = await ctx.service.claimLinkDeviceSession(parsed.request);
    const status = result.ok
      ? 200
      : result.code === 'not_found'
        ? 404
        : result.code === 'internal'
          ? 500
          : 400;
    return json(result, { status });
  }

  if (ctx.method === 'POST' && ctx.pathname === '/link-device/ecdsa/respond') {
    const body = await readJson(ctx.request);
    const parsed = parseRespondLinkDeviceEcdsaRequest(body);
    if (!parsed.ok) return json(parsed.body, { status: parsed.status });
    const result = await ctx.service.respondLinkDeviceEcdsa(parsed.request);
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
  const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;
  const parsed = parsePrepareLinkDeviceRequest({ body, origin });
  if (!parsed.ok) return json(parsed.body, { status: parsed.status });
  const result = await ctx.service.prepareLinkDevice(parsed.request);
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
      rpId: parsed.request.rp_id,
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
