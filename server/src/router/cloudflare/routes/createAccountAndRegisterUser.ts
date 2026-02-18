import type { CreateAccountAndRegisterRequest, CreateAccountAndRegisterResult } from '../../../core/types';
import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { isObject, json, readJson } from '../http';

export async function handleCreateAccountAndRegisterUser(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/registration/bootstrap') return null;

  const body = await readJson(ctx.request);
  if (!isObject(body)) {
    return json({ code: 'invalid_body', message: 'JSON body required' }, { status: 400 });
  }

  const new_account_id = typeof body.new_account_id === 'string' ? body.new_account_id : '';
  const new_public_key = typeof body.new_public_key === 'string' ? String(body.new_public_key || '').trim() : '';
  const device_number = typeof (body as Record<string, unknown>).device_number === 'number'
    ? (body as Record<string, unknown>).device_number
    : Number((body as Record<string, unknown>).device_number);
  const threshold_ed25519 = isObject((body as Record<string, unknown>).threshold_ed25519)
    ? (body as Record<string, unknown>).threshold_ed25519
    : undefined;
  const threshold_ecdsa = isObject((body as Record<string, unknown>).threshold_ecdsa)
    ? (body as Record<string, unknown>).threshold_ecdsa
    : undefined;
  const rp_id = typeof (body as Record<string, unknown>).rp_id === 'string'
    ? String((body as Record<string, unknown>).rp_id || '').trim()
    : '';
  const webauthn_registration = isObject(body.webauthn_registration) ? body.webauthn_registration : null;
  const authenticator_options = isObject((body as Record<string, unknown>).authenticator_options)
    ? (body as Record<string, unknown>).authenticator_options
    : undefined;

  if (!new_account_id) {
    return json({ code: 'invalid_body', message: 'Missing or invalid new_account_id' }, { status: 400 });
  }
  if (!rp_id) {
    return json({ code: 'invalid_body', message: 'Missing or invalid rp_id' }, { status: 400 });
  }
  if (!webauthn_registration) {
    return json({ code: 'invalid_body', message: 'Missing or invalid webauthn_registration' }, { status: 400 });
  }

  const input = {
    new_account_id,
    ...(new_public_key ? { new_public_key } : {}),
    device_number,
    ...(threshold_ed25519 ? { threshold_ed25519 } : {}),
    ...(threshold_ecdsa ? { threshold_ecdsa } : {}),
    rp_id,
    webauthn_registration,
    expected_origin: ctx.request.headers.get('origin') || ctx.request.headers.get('Origin') || undefined,
    authenticator_options,
  } as unknown as CreateAccountAndRegisterRequest;

  const result = await ctx.service.createAccountAndRegisterUser(input);
  const response: CreateAccountAndRegisterResult = result;
  if (!response.success) return json(response, { status: 400 });

  const session = ctx.opts.session;
  if (!session) return json(response, { status: 200 });

  const signThresholdSessionJwt = async (args: {
    kind: 'threshold_ed25519_session_v1' | 'threshold_ecdsa_session_v1';
    userId: string;
    sessionId: string;
    relayerKeyId: string;
    rpId: string;
    participantIds: number[];
    thresholdExpiresAtMs: number;
  }): Promise<string> => {
    const nowSec = Math.floor(Date.now() / 1000);
    const expSec = Math.floor(args.thresholdExpiresAtMs / 1000);
    return await session.signJwt(args.userId, {
      kind: args.kind,
      sessionId: args.sessionId,
      relayerKeyId: args.relayerKeyId,
      rpId: args.rpId,
      participantIds: args.participantIds,
      thresholdExpiresAtMs: args.thresholdExpiresAtMs,
      iat: nowSec,
      exp: expSec,
    });
  };

  if (response.thresholdEd25519?.session) {
    const sessionInfo = response.thresholdEd25519.session;
    const sessionKind = String(sessionInfo.sessionKind || '').trim().toLowerCase();
    if (sessionKind !== 'jwt') {
      return json({ success: false, error: 'threshold_ed25519.session_kind must be jwt' }, { status: 400 });
    }
    const sessionId = String(sessionInfo.sessionId || '').trim();
    const relayerKeyId = String(response.thresholdEd25519.relayerKeyId || '').trim();
    const thresholdExpiresAtMs = Number(sessionInfo.expiresAtMs);
    const participantIds = Array.isArray(sessionInfo.participantIds)
      ? sessionInfo.participantIds
      : Array.isArray(response.thresholdEd25519.participantIds)
        ? response.thresholdEd25519.participantIds
        : [];
    if (!sessionId || !relayerKeyId || !Number.isFinite(thresholdExpiresAtMs) || thresholdExpiresAtMs <= 0 || participantIds.length < 2) {
      return json({ success: false, error: 'invalid thresholdEd25519 session payload for jwt signing' }, { status: 500 });
    }
    const jwt = await signThresholdSessionJwt({
      kind: 'threshold_ed25519_session_v1',
      userId: new_account_id,
      sessionId,
      relayerKeyId,
      rpId: rp_id,
      participantIds,
      thresholdExpiresAtMs,
    });
    response.thresholdEd25519.session.jwt = jwt;
  }

  if (response.thresholdEcdsa?.session) {
    const sessionInfo = response.thresholdEcdsa.session;
    const sessionKind = String(sessionInfo.sessionKind || '').trim().toLowerCase();
    if (sessionKind !== 'jwt') {
      return json({ success: false, error: 'threshold_ecdsa.session_kind must be jwt' }, { status: 400 });
    }
    const sessionId = String(sessionInfo.sessionId || '').trim();
    const relayerKeyId = String(response.thresholdEcdsa.relayerKeyId || '').trim();
    const thresholdExpiresAtMs = Number(sessionInfo.expiresAtMs);
    const participantIds = Array.isArray(sessionInfo.participantIds)
      ? sessionInfo.participantIds
      : Array.isArray(response.thresholdEcdsa.participantIds)
        ? response.thresholdEcdsa.participantIds
        : [];
    if (!sessionId || !relayerKeyId || !Number.isFinite(thresholdExpiresAtMs) || thresholdExpiresAtMs <= 0 || participantIds.length < 2) {
      return json({ success: false, error: 'invalid thresholdEcdsa session payload for jwt signing' }, { status: 500 });
    }
    const jwt = await signThresholdSessionJwt({
      kind: 'threshold_ecdsa_session_v1',
      userId: new_account_id,
      sessionId,
      relayerKeyId,
      rpId: rp_id,
      participantIds,
      thresholdExpiresAtMs,
    });
    response.thresholdEcdsa.session.jwt = jwt;
  }

  return json(response, { status: 200 });
}
