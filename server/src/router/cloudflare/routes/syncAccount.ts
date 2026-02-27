import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { isObject, json, readJson } from '../http';
import { signThresholdSessionJwt } from '../../commonRouterUtils';

export async function handleSyncAccount(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'POST') return null;

  if (ctx.pathname === '/sync-account/options') {
    const body = await readJson(ctx.request);
    if (!isObject(body)) {
      return json(
        { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
        { status: 400 },
      );
    }
    const result = await ctx.service.createWebAuthnSyncAccountOptions(body as any);
    return json(result, { status: result.ok ? 200 : result.code === 'internal' ? 500 : 400 });
  }

  if (ctx.pathname === '/sync-account/verify') {
    const body = await readJson(ctx.request);
    if (!isObject(body)) {
      return json(
        { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
        { status: 400 },
      );
    }
    const challengeId = String(
      (body as any).challengeId ?? (body as any).challenge_id ?? '',
    ).trim();
    if (!challengeId) {
      return json(
        { ok: false, code: 'invalid_body', message: 'challengeId is required' },
        { status: 400 },
      );
    }
    if (!isObject((body as any).webauthn_authentication)) {
      return json(
        { ok: false, code: 'invalid_body', message: 'webauthn_authentication is required' },
        { status: 400 },
      );
    }
    const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;
    const result = await ctx.service.verifyWebAuthnSyncAccount({
      challengeId,
      webauthn_authentication: (body as any).webauthn_authentication,
      ...(isObject((body as any).threshold_ed25519)
        ? { threshold_ed25519: (body as any).threshold_ed25519 }
        : {}),
      expected_origin: origin,
    });
    if (result.ok && result.verified && result.thresholdEd25519?.session) {
      const signed = await signThresholdSessionJwt({
        session: ctx.opts.session,
        kind: 'threshold_ed25519_session_v1',
        userId: result.accountId,
        rpId: result.rpId,
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
    return json(result, {
      status: result.ok && result.verified ? 200 : result.code === 'internal' ? 500 : 400,
    });
  }

  return null;
}
