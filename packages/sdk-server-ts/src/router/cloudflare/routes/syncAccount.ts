import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { isObject, json, readJson } from '../http';
import {
  parseRouterAbEd25519WalletSessionJwtSessionInfo,
  signRouterAbEd25519WalletSessionJwt,
} from '../../commonRouterUtils';

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
        rpId: result.rpId,
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
