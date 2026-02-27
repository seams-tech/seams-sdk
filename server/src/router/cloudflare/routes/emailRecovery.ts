import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { isObject, json, readJson } from '../http';

export async function handleEmailRecoveryPrepare(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/email-recovery/prepare') return null;

  const body = await readJson(ctx.request);
  if (!isObject(body)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
      { status: 400 },
    );
  }

  const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;
  const result = await ctx.service.prepareEmailRecovery({
    ...(body as any),
    ...(origin ? { expected_origin: origin } : {}),
  });
  if (result.ok && result.thresholdEd25519?.session) {
    const sessionAdapter = ctx.opts.session;
    if (!sessionAdapter) {
      return json(
        {
          ok: false,
          code: 'sessions_disabled',
          message: 'Session signing is not configured on this server',
        },
        { status: 500 },
      );
    }

    const thresholdSession = result.thresholdEd25519.session;
    const sessionKind = String(thresholdSession.sessionKind || '')
      .trim()
      .toLowerCase();
    if (sessionKind !== 'jwt') {
      return json(
        {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_kind must be jwt',
        },
        { status: 400 },
      );
    }

    const accountId = String(result.accountId || '').trim();
    const rpId = String((body as Record<string, unknown>).rp_id || '').trim();
    const relayerKeyId = String(result.thresholdEd25519.relayerKeyId || '').trim();
    const sessionId = String(thresholdSession.sessionId || '').trim();
    const thresholdExpiresAtMs = Number(thresholdSession.expiresAtMs);
    const participantIds = Array.isArray(thresholdSession.participantIds)
      ? thresholdSession.participantIds
      : Array.isArray(result.thresholdEd25519.participantIds)
        ? result.thresholdEd25519.participantIds
        : [];
    if (
      !accountId ||
      !rpId ||
      !relayerKeyId ||
      !sessionId ||
      !Number.isFinite(thresholdExpiresAtMs) ||
      thresholdExpiresAtMs <= 0 ||
      participantIds.length < 2
    ) {
      return json(
        {
          ok: false,
          code: 'internal',
          message: 'invalid thresholdEd25519 session payload for jwt signing',
        },
        { status: 500 },
      );
    }
    const nowSec = Math.floor(Date.now() / 1000);
    const expSec = Math.floor(thresholdExpiresAtMs / 1000);
    const jwt = await sessionAdapter.signJwt(accountId, {
      kind: 'threshold_ed25519_session_v1',
      sessionId,
      relayerKeyId,
      rpId,
      participantIds,
      thresholdExpiresAtMs,
      iat: nowSec,
      exp: expSec,
    });
    result.thresholdEd25519.session.jwt = jwt;
  }
  return json(result, { status: result.ok ? 200 : result.code === 'internal' ? 500 : 400 });
}
