import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import {
  parseRouterAbEd25519BootstrapSessionJwtSessionInfo,
  signRouterAbEd25519WalletSessionJwt,
} from '../../commonRouterUtils';
import {
  parsePrepareEmailRecoveryRequest,
  parseRespondEmailRecoveryEcdsaRequest,
} from '../../emailRecoveryRequestValidation';

export async function handleEmailRecoveryPrepare(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (
    ctx.method !== 'POST' ||
    (ctx.pathname !== '/email-recovery/prepare' && ctx.pathname !== '/email-recovery/ecdsa/respond')
  ) {
    return null;
  }

  const body = await readJson(ctx.request);
  const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;
  const isPrepare = ctx.pathname === '/email-recovery/prepare';
  const prepareParsed = isPrepare ? parsePrepareEmailRecoveryRequest({ body, origin }) : null;
  if (prepareParsed && !prepareParsed.ok) return json(prepareParsed.body, { status: prepareParsed.status });
  const respondParsed = isPrepare ? null : parseRespondEmailRecoveryEcdsaRequest(body);
  if (respondParsed && !respondParsed.ok) return json(respondParsed.body, { status: respondParsed.status });

  const result = prepareParsed
    ? await ctx.service.prepareEmailRecovery(prepareParsed.request)
    : await ctx.service.respondEmailRecoveryEcdsa(respondParsed!.request);
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
      rpId: prepareParsed ? prepareParsed.request.rp_id : (result as any).walletBinding?.rpId,
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
