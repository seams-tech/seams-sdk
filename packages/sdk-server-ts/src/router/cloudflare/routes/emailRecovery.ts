import type { CloudflareRouterApiContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import { signEmailRecoveryThresholdSessionJwt } from '../../emailRecoveryThresholdSession';
import {
  parseFinalizeEmailRecoveryEd25519Request,
  parsePrepareEmailRecoveryRequest,
  parseRespondEmailRecoveryEd25519Request,
  parseRespondEmailRecoveryEcdsaRequest,
} from '../../emailRecoveryRequestValidation';

export async function handleEmailRecoveryPrepare(
  ctx: CloudflareRouterApiContext,
): Promise<Response | null> {
  if (
    ctx.method !== 'POST' ||
    (ctx.pathname !== '/email-recovery/prepare' &&
      ctx.pathname !== '/email-recovery/ed25519/respond' &&
      ctx.pathname !== '/email-recovery/ed25519/finalize' &&
      ctx.pathname !== '/email-recovery/ecdsa/respond')
  ) {
    return null;
  }

  const emailRecovery = ctx.opts.emailRecovery;
  if (!emailRecovery) return null;

  const body = await readJson(ctx.request);
  const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;
  const isPrepare = ctx.pathname === '/email-recovery/prepare';
  if (isPrepare) {
    const parsed = parsePrepareEmailRecoveryRequest({ body, origin });
    if (!parsed.ok) return json(parsed.body, { status: parsed.status });
    const result = await emailRecovery.authService.prepareEmailRecovery(parsed.request);
    if (result.ok) {
      const signed = await signEmailRecoveryThresholdSessionJwt({
        result,
        session: ctx.opts.session,
      });
      if (!signed.ok) return json(signed.body, { status: signed.status });
    }
    return json(result, { status: result.ok ? 200 : result.code === 'internal' ? 500 : 400 });
  }

  if (ctx.pathname === '/email-recovery/ed25519/respond') {
    const parsed = parseRespondEmailRecoveryEd25519Request(body);
    if (!parsed.ok) return json(parsed.body, { status: parsed.status });
    const result = await emailRecovery.authService.respondEmailRecoveryEd25519(parsed.request);
    return json(result, { status: result.ok ? 200 : result.code === 'internal' ? 500 : 400 });
  }

  if (ctx.pathname === '/email-recovery/ed25519/finalize') {
    const parsed = parseFinalizeEmailRecoveryEd25519Request(body);
    if (!parsed.ok) return json(parsed.body, { status: parsed.status });
    const result = await emailRecovery.authService.finalizeEmailRecoveryEd25519(parsed.request);
    if (result.ok) {
      const signed = await signEmailRecoveryThresholdSessionJwt({
        result,
        session: ctx.opts.session,
      });
      if (!signed.ok) return json(signed.body, { status: signed.status });
    }
    return json(result, { status: result.ok ? 200 : result.code === 'internal' ? 500 : 400 });
  }

  const parsed = parseRespondEmailRecoveryEcdsaRequest(body);
  if (!parsed.ok) return json(parsed.body, { status: parsed.status });
  const result = await emailRecovery.authService.respondEmailRecoveryEcdsa(parsed.request);
  if (result.ok) {
    const signed = await signEmailRecoveryThresholdSessionJwt({
      result,
      session: ctx.opts.session,
    });
    if (!signed.ok) return json(signed.body, { status: signed.status });
  }
  return json(result, { status: result.ok ? 200 : result.code === 'internal' ? 500 : 400 });
}
