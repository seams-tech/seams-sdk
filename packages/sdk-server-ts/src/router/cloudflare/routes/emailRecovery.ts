import type { CloudflareRouterApiContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import { parsePrepareEmailRecoveryRequest } from '../../emailRecoveryRequestValidation';

export async function handleEmailRecoveryPrepare(
  ctx: CloudflareRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/email-recovery/prepare') {
    return null;
  }

  const emailRecovery = ctx.opts.emailRecovery;
  if (!emailRecovery) return null;

  const body = await readJson(ctx.request);
  const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;
  const parsed = parsePrepareEmailRecoveryRequest({ body, origin });
  if (!parsed.ok) return json(parsed.body, { status: parsed.status });
  const result = await emailRecovery.authService.prepareEmailRecovery(parsed.request);
  return json(result, { status: result.ok ? 200 : result.code === 'internal' ? 500 : 400 });
}
