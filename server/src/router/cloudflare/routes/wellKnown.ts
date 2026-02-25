import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json } from '../http';
import { normalizeRorHost, sanitizeRorOrigins } from '../../ror/normalize';
import { resolveRorRpId } from '../../ror/provider';

export async function handleWellKnown(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'GET') return null;
  if (ctx.pathname !== '/.well-known/webauthn' && ctx.pathname !== '/.well-known/webauthn/') return null;

  let origins: string[] = [];
  try {
    const host = normalizeRorHost(ctx.request.headers.get('x-forwarded-host') || ctx.request.headers.get('host') || ctx.url.hostname);
    const rpId = resolveRorRpId({ ror: ctx.opts.ror, host: host || undefined });
    origins = (
      rpId && ctx.opts.ror
        ? sanitizeRorOrigins(await ctx.opts.ror.provider.getAllowedOrigins({ rpId, ...(host ? { host } : {}) }))
        : []
    );
  } catch {}

  return json({ origins }, { status: 200, headers: { 'Cache-Control': 'max-age=60, stale-while-revalidate=600' } });
}
