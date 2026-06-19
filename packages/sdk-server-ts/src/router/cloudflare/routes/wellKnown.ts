import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json } from '../http';
import {
  normalizeRorHost,
  resolveWellKnownSigningSessionSealCapabilities,
  sanitizeRorOrigins,
} from '../../ror/normalize';
import { resolveRorRpId } from '../../ror/provider';
import {
  ROUTER_AB_PUBLIC_KEYSET_PATH_V2,
  ROUTER_AB_PUBLIC_KEYSET_WELL_KNOWN_PATH_V2,
} from '@shared/utils/routerAbPublicKeyset';

export async function handleWellKnown(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'GET') return null;
  if (
    ctx.pathname === ROUTER_AB_PUBLIC_KEYSET_WELL_KNOWN_PATH_V2 ||
    ctx.pathname === `${ROUTER_AB_PUBLIC_KEYSET_WELL_KNOWN_PATH_V2}/` ||
    ctx.pathname === ROUTER_AB_PUBLIC_KEYSET_PATH_V2 ||
    ctx.pathname === `${ROUTER_AB_PUBLIC_KEYSET_PATH_V2}/`
  ) {
    const keyset = ctx.opts.routerAbPublicKeyset;
    if (!keyset) {
      return json(
        {
          ok: false,
          code: 'router_ab_public_keyset_not_configured',
          message: 'Router A/B public keyset is not configured',
        },
        { status: 404, headers: { 'Cache-Control': 'max-age=60, stale-while-revalidate=600' } },
      );
    }
    return json(keyset, {
      status: 200,
      headers: { 'Cache-Control': 'max-age=60, stale-while-revalidate=600' },
    });
  }
  if (ctx.pathname !== '/.well-known/webauthn' && ctx.pathname !== '/.well-known/webauthn/')
    return null;

  let origins: string[] = [];
  const signingSessionSeal = resolveWellKnownSigningSessionSealCapabilities(
    ctx.opts.signingSessionSeal,
  );
  try {
    const host = normalizeRorHost(
      ctx.request.headers.get('x-forwarded-host') ||
        ctx.request.headers.get('host') ||
        ctx.url.hostname,
    );
    const rpId = resolveRorRpId({ ror: ctx.opts.ror, host: host || undefined });
    origins =
      rpId && ctx.opts.ror
        ? sanitizeRorOrigins(
            await ctx.opts.ror.provider.getAllowedOrigins({ rpId, ...(host ? { host } : {}) }),
          )
        : [];
  } catch {}

  return json(
    { origins, capabilities: { signingSessionSeal } },
    { status: 200, headers: { 'Cache-Control': 'max-age=60, stale-while-revalidate=600' } },
  );
}
