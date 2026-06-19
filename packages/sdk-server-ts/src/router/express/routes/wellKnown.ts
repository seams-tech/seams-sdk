import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
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

export function registerWellKnownRoutes(router: ExpressRouter, ctx: ExpressRelayContext): void {
  const routerAbKeysetPaths = [
    ROUTER_AB_PUBLIC_KEYSET_WELL_KNOWN_PATH_V2,
    `${ROUTER_AB_PUBLIC_KEYSET_WELL_KNOWN_PATH_V2}/`,
    ROUTER_AB_PUBLIC_KEYSET_PATH_V2,
    `${ROUTER_AB_PUBLIC_KEYSET_PATH_V2}/`,
  ];
  for (const p of routerAbKeysetPaths) {
    router.get(p, (_req: Request, res: Response) => {
      const keyset = ctx.opts.routerAbPublicKeyset;
      res.set('Content-Type', 'application/json; charset=utf-8');
      res.set('Cache-Control', 'max-age=60, stale-while-revalidate=600');
      if (!keyset) {
        res.status(404).send(
          JSON.stringify({
            ok: false,
            code: 'router_ab_public_keyset_not_configured',
            message: 'Router A/B public keyset is not configured',
          }),
        );
        return;
      }
      res.status(200).send(JSON.stringify(keyset));
    });
  }

  // ROR manifest for Related Origin Requests (wallet-scoped credentials)
  const wellKnownPaths = ['/.well-known/webauthn', '/.well-known/webauthn/'];
  for (const p of wellKnownPaths) {
    router.get(p, async (req: Request, res: Response) => {
      try {
        const headers = req.headers || {};
        const forwardedHostHeader = headers['x-forwarded-host'];
        const hostHeader = headers.host;
        const forwardedHostRaw = String(
          Array.isArray(forwardedHostHeader) ? forwardedHostHeader[0] : forwardedHostHeader || '',
        ).trim();
        const hostFromForwarded = forwardedHostRaw ? forwardedHostRaw.split(',')[0].trim() : '';
        const hostRaw = Array.isArray(hostHeader) ? hostHeader[0] : hostHeader;
        const host = normalizeRorHost(hostFromForwarded || hostRaw || '');
        const rpId = resolveRorRpId({ ror: ctx.opts.ror, host: host || undefined });
        const origins =
          rpId && ctx.opts.ror
            ? sanitizeRorOrigins(
                await ctx.opts.ror.provider.getAllowedOrigins({ rpId, ...(host ? { host } : {}) }),
              )
            : [];
        const signingSessionSeal = resolveWellKnownSigningSessionSealCapabilities(
          ctx.opts.signingSessionSeal,
        );
        res.set('Content-Type', 'application/json; charset=utf-8');
        // Short TTL + SWR so updates propagate while staying cache-friendly
        res.set('Cache-Control', 'max-age=60, stale-while-revalidate=600');
        res.status(200).send(JSON.stringify({ origins, capabilities: { signingSessionSeal } }));
      } catch {
        res
          .status(200)
          .json({ origins: [], capabilities: { signingSessionSeal: { mode: 'none' } } });
      }
    });
  }
}
