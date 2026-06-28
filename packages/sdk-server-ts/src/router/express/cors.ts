import type { Request, Response, Router as ExpressRouter } from 'express';
import { buildCorsOrigins, normalizeCorsOrigin } from '../../core/SessionService';
import type { RouterApiOptions } from '../routerApi';

const CORS_ALLOW_METHODS = 'GET,POST,PUT,PATCH,DELETE,OPTIONS';
const CORS_ALLOW_HEADERS =
  'Content-Type,Authorization,X-Seams-Benchmark-Diagnostics,X-Seams-Environment-Id,X-Environment-Id,X-Console-Org-Id,X-Console-User-Id,X-Console-Roles,X-Console-Project-Id,X-Console-Environment-Id,X-Console-Stripe-Webhook-Secret';

function withCors(res: Response, opts?: RouterApiOptions, req?: Request): void {
  const pathname = String((req as any)?.path || '').trim();

  // Public CORS: allow any origin to read `/healthz` and `/readyz`.
  // These endpoints only expose non-sensitive deployment metadata and are used by SDKs
  // for auto-discovery (e.g., correct relayerAccount postfix).
  if (pathname === '/healthz' || pathname === '/readyz') {
    res.set('Access-Control-Allow-Origin', '*');
    (res as any).removeHeader?.('Access-Control-Allow-Credentials');
    res.set('Access-Control-Allow-Methods', CORS_ALLOW_METHODS);
    res.set('Access-Control-Allow-Headers', CORS_ALLOW_HEADERS);
    return;
  }

  if (!opts?.corsOrigins) return;

  let allowedOrigin: string | '*' | undefined;
  const normalized = buildCorsOrigins(...(opts.corsOrigins || []));
  if (normalized === '*') {
    allowedOrigin = '*';
    res.set('Access-Control-Allow-Origin', '*');
  } else if (Array.isArray(normalized)) {
    const originRaw = String((req as any)?.headers?.origin || '').trim();
    const originNormalized = normalizeCorsOrigin(originRaw);
    if (originRaw && originNormalized && normalized.includes(originNormalized)) {
      allowedOrigin = originRaw;
      res.set('Access-Control-Allow-Origin', originRaw);
      res.set('Vary', 'Origin');
    }
  }

  res.set('Access-Control-Allow-Methods', CORS_ALLOW_METHODS);
  res.set('Access-Control-Allow-Headers', CORS_ALLOW_HEADERS);
  // Only advertise credentials when we echo back a specific origin (not '*')
  if (allowedOrigin && allowedOrigin !== '*') {
    res.set('Access-Control-Allow-Credentials', 'true');
  }
}

export function installCors(router: ExpressRouter, opts: RouterApiOptions): void {
  // Optional CORS: implemented here to keep setup simple for example relayers.
  // If you prefer custom CORS middleware, omit `corsOrigins` and wire your own.
  router.use((req: Request, res: Response, next: any) => {
    withCors(res, opts, req);
    const method = String((req as any)?.method || '').toUpperCase();
    const pathname = String((req as any)?.path || '').trim();
    const isPublicPreflight = pathname === '/healthz' || pathname === '/readyz';
    if ((opts.corsOrigins || isPublicPreflight) && method === 'OPTIONS') {
      res.status(204).send('');
      return;
    }
    next();
  });
}
