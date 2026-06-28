import { buildCorsOrigins, normalizeCorsOrigin } from '../../core/SessionService';
import type { RouterApiOptions } from '../routerApi';

const CORS_ALLOW_METHODS = 'GET,POST,PUT,PATCH,DELETE,OPTIONS';
const CORS_ALLOW_HEADERS =
  'Content-Type,Authorization,X-Seams-Benchmark-Diagnostics,X-Seams-Environment-Id,X-Environment-Id,X-Console-Org-Id,X-Console-User-Id,X-Console-Roles,X-Console-Project-Id,X-Console-Environment-Id,X-Console-Stripe-Webhook-Secret';

export function json(
  body: unknown,
  init?: ResponseInit,
  extraHeaders?: Record<string, string>,
): Response {
  const headers = new Headers({ 'Content-Type': 'application/json; charset=utf-8' });

  // Merge init.headers into our base headers (ResponseInit headers are otherwise overwritten).
  const initHeaders = init?.headers;
  if (initHeaders) {
    try {
      new Headers(initHeaders).forEach((v, k) => headers.set(k, v));
    } catch {}
  }

  if (extraHeaders) {
    for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v);
  }

  const { headers: _omit, ...rest } = init || {};
  return new Response(JSON.stringify(body), { status: 200, ...rest, headers });
}

export function withCors(headers: Headers, opts?: RouterApiOptions, request?: Request): void {
  const pathname = request ? new URL(request.url).pathname : '';

  // Public CORS: allow any origin to read `/healthz` and `/readyz`.
  // These endpoints only expose non-sensitive deployment metadata and are used by SDKs
  // for auto-discovery (e.g., correct relayerAccount postfix).
  if (pathname === '/healthz' || pathname === '/readyz') {
    headers.set('Access-Control-Allow-Origin', '*');
    headers.delete('Access-Control-Allow-Credentials');
    headers.set('Access-Control-Allow-Methods', CORS_ALLOW_METHODS);
    headers.set('Access-Control-Allow-Headers', CORS_ALLOW_HEADERS);
    return;
  }

  if (!opts?.corsOrigins) return;
  let allowedOrigin: string | '*' | undefined;
  const normalized = buildCorsOrigins(...(opts.corsOrigins || []));
  if (normalized === '*') {
    allowedOrigin = '*';
    headers.set('Access-Control-Allow-Origin', '*');
  } else if (Array.isArray(normalized)) {
    const originRaw = String(request?.headers.get('Origin') || '').trim();
    const originNormalized = normalizeCorsOrigin(originRaw);
    if (originRaw && originNormalized && normalized.includes(originNormalized)) {
      allowedOrigin = originRaw;
      headers.set('Access-Control-Allow-Origin', originRaw);
      headers.append('Vary', 'Origin');
    }
  }
  headers.set('Access-Control-Allow-Methods', CORS_ALLOW_METHODS);
  headers.set('Access-Control-Allow-Headers', CORS_ALLOW_HEADERS);
  // Only advertise credentials when we echo back a specific origin (not '*')
  if (allowedOrigin && allowedOrigin !== '*') {
    headers.set('Access-Control-Allow-Credentials', 'true');
  }
}

export function toResponse(out: {
  status: number;
  headers: Record<string, string>;
  body: string;
}): Response {
  return new Response(out.body, { status: out.status, headers: out.headers });
}

export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null;
}

export async function readJson(request: Request): Promise<unknown> {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

export function headersToRecord(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((v, k) => {
    out[k] = v;
  });
  return out;
}
