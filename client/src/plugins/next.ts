// Minimal Next.js helpers: compose a headers() entry for cross-origin wallet embedding.
// Avoid importing Next types; keep shapes generic.
//
// CSP policy note:
// - We RELAX CSP ONLY FOR NEXT DEV to accommodate the framework's dev runtime (Fast Refresh/overlay),
//   which requires 'unsafe-eval' and inline styles. This relaxation is not required by the Seams SDK itself.
// - In PRODUCTION you should keep a strict CSP: no JS 'unsafe-eval', no inline styles, include
//   "style-src-attr 'none'", and allow only 'wasm-unsafe-eval' for wallet WASM compilation.

import { buildPermissionsPolicy, buildWalletCsp, type CspMode } from './headers';
import { sanitizeOrigins } from './plugin-utils';

export type NextHeader = { key: string; value: string };
export type NextHeaderEntry = { source: string; headers: NextHeader[] };

export function seamsNextHeaders(opts: {
  walletOrigin: string;
  cspMode?: CspMode;
  extraFrameSrc?: string[];
  /** Optional allowlist for script-src (e.g., wallet origin for modulepreload in dev) */
  extraScriptSrc?: string[];
  allowUnsafeEvalDev?: boolean;
  compatibleInDev?: boolean;
}): NextHeaderEntry[] {
  const wallet = opts.walletOrigin;
  const permissions = buildPermissionsPolicy(wallet);
  const isDev = process.env.NODE_ENV !== 'production';
  const mode: CspMode =
    opts.cspMode ?? (isDev && (opts.compatibleInDev ?? true) ? 'compatible' : 'strict');
  const allowUnsafeEval = isDev && (opts.allowUnsafeEvalDev ?? true);
  const csp = buildWalletCsp({
    frameSrc: [wallet, ...(opts.extraFrameSrc || [])],
    scriptSrcAllowlist: [...(opts.extraScriptSrc || [])],
    mode,
    allowUnsafeEval,
  });
  return [
    {
      source: '/:path*',
      headers: [
        { key: 'Permissions-Policy', value: permissions },
        { key: 'Content-Security-Policy', value: csp },
      ],
    },
  ];
}

/**
 * Convenience wrapper for Next.js app origin.
 * Adds Permissions-Policy and a wallet-friendly CSP via Next's headers() API.
 * emitHeaders has no effect for Next.js; kept for parity with Vite wrappers.
 */
export function seamsNextApp(opts: {
  walletOrigin: string;
  emitHeaders?: boolean;
  cspMode?: CspMode;
  extraFrameSrc?: string[];
  extraScriptSrc?: string[];
  allowUnsafeEvalDev?: boolean;
  compatibleInDev?: boolean;
}) {
  if (opts.emitHeaders) {
    console.warn(
      '[seams] seamsNextApp: emitHeaders has no effect in Next.js; headers are applied via next.config.js headers().',
    );
  }
  return (config: any) => {
    const existing = config?.headers;
    return {
      ...config,
      async headers() {
        const user = typeof existing === 'function' ? await existing() : [];
        return [...(user || []), ...seamsNextHeaders(opts)];
      },
    };
  };
}

/**
 * Convenience wrapper for Next.js wallet origin.
 * Same behavior as seamsNextApp — Next.js does not serve the SDK/wallet HTML; this
 * helper only sets headers via headers() so the wallet host can be prepped if you
 * proxy wallet routes through Next in dev.
 */
export function seamsNextWallet(opts: {
  walletOrigin: string;
  emitHeaders?: boolean;
  cspMode?: CspMode;
  extraFrameSrc?: string[];
  extraScriptSrc?: string[];
  allowUnsafeEvalDev?: boolean;
  compatibleInDev?: boolean;
}) {
  if (opts.emitHeaders) {
    console.warn(
      '[seams] seamsNextWallet: emitHeaders has no effect in Next.js; headers are applied via next.config.js headers().',
    );
  }
  return (config: any) => {
    const existing = config?.headers;
    return {
      ...config,
      async headers() {
        const user = typeof existing === 'function' ? await existing() : [];
        return [...(user || []), ...seamsNextHeaders(opts)];
      },
    };
  };
}

// === Well-known (/.well-known/webauthn) helpers for Next.js ===
// These helpers mirror the Vite dev server behavior and expose a server-owned
// static allowlist.

type RorOpts = {
  origins?: string[];
};

function resolveRorParams(opts: RorOpts) {
  return sanitizeOrigins([
    ...(opts.origins || []),
    ...String(process.env.VITE_ROR_ALLOWED_ORIGINS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    String(process.env.VITE_DOCS_ORIGIN || '').trim(),
  ]);
}

/**
 * Pages Router compatible handler (Node runtime).
 * Usage (pages/api/.well-known/webauthn.ts):
 *   export default (req, res) => handleWellKnownRorNode(req, res)
 */
export async function handleWellKnownRorNode(_req: any, res: any, opts: RorOpts = {}) {
  const origins = resolveRorParams(opts);
  res.statusCode = 200;
  res.setHeader?.('Content-Type', 'application/json; charset=utf-8');
  res.setHeader?.('Cache-Control', 'max-age=60, stale-while-revalidate=600');
  res.end?.(JSON.stringify({ origins }));
}

/**
 * App Router compatible handler (Edge/Route Handler style).
 * Usage (app/.well-known/webauthn/route.ts):
 *   export async function GET(req: Request) { return handleWellKnownRorEdge(req) }
 */
export async function handleWellKnownRorEdge(
  _request: Request,
  opts: RorOpts = {},
): Promise<Response> {
  const origins = resolveRorParams(opts);
  return new Response(JSON.stringify({ origins }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'max-age=60, stale-while-revalidate=600',
    },
  });
}
