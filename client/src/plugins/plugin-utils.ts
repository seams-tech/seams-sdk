// Small shared helpers for Vite/Next plugins
import * as path from 'node:path';
import * as fs from 'node:fs';
import { createRequire } from 'node:module';
import {
  normalizeWalletHostVariant,
  walletHostScriptFileForVariant,
  type WalletHostVariant,
} from '../core/WalletIframe/hostVariant';

export function addPreconnectLink(res: any, origin?: string) {
  if (!origin) return;
  try {
    const link = `<${origin}>; rel=preconnect; crossorigin`;
    const existing = res.getHeader?.('Link');
    if (!existing) {
      res.setHeader?.('Link', link);
      return;
    }
    if (typeof existing === 'string') {
      if (!existing.includes(link)) res.setHeader?.('Link', existing + ', ' + link);
      return;
    }
    if (Array.isArray(existing)) {
      if (!existing.includes(link)) res.setHeader?.('Link', [...existing, link]);
    }
  } catch {}
}

function withAssetVersion(url: string, assetVersion?: string): string {
  const version = String(assetVersion || '').trim();
  if (!version) return url;
  const sep = url.includes('?') ? '&' : '?';
  return `${url}${sep}v=${encodeURIComponent(version)}`;
}

// Builds wallet service HTML that links only external CSS/JS (no inline),
// so strict CSP (style-src 'self'; style-src-attr 'none') works in dev/prod.
export function buildWalletServiceHtml(
  sdkBasePath: string = '/sdk',
  assetVersion?: string,
  walletHostVariant: WalletHostVariant = 'runtime',
): string {
  const walletServiceCss = withAssetVersion(`${sdkBasePath}/wallet-service.css`, assetVersion);
  const drawerCss = withAssetVersion(`${sdkBasePath}/drawer.css`, assetVersion);
  const txTreeCss = withAssetVersion(`${sdkBasePath}/tx-tree.css`, assetVersion);
  const haloBorderCss = withAssetVersion(`${sdkBasePath}/halo-border.css`, assetVersion);
  const passkeyHaloLoadingCss = withAssetVersion(
    `${sdkBasePath}/passkey-halo-loading.css`,
    assetVersion,
  );
  const componentsCss = withAssetVersion(`${sdkBasePath}/w3a-components.css`, assetVersion);
  const txConfirmerCss = withAssetVersion(`${sdkBasePath}/tx-confirmer.css`, assetVersion);
  const walletShimsJs = withAssetVersion(`${sdkBasePath}/wallet-shims.js`, assetVersion);
  const walletHostScript = withAssetVersion(
    `${sdkBasePath}/${walletHostScriptFileForVariant(normalizeWalletHostVariant(walletHostVariant))}`,
    assetVersion,
  );

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Web3Authn Wallet Service</title>
    <!-- Surface styles are external so strict CSP can keep style-src 'self' -->
    <link rel="stylesheet" href="${walletServiceCss}" />
    <!-- Prefetch component styles so they are warmed without triggering preload warnings -->
    <link rel="prefetch" as="style" href="${drawerCss}" />
    <link rel="prefetch" as="style" href="${txTreeCss}" />
    <link rel="prefetch" as="style" href="${haloBorderCss}" />
    <link rel="prefetch" as="style" href="${passkeyHaloLoadingCss}" />
    <!-- Component theme CSS: shared tokens + component-scoped tokens -->
    <link rel="stylesheet" href="${componentsCss}" />
    <link rel="stylesheet" href="${drawerCss}" />
    <link rel="stylesheet" href="${txTreeCss}" />
    <link rel="stylesheet" href="${txConfirmerCss}" />
    <!-- Minimal shims some ESM bundles expect (externalized to enable strict CSP) -->
    <script src="${walletShimsJs}"></script>
    <!-- Hint the browser to fetch the host script earlier -->
    <link rel="modulepreload" href="${walletHostScript}" crossorigin>
  </head>
  <body>
    <!-- sdkBasePath points to the SDK root (e.g. '/sdk'). Load the host directly. -->
    <script type="module" src="${walletHostScript}"></script>
  </body>
</html>`;
}

// Export viewer HTML is also fully externalized (no inline) to keep CSP strict.
export function buildExportViewerHtml(sdkBasePath: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
    <link rel="stylesheet" href="${sdkBasePath}/wallet-service.css">
    <link rel="stylesheet" href="${sdkBasePath}/w3a-components.css">
    <link rel="stylesheet" href="${sdkBasePath}/drawer.css">
    <link rel="stylesheet" href="${sdkBasePath}/tx-tree.css">
    <link rel="stylesheet" href="${sdkBasePath}/tx-confirmer.css">
    <script src="${sdkBasePath}/wallet-shims.js"></script>
    <link rel="modulepreload" href="${sdkBasePath}/export-private-key-viewer.js" crossorigin>
    <link rel="modulepreload" href="${sdkBasePath}/iframe-export-bootstrap.js" crossorigin>
  </head>
  <body>
    <w3a-drawer id="exp" theme="dark"></w3a-drawer>
    <script type="module" src="${sdkBasePath}/export-private-key-viewer.js" crossorigin></script>
    <script type="module" src="${sdkBasePath}/iframe-export-bootstrap.js" crossorigin></script>
  </body>
</html>`;
}

export function resolveCoepMode(explicit?: 'strict' | 'off'): 'strict' | 'off' {
  if (explicit === 'strict' || explicit === 'off') return explicit;
  const raw = String((globalThis as any)?.process?.env?.VITE_COEP_MODE || '')
    .trim()
    .toLowerCase();
  if (raw === 'strict' || raw === 'on' || raw === '1' || raw === 'require-corp') return 'strict';
  if (raw === 'off' || raw === '0' || raw === 'false') return 'off';
  return 'off';
}

export function applyCoepCorp(res: any) {
  res.setHeader?.('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader?.('Cross-Origin-Resource-Policy', 'cross-origin');
}

export function applyCoepCorpIfNeeded(res: any, coepMode?: 'strict' | 'off') {
  if (resolveCoepMode(coepMode) !== 'off') applyCoepCorp(res);
}

export function echoCorsFromRequest(
  res: any,
  req: any,
  opts: {
    honorExistingAcaOrigin?: boolean;
    allowCredentialsWhenExplicit?: boolean;
    methods?: string;
    headers?: string;
    handlePreflight?: boolean;
  } = {},
) {
  const honorExisting = opts.honorExistingAcaOrigin === true;
  const allowCreds = opts.allowCredentialsWhenExplicit !== false;
  const methods = opts.methods || 'GET,OPTIONS';
  const headers = opts.headers || 'Content-Type,Authorization';
  const handlePreflight = opts.handlePreflight === true;

  const origin = (req?.headers && (req.headers.origin as string)) || '*';
  const hasExisting =
    typeof res.getHeader === 'function' && !!res.getHeader('Access-Control-Allow-Origin');
  if (!honorExisting || !hasExisting) {
    res.setHeader?.('Access-Control-Allow-Origin', origin);
  }
  res.setHeader?.('Vary', 'Origin');
  res.setHeader?.('Access-Control-Allow-Methods', methods);
  res.setHeader?.('Access-Control-Allow-Headers', headers);
  if (origin !== '*' && allowCreds) res.setHeader?.('Access-Control-Allow-Credentials', 'true');
  if (handlePreflight) {
    const method = req?.method && String(req.method).toUpperCase();
    if (method === 'OPTIONS') {
      res.statusCode = 204;
      res.end?.();
      return true;
    }
  }
  return false;
}

/**
 * Log and validate Related Origin Requests (ROR) configuration.
 * - Prints the well-known endpoint and the configured origins list.
 * - Warns if any origins are not absolute (e.g., missing protocol/hostname).
 */
export function logRorConfig(origins: string[], endpoint = '/.well-known/webauthn') {
  if (!Array.isArray(origins) || origins.length === 0) return;
  const invalid: string[] = [];
  for (const o of origins) {
    try {
      const u = new URL(o);
      if (!u.protocol || !u.hostname) invalid.push(o);
    } catch {
      invalid.push(o);
    }
  }
  const msg = `[seams] ROR enabled: GET ${endpoint} -> { origins: [${origins.join(', ')}] }`;
  console.log(msg);
  if (invalid.length > 0) {
    console.warn(
      `[seams] ROR warning: invalid origins: ${invalid.join(
        ', ',
      )} (expected absolute origins like https://app.example.com)`,
    );
  }
}

// Sanitize a dynamic allowlist into a normalized set of absolute origins.
export function sanitizeOrigins(values: unknown): string[] {
  const out = new Set<string>();
  if (Array.isArray(values)) {
    for (const v of values) {
      if (typeof v !== 'string') continue;
      try {
        const u = new URL(v.trim());
        const scheme = u.protocol;
        const host = u.hostname.toLowerCase();
        const port = u.port ? `:${u.port}` : '';
        const isHttps = scheme === 'https:';
        const isLocalhostHttp = scheme === 'http:' && host === 'localhost';
        if (!isHttps && !isLocalhostHttp) continue;
        if ((u.pathname && u.pathname !== '/') || u.search || u.hash) continue;
        out.add(`${scheme}//${host}${port}`);
      } catch {}
    }
  }
  return Array.from(out);
}

/**
 * Infer and set a proper Content-Type header for a given file path.
 * Shared by both app and wallet-iframe dev servers.
 */
export function setContentType(res: any, filePath: string) {
  const ext = path.extname(filePath);
  switch (ext) {
    case '.js':
      res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
      break;
    case '.css':
      res.setHeader('Content-Type', 'text/css; charset=utf-8');
      break;
    case '.map':
    case '.json':
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      break;
    case '.wasm':
      res.setHeader('Content-Type', 'application/wasm');
      break;
    case '.html':
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      break;
    default:
      res.setHeader('Content-Type', 'application/octet-stream');
  }
}

// === Shared path helpers across Vite/Next plugins ===

export { toBasePath } from '@shared/utils/validation';

const requireCjs = createRequire(import.meta.url);

export function resolveSdkDistRoot(explicit?: string): string {
  if (explicit) return path.resolve(explicit);
  const pkgPath = requireCjs.resolve('@seams/sdk/package.json');
  const pkgDir = path.dirname(pkgPath);
  try {
    const pkgJson = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as { module?: string };
    const esmEntry = pkgJson.module || 'dist/esm/index.js';
    const esmAbs = path.resolve(pkgDir, esmEntry);
    return path.resolve(path.dirname(esmAbs), '..');
  } catch {
    return path.join(pkgDir, 'dist');
  }
}
