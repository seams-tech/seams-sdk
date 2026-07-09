import { Page } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { buildPermissionsPolicy, buildWalletCsp } from '@/plugins/headers';
import { buildWalletServiceHtml } from '@/plugins/plugin-utils';
import { printLog, printStepLine } from './logging';
import {
  buildTestBrowserImportMapHtml,
  TEST_BROWSER_IMPORT_MAP_MARKER,
} from './importMap';

/**
 * Installs Playwright routes that simulate production cross-origin headers for
 * wallet SDK assets (/sdk/*) and the wallet-service surface. This enables
 * cross-origin workers and WASM to load during tests without same-origin hacks.
 *
 * Logging can be emitted in two styles:
 *  - 'intercept' (default): intercepted category logs
 *  - 'setup': prints as setup step 1 lines for nicer sequence
 *  - 'silent': no logs
 */
export async function installWalletSdkCorsShim(
  page: Page,
  options: {
    walletOrigin?: string;
    appOrigin?: string;
    logStyle?: 'intercept' | 'setup' | 'silent';
    mirror?: boolean;
    injectWalletServiceImportMap?: boolean;
  } = {},
): Promise<void> {
  const walletOrigin = options.walletOrigin ?? 'https://wallet.example.localhost';
  const appOrigin = options.appOrigin ?? 'https://example.localhost';
  const logStyle = options.logStyle ?? 'silent';
  const mirror = options.mirror !== false; // default true to support NO_CADDY
  const injectWalletServiceImportMap = options.injectWalletServiceImportMap === true;

  const repoRoot = (() => {
    if (process.env.W3A_REPO_ROOT) return process.env.W3A_REPO_ROOT;
    const cwd = process.cwd();
    if (fs.existsSync(path.join(cwd, 'packages/sdk-web'))) return cwd;
    return path.resolve(cwd, '..');
  })();
  const sdkPublicRoot = path.join(repoRoot, 'packages/sdk-web/dist/public');

  // Prefer BrowserContext glob patterns to ensure reliable matching across transports
  const walletHost = (() => {
    try {
      return new URL(walletOrigin).host;
    } catch {
      return 'wallet.example.localhost';
    }
  })();
  const appHost = (() => {
    try {
      return new URL(appOrigin).host;
    } catch {
      return '';
    }
  })();
  const sdkPatterns = Array.from(
    new Set(
      [`**://${walletHost}/sdk/**`, appHost ? `**://${appHost}/sdk/**` : ''].filter(Boolean),
    ),
  );
  const walletServicePattern: string = `**://${walletHost}/wallet-service*`;

  const contentTypeForAsset = (filePath: string): string => {
    switch (path.extname(filePath)) {
      case '.js':
        return 'application/javascript; charset=utf-8';
      case '.css':
        return 'text/css; charset=utf-8';
      case '.json':
      case '.map':
        return 'application/json; charset=utf-8';
      case '.wasm':
        return 'application/wasm';
      default:
        return 'application/octet-stream';
    }
  };

  const resolveSdkPublicAsset = (url: string): string | null => {
    try {
      const parsed = new URL(url);
      const sdkIndex = parsed.pathname.indexOf('/sdk/');
      if (sdkIndex < 0) return null;
      const rel = decodeURIComponent(parsed.pathname.slice(sdkIndex + 1));
      const candidate = path.normalize(path.join(sdkPublicRoot, rel));
      const normalizedRoot = path.normalize(sdkPublicRoot);
      if (candidate !== normalizedRoot && !candidate.startsWith(`${normalizedRoot}${path.sep}`)) {
        return null;
      }
      if (!fs.existsSync(candidate) || !fs.statSync(candidate).isFile()) return null;
      return candidate;
    } catch {
      return null;
    }
  };

  const buildAssetHeaders = (orig: Record<string, string>, url: string): Record<string, string> => {
    const headers: Record<string, string> = { ...orig };
    // Match dev plugin behavior so COEP documents can import module workers and WASM
    headers['cross-origin-embedder-policy'] = 'require-corp';
    headers['cross-origin-resource-policy'] = 'cross-origin';
    headers['access-control-allow-origin'] = appOrigin;
    headers['access-control-allow-credentials'] = 'true';
    headers['access-control-allow-methods'] = 'GET,OPTIONS';
    headers['access-control-allow-headers'] = 'Content-Type,Authorization';
    headers['access-control-expose-headers'] = [
      'Cross-Origin-Resource-Policy',
      'Cross-Origin-Embedder-Policy',
      'Access-Control-Allow-Origin',
      'Content-Type',
    ].join(', ');
    headers['vary'] = 'Origin';
    if (/\.wasm(\?|$)/i.test(url)) headers['content-type'] = 'application/wasm';
    return headers;
  };

  // Install at BrowserContext level so worker/iframe requests are covered too
  const ctx = page.context();

  // Ensure previous routes are cleared
  for (const sdkPattern of sdkPatterns) {
    await ctx.unroute(sdkPattern as any).catch(() => undefined);
    await ctx.route(sdkPattern as any, async (route) => {
      const req = route.request();
      const url = req.url();
      const method = (req.method() || 'GET').toUpperCase();

      if (method === 'OPTIONS') {
        if (logStyle === 'intercept') {
          printLog('intercept', `sdk preflight OPTIONS ${url}`, { scope: 'cors' });
        }
        return route.fulfill({
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': appOrigin,
            'Access-Control-Allow-Methods': 'GET,OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type,Authorization',
            'Access-Control-Allow-Credentials': 'true',
          },
          body: '',
        });
      }

      try {
        if (logStyle === 'intercept') {
          printLog('intercept', `sdk ${method} ${url} [mirror=${mirror ? 'on' : 'off'}]`, {
            scope: 'cors',
          });
        }
        const assetPath = resolveSdkPublicAsset(url);
        if (assetPath) {
          const headers = buildAssetHeaders(
            { 'content-type': contentTypeForAsset(assetPath) },
            url,
          );
          await route.fulfill({ status: 200, headers, path: assetPath });
          return;
        }

        const upstreamUrl = mirror ? url.replace(walletOrigin, appOrigin) : url;
        const fetched = await route.fetch({ url: upstreamUrl });
        const body = await fetched.body();
        const originalHeaders = fetched.headers();
        const lower: Record<string, string> = {};
        for (const [k, v] of Object.entries(originalHeaders)) {
          if (typeof v === 'string') lower[k] = v;
        }
        const headers = buildAssetHeaders(lower, url);
        await route.fulfill({ status: fetched.status(), headers, body });
        if (logStyle === 'intercept') {
          printLog(
            'intercept',
            `sdk fulfilled ${url} ← ${upstreamUrl} (status ${fetched.status()})`,
            { scope: 'cors', indent: 1 },
          );
        }
      } catch (error) {
        // Quiet teardown noise (page/context closed or response disposed) unless explicitly in intercept mode
        const msg = String((error as Error)?.message || '');
        const isTeardownNoise =
          /Target page|context|browser has been closed|Response has been disposed/i.test(msg);
        if (!isTeardownNoise && options.logStyle === 'intercept') {
          printLog('intercept', `cors shim fell back (${msg})`, { scope: 'cors', indent: 1 });
        }
        return route.fallback();
      }
    });
  }
  if (logStyle === 'intercept') {
    printLog('intercept', `wallet SDK CORS/CORP shim installed for ${walletOrigin}/sdk/*`, {
      scope: 'cors',
      step: 'ready',
    });
  } else if (logStyle === 'setup') {
    printStepLine(1, `wallet SDK CORS/CORP headers installed for ${walletOrigin}/sdk/*`);
  }

  await ctx.unroute(walletServicePattern as any).catch(() => undefined);
  await ctx.route(walletServicePattern as any, async (route) => {
    try {
      const req = route.request();
      const url = req.url();
      const upstreamUrl = mirror ? url.replace(walletOrigin, appOrigin) : url;
      if (logStyle === 'intercept') {
        printLog('intercept', `wallet-service GET ${url} [mirror=${mirror ? 'on' : 'off'}]`, {
          scope: 'cors',
        });
      }
      const fetched = await route.fetch({ url: upstreamUrl });
      let status = fetched.status();
      let body = await fetched.body();
      const headers: Record<string, string> = {
        'cross-origin-opener-policy': 'unsafe-none',
        'cross-origin-embedder-policy': 'require-corp',
        'cross-origin-resource-policy': 'cross-origin',
        'permissions-policy': buildPermissionsPolicy(walletOrigin),
        'content-security-policy': buildWalletCsp(
          injectWalletServiceImportMap
            ? { mode: 'compatible', scriptSrcAllowlist: ['https://esm.sh'] }
            : { mode: 'strict' },
        ),
      };

      // In NO_CADDY (mirror) mode, the app dev server might not have /wallet-service
      // (e.g. if the Vite plugin didn't load). Fall back to a minimal wallet-service
      // surface so wallet iframe handshake remains deterministic.
      if (mirror && (status === 404 || status === 500) && body.byteLength === 0) {
        body = Buffer.from(buildWalletServiceHtml('/sdk'), 'utf8');
        status = 200;
        headers['content-type'] = 'text/html; charset=utf-8';
      }
      if (injectWalletServiceImportMap && isHtmlResponse(headers, body)) {
        body = injectImportMapIntoWalletServiceHtml(body);
        headers['content-type'] = headers['content-type'] || 'text/html; charset=utf-8';
        delete headers['content-length'];
        delete headers['Content-Length'];
      }

      await route.fulfill({ status, headers, body });
      if (logStyle === 'intercept') {
        printLog(
          'intercept',
          `wallet-service fulfilled ${url} ← ${upstreamUrl} (status ${fetched.status()})`,
          { scope: 'cors', indent: 1 },
        );
      }
    } catch (error) {
      const msg = String((error as Error)?.message || '');
      const isTeardownNoise =
        /Target page|context|browser has been closed|Response has been disposed/i.test(msg);
      if (!isTeardownNoise && options.logStyle === 'intercept') {
        printLog('intercept', `wallet-service shim fell back (${msg})`, {
          scope: 'cors',
          indent: 1,
        });
      }
      return route.fallback();
    }
  });
  if (logStyle === 'intercept') {
    printLog(
      'intercept',
      `wallet service headers shim installed for ${walletOrigin}/wallet-service/*`,
      { scope: 'cors', step: 'ready' },
    );
  } else if (logStyle === 'setup') {
    printStepLine(
      1,
      `wallet service headers shim installed for ${walletOrigin}/wallet-service/*`,
      2,
    );
  }

  // Also emit a browser‑console breadcrumb so logs appear in Playwright console capture
  try {
    if (logStyle === 'intercept') {
      await page.evaluate(
        (args) => {
          const { walletOrigin, appOrigin, mirror } = args;
          console.log(
            `[cors] shim ready sdk: ${walletOrigin}/sdk/* (mirror=${mirror ? 'on' : 'off'}) → upstream: ${mirror ? appOrigin : walletOrigin}`,
          );
          console.log(`[cors] shim ready wallet-service: ${walletOrigin}/wallet-service/*`);
        },
        { walletOrigin, appOrigin, mirror },
      );
    }
  } catch {}
}

function isHtmlResponse(headers: Record<string, string>, body: Buffer): boolean {
  const contentType = String(headers['content-type'] || headers['Content-Type'] || '').toLowerCase();
  const prefix = body.toString('utf8', 0, 256).toLowerCase();
  return (
    contentType.includes('text/html') ||
    prefix.includes('<!doctype') ||
    prefix.includes('<html') ||
    prefix.includes('<head')
  );
}

function injectImportMapIntoWalletServiceHtml(body: Buffer): Buffer {
  const html = body.toString('utf8');
  if (html.includes(TEST_BROWSER_IMPORT_MAP_MARKER)) return body;
  const importMapHtml = buildTestBrowserImportMapHtml();
  const patched = /<head[^>]*>/i.test(html)
    ? html.replace(/<head[^>]*>/i, (head) => `${head}${importMapHtml}`)
    : html.includes('</head>')
      ? html.replace(/<\/head>/i, `${importMapHtml}</head>`)
      : `${importMapHtml}${html}`;
  return Buffer.from(patched, 'utf8');
}
