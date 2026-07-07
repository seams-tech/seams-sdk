import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildPermissionsPolicy, buildWalletCsp } from './headers';
import {
  addPreconnectLink,
  buildWalletServiceHtml,
  buildExportViewerHtml,
  applyCoepCorpIfNeeded,
  echoCorsFromRequest,
  logRorConfig,
  parseConfiguredRorOrigins,
  resolveRorOrigins,
  toBasePath,
  resolveCoepMode,
  resolveSdkDistRoot,
} from './plugin-utils';
import { setContentType } from './plugin-utils';
import {
  normalizeWalletHostVariant,
  type WalletHostVariant,
} from '../core/browser/walletIframe/hostVariant';

export type VitePlugin = {
  name: string;
  apply?: 'serve' | 'build';
  enforce?: 'pre' | 'post';
  configureServer?: (server: any) => void | Promise<void>;
};

export type Web3AuthnDevOptions = {
  sdkDistRoot?: string;
  sdkBasePath?: string;
  walletServicePath?: string;
  walletOrigin?: string;
  walletHostVariant?: WalletHostVariant;
  setDevHeaders?: boolean;
  enableDebugRoutes?: boolean;
  coepMode?: 'strict' | 'off';
};

export type ServeSdkOptions = {
  sdkDistRoot?: string;
  sdkBasePath?: string;
  enableDebugRoutes?: boolean;
  coepMode?: 'strict' | 'off';
};

export type WalletServiceOptions = {
  walletServicePath?: string;
  sdkBasePath?: string;
  walletHostVariant?: WalletHostVariant;
  coepMode?: 'strict' | 'off';
};

export type DevHeadersOptions = {
  walletOrigin?: string;
  walletServicePath?: string;
  sdkBasePath?: string;
  coepMode?: 'strict' | 'off';
};

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const WALLET_STATIC_ASSET_NAMES = ['wallet-shims.js', 'wallet-service.css'] as const;

type WalletStaticAssetName = (typeof WALLET_STATIC_ASSET_NAMES)[number];

function tryFile(...candidates: string[]): string | undefined {
  for (const file of candidates) {
    try {
      const stat = fs.statSync(file);
      if (stat.isFile()) return file;
    } catch {}
  }
  return undefined;
}

function walletStaticAssetCandidates(fileName: WalletStaticAssetName): string[] {
  return [
    path.resolve(MODULE_DIR, '../static/wallet-assets', fileName),
    path.resolve(MODULE_DIR, '../sdk', fileName),
    path.resolve(MODULE_DIR, '../../public/sdk', fileName),
    path.resolve(process.cwd(), 'src/static/wallet-assets', fileName),
    path.resolve(process.cwd(), 'packages/sdk-web/src/static/wallet-assets', fileName),
  ];
}

function resolveWalletStaticAsset(fileName: WalletStaticAssetName): string {
  const assetPath = tryFile(...walletStaticAssetCandidates(fileName));
  if (assetPath) return assetPath;
  throw new Error(`Missing wallet static asset source: ${fileName}`);
}

function copyWalletStaticAssetIfMissing(fileName: WalletStaticAssetName, destination: string): void {
  if (fs.existsSync(destination)) return;
  fs.copyFileSync(resolveWalletStaticAsset(fileName), destination);
}

/**
 * Seams SDK plugin: serve SDK assets under a stable base (default: /sdk) with optional COEP/CORP (strict mode) and permissive CORS.
 * Where it runs: both the app server and the wallet-iframe server.
 * - App server: lets host pages and Lit components load SDK CSS/JS locally.
 * - Wallet server: used by /wallet-service to load the selected wallet host script and related CSS/JS.
 */
export function seamsServeSdk(opts: ServeSdkOptions = {}): VitePlugin {
  const configuredBase = toBasePath(opts.sdkBasePath, '/sdk');
  const sdkDistRoot = resolveSdkDistRoot(opts.sdkDistRoot);
  const enableDebugRoutes = opts.enableDebugRoutes === true;
  const coepMode = resolveCoepMode(opts.coepMode);

  // In dev we want both '/sdk' and a custom base to work.
  const bases = Array.from(new Set([configuredBase, toBasePath('/sdk')])).sort(
    (a, b) => b.length - a.length,
  );
  // Prefer longest base match first (e.g., '/sdk/esm/react' before '/sdk')

  return {
    name: 'seams:serve-sdk',
    apply: 'serve',
    enforce: 'pre',
    configureServer(server) {
      // Optional debug route to confirm resolution
      if (enableDebugRoutes) {
        server.middlewares.use('/__sdk-root', (req: any, res: any) => {
          res.setHeader('Content-Type', 'text/plain; charset=utf-8');
          res.setHeader('Cache-Control', 'no-store, max-age=0');
          res.end(sdkDistRoot);
        });
      }

      // Serve files under any recognized base from sdkDistRoot with fallbacks
      server.middlewares.use((req: any, res: any, next: any) => {
        if (!req.url) return next();
        const url = req.url.split('?')[0];

        const matchBase = bases.find((b) => url.startsWith(b + '/'));
        if (!matchBase) return next();

        const rel = url.slice((matchBase + '/').length);
        // Try dist/esm/sdk first (canonical), then common fallbacks
        const candidate = tryFile(
          path.join(sdkDistRoot, 'esm', 'sdk', rel),
          path.join(sdkDistRoot, rel),
          path.join(sdkDistRoot, 'esm', rel),
        );

        if (!candidate) {
          res.statusCode = 404;
          res.setHeader('Content-Type', 'application/json; charset=utf-8');
          res.setHeader('Cache-Control', 'no-store, max-age=0');
          res.end(JSON.stringify({ error: 'SDK asset not found', path: rel }));
          return;
        }

        setContentType(res, candidate);
        res.setHeader('Cache-Control', 'no-store, max-age=0');
        // SDK assets need COEP headers to work in wallet iframe with COEP enabled
        applyCoepCorpIfNeeded(res, coepMode);
        // Dev-only CORS echo (no preflight handling here)
        echoCorsFromRequest(res, req, { handlePreflight: false });
        const stream = fs.createReadStream(candidate);
        stream.on('error', () => next());
        stream.pipe(res);
      });
    },
  };
}

/**
 * Dev plugin: expose the wallet service HTML route (default: /wallet-service) that links only external CSS/JS.
 * Where it runs: wallet-iframe dev server (wallet origin). Used by seamsWalletServer.
 */
export function seamsWalletService(opts: WalletServiceOptions = {}): VitePlugin {
  const walletServicePath = toBasePath(opts.walletServicePath, '/wallet-service');
  const sdkBasePath = toBasePath(opts.sdkBasePath, '/sdk');
  const walletHostVariant = normalizeWalletHostVariant(
    opts.walletHostVariant || process.env.VITE_WALLET_HOST_VARIANT,
  );
  const coepMode = resolveCoepMode(opts.coepMode);

  return {
    name: 'seams:wallet-service',
    apply: 'serve',
    enforce: 'pre',
    configureServer(server) {
      server.middlewares.use((req: any, res: any, next: any) => {
        if (!req.url) return next();
        const url = req.url.split('?')[0];
        const isWalletRoute =
          url === walletServicePath ||
          url === `${walletServicePath}/` ||
          url === `${walletServicePath}//`;
        if (isWalletRoute) {
          const html = buildWalletServiceHtml(sdkBasePath, String(Date.now()), walletHostVariant);
          res.statusCode = 200;
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          res.setHeader('Cache-Control', 'no-store, max-age=0');
          res.setHeader('Pragma', 'no-cache');
          applyCoepCorpIfNeeded(res, coepMode);
          res.end(html);
          return;
        }
        next();
      });
    },
  };
}

/**
 * Dev plugin: serve the RP ID related-origin helper and optional strict-isolation headers.
 * Where it runs: Seams-owned local development only.
 */
export function seamsHeaders(opts: DevHeadersOptions = {}): VitePlugin {
  const walletOriginRaw = opts.walletOrigin ?? process.env.VITE_WALLET_ORIGIN;
  const walletOrigin = walletOriginRaw?.trim();
  const walletServicePath = toBasePath(
    opts.walletServicePath || process.env.VITE_WALLET_SERVICE_PATH,
    '/wallet-service',
  );
  const sdkBasePath = toBasePath(opts.sdkBasePath || process.env.VITE_SDK_BASE_PATH, '/sdk');
  const coepMode = resolveCoepMode(opts.coepMode);

  const rorOrigins = resolveRorOrigins({
    configuredOrigins: parseConfiguredRorOrigins(
      String(process.env.VITE_ROR_ALLOWED_ORIGINS || ''),
    ),
    docsOrigin: String(process.env.VITE_DOCS_ORIGIN || ''),
    walletOrigin: walletOrigin || '',
  });
  logRorConfig(rorOrigins);

  return {
    name: 'seams:dev-headers',
    apply: 'serve',
    enforce: 'pre',
    configureServer(server) {
      console.log('[seams] headers enabled', {
        walletServicePath,
        sdkBasePath,
        coepMode,
        rorOriginsCount: rorOrigins.length,
      });

      server.middlewares.use((req: any, res: any, next: any) => {
        const url = (req.url || '').split('?')[0] || '';
        if (coepMode !== 'off') {
          res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
          res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
        }
        addPreconnectLink(res, walletOrigin);

        // Serve /.well-known/webauthn for ROR from server-owned configuration in dev.
        const isWellKnown = url === '/.well-known/webauthn' || url === '/.well-known/webauthn/';
        if (isWellKnown) {
          res.statusCode = 200;
          res.setHeader('Content-Type', 'application/json; charset=utf-8');
          res.setHeader('Cache-Control', 'max-age=60, stale-while-revalidate=600');
          res.end(JSON.stringify({ origins: rorOrigins }));
          return;
        }

        if (url.startsWith(`${sdkBasePath}/`)) {
          // Dev-only CORS for SDK assets served by Vite
          applyCoepCorpIfNeeded(res, coepMode);
          // Honor existing echo from SDK server; otherwise echo
          const ended = echoCorsFromRequest(res, req, {
            honorExistingAcaOrigin: true,
            handlePreflight: true,
          });
          if (ended) return;
        }
        next();
      });
    },
  };
}

function createDevServerPlugin(
  options: Web3AuthnDevOptions,
  includeWalletService: boolean,
): VitePlugin {
  const sdkBasePath = toBasePath(options.sdkBasePath || process.env.VITE_SDK_BASE_PATH, '/sdk');
  const walletServicePath = toBasePath(
    options.walletServicePath || process.env.VITE_WALLET_SERVICE_PATH,
    '/wallet-service',
  );
  const walletOrigin = (options.walletOrigin ?? process.env.VITE_WALLET_ORIGIN)?.trim();
  const walletHostVariant = normalizeWalletHostVariant(
    options.walletHostVariant || process.env.VITE_WALLET_HOST_VARIANT,
  );
  const setDevHeaders = options.setDevHeaders === true;
  const enableDebugRoutes = options.enableDebugRoutes === true;
  const sdkDistRoot = resolveSdkDistRoot(options.sdkDistRoot);
  const coepMode = resolveCoepMode(options.coepMode);

  const sdkPlugin = seamsServeSdk({ sdkBasePath, sdkDistRoot, enableDebugRoutes, coepMode });
  const walletPlugin = seamsWalletService({
    walletServicePath,
    sdkBasePath,
    walletHostVariant,
    coepMode,
  });
  const headersPlugin = setDevHeaders
    ? seamsHeaders({ walletOrigin, walletServicePath, sdkBasePath, coepMode })
    : undefined;

  return {
    name: 'seams:dev',
    apply: 'serve',
    enforce: 'pre',
    configureServer(server) {
      sdkPlugin.configureServer?.(server);
      if (headersPlugin) headersPlugin.configureServer?.(server);
      if (includeWalletService) walletPlugin.configureServer?.(server);
    },
  };
}

// === Build-time helper: emit Cloudflare Pages/Netlify _headers ===
/**
 * Build-time plugin: writes optional static-host `_headers` only for explicitly requested CORS or strict isolation.
 * Where it runs: Seams-owned static wallet host development.
 */
export function seamsBuildHeaders(
  opts: {
    cors?: { accessControlAllowOrigin?: string };
    coepMode?: 'strict' | 'off';
    walletHostVariant?: WalletHostVariant;
  } = {},
): VitePlugin {
  const walletServicePath = toBasePath(process.env.VITE_WALLET_SERVICE_PATH, '/wallet-service');
  const sdkBasePath = toBasePath(process.env.VITE_SDK_BASE_PATH, '/sdk');
  const walletHostVariant = normalizeWalletHostVariant(
    opts.walletHostVariant || process.env.VITE_WALLET_HOST_VARIANT,
  );
  const coepMode = resolveCoepMode(opts.coepMode);

  let outDir = 'dist';

  // We intentionally return a broader shape than VitePlugin; cast at the end
  const plugin = {
    name: 'seams:build-headers',
    apply: 'build' as const,
    enforce: 'post' as const,
    // Capture the resolved outDir
    configResolved(config: any) {
      outDir = (config?.build?.outDir as string) || outDir;
    },
    generateBundle() {
      try {
        const hdrPath = path.join(outDir, '_headers');
        if (fs.existsSync(hdrPath)) {
          // Do not override existing headers; leave a note in build logs
          console.warn('[seams] _headers already exists in outDir; skipping auto-emission');
        } else {
          const contentLines: string[] = [
            ...(coepMode === 'off'
              ? []
              : [
                  '/*',
                  '  Cross-Origin-Embedder-Policy: require-corp',
                  '  Cross-Origin-Resource-Policy: cross-origin',
                  '',
                ]),
          ];
          const configuredAcaOrigin = (
            opts.cors && typeof opts.cors.accessControlAllowOrigin === 'string'
              ? opts.cors.accessControlAllowOrigin.trim()
              : undefined
          ) as string | undefined;
          if (configuredAcaOrigin) {
            contentLines.push(
              `${sdkBasePath}/*`,
              `  Access-Control-Allow-Origin: ${configuredAcaOrigin}`,
            );
          }
          if (contentLines.length > 0) {
            const content = contentLines.join('\n') + '\n';
            fs.mkdirSync(outDir, { recursive: true });
            fs.writeFileSync(hdrPath, content, 'utf-8');
            console.log(
              '[seams] emitted _headers' +
                (coepMode === 'off' ? '' : ' with strict isolation') +
                (configuredAcaOrigin ? ' + CORS' : ''),
            );
          }
        }

        const sdkDir = path.join(outDir, sdkBasePath.replace(/^\//, ''));
        try {
          fs.mkdirSync(sdkDir, { recursive: true });
        } catch {}
        const shimPath = path.join(sdkDir, 'wallet-shims.js');
        copyWalletStaticAssetIfMissing('wallet-shims.js', shimPath);
        const cssPath = path.join(sdkDir, 'wallet-service.css');
        copyWalletStaticAssetIfMissing('wallet-service.css', cssPath);

        // Emit minimal wallet-service/index.html if the app hasn't provided one
        const walletRel = walletServicePath.replace(/^\//, '');
        const wsDir = path.join(outDir, walletRel);
        const wsHtml = path.join(wsDir, 'index.html');
        if (!fs.existsSync(wsHtml)) {
          fs.mkdirSync(wsDir, { recursive: true });
          fs.writeFileSync(
            wsHtml,
            buildWalletServiceHtml(sdkBasePath, undefined, walletHostVariant),
            'utf-8',
          );
          console.log(
            `[seams] emitted ${path.posix.join('/', walletRel, 'index.html')} (minimal wallet service)`,
          );
        }

        // Emit minimal export viewer HTML for production
        const evDir = path.join(outDir, 'export-viewer');
        const evHtml = path.join(evDir, 'index.html');
        if (!fs.existsSync(evHtml)) {
          fs.mkdirSync(evDir, { recursive: true });
          fs.writeFileSync(evHtml, buildExportViewerHtml(sdkBasePath), 'utf-8');
          console.log('[seams] emitted /export-viewer/index.html (minimal export viewer)');
        }
      } catch (e) {
        console.warn('[seams] failed to emit _headers:', e);
      }
    },
  };

  return plugin as unknown as VitePlugin;
}

export function computeDevPermissionsPolicy(walletOrigin?: string): string {
  return buildPermissionsPolicy(walletOrigin);
}

export function computeDevWalletCsp(mode: 'strict' | 'compatible' = 'strict'): string {
  return buildWalletCsp({ mode });
}

export function seamsWalletServer(options: Web3AuthnDevOptions = {}): VitePlugin {
  return createDevServerPlugin(options, true);
}

export function seamsAppServer(options: Web3AuthnDevOptions = {}): VitePlugin {
  return createDevServerPlugin(options, false);
}

export function seamsApp(
  options: Web3AuthnDevOptions & { emitHeaders?: boolean } = {},
): any[] /* Vite Plugin[] */ {
  const { emitHeaders, ...devOpts } = options;
  const app = seamsAppServer(devOpts);
  const hdr = emitHeaders
    ? seamsBuildHeaders({
        coepMode: devOpts.coepMode,
        walletHostVariant: devOpts.walletHostVariant,
      })
    : undefined;
  return [app, hdr].filter(Boolean) as any[];
}

export function seamsWallet(
  options: Web3AuthnDevOptions & { emitHeaders?: boolean } = {},
): any[] /* Vite Plugin[] */ {
  const { emitHeaders, ...devOpts } = options;
  const wallet = seamsWalletServer(devOpts);
  const hdr = emitHeaders
    ? seamsBuildHeaders({
        coepMode: devOpts.coepMode,
        walletHostVariant: devOpts.walletHostVariant,
      })
    : undefined;
  return [wallet, hdr].filter(Boolean) as any[];
}
