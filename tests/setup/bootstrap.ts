import { Page, type Route } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { printStepLine } from './logging';
import { installRelayServerProxyShim, installWalletSdkCorsShim } from './cross-origin-headers';
import type { PasskeyTestConfig } from './types';
import { DEFAULT_TEST_CONFIG } from './config';
import { SDK_ESM_PATHS } from './sdkEsmPaths';
import {
  buildTestBrowserImportMapHtml,
  TEST_BROWSER_IMPORT_MAP_ATTR,
  TEST_BROWSER_IMPORT_MAP_MARKER,
} from './importMap';

const SERVER_ESM_ROUTE_PATTERN = '**/sdk/esm/server/**';

function resolveRepoRoot(): string {
  if (process.env.W3A_REPO_ROOT) return process.env.W3A_REPO_ROOT;
  const cwd = process.cwd();
  if (fs.existsSync(path.join(cwd, 'packages/sdk-server-ts'))) return cwd;
  return path.resolve(cwd, '..');
}

function contentTypeForEsmFixture(filePath: string): string {
  switch (path.extname(filePath)) {
    case '.js':
      return 'application/javascript; charset=utf-8';
    case '.map':
    case '.json':
      return 'application/json; charset=utf-8';
    case '.wasm':
      return 'application/wasm';
    default:
      return 'application/octet-stream';
  }
}

function resolveServerEsmFixturePath(url: string): string | null {
  const parsed = new URL(url);
  const marker = '/sdk/esm/server/';
  const markerIndex = parsed.pathname.indexOf(marker);
  if (markerIndex < 0) return null;

  const rel = decodeURIComponent(parsed.pathname.slice(markerIndex + marker.length));
  const root = path.join(resolveRepoRoot(), 'packages/sdk-server-ts/dist/esm');
  const candidate = path.normalize(path.join(root, rel));
  const normalizedRoot = path.normalize(root);
  if (candidate !== normalizedRoot && !candidate.startsWith(`${normalizedRoot}${path.sep}`)) {
    return null;
  }
  return candidate;
}

async function installServerEsmDynamicModuleRoute(page: Page): Promise<void> {
  const context = page.context();
  await context.unroute(SERVER_ESM_ROUTE_PATTERN as any).catch(() => undefined);
  await context.route(SERVER_ESM_ROUTE_PATTERN as any, async (route) => {
    const filePath = resolveServerEsmFixturePath(route.request().url());
    if (!filePath || !fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
      return route.fulfill({
        status: 404,
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store, max-age=0',
        },
        body: JSON.stringify({ error: 'server ESM fixture not found' }),
      });
    }

    return route.fulfill({
      status: 200,
      path: filePath,
      headers: {
        'content-type': contentTypeForEsmFixture(filePath),
        'cache-control': 'no-store, max-age=0',
      },
    });
  });
}

async function setupWebAuthnVirtualAuthenticator(page: Page): Promise<string> {
  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');

  // Add virtual authenticator with configuration based on
  // https://www.corbado.com/blog/passkeys-e2e-playwright-testing-webauthn-virtual-authenticator
  const authenticator = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal', // Platform authenticator (like Touch ID/Face ID)
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  const authenticatorId = authenticator.authenticatorId;
  printStepLine(2, `virtual authenticator ready (${authenticatorId})`);
  return authenticatorId;
}

/**
 * Step 2: IMPORT MAP INJECTION
 * Add module resolution mappings to the page
 */
export async function injectImportMap(page: Page): Promise<void>;
export async function injectImportMap(page: Page, options: { frontendUrl: string }): Promise<void>;
export async function injectImportMap(
  page: Page,
  options?: { frontendUrl: string },
): Promise<void> {
  await installServerEsmDynamicModuleRoute(page);

  // Import maps must be present in the HTML during parsing (before any module scripts run).
  // The Vite example app includes `<script type="module" src="/src/main.tsx">`, so we inject
  // the import map by rewriting the top-level document HTML during the initial navigation.
  const importMapAttr = TEST_BROWSER_IMPORT_MAP_ATTR;
  const importMapMarker = TEST_BROWSER_IMPORT_MAP_MARKER;
  const importMapHtml = buildTestBrowserImportMapHtml();

  const handler = async (route: Route) => {
    const req = route.request();
    // Safety: only touch top-level documents (never iframe documents like wallet-service).
    try {
      if (req.resourceType() !== 'document') return route.fallback();
      if (req.frame().parentFrame()) return route.fallback();
    } catch {
      return route.fallback();
    }

    const fetched = await route.fetch();
    const headers = fetched.headers();
    const ct = headers['content-type'] || headers['Content-Type'] || '';
    if (!String(ct).toLowerCase().includes('text/html')) {
      return route.fulfill({ status: fetched.status(), headers, body: await fetched.body() });
    }

    const html = await fetched.text();
    if (html.includes(importMapMarker)) {
      return route.fulfill({ status: fetched.status(), headers, body: html });
    }

    const patched = /<head[^>]*>/i.test(html)
      ? html.replace(/<head[^>]*>/i, (head) => `${head}${importMapHtml}`)
      : html.includes('</head>')
        ? html.replace(/<\/head>/i, `${importMapHtml}</head>`)
        : `${importMapHtml}${html}`;

    // Avoid stale content-length; Playwright will compute it.
    const nextHeaders = { ...headers };
    delete (nextHeaders as any)['content-length'];
    delete (nextHeaders as any)['Content-Length'];
    return route.fulfill({ status: fetched.status(), headers: nextHeaders, body: patched });
  };

  const ensureUrl = (raw: string): string => {
    const u = new URL(raw);
    u.hash = '';
    u.search = '';
    return u.toString();
  };

  const currentUrlRaw = page.url();
  const currentUrl = (() => {
    try {
      return new URL(currentUrlRaw);
    } catch {
      return null;
    }
  })();

  // Route-only mode (pre-navigation): used by executeSequentialSetup() to patch the initial HTML response.
  if (options?.frontendUrl) {
    const frontendUrl = ensureUrl(options.frontendUrl);
    const indexUrl = new URL('/index.html', frontendUrl).toString();

    await page.unroute(frontendUrl).catch(() => undefined);
    await page.route(frontendUrl, handler);
    await page.unroute(indexUrl).catch(() => undefined);
    await page.route(indexUrl, handler);

    printStepLine(3, 'import map route installed (document rewrite)');
    return;
  }

  // If the current document already has the import map, do nothing.
  try {
    const alreadyInjected = await page.evaluate((attr) => {
      return !!document.querySelector(`script[type="importmap"][${attr}="1"]`);
    }, importMapAttr);
    if (alreadyInjected) {
      return;
    }
  } catch {}

  // If we're on a non-http(s) URL (about:blank, data:), we can't rewrite network HTML.
  // Use setContent() to create a fresh document that includes the import map during parsing.
  if (!currentUrl || (currentUrl.protocol !== 'http:' && currentUrl.protocol !== 'https:')) {
    const baseHref = ensureUrl(DEFAULT_TEST_CONFIG.frontendUrl);
    const html = `<!DOCTYPE html><html><head><base href="${baseHref}">${importMapHtml}</head><body></body></html>`;
    await page.setContent(html, { waitUntil: 'domcontentloaded' });
    return;
  }

  // Reload once to apply import map injection to the current document.
  const docUrl = ensureUrl(currentUrl.toString());
  const indexUrl = new URL('/index.html', docUrl).toString();

  await page.unroute(docUrl).catch(() => undefined);
  await page.route(docUrl, handler);
  await page.unroute(indexUrl).catch(() => undefined);
  await page.route(indexUrl, handler);

  await page.reload({ waitUntil: 'domcontentloaded' });
}

/**
 * Step 3: STABILIZATION WAIT
 * Allow browser environment to settle
 */
async function waitForEnvironmentStabilization(page: Page): Promise<void> {
  await page.waitForLoadState('domcontentloaded');
  await page.waitForFunction(
    () => document.readyState === 'complete' || document.readyState === 'interactive',
  );

  printStepLine(4, 'environment stabilized');
}

/**
 * Step 4: DYNAMIC IMPORTS
 * Load SeamsWeb only after environment is ready
 *
 * NOTE (UserConfirm worker):
 * - The dynamically loaded SeamsWeb instance wires:
 *   - UserConfirm worker as the owner of WebAuthn PRF + UserConfirm
 *     (via awaitUserConfirmationV2 in the UserConfirm worker bundle).
 *   - Signer worker as a WrapKeySeed/KEK/NEAR‑signature enclave that derives
 *     WrapKeySeed from prfFirstB64u + wrapKeySalt supplied in wallet-origin requests.
 */
async function loadSeamsWebDynamically(
  page: Page,
  configs: PasskeyTestConfig,
): Promise<void> {
  // Wait for the page to be ready before attempting imports.
  // Note: `networkidle` is unreliable on Vite dev pages due to HMR/WebSocket connections.
  await page.waitForLoadState('domcontentloaded');
  await page.waitForFunction(
    () => document.readyState === 'complete' || document.readyState === 'interactive',
  );

  // Robust error handling + retry logic
  const maxRetries = 3;
  let lastError: any = null;
  const attemptTimeoutMs = 15_000;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      printStepLine(5, `importing SeamsWeb: attempt ${attempt}/${maxRetries}`, 1);

      const modulePaths = { seamsWeb: SDK_ESM_PATHS.seamsWeb } as const;
      const loadHandle = await page.waitForFunction(
        async (args) => {
          try {
            const { setupOptions, modulePaths } = args as any;
            const { SeamsWeb } = await import(modulePaths.seamsWeb);

            if (!SeamsWeb) {
              throw new Error('SeamsWeb not found in SDK module');
            }

            // Create and validate configuration
            const runtimeConfigs = {
              nearNetwork: setupOptions.nearNetwork as 'testnet',
              relayerAccount: setupOptions.relayerAccount,
              nearRpcUrl: setupOptions.nearRpcUrl,
              useRelayer: setupOptions.useRelayer || false,
              relayServerUrl: setupOptions.relayServerUrl,
              relayer: setupOptions.relayer,
              // Additional centralized configuration
              frontendUrl: setupOptions.frontendUrl,
              rpId: setupOptions.rpId,
              testReceiverAccountId: setupOptions.testReceiverAccountId,
            };

            // Validate required configs
            if (!runtimeConfigs.nearRpcUrl)
              throw new Error('nearRpcUrl is required but not provided');
            if (!runtimeConfigs.relayerAccount)
              throw new Error('relayerAccount is required but not provided');

            // Create SeamsWeb instance
            const seams = new SeamsWeb(runtimeConfigs);

            // Store in window for test access
            (window as any).SeamsWeb = SeamsWeb;
            (window as any).seams = seams;
            (window as any).configs = runtimeConfigs;

            return { success: true, message: 'SeamsWeb loaded successfully' };
          } catch (error: any) {
            const message = error?.message ? String(error.message) : String(error);
            return { success: false, error: message };
          }
        },
        { setupOptions: configs, modulePaths },
        {
          timeout: attemptTimeoutMs,
          polling: 1000,
        },
      );

      const loadResult = await loadHandle.jsonValue().catch(() => ({ success: true }));
      await loadHandle.dispose();

      if (!loadResult?.success) {
        const message =
          loadResult &&
          typeof loadResult === 'object' &&
          'error' in loadResult &&
          typeof (loadResult as { error?: unknown }).error === 'string'
            ? (loadResult as { error: string }).error
            : 'Unknown error loading SeamsWeb';
        throw new Error(message);
      }

      printStepLine(5, `SeamsWeb ready (attempt ${attempt})`, 2);
      return;
    } catch (error: any) {
      lastError = error;
      printStepLine(5, `attempt ${attempt} failed: ${error.message}`, 3);

      if (attempt < maxRetries) {
        printStepLine(5, `retrying in 0.5 seconds (${maxRetries - attempt} retries remaining)`, 3);
        await new Promise((resolve) => setTimeout(resolve, 500));
        // Wait for page to be stable again before retry
        await page.waitForLoadState('domcontentloaded');
      }
    }
  }

  // All retries failed
  throw new Error(
    `Failed to load SeamsWeb after ${maxRetries} attempts. Last error: ${lastError?.message}`,
  );
}

/**
 * Step 5: GLOBAL FALLBACK
 * Ensure base64UrlEncode is available as safety measure
 */
async function ensureGlobalFallbacks(page: Page): Promise<void> {
  const paths = { base64: SDK_ESM_PATHS.base64, accountIds: SDK_ESM_PATHS.accountIds } as const;
  await page.waitForFunction(
    async (paths) => {
      try {
        // Defense in depth: Ensure base64UrlEncode is globally available
        // This prevents "base64UrlEncode is not defined" errors even if timing issues occur
        if (typeof (window as any).base64UrlEncode === 'undefined') {
          try {
            const { base64UrlEncode } = await import(paths.base64);
            (window as any).base64UrlEncode = base64UrlEncode;
            console.log('[setup:browser] base64UrlEncode made available globally as fallback');
          } catch (encoderError) {
            console.error(
              '[setup:browser] Failed to import base64UrlEncode fallback:',
              encoderError,
            );
          }
        }

        // Also ensure base64UrlDecode is available for credential ID decoding
        if (typeof (window as any).base64UrlDecode === 'undefined') {
          try {
            const { base64UrlDecode } = await import(paths.base64);
            (window as any).base64UrlDecode = base64UrlDecode;
          } catch (encoderError) {
            console.error(
              '[setup:browser - step 5] Failed to import base64UrlDecode fallback:',
              encoderError,
            );
          }
        }

        // Ensure toAccountId is available globally for tests
        if (typeof (window as any).toAccountId === 'undefined') {
          try {
            const { toAccountId } = await import(paths.accountIds);
            (window as any).toAccountId = toAccountId;
          } catch (accountIdError) {
            console.error(
              '[setup:browser - step 5] Failed to import toAccountId fallback:',
              accountIdError,
            );
          }
        }

        return true; // Success indicator
      } catch (error) {
        console.error('Global fallbacks setup failed:', error);
        return false;
      }
    },
    paths,
    {
      timeout: 15000, // 15 second timeout
      polling: 500, // Check every 500ms
    },
  );

  printStepLine(6, 'global fallbacks ready');
}

/**
 * Orchestrator function that executes all 5 setup steps sequentially
 */
export async function executeSequentialSetup(
  page: Page,
  configs: PasskeyTestConfig,
  options: { skipSeamsWebInit?: boolean; injectWalletServiceImportMap?: boolean } = {},
): Promise<string> {
  printStepLine('bootstrap', 'starting 6-step sequential bootstrap', 0);

  // Step 1a: Log CORS/CORP headers installation (routes already installed pre-navigation)
  const appOrigin = new URL(configs.frontendUrl).origin;
  const mirrorWalletOrigin = (() => {
    // When running without Caddy, tests only start the app dev server, so we mirror wallet-origin
    // assets/routes from the app origin. With Caddy enabled (default), wallet.example.localhost is
    // served separately and we should not mirror to avoid breaking the iframe handshake.
    const noCaddy =
      process.env.NO_CADDY === '1' || process.env.VITE_NO_CADDY === '1' || process.env.CI === '1';
    return noCaddy;
  })();
  await installWalletSdkCorsShim(page, {
    appOrigin,
    logStyle: 'setup',
    mirror: mirrorWalletOrigin,
    injectWalletServiceImportMap: options.injectWalletServiceImportMap,
  });
  const useRelayServer =
    process.env.USE_RELAY_SERVER === '1' || process.env.USE_RELAY_SERVER === 'true';
  if (mirrorWalletOrigin && useRelayServer) {
    await installRelayServerProxyShim(page, { logStyle: 'setup' });
  }

  // Step 2: ENVIRONMENT SETUP
  const authenticatorId = await setupWebAuthnVirtualAuthenticator(page);

  // Step 3: IMPORT MAP INJECTION
  await injectImportMap(page, { frontendUrl: configs.frontendUrl });

  // Navigate after import map injection so the initial HTML parse can apply the map.
  try {
    const frontend = new URL(configs.frontendUrl);
    frontend.hash = '';
    frontend.search = '';
    await page.goto(frontend.toString(), { waitUntil: 'domcontentloaded' });
  } catch {
    await page.goto('/', { waitUntil: 'domcontentloaded' });
  }

  // Step 4: STABILIZATION WAIT
  await waitForEnvironmentStabilization(page);

  if (!options.skipSeamsWebInit) {
    // Step 5: DYNAMIC IMPORTS
    await loadSeamsWebDynamically(page, configs);

    // Step 6: GLOBAL FALLBACK
    await ensureGlobalFallbacks(page);
  }

  // finished
  return authenticatorId;
}
