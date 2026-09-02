/**
 * WASM worker loading overview
 *
 * Environments and how URLs are resolved:
 *
 * - Production (wallet origin)
 *   - WASM Workers live under the wallet site at `${walletOrigin}/sdk/workers/*`.
 *   - `.wasm` must be served with `Content-Type: application/wasm`.
 *   - The wallet iframe announces `window.__W3A_WALLET_SDK_BASE__ = ${walletOrigin}/sdk/`.
 *   - resolveWorkerBaseOrigin() uses that base; resolveWasmUrl() uses the bundler-relative
 *     URL first (import.meta.url) and falls back to `/sdk/workers/*` when needed.
 *
 * - Development (wallet origin)
 *   - Local Caddy/static hosting serves `/sdk/*` and `/sdk/workers/*` from `dist/public`.
 *   - import.meta.url and relative paths work inside the wallet origin.
 *
 * - Development (cross‑origin: app + wallet on different hosts)
 *   - The app does not construct workers from its own origin to avoid SecurityError.
 *     Workers prewarm inside the wallet iframe (wallet origin) instead.
 *   - Loading WASM from the wallet origin requires CORS + correct MIME on the wallet origin.
 *
 * - CI / Node
 *   - Consumers may set `process.env.WASM_BASE_URL` or a worker‑specific
 *     `${WORKER_NAME}_WASM_BASE_URL` to override the base explicitly.
 *   - A global `self.WASM_BASE_URL` is also supported when running in workers.
 *
 * Path Resolution Strategy summary:
 * - resolveWasmUrl() picks the most explicit hint first (customBaseUrl, env, globals),
 *   then tries bundler‑relative (import.meta.url), and finally falls back to `/sdk/workers/*`.
 * - initializeWasm() passes the resolved module_or_path into the generated wasm-bindgen
 *   loader, with a timeout and optional fallback module factory for graceful degradation.
 */

import { getEmbeddedBase } from './base';

export interface WasmLoaderOptions {
  workerName: string;
  wasmUrl: URL;
  initFunction: (wasmModule?: any) => Promise<void>;
  validateFunction?: () => void | Promise<void>;
  timeoutMs?: number;
  createFallbackModule?: (errorMessage: string) => any;
  testFunction?: () => void | Promise<void>;
}

function getGlobalSelf(): (typeof globalThis & { location?: Location; WASM_BASE_URL?: string }) | null {
  return typeof self !== 'undefined'
    ? ((self as typeof globalThis & { location?: Location; WASM_BASE_URL?: string }) ?? null)
    : null;
}

function getGlobalLocationHref(): string | undefined {
  return getGlobalSelf()?.location?.href;
}

function getGlobalLocationOrigin(): string | undefined {
  return getGlobalSelf()?.location?.origin;
}

/**
 * Resolve a WASM binary URL for a given worker.
 * Priority order:
 * 1) Custom base URL provided by the caller
 * 2) process.env.WASM_BASE_URL
 * 3) process.env[`${WORKER_NAME}_WASM_BASE_URL`]
 * 4) self.WASM_BASE_URL (when running inside a worker)
 * 5) Embedded wallet SDK base (`${walletOrigin}/sdk/`) + `workers/`
 * 6) SDK-root-relative URL inferred from import.meta.url for browser bundles
 * 7) Bundler‑relative URL via import.meta.url
 * 8) Fallback `/sdk/workers/${wasmFilename}` under the current origin
 *
 * @param wasmFilename - Name of the WASM binary, e.g. `wasm_signer_worker_bg.wasm`.
 * @param workerName - Human‑readable worker name for logs and env var lookup.
 * @param customBaseUrl - Optional absolute base URL that takes precedence over env/globals.
 * @returns Absolute URL to the resolved WASM binary.
 */
export function resolveWasmUrl(
  wasmFilename: string,
  workerName: string,
  customBaseUrl?: string,
): URL {
  if (customBaseUrl) {
    return new URL(wasmFilename, customBaseUrl);
  }
  if (typeof process !== 'undefined' && (process as any).env?.WASM_BASE_URL) {
    return new URL(wasmFilename, (process as any).env.WASM_BASE_URL);
  }
  const workerEnvVar = workerName.toUpperCase().replace(/[^A-Z]/g, '_') + '_WASM_BASE_URL';
  if (typeof process !== 'undefined' && (process as any).env?.[workerEnvVar]) {
    return new URL(wasmFilename, (process as any).env[workerEnvVar]);
  }
  const globalSelf = getGlobalSelf();
  if (globalSelf?.WASM_BASE_URL) {
    return new URL(wasmFilename, globalSelf.WASM_BASE_URL);
  }
  try {
    const embeddedBase = getEmbeddedBase();
    if (embeddedBase) {
      return new URL(`workers/${wasmFilename}`, embeddedBase);
    }
  } catch {}
  try {
    let metaUrl: string | null = null;
    try {
      metaUrl =
        typeof import.meta !== 'undefined' && (import.meta as any)?.url
          ? ((import.meta as any).url as string)
          : null;
    } catch {
      metaUrl = null;
    }
    if (metaUrl) {
      const meta = new URL(metaUrl, getGlobalLocationHref());
      if (meta.protocol === 'http:' || meta.protocol === 'https:') {
        const sdkSegmentIndex = meta.pathname.indexOf('/sdk/');
        if (sdkSegmentIndex >= 0) {
          const sdkBasePath = meta.pathname.slice(0, sdkSegmentIndex + '/sdk/'.length);
          return new URL(`${sdkBasePath}workers/${wasmFilename}`, meta.origin);
        }
      }
      return new URL(`./${wasmFilename}`, meta);
    }
    const baseUrl = getGlobalLocationHref() || '/';
    return new URL(`./${wasmFilename}`, baseUrl);
  } catch {
    return new URL(`/sdk/workers/${wasmFilename}`, getGlobalLocationOrigin() || '/');
  }
}

/**
 * Initialize a WASM module with robust fallbacks and diagnostics.
 *
 * - PRIMARY: pass a URL (or module) to the WASM `initFunction` so bundlers rewrite
 *   it to the correct asset in production. This is the fastest & most reliable path.
 * - TIMEOUT: guard initialization with a timeout; optionally create a fallback module
 *   via `createFallbackModule` to keep the worker responsive in degraded conditions.
 *
 * @param options - Configuration for WASM initialization: worker name, URL, and hooks.
 * @returns A truthy value on success (or a fallback module if provided). Throws on failure.
 */
export async function initializeWasm(options: WasmLoaderOptions): Promise<any> {
  const {
    workerName,
    wasmUrl,
    initFunction,
    validateFunction,
    testFunction,
    createFallbackModule,
    timeoutMs = 20000,
  } = options;

  const initWithTimeout = async (): Promise<any> => {
    try {
      await initFunction({ module_or_path: wasmUrl as any });
      if (validateFunction) await validateFunction();
      if (testFunction) await testFunction();
      return true;
    } catch (initError: any) {
      console.error(`[${workerName}]: WASM initialization failed`);
      const helpfulMessage =
        `\n${workerName.toUpperCase()} WASM initialization failed. This may be due to:\n1. Server MIME type configuration (WASM files should be served with 'application/wasm')\n2. Network connectivity issues\n3. CORS policy restrictions\n4. Missing WASM files in deployment\n5. SDK packaging problems\n\nOriginal error: ${initError?.message}\n`.trim();
      if (createFallbackModule) {
        console.warn(
          `[${workerName}]: Creating fallback module due to WASM initialization failure`,
        );
        return createFallbackModule(helpfulMessage);
      }
      throw new Error(helpfulMessage);
    }
  };

  let timeoutId: any;
  try {
    const result = await Promise.race([
      initWithTimeout(),
      new Promise<never>((_, reject) => {
        timeoutId = setTimeout(
          () => reject(new Error(`WASM initialization timeout after ${timeoutMs}ms`)),
          timeoutMs,
        );
      }),
    ]);
    clearTimeout(timeoutId);
    return result;
  } catch (timeoutError: any) {
    console.error(`[${workerName}]: WASM initialization failed:`, timeoutError?.message);
    if (createFallbackModule) {
      console.warn(`[${workerName}]: Creating fallback module due to timeout`);
      return createFallbackModule(timeoutError.message);
    }
    throw timeoutError;
  }
}
