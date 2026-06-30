import initSignerWasm, {
  init_worker,
} from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import type { InitInput } from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';

type NearSignerWasmModuleImport = {
  readonly default?: WebAssembly.Module;
};

const SIGNER_WASM_PATH_CANDIDATES = [
  '../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm',
  '../../../../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm',
];

let signerWasmInitPromise: Promise<void> | null = null;
let signerWasmReady = false;
const capturedFetch =
  typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null;

function isNodeEnvironment(): boolean {
  const processObj = (globalThis as unknown as { process?: { versions?: { node?: string } } })
    .process;
  const isNode = Boolean(processObj?.versions?.node);
  const webSocketPair = (globalThis as unknown as { WebSocketPair?: unknown }).WebSocketPair;
  const nav = (globalThis as unknown as { navigator?: { userAgent?: unknown } }).navigator;
  const isCloudflareWorker =
    typeof webSocketPair !== 'undefined' ||
    (typeof nav?.userAgent === 'string' && nav.userAgent.includes('Cloudflare-Workers'));
  return isNode && !isCloudflareWorker;
}

function getSignerWasmUrls(): URL[] {
  const baseUrl = import.meta.url;
  const resolved: URL[] = [];
  for (const path of SIGNER_WASM_PATH_CANDIDATES) {
    try {
      resolved.push(new URL(path, baseUrl));
    } catch {
      // ignore invalid URL candidate
    }
  }
  return resolved;
}

async function initSignerFromCompiledModule(module: WebAssembly.Module): Promise<void> {
  await initSignerWasm({ module_or_path: module as unknown as InitInput });
  init_worker();
  signerWasmReady = true;
}

async function loadBundledNearSignerWasmModule(): Promise<WebAssembly.Module | null> {
  try {
    const imported =
      (await import(
        '../../../../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm'
      )) as NearSignerWasmModuleImport;
    return imported.default instanceof WebAssembly.Module ? imported.default : null;
  } catch {
    return null;
  }
}

async function initNearSignerFromBundledModule(): Promise<boolean> {
  const module = await loadBundledNearSignerWasmModule();
  if (!module) return false;
  await initSignerFromCompiledModule(module);
  return true;
}

async function compileWasmFromUrl(url: URL): Promise<WebAssembly.Module> {
  const fetchFn =
    capturedFetch ??
    (typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null);
  if (!fetchFn) {
    throw new Error('[near-signer] fetch is not available to load signer WASM');
  }
  const response = await fetchFn(url.toString());
  if (!response || typeof (response as { arrayBuffer?: unknown }).arrayBuffer !== 'function') {
    throw new Error('[near-signer] signer WASM fetch returned a non-Response object');
  }
  const status =
    typeof (response as { status?: unknown }).status === 'number'
      ? (response as { status: number }).status
      : 0;
  const ok =
    typeof (response as { ok?: unknown }).ok === 'boolean'
      ? (response as { ok: boolean }).ok
      : status === 0 || (status >= 200 && status < 300);
  if (!ok) {
    throw new Error(`[near-signer] signer WASM fetch failed with status ${status}`);
  }
  const bytes = await response.arrayBuffer();
  return WebAssembly.compile(bytes);
}

async function initializeNearSignerWasm(): Promise<void> {
  const urls = getSignerWasmUrls();
  if (isNodeEnvironment()) {
    const { fileURLToPath } = await import('node:url');
    const { readFile } = await import('node:fs/promises');
    for (const url of urls) {
      try {
        const filePath = fileURLToPath(url);
        const bytes = await readFile(filePath);
        const ab = new ArrayBuffer(bytes.byteLength);
        new Uint8Array(ab).set(bytes);
        const module = await WebAssembly.compile(ab);
        await initSignerFromCompiledModule(module);
        return;
      } catch {
        // try next candidate
      }
    }
    throw new Error('[near-signer] Failed to initialize signer WASM from filesystem candidates');
  }

  if (await initNearSignerFromBundledModule()) return;

  let lastErr: unknown = null;
  for (const url of urls) {
    try {
      const module = await compileWasmFromUrl(url);
      await initSignerFromCompiledModule(module);
      return;
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr instanceof Error
    ? lastErr
    : new Error(String(lastErr || 'Failed to initialize signer WASM'));
}

export async function ensureNearSignerWasm(): Promise<void> {
  if (signerWasmReady) return;
  if (!signerWasmInitPromise) {
    signerWasmInitPromise = initializeNearSignerWasm();
  }
  await signerWasmInitPromise;
}

export function isNearSignerWasmReady(): boolean {
  return signerWasmReady;
}
