import initShamir3PassWasm, {
  init_shamir3pass_runtime,
  shamir3pass_add_lock,
  shamir3pass_derive_lock_key_handle,
  shamir3pass_destroy_lock_key_handle,
  shamir3pass_remove_lock,
} from '../../../../../../../wasm/shamir3pass_runtime/pkg/shamir3pass_runtime.js';
import type { InitInput } from '../../../../../../../wasm/shamir3pass_runtime/pkg/shamir3pass_runtime.js';

type Shamir3PassWasmModuleImport = {
  readonly default?: WebAssembly.Module;
};

const SHAMIR3PASS_WASM_PATH_CANDIDATES = [
  '../../wasm/shamir3pass_runtime/pkg/shamir3pass_runtime_bg.wasm',
  '../wasm/shamir3pass_runtime/pkg/shamir3pass_runtime_bg.wasm',
  '../../../../../../../wasm/shamir3pass_runtime/pkg/shamir3pass_runtime_bg.wasm',
];

let initialization: Promise<void> | null = null;

function isNodeEnvironment(): boolean {
  const processObject = (globalThis as { process?: { versions?: { node?: string } } }).process;
  const isNode = Boolean(processObject?.versions?.node);
  const webSocketPair = (globalThis as { WebSocketPair?: unknown }).WebSocketPair;
  const navigatorObject = (globalThis as { navigator?: { userAgent?: unknown } }).navigator;
  const isCloudflareWorker =
    typeof webSocketPair !== 'undefined' ||
    (typeof navigatorObject?.userAgent === 'string' &&
      navigatorObject.userAgent.includes('Cloudflare-Workers'));
  return isNode && !isCloudflareWorker;
}

function wasmUrls(): URL[] {
  return SHAMIR3PASS_WASM_PATH_CANDIDATES.map((path) => new URL(path, import.meta.url));
}

async function initializeCompiledModule(module: WebAssembly.Module): Promise<void> {
  await initShamir3PassWasm({ module_or_path: module as unknown as InitInput });
  init_shamir3pass_runtime();
}

async function loadBundledModule(): Promise<WebAssembly.Module | null> {
  try {
    const imported = (await import(
      '../../../../../../../wasm/shamir3pass_runtime/pkg/shamir3pass_runtime_bg.wasm'
    )) as Shamir3PassWasmModuleImport;
    return imported.default instanceof WebAssembly.Module ? imported.default : null;
  } catch {
    return null;
  }
}

async function initializeNodeRuntime(): Promise<void> {
  const { fileURLToPath } = await import('node:url');
  const { readFile } = await import('node:fs/promises');
  for (const url of wasmUrls()) {
    try {
      const bytes = await readFile(fileURLToPath(url));
      await initializeCompiledModule(await WebAssembly.compile(bytes));
      return;
    } catch {
      // Try the next package layout.
    }
  }
  throw new Error('[shamir3pass] Failed to initialize WASM from filesystem candidates');
}

async function initializeWorkerRuntime(): Promise<void> {
  const bundledModule = await loadBundledModule();
  if (bundledModule) {
    await initializeCompiledModule(bundledModule);
    return;
  }

  let lastError: unknown = null;
  for (const url of wasmUrls()) {
    try {
      await initShamir3PassWasm({ module_or_path: url as unknown as InitInput });
      init_shamir3pass_runtime();
      return;
    } catch (error: unknown) {
      lastError = error;
    }
  }
  throw lastError instanceof Error
    ? lastError
    : new Error('[shamir3pass] Failed to initialize WASM');
}

export async function ensureSigningSessionSealShamir3PassWasm(): Promise<void> {
  if (!initialization) {
    initialization = isNodeEnvironment() ? initializeNodeRuntime() : initializeWorkerRuntime();
  }
  await initialization;
}

export async function deriveSigningSessionSealLockKeyHandle(input: {
  readonly groupId: string;
  readonly rootSecret32: Uint8Array;
  readonly context: Uint8Array;
}): Promise<number> {
  await ensureSigningSessionSealShamir3PassWasm();
  const rootSecret32 = input.rootSecret32.slice();
  const context = input.context.slice();
  try {
    return shamir3pass_derive_lock_key_handle(input.groupId, rootSecret32, context);
  } finally {
    rootSecret32.fill(0);
    context.fill(0);
  }
}

export async function addSigningSessionSealLock(input: {
  readonly handle: number;
  readonly ciphertextB64u: string;
}): Promise<string> {
  await ensureSigningSessionSealShamir3PassWasm();
  return shamir3pass_add_lock(input.handle, input.ciphertextB64u);
}

export async function removeSigningSessionSealLock(input: {
  readonly handle: number;
  readonly ciphertextB64u: string;
}): Promise<string> {
  await ensureSigningSessionSealShamir3PassWasm();
  return shamir3pass_remove_lock(input.handle, input.ciphertextB64u);
}

export function destroySigningSessionSealLockKeyHandle(handle: number): boolean {
  return shamir3pass_destroy_lock_key_handle(handle);
}
