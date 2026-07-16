import initRouterAbEcdsaSigningWorkerWasm, {
  init_router_ab_ecdsa_signing_worker,
  router_ab_ecdsa_derivation_relayer_bootstrap,
} from '../../../../../wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker.js';
import type { InitInput } from '../../../../../wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker.js';

const WASM_PATH_CANDIDATES = [
  '../../wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker_bg.wasm',
  '../wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker_bg.wasm',
  '../../../../../wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker_bg.wasm',
];

type SigningWorkerWasmModuleImport = { readonly default?: WebAssembly.Module };

let initPromise: Promise<void> | null = null;
let isReady = false;

function isNodeEnvironment(): boolean {
  const processObject = (globalThis as { process?: { versions?: { node?: string } } }).process;
  const webSocketPair = (globalThis as { WebSocketPair?: unknown }).WebSocketPair;
  const navigatorObject = (globalThis as { navigator?: { userAgent?: unknown } }).navigator;
  const isCloudflareWorker =
    typeof webSocketPair !== 'undefined' ||
    (typeof navigatorObject?.userAgent === 'string' &&
      navigatorObject.userAgent.includes('Cloudflare-Workers'));
  return Boolean(processObject?.versions?.node) && !isCloudflareWorker;
}

function resolveWasmUrls(): URL[] {
  const baseUrl = import.meta.url;
  const resolved: URL[] = [];
  for (const candidate of WASM_PATH_CANDIDATES) {
    try {
      resolved.push(new URL(candidate, baseUrl));
    } catch {
      continue;
    }
  }
  return resolved;
}

async function loadBundledModule(): Promise<WebAssembly.Module | null> {
  try {
    const imported =
      (await import('../../../../../wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker_bg.wasm')) as SigningWorkerWasmModuleImport;
    return imported.default instanceof WebAssembly.Module ? imported.default : null;
  } catch {
    return null;
  }
}

async function initializeCompiledModule(module: WebAssembly.Module): Promise<void> {
  await initRouterAbEcdsaSigningWorkerWasm({ module_or_path: module as unknown as InitInput });
  init_router_ab_ecdsa_signing_worker();
  isReady = true;
}

async function initializeNodeWasm(urls: URL[]): Promise<void> {
  const { fileURLToPath } = await import('node:url');
  const { readFile } = await import('node:fs/promises');
  for (const url of urls) {
    try {
      const bytes = await readFile(fileURLToPath(url));
      const moduleBytes = new ArrayBuffer(bytes.byteLength);
      new Uint8Array(moduleBytes).set(bytes);
      await initializeCompiledModule(await WebAssembly.compile(moduleBytes));
      return;
    } catch {
      continue;
    }
  }
  throw new Error(
    `[threshold-ecdsa] Failed to initialize Router A/B signing worker WASM: ${urls.map(String).join(', ')}`,
  );
}

async function initializeWorkerWasm(urls: URL[]): Promise<void> {
  let lastError: unknown = null;
  const bundledModule = await loadBundledModule();
  if (bundledModule) {
    try {
      await initializeCompiledModule(bundledModule);
      return;
    } catch (error: unknown) {
      lastError = error;
    }
  }
  for (const url of urls) {
    try {
      await initRouterAbEcdsaSigningWorkerWasm({ module_or_path: url as unknown as InitInput });
      init_router_ab_ecdsa_signing_worker();
      isReady = true;
      return;
    } catch (error: unknown) {
      lastError = error;
    }
  }
  throw lastError instanceof Error
    ? lastError
    : new Error('Failed to initialize Router A/B signing worker WASM');
}

async function initializeWasm(): Promise<void> {
  const urls = resolveWasmUrls();
  if (isNodeEnvironment()) {
    await initializeNodeWasm(urls);
    return;
  }
  await initializeWorkerWasm(urls);
}

export function ensureRouterAbEcdsaSigningWorkerWasm(): Promise<void> {
  initPromise ??= initializeWasm();
  return initPromise;
}

function requireReady(): void {
  if (!isReady) throw new Error('[threshold-ecdsa] Router A/B signing worker WASM is not ready');
}

function checkedBytes(label: string, value: Uint8Array, expectedLength: number): Uint8Array {
  if (value.length !== expectedLength) {
    throw new Error(`${label} must be ${expectedLength} bytes (got ${value.length})`);
  }
  return value;
}

export async function roleLocalThresholdEcdsaDerivationRelayerBootstrap(input: {
  applicationBindingDigest: Uint8Array;
  relayerKeyId: string;
  yRelayer32Le: Uint8Array;
  clientPublicKey33: Uint8Array;
  clientShareRetryCounter: number;
}): Promise<{
  contextBinding32: Uint8Array;
  relayerShare32: Uint8Array;
  relayerPublicKey33: Uint8Array;
  groupPublicKey33: Uint8Array;
  ethereumAddress20: Uint8Array;
  relayerMappedPrivateShare32: Uint8Array;
  relayerShareRetryCounter: number;
  publicTranscriptDigest32: Uint8Array;
}> {
  await ensureRouterAbEcdsaSigningWorkerWasm();
  requireReady();
  const raw = router_ab_ecdsa_derivation_relayer_bootstrap({
    applicationBindingDigest: Array.from(
      checkedBytes('applicationBindingDigest', input.applicationBindingDigest, 32),
    ),
    relayerKeyId: input.relayerKeyId,
    yRelayer32Le: Array.from(checkedBytes('yRelayer32Le', input.yRelayer32Le, 32)),
    clientPublicKey33: Array.from(checkedBytes('clientPublicKey33', input.clientPublicKey33, 33)),
    clientShareRetryCounter: input.clientShareRetryCounter,
  }) as {
    contextBinding32: Uint8Array;
    relayerShare32: Uint8Array;
    relayerPublicKey33: Uint8Array;
    groupPublicKey33: Uint8Array;
    ethereumAddress20: Uint8Array;
    relayerMappedPrivateShare32: Uint8Array;
    relayerShareRetryCounter: number;
    publicTranscriptDigest32: Uint8Array;
  };
  return {
    contextBinding32: checkedBytes('contextBinding32', raw.contextBinding32, 32),
    relayerShare32: checkedBytes('relayerShare32', raw.relayerShare32, 32),
    relayerPublicKey33: checkedBytes('relayerPublicKey33', raw.relayerPublicKey33, 33),
    groupPublicKey33: checkedBytes('groupPublicKey33', raw.groupPublicKey33, 33),
    ethereumAddress20: checkedBytes('ethereumAddress20', raw.ethereumAddress20, 20),
    relayerMappedPrivateShare32: checkedBytes(
      'relayerMappedPrivateShare32',
      raw.relayerMappedPrivateShare32,
      32,
    ),
    relayerShareRetryCounter: raw.relayerShareRetryCounter,
    publicTranscriptDigest32: checkedBytes(
      'publicTranscriptDigest32',
      raw.publicTranscriptDigest32,
      32,
    ),
  };
}
